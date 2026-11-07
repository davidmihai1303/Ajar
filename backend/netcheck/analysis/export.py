"""Offline analysis and canonical CSV output for a folder of Nmap reports."""
import csv
from pathlib import Path
from tempfile import TemporaryDirectory

from .models import Finding, ScanResult
from .parser import DEFAULT_MAX_XML_BYTES, parse_scan
from .privacy import mask_macs_in_text
from .rules import evaluate_devices
from .scoring import compute_score


def analyze_file(path: Path, max_bytes: int = DEFAULT_MAX_XML_BYTES) -> tuple[ScanResult, list[Finding], int | None]:
    scan = parse_scan(str(path), max_bytes=max_bytes)
    if not scan.ok:
        return scan, [], None
    findings = evaluate_devices(scan.devices)
    return scan, findings, compute_score(findings)


def export_folder(folder_path: str | Path, out_dir: str | Path,
                  max_bytes: int = DEFAULT_MAX_XML_BYTES) -> tuple[str, str]:
    """Export a score for every input XML, including an ERROR row for each unreadable scan."""
    folder = Path(folder_path)
    # Enumerate before creating the output: by default, input and output are the same directory.
    paths = sorted((p for p in folder.iterdir() if p.suffix.lower() == ".xml" and p.is_file()),
                   key=lambda p: (mask_macs_in_text(p.name), p.name))
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    findings_path, scores_path = output / "findings.csv", output / "scores.csv"
    for target in (findings_path, scores_path):
        if target.is_dir():
            raise IsADirectoryError(str(target))

    with TemporaryDirectory(dir=output) as tmp:
        staged_findings = Path(tmp) / findings_path.name
        staged_scores = Path(tmp) / scores_path.name
        with (staged_findings.open("w", encoding="utf-8", newline="") as findings_file,
              staged_scores.open("w", encoding="utf-8", newline="") as scores_file):
            findings_writer = csv.writer(findings_file)
            scores_writer = csv.writer(scores_file)
            findings_writer.writerow(("file", "ip", "port", "finding_code", "severity"))
            scores_writer.writerow(("file", "network_score"))
            for path in paths:
                scan, findings, score = analyze_file(path, max_bytes)
                scores_writer.writerow((scan.file, "ERROR" if score is None else score))
                findings_writer.writerows((scan.file, f.ip, f.port, f.code, f.severity) for f in findings)
        staged_findings.replace(findings_path)
        staged_scores.replace(scores_path)
    return str(findings_path), str(scores_path)
