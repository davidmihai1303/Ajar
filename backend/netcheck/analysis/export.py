"""Offline analysis and canonical CSV output for a folder of Nmap reports."""
import csv
from pathlib import Path
from tempfile import TemporaryDirectory

from .models import Finding, ScanResult
from .parser import DEFAULT_MAX_XML_BYTES, parse_scan
from .rules import evaluate_devices
from .scoring import compute_score


def analyze_file(path: Path, max_bytes: int = DEFAULT_MAX_XML_BYTES) -> tuple[ScanResult, list[Finding], int | None]:
    scan = parse_scan(str(path), max_bytes=max_bytes)
    if not scan.ok:
        return scan, [], None
    findings = evaluate_devices(scan.devices)
    return scan, findings, compute_score(findings)


def scan_paths(input_path: str | Path) -> list[Path]:
    """One .xml file, or every *.xml directly inside a folder, sorted by file name.

    A missing path raises FileNotFoundError (an OSError), before any output is created.
    """
    path = Path(input_path)
    if path.is_file():
        return [path]
    return sorted((p for p in path.iterdir() if p.suffix.lower() == ".xml" and p.is_file()), key=lambda p: p.name)


def export_folder(folder_path: str | Path, out_dir: str | Path,
                  max_bytes: int = DEFAULT_MAX_XML_BYTES) -> tuple[str, str]:
    """Export a score for every input XML, including an ERROR row for each unreadable scan.

    `folder_path` may also be a single .xml file (live check #1: re-run one Test Set file).

    The CSV `file` column is the real file name, exactly as the jury's answer key has it. The parser
    masks MAC-like text in ScanResult.file for the UI and history, which would turn a Test Set name
    such as "T5_202611081200.xml" into "T5_20:26:11:xx:xx:xx.xml" and make every row of that file
    miss the key. A file name chosen by the jury is not data read from the network.
    """
    # Enumerate before creating the output: by default, input and output are the same directory.
    paths = scan_paths(folder_path)
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
                scores_writer.writerow((path.name, "ERROR" if score is None else score))
                findings_writer.writerows((path.name, f.ip, f.port, f.code, f.severity) for f in findings)
        staged_findings.replace(findings_path)
        staged_scores.replace(scores_path)
    return str(findings_path), str(scores_path)
