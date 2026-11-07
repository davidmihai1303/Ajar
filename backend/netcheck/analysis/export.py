"""Offline analysis and canonical CSV output for a folder of Nmap reports."""
import csv
from collections import defaultdict
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


def _input_labels(folder: Path) -> dict[Path, str]:
    groups: dict[str, list[Path]] = defaultdict(list)
    for path in folder.iterdir():
        if path.suffix.lower() == ".xml" and path.is_file():
            groups[mask_macs_in_text(path.name)].append(path)

    # Reserve every original public label, including names that already end in " (2)".
    reserved = set(groups)
    labels = {}
    for label, paths in sorted(groups.items()):
        first, *others = sorted(paths, key=lambda p: (p.name != label, p.name))
        labels[first] = label
        base = Path(label)
        number = 2
        for path in others:
            candidate = f"{base.stem} ({number}){base.suffix}"
            while candidate in reserved:
                number += 1
                candidate = f"{base.stem} ({number}){base.suffix}"
            labels[path] = candidate
            reserved.add(candidate)
            number += 1
    return labels


def single_file_label(path: Path, masked_name: str) -> str:
    if masked_name == path.name:
        return masked_name
    try:
        return _input_labels(path.parent).get(path, masked_name)
    except OSError:
        # A single file can still be readable in a directory the caller cannot list.
        return masked_name


def export_folder(folder_path: str | Path, out_dir: str | Path,
                  max_bytes: int = DEFAULT_MAX_XML_BYTES) -> tuple[str, str]:
    """Export a score for every input XML, including an ERROR row for each unreadable scan."""
    folder = Path(folder_path)
    # Enumerate before creating the output: by default, input and output are the same directory.
    labels = _input_labels(folder)
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
            for path, label in sorted(labels.items(), key=lambda item: item[1]):
                _, findings, score = analyze_file(path, max_bytes)
                scores_writer.writerow((label, "ERROR" if score is None else score))
                findings_writer.writerows((label, f.ip, f.port, f.code, f.severity) for f in findings)
        staged_findings.replace(findings_path)
        staged_scores.replace(scores_path)
    return str(findings_path), str(scores_path)
