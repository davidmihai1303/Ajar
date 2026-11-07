"""Offline analysis and canonical CSV output for a folder of Nmap reports."""
import csv
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from .models import Finding, ScanResult
from .parser import DEFAULT_MAX_XML_BYTES, parse_scan
from .privacy import mask_macs_in_text, mask_scan_filename
from .publication import CSV_NAMES, csv_publication
from .rules import evaluate_devices
from .scoring import compute_score


def analyze_file(path: Path, max_bytes: int = DEFAULT_MAX_XML_BYTES) -> tuple[ScanResult, list[Finding], int | None]:
    scan = parse_scan(str(path), max_bytes=max_bytes)
    if not scan.ok:
        return scan, [], None
    findings = evaluate_devices(scan.devices)
    return scan, findings, compute_score(findings)


def _xml_inputs(folder: Path) -> Iterator[Path]:
    return (path for path in folder.iterdir() if path.suffix.lower() == ".xml" and path.is_file())


def scan_paths(input_path: str | Path) -> list[Path]:
    """Return one XML input or the XML files directly inside a directory, sorted by name."""
    source = Path(input_path)
    if source.is_file():
        if source.suffix.lower() != ".xml":
            raise OSError("Se acceptă doar fișiere .xml / Expected an .xml file")
        return [source]
    return sorted(_xml_inputs(source), key=lambda path: path.name)


def _scan_label(path: Path, max_bytes: int) -> str:
    name = mask_scan_filename(path.name)
    if name != mask_macs_in_text(path.name):
        # A timestamp-shaped token could also be a MAC recorded in this report.
        return parse_scan(str(path), max_bytes).file
    return name


def _unique_labels(names: dict[Path, str]) -> dict[Path, str]:
    groups: dict[str, list[Path]] = defaultdict(list)
    for path, name in names.items():
        groups[name].append(path)

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


def single_file_label(path: Path, masked_name: str, max_bytes: int = DEFAULT_MAX_XML_BYTES) -> str:
    if masked_name == path.name:
        return masked_name
    try:
        names = {path: masked_name}
        # Only siblings with this stem can claim the label or a numbered variant.
        stem = mask_macs_in_text(Path(masked_name).stem)
        for sibling in _xml_inputs(path.parent):
            if sibling != path and mask_macs_in_text(sibling.name).startswith(stem):
                names[sibling] = _scan_label(sibling, max_bytes)
        return _unique_labels(names)[path]
    except OSError:
        # A single file can still be readable in a directory the caller cannot list.
        return masked_name


def export_folder(folder_path: str | Path, out_dir: str | Path,
                  max_bytes: int = DEFAULT_MAX_XML_BYTES) -> tuple[str, str]:
    """Return the two published CSV paths."""
    paths, _ = export_scans(folder_path, out_dir, max_bytes)
    return paths


def export_scans(input_path: str | Path, out_dir: str | Path | None = None,
                 max_bytes: int = DEFAULT_MAX_XML_BYTES) -> tuple[tuple[str, str], list[tuple[str, str]]]:
    """Publish the CSVs and return their paths and this run's score rows in CSV order."""
    source = Path(input_path)
    paths = scan_paths(source)
    single_file = paths == [source]
    if single_file and out_dir is None:
        raise OSError("Pentru un singur fișier, specificați --out / For one XML file, specify --out")
    names = {path: _scan_label(path, max_bytes) for path in paths}
    if single_file:
        labels = {source: single_file_label(source, names[source], max_bytes)}
    else:
        labels = _unique_labels(names)
    output = source if out_dir is None else Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    findings_path, scores_path = (output / name for name in CSV_NAMES)
    score_rows = []
    with csv_publication(output) as staged:
        staged_findings = staged / findings_path.name
        staged_scores = staged / scores_path.name
        with (staged_findings.open("w", encoding="utf-8", newline="") as findings_file,
              staged_scores.open("w", encoding="utf-8", newline="") as scores_file):
            findings_writer = csv.writer(findings_file)
            scores_writer = csv.writer(scores_file)
            findings_writer.writerow(("file", "ip", "port", "finding_code", "severity"))
            scores_writer.writerow(("file", "network_score"))
            for path, label in sorted(labels.items(), key=lambda item: item[1]):
                scan, findings, score = analyze_file(path, max_bytes)
                if scan.file != names[path]:
                    raise OSError("Scan changed during export")
                row = (label, "ERROR" if score is None else str(score))
                scores_writer.writerow(row)
                score_rows.append(row)
                findings_writer.writerows((label, f.ip, f.port, f.code, f.severity) for f in findings)
    return (str(findings_path), str(scores_path)), score_rows
