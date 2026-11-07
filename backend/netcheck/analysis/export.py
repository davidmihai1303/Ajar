"""findings.csv + scores.csv for a whole folder, deterministic order, ERROR rows for unreadable files (FR-15)."""
import csv
import ipaddress
import os
from typing import Sequence

from netcheck.analysis.models import Finding, ScanResult
from netcheck.analysis.parser import parse_xml_file


def sort_key_finding(f: Finding):
    """Sort key: file -> IP (numeric) -> port (numeric, empty last) -> code."""
    try:
        ip_num = int(ipaddress.ip_address(f.ip))
    except ValueError:
        ip_num = 0
    
    port_key = (0, f.port) if f.port is not None else (1, 0)
    return (f.file, ip_num, port_key, f.finding_code)


def write_findings_csv(findings: Sequence[Finding], out_path: str) -> None:
    """Write findings.csv with deterministic sorting and lowercase severity."""
    sorted_findings = sorted(findings, key=sort_key_finding)
    
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "ip", "port", "finding_code", "severity"])
        for item in sorted_findings:
            port_val = "" if item.port is None else str(item.port)
            writer.writerow([item.file, item.ip, port_val, item.finding_code, item.severity.lower()])


def write_scores_csv(results: Sequence[ScanResult], out_path: str) -> None:
    """Write scores.csv with deterministic file sorting, 'ERROR' for unreadable files."""
    sorted_results = sorted(results, key=lambda r: r.file)
    
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "network_score"])
        for r in sorted_results:
            score_val = "ERROR" if r.error or r.score is None else str(r.score)
            writer.writerow([r.file, score_val])


def export_folder(folder_path: str, out_dir: str) -> tuple[str, str]:
    """Parse all XML files in folder_path and write findings.csv and scores.csv to out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    
    xml_files = [
        f for f in os.listdir(folder_path)
        if f.lower().endswith(".xml") and os.path.isfile(os.path.join(folder_path, f))
    ]
    xml_files.sort()

    all_results: list[ScanResult] = []
    all_findings: list[Finding] = []

    for filename in xml_files:
        filepath = os.path.join(folder_path, filename)
        result = parse_xml_file(filepath)
        all_results.append(result)
        if not result.error:
            all_findings.extend(result.findings)

    findings_path = os.path.join(out_dir, "findings.csv")
    scores_path = os.path.join(out_dir, "scores.csv")

    write_findings_csv(all_findings, findings_path)
    write_scores_csv(all_results, scores_path)

    return findings_path, scores_path
