"""Standard CSV results export (FR-15).

Produces findings.csv and scores.csv for a list of ScanResults.
Deterministic sorting: file -> IP (numeric) -> port (numeric, empty last) -> code.
Severity lowercase. Unreadable file -> ERROR in scores.csv, continue with others.
"""
from __future__ import annotations

import csv
import ipaddress
from pathlib import Path
from typing import Iterable, List

from netcheck.analysis.models import ScanResult


def _ip_sort_key(ip_str: str) -> tuple:
    """Parse IPv4 for numeric sorting."""
    try:
        return (0, int(ipaddress.IPv4Address(ip_str)))
    except Exception:
        return (1, ip_str)


def _port_sort_key(port: int | None) -> tuple:
    """Empty port last, otherwise numerical."""
    if port is None:
        return (1, 0)
    return (0, port)


def export_results(
    results: Iterable[ScanResult],
    output_dir: str | Path,
) -> tuple[Path, Path]:
    """Write findings.csv and scores.csv into output_dir.

    Returns (findings_csv_path, scores_csv_path).
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    findings_path = out / "findings.csv"
    scores_path = out / "scores.csv"

    # Flatten and sort all findings
    finding_rows: List[dict] = []
    for res in results:
        if res.error:
            # Files with errors produce no finding rows
            continue
        for f in res.findings:
            finding_rows.append(
                {
                    "file": res.file_name,
                    "ip": f.ip,
                    "port": f.port,
                    "finding_code": f.code,
                    "severity": f.severity.lower(),
                }
            )

    # Sort: file -> IP (numeric) -> port (numeric, empty last) -> code
    finding_rows.sort(
        key=lambda r: (
            r["file"],
            _ip_sort_key(r["ip"]),
            _port_sort_key(r["port"]),
            r["finding_code"],
        )
    )

    with open(findings_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "ip", "port", "finding_code", "severity"])
        for r in finding_rows:
            port_val = "" if r["port"] is None else str(r["port"])
            writer.writerow([r["file"], r["ip"], port_val, r["finding_code"], r["severity"]])

    # Scores: one row per file, sorted by file name
    sorted_results = sorted(results, key=lambda res: res.file_name)
    with open(scores_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "network_score"])
        for res in sorted_results:
            score_val = "ERROR" if res.error or res.score is None else str(res.score)
            writer.writerow([res.file_name, score_val])

    return findings_path, scores_path
