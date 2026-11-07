"""CLI entry point: `netcheck analyze <folder> --out <dir>` (FR-05, FR-15), `netcheck serve`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from netcheck.analysis.export import export_results
from netcheck.analysis.parser import parse_nmap_xml


def analyze_folder(folder_path: str, out_dir: str) -> int:
    """Analyze all XML files in folder_path and write findings.csv and scores.csv to out_dir."""
    folder = Path(folder_path)
    if not folder.exists():
        print(f"Error: Folder '{folder_path}' does not exist.", file=sys.stderr)
        return 1

    xml_files = sorted(list(folder.glob("*.xml")))
    if not xml_files:
        print(f"Warning: No XML files found in '{folder_path}'.", file=sys.stderr)

    results = [parse_nmap_xml(f) for f in xml_files]
    findings_path, scores_path = export_results(results, out_dir)

    print(f"Analyzed {len(results)} files.")
    print(f"Exported findings to: {findings_path}")
    print(f"Exported scores to:   {scores_path}")
    return 0


def analyze_single_file(file_path: str) -> int:
    """Analyze a single XML file and print findings and score (live checks #1 and #5)."""
    p = Path(file_path)
    if not p.exists():
        print(f"Error: File '{file_path}' does not exist.", file=sys.stderr)
        return 1

    res = parse_nmap_xml(p)
    if res.error:
        print(f"File: {res.file_name}")
        print(f"Status: ERROR ({res.error})")
        print("Score: ERROR")
        return 0

    print(f"File: {res.file_name}")
    print(f"Score: {res.score}/100")
    print(f"Devices found: {len(res.devices)}")
    print(f"Findings ({len(res.findings)}):")
    for f in res.findings:
        port_str = f":{f.port}" if f.port is not None else ""
        print(f"  - [{f.severity.upper()}] {f.ip}{port_str} -> {f.code} ({f.points} pts)")
        if f.evidence:
            print(f"    Evidence: {f.evidence}")
    return 0


def main(args: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="netcheck",
        description="Local Network Security Checker - Analysis & API CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze <folder> [--out <dir>]
    p_analyze = subparsers.add_parser("analyze", help="Analyze all scan files in a folder and export CSVs")
    p_analyze.add_argument("folder", help="Directory containing nmap XML files")
    p_analyze.add_argument("--out", "-o", default="validation_results", help="Output directory for CSV files")

    # analyze-file <file>
    p_file = subparsers.add_parser("analyze-file", help="Analyze a single XML file and print details to stdout")
    p_file.add_argument("file", help="Path to an nmap XML file")

    # serve
    p_serve = subparsers.add_parser("serve", help="Run the FastAPI web backend")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8001, help="Port (default: 8001)")

    parsed = parser.parse_args(args)

    if parsed.command == "analyze":
        sys.exit(analyze_folder(parsed.folder, parsed.out))
    elif parsed.command == "analyze-file":
        sys.exit(analyze_single_file(parsed.file))
    elif parsed.command == "serve":
        try:
            import uvicorn
            uvicorn.run("netcheck.api.app:app", host=parsed.host, port=parsed.port, reload=False)
        except ImportError:
            print("Error: uvicorn is required to run the server.", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
