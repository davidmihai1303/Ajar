"""Offline scan analysis commands for the folder export and single-file jury check.

  netcheck analyze <folder> [--out DIR]     -> folder export
  netcheck analyze <file.xml> --out DIR    -> one-file CSV export
  netcheck analyze-file <file.xml>         -> readable findings and score

The terminal summary uses the privacy-aware file labels written to the CSVs.
"""
import argparse
import sys
from pathlib import Path

from netcheck import config
from netcheck.analysis.export import analyze_file, export_scans, single_file_label
from netcheck.analysis.models import ERROR_NOT_NMAP, ERROR_TOO_LARGE, ERROR_UNREADABLE, ERROR_UNSAFE
from netcheck.analysis.privacy import mask_macs_in_text

ERROR_REASONS = {
    ERROR_UNREADABLE: ("fișierul lipsește, este gol, trunchiat sau scanarea nmap a eșuat",
                       "the file is missing, empty, truncated, or the nmap run failed"),
    ERROR_TOO_LARGE: ("fișierul depășește limita de mărime", "the file is larger than the size limit"),
    ERROR_UNSAFE: ("fișierul conține construcții XML nesigure și a fost refuzat",
                   "the file contains unsafe XML and was refused"),
    ERROR_NOT_NMAP: ("fișierul nu este un raport nmap", "the file is not an nmap report"),
}


def _text(ro: str, en: str) -> str:
    """Both languages, always Romanian first, so labels read the same in every terminal and log."""
    return f"{ro} / {en}"


def _reason(error: str) -> str:
    ro, en = ERROR_REASONS.get(error, ("eroare necunoscută", "unknown error"))
    return _text(ro, en)


def _print_summary(rows: list[tuple[str, str]]) -> None:
    width = max((len(name) for name, _ in rows), default=0)
    for name, score in rows:
        print(f"  {name:<{width}}  {score:>5}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netcheck")
    subparsers = parser.add_subparsers(dest="command", required=True)
    folder = subparsers.add_parser("analyze", help=_text("Analizează un dosar sau un fișier XML",
                                                         "Analyze a folder of XML scans or one XML file"))
    folder.add_argument("folder", type=Path)
    folder.add_argument("--out", "-o", type=Path,
                        help=_text("Dosarul CSV (obligatoriu pentru un fișier)",
                                   "CSV output directory (required for a single file)"))
    single = subparsers.add_parser("analyze-file", help=_text("Analizează un fișier XML", "Analyze one XML scan"))
    single.add_argument("file", type=Path)
    args = parser.parse_args(argv)

    if args.command == "analyze":
        try:
            paths, rows = export_scans(args.folder, args.out, max_bytes=config.MAX_XML_BYTES)
        except OSError as exc:
            print(_text("Eroare la export", "Export failed"), mask_macs_in_text(str(exc)), file=sys.stderr)
            return 1
        _print_summary(rows)
        for path in paths:
            print(path if mask_macs_in_text(path) == path else Path(path).name)
        return 0

    scan, findings, score = analyze_file(args.file, max_bytes=config.MAX_XML_BYTES)
    label = single_file_label(args.file, scan.file, max_bytes=config.MAX_XML_BYTES)
    if not scan.ok:
        print(_text("EROARE: fișierul nu poate fi analizat", "ERROR: could not analyze file"), label,
              file=sys.stderr)
        print(f"  {_reason(scan.error)}", file=sys.stderr)
        return 1
    print(f"{_text('Fișier', 'File')}: {label}")
    print(f"{_text('Scor', 'Score')}: {score}")
    print(f"{_text('Constatări', 'Findings')}: {len(findings)}")
    for finding in findings:
        endpoint = finding.ip if finding.port is None else f"{finding.ip} {finding.protocol}/{finding.port}"
        print(f"  {endpoint} {finding.code} ({finding.severity})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
