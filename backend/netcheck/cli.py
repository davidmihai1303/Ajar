"""Offline scan analysis commands for the folder export and single-file jury check.

  netcheck analyze <folder|file.xml> [--out DIR]   -> DIR/findings.csv + DIR/scores.csv
  netcheck analyze-file <file.xml>                  -> readable findings + score of one file

User-facing text is printed in Romanian and English (AGENTS.md: everything the user sees is
bilingual), Romanian first. Scan text and scan file names shown on screen are
MAC-masked. The CSV keeps the real file name so it matches the jury's answer key
(see analysis.export.export_folder). Output paths chosen by the user are printed as they are:
masking them would print a path that does not exist (e.g. a folder whose name has 12 hex digits).
"""
import argparse
import csv
import sys
from pathlib import Path

from netcheck import config
from netcheck.analysis.export import analyze_file, export_folder
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


def _print_summary(scores_csv: str) -> None:
    """One line per scan file: masked name and score (or ERROR)."""
    with open(scores_csv, encoding="utf-8", newline="") as fh:
        rows = [(mask_macs_in_text(name), score) for name, score in list(csv.reader(fh))[1:]]
    width = max((len(name) for name, _ in rows), default=0)
    for name, score in rows:
        print(f"  {name:<{width}}  {score:>5}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netcheck")
    subparsers = parser.add_subparsers(dest="command", required=True)
    folder = subparsers.add_parser("analyze", help=_text("Analizează un dosar sau un fișier XML",
                                                         "Analyze a folder of XML scans or one XML file"))
    folder.add_argument("folder", type=Path)
    folder.add_argument("--out", "-o", type=Path, help=_text("Dosarul pentru CSV", "Directory for CSV output"))
    single = subparsers.add_parser("analyze-file", help=_text("Analizează un fișier XML", "Analyze one XML scan"))
    single.add_argument("file", type=Path)
    args = parser.parse_args(argv)

    if args.command == "analyze":
        default_out = args.folder.parent if args.folder.is_file() else args.folder
        try:
            paths = export_folder(args.folder, args.out or default_out, max_bytes=config.MAX_XML_BYTES)
        except OSError as exc:
            print(_text("Eroare la export", "Export failed"), mask_macs_in_text(str(exc)), file=sys.stderr)
            return 1
        _print_summary(paths[1])
        for path in paths:
            print(path)
        return 0

    scan, findings, score = analyze_file(args.file, max_bytes=config.MAX_XML_BYTES)
    if not scan.ok:
        print(_text("EROARE: fișierul nu poate fi analizat", "ERROR: could not analyze file"), scan.file,
              file=sys.stderr)
        print(f"  {_reason(scan.error)}", file=sys.stderr)
        return 1
    print(f"{_text('Fișier', 'File')}: {scan.file}")
    print(f"{_text('Scor', 'Score')}: {score}")
    print(f"{_text('Constatări', 'Findings')}: {len(findings)}")
    for finding in findings:
        endpoint = finding.ip if finding.port is None else f"{finding.ip} {finding.protocol}/{finding.port}"
        print(f"  {endpoint} {finding.code} ({finding.severity})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
