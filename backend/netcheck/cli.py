"""Offline scan analysis commands for the folder export and single-file jury check."""
import argparse
import sys
from pathlib import Path

from netcheck import config
from netcheck.analysis.export import analyze_file, export_folder, single_file_label
from netcheck.analysis.privacy import mask_macs_in_text


def _text(ro: str, en: str) -> str:
    return ro if config.DEFAULT_LANG == "ro" else en


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netcheck")
    subparsers = parser.add_subparsers(dest="command", required=True)
    folder = subparsers.add_parser("analyze", help=_text("Analizează un dosar XML", "Analyze a folder of XML scans"))
    folder.add_argument("folder", type=Path)
    folder.add_argument("--out", "-o", type=Path, help=_text("Dosarul pentru CSV", "Directory for CSV output"))
    single = subparsers.add_parser("analyze-file", help=_text("Analizează un fișier XML", "Analyze one XML scan"))
    single.add_argument("file", type=Path)
    args = parser.parse_args(argv)

    if args.command == "analyze":
        try:
            paths = export_folder(args.folder, args.out or args.folder, max_bytes=config.MAX_XML_BYTES)
        except OSError as exc:
            print(_text("Eroare la export", "Export failed"), mask_macs_in_text(str(exc)), file=sys.stderr)
            return 1
        for path in paths:
            print(mask_macs_in_text(path))
        return 0

    scan, findings, score = analyze_file(args.file, max_bytes=config.MAX_XML_BYTES)
    label = single_file_label(args.file, scan.file)
    if not scan.ok:
        print(_text("EROARE: fișierul nu poate fi analizat", "ERROR: could not analyze file"), label,
              file=sys.stderr)
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
