"""CLI entry point: `netcheck analyze <folder> --out <dir>` (FR-05, FR-15), `netcheck serve`."""
import argparse
import sys
from netcheck.analysis.export import export_folder
from netcheck.analysis.parser import parse_xml_file


def cmd_analyze(args: argparse.Namespace) -> int:
    out_dir = args.out or args.folder
    try:
        findings_path, scores_path = export_folder(args.folder, out_dir)
        print(f"Export completed:")
        print(f"  Findings: {findings_path}")
        print(f"  Scores:   {scores_path}")
        return 0
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        return 1


def cmd_analyze_file(args: argparse.Namespace) -> int:
    result = parse_xml_file(args.file)
    if result.error:
        print(f"ERROR: Could not parse '{args.file}'", file=sys.stderr)
        return 1
    print(f"File: {result.file}")
    print(f"Score: {result.score}")
    print(f"Findings ({len(result.findings)}):")
    for f in result.findings:
        port_str = f":{f.port}" if f.port is not None else ""
        print(f"  - [{f.severity.upper()}] {f.ip}{port_str} -> {f.finding_code}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    uvicorn.run("netcheck.api.app:app", host="127.0.0.1", port=8001)
    return 0


def main(argv: list[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(prog="netcheck")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze folder of XML files and output CSVs")
    p_analyze.add_argument("folder", help="Path to folder containing XML files")
    p_analyze.add_argument("--out", "-o", default="", help="Output directory for CSVs (defaults to folder)")
    p_analyze.set_defaults(func=cmd_analyze)

    # analyze-file
    p_file = subparsers.add_parser("analyze-file", help="Analyze single XML file and print findings")
    p_file.add_argument("file", help="Path to XML file")
    p_file.set_defaults(func=cmd_analyze_file)

    # serve
    p_serve = subparsers.add_parser("serve", help="Run the local web API server")
    p_serve.set_defaults(func=cmd_serve)

    parsed = parser.parse_args(argv)
    sys.exit(parsed.func(parsed))


if __name__ == "__main__":
    main()
