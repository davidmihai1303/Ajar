"""CLI entry point: `netcheck analyze <folder> --out <dir>` (FR-05, FR-15), `netcheck serve`."""

# TODO: argparse with subcommands:
#   analyze <folder> [--out DIR]  -> analysis.export.export_folder(...)
#   analyze-file <file.xml>       -> prints findings + score (live check #1 / #5)
#   serve                         -> uvicorn netcheck.api.app:app on 127.0.0.1


def main() -> None:
    raise SystemExit("not implemented yet")
