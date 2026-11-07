"""Re-running folder analysis must produce the same CSV bytes."""
from pathlib import Path

from netcheck.analysis.export import export_folder


def test_three_exports_match(tmp_path):
    fixtures = Path(__file__).parent / "fixtures" / "validation"
    runs = []
    for _ in range(3):
        files = export_folder(fixtures, tmp_path)
        runs.append(tuple(Path(file).read_bytes() for file in files))
    assert runs[0] == runs[1] == runs[2]
