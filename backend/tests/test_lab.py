"""Own hotspot lab scans (NFR-10): scan_01 -> score 0, scan_03_after -> score 75, findings resolved.

The XML files come from the team's scanner laptop (see fixtures/lab/README.md). Until they are
copied in, the lab tests are reported as skipped, so the missing deliverable stays visible.
The checks themselves always run, on the Validation Set's before/after pair.
"""
from pathlib import Path

import pytest

from netcheck.analysis.export import analyze_file

FIXTURES = Path(__file__).parent / "fixtures"
BEFORE = FIXTURES / "lab" / "scan_01.xml"
AFTER = FIXTURES / "lab" / "scan_03_after.xml"
needs_lab = pytest.mark.skipif(not (BEFORE.exists() and AFTER.exists()), reason="lab scans not copied into fixtures/lab yet")


def check_before_after(before: Path, after: Path, scores: tuple[int, int], min_types: int) -> None:
    assert (analyze_file(before)[2], analyze_file(after)[2]) == scores
    found_before = {(f.ip, f.port, f.code) for f in analyze_file(before)[1]}
    found_after = {(f.ip, f.port, f.code) for f in analyze_file(after)[1]}
    assert len({code for _, _, code in found_before}) >= min_types
    assert len(found_before - found_after) >= 2


def test_before_after_check_on_the_validation_pair():
    folder = FIXTURES / "validation"
    check_before_after(folder / "V6a_before.xml", folder / "V6b_after.xml", (60, 100), 3)


@needs_lab
def test_lab_before_and_after():
    check_before_after(BEFORE, AFTER, (0, 75), 5)
