"""Own hotspot lab scans (NFR-10): scan_01 -> score 0, scan_03_after -> score 75, findings resolved.

The XML files come from the team's scanner laptop (see fixtures/lab/README.md). Until they are
copied in, these tests are reported as skipped, so the missing deliverable stays visible.
"""
from pathlib import Path

import pytest

from netcheck.analysis.export import analyze_file

LAB = Path(__file__).parent / "fixtures" / "lab"
BEFORE = LAB / "scan_01.xml"
AFTER = LAB / "scan_03_after.xml"
pytestmark = pytest.mark.skipif(not (BEFORE.exists() and AFTER.exists()), reason="lab scans not copied into fixtures/lab yet")


def test_lab_before_and_after_scores():
    assert analyze_file(BEFORE)[2] == 0
    assert analyze_file(AFTER)[2] == 75


def test_lab_has_five_finding_types_and_at_least_two_are_fixed():
    before = {(f.ip, f.port, f.code) for f in analyze_file(BEFORE)[1]}
    after = {(f.ip, f.port, f.code) for f in analyze_file(AFTER)[1]}
    assert len({code for _, _, code in before}) >= 5
    assert len(before - after) >= 2
