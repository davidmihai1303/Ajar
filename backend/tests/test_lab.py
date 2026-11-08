"""Own hotspot lab scans (NFR-10, brief "Minimum lab"): a before/after pair from our own hotspot.

fixtures/lab/lab_before.xml and lab_after.xml are copies of the current pair in lab/scans/
(MACs masked: maker part kept, device part zeroed). The checks follow the brief, not fixed scores,
so a better rescan only needs the two files replaced (see fixtures/lab/README.md):
- at least 3 target devices besides the scanner laptop,
- at least 5 different finding types before the fixes,
- at least 2 findings fixed, and the score improves.
The same checks always run on the Validation Set's before/after pair as well.
"""
from pathlib import Path

import pytest

from netcheck.analysis.export import analyze_file

FIXTURES = Path(__file__).parent / "fixtures"
BEFORE = FIXTURES / "lab" / "lab_before.xml"
AFTER = FIXTURES / "lab" / "lab_after.xml"
# Only present in a repository checkout (the app image copies backend/tests, not lab/).
LAB_SCANS = Path(__file__).resolve().parents[2] / "lab" / "scans"


def check_before_after(before: Path, after: Path, min_types: int, min_devices: int) -> None:
    scan_before, findings_before, score_before = analyze_file(before)
    _, findings_after, score_after = analyze_file(after)
    assert score_before is not None and score_after is not None
    assert score_after > score_before
    found_before = {(f.ip, f.port, f.code) for f in findings_before}
    found_after = {(f.ip, f.port, f.code) for f in findings_after}
    assert len({code for _, _, code in found_before}) >= min_types
    assert len(found_before - found_after) >= 2
    assert sum(1 for device in scan_before.devices if device.ports) >= min_devices


def test_before_after_check_on_the_validation_pair():
    folder = FIXTURES / "validation"
    check_before_after(folder / "V6a_before.xml", folder / "V6b_after.xml", 3, 2)


def test_lab_before_and_after():
    # 3 targets + the scanner laptop, which is a host with open ports too.
    check_before_after(BEFORE, AFTER, 5, 4)


def test_lab_scans_keep_macs_masked():
    for path in (BEFORE, AFTER):
        scan, _, _ = analyze_file(path)
        assert all(not d.mac_masked or d.mac_masked.endswith(":xx:xx:xx") for d in scan.devices)
        text = path.read_text(encoding="utf-8")
        assert 'addrtype="mac"' not in text.replace(':00:00:00" addrtype="mac"', "")


@pytest.mark.skipif(not LAB_SCANS.is_dir(), reason="lab/scans is only in a repository checkout")
def test_lab_fixtures_match_lab_scans():
    published = {path.read_bytes() for path in LAB_SCANS.glob("*.xml")}
    assert BEFORE.read_bytes() in published and AFTER.read_bytes() in published
