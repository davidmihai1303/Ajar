# Lab scans (test fixtures)

`lab_before.xml` and `lab_after.xml` are byte-identical copies of the current before/after pair in
[`lab/scans/`](../../../../lab/scans/), checked by `tests/test_lab.py`.

After a new lab scan:
1. Mask MACs: keep the maker part, zero the device part (`AA:BB:CC:00:00:00`). Keep `vendor`.
2. Put the pair in `lab/scans/` (`scan_<timestamp>_before.xml`, `scan_<timestamp>_after.xml`).
3. Copy them here as `lab_before.xml` and `lab_after.xml`.

The test requires ≥ 3 targets besides the scanner, ≥ 5 finding types before, ≥ 2 fixed findings
and a better score after.
