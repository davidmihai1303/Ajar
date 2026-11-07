"""Exercise persistence and comparisons using the same scans as the offline analyzer."""
import sqlite3
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from netcheck.analysis.export import analyze_file
from netcheck.analysis.parser import parse_bytes
from netcheck.history import compute_diff, get_scan, get_scan_diff_with_previous, get_score_trend, list_scans, save_scan
from netcheck.history import store

FIXTURES = Path(__file__).parent / "fixtures" / "validation"


def test_repeated_filename_records_both_scans_and_diffs_the_previous_success(tmp_path):
    db = tmp_path / "history.sqlite"
    before, findings, _ = analyze_file(FIXTURES / "V6a_before.xml")
    after, _, _ = analyze_file(FIXTURES / "V6b_after.xml")
    broken, _, _ = analyze_file(FIXTURES / "V7_broken.xml")
    scans = [replace(scan, file="scan.xml", started=before.started) for scan in (before, broken, after)]
    first, failed, last = [save_scan(scan, db_path=db) for scan in scans]
    assert len({first, failed, last}) == 3
    assert [entry["scan_id"] for entry in list_scans(db)] == [last, failed, first]
    assert store.get_latest_scan(db).scan_id == last
    assert [entry["score"] for entry in get_score_trend(db)] == [60, 100]
    assert get_scan_diff_with_previous(failed, db) is None
    assert compute_diff(scans[0], scans[1]) is None
    assert compute_diff(scans[1], scans[2]) is None
    # A retry using an explicit ID keeps the original tie-break position.
    assert save_scan(scans[0], scan_id=first, db_path=db) == first
    diff = get_scan_diff_with_previous(last, db)
    assert diff.prev_scan_id == first
    assert diff.score_change == 40
    assert diff.resolved_findings == findings
    assert not diff.new_devices and not diff.removed_devices


def test_effective_findings_and_scores_for_raw_and_loaded_scans(tmp_path):
    before, findings, _ = analyze_file(FIXTURES / "V6a_before.xml")
    after, _, _ = analyze_file(FIXTURES / "V6b_after.xml")
    assert compute_diff(before, after, findings, []).score_change == 40
    assert compute_diff(before, after).score_change == 40
    db = tmp_path / "history.sqlite"
    record = get_scan(save_scan(before, db_path=db), db)
    diff = compute_diff(record, record, curr_findings=[])
    assert (diff.score_before, diff.score_after, diff.score_change) == (60, 100, 40)


def test_round_trip_preserves_all_scan_and_finding_fields(tmp_path):
    db = tmp_path / "history.sqlite"
    for path in sorted(FIXTURES.glob("*.xml")):
        scan, findings, score = analyze_file(path)
        record = get_scan(save_scan(scan, findings, score, db_path=db), db)
        assert (record.scan, record.findings, record.score) == (scan, findings, score)
    # Two host records can have the same IP. Keep their individual port observations.
    original = analyze_file(FIXTURES / "V1_home_basic.xml")[0]
    device = original.devices[0]
    port = replace(device.ports[0], extrainfo="release edition", scripts={"http-title": "Router", "inventory": "v3"})
    scan = replace(original, devices=(replace(device, ports=(port,)), replace(device, ports=())))
    assert get_scan(save_scan(scan, db_path=db), db).scan == scan


def test_private_explicit_id_and_out_of_range_scan_time(tmp_path):
    db = tmp_path / "history.sqlite"
    raw = "printer-50-C7-BF-39-0C-8C.xml"
    scan = parse_bytes(b'<nmaprun start="99999999999999999999"/>', raw)
    with pytest.raises(ValueError, match="Scan ID"):
        save_scan(scan, scan_id=raw, db_path=db)
    earliest = datetime.now(timezone.utc)
    sid = save_scan(scan, db_path=db)
    record = get_scan(sid, db)
    assert record.scan.started is None
    assert earliest <= datetime.fromisoformat(record.created_at) <= datetime.now(timezone.utc)
    assert "50-C7-BF-39-0C-8C" not in repr(list_scans(db))
    assert record.file == "printer-50:C7:BF:xx:xx:xx.xml"


def test_concurrent_replacement_cannot_mix_header_and_findings(tmp_path, monkeypatch):
    db = tmp_path / "history.sqlite"
    before = analyze_file(FIXTURES / "V4_legacy.xml")
    after = analyze_file(FIXTURES / "V1_home_basic.xml")
    sid = save_scan(*before, db_path=db)
    # WAL allows a writer to commit while the reader's transaction is open.
    with sqlite3.connect(db) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
    connect = store._get_connection
    replaced = []

    @contextmanager
    def replace_after_header(path):
        with connect(path) as conn:
            def on_select(sql):
                if sql.lstrip().startswith("SELECT") and "FROM devices WHERE scan_id" in sql and not replaced:
                    replaced.append(save_scan(*after, scan_id=sid, db_path=db))
            conn.set_trace_callback(on_select)
            yield conn

    with monkeypatch.context() as patch:
        patch.setattr(store, "_get_connection", replace_after_header)
        snapshot = get_scan(sid, db)
    assert replaced == [sid]
    assert (snapshot.scan, snapshot.findings, snapshot.score) == before
    latest = get_scan(sid, db)
    assert (latest.scan, latest.findings, latest.score) == after


@pytest.mark.parametrize("sid", ["550e8400-e29b-41d4-a716-446655440000", "550E8400-E29B-41D4-A716-446655440000"])
def test_uuid4_can_be_retried_and_reused_from_a_diff(tmp_path, sid):
    db = tmp_path / "history.sqlite"
    before = analyze_file(FIXTURES / "V6a_before.xml")[0]
    after = analyze_file(FIXTURES / "V6b_after.xml")[0]
    save_scan(before, scan_id=sid, db_path=db)
    save_scan(before, scan_id=sid, db_path=db)
    last = save_scan(after, db_path=db)
    diff = get_scan_diff_with_previous(last, db).to_dict()
    assert diff["prev_scan_id"] == sid
    assert get_scan(diff["prev_scan_id"], db).scan == before
    assert len(list_scans(db)) == 2
    for private_id in ("550e8400-e29b-11d4-a716-446655440000", sid + "_50-C7-BF-39-0C-8C"):
        with pytest.raises(ValueError, match="Scan ID"):
            save_scan(before, scan_id=private_id, db_path=db)


def test_original_database_migrates_private_keys_and_keeps_known_evidence(tmp_path):
    db = tmp_path / "history.sqlite"
    private_id = "capture-D8-43-AE-2E-C3-6D"
    public_id = "550e8400-e29b-41d4-a716-446655440000"
    with sqlite3.connect(db) as conn:
        conn.executescript("""
            CREATE TABLE scans(scan_id TEXT PRIMARY KEY, created_at TEXT, file_name TEXT, score INTEGER, error TEXT);
            CREATE TABLE devices(id INTEGER PRIMARY KEY, scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                ip TEXT, mac TEXT, vendor TEXT, hostname TEXT, device_type TEXT);
            CREATE TABLE ports(id INTEGER PRIMARY KEY, scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                ip TEXT, port_number INTEGER, protocol TEXT, state TEXT, service_name TEXT, product TEXT,
                version TEXT, tunnel TEXT, title TEXT);
            CREATE TABLE findings(id INTEGER PRIMARY KEY, scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                ip TEXT, port_number INTEGER, finding_code TEXT, severity TEXT, points INTEGER, evidence TEXT);
        """)
        conn.execute("INSERT INTO scans VALUES (?, '2026-11-01T00:00:00+00:00', ?, NULL, NULL)",
                     (private_id, private_id + ".xml"))
        conn.execute("INSERT INTO devices VALUES (1, ?, '192.0.2.5', '', '', '', 'unknown')", (private_id,))
        conn.execute("INSERT INTO ports VALUES (1, ?, '192.0.2.5', 1900, 'udp', 'open', 'upnp', '', '', '', '')",
                     (private_id,))
        conn.execute("INSERT INTO findings VALUES (1, ?, '192.0.2.5', 1900, 'UPNP_EXPOSED', 'medium', 10, '')",
                     (private_id,))
        conn.execute("INSERT INTO scans VALUES (?, '2026-10-31T00:00:00+00:00', 'old.xml', 100, NULL)", (public_id,))
    store.init_db(db)
    store.init_db(db)
    summary, original = list_scans(db)
    assert get_scan(public_id, db).scan_id == original["scan_id"] == public_id
    assert private_id not in str(summary)
    assert summary["file_name"] == "capture-D8:43:AE:xx:xx:xx.xml"
    record = get_scan(summary["scan_id"], db)
    assert record.score == 90 and record.scan.started is None
    assert [entry["score"] for entry in get_score_trend(db)] == [100, 90]
    assert record.findings[0].protocol == "udp"
    assert record.devices[0].ports[0].port == 1900
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
