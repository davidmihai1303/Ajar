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
from netcheck.history import ScanRecord, store

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


def test_wrapped_scan_derives_analysis_but_preserves_explicit_empty_findings(tmp_path):
    db = tmp_path / "history.sqlite"
    before, findings, _ = analyze_file(FIXTURES / "V6a_before.xml")
    after = analyze_file(FIXTURES / "V6b_after.xml")[0]
    wrapped = ScanRecord(before)
    assert wrapped.findings == findings
    record = get_scan(save_scan(wrapped, db_path=db), db)
    assert (record.findings, record.score) == (findings, 60)
    assert compute_diff(wrapped, ScanRecord(after)).score_change == 40
    for clean in (ScanRecord(before, findings=[]), ScanRecord(before, findings=[], score=81)):
        saved = get_scan(save_scan(clean, db_path=db), db)
        assert (saved.findings, saved.score) == ([], clean.score if clean.score is not None else 100)
    assert compute_diff(wrapped, wrapped, curr_findings=[]).score_change == 40


def test_legacy_analysis_is_recovered_only_where_evidence_exists(tmp_path):
    db = tmp_path / "history.sqlite"
    before, findings, _ = analyze_file(FIXTURES / "V6a_before.xml")
    after = analyze_file(FIXTURES / "V6b_after.xml")[0]
    for sid, scan in (("before", before), ("after", after), ("unknown", replace(after, devices=()))):
        save_scan(scan, scan_id=sid, db_path=db)
    with sqlite3.connect(db) as conn:
        conn.execute("ALTER TABLE scans DROP COLUMN findings_available")
        conn.execute("UPDATE scans SET score = NULL")
        conn.execute("DELETE FROM findings")
        conn.execute("PRAGMA user_version = 1")
    assert [row["score"] for row in get_score_trend(db)] == [60, 100]
    diff = get_scan_diff_with_previous("after", db)
    assert diff.resolved_findings == findings and diff.score_change == 40
    unknown = get_scan("unknown", db)
    assert unknown.score is None and not unknown.findings_available
    save_scan(unknown, db_path=db)
    for old, new in ((before, get_scan("unknown", db)), (get_scan("unknown", db), before)):
        diff = compute_diff(old, new)
        assert diff.score_change is None and {diff.score_before, diff.score_after} == {None, 60}
        assert not diff.new_findings and not diff.resolved_findings and not diff.retained_findings
    save_scan(unknown, score=85, db_path=db)
    scored = get_scan("unknown", db)
    assert scored.score == 85 and not scored.findings_available
    assert compute_diff(scored, before).score_change == -25
    save_scan(scored, findings=[], db_path=db)
    clean = get_scan("unknown", db)
    assert clean.findings_available and clean.score == 100


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


def test_history_counts_each_ip_once_without_dropping_observations(tmp_path):
    db = tmp_path / "history.sqlite"
    before, findings, _ = analyze_file(FIXTURES / "V6a_before.xml")
    router, *others = before.devices
    first = replace(router, ports=router.ports[:1])
    last = replace(router, ports=router.ports[1:], hostname="updated-router.lan")
    repeated = replace(before, devices=(first, last, *others))
    original_id = save_scan(before, db_path=db)
    repeated_id = save_scan(repeated, db_path=db)
    history = store.get_device_history(router.ip, db)
    assert [(row["scan_id"], row["hostname"]) for row in history] == [
        (repeated_id, last.hostname), (original_id, router.hostname),
    ]
    assert [(row["device_count"], row["finding_count"]) for row in list_scans(db)] == [
        (len(before.devices), len(findings)), (len(before.devices), len(findings)),
    ]
    assert get_scan(repeated_id, db).scan == repeated
    diff = get_scan_diff_with_previous(repeated_id, db)
    assert not diff.new_devices and not diff.removed_devices
    assert not diff.newly_opened_ports and not diff.closed_ports
    assert diff.retained_findings == findings


@pytest.mark.parametrize("old_version", [1, 2, 3])
def test_upgrade_recovers_a_score_only_legacy_scan_in_a_mixed_database(tmp_path, old_version):
    db = tmp_path / "history.sqlite"
    scan, expected, score = analyze_file(FIXTURES / "V6a_before.xml")
    for sid, saved_score in (("match", score), ("conflict", 85), ("explicit", score)):
        save_scan(scan, findings=[], score=saved_score, scan_id=sid, db_path=db)
    save_scan(replace(scan, devices=(), started=None), findings=[], score=85, scan_id="header", db_path=db)
    save_scan(scan, findings=expected, score=85, scan_id="has-ledger", db_path=db)
    with sqlite3.connect(db) as conn:
        # Original-schema rows retained only the title. Later writers saved JSON for every port.
        conn.execute("UPDATE ports SET scripts = NULL WHERE scan_id IN ('match', 'conflict', 'has-ledger')")
        conn.execute("UPDATE scans SET started = NULL WHERE scan_id != 'explicit'")
        if old_version < 3:
            conn.execute("ALTER TABLE scans DROP COLUMN findings_available")
        conn.execute(f"PRAGMA user_version = {old_version}")
    store.init_db(db)
    store.init_db(db)
    restored = get_scan("match", db)
    assert restored.findings_available and (restored.score, restored.findings) == (score, expected)
    identical = compute_diff(restored, scan)
    assert identical.retained_findings == expected
    assert (identical.score_change, identical.new_findings, identical.resolved_findings) == (0, [], [])
    for sid in ("conflict", "header"):
        unavailable = get_scan(sid, db)
        assert (unavailable.score, unavailable.findings_available, unavailable.findings) == (85, False, [])
        diff = compute_diff(unavailable, scan)
        assert not diff.new_findings and not diff.resolved_findings
    explicit = get_scan("explicit", db)
    assert (explicit.score, explicit.findings_available, explicit.findings) == (score, True, [])
    known = get_scan("has-ledger", db)
    assert (known.score, known.findings) == (85, expected)


@pytest.mark.parametrize("upgrade", [False, True], ids=["new-records", "existing-database"])
def test_history_orders_equivalent_and_mixed_offsets_by_instant(tmp_path, upgrade):
    db = tmp_path / "history.sqlite"
    scan, findings, score = analyze_file(FIXTURES / "V6a_before.xml")
    stamps = {
        "later": "2026-05-01T08:30:00.000001Z",
        "early": "2026-05-01T10:00:00+03:00",
        "tied": "2026-05-01T07:00:00",
    }
    for sid, stamp in stamps.items():
        save_scan(ScanRecord(scan, findings, score, created_at=stamp), scan_id=sid, db_path=db)
    if upgrade:
        with sqlite3.connect(db) as conn:
            conn.execute("ALTER TABLE scans DROP COLUMN findings_available")
            conn.executemany("UPDATE scans SET created_at = ? WHERE scan_id = ?",
                             [(stamp, sid) for sid, stamp in stamps.items()])
            conn.execute("PRAGMA user_version = 1")
    expected = ["later", "tied", "early"]
    assert [row["scan_id"] for row in list_scans(db)] == expected
    assert [row["scan_id"] for row in store.get_device_history(scan.devices[0].ip, db)] == expected
    assert [row["scan_id"] for row in get_score_trend(db)] == expected[::-1]
    assert store.get_latest_scan(db).scan_id == "later"
    assert get_scan_diff_with_previous("later", db).prev_scan_id == "tied"
    assert get_scan_diff_with_previous("tied", db).prev_scan_id == "early"
    assert get_scan_diff_with_previous("early", db) is None
    assert get_scan("early", db).created_at == get_scan("tied", db).created_at == "2026-05-01T07:00:00+00:00"


def test_invalid_legacy_dates_do_not_block_other_history(tmp_path):
    db = tmp_path / "history.sqlite"
    scan = analyze_file(FIXTURES / "V6a_before.xml")[0]
    for sid in ("dated", "undated"):
        save_scan(scan, scan_id=sid, db_path=db)
    with sqlite3.connect(db) as conn:
        conn.execute("ALTER TABLE scans DROP COLUMN findings_available")
        conn.execute("UPDATE scans SET created_at = 'invalid'")
        conn.execute("UPDATE scans SET started = NULL WHERE scan_id = 'undated'")
        conn.execute("PRAGMA user_version = 1")
    assert get_scan("dated", db).created_at == datetime.fromtimestamp(scan.started, timezone.utc).isoformat()
    assert get_scan("undated", db).created_at == ""
    save_scan(get_scan("undated", db), db_path=db)
    assert get_scan("undated", db).created_at == ""
    assert get_scan_diff_with_previous("dated", db) is None
    assert get_scan_diff_with_previous("undated", db) is None
    assert [entry["scan_id"] for entry in get_score_trend(db)] == ["dated"]
    with pytest.raises(ValueError):
        save_scan(ScanRecord(scan, created_at="invalid"), scan_id="dated", db_path=db)
    assert store.get_latest_scan(db).scan_id == "dated"


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
        # Earlier scan of the same device: the original writer accepted its score alone.
        conn.execute("INSERT INTO scans VALUES (?, '2026-10-31T00:00:00+00:00', 'old.xml', 90, NULL)", (public_id,))
        conn.execute("INSERT INTO devices VALUES (2, ?, '192.0.2.5', '', 'RouterCo', '', 'router')", (public_id,))
        conn.execute("INSERT INTO ports VALUES (2, ?, '192.0.2.5', 1900, 'udp', 'open', 'upnp', '', '', '', '')",
                     (public_id,))
    store.init_db(db)
    store.init_db(db)
    summary, original = list_scans(db)
    assert get_scan(public_id, db).scan_id == original["scan_id"] == public_id
    assert private_id not in str(summary)
    assert summary["file_name"] == "capture-D8:43:AE:xx:xx:xx.xml"
    record = get_scan(summary["scan_id"], db)
    assert record.score == 90 and record.scan.started is None
    assert [entry["score"] for entry in get_score_trend(db)] == [90, 90]
    diff = get_scan_diff_with_previous(record.scan_id, db)
    assert (diff.new_findings, diff.resolved_findings, diff.retained_findings) == ([], [], record.findings)
    assert record.findings[0].protocol == "udp"
    assert record.devices[0].ports[0].port == 1900
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
