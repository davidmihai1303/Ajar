"""SQLite store: save ScanResult, list scans, delete all history (NFR-02 one-click delete).

Stores history locally in SQLite. Enforces foreign key constraints and
masks MAC addresses in all stored outputs.
"""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Generator, Optional
from uuid import uuid4

from netcheck.analysis.models import Finding, ScanResult
from netcheck.analysis.privacy import mask_mac, mask_macs_in_text, mask_scan_filename
from netcheck.config import DB_PATH

from .diff import ScanDiff, compute_diff
from .records import ScanRecord, analysis_for, public_scan_id, scan_start_time, utc_timestamp
from .rows import read_scan, write_findings
from .schema import ensure_schema


@contextlib.contextmanager
def _get_connection(db_path: str = DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Open SQLite connection with row factory, foreign keys enabled, and automatic closing."""
    dir_name = os.path.dirname(db_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH) -> None:
    """Initialize or migrate the local database before opening a read or write transaction."""
    with _get_connection(db_path) as conn:
        ensure_schema(conn)


def save_scan(
    scan: ScanResult | ScanRecord,
    findings: Sequence[Finding] | None = None,
    score: Optional[int] = None,
    scan_id: Optional[str] = None,
    db_path: str = DB_PATH,
) -> str:
    """Append a scan, or update the record identified by an explicit public ID."""
    if isinstance(scan, ScanRecord):
        record = scan
    else:
        record = ScanRecord(scan, findings=list(findings) if findings is not None else None)
    sid = scan_id or record.scan_id or uuid4().hex
    if public_scan_id(sid) != sid:
        raise ValueError("Scan ID must not contain a MAC address; omit it to generate an ID")

    fname = mask_scan_filename(record.file)
    started = record.scan.started
    scan_time = scan_start_time(started)
    if scan_time is None:
        started = None
    created_at = (utc_timestamp(record.created_at) if record.created_at
                  else (scan_time or datetime.now(timezone.utc)).isoformat())
    all_findings, final_score = analysis_for(record, findings, score) if scan.ok else ((), None)
    init_db(db_path)
    with _get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scans (scan_id, created_at, file_name, score, error, started, findings_available)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                created_at = CASE WHEN ? THEN excluded.created_at ELSE scans.created_at END,
                file_name = excluded.file_name, score = excluded.score, error = excluded.error,
                started = excluded.started, findings_available = excluded.findings_available
            """,
            (sid, created_at, fname, final_score, record.error, started, all_findings is not None,
             bool(record.created_at or scan_time)),
        )

        # Delete existing child rows if updating/replacing
        conn.execute("DELETE FROM devices WHERE scan_id = ?", (sid,))
        conn.execute("DELETE FROM ports WHERE scan_id = ?", (sid,))
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (sid,))

        for device in record.devices:
            mac = mask_mac(device.mac_masked) or mask_macs_in_text(device.mac_masked)
            cursor = conn.execute(
                """
                INSERT INTO devices (scan_id, ip, mac, vendor, hostname, device_type)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (sid, device.ip, mac, device.vendor, device.hostname, device.device_type),
            )
            for port in device.ports:
                conn.execute(
                    """
                    INSERT INTO ports (device_id, scan_id, ip, port_number, protocol, state,
                                       service_name, product, version, tunnel, title, extrainfo, scripts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (cursor.lastrowid, sid, device.ip, port.port, port.protocol, port.state,
                     port.service, port.product, port.version, port.tunnel, port.http_title,
                     port.extrainfo, json.dumps(port.scripts)),
                )

        if all_findings:
            write_findings(conn, sid, all_findings)

    return sid


def get_scan(scan_id: str, db_path: str = DB_PATH) -> Optional[ScanRecord]:
    """Retrieve a complete ScanRecord by scan_id."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        conn.execute("BEGIN")
        return read_scan(conn, scan_id)


def list_scans(db_path: str = DB_PATH) -> list[dict]:
    """Return summary list of all scans ordered by creation date descending."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
                s.scan_id,
                s.created_at,
                s.file_name,
                s.score,
                s.error,
                COUNT(DISTINCT d.id) AS device_count,
                COUNT(DISTINCT f.id) AS finding_count
            FROM scans s
            LEFT JOIN devices d ON s.scan_id = d.scan_id
            LEFT JOIN findings f ON s.scan_id = f.scan_id
            GROUP BY s.scan_id
            ORDER BY s.created_at DESC, s.rowid DESC
            """
        ).fetchall()

        return [
            {
                "scan_id": r["scan_id"],
                "created_at": r["created_at"],
                "file_name": r["file_name"],
                "score": r["score"],
                "error": r["error"],
                "device_count": r["device_count"],
                "finding_count": r["finding_count"],
            }
            for r in rows
        ]


def get_latest_scan(db_path: str = DB_PATH) -> Optional[ScanRecord]:
    """Retrieve the most recent ScanRecord, or None if history is empty."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        conn.execute("BEGIN")
        latest = conn.execute(
            "SELECT scan_id FROM scans WHERE created_at != '' ORDER BY created_at DESC, rowid DESC LIMIT 1"
        ).fetchone()
        return read_scan(conn, latest["scan_id"]) if latest else None


def delete_scan(scan_id: str, db_path: str = DB_PATH) -> bool:
    """Delete a single scan by scan_id. Returns True if deleted."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        return cursor.rowcount > 0


def delete_all_history(db_path: str = DB_PATH) -> None:
    """NFR-02: One-click 'delete my history' option. Completely removes all history."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM ports")
        conn.execute("DELETE FROM devices")
        conn.execute("DELETE FROM scans")

    conn_vacuum = sqlite3.connect(db_path, isolation_level=None)
    try:
        conn_vacuum.execute("VACUUM")
    finally:
        conn_vacuum.close()


def get_score_trend(db_path: str = DB_PATH) -> list[dict]:
    """FR-10: Score trend over time, ordered chronologically (oldest to newest)."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT scan_id, created_at, file_name, score
            FROM scans
            WHERE error IS NULL AND score IS NOT NULL AND created_at != ''
            ORDER BY created_at ASC, rowid ASC
            """
        ).fetchall()
        return [
            {
                "scan_id": r["scan_id"],
                "created_at": r["created_at"],
                "file_name": r["file_name"],
                "score": r["score"],
            }
            for r in rows
        ]


def get_device_history(ip: str, db_path: str = DB_PATH) -> list[dict]:
    """Get history of a specific device across scans by IP (FR-10)."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT s.scan_id, s.created_at, s.score, d.mac, d.vendor, d.hostname, d.device_type
            FROM devices d
            JOIN scans s ON d.scan_id = s.scan_id
            WHERE d.ip = ?
            ORDER BY s.created_at DESC, s.rowid DESC
            """,
            (ip,),
        ).fetchall()
        return [
            {
                "scan_id": r["scan_id"],
                "created_at": r["created_at"],
                "network_score": r["score"],
                "mac": r["mac"],
                "vendor": r["vendor"],
                "hostname": r["hostname"],
                "device_type": r["device_type"],
            }
            for r in rows
        ]


def get_scan_diff_with_previous(scan_id: str, db_path: str = DB_PATH) -> ScanDiff | None:
    """Compute difference between scan_id and the chronologically preceding scan (FR-10, FR-13)."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        conn.execute("BEGIN")
        curr = read_scan(conn, scan_id)
        if curr is None or not curr.ok:
            return None
        previous = conn.execute(
            """
            SELECT p.scan_id FROM scans p JOIN scans c ON c.scan_id = ?
            WHERE p.error IS NULL AND p.created_at != '' AND (p.created_at, p.rowid) < (c.created_at, c.rowid)
            ORDER BY p.created_at DESC, p.rowid DESC LIMIT 1
            """,
            (scan_id,),
        ).fetchone()
        if previous is None:
            return None
        prev = read_scan(conn, previous["scan_id"])
    return compute_diff(prev, curr) if prev is not None else None
