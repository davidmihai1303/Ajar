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

from netcheck.analysis.models import Device, Finding, Port, ScanResult
from netcheck.analysis.privacy import mask_mac, mask_macs_in_text, mask_scan_filename
from netcheck.config import DB_PATH

from .diff import ScanDiff, compute_diff
from .records import ScanRecord, analysis_for
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
    record = scan if isinstance(scan, ScanRecord) else ScanRecord(scan)
    sid = scan_id or record.scan_id or uuid4().hex
    if mask_macs_in_text(sid) != sid:
        raise ValueError("Scan ID must not contain a MAC address; omit it to generate an ID")

    fname = mask_scan_filename(record.file)
    started = record.scan.started
    scan_time = None
    if started is not None:
        try:
            scan_time = datetime.fromtimestamp(started, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            started = None
    created_at = record.created_at or (scan_time or datetime.now(timezone.utc)).isoformat()
    all_findings, final_score = analysis_for(scan, findings, score) if scan.ok else ((), None)
    init_db(db_path)
    with _get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scans (scan_id, created_at, file_name, score, error, started)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET created_at = excluded.created_at,
                file_name = excluded.file_name, score = excluded.score, error = excluded.error,
                started = excluded.started
            """,
            (sid, created_at, fname, final_score, record.error, started),
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

        for f in all_findings:
            conn.execute(
                """
                INSERT INTO findings (scan_id, ip, port_number, finding_code, severity, points, evidence, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (sid, f.ip, f.port, f.code, f.severity, f.points, f.evidence, f.protocol),
            )

    return sid


def get_scan(scan_id: str, db_path: str = DB_PATH) -> Optional[ScanRecord]:
    """Retrieve a complete ScanRecord by scan_id."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        conn.execute("BEGIN")
        return _read_scan(conn, scan_id)


def _read_scan(conn: sqlite3.Connection, scan_id: str) -> Optional[ScanRecord]:
    scan_row = conn.execute(
        "SELECT scan_id, created_at, file_name, score, error, started FROM scans WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()

    if not scan_row:
        return None

    # Fetch devices
    dev_rows = conn.execute(
        "SELECT id, ip, mac, vendor, hostname, device_type FROM devices WHERE scan_id = ? ORDER BY id",
        (scan_id,),
    ).fetchall()

    # Fetch ports
    port_rows = conn.execute(
        """
        SELECT device_id, port_number, protocol, state, service_name, product, version, tunnel, title, extrainfo, scripts
        FROM ports WHERE scan_id = ? ORDER BY id
        """,
        (scan_id,),
    ).fetchall()

    ports_by_device: dict[int, list[Port]] = {}
    for pr in port_rows:
        scripts = json.loads(pr["scripts"]) if pr["scripts"] is not None else {}
        if pr["scripts"] is None and pr["title"]:
            scripts["http-title"] = pr["title"]
        p = Port(
            protocol=pr["protocol"],
            port=pr["port_number"],
            state=pr["state"],
            service=pr["service_name"] or "",
            product=pr["product"] or "",
            version=pr["version"] or "",
            tunnel=pr["tunnel"] or "",
            extrainfo=pr["extrainfo"] or "",
            scripts=scripts,
        )
        ports_by_device.setdefault(pr["device_id"], []).append(p)

    devices: list[Device] = []
    for dr in dev_rows:
        ip = dr["ip"]
        devices.append(
            Device(
                ip=ip,
                mac_masked=dr["mac"] or "",
                vendor=dr["vendor"] or "",
                hostname=dr["hostname"] or "",
                device_type=dr["device_type"] or "unknown",
                ports=tuple(ports_by_device.get(dr["id"], [])),
            )
        )

    # Fetch findings
    finding_rows = conn.execute(
        """
        SELECT ip, port_number, finding_code, severity, points, evidence, protocol
        FROM findings WHERE scan_id = ? ORDER BY id
        """,
        (scan_id,),
    ).fetchall()

    findings: list[Finding] = []
    for fr in finding_rows:
        findings.append(
            Finding(
                code=fr["finding_code"],
                severity=fr["severity"],
                points=fr["points"],
                ip=fr["ip"],
                port=fr["port_number"],
                protocol=fr["protocol"] or "",
                evidence=fr["evidence"] or "",
            )
        )

    scan_result = ScanResult(
        file=scan_row["file_name"] or scan_row["scan_id"],
        devices=tuple(devices),
        error=scan_row["error"],
        started=scan_row["started"],
    )

    return ScanRecord(
        scan=scan_result,
        findings=findings,
        score=scan_row["score"],
        created_at=scan_row["created_at"],
        scan_id=scan_row["scan_id"],
    )


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
        latest = conn.execute("SELECT scan_id FROM scans ORDER BY created_at DESC, rowid DESC LIMIT 1").fetchone()
        return _read_scan(conn, latest["scan_id"]) if latest else None


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
            WHERE error IS NULL AND score IS NOT NULL
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
        curr = _read_scan(conn, scan_id)
        if curr is None or not curr.ok:
            return None
        previous = conn.execute(
            """
            SELECT p.scan_id FROM scans p JOIN scans c ON c.scan_id = ?
            WHERE p.error IS NULL AND (p.created_at, p.rowid) < (c.created_at, c.rowid)
            ORDER BY p.created_at DESC, p.rowid DESC LIMIT 1
            """,
            (scan_id,),
        ).fetchone()
        if previous is None:
            return None
        prev = _read_scan(conn, previous["scan_id"])
    return compute_diff(prev, curr) if prev is not None else None
