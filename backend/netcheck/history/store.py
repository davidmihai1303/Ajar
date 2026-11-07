"""SQLite store: save ScanResult, list scans, delete all history (NFR-02 one-click delete).

Stores history locally in SQLite. Enforces foreign key constraints and
masks MAC addresses in all stored outputs.
"""
from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Generator, Optional

from netcheck.analysis.models import Device, Finding, Port, ScanResult
from netcheck.analysis.privacy import mask_mac
from netcheck.config import DB_PATH


@dataclass
class ScanRecord:
    """Wrapper around ScanResult retrieved from the SQLite history database."""

    scan: ScanResult
    findings: list[Finding] = field(default_factory=list)
    score: Optional[int] = None
    created_at: str = ""
    scan_id: str = ""

    @property
    def file(self) -> str:
        return self.scan.file

    @property
    def file_name(self) -> str:
        return self.scan.file

    @property
    def timestamp(self) -> str:
        return self.created_at

    @property
    def devices(self) -> tuple[Device, ...]:
        return self.scan.devices

    @property
    def error(self) -> Optional[str]:
        return self.scan.error

    @property
    def ok(self) -> bool:
        return self.scan.ok


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
    """Initialize SQLite schema if it does not exist."""
    with _get_connection(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                file_name TEXT,
                score INTEGER,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                mac TEXT,
                vendor TEXT,
                hostname TEXT,
                device_type TEXT
            );

            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                port_number INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service_name TEXT,
                product TEXT,
                version TEXT,
                tunnel TEXT,
                title TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                port_number INTEGER,
                finding_code TEXT NOT NULL,
                severity TEXT NOT NULL,
                points INTEGER NOT NULL,
                evidence TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id);
            CREATE INDEX IF NOT EXISTS idx_ports_scan_id ON ports(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
        """)


def save_scan(
    scan: Any,
    findings: Sequence[Finding] = (),
    score: Optional[int] = None,
    scan_id: Optional[str] = None,
    db_path: str = DB_PATH,
) -> str:
    """Save a ScanResult / ScanRecord into the SQLite database. Returns scan_id."""
    init_db(db_path)

    sid = (
        scan_id
        or getattr(scan, "scan_id", None)
        or getattr(scan, "file", None)
        or getattr(scan, "file_name", None)
        or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    )
    fname = getattr(scan, "file", getattr(scan, "file_name", sid))
    created_at = (
        getattr(scan, "timestamp", None)
        or getattr(scan, "created_at", None)
        or (
            datetime.fromtimestamp(scan.started, tz=timezone.utc).isoformat()
            if getattr(scan, "started", None) is not None
            else None
        )
        or datetime.now(timezone.utc).isoformat()
    )
    final_score = score if score is not None else getattr(scan, "score", None)
    err = getattr(scan, "error", None)

    all_findings = list(findings) if findings else list(getattr(scan, "findings", ()))

    with _get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans (scan_id, created_at, file_name, score, error)
            VALUES (?, ?, ?, ?, ?)
            """,
            (sid, created_at, fname, final_score, err),
        )

        # Delete existing child rows if updating/replacing
        conn.execute("DELETE FROM devices WHERE scan_id = ?", (sid,))
        conn.execute("DELETE FROM ports WHERE scan_id = ?", (sid,))
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (sid,))

        for d in getattr(scan, "devices", ()):
            raw_mac = getattr(d, "mac_masked", getattr(d, "mac", ""))
            if ":xx:xx:xx" in raw_mac.lower() or ":**:**:**" in raw_mac:
                masked_mac_val = raw_mac
            else:
                masked_mac_val = mask_mac(raw_mac)
            conn.execute(
                """
                INSERT INTO devices (scan_id, ip, mac, vendor, hostname, device_type)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (sid, d.ip, masked_mac_val, d.vendor, d.hostname, d.device_type),
            )
            for p in getattr(d, "ports", ()):
                svc = getattr(p, "service", getattr(p, "service_name", ""))
                title = getattr(p, "http_title", getattr(p, "title", ""))
                conn.execute(
                    """
                    INSERT INTO ports (scan_id, ip, port_number, protocol, state,
                                       service_name, product, version, tunnel, title)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sid,
                        d.ip,
                        p.port,
                        p.protocol,
                        p.state,
                        svc,
                        p.product,
                        p.version,
                        p.tunnel,
                        title,
                    ),
                )

        for f in all_findings:
            conn.execute(
                """
                INSERT INTO findings (scan_id, ip, port_number, finding_code, severity, points, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (sid, f.ip, f.port, f.code, f.severity, f.points, f.evidence),
            )

    return sid


def get_scan(scan_id: str, db_path: str = DB_PATH) -> Optional[ScanRecord]:
    """Retrieve a complete ScanRecord by scan_id."""
    init_db(db_path)
    with _get_connection(db_path) as conn:
        scan_row = conn.execute(
            "SELECT scan_id, created_at, file_name, score, error FROM scans WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()

        if not scan_row:
            return None

        # Fetch devices
        dev_rows = conn.execute(
            "SELECT ip, mac, vendor, hostname, device_type FROM devices WHERE scan_id = ? ORDER BY ip",
            (scan_id,),
        ).fetchall()

        # Fetch ports
        port_rows = conn.execute(
            """
            SELECT ip, port_number, protocol, state, service_name, product, version, tunnel, title
            FROM ports WHERE scan_id = ? ORDER BY port_number
            """,
            (scan_id,),
        ).fetchall()

        ports_by_ip: dict[str, list[Port]] = {}
        for pr in port_rows:
            scripts = {}
            if pr["title"]:
                scripts["http-title"] = pr["title"]
            p = Port(
                protocol=pr["protocol"],
                port=pr["port_number"],
                state=pr["state"],
                service=pr["service_name"] or "",
                product=pr["product"] or "",
                version=pr["version"] or "",
                tunnel=pr["tunnel"] or "",
                scripts=scripts,
            )
            ports_by_ip.setdefault(pr["ip"], []).append(p)

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
                    ports=tuple(ports_by_ip.get(ip, [])),
                )
            )

        # Fetch findings
        finding_rows = conn.execute(
            """
            SELECT ip, port_number, finding_code, severity, points, evidence
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
                    protocol="tcp",
                    evidence=fr["evidence"] or "",
                )
            )

        scan_result = ScanResult(
            file=scan_row["file_name"] or scan_row["scan_id"],
            devices=tuple(devices),
            error=scan_row["error"],
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
            ORDER BY s.created_at DESC
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
    scans = list_scans(db_path)
    if not scans:
        return None
    return get_scan(scans[0]["scan_id"], db_path)


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
            WHERE score IS NOT NULL
            ORDER BY created_at ASC
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
            ORDER BY s.created_at DESC
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


def get_scan_diff_with_previous(scan_id: str, db_path: str = DB_PATH):
    """Compute difference between scan_id and the chronologically preceding scan (FR-10, FR-13)."""
    from netcheck.history.diff import compute_diff

    init_db(db_path)
    with _get_connection(db_path) as conn:
        curr_row = conn.execute(
            "SELECT scan_id, created_at FROM scans WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        if not curr_row:
            return None

        # Find the immediately preceding scan
        prev_row = conn.execute(
            """
            SELECT scan_id FROM scans
            WHERE created_at < ? AND scan_id != ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (curr_row["created_at"], scan_id),
        ).fetchone()

        if not prev_row:
            return None

    prev_scan = get_scan(prev_row["scan_id"], db_path)
    curr_scan = get_scan(scan_id, db_path)
    if not prev_scan or not curr_scan:
        return None

    return compute_diff(prev_scan, curr_scan)
