"""Create the history schema or upgrade the original, unversioned PR schema."""
import sqlite3
from uuid import uuid4

from netcheck.analysis.privacy import mask_scan_filename

from .records import public_scan_id, scan_start_time, utc_timestamp


_CREATE = (
    """CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        file_name TEXT,
        score INTEGER,
        error TEXT,
        started INTEGER
    )""",
    """CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        ip TEXT NOT NULL,
        mac TEXT,
        vendor TEXT,
        hostname TEXT,
        device_type TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS ports (
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
        title TEXT,
        device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
        extrainfo TEXT,
        scripts TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        ip TEXT NOT NULL,
        port_number INTEGER,
        finding_code TEXT NOT NULL,
        severity TEXT NOT NULL,
        points INTEGER NOT NULL,
        evidence TEXT,
        protocol TEXT
    )""",
    """CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id)""",
    """CREATE INDEX IF NOT EXISTS idx_ports_scan_id ON ports(scan_id)""",
    """CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)""",
)


def _upgrade_original(conn: sqlite3.Connection) -> None:
    conn.execute("ALTER TABLE scans ADD COLUMN started INTEGER")
    conn.execute("ALTER TABLE findings ADD COLUMN protocol TEXT")
    conn.execute("ALTER TABLE ports ADD COLUMN device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE")
    conn.execute("ALTER TABLE ports ADD COLUMN extrainfo TEXT")
    conn.execute("ALTER TABLE ports ADD COLUMN scripts TEXT")

    # The old schema associated ports by IP. Assign each saved port to one device.
    conn.execute("""
        UPDATE ports SET device_id = (
            SELECT MIN(d.id) FROM devices d WHERE d.scan_id = ports.scan_id AND d.ip = ports.ip
        )
    """)
    # Preserve only protocols supported by the old evidence or an unambiguous open port.
    conn.execute("""
        UPDATE findings SET protocol = CASE
            WHEN port_number IS NULL THEN ''
            WHEN evidence = 'udp/' || port_number OR evidence LIKE 'udp/' || port_number || ' %' THEN 'udp'
            WHEN evidence = 'tcp/' || port_number OR evidence LIKE 'tcp/' || port_number || ' %' THEN 'tcp'
            ELSE COALESCE((
                SELECT MIN(p.protocol) FROM ports p
                WHERE p.scan_id = findings.scan_id AND p.ip = findings.ip
                    AND p.port_number = findings.port_number AND p.state = 'open'
                HAVING COUNT(DISTINCT p.protocol) = 1
            ), '')
        END
    """)
    # A missing legacy score can be recovered from a saved findings ledger. When neither
    # was supplied, the old format cannot distinguish an unanalyzed scan from a clean one.
    conn.execute("""
        UPDATE scans SET score = (
            SELECT MAX(0, 100 - SUM(f.points)) FROM findings f WHERE f.scan_id = scans.scan_id
        ) WHERE score IS NULL AND error IS NULL AND EXISTS (
            SELECT 1 FROM findings f WHERE f.scan_id = scans.scan_id
        )
    """)

    # Older callers could store a full MAC in the public ID. Rekey the complete record atomically.
    conn.execute("PRAGMA defer_foreign_keys = ON")
    for sid, filename in conn.execute("SELECT scan_id, file_name FROM scans").fetchall():
        public_id = uuid4().hex if public_scan_id(sid) != sid else sid
        public_name = mask_scan_filename(filename) if filename else public_id
        if public_id == sid and public_name == filename:
            continue
        conn.execute("UPDATE scans SET scan_id = ?, file_name = ? WHERE scan_id = ?", (public_id, public_name, sid))
        if public_id != sid:
            for table in ("devices", "ports", "findings"):
                conn.execute(f"UPDATE {table} SET scan_id = ? WHERE scan_id = ?", (public_id, sid))


def _normalize_timestamps(conn: sqlite3.Connection) -> None:
    for sid, created_at, started in conn.execute("SELECT scan_id, created_at, started FROM scans").fetchall():
        try:
            value = utc_timestamp(created_at)
        except (TypeError, ValueError, OverflowError):
            # Undated records stay visible in history but cannot establish a chronological comparison.
            instant = scan_start_time(started)
            value = instant.isoformat() if instant else ""
        if value != created_at:
            conn.execute("UPDATE scans SET created_at = ? WHERE scan_id = ?", (value, sid))


def ensure_schema(conn: sqlite3.Connection) -> None:
    if conn.execute("PRAGMA user_version").fetchone()[0] == 2:
        return
    conn.execute("BEGIN IMMEDIATE")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == 2:  # Another initializer finished while we were waiting.
        return
    if version not in (0, 1):
        raise ValueError(f"Unsupported history database version {version}")
    if version == 0:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'scans'").fetchone():
            _upgrade_original(conn)
        else:
            for statement in _CREATE:
                conn.execute(statement)
    _normalize_timestamps(conn)
    conn.execute("PRAGMA user_version = 2")
