"""Read a history snapshot and persist its finding ledger within the caller's transaction."""
import json
import sqlite3
from collections.abc import Sequence

from netcheck.analysis.models import Device, Finding, Port, ScanResult

from .records import ScanRecord


def write_findings(conn: sqlite3.Connection, scan_id: str, findings: Sequence[Finding]) -> None:
    conn.executemany(
        """INSERT INTO findings (scan_id, ip, port_number, finding_code, severity, points, evidence, protocol)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        ((scan_id, f.ip, f.port, f.code, f.severity, f.points, f.evidence, f.protocol) for f in findings),
    )


def read_scan(conn: sqlite3.Connection, scan_id: str) -> ScanRecord | None:
    scan_row = conn.execute(
        """SELECT s.*, o.source, o.ssid, o.subnet, o.network_id FROM scans s
           LEFT JOIN scan_origin o USING (scan_id) WHERE s.scan_id = ?""",
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
        source=scan_row["source"], ssid=scan_row["ssid"], subnet=scan_row["subnet"],
        network_id=scan_row["network_id"], findings_available=bool(scan_row["findings_available"]),
    )
