"""Compare two analysed scans BY IP (not MAC): new/removed devices, opened/closed ports, resolved findings, score trend (FR-10, FR-13).

Strict rule: Compare scans BY IP, NEVER BY MAC. MAC addresses can randomize
or change on reconnects, but devices on a local subnet are compared by IP.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Optional

from netcheck.analysis.models import Device, Finding, ScanResult
from netcheck.analysis.privacy import mask_macs_in_text, mask_scan_filename

from .records import ScanRecord, analysis_for


@dataclass
class ScanDiff:
    prev_scan_id: str
    curr_scan_id: str
    score_before: Optional[int] = None
    score_after: Optional[int] = None
    score_change: Optional[int] = None  # curr - prev (positive = improved)
    new_devices: list[Device] = field(default_factory=list)
    removed_devices: list[Device] = field(default_factory=list)
    newly_opened_ports: list[dict] = field(default_factory=list)  # {ip, port, protocol, service}
    closed_ports: list[dict] = field(default_factory=list)        # {ip, port, protocol, service}
    resolved_findings: list[Finding] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    retained_findings: list[Finding] = field(default_factory=list)

    @property
    def alerts(self) -> list[dict]:
        """FR-13: Flags a new device or newly opened port compared with the previous scan."""
        alerts_list: list[dict] = []
        for d in self.new_devices:
            dev_desc = d.vendor or d.hostname or "unknown"
            alerts_list.append({
                "type": "NEW_DEVICE",
                "severity": "warning",
                "title": f"New device: {d.ip}",
                "title_ro": f"Dispozitiv nou: {d.ip}",
                "description": f"Device {d.ip} ({dev_desc}) connected to the network.",
                "description_ro": f"Dispozitivul {d.ip} ({dev_desc}) s-a conectat la rețea.",
                "ip": d.ip,
                "port": None,
            })
        for p in self.newly_opened_ports:
            alerts_list.append({
                "type": "NEW_PORT",
                "severity": "danger",
                "title": f"New port opened: {p['ip']}:{p['port']}",
                "title_ro": f"Port nou deschis: {p['ip']}:{p['port']}",
                "description": f"Port {p['port']}/{p['protocol']} ({p.get('service') or 'unknown'}) was opened on {p['ip']}.",
                "description_ro": f"Portul {p['port']}/{p['protocol']} ({p.get('service') or 'necunoscut'}) a fost deschis pe {p['ip']}.",
                "ip": p["ip"],
                "port": p["port"],
            })
        return alerts_list

    def to_dict(self) -> dict:
        return {
            "prev_scan_id": self.prev_scan_id,
            "curr_scan_id": self.curr_scan_id,
            "score_before": self.score_before,
            "score_after": self.score_after,
            "score_change": self.score_change,
            "new_devices": [
                {
                    "ip": d.ip,
                    "mac": getattr(d, "mac_masked", getattr(d, "mac", "")),
                    "vendor": d.vendor,
                    "hostname": d.hostname,
                    "device_type": d.device_type,
                }
                for d in self.new_devices
            ],
            "removed_devices": [
                {
                    "ip": d.ip,
                    "mac": getattr(d, "mac_masked", getattr(d, "mac", "")),
                    "vendor": d.vendor,
                    "hostname": d.hostname,
                    "device_type": d.device_type,
                }
                for d in self.removed_devices
            ],
            "newly_opened_ports": self.newly_opened_ports,
            "closed_ports": self.closed_ports,
            "resolved_findings": [
                {"ip": f.ip, "port": f.port, "code": f.code, "severity": f.severity, "points": f.points}
                for f in self.resolved_findings
            ],
            "new_findings": [
                {"ip": f.ip, "port": f.port, "code": f.code, "severity": f.severity, "points": f.points}
                for f in self.new_findings
            ],
            "retained_findings": [
                {"ip": f.ip, "port": f.port, "code": f.code, "severity": f.severity, "points": f.points}
                for f in self.retained_findings
            ],
            "alerts": self.alerts,
        }


def _public_id(scan: ScanResult | ScanRecord) -> str:
    if isinstance(scan, ScanRecord) and scan.scan_id:
        return mask_macs_in_text(scan.scan_id)
    return mask_scan_filename(scan.file)


def compute_diff(
    prev: ScanResult | ScanRecord,
    curr: ScanResult | ScanRecord,
    prev_findings: Sequence[Finding] | None = None,
    curr_findings: Sequence[Finding] | None = None,
    prev_score: Optional[int] = None,
    curr_score: Optional[int] = None,
) -> ScanDiff | None:
    """Compare two successful scans by IP. Failed scans have no change assessment."""
    if not prev.ok or not curr.ok:
        return None
    findings_prev, score_before = analysis_for(prev, prev_findings, prev_score)
    findings_curr, score_after = analysis_for(curr, curr_findings, curr_score)

    # Devices diff by IP (NEVER by MAC)
    prev_devs_by_ip = {d.ip: d for d in prev.devices}
    curr_devs_by_ip = {d.ip: d for d in curr.devices}

    new_devices = [curr_devs_by_ip[ip] for ip in curr_devs_by_ip if ip not in prev_devs_by_ip]
    removed_devices = [prev_devs_by_ip[ip] for ip in prev_devs_by_ip if ip not in curr_devs_by_ip]

    # Ports diff (only open ports count)
    def open_ports_map(devs: Iterable[Device]) -> dict[tuple[str, int, str], str]:
        ports: dict[tuple[str, int, str], str] = {}
        for dev in devs:
            for p in dev.open_ports:
                ports[(dev.ip, p.port, p.protocol.lower())] = p.service
        return ports

    prev_ports = open_ports_map(prev.devices)
    curr_ports = open_ports_map(curr.devices)

    newly_opened_ports = [
        {"ip": k[0], "port": k[1], "protocol": k[2], "service": curr_ports[k]}
        for k in curr_ports
        if k not in prev_ports
    ]
    closed_ports = [
        {"ip": k[0], "port": k[1], "protocol": k[2], "service": prev_ports[k]}
        for k in prev_ports
        if k not in curr_ports
    ]

    # Findings diff by (ip, port, finding_code)
    def finding_key(f: Finding) -> tuple[str, Optional[int], str]:
        return (f.ip, f.port, f.code)

    prev_findings_map = {finding_key(f): f for f in findings_prev}
    curr_findings_map = {finding_key(f): f for f in findings_curr}

    resolved_findings = [
        prev_findings_map[k] for k in prev_findings_map if k not in curr_findings_map
    ]
    new_findings = [
        curr_findings_map[k] for k in curr_findings_map if k not in prev_findings_map
    ]
    retained_findings = [
        curr_findings_map[k] for k in curr_findings_map if k in prev_findings_map
    ]

    return ScanDiff(
        prev_scan_id=_public_id(prev),
        curr_scan_id=_public_id(curr),
        score_before=score_before,
        score_after=score_after,
        score_change=score_after - score_before,
        new_devices=new_devices,
        removed_devices=removed_devices,
        newly_opened_ports=newly_opened_ports,
        closed_ports=closed_ports,
        resolved_findings=resolved_findings,
        new_findings=new_findings,
        retained_findings=retained_findings,
    )
