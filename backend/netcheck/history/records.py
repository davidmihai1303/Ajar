"""Saved scan snapshots and the findings and score used for history comparisons."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from netcheck.analysis.models import Device, Finding, ScanResult
from netcheck.analysis.privacy import mask_macs_in_text
from netcheck.analysis.rules import evaluate_devices
from netcheck.analysis.scoring import compute_score


def utc_timestamp(value: str) -> str:
    """Store history timestamps in UTC; old timezone-free timestamps are interpreted as UTC."""
    instant = datetime.fromisoformat(value)
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.astimezone(timezone.utc).isoformat()


def scan_start_time(started: int | None) -> datetime | None:
    if started is None:
        return None
    try:
        return datetime.fromtimestamp(started, tz=timezone.utc)
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def public_scan_id(scan_id: str) -> str:
    """Mask embedded MACs, allowing an entire canonical random UUID as a public ID."""
    try:
        identifier = UUID(scan_id)
    except ValueError:
        pass
    else:
        if identifier.version == 4 and str(identifier) == scan_id.lower():
            return scan_id
    return mask_macs_in_text(scan_id)


@dataclass
class ScanRecord:
    """Wrapper around ScanResult retrieved from the SQLite history database."""

    scan: ScanResult
    findings: list[Finding] | None = None  # None requests analysis; [] is an explicitly clean ledger.
    score: Optional[int] = None
    created_at: str = ""
    scan_id: str = ""
    # False when the old database stored neither a ledger nor enough evidence to reconstruct it.
    findings_available: bool = field(default=True, kw_only=True)

    def __post_init__(self) -> None:
        if self.findings is None:
            self.findings = evaluate_devices(self.devices) if self.ok and self.findings_available else []

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


def analysis_for(scan: ScanResult | ScanRecord, findings: Sequence[Finding] | None,
                 score: int | None) -> tuple[Sequence[Finding] | None, int | None]:
    """Resolve findings and score for a successful scan, preserving explicit overrides."""
    if findings is None:
        if isinstance(scan, ScanRecord):
            if score is None:
                score = scan.score
            if not scan.findings_available:
                return None, score
            findings = scan.findings
        else:
            findings = evaluate_devices(scan.devices)
    assert findings is not None
    return findings, compute_score(findings) if score is None else score
