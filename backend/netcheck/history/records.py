"""Saved scan snapshots and the findings and score used for history comparisons."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Optional

from netcheck.analysis.models import Device, Finding, ScanResult
from netcheck.analysis.rules import evaluate_devices
from netcheck.analysis.scoring import compute_score


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


def analysis_for(scan: ScanResult | ScanRecord, findings: Sequence[Finding] | None,
                 score: int | None) -> tuple[Sequence[Finding], int]:
    """Resolve findings and score for a successful scan, preserving explicit overrides."""
    if findings is None:
        if isinstance(scan, ScanRecord):
            findings = scan.findings
            if score is None:
                score = scan.score
        else:
            findings = evaluate_devices(scan.devices)
    return findings, compute_score(findings) if score is None else score
