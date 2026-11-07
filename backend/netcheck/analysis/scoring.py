"""Standard network score calculation (FR-09).

Score = max(0, 100 - sum(points of all findings)).
Points: High 20, Medium 10, Low 5, Info 0.
"""
from __future__ import annotations

from typing import Iterable

from netcheck.analysis.models import Finding


def calculate_score(findings: Iterable[Finding]) -> int:
    """Calculate the official security score from 0 to 100."""
    total_points = sum(f.points for f in findings)
    return max(0, 100 - total_points)
