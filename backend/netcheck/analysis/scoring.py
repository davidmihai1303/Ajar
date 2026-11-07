"""Standard score: max(0, 100 - sum(points)) (FR-09)."""
from typing import Sequence
from netcheck.analysis.models import Finding


def compute_score(findings: Sequence[Finding]) -> int:
    """Calculate the standard network score from a list of findings."""
    total_points = sum(f.points for f in findings)
    return max(0, 100 - total_points)
