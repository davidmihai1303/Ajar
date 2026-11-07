"""History package: local SQLite persistence and scan diffing."""
from netcheck.history.diff import ScanDiff, compute_diff
from netcheck.history.records import ScanRecord
from netcheck.history.store import (
    delete_all_history,
    delete_scan,
    get_device_history,
    get_latest_scan,
    get_scan,
    get_scan_diff_with_previous,
    get_score_trend,
    init_db,
    list_scans,
    save_scan,
)

__all__ = [
    "ScanRecord",
    "init_db",
    "save_scan",
    "get_scan",
    "list_scans",
    "get_latest_scan",
    "delete_scan",
    "delete_all_history",
    "get_score_trend",
    "get_device_history",
    "get_scan_diff_with_previous",
    "ScanDiff",
    "compute_diff",
]
