"""History package: local SQLite persistence and scan diffing."""
from netcheck.history.diff import ScanDiff, compute_diff
from netcheck.history.store import (
    delete_all_history,
    delete_scan,
    get_latest_scan,
    get_scan,
    init_db,
    list_scans,
    save_scan,
)

__all__ = [
    "init_db",
    "save_scan",
    "get_scan",
    "list_scans",
    "get_latest_scan",
    "delete_scan",
    "delete_all_history",
    "ScanDiff",
    "compute_diff",
]
