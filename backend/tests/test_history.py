"""Tests for backend/netcheck/history/ (store.py and diff.py).

Verifies:
1. Local SQLite store correctly saves, retrieves, and lists scans.
2. MAC addresses are masked in SQLite output (NFR-02).
3. One-click delete wipes all history (NFR-02).
4. Diff compares scans strictly BY IP, NEVER BY MAC (FR-10, FR-13).
5. V6a -> V6b shows 3 resolved findings and score improvement even though MACs changed.
6. FR-10: Score trend and device history across multiple scans.
7. FR-13: Alerts on new device and newly opened port.
8. Automatic diff against preceding scan in history.
"""
import os
import tempfile
import unittest

from netcheck.analysis.models import Device, Finding, Port, ScanResult
from netcheck.history import (
    compute_diff,
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


class TestHistoryStore(unittest.TestCase):
    def setUp(self):
        self.fd, self.temp_db = tempfile.mkstemp(suffix=".sqlite")
        os.close(self.fd)
        init_db(self.temp_db)

    def tearDown(self):
        if os.path.exists(self.temp_db):
            os.remove(self.temp_db)

    def test_sqlite_save_and_retrieve(self):
        scan = ScanResult(
            file="test.xml",
            devices=(
                Device(
                    ip="192.168.1.10",
                    mac_masked="50:C7:BF:xx:xx:xx",
                    vendor="TP-Link",
                    hostname="router.lan",
                    device_type="router",
                    ports=(
                        Port(protocol="tcp", port=80, state="open", service="http", scripts={"http-title": "Router Login"}),
                        Port(protocol="tcp", port=22, state="closed", service="ssh"),
                    ),
                ),
            ),
        )
        findings = [
            Finding(
                ip="192.168.1.10",
                port=80,
                protocol="tcp",
                code="HTTP_ADMIN_CLEARTEXT",
                severity="medium",
                points=10,
                evidence="http without SSL with Router Login",
            )
        ]

        saved_id = save_scan(scan, findings=findings, score=75, scan_id="scan_test_1", db_path=self.temp_db)
        self.assertEqual(saved_id, "scan_test_1")

        loaded = get_scan("scan_test_1", self.temp_db)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.scan_id, "scan_test_1")
        self.assertEqual(loaded.score, 75)
        self.assertEqual(len(loaded.devices), 1)
        self.assertEqual(loaded.devices[0].ip, "192.168.1.10")
        # MAC must be masked in store output (NFR-02)
        self.assertEqual(loaded.devices[0].mac_masked, "50:C7:BF:xx:xx:xx")
        self.assertEqual(len(loaded.devices[0].ports), 2)
        self.assertEqual(len(loaded.findings), 1)
        self.assertEqual(loaded.findings[0].code, "HTTP_ADMIN_CLEARTEXT")

        # List scans
        summaries = list_scans(self.temp_db)
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["scan_id"], "scan_test_1")
        self.assertEqual(summaries[0]["score"], 75)
        self.assertEqual(summaries[0]["device_count"], 1)
        self.assertEqual(summaries[0]["finding_count"], 1)

    def test_delete_all_history(self):
        scan = ScanResult(
            file="test.xml",
            devices=(Device(ip="192.168.1.1", mac_masked="50:C7:BF:xx:xx:xx"),),
        )
        findings = [Finding(ip="192.168.1.1", port=22, protocol="tcp", code="SSH_OPEN", severity="info", points=0)]
        save_scan(scan, findings=findings, score=90, scan_id="scan_1", db_path=self.temp_db)
        self.assertEqual(len(list_scans(self.temp_db)), 1)

        delete_all_history(self.temp_db)
        self.assertEqual(len(list_scans(self.temp_db)), 0)
        self.assertIsNone(get_scan("scan_1", self.temp_db))
        self.assertIsNone(get_latest_scan(self.temp_db))

    def test_delete_single_scan(self):
        s1 = ScanResult(file="s1.xml")
        s2 = ScanResult(file="s2.xml")
        save_scan(s1, score=90, scan_id="s1", db_path=self.temp_db)
        save_scan(s2, score=80, scan_id="s2", db_path=self.temp_db)

        self.assertEqual(len(list_scans(self.temp_db)), 2)
        self.assertTrue(delete_scan("s1", self.temp_db))
        self.assertEqual(len(list_scans(self.temp_db)), 1)
        self.assertIsNone(get_scan("s1", self.temp_db))
        self.assertIsNotNone(get_scan("s2", self.temp_db))

    def test_score_trend_and_device_history(self):
        """FR-10: Score trend progression over time and per-device historical lookup."""
        s1 = ScanResult(
            file="s_100.xml",
            started=1793500000,
            devices=(Device(ip="192.168.1.50", mac_masked="AA:BB:CC:xx:xx:xx", vendor="CameraCo"),),
        )
        s2 = ScanResult(
            file="s_101.xml",
            started=1793510000,
            devices=(Device(ip="192.168.1.50", mac_masked="AA:BB:CC:xx:xx:xx", vendor="CameraCo"),),
        )
        save_scan(s1, score=50, scan_id="s_100", db_path=self.temp_db)
        save_scan(s2, score=85, scan_id="s_101", db_path=self.temp_db)

        trend = get_score_trend(self.temp_db)
        self.assertEqual(len(trend), 2)
        self.assertEqual(trend[0]["scan_id"], "s_100")
        self.assertEqual(trend[0]["score"], 50)
        self.assertEqual(trend[1]["scan_id"], "s_101")
        self.assertEqual(trend[1]["score"], 85)

        dev_hist = get_device_history("192.168.1.50", self.temp_db)
        self.assertEqual(len(dev_hist), 2)
        self.assertEqual(dev_hist[0]["scan_id"], "s_101")
        self.assertEqual(dev_hist[1]["scan_id"], "s_100")

    def test_scan_diff_with_previous_in_db(self):
        """FR-10 & FR-13: Automatically diff against chronologically preceding scan in DB."""
        s1 = ScanResult(
            file="s_before.xml",
            started=1793500000,
            devices=(Device(ip="192.168.1.1", ports=(Port(protocol="tcp", port=80, state="open", service="http"),)),),
        )
        f1 = [Finding(ip="192.168.1.1", port=80, protocol="tcp", code="HTTP_ADMIN_CLEARTEXT", severity="medium", points=10)]

        s2 = ScanResult(
            file="s_after.xml",
            started=1793510000,
            devices=(Device(ip="192.168.1.1", ports=(Port(protocol="tcp", port=443, state="open", service="http", tunnel="ssl"),)),),
        )
        save_scan(s1, findings=f1, score=60, scan_id="s_before", db_path=self.temp_db)
        save_scan(s2, findings=[], score=100, scan_id="s_after", db_path=self.temp_db)

        diff = get_scan_diff_with_previous("s_after", self.temp_db)
        self.assertIsNotNone(diff)
        self.assertEqual(diff.prev_scan_id, "s_before")
        self.assertEqual(diff.curr_scan_id, "s_after")
        self.assertEqual(diff.score_change, 40)
        self.assertEqual(len(diff.resolved_findings), 1)
        self.assertEqual(diff.resolved_findings[0].code, "HTTP_ADMIN_CLEARTEXT")

    def test_fr13_alerts_on_new_device_and_port(self):
        """FR-13: Flags a new device or newly opened port as alerts."""
        s_base = ScanResult(
            file="base.xml",
            devices=(
                Device(ip="192.168.1.1", ports=(Port(protocol="tcp", port=80, state="open", service="http"),)),
            ),
        )
        s_next = ScanResult(
            file="next.xml",
            devices=(
                Device(
                    ip="192.168.1.1",
                    ports=(
                        Port(protocol="tcp", port=80, state="open", service="http"),
                        Port(protocol="tcp", port=22, state="open", service="ssh"),  # NEW PORT
                    ),
                ),
                Device(ip="192.168.1.99", vendor="UnknownESP"),  # NEW DEVICE
            ),
        )

        diff = compute_diff(s_base, s_next)
        alerts = diff.alerts

        self.assertEqual(len(alerts), 2)
        types = {a["type"] for a in alerts}
        self.assertEqual(types, {"NEW_DEVICE", "NEW_PORT"})

        dev_alert = next(a for a in alerts if a["type"] == "NEW_DEVICE")
        self.assertEqual(dev_alert["ip"], "192.168.1.99")
        self.assertEqual(dev_alert["severity"], "warning")

        port_alert = next(a for a in alerts if a["type"] == "NEW_PORT")
        self.assertEqual(port_alert["ip"], "192.168.1.1")
        self.assertEqual(port_alert["port"], 22)
        self.assertEqual(port_alert["severity"], "danger")

    def test_diff_v6a_v6b_mac_change_matches_by_ip(self):
        """V6a -> V6b: 3 resolved findings even though MAC addresses changed."""
        v6a = ScanResult(
            file="V6a_before.xml",
            devices=(
                Device(
                    ip="192.168.1.1",
                    mac_masked="50:C7:BF:xx:xx:xx",  # MAC in V6a
                    vendor="TP-Link",
                    hostname="router.lan",
                    device_type="router",
                    ports=(
                        Port(protocol="tcp", port=80, state="open", service="http", scripts={"http-title": "Router Login"}),
                        Port(protocol="udp", port=1900, state="open", service="upnp"),
                    ),
                ),
                Device(
                    ip="192.168.1.20",
                    mac_masked="54:E1:AD:xx:xx:xx",
                    vendor="Lenovo",
                    hostname="laptop-ioana",
                    device_type="laptop",
                    ports=(),
                ),
                Device(
                    ip="192.168.1.30",
                    mac_masked="24:0A:C4:xx:xx:xx",  # MAC in V6a
                    vendor="Espressif",
                    hostname="plug-kitchen",
                    device_type="iot",
                    ports=(
                        Port(protocol="tcp", port=23, state="open", service="telnet"),
                    ),
                ),
            ),
        )
        f_v6a = [
            Finding(ip="192.168.1.1", port=80, protocol="tcp", code="HTTP_ADMIN_CLEARTEXT", severity="medium", points=10),
            Finding(ip="192.168.1.1", port=1900, protocol="udp", code="UPNP_EXPOSED", severity="medium", points=10),
            Finding(ip="192.168.1.30", port=23, protocol="tcp", code="TELNET_OPEN", severity="high", points=20),
        ]

        v6b = ScanResult(
            file="V6b_after.xml",
            devices=(
                Device(
                    ip="192.168.1.1",
                    mac_masked="50:C7:BF:yy:yy:yy",  # DIFFERENT MAC!
                    vendor="TP-Link",
                    hostname="router.lan",
                    device_type="router",
                    ports=(
                        Port(protocol="tcp", port=443, state="open", service="http", tunnel="ssl"),
                    ),
                ),
                Device(
                    ip="192.168.1.20",
                    mac_masked="54:E1:AD:yy:yy:yy",  # DIFFERENT MAC!
                    vendor="Lenovo",
                    hostname="laptop-ioana",
                    device_type="laptop",
                    ports=(),
                ),
                Device(
                    ip="192.168.1.30",
                    mac_masked="24:0A:C4:yy:yy:yy",  # DIFFERENT MAC!
                    vendor="Espressif",
                    hostname="plug-kitchen",
                    device_type="iot",
                    ports=(),
                ),
            ),
        )
        f_v6b = []

        diff = compute_diff(v6a, v6b, prev_findings=f_v6a, curr_findings=f_v6b, prev_score=60, curr_score=100)

        # Match by IP -> 0 new or removed devices
        self.assertEqual(len(diff.new_devices), 0)
        self.assertEqual(len(diff.removed_devices), 0)

        # Score trend
        self.assertEqual(diff.score_before, 60)
        self.assertEqual(diff.score_after, 100)
        self.assertEqual(diff.score_change, 40)

        # 3 resolved findings
        self.assertEqual(len(diff.resolved_findings), 3)
        resolved_codes = {f.code for f in diff.resolved_findings}
        self.assertEqual(resolved_codes, {"HTTP_ADMIN_CLEARTEXT", "UPNP_EXPOSED", "TELNET_OPEN"})
        self.assertEqual(len(diff.new_findings), 0)

        # Closed ports
        self.assertEqual(len(diff.closed_ports), 3)
        # Newly opened ports
        self.assertEqual(len(diff.newly_opened_ports), 1)
        self.assertEqual(diff.newly_opened_ports[0]["port"], 443)
        self.assertEqual(diff.newly_opened_ports[0]["ip"], "192.168.1.1")


if __name__ == "__main__":
    unittest.main()
