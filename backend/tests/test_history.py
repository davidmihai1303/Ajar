"""Tests for backend/netcheck/history/ (store.py and diff.py).

Verifies:
1. Local SQLite store correctly saves, retrieves, and lists scans.
2. MAC addresses are masked in SQLite output (NFR-02).
3. One-click delete wipes all history (NFR-02).
4. Diff compares scans strictly BY IP, NEVER BY MAC (FR-10, FR-13).
5. V6a -> V6b shows 3 resolved findings and score improvement even though MACs changed.
"""
import os
import tempfile
import unittest

from netcheck.analysis.models import Device, Finding, Port, ScanResult
from netcheck.history import (
    compute_diff,
    delete_all_history,
    delete_scan,
    get_latest_scan,
    get_scan,
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
            scan_id="scan_test_1",
            file_name="test.xml",
            timestamp="2026-11-07T10:00:00Z",
            score=75,
            devices=[
                Device(
                    ip="192.168.1.10",
                    mac="50:C7:BF:88:24:57",
                    vendor="TP-Link",
                    hostname="router.lan",
                    device_type="router",
                    ports=[
                        Port(port=80, protocol="tcp", state="open", service_name="http", title="Router Login"),
                        Port(port=22, protocol="tcp", state="closed", service_name="ssh"),
                    ],
                )
            ],
            findings=[
                Finding(
                    code="HTTP_ADMIN_CLEARTEXT",
                    severity="medium",
                    points=10,
                    ip="192.168.1.10",
                    port=80,
                    evidence="http without SSL with Router Login",
                )
            ],
        )

        saved_id = save_scan(scan, self.temp_db)
        self.assertEqual(saved_id, "scan_test_1")

        loaded = get_scan("scan_test_1", self.temp_db)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.scan_id, "scan_test_1")
        self.assertEqual(loaded.score, 75)
        self.assertEqual(len(loaded.devices), 1)
        self.assertEqual(loaded.devices[0].ip, "192.168.1.10")
        # MAC must be masked in store output (NFR-02)
        self.assertEqual(loaded.devices[0].mac, "50:C7:BF:xx:xx:xx")
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
            scan_id="scan_1",
            file_name="test.xml",
            score=90,
            devices=[Device(ip="192.168.1.1", mac="50:C7:BF:11:22:33")],
            findings=[Finding(code="SSH_OPEN", severity="info", points=0, ip="192.168.1.1", port=22)],
        )
        save_scan(scan, self.temp_db)
        self.assertEqual(len(list_scans(self.temp_db)), 1)

        delete_all_history(self.temp_db)
        self.assertEqual(len(list_scans(self.temp_db)), 0)
        self.assertIsNone(get_scan("scan_1", self.temp_db))
        self.assertIsNone(get_latest_scan(self.temp_db))

    def test_delete_single_scan(self):
        s1 = ScanResult(scan_id="s1", score=90)
        s2 = ScanResult(scan_id="s2", score=80)
        save_scan(s1, self.temp_db)
        save_scan(s2, self.temp_db)

        self.assertEqual(len(list_scans(self.temp_db)), 2)
        self.assertTrue(delete_scan("s1", self.temp_db))
        self.assertEqual(len(list_scans(self.temp_db)), 1)
        self.assertIsNone(get_scan("s1", self.temp_db))
        self.assertIsNotNone(get_scan("s2", self.temp_db))

    def test_diff_v6a_v6b_mac_change_matches_by_ip(self):
        """V6a -> V6b: 3 resolved findings even though MAC addresses changed."""
        v6a = ScanResult(
            scan_id="V6a_before",
            file_name="V6a_before.xml",
            score=60,
            devices=[
                Device(
                    ip="192.168.1.1",
                    mac="50:C7:BF:88:24:57",  # MAC in V6a
                    vendor="TP-Link",
                    hostname="router.lan",
                    device_type="router",
                    ports=[
                        Port(port=80, protocol="tcp", state="open", service_name="http", title="Router Login"),
                        Port(port=1900, protocol="udp", state="open", service_name="upnp"),
                    ],
                ),
                Device(
                    ip="192.168.1.20",
                    mac="54:E1:AD:7D:53:EC",
                    vendor="Lenovo",
                    hostname="laptop-ioana",
                    device_type="laptop",
                    ports=[],
                ),
                Device(
                    ip="192.168.1.30",
                    mac="24:0A:C4:C2:8A:70",  # MAC in V6a
                    vendor="Espressif",
                    hostname="plug-kitchen",
                    device_type="iot",
                    ports=[
                        Port(port=23, protocol="tcp", state="open", service_name="telnet"),
                    ],
                ),
            ],
            findings=[
                Finding(code="HTTP_ADMIN_CLEARTEXT", severity="medium", points=10, ip="192.168.1.1", port=80),
                Finding(code="UPNP_EXPOSED", severity="medium", points=10, ip="192.168.1.1", port=1900),
                Finding(code="TELNET_OPEN", severity="high", points=20, ip="192.168.1.30", port=23),
            ],
        )

        v6b = ScanResult(
            scan_id="V6b_after",
            file_name="V6b_after.xml",
            score=100,
            devices=[
                Device(
                    ip="192.168.1.1",
                    mac="50:C7:BF:A6:1C:75",  # DIFFERENT MAC!
                    vendor="TP-Link",
                    hostname="router.lan",
                    device_type="router",
                    ports=[
                        Port(port=443, protocol="tcp", state="open", service_name="http", tunnel="ssl"),
                    ],
                ),
                Device(
                    ip="192.168.1.20",
                    mac="54:E1:AD:10:A1:CD",  # DIFFERENT MAC!
                    vendor="Lenovo",
                    hostname="laptop-ioana",
                    device_type="laptop",
                    ports=[],
                ),
                Device(
                    ip="192.168.1.30",
                    mac="24:0A:C4:89:21:6C",  # DIFFERENT MAC!
                    vendor="Espressif",
                    hostname="plug-kitchen",
                    device_type="iot",
                    ports=[],
                ),
            ],
            findings=[],
        )

        diff = compute_diff(v6a, v6b)

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
