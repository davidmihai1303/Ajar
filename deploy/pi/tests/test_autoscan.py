"""Tests for deploy/pi/ajar_autoscan.py. Standard library only; the app API and the network are mocked,
nothing is scanned.  Run:  python3 -m unittest discover -s deploy/pi/tests -v
"""
import datetime as dt
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ajar_autoscan", HERE.parent / "ajar_autoscan.py")
autoscan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(autoscan)

HOTSPOT = {"interface": "wlan0", "subnet": "172.20.10.0/28", "gateway": "172.20.10.1",
           "ssid": "RSH-Byte_me", "confirmation_id": None}
GATEWAY_MAC = "aa:bb:cc:11:22:33"
NOW = dt.datetime(2026, 11, 8, 12, 0, tzinfo=dt.timezone.utc)


class StateDirTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(autoscan, "STATE_DIR", Path(self.tmp.name) / "ajar")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.posts = []

    def fake_api(self, network=HOTSPOT, scan_status=200):
        def api(method, path, body=None, timeout=10):
            if method == "GET" and path == "/api/network":
                return 200, dict(network)
            if method == "POST" and path == "/api/scans":
                self.posts.append(body)
                return scan_status, {"score": 60, "findings": [{}, {}, {}]} if scan_status == 200 else {}
            raise AssertionError(f"unexpected call {method} {path}")
        return api

    def grant(self, network=HOTSPOT, mac=GATEWAY_MAC, answer="DA", days=30):
        with mock.patch.object(autoscan, "api", self.fake_api(network)), \
                mock.patch.object(autoscan, "gateway_mac", return_value=mac), \
                mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", return_value=answer), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            return autoscan.cmd_grant(days)

    def run_scan(self, network=HOTSPOT, mac=GATEWAY_MAC, scan_status=200, now=None):
        out = io.StringIO()
        with mock.patch.object(autoscan, "api", self.fake_api(network, scan_status)), \
                mock.patch.object(autoscan, "gateway_mac", return_value=mac), \
                mock.patch.object(autoscan, "now_utc", return_value=now or autoscan.now_utc()), \
                mock.patch("sys.stdout", out):
            code = autoscan.cmd_run()
        return code, out.getvalue()


class PureFunctionTests(unittest.TestCase):
    def test_fingerprint_is_stable_keyed_and_hides_the_mac(self):
        key = b"k" * 32
        fp = autoscan.fingerprint(key, "AA:BB:CC:11:22:33")
        self.assertEqual(fp, autoscan.fingerprint(key, "aa:bb:cc:11:22:33"))
        self.assertNotEqual(fp, autoscan.fingerprint(b"x" * 32, "aa:bb:cc:11:22:33"))
        self.assertNotIn("aabbcc", fp)
        self.assertEqual(len(fp), 32)

    def test_parse_neighbour(self):
        entries = [{"dst": "172.20.10.3", "lladdr": "11:11:11:11:11:11", "state": ["REACHABLE"]},
                   {"dst": "172.20.10.1", "lladdr": "AA:BB:CC:11:22:33", "state": ["STALE"]}]
        self.assertEqual(autoscan.parse_neighbour(entries, "172.20.10.1"), GATEWAY_MAC)
        self.assertIsNone(autoscan.parse_neighbour(entries, "172.20.10.9"))
        failed = [{"dst": "172.20.10.1", "lladdr": "aa:bb:cc:11:22:33", "state": ["FAILED"]}]
        self.assertIsNone(autoscan.parse_neighbour(failed, "172.20.10.1"))

    def test_gateway_that_is_not_an_ip_is_never_passed_to_a_command(self):
        with mock.patch.object(autoscan.subprocess, "run") as run:
            self.assertIsNone(autoscan.gateway_mac("172.20.10.1; rm -rf /"))
            run.assert_not_called()

    def test_matches(self):
        consent = {"ssid": "RSH-Byte_me", "subnet": "172.20.10.0/28", "gateway": "172.20.10.1",
                   "gateway_fp": "fp1", "expires_at": "2026-12-08T12:00:00+00:00"}
        same = {k: consent[k] for k in ("ssid", "subnet", "gateway", "gateway_fp")}
        self.assertEqual(autoscan.matches(consent, same, NOW), (True, "ok"))
        for field, value in (("ssid", "Venue-WiFi"), ("subnet", "10.5.3.0/24"),
                             ("gateway", "172.20.10.2"), ("gateway_fp", "fp2")):
            ok, reason = autoscan.matches(consent, {**same, field: value}, NOW)
            self.assertFalse(ok)
            self.assertIn(field, reason)
        self.assertEqual(autoscan.matches(consent, {**same, "gateway_fp": ""}, NOW), (False, "missing gateway_fp"))
        later = dt.datetime(2026, 12, 9, tzinfo=dt.timezone.utc)
        self.assertEqual(autoscan.matches(consent, same, later), (False, "consent expired"))


class ConsentAndRunTests(StateDirTestCase):
    def test_no_consent_means_no_scan(self):
        code, out = self.run_scan()
        self.assertEqual(code, autoscan.EXIT_SKIPPED)
        self.assertEqual(self.posts, [])
        self.assertIn("no consent", out)

    def test_grant_then_run_scans_the_same_network(self):
        self.assertEqual(self.grant(), autoscan.EXIT_OK)
        code, out = self.run_scan()
        self.assertEqual(code, autoscan.EXIT_OK)
        self.assertEqual(self.posts, [{"confirm": True, "expected_network": HOTSPOT}])
        self.assertIn("score 60", out)

    def test_same_ssid_and_subnet_but_another_router_is_refused(self):
        """Every iPhone hotspot is 172.20.10.0/28 and a Wi-Fi name can be copied."""
        self.grant()
        code, out = self.run_scan(mac="de:ad:be:ef:00:01")
        self.assertEqual(code, autoscan.EXIT_SKIPPED)
        self.assertEqual(self.posts, [])
        self.assertIn("gateway_fp", out)

    def test_venue_network_is_refused(self):
        self.grant()
        venue = {**HOTSPOT, "ssid": "Venue-Guest", "subnet": "10.5.3.0/24", "gateway": "10.5.3.1"}
        code, _ = self.run_scan(network=venue, mac="00:11:22:33:44:55")
        self.assertEqual(code, autoscan.EXIT_SKIPPED)
        self.assertEqual(self.posts, [])

    def test_expired_consent_is_refused(self):
        self.grant(days=1)
        code, out = self.run_scan(now=autoscan.now_utc() + dt.timedelta(days=2))
        self.assertEqual(code, autoscan.EXIT_SKIPPED)
        self.assertIn("expired", out)
        self.assertEqual(self.posts, [])

    def test_answer_other_than_yes_saves_nothing(self):
        self.assertEqual(self.grant(answer="nu"), autoscan.EXIT_SKIPPED)
        self.assertEqual(autoscan.load_consents(), [])

    def test_grant_needs_an_identifiable_router(self):
        with mock.patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(self.grant(mac=None), autoscan.EXIT_ERROR)
        self.assertEqual(autoscan.load_consents(), [])

    def test_grant_is_interactive_only(self):
        with mock.patch.object(autoscan, "api", self.fake_api()), \
                mock.patch.object(autoscan, "gateway_mac", return_value=GATEWAY_MAC), \
                mock.patch.object(sys.stdin, "isatty", return_value=False), \
                mock.patch("builtins.input", side_effect=AssertionError("must not ask")), \
                mock.patch("sys.stdout", new_callable=io.StringIO), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(autoscan.cmd_grant(30), autoscan.EXIT_ERROR)
        self.assertEqual(autoscan.load_consents(), [])

    def test_consent_file_never_contains_the_gateway_mac(self):
        self.grant()
        text = (autoscan.STATE_DIR / "consent.json").read_text()
        self.assertNotIn(GATEWAY_MAC, text.lower())
        self.assertNotIn("aabbcc112233", text.lower().replace(":", ""))
        saved = json.loads(text)["networks"][0]
        self.assertEqual((saved["ssid"], saved["subnet"], saved["gateway"]),
                         (HOTSPOT["ssid"], HOTSPOT["subnet"], HOTSPOT["gateway"]))

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_state_files_are_private(self):
        self.grant()
        for name in ("consent.json", "consent.key"):
            mode = (autoscan.STATE_DIR / name).stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, name)

    def test_regrant_replaces_instead_of_duplicating(self):
        self.grant()
        self.grant()
        self.assertEqual(len(autoscan.load_consents()), 1)

    def test_busy_or_changed_network_is_a_skip_not_a_failure(self):
        self.grant()
        for status in (409, 403):
            code, _ = self.run_scan(scan_status=status)
            self.assertEqual(code, autoscan.EXIT_SKIPPED)

    def test_server_error_is_reported_as_failure(self):
        self.grant()
        with self.assertRaises(autoscan.AutoscanError):
            self.run_scan(scan_status=502)

    def test_revoke_all(self):
        self.grant()
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            autoscan.cmd_revoke(revoke_all=True)
        code, _ = self.run_scan()
        self.assertEqual(code, autoscan.EXIT_SKIPPED)
        self.assertEqual(self.posts, [])

    def test_revoke_current_network(self):
        self.grant()
        with mock.patch.object(autoscan, "api", self.fake_api()), \
                mock.patch.object(autoscan, "gateway_mac", return_value=GATEWAY_MAC), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            autoscan.cmd_revoke(revoke_all=False)
        self.assertEqual(autoscan.load_consents(), [])


if __name__ == "__main__":
    unittest.main()
