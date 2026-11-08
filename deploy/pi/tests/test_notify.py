"""Tests for the event log and the phone events service. Standard library only; HTTP runs on a random
localhost port, nothing is scanned.  Run:  python3 -m unittest discover -s deploy/pi/tests -v
"""
import http.client
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import ajar_events  # noqa: E402
from ajar_events import EventLog  # noqa: E402

spec = importlib.util.spec_from_file_location("ajar_notify", HERE.parent / "ajar_notify.py")
notify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notify)

TOKEN = "t0k3n-for-tests-only"


class EventLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = EventLog(Path(self.tmp.name))

    def test_empty_log(self):
        self.assertEqual(self.log.last_id(), 0)
        self.assertEqual(self.log.since(0), [])

    def test_add_and_read_since(self):
        first = self.log.add("new_device", count=2)
        second = self.log.add("score_drop", score=40, previous=90)
        self.assertEqual(self.log.last_id(), second)
        events = self.log.since(first)
        self.assertEqual(len(events), 1)
        self.assertEqual({k: events[0][k] for k in ("type", "severity", "score", "previous")},
                         {"type": "score_drop", "severity": "medium", "score": 40, "previous": 90})

    def test_event_fields_never_identify_a_device(self):
        self.log.add("new_device", count=1)
        self.log.add("new_high_risk", count=3)
        for event in self.log.since(0):
            self.assertLessEqual(set(event), {"id", "time", "type", "severity", "count", "score", "previous"})

    def test_unknown_type_is_refused(self):
        with self.assertRaises(ValueError):
            self.log.add("ip=172.20.10.7")

    def test_old_events_are_pruned(self):
        with mock.patch.object(ajar_events, "KEEP", 3):
            for _ in range(5):
                self.log.add("new_device")
        self.assertEqual([e["id"] for e in self.log.since(0)], [3, 4, 5])

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_database_is_private(self):
        self.log.add("new_device")
        self.assertEqual(self.log.path.stat().st_mode & 0o777, 0o600)


class QueryAndLimiterTests(unittest.TestCase):
    def test_parse_query(self):
        self.assertEqual(notify.parse_query("since=42&wait=30"), (42, 30))
        self.assertEqual(notify.parse_query("since=0"), (0, 0))
        self.assertEqual(notify.parse_query("wait=999&since=1"), (1, 60))
        self.assertEqual(notify.parse_query(""), (None, 0))
        for bad in ("since=-1", "since=abc", "since=1e9", "since=" + "9" * 20):
            self.assertIsNone(notify.parse_query(bad)[0], bad)

    def test_rate_limiter(self):
        now = [0.0]
        limiter = notify.RateLimiter(3, clock=lambda: now[0])
        self.assertEqual([limiter.allow("a") for _ in range(4)], [True, True, True, False])
        self.assertTrue(limiter.allow("b"))
        now[0] = 61
        self.assertTrue(limiter.allow("a"))


class EventsServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = EventLog(Path(self.tmp.name))
        self.server = notify.EventsServer(("127.0.0.1", 0), TOKEN, self.log, poll_every=0.05)
        self.port = self.server.server_address[1]
        mock.patch.object(notify.EventsHandler, "log_message", lambda *a: None).start()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        mock.patch.stopall()
        self.server.shutdown()
        self.server.server_close()

    def get(self, path, token=TOKEN, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
        conn.request(method, path, headers=headers)
        response = conn.getresponse()
        result = response.status, json.loads(response.read() or b"{}")
        conn.close()
        return result

    def test_token_is_required(self):
        self.assertEqual(self.get("/events?since=0", token=None)[0], 401)
        self.assertEqual(self.get("/events?since=0", token="wrong")[0], 401)
        self.assertEqual(self.get("/events?since=0", token=TOKEN + "x")[0], 401)

    def test_without_since_only_the_current_position_is_returned(self):
        self.log.add("new_device")
        self.log.add("new_device")
        self.assertEqual(self.get("/events"), (200, {"events": [], "last_id": 2}))

    def test_returns_newer_events(self):
        self.log.add("new_device", count=1)
        self.log.add("new_high_risk", count=2)
        status, body = self.get("/events?since=1")
        self.assertEqual(status, 200)
        self.assertEqual([e["type"] for e in body["events"]], ["new_high_risk"])
        self.assertEqual(body["last_id"], 2)

    def test_long_poll_answers_as_soon_as_an_event_arrives(self):
        threading.Timer(0.3, lambda: self.log.add("new_device", count=1)).start()
        started = time.monotonic()
        status, body = self.get("/events?since=0&wait=10")
        elapsed = time.monotonic() - started
        self.assertEqual(status, 200)
        self.assertEqual(len(body["events"]), 1)
        self.assertLess(elapsed, 3)

    def test_long_poll_times_out_with_an_empty_list(self):
        status, body = self.get("/events?since=0&wait=1")
        self.assertEqual((status, body), (200, {"events": [], "last_id": 0}))

    def test_read_only_and_single_path(self):
        self.assertEqual(self.get("/events?since=0", method="POST")[0], 405)
        self.assertEqual(self.get("/events?since=0", method="DELETE")[0], 405)
        self.assertEqual(self.get("/scan")[0], 404)

    def test_too_many_open_long_polls_are_refused(self):
        self.server.waiters = threading.BoundedSemaphore(1)
        self.server.waiters.acquire()
        try:
            self.assertEqual(self.get("/events?since=0&wait=1")[0], 503)
        finally:
            self.server.waiters.release()

    def test_rate_limit_per_client(self):
        self.server.limiter = notify.RateLimiter(2)
        codes = [self.get("/events")[0] for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])


class PairTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        mock.patch.object(notify, "STATE_DIR", Path(self.tmp.name) / "ajar").start()
        mock.patch.object(notify, "pi_address", return_value="172.20.10.5").start()
        mock.patch.object(notify.shutil, "which", return_value=None).start()
        self.addCleanup(mock.patch.stopall)

    def pair(self, rotate=False):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(notify.cmd_pair(rotate), 0)
        return out.getvalue()

    def test_pair_creates_a_token_and_prints_the_pairing_uri(self):
        out = self.pair()
        token = notify.load_token()
        self.assertTrue(token and len(token) >= 40)
        self.assertIn("ajar://pair?host=172.20.10.5&port=8002&token=" + token, out)

    def test_pair_again_keeps_the_token_and_new_rotates_it(self):
        self.pair()
        first = notify.load_token()
        self.pair()
        self.assertEqual(notify.load_token(), first)
        self.pair(rotate=True)
        self.assertNotEqual(notify.load_token(), first)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_token_file_is_private(self):
        self.pair()
        self.assertEqual(notify.token_path().stat().st_mode & 0o777, 0o600)

    def test_serve_refuses_to_start_without_a_token(self):
        with mock.patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(notify.cmd_serve(), 1)


if __name__ == "__main__":
    unittest.main()
