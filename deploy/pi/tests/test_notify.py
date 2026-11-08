"""Tests for the event log, paired phones, the pairing window and the phone events service.
Standard library only; HTTP runs on a random localhost port, nothing is scanned.
Run:  python3 -m unittest discover -s deploy/pi/tests -v
"""
import datetime as dt
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
from ajar_phones import PairingError, PairingWindow, PhoneRegistry, clean_name  # noqa: E402

spec = importlib.util.spec_from_file_location("ajar_notify", HERE.parent / "ajar_notify.py")
notify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notify)


class TempStateTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "ajar"


class EventLogTests(TempStateTestCase):
    def setUp(self):
        super().setUp()
        self.log = EventLog(self.state)

    def test_empty_log(self):
        self.assertEqual(self.log.last_id(), 0)
        self.assertEqual(self.log.since(0), [])

    def test_add_and_read_since(self):
        first = self.log.add("new_device", count=2)
        second = self.log.add("score_drop", score=40, previous=90)
        self.assertEqual(self.log.last_id(), second)
        events = self.log.since(first)
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


class PhoneRegistryTests(TempStateTestCase):
    def test_each_phone_gets_its_own_token_and_only_a_hash_is_stored(self):
        phones = PhoneRegistry(self.state)
        id1, token1 = phones.add("Pixel 7")
        id2, token2 = phones.add("Galaxy")
        self.assertNotEqual(token1, token2)
        self.assertEqual(phones.verify(token1), id1)
        self.assertEqual(phones.verify(token2), id2)
        self.assertIsNone(phones.verify(token1 + "x"))
        self.assertIsNone(phones.verify(""))
        stored = (self.state / "phones.json").read_text()
        self.assertNotIn(token1, stored)
        self.assertNotIn(token2, stored)

    def test_unpair_one_phone_keeps_the_others(self):
        phones = PhoneRegistry(self.state)
        id1, token1 = phones.add("Pixel 7")
        _, token2 = phones.add("Galaxy")
        self.assertEqual(phones.remove(id1), 1)
        self.assertIsNone(phones.verify(token1))
        self.assertIsNotNone(phones.verify(token2))
        self.assertEqual(phones.remove("Galaxy"), 1)
        self.assertEqual(phones.list(), [])

    def test_legacy_qr_token_still_works_and_can_be_removed(self):
        self.state.mkdir(parents=True)
        (self.state / "notify.token").write_text("legacy-token-value\n")
        phones = PhoneRegistry(self.state)
        self.assertEqual(phones.verify("legacy-token-value"), "qr-legacy")
        phones.remove("qr-legacy")
        self.assertIsNone(phones.verify("legacy-token-value"))

    def test_remove_all(self):
        phones = PhoneRegistry(self.state)
        _, token = phones.add("Pixel 7")
        phones.remove_all()
        self.assertIsNone(phones.verify(token))

    def test_clean_name(self):
        self.assertEqual(clean_name("  Pixel\n7\x1b[31m "), "Pixel7[31m")
        self.assertEqual(clean_name(""), "Telefon")
        self.assertEqual(len(clean_name("x" * 100)), 40)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_phone_file_is_private(self):
        PhoneRegistry(self.state).add("Pixel 7")
        self.assertEqual((self.state / "phones.json").stat().st_mode & 0o777, 0o600)


class PairingWindowTests(TempStateTestCase):
    def setUp(self):
        super().setUp()
        self.window = PairingWindow(self.state)
        self.phones = PhoneRegistry(self.state)

    def test_no_request_without_an_open_window(self):
        with self.assertRaises(PairingError) as ctx:
            self.window.request("Pixel 7")
        self.assertEqual(ctx.exception.status, 403)

    def test_full_flow_token_handed_out_exactly_once(self):
        self.window.open(2)
        asked = self.window.request("Pixel 7")
        self.assertRegex(asked["code"], r"^\d{3}$")
        self.assertEqual(self.window.pending(), {"name": "Pixel 7", "code": asked["code"]})
        self.assertEqual(self.window.poll(asked["request_id"], self.phones), {"status": "pending"})
        self.window.decide(True)
        first = self.window.poll(asked["request_id"], self.phones)
        self.assertEqual(first["status"], "approved")
        self.assertEqual(self.phones.verify(first["token"]), first["phone_id"])
        self.assertEqual(self.window.poll(asked["request_id"], self.phones), {"status": "delivered"})
        self.assertEqual(len(self.phones.list()), 1)

    def test_only_one_pending_request(self):
        self.window.open(2)
        self.window.request("Pixel 7")
        with self.assertRaises(PairingError) as ctx:
            self.window.request("Stranger")
        self.assertEqual(ctx.exception.status, 409)

    def test_rejected_request_gets_no_token(self):
        self.window.open(2)
        asked = self.window.request("Stranger")
        self.window.decide(False)
        self.assertEqual(self.window.poll(asked["request_id"], self.phones), {"status": "rejected"})
        self.assertEqual(self.phones.list(), [])

    def test_wrong_request_id_is_unknown(self):
        self.window.open(2)
        self.window.request("Pixel 7")
        self.window.decide(True)
        with self.assertRaises(PairingError) as ctx:
            self.window.poll("not-the-right-id-xxxxxxxx", self.phones)
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(self.phones.list(), [])

    def test_expired_window(self):
        start = dt.datetime(2026, 11, 8, 12, 0, tzinfo=dt.timezone.utc)
        self.window.open(2, now=start)
        asked = self.window.request("Pixel 7", now=start + dt.timedelta(seconds=30))
        later = start + dt.timedelta(minutes=3)
        self.assertIsNone(self.window.pending(now=later))
        self.assertEqual(self.window.poll(asked["request_id"], self.phones, now=later), {"status": "expired"})
        with self.assertRaises(PairingError):
            self.window.request("Pixel 7", now=later)

    def test_approval_is_only_possible_for_a_pending_request(self):
        self.window.open(2)
        self.window.decide(True)                    # nothing pending: no effect
        self.assertEqual(self.window.status_name(), "open")


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


class ServerTestCase(TempStateTestCase):
    def setUp(self):
        super().setUp()
        self.server = notify.EventsServer(("127.0.0.1", 0), self.state, poll_every=0.05)
        self.port = self.server.server_address[1]
        mock.patch.object(notify.EventsHandler, "log_message", lambda *a: None).start()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        _, self.token = self.server.phones.add("Pixel 7")

    def tearDown(self):
        mock.patch.stopall()
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def request(self, method, path, token=None, body=None, ctype="application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode() if not isinstance(body, bytes) else body
            headers.update({"Content-Type": ctype, "Content-Length": str(len(data))})
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        result = response.status, json.loads(response.read() or b"{}")
        conn.close()
        return result


class EventsServerTests(ServerTestCase):
    def test_token_is_required(self):
        self.assertEqual(self.request("GET", "/events?since=0")[0], 401)
        self.assertEqual(self.request("GET", "/events?since=0", token="wrong")[0], 401)

    def test_without_since_only_the_current_position_is_returned(self):
        self.server.log.add("new_device")
        self.server.log.add("new_device")
        self.assertEqual(self.request("GET", "/events", self.token), (200, {"events": [], "last_id": 2}))

    def test_returns_newer_events(self):
        self.server.log.add("new_device", count=1)
        self.server.log.add("new_high_risk", count=2)
        status, body = self.request("GET", "/events?since=1", self.token)
        self.assertEqual([e["type"] for e in body["events"]], ["new_high_risk"])
        self.assertEqual((status, body["last_id"]), (200, 2))

    def test_long_poll_answers_as_soon_as_an_event_arrives(self):
        threading.Timer(0.3, lambda: self.server.log.add("new_device", count=1)).start()
        started = time.monotonic()
        status, body = self.request("GET", "/events?since=0&wait=10", self.token)
        self.assertEqual((status, len(body["events"])), (200, 1))
        self.assertLess(time.monotonic() - started, 3)

    def test_long_poll_times_out_with_an_empty_list(self):
        self.assertEqual(self.request("GET", "/events?since=0&wait=1", self.token),
                         (200, {"events": [], "last_id": 0}))

    def test_only_pair_accepts_post_and_nothing_else_writes(self):
        self.assertEqual(self.request("POST", "/events?since=0", self.token, body={})[0], 405)
        self.assertEqual(self.request("DELETE", "/events", self.token)[0], 405)
        self.assertEqual(self.request("GET", "/scan", self.token)[0], 404)

    def test_too_many_open_long_polls_are_refused(self):
        self.server.waiters = threading.BoundedSemaphore(1)
        self.server.waiters.acquire()
        try:
            self.assertEqual(self.request("GET", "/events?since=0&wait=1", self.token)[0], 503)
        finally:
            self.server.waiters.release()

    def test_rate_limit_per_client(self):
        self.server.limiter = notify.RateLimiter(2)
        self.assertEqual([self.request("GET", "/events", self.token)[0] for _ in range(3)], [200, 200, 429])


class PairingHttpTests(ServerTestCase):
    def test_pairing_over_http_with_approval_on_the_pi(self):
        self.server.window.open(2)
        status, asked = self.request("POST", "/pair", body={"name": "Pixel 8"})
        self.assertEqual(status, 200)
        self.assertRegex(asked["code"], r"^\d{3}$")
        self.assertEqual(self.server.window.pending()["code"], asked["code"])
        self.assertEqual(self.request("GET", f"/pair/{asked['request_id']}"), (200, {"status": "pending"}))
        self.server.window.decide(True)                       # what the owner does on the Pi
        status, result = self.request("GET", f"/pair/{asked['request_id']}")
        self.assertEqual((status, result["status"]), (200, "approved"))
        self.assertEqual(self.request("GET", "/events", result["token"])[0], 200)
        self.assertEqual(self.request("GET", f"/pair/{asked['request_id']}"), (200, {"status": "delivered"}))

    def test_pair_is_refused_when_the_window_is_closed(self):
        self.assertEqual(self.request("POST", "/pair", body={"name": "x"})[0], 403)

    def test_second_phone_during_a_pending_request_is_refused(self):
        self.server.window.open(2)
        self.request("POST", "/pair", body={"name": "Mine"})
        self.assertEqual(self.request("POST", "/pair", body={"name": "Stranger"})[0], 409)

    def test_pair_body_rules(self):
        self.server.window.open(2)
        self.assertEqual(self.request("POST", "/pair", body=b"{}", ctype="text/plain")[0], 400)
        self.assertEqual(self.request("POST", "/pair", body=b"not json")[0], 400)
        self.assertEqual(self.request("POST", "/pair", body=b"x" * 2000)[0], 400)

    def test_bad_or_unknown_request_ids(self):
        for rid in ("short", "../../etc/passwd", "a" * 100, "x" * 32):
            self.assertEqual(self.request("GET", f"/pair/{rid}")[0], 404, rid)


class OwnerCommandTests(TempStateTestCase):
    def test_owner_approves_the_matching_code(self):
        window, phones = PairingWindow(self.state), PhoneRegistry(self.state)
        asked = {}

        def phone_side():
            asked.update(window.request("Pixel 8"))
        steps = iter([phone_side])

        def sleep(_):
            step = next(steps, None)
            if step:
                step()
            elif window.status_name() == "approved":
                window.poll(asked["request_id"], phones)        # the phone fetches its token

        out = []
        code = notify.run_pairing_window(window, 2, ask=lambda _: "DA", sleep=sleep, out=out.append)
        self.assertEqual(code, 0)
        self.assertEqual(len(phones.list()), 1)
        self.assertTrue(any(" ".join(asked["code"]) in line.replace("  ", " ") for line in out))
        self.assertFalse((self.state / "pairing.json").exists())

    def test_owner_rejects(self):
        window, phones = PairingWindow(self.state), PhoneRegistry(self.state)
        steps = iter([lambda: window.request("Stranger")])
        code = notify.run_pairing_window(window, 2, ask=lambda _: "nu",
                                         sleep=lambda _: next(steps, lambda: None)(), out=lambda *_: None)
        self.assertEqual(code, 1)
        self.assertEqual(phones.list(), [])

    def test_window_expires_without_a_request(self):
        now = [0.0]

        def sleep(seconds):
            now[0] += seconds
        code = notify.run_pairing_window(PairingWindow(self.state), 1, ask=lambda _: "DA", sleep=sleep,
                                         clock=lambda: now[0], out=lambda *_: None)
        self.assertEqual(code, 1)

    def test_qr_pairing_creates_one_phone(self):
        phones = PhoneRegistry(self.state)
        with mock.patch.object(notify, "pi_address", return_value="172.20.10.5"), \
                mock.patch.object(notify.shutil, "which", return_value=None), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            notify.cmd_pair_qr(phones, "Old phone")
        self.assertEqual(len(phones.list()), 1)
        uri = [line for line in out.getvalue().splitlines() if line.startswith("ajar://pair?")][0]
        token = uri.split("token=")[1].split("&")[0]
        self.assertIsNotNone(phones.verify(token))


if __name__ == "__main__":
    unittest.main()
