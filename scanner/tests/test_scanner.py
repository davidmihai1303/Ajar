"""Scanner tests: scope guard, network detection, root wrapper selection, agent HTTP checks.

Standard library only, never touches the network and never starts a real scan:
    python3 -m unittest discover -s scanner/tests -v
"""
import http.client
import importlib.machinery
import importlib.util
import json
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.dirname(HERE)
sys.path.insert(0, SCANNER)

import agent  # noqa: E402
import detect  # noqa: E402
from detect import DetectError, choose_network  # noqa: E402
from guard import ScopeError, check_scope  # noqa: E402


def load_wrapper():
    """Load scanner/netcheck-nmap (no .py extension) as a module without running main()."""
    path = os.path.join(SCANNER, "netcheck-nmap")
    loader = importlib.machinery.SourceFileLoader("netcheck_nmap", path)
    spec = importlib.util.spec_from_loader("netcheck_nmap", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def iface(name: str, ip: str, prefix: int, flags=None, family: str = "inet") -> dict:
    return {"ifname": name, "flags": flags or ["BROADCAST", "UP", "LOWER_UP"],
            "addr_info": [{"family": family, "local": ip, "prefixlen": prefix}]}


LOOPBACK = iface("lo", "127.0.0.1", 8, ["LOOPBACK", "UP", "LOWER_UP"])
HOTSPOT = iface("wlp2s0", "172.20.10.9", 28)
VENUE_CABLE = iface("enp3s0", "10.5.3.20", 24)
DOCKER = iface("docker0", "172.17.0.1", 16)
VPN = iface("wg0", "10.8.0.2", 24)
ROUTES = [{"dst": "default", "gateway": "10.5.3.1", "dev": "enp3s0"},
          {"dst": "default", "gateway": "172.20.10.1", "dev": "wlp2s0"}]
HOTSPOT_NET = "172.20.10.0/28"


class GuardTests(unittest.TestCase):
    """Live check #4: public IPs and the venue network are refused."""

    def refused(self, target: str, confirm: bool = True) -> ScopeError:
        with self.assertRaises(ScopeError) as ctx:
            check_scope(target, [HOTSPOT_NET], confirm)
        return ctx.exception

    def test_public_ip_refused(self):
        self.assertIn("not a private", self.refused("8.8.8.8").en)

    def test_public_ip_refused_for_the_right_reason_without_confirm(self):
        self.assertIn("not a private", self.refused("8.8.8.8", confirm=False).en)

    def test_everything_refused(self):
        self.refused("0.0.0.0/0")

    def test_too_large_refused(self):
        self.assertIn("too large", self.refused("10.0.0.0/8").en)

    def test_venue_network_refused(self):
        self.assertIn("outside the allowed", self.refused("10.5.3.0/24").en)

    def test_other_private_network_refused(self):
        self.assertIn("outside the allowed", self.refused("192.168.1.0/24").en)

    def test_hostname_refused(self):
        self.assertIn("not a valid", self.refused("google.com").en)

    def test_carrier_grade_nat_refused(self):
        self.refused("100.64.0.0/24")

    def test_wider_than_own_subnet_refused(self):
        self.refused("172.20.10.0/27")

    def test_own_subnet_needs_confirm(self):
        self.assertIn("--confirm", self.refused(HOTSPOT_NET, confirm=False).en)

    def test_own_subnet_allowed_with_confirm(self):
        self.assertEqual(str(check_scope(HOTSPOT_NET, [HOTSPOT_NET], True)), HOTSPOT_NET)

    def test_single_host_in_own_subnet_allowed(self):
        self.assertEqual(str(check_scope("172.20.10.5", [HOTSPOT_NET], True)), "172.20.10.5/32")

    def test_refusals_are_bilingual(self):
        error = self.refused("8.8.8.8")
        self.assertTrue(error.en and error.ro and error.en != error.ro)


class DetectTests(unittest.TestCase):
    """FR-01, and never treat the venue network as ours."""

    def test_hotspot_only(self):
        self.assertEqual(choose_network(ROUTES[1:], [LOOPBACK, HOTSPOT]),
                         ("wlp2s0", "172.20.10.9", 28, "172.20.10.1"))

    def test_hotspot_plus_venue_cable_refused(self):
        with self.assertRaises(DetectError) as ctx:
            choose_network(ROUTES, [LOOPBACK, VENUE_CABLE, HOTSPOT])
        self.assertIn("more than one network", ctx.exception.en)
        self.assertIn("enp3s0", ctx.exception.ro)
        self.assertIn("wlp2s0", ctx.exception.ro)

    def test_docker_and_vpn_ignored(self):
        routes = [{"dst": "default", "gateway": "10.8.0.1", "dev": "wg0"}] + ROUTES[1:]
        name, _, _, _ = choose_network(routes, [LOOPBACK, DOCKER, VPN, HOTSPOT])
        self.assertEqual(name, "wlp2s0")

    def test_unplugged_cable_ignored(self):
        unplugged = iface("enp3s0", "10.5.3.20", 24, ["BROADCAST", "UP", "NO-CARRIER"])
        name, _, _, _ = choose_network(ROUTES[1:], [unplugged, HOTSPOT])
        self.assertEqual(name, "wlp2s0")

    def test_no_network(self):
        with self.assertRaises(DetectError):
            choose_network([], [LOOPBACK, DOCKER])

    def test_no_default_route_gives_empty_gateway(self):
        self.assertEqual(choose_network([], [HOTSPOT])[3], "")


class WrapperTests(unittest.TestCase):
    """The root wrapper must apply the same rule on its own (it imports nothing from the repo)."""

    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_wrapper()

    def test_hotspot_only(self):
        self.assertEqual(str(self.wrapper.choose_subnet([LOOPBACK, DOCKER, HOTSPOT])), HOTSPOT_NET)

    def test_two_networks_refused(self):
        with self.assertRaises(ValueError):
            self.wrapper.choose_subnet([LOOPBACK, VENUE_CABLE, HOTSPOT])

    def test_no_network_refused(self):
        with self.assertRaises(ValueError):
            self.wrapper.choose_subnet([LOOPBACK])

    def test_does_not_import_the_repo(self):
        with open(os.path.join(SCANNER, "netcheck-nmap"), encoding="utf-8") as fh:
            source = fh.read()
        for name in ("detect", "guard", "agent"):
            self.assertNotIn(f"import {name}", source)
            self.assertNotIn(f"from {name}", source)


class InterfaceInventoryTests(unittest.TestCase):
    def test_both_guards_count_the_second_link_before_selecting_an_address(self):
        wrapper = load_wrapper()
        second_links = {
            "public IPv4": iface("enp3s0", "8.8.8.8", 24),
            "IPv6 only": iface("enp3s0", "2001:db8::2", 64, family="inet6"),
            "awaiting an address": {**VENUE_CABLE, "addr_info": []},
        }
        for label, second in second_links.items():
            with self.subTest(link=label):
                inventory = [HOTSPOT, second]
                with self.assertRaisesRegex(DetectError, "more than one network"):
                    choose_network(ROUTES, inventory)
                with self.assertRaisesRegex(ValueError, "more than one network"):
                    wrapper.choose_subnet(inventory)
                with self.assertRaisesRegex(DetectError, "private IPv4"):
                    choose_network([], [second])
                with self.assertRaisesRegex(ValueError, "private IPv4"):
                    wrapper.choose_subnet([second])

    def test_both_entry_points_request_all_address_families(self):
        with mock.patch.object(detect, "_ip_json", side_effect=[ROUTES, [HOTSPOT]]) as query, \
                mock.patch.object(detect, "_ssid", return_value=""):
            self.assertEqual(detect.detect_network().subnet, HOTSPOT_NET)
        self.assertEqual(query.call_args, mock.call("addr", "show"))

        wrapper = load_wrapper()
        with mock.patch.object(wrapper, "first_existing", return_value="/usr/bin/ip"), \
                mock.patch.object(wrapper.subprocess, "run", return_value=mock.Mock(
                    stdout=json.dumps([HOTSPOT]))) as run:
            self.assertEqual(str(wrapper.current_subnet()), HOTSPOT_NET)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/ip", "-j", "addr", "show"])


class TrustedRequestTests(unittest.TestCase):
    """Pure header checks of the HTTP agent."""

    def check(self, headers: dict, method: str = "POST") -> bool:
        return agent.is_trusted_request(headers, 8765, method)[0]

    def test_app_client_accepted(self):
        self.assertTrue(self.check({"Host": "127.0.0.1:8765", "Content-Type": "application/json"}))

    def test_localhost_name_accepted(self):
        self.assertTrue(self.check({"Host": "localhost:8765"}, "GET"))

    def test_dns_rebinding_host_refused(self):
        self.assertFalse(self.check({"Host": "evil.example:8765", "Content-Type": "application/json"}))

    def test_browser_origin_refused(self):
        self.assertFalse(self.check({"Host": "127.0.0.1:8765", "Content-Type": "application/json",
                                     "Origin": "https://evil.example"}))

    def test_text_plain_simple_request_refused(self):
        self.assertFalse(self.check({"Host": "127.0.0.1:8765", "Content-Type": "text/plain"}))

    def test_missing_content_type_refused(self):
        self.assertFalse(self.check({"Host": "127.0.0.1:8765"}))


class RefusalTests(unittest.TestCase):
    def test_sends_refusal_before_bounded_body_cleanup(self):
        handler = agent.Handler.__new__(agent.Handler)
        handler.server = mock.Mock(server_address=("127.0.0.1", 8765))
        handler.headers = {"Host": "localhost:8765", "Content-Type": "text/plain", "Content-Length": "12"}
        handler.connection = mock.Mock()
        handler.rfile = mock.Mock()
        handler._send = mock.Mock()

        def pending_body(length):
            handler._send.assert_called_once()
            self.assertEqual(handler._send.call_args.args[0], 403)
            handler.connection.settimeout.assert_called_once_with(agent.REFUSAL_DRAIN_TIMEOUT_SECONDS)
            raise TimeoutError

        handler.rfile.read1.side_effect = pending_body
        self.assertFalse(handler._trusted("POST"))
        self.assertTrue(handler.close_connection)
        handler.rfile.read1.assert_called_once_with(12)
        handler.rfile.read.assert_not_called()

    def test_invalid_body_answers_400_then_drains_a_bounded_amount(self):
        handler = agent.Handler.__new__(agent.Handler)
        handler.server = mock.Mock(server_address=("127.0.0.1", 8765))
        handler.headers = {"Host": "127.0.0.1:8765", "Content-Type": "application/json", "Content-Length": "abc"}
        handler.path = "/scan"
        handler.connection = mock.Mock()
        handler.rfile = mock.Mock()
        handler._send = mock.Mock()

        def pending_body(length):
            self.assertEqual(handler._send.call_args.args[0], 400)
            raise TimeoutError

        handler.rfile.read1.side_effect = pending_body
        handler.do_POST()
        self.assertTrue(handler.close_connection)
        handler.rfile.read1.assert_called_once_with(agent.MAX_BODY_BYTES)
        handler.rfile.read.assert_not_called()


class AgentHttpTests(unittest.TestCase):
    """Real HTTP round trips against the agent on a random localhost port; scanning is mocked."""

    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), agent.Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        fake_result = {"network": {}, "target": HOTSPOT_NET, "xml_path": "/tmp/scan.xml"}
        self.scan = mock.patch.object(agent, "run_scan", return_value=fake_result).start()
        mock.patch.object(agent.Handler, "log_message", lambda *a: None).start()

    def tearDown(self):
        mock.patch.stopall()
        self.server.shutdown()
        self.server.server_close()

    def post(self, body: bytes, headers: dict) -> tuple:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest("POST", "/scan", skip_host=True)
        for key, value in headers.items():
            conn.putheader(key, value)
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        response = conn.getresponse()
        result = (response.status, json.loads(response.read() or b"{}"))
        conn.close()
        return result

    def test_app_request_starts_scan(self):
        network = {"interface": "wlp2s0", "subnet": HOTSPOT_NET, "gateway": None, "ssid": None}
        body = json.dumps({"confirm": True, "expected_network": network}).encode()
        status, _ = self.post(body, {"Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.scan.assert_called_once_with(True, expected_network=network)

    def test_bare_confirmation_is_refused(self):
        status, refusal = self.post(b'{"confirm": true}', {"Host": f"127.0.0.1:{self.port}",
                                                           "Content-Type": "application/json"})
        self.assertEqual(status, 403)
        self.assertTrue(refusal["ro"] and refusal["en"])
        self.scan.assert_not_called()

    def test_cross_site_simple_request_blocked(self):
        status, _ = self.post(b'{"confirm": true}', {"Host": f"127.0.0.1:{self.port}",
                                                      "Content-Type": "text/plain",
                                                      "Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        self.scan.assert_not_called()

    def test_bad_content_length_is_rejected_not_crashing(self):
        status, _ = self.post(b"{}", {"Host": f"127.0.0.1:{self.port}",
                                      "Content-Type": "application/json",
                                      "Content-Length": "abc"})
        self.assertIn(status, (400, 403))
        self.scan.assert_not_called()


class RunScanTests(unittest.TestCase):
    def test_only_the_confirmed_network_can_be_dispatched(self):
        info = agent.NetworkInfo("wlan0", "172.20.10.9", HOTSPOT_NET, "", "Team")
        approved = {"interface": "wlan0", "subnet": HOTSPOT_NET, "gateway": None, "ssid": "Team"}
        result = mock.Mock(returncode=0, stdout="/tmp/fixture.xml", stderr="")
        with mock.patch.object(agent, "detect_network", return_value=info), \
                mock.patch.object(agent.subprocess, "run", return_value=result) as dispatch:
            for key in approved:
                with self.subTest(key=key), self.assertRaises(ScopeError):
                    agent.run_scan(True, expected_network={**approved, key: "different"})
            with self.assertRaises(ScopeError):
                agent.run_scan(True, expected_network={})
            dispatch.assert_not_called()
            self.assertEqual(agent.run_scan(True, expected_network=approved)["target"], HOTSPOT_NET)
            dispatch.assert_called_once()

    def test_wrapper_without_output_is_a_clear_error(self):
        info = agent.NetworkInfo("wlp2s0", "172.20.10.9", HOTSPOT_NET, "172.20.10.1", "RSH-Byte_me")
        empty = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(agent, "detect_network", return_value=info), \
                mock.patch.object(agent.subprocess, "run", return_value=empty):
            with self.assertRaises(agent.ScanError):
                agent.run_scan(True)


if __name__ == "__main__":
    unittest.main()
