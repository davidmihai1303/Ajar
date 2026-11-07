"""Rule traps: tunnel=ssl, filtered, open|filtered UDP, SMB 139+445, UNKNOWN_DEVICE, outdated versions."""
import unittest
from netcheck.analysis.models import Device, Port
from netcheck.analysis.parser import MAX_TEXT_CHARS, parse_bytes
from netcheck.analysis.rules import evaluate_device, evaluate_devices
from netcheck.analysis.scoring import compute_score
from netcheck.analysis.versions import is_outdated_service


class TestRules(unittest.TestCase):
    def test_admin_evidence_survives_a_long_title(self):
        for position in (MAX_TEXT_CHARS - 2, MAX_TEXT_CHARS + 20, 3000):
            with self.subTest(position=position):
                title = "x" * position + "aDmIn 02:00:00:01:02:03"
                xml = ('<nmaprun><host><status state="up"/><address addrtype="ipv4" addr="192.0.2.1"/>'
                       '<hostnames><hostname name="web"/></hostnames><ports><port protocol="tcp" portid="80">'
                       '<state state="open"/><service name="http"/><script id="http-title">'
                       f'<elem key="title">{title}</elem></script></port></ports></host></nmaprun>')
                scan = parse_bytes(xml.encode(), "web.xml")
                excerpt = scan.devices[0].ports[0].http_title
                self.assertLessEqual(len(excerpt), MAX_TEXT_CHARS)
                self.assertIn("aDmIn 02:00:00:xx:xx:xx", excerpt)
                findings = evaluate_devices(scan.devices)
                self.assertEqual([f.code for f in findings], ["HTTP_ADMIN_CLEARTEXT"])
                self.assertIn(excerpt, findings[0].evidence)
                self.assertEqual(compute_score(findings), 90)

    def test_https_ssl_tunnel_not_admin_cleartext(self):
        """HTTPS (tunnel='ssl') must NOT trigger HTTP_ADMIN_CLEARTEXT even if title says 'Admin Login'."""
        dev = Device(
            ip="192.168.1.8",
            vendor="Ubiquiti",
            hostname="ap",
            ports=[
                Port(port=8443, protocol="tcp", state="open", service="http", tunnel="ssl", scripts={"http-title": "Admin Login"})
            ]
        )
        findings = evaluate_device(dev)
        self.assertFalse(any(f.code == "HTTP_ADMIN_CLEARTEXT" for f in findings))

    def test_filtered_and_closed_ports_ignored(self):
        """Only ports with state='open' can produce findings."""
        dev = Device(
            ip="192.168.1.9",
            vendor="Dell",
            hostname="db",
            ports=[
                Port(port=3306, protocol="tcp", state="filtered", service="mysql"),
                Port(port=23, protocol="tcp", state="closed", service="telnet"),
                Port(port=161, protocol="udp", state="open|filtered", service="snmp"),
            ]
        )
        findings = evaluate_device(dev)
        self.assertEqual(len(findings), 0)

    def test_smb_one_per_device_prefers_445(self):
        """When both 139 and 445 are open, exactly one SMB finding is produced on port 445."""
        dev = Device(
            ip="192.168.1.20",
            vendor="Synology",
            hostname="nas",
            ports=[
                Port(port=139, protocol="tcp", state="open", service="netbios-ssn"),
                Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),
            ]
        )
        findings = evaluate_device(dev)
        smb_findings = [f for f in findings if f.code == "SMB_EXPOSED"]
        self.assertEqual(len(smb_findings), 1)
        self.assertEqual(smb_findings[0].port, 445)

    def test_smb_fallback_to_139(self):
        """When only 139 is open, SMB finding is on port 139."""
        dev = Device(
            ip="192.168.1.21",
            vendor="Synology",
            hostname="nas2",
            ports=[
                Port(port=139, protocol="tcp", state="open", service="netbios-ssn"),
            ]
        )
        findings = evaluate_device(dev)
        smb_findings = [f for f in findings if f.code == "SMB_EXPOSED"]
        self.assertEqual(len(smb_findings), 1)
        self.assertEqual(smb_findings[0].port, 139)

    def test_outdated_is_per_port_and_smb_exposure_is_per_device(self):
        """Report the version evidence on each port and the SMB exposure once."""
        dev = Device(
            ip="192.168.1.22",
            vendor="Synology",
            hostname="old-nas",
            ports=[
                Port(port=139, protocol="tcp", state="open", service="netbios-ssn", product="Samba smbd", version="3.0.24"),
                Port(port=445, protocol="tcp", state="open", service="microsoft-ds", product="Samba smbd", version="3.0.24"),
            ]
        )
        findings = evaluate_device(dev)
        codes = [(f.port, f.code) for f in findings]
        self.assertEqual(codes, [(139, "OUTDATED_SERVICE"), (445, "OUTDATED_SERVICE"), (445, "SMB_EXPOSED")])

    def test_smb_version_on_139_survives_selecting_445_for_exposure(self):
        device = Device(ip="192.0.2.1", hostname="nas", ports=(
            Port("tcp", 139, "open", "netbios-ssn", "Samba smbd", "3.0.24"),
            Port("tcp", 445, "open", "microsoft-ds"),
        ))
        findings = evaluate_device(device)
        self.assertEqual([(f.port, f.code) for f in findings], [(139, "OUTDATED_SERVICE"), (445, "SMB_EXPOSED")])
        self.assertEqual(compute_score(findings), 70)

    def test_same_csv_finding_across_transports_or_host_records_counts_once(self):
        tcp = Port("tcp", 554, "open", "rtsp")
        udp = Port("udp", 554, "open", "rtsp")
        hosts = [Device(ip="192.0.2.1", ports=(udp,)), Device(ip="192.0.2.1", hostname="camera", ports=(tcp, udp))]
        findings = evaluate_devices(hosts)
        self.assertEqual([(f.port, f.protocol, f.code) for f in findings], [(554, "tcp", "CAMERA_STREAM_EXPOSED")])
        self.assertEqual(compute_score(findings), 80)
        self.assertEqual(findings, evaluate_devices(reversed(hosts)))

    def test_upnp_and_snmp_udp_only(self):
        """UPNP_EXPOSED and SNMP_EXPOSED only trigger on UDP, never on TCP."""
        dev = Device(
            ip="192.168.1.1",
            vendor="TP-Link",
            hostname="router",
            ports=[
                Port(port=1900, protocol="tcp", state="open", service="upnp"),
                Port(port=161, protocol="tcp", state="open", service="snmp"),
            ]
        )
        findings = evaluate_device(dev)
        self.assertEqual(len(findings), 0)

    def test_unknown_device_rule(self):
        """Device with no MAC vendor and no hostname and >= 1 open port triggers UNKNOWN_DEVICE with empty port."""
        dev = Device(
            ip="192.168.1.99",
            vendor="",
            hostname="",
            ports=[
                Port(port=8888, protocol="tcp", state="open", service="sun-answerbook")
            ]
        )
        findings = evaluate_device(dev)
        unknown = [f for f in findings if f.code == "UNKNOWN_DEVICE"]
        self.assertEqual(len(unknown), 1)
        self.assertIsNone(unknown[0].port)
        self.assertEqual(unknown[0].points, 5)

    def test_mini_httpd_and_tomcat_are_not_apache_httpd(self):
        """mini_httpd and Apache Tomcat are not Apache httpd and must not trigger OUTDATED_SERVICE."""
        self.assertFalse(is_outdated_service("mini_httpd", "1.19"))
        self.assertFalse(is_outdated_service("Apache Tomcat", "2.1"))

    def test_outdated_requires_a_conclusive_version(self):
        cases = [
            ("Samba smbd", "3.X - 4.X", False), ("Samba smbd", "3.0–4.1", False),
            ("Samba smbd", "3.X or newer", False), ("Samba smbd", "3.0 - 3.6", True),
            ("Samba smbd", "3.X", True), ("OpenSSH", "7.X", False),
            ("OpenSSH", "6.9-7.3", True), ("OpenSSH", "7.2 to 7.4", False),
            ("vsftpd", "2.3.4.1", False), ("vsftpd", "2.3.4-1ubuntu1", True),
            ("Apache httpd", "unknown build 2.2", False), ("Apache httpd", "2.2.x", True),
            ("Samba smbd", "3.0.14a", True), ("Samba smbd", "3.0.20b (Debian)", True),
            ("Samba smbd", "3.X (or newer)", False), ("Samba smbd", "3.X (newer releases possible)", False),
            ("Samba smbd", "3.0.14a - 4.0.0", False), ("vsftpd", "2.3.4a", False),
        ]
        for product, version, expected in cases:
            with self.subTest(product=product, version=version):
                self.assertEqual(is_outdated_service(product, version), expected)

    def test_outdated_versions_detection(self):
        """Validates the official list of outdated versions."""
        # vsftpd 2.3.4
        self.assertTrue(is_outdated_service("vsftpd", "2.3.4"))
        self.assertFalse(is_outdated_service("vsftpd", "3.0.3"))

        # OpenSSH < 7.4
        self.assertTrue(is_outdated_service("OpenSSH", "6.6.1p1"))
        self.assertTrue(is_outdated_service("OpenSSH", "7.2p2 Ubuntu-4"))
        self.assertFalse(is_outdated_service("OpenSSH", "7.4"))
        self.assertFalse(is_outdated_service("OpenSSH", "8.4p1 Debian 5+deb11u3"))

        # Apache httpd <= 2.2.x
        self.assertTrue(is_outdated_service("Apache httpd", "2.2.34"))
        self.assertFalse(is_outdated_service("Apache httpd", "2.4.52"))

        # Microsoft IIS <= 7.5
        self.assertTrue(is_outdated_service("Microsoft IIS", "7.5"))
        self.assertFalse(is_outdated_service("Microsoft-IIS", "10.0"))

        # Samba <= 3.x
        self.assertTrue(is_outdated_service("Samba smbd", "3.0.24"))
        self.assertFalse(is_outdated_service("Samba smbd", "4.15"))

    def test_upper_bound_must_qualify_for_the_specific_catalog_rule(self):
        for version, expected_score in [
            ("3.6 or older", 70), ("3.6 or earlier", 70), ("3.X (OR OLDER)", 70),
            ("3.0.14a (Debian) and earlier", 70), ("3.6 or older (Debian)", 70), ("4.0 or older", 90),
            ("3.6 or older (higher versions possible)", 90),
            ("3.6 or newer", 90), ("3.6 or later", 90), ("3.6 or newer or older", 90),
        ]:
            with self.subTest(version=version):
                nas = Device(ip="192.0.2.1", hostname="nas", ports=(
                    Port("tcp", 445, "open", "microsoft-ds", "Samba smbd", version),
                ))
                self.assertEqual(compute_score(evaluate_device(nas)), expected_score)
        self.assertTrue(is_outdated_service("OpenSSH", "7.3 or older"))
        self.assertFalse(is_outdated_service("OpenSSH", "7.4 or older"))
        self.assertTrue(is_outdated_service("Apache httpd", "2.2.x or earlier"))
        self.assertTrue(is_outdated_service("Microsoft IIS", "7.5 (or earlier)"))
        self.assertFalse(is_outdated_service("vsftpd", "2.3.4 or older"))


if __name__ == "__main__":
    unittest.main()
