"""Rule traps: tunnel=ssl, filtered, open|filtered UDP, SMB 139+445, UNKNOWN_DEVICE, outdated versions."""
import unittest
from netcheck.analysis.models import Device, Port
from netcheck.analysis.rules import evaluate_device
from netcheck.analysis.versions import is_outdated_service


class TestRules(unittest.TestCase):
    def test_https_ssl_tunnel_not_admin_cleartext(self):
        """HTTPS (tunnel='ssl') must NOT trigger HTTP_ADMIN_CLEARTEXT even if title says 'Admin Login'."""
        dev = Device(
            ip="192.168.1.8",
            vendor="Ubiquiti",
            hostname="ap",
            ports=[
                Port(portid=8443, protocol="tcp", state="open", service_name="http", tunnel="ssl", http_title="Admin Login")
            ]
        )
        findings = evaluate_device("test.xml", dev)
        self.assertFalse(any(f.finding_code == "HTTP_ADMIN_CLEARTEXT" for f in findings))

    def test_filtered_and_closed_ports_ignored(self):
        """Only ports with state='open' can produce findings."""
        dev = Device(
            ip="192.168.1.9",
            vendor="Dell",
            hostname="db",
            ports=[
                Port(portid=3306, protocol="tcp", state="filtered", service_name="mysql"),
                Port(portid=23, protocol="tcp", state="closed", service_name="telnet"),
                Port(portid=161, protocol="udp", state="open|filtered", service_name="snmp"),
            ]
        )
        findings = evaluate_device("test.xml", dev)
        self.assertEqual(len(findings), 0)

    def test_smb_one_per_device_prefers_445(self):
        """When both 139 and 445 are open, exactly one SMB finding is produced on port 445."""
        dev = Device(
            ip="192.168.1.20",
            vendor="Synology",
            hostname="nas",
            ports=[
                Port(portid=139, protocol="tcp", state="open", service_name="netbios-ssn"),
                Port(portid=445, protocol="tcp", state="open", service_name="microsoft-ds"),
            ]
        )
        findings = evaluate_device("test.xml", dev)
        smb_findings = [f for f in findings if f.finding_code == "SMB_EXPOSED"]
        self.assertEqual(len(smb_findings), 1)
        self.assertEqual(smb_findings[0].port, 445)

    def test_smb_fallback_to_139(self):
        """When only 139 is open, SMB finding is on port 139."""
        dev = Device(
            ip="192.168.1.21",
            vendor="Synology",
            hostname="nas2",
            ports=[
                Port(portid=139, protocol="tcp", state="open", service_name="netbios-ssn"),
            ]
        )
        findings = evaluate_device("test.xml", dev)
        smb_findings = [f for f in findings if f.finding_code == "SMB_EXPOSED"]
        self.assertEqual(len(smb_findings), 1)
        self.assertEqual(smb_findings[0].port, 139)

    def test_unknown_device_rule(self):
        """Device with no MAC vendor and no hostname and >= 1 open port triggers UNKNOWN_DEVICE with empty port."""
        dev = Device(
            ip="192.168.1.99",
            vendor="",
            hostname="",
            ports=[
                Port(portid=8888, protocol="tcp", state="open", service_name="sun-answerbook")
            ]
        )
        findings = evaluate_device("test.xml", dev)
        unknown = [f for f in findings if f.finding_code == "UNKNOWN_DEVICE"]
        self.assertEqual(len(unknown), 1)
        self.assertIsNone(unknown[0].port)
        self.assertEqual(unknown[0].points, 5)

    def test_mini_httpd_is_not_apache(self):
        """mini_httpd is not Apache httpd and must not trigger OUTDATED_SERVICE."""
        self.assertFalse(is_outdated_service("http", "mini_httpd", "1.19"))

    def test_outdated_versions_detection(self):
        """Validates the official list of outdated versions."""
        # vsftpd 2.3.4
        self.assertTrue(is_outdated_service("ftp", "vsftpd", "2.3.4"))
        self.assertFalse(is_outdated_service("ftp", "vsftpd", "3.0.3"))

        # OpenSSH < 7.4
        self.assertTrue(is_outdated_service("ssh", "OpenSSH", "6.6.1p1"))
        self.assertTrue(is_outdated_service("ssh", "OpenSSH", "7.2p2 Ubuntu-4"))
        self.assertFalse(is_outdated_service("ssh", "OpenSSH", "7.4"))
        self.assertFalse(is_outdated_service("ssh", "OpenSSH", "8.4p1 Debian 5+deb11u3"))

        # Apache httpd <= 2.2.x
        self.assertTrue(is_outdated_service("http", "Apache httpd", "2.2.34"))
        self.assertFalse(is_outdated_service("http", "Apache", "2.4.52"))

        # Microsoft IIS <= 7.5
        self.assertTrue(is_outdated_service("http", "Microsoft IIS", "7.5"))
        self.assertFalse(is_outdated_service("http", "Microsoft-IIS", "10.0"))

        # Samba <= 3.x
        self.assertTrue(is_outdated_service("netbios-ssn", "Samba smbd", "3.0.24"))
        self.assertFalse(is_outdated_service("microsoft-ds", "Samba smbd", "4.15"))


if __name__ == "__main__":
    unittest.main()
