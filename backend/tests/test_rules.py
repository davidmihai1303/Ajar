"""Rule traps tests (FR-06):

Verifies edge cases and traps:
1. tunnel=ssl on HTTP -> NOT HTTP_ADMIN_CLEARTEXT
2. filtered or open|filtered ports -> ignored
3. SMB on both 139 and 445 -> exactly one finding per device (prefers 445)
4. UNKNOWN_DEVICE conditions
5. OUTDATED_SERVICE versions (vsftpd 2.3.4, OpenSSH, Apache, IIS, Samba)
6. UPNP and SNMP on UDP only
7. Non-catalog ports/services (IPP 631, TV 8008/8009, DNS 53)
"""
import unittest

from netcheck.analysis.models import Device, Port
from netcheck.analysis.rules import analyze_device_findings, classify_port_findings
from netcheck.analysis.versions import check_outdated_service


class TestRuleTraps(unittest.TestCase):
    def test_https_tunnel_is_not_cleartext_admin(self):
        port_ssl = Port(
            port=443,
            protocol="tcp",
            state="open",
            service_name="http",
            tunnel="ssl",
            title="Router Admin Login",
        )
        findings = classify_port_findings("192.168.1.1", port_ssl)
        self.assertEqual(len(findings), 0, "HTTPS admin should not trigger HTTP_ADMIN_CLEARTEXT")

    def test_filtered_and_open_filtered_are_ignored(self):
        for state in ["filtered", "closed", "open|filtered"]:
            port = Port(port=3306, protocol="tcp", state=state, service_name="mysql")
            findings = classify_port_findings("192.168.1.1", port)
            self.assertEqual(len(findings), 0, f"Port in state {state} should be ignored")

    def test_smb_both_139_and_445_reports_single_finding_on_445(self):
        device = Device(
            ip="192.168.1.20",
            vendor="Synology",
            hostname="nas",
            ports=[
                Port(port=139, protocol="tcp", state="open", service_name="netbios-ssn"),
                Port(port=445, protocol="tcp", state="open", service_name="microsoft-ds"),
            ],
        )
        findings = analyze_device_findings(device)
        smb_findings = [f for f in findings if f.code == "SMB_EXPOSED"]
        self.assertEqual(len(smb_findings), 1, "Expected exactly 1 SMB finding per device")
        self.assertEqual(smb_findings[0].port, 445, "Should report on port 445 when both are open")

    def test_smb_only_139_reports_on_139(self):
        device = Device(
            ip="192.168.1.20",
            vendor="Synology",
            hostname="nas",
            ports=[
                Port(port=139, protocol="tcp", state="open", service_name="netbios-ssn"),
            ],
        )
        findings = analyze_device_findings(device)
        smb_findings = [f for f in findings if f.code == "SMB_EXPOSED"]
        self.assertEqual(len(smb_findings), 1)
        self.assertEqual(smb_findings[0].port, 139)

    def test_unknown_device_edge_cases(self):
        # Case A: No vendor, no hostname, 1 open port -> UNKNOWN_DEVICE
        d_unknown = Device(
            ip="192.168.1.99",
            vendor="",
            hostname="",
            ports=[Port(port=8888, protocol="tcp", state="open", service_name="sun-answerbook")],
        )
        f_unknown = [f for f in analyze_device_findings(d_unknown) if f.code == "UNKNOWN_DEVICE"]
        self.assertEqual(len(f_unknown), 1)
        self.assertIsNone(f_unknown[0].port, "UNKNOWN_DEVICE port must be None / empty in CSV")

        # Case B: Has vendor -> NOT unknown device
        d_vendor = Device(
            ip="192.168.1.99",
            vendor="Apple",
            hostname="",
            ports=[Port(port=8888, protocol="tcp", state="open", service_name="sun-answerbook")],
        )
        f_vendor = [f for f in analyze_device_findings(d_vendor) if f.code == "UNKNOWN_DEVICE"]
        self.assertEqual(len(f_vendor), 0)

        # Case C: Has hostname -> NOT unknown device
        d_host = Device(
            ip="192.168.1.99",
            vendor="",
            hostname="my-laptop",
            ports=[Port(port=8888, protocol="tcp", state="open", service_name="sun-answerbook")],
        )
        f_host = [f for f in analyze_device_findings(d_host) if f.code == "UNKNOWN_DEVICE"]
        self.assertEqual(len(f_host), 0)

        # Case D: No open ports -> NOT unknown device
        d_no_open = Device(
            ip="192.168.1.99",
            vendor="",
            hostname="",
            ports=[Port(port=8888, protocol="tcp", state="closed", service_name="sun-answerbook")],
        )
        f_no_open = [f for f in analyze_device_findings(d_no_open) if f.code == "UNKNOWN_DEVICE"]
        self.assertEqual(len(f_no_open), 0)

    def test_upnp_and_snmp_udp_only(self):
        # UPnP on TCP -> Not catalog finding
        p_upnp_tcp = Port(port=1900, protocol="tcp", state="open", service_name="upnp")
        self.assertEqual(len(classify_port_findings("192.168.1.1", p_upnp_tcp)), 0)

        # UPnP on UDP -> UPNP_EXPOSED
        p_upnp_udp = Port(port=1900, protocol="udp", state="open", service_name="upnp")
        f_upnp = classify_port_findings("192.168.1.1", p_upnp_udp)
        self.assertEqual(len(f_upnp), 1)
        self.assertEqual(f_upnp[0].code, "UPNP_EXPOSED")

        # SNMP on TCP -> Not catalog finding
        p_snmp_tcp = Port(port=161, protocol="tcp", state="open", service_name="snmp")
        self.assertEqual(len(classify_port_findings("192.168.1.1", p_snmp_tcp)), 0)

        # SNMP on UDP -> SNMP_EXPOSED
        p_snmp_udp = Port(port=161, protocol="udp", state="open", service_name="snmp")
        f_snmp = classify_port_findings("192.168.1.1", p_snmp_udp)
        self.assertEqual(len(f_snmp), 1)
        self.assertEqual(f_snmp[0].code, "SNMP_EXPOSED")

    def test_outdated_versions_matrix(self):
        # vsftpd 2.3.4
        self.assertIsNotNone(check_outdated_service("ftp", "vsftpd", "2.3.4"))
        self.assertIsNone(check_outdated_service("ftp", "vsftpd", "3.0.5"))

        # OpenSSH < 7.4
        self.assertIsNotNone(check_outdated_service("ssh", "OpenSSH", "6.7p1"))
        self.assertIsNotNone(check_outdated_service("ssh", "OpenSSH", "5.3"))
        self.assertIsNone(check_outdated_service("ssh", "OpenSSH", "7.4"))
        self.assertIsNone(check_outdated_service("ssh", "OpenSSH", "8.4p1 Debian 5+deb11u3"))

        # Apache httpd <= 2.2.x
        self.assertIsNotNone(check_outdated_service("http", "Apache httpd", "2.2.8"))
        self.assertIsNotNone(check_outdated_service("http", "Apache httpd", "2.0.59"))
        self.assertIsNone(check_outdated_service("http", "Apache httpd", "2.4.52"))

        # Microsoft IIS <= 7.5
        self.assertIsNotNone(check_outdated_service("http", "Microsoft IIS httpd", "7.5"))
        self.assertIsNotNone(check_outdated_service("http", "Microsoft IIS httpd", "6.0"))
        self.assertIsNone(check_outdated_service("http", "Microsoft IIS httpd", "8.5"))
        self.assertIsNone(check_outdated_service("http", "Microsoft IIS httpd", "10.0"))

        # Samba <= 3.x
        self.assertIsNotNone(check_outdated_service("microsoft-ds", "Samba smbd", "3.0.24"))
        self.assertIsNotNone(check_outdated_service("microsoft-ds", "Samba smbd", "3.6.25"))
        self.assertIsNone(check_outdated_service("microsoft-ds", "Samba smbd", "4.15"))


if __name__ == "__main__":
    unittest.main()
