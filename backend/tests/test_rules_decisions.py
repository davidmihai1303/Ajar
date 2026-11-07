"""Extra rule coverage: every catalog code, the agreed decisions D1-D7 (AGENTS.md), every outdated-version
boundary, order, duplicates and the score floor. Complements test_rules.py."""
import pytest

from netcheck.analysis.catalog import CATALOG
from netcheck.analysis.models import ERROR_UNREADABLE, Device, Port, ScanResult
from netcheck.analysis.rules import evaluate_devices
from netcheck.analysis.scoring import compute_score
from netcheck.analysis.versions import is_outdated_service

SEVERITY_POINTS = {"high": 20, "medium": 10, "low": 5, "info": 0}


def find_findings(scan):
    return tuple(evaluate_devices(scan.devices)) if scan.ok else ()


def port(number, service="", protocol="tcp", state="open", product="", version="", tunnel="", title=None):
    scripts = {} if title is None else {"http-title": title}
    return Port(protocol=protocol, port=number, state=state, service=service, product=product,
                version=version, tunnel=tunnel, scripts=scripts)


def device(*ports, ip="192.168.1.10", vendor="Dell", hostname="pc"):
    return Device(ip=ip, mac_masked="F8:BC:12:xx:xx:xx", vendor=vendor, hostname=hostname, ports=tuple(ports))


def rows(*devices):
    return [(f.ip, f.port, f.code) for f in find_findings(ScanResult(file="t.xml", devices=tuple(devices)))]


def codes(*ports, **kwargs):
    return [code for _, _, code in rows(device(*ports, **kwargs))]


# ------------------------------------------------------------ catalog data

def test_catalog_has_the_15_official_codes_with_their_points():
    expected = {
        "TELNET_OPEN": 20, "RDP_EXPOSED": 20, "VNC_EXPOSED": 20, "DB_EXPOSED": 20, "CAMERA_STREAM_EXPOSED": 20,
        "OUTDATED_SERVICE": 20, "FTP_CLEARTEXT": 10, "HTTP_ADMIN_CLEARTEXT": 10, "SMB_EXPOSED": 10,
        "MQTT_EXPOSED": 10, "UPNP_EXPOSED": 10, "SNMP_EXPOSED": 10, "PRINTER_RAW_EXPOSED": 5,
        "UNKNOWN_DEVICE": 5, "SSH_OPEN": 0,
    }
    assert {code: entry.points for code, entry in CATALOG.items()} == expected
    assert all(SEVERITY_POINTS[entry.severity] == entry.points for entry in CATALOG.values())


@pytest.mark.parametrize("service, code", [
    ("telnet", "TELNET_OPEN"), ("ms-wbt-server", "RDP_EXPOSED"), ("vnc", "VNC_EXPOSED"),
    ("mysql", "DB_EXPOSED"), ("postgresql", "DB_EXPOSED"), ("redis", "DB_EXPOSED"), ("mongodb", "DB_EXPOSED"),
    ("rtsp", "CAMERA_STREAM_EXPOSED"), ("ftp", "FTP_CLEARTEXT"), ("mqtt", "MQTT_EXPOSED"),
    ("jetdirect", "PRINTER_RAW_EXPOSED"), ("ssh", "SSH_OPEN"),
])
def test_each_service_rule(service, code):
    assert codes(port(1234, service)) == [code]


def test_severity_comes_from_the_catalog():
    finding = find_findings(ScanResult(file="t.xml", devices=(device(port(23, "telnet")),)))[0]
    assert (finding.severity, finding.points) == ("high", 20)
    assert CATALOG["SSH_OPEN"].severity == "info"


# ------------------------------------------------------------ general rules

@pytest.mark.parametrize("state", ["filtered", "closed", "open|filtered", "unfiltered", ""])
def test_only_open_ports_count(state):
    assert codes(port(3306, "mysql", state=state)) == []


def test_service_name_decides_not_the_port_number():
    assert codes(port(2323, "telnet")) == ["TELNET_OPEN"]
    assert codes(port(23, "http")) == []
    assert codes(port(3306, "unknown")) == []


def test_service_names_are_exact_D2():
    assert codes(port(27017, "mongod")) == []
    assert codes(port(8080, "http-proxy", title="Admin Login")) == []
    assert codes(port(8443, "https-alt", title="Admin Login")) == []
    assert codes(port(5901, "vnc-http")) == []


def test_ports_outside_the_catalog_are_ignored():
    assert codes(port(631, "ipp"), port(8008, "http"), port(8009, "ajp13"), port(53, "domain")) == []


def test_same_service_on_two_ports_gives_two_rows_D5():
    assert rows(device(port(5000, "rtsp"), port(7000, "rtsp"))) == [
        ("192.168.1.10", 5000, "CAMERA_STREAM_EXPOSED"), ("192.168.1.10", 7000, "CAMERA_STREAM_EXPOSED")]


# ------------------------------------------------------------ UDP-only rules

def test_upnp_and_snmp_only_on_udp():
    assert codes(port(1900, "upnp", protocol="udp"), port(161, "snmp", protocol="udp")) == ["SNMP_EXPOSED", "UPNP_EXPOSED"]
    assert codes(port(5000, "upnp"), port(161, "snmp")) == []


# ------------------------------------------------------------ HTTP admin

@pytest.mark.parametrize("title", ["Router Login", "ADMIN PANEL", "Device Configuration", "Setup Wizard",
                                   "TP-Link Router", "Network Settings", "Administrator"])
def test_http_admin_titles(title):
    assert codes(port(80, "http", title=title)) == ["HTTP_ADMIN_CLEARTEXT"]


@pytest.mark.parametrize("title", ["Welcome", "", "Camera Stream", "Index of /"])
def test_http_without_admin_title(title):
    assert codes(port(80, "http", title=title)) == []


def test_http_without_title_script():
    assert codes(port(80, "http")) == []


def test_https_is_not_cleartext():
    assert codes(port(443, "http", tunnel="ssl", title="Router Login")) == []
    assert codes(port(443, "https", title="Router Login")) == []


def test_ftp_and_telnet_over_ssl_are_still_reported_D1():
    assert codes(port(990, "ftp", tunnel="ssl")) == ["FTP_CLEARTEXT"]
    assert codes(port(992, "telnet", tunnel="ssl")) == ["TELNET_OPEN"]


# ------------------------------------------------------------ SMB

@pytest.mark.parametrize("ports, expected_port", [
    ([port(139, "netbios-ssn"), port(445, "microsoft-ds")], 445),
    ([port(445, "microsoft-ds")], 445),
    ([port(139, "netbios-ssn")], 139),
    ([port(139, "netbios-ssn"), port(445, "microsoft-ds", state="filtered")], 139),
    ([port(4455, "microsoft-ds")], 4455),
])
def test_smb_one_finding_per_device(ports, expected_port):
    assert rows(device(*ports)) == [("192.168.1.10", expected_port, "SMB_EXPOSED")]


def test_smb_on_two_devices_gives_two_rows():
    found = rows(device(port(445, "microsoft-ds"), ip="192.168.1.2"), device(port(139, "netbios-ssn"), ip="192.168.1.3"))
    assert found == [("192.168.1.2", 445, "SMB_EXPOSED"), ("192.168.1.3", 139, "SMB_EXPOSED")]


# ------------------------------------------------------------ outdated versions

@pytest.mark.parametrize("product, version, outdated", [
    ("vsftpd", "2.3.4", True), ("vsftpd", "2.3.5", False), ("vsftpd", "3.0.3", False), ("vsftpd", "", False),
    ("OpenSSH", "7.3p1", True), ("OpenSSH", "7.2p2 Ubuntu-4ubuntu2.8", True), ("OpenSSH", "5.3", True),
    ("OpenSSH", "7.4", False), ("OpenSSH", "7.4p1 Debian 10+deb9u7", False), ("OpenSSH", "7.10", False),
    ("OpenSSH", "8.4p1 Debian 5+deb11u3", False),
    ("Apache httpd", "2.2.34", True), ("Apache httpd", "2.2", True), ("Apache httpd", "2.0.65", True),
    ("Apache httpd", "1.3.42", True), ("Apache httpd", "2.4.1", False), ("Apache httpd", "2.4.58", False),
    ("Microsoft IIS httpd", "7.5", True), ("Microsoft IIS httpd", "6.0", True),
    ("Microsoft IIS httpd", "8.0", False), ("Microsoft IIS httpd", "10.0", False),
    ("Samba smbd", "3.6.25", True), ("Samba smbd", "3.X", True), ("Samba smbd", "2.2.8", True),
    ("Samba smbd", "4.15", False), ("Samba smbd", "3.X - 4.X", False), ("Samba smbd", "4.6.2", False),
    ("nginx", "1.0", False), ("lighttpd", "", False),
])
def test_outdated_list(product, version, outdated):
    assert is_outdated_service(product, version) is outdated



def test_outdated_is_in_addition_to_the_service_finding():
    assert codes(port(21, "ftp", product="vsftpd", version="2.3.4")) == ["FTP_CLEARTEXT", "OUTDATED_SERVICE"]
    assert codes(port(22, "ssh", product="OpenSSH", version="7.2p2")) == ["OUTDATED_SERVICE", "SSH_OPEN"]


def test_outdated_without_own_finding_is_still_reported_D4():
    assert codes(port(80, "http", product="Apache httpd", version="2.2.15", title="Welcome")) == ["OUTDATED_SERVICE"]


def test_outdated_needs_an_open_port():
    assert codes(port(21, "ftp", product="vsftpd", version="2.3.4", state="filtered")) == []


# ------------------------------------------------------------ unknown device

def test_unknown_device_has_empty_port_and_one_row():
    assert rows(device(port(8888, "sun-answerbook"), port(9999, "abyss"), vendor="", hostname="")) == [
        ("192.168.1.10", None, "UNKNOWN_DEVICE")]


@pytest.mark.parametrize("vendor, hostname", [("Dell", ""), ("", "pc"), ("Dell", "pc")])
def test_known_device_is_not_unknown(vendor, hostname):
    assert codes(port(8888, "sun-answerbook"), vendor=vendor, hostname=hostname) == []


def test_unknown_device_needs_an_open_port():
    assert codes(port(8888, "x", state="filtered"), vendor="", hostname="") == []
    assert codes(vendor="", hostname="") == []


def test_unknown_device_counts_udp_and_adds_to_service_findings():
    assert codes(port(23, "telnet"), port(53, "domain", protocol="udp"), vendor="", hostname="") == [
        "TELNET_OPEN", "UNKNOWN_DEVICE"]


# ------------------------------------------------------------ order, duplicates, score

def test_rows_sorted_by_numeric_ip_then_port_then_code():
    found = rows(device(port(80, "http", title="Login"), port(23, "telnet"), ip="192.168.1.10"),
                 device(port(21, "ftp", product="vsftpd", version="2.3.4"), ip="192.168.1.9"),
                 device(port(1, "x"), ip="192.168.1.100", vendor="", hostname=""))
    assert found == [("192.168.1.9", 21, "FTP_CLEARTEXT"), ("192.168.1.9", 21, "OUTDATED_SERVICE"),
                     ("192.168.1.10", 23, "TELNET_OPEN"), ("192.168.1.10", 80, "HTTP_ADMIN_CLEARTEXT"),
                     ("192.168.1.100", None, "UNKNOWN_DEVICE")]


def test_same_port_number_on_tcp_and_udp_gives_one_row():
    assert rows(device(port(23, "telnet"), port(23, "telnet", protocol="udp"))) == [("192.168.1.10", 23, "TELNET_OPEN")]


def test_unreadable_scan_has_no_findings():
    assert find_findings(ScanResult(file="x.xml", error=ERROR_UNREADABLE)) == ()


@pytest.mark.parametrize("points, score", [([], 100), ([20], 80), ([20, 10, 5, 0], 65), ([20] * 5, 0), ([20] * 9, 0)])
def test_score_floor_at_zero(points, score):
    class F:
        def __init__(self, p):
            self.points = p
    assert compute_score([F(p) for p in points]) == score
