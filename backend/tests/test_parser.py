"""Parser tests: Validation Set facts, hostile and broken input, MAC masking, determinism (FR-05, NFR-02, NFR-03, NFR-05)."""
from pathlib import Path

import pytest

from netcheck.analysis.models import (ERROR_NOT_NMAP, ERROR_TOO_LARGE, ERROR_UNREADABLE, ERROR_UNSAFE,
                                      Device, ScanResult)
from netcheck.analysis.parser import clean_text, parse_bytes, parse_scan
from netcheck.analysis.privacy import mask_mac

VALIDATION = Path(__file__).parent / "fixtures" / "validation"
GOOD_FILES = ["V1_home_basic.xml", "V2_smart_home.xml", "V3_small_office.xml", "V4_legacy.xml",
              "V5_nonstandard_ports.xml", "V6a_before.xml", "V6b_after.xml"]
DEVICE_COUNTS = {"V1_home_basic.xml": 3, "V2_smart_home.xml": 4, "V3_small_office.xml": 4,
                 "V4_legacy.xml": 3, "V5_nonstandard_ports.xml": 5, "V6a_before.xml": 3, "V6b_after.xml": 3}

HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'


def scan(name: str) -> ScanResult:
    return parse_scan(str(VALIDATION / name))


def device(result: ScanResult, ip: str) -> Device:
    return next(d for d in result.devices if d.ip == ip)


def port(dev: Device, protocol: str, number: int):
    return next(p for p in dev.ports if p.protocol == protocol and p.port == number)


def nmap_xml(hosts: str) -> bytes:
    return (HEADER + f'<nmaprun scanner="nmap" start="1">{hosts}</nmaprun>').encode()


# ------------------------------------------------------------ Validation Set

@pytest.mark.parametrize("name", GOOD_FILES)
def test_validation_files_are_read(name):
    result = scan(name)
    assert result.ok, result.error
    assert result.file == name
    assert len(result.devices) == DEVICE_COUNTS[name]


def test_broken_file_gives_error_not_exception():
    result = scan("V7_broken.xml")
    assert result.error == ERROR_UNREADABLE
    assert result.devices == ()
    assert result.file == "V7_broken.xml"


def test_bad_xml_encoding_does_not_interrupt_folder_import(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_bytes(b'<?xml version="1.0" encoding="utf-88"?><nmaprun/>')
    results = [parse_scan(path) for path in (bad, VALIDATION / "V1_home_basic.xml")]
    assert results[0].error == ERROR_UNREADABLE
    assert results[1].ok and len(results[1].devices) == 3


@pytest.mark.parametrize("hosts", [
    "",
    '<host><status state="up"/><address addrtype="ipv4" addr="192.0.2.5"/></host>',
])
def test_failed_scan_discards_partial_results(hosts):
    report = nmap_xml(hosts + '<runstats><finished exit="error"/></runstats>')
    result = parse_bytes(report, "failed.xml")
    assert result.error == ERROR_UNREADABLE and result.devices == ()


def test_successful_scan_with_no_hosts():
    report = nmap_xml('<runstats><finished exit="success"/></runstats>')
    result = parse_bytes(report, "empty.xml")
    assert result.ok and result.devices == ()


def test_devices_sorted_by_numeric_ip():
    ips = [d.ip for d in scan("V5_nonstandard_ports.xml").devices]
    assert ips == ["192.168.1.5", "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9"]


def test_https_keeps_the_ssl_tunnel():
    router = device(scan("V1_home_basic.xml"), "192.168.1.1")
    assert port(router, "tcp", 80).tunnel == ""
    assert port(router, "tcp", 443).tunnel == "ssl"
    assert port(router, "tcp", 443).service == "http"


def test_http_title_is_read():
    v5 = scan("V5_nonstandard_ports.xml")
    assert port(device(v5, "192.168.1.6"), "tcp", 8081).http_title == "Admin Panel"
    assert port(device(v5, "192.168.1.8"), "tcp", 8443).http_title == "Admin Login"


def test_filtered_port_is_kept_with_its_state():
    db = device(scan("V5_nonstandard_ports.xml"), "192.168.1.9")
    mysql = port(db, "tcp", 3306)
    assert mysql.state == "filtered" and not mysql.is_open
    assert db.open_ports == ()


def test_udp_ports_are_read():
    router = device(scan("V2_smart_home.xml"), "192.168.1.1")
    assert port(router, "udp", 1900).service == "upnp"
    assert port(device(scan("V4_legacy.xml"), "192.168.1.1"), "udp", 161).service == "snmp"


def test_product_and_version_are_read():
    ftp = port(device(scan("V4_legacy.xml"), "192.168.1.60"), "tcp", 21)
    assert (ftp.service, ftp.product, ftp.version) == ("ftp", "vsftpd", "2.3.4")
    ssh = port(device(scan("V3_small_office.xml"), "192.168.1.40"), "tcp", 22)
    assert ssh.version == "8.4p1 Debian 5+deb11u3"


def test_device_without_vendor_and_hostname():
    unknown = device(scan("V4_legacy.xml"), "192.168.1.99")
    assert unknown.vendor == "" and unknown.hostname == ""
    assert unknown.mac_masked == "02:1A:7D:xx:xx:xx"
    assert len(unknown.open_ports) == 1


def test_vendor_and_hostname_are_read():
    router = device(scan("V1_home_basic.xml"), "192.168.1.1")
    assert router.vendor == "TP-Link" and router.hostname == "router.lan"


def test_smb_ports_both_present_for_the_rules():
    nas = device(scan("V3_small_office.xml"), "192.168.1.20")
    assert {p.port for p in nas.open_ports if p.service in ("microsoft-ds", "netbios-ssn")} == {139, 445}


def test_device_type_guesses():
    v2 = scan("V2_smart_home.xml")
    assert device(v2, "192.168.1.1").device_type == "router"
    assert device(v2, "192.168.1.40").device_type == "camera"
    assert device(scan("V3_small_office.xml"), "192.168.1.10").device_type == "printer"


# ------------------------------------------------------------ privacy (NFR-02)

@pytest.mark.parametrize("name", GOOD_FILES)
def test_no_full_mac_anywhere_in_the_result(name):
    raw = (VALIDATION / name).read_text(encoding="utf-8")
    text = repr(scan(name))
    for chunk in raw.split('addr="')[1:]:
        value = chunk.split('"')[0]
        if value.count(":") == 5:
            assert value not in text
            assert value[:8] in text


@pytest.mark.parametrize("raw, masked", [
    ("D8:43:AE:2E:C3:6D", "D8:43:AE:xx:xx:xx"),
    ("d8-43-ae-2e-c3-6d", "D8:43:AE:xx:xx:xx"),
    (" 50:c7:bf:01:02:03 ", "50:C7:BF:xx:xx:xx"),
    ("", ""),
    ("not-a-mac", ""),
    ("D8:43:AE:2E:C3", ""),
    ("D8:43:AE:2E:C3:6D:00", ""),
    ("ZZ:43:AE:2E:C3:6D", ""),
])
def test_mask_mac(raw, masked):
    assert mask_mac(raw) == masked


def test_mac_addresses_are_masked_in_all_scan_text_and_filenames(tmp_path):
    raw = "D8:43:AE:2E:C3:6D"
    masked = "D8:43:AE:xx:xx:xx"
    hosts = (f'<host><status state="up"/><address addrtype="ipv4" addr="192.0.2.1"/>'
             f'<address addrtype="mac" addr="{raw}" vendor="Vendor {raw}"/>'
             '<hostnames><hostname name="printer-d8-43-ae-2e-c3-6d.local"/></hostnames>'
             '<ports><port protocol="tcp" portid="80"><state state="open"/>'
             '<service name="http" product="unit d843.ae2e.c36d" version="1.0" extrainfo="D843AE2EC36D"/>'
             f'<script id="http-title"><elem key="title">Login {raw}</elem></script>'
             f'<script id="extra-{raw}" output="MAC:{raw}:"/></port></ports></host>')
    report = nmap_xml(hosts)
    path = tmp_path / f"scan-{raw}.xml"
    missing = parse_scan(path)
    path.write_bytes(report)
    result = parse_scan(path)
    assert result == parse_bytes(report, str(path))
    assert missing.file == result.file == f"scan-{masked}.xml"
    assert parse_bytes(b"", path.name).file == result.file
    dev = result.devices[0]
    assert (dev.mac_masked, dev.vendor, dev.hostname) == (masked, f"Vendor {masked}", f"printer-{masked}.local")
    web = dev.ports[0]
    assert (web.product, web.extrainfo, web.http_title) == (f"unit {masked}", masked, f"Login {masked}")
    assert web.scripts[f"extra-{masked}"] == f"MAC:{masked}:"


def test_masking_preserves_ipv6_and_redacts_before_truncating_text():
    ipv6 = "2001:db8:aa:bb:cc:dd:ee:ff"
    assert clean_text(f"printer [{ipv6}]") == f"printer [{ipv6}]"
    assert clean_text("x" * 499 + " D8:43:AE:2E:C3:6D").endswith("D8:43:AE:xx:")


def test_ipv6_interface_label_does_not_expose_a_mac():
    hosts = ('<host><status state="up"/>'
             '<address addrtype="ipv6" addr="fe80::1%nic-d8-43-ae-2e-c3-6d"/></host>')
    result = parse_bytes(nmap_xml(hosts), "scoped.xml")
    assert result.devices[0].ip == "fe80::1%nic-D8:43:AE:xx:xx:xx"


# ------------------------------------------------------------ hostile input (NFR-03)

def test_xxe_external_entity_is_refused(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET")
    evil = tmp_path / "xxe.xml"
    evil.write_text(f'<?xml version="1.0"?>\n<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///{secret.as_posix()}">]>\n'
                    '<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                    '<hostnames><hostname name="&x;"/></hostnames></host></nmaprun>')
    result = parse_scan(str(evil))
    assert result.error == ERROR_UNSAFE
    assert "TOP-SECRET" not in repr(result)


def test_billion_laughs_is_refused():
    bomb = ('<?xml version="1.0"?>\n<!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>\n'
            '<nmaprun>&lol3;</nmaprun>').encode()
    assert parse_bytes(bomb, "bomb.xml").error == ERROR_UNSAFE


def test_oversized_file_is_refused_before_parsing(tmp_path):
    big = tmp_path / "big.xml"
    big.write_bytes(nmap_xml("") + b" " * 2000)
    assert parse_scan(str(big), max_bytes=1000).error == ERROR_TOO_LARGE
    assert parse_scan(str(big), max_bytes=10_000).ok


def test_file_and_upload_share_the_exact_size_limit(tmp_path):
    data = nmap_xml("")
    path = tmp_path / "upload.xml"
    path.write_bytes(data)
    for limit in (len(data), len(data) - 1, 0, -2):
        uploaded = parse_bytes(data, path.name, max_bytes=limit)
        assert parse_scan(path, max_bytes=limit) == uploaded
        assert uploaded.error == (None if limit == len(data) else ERROR_TOO_LARGE)


@pytest.mark.parametrize("number", ["²", "9" * 5000])
def test_malformed_numeric_fields_preserve_valid_scan_data(number):
    xml = (f'<nmaprun start="{number}"><host><status state="up"/>'
           '<address addr="192.0.2.1" addrtype="ipv4"/><ports>'
           f'<port protocol="tcp" portid="{number}"/>'
           '<port protocol="tcp" portid="22"><state state="open"/></port>'
           '</ports></host></nmaprun>')
    result = parse_bytes(xml.encode(), "numbers.xml")
    assert result.ok and result.started is None
    assert [p.port for p in result.devices[0].ports] == [22]


@pytest.mark.parametrize("content", [b"", b"   \n", b"not xml at all", b"<nmaprun><host>"])
def test_garbage_is_unreadable(content):
    assert parse_bytes(content, "x.xml").error == ERROR_UNREADABLE


def test_missing_file_is_unreadable(tmp_path):
    result = parse_scan(str(tmp_path / "does_not_exist.xml"))
    assert result.error == ERROR_UNREADABLE and result.file == "does_not_exist.xml"


def test_other_xml_is_not_nmap():
    assert parse_bytes(b"<html><body>hi</body></html>", "page.xml").error == ERROR_NOT_NMAP


def test_banners_are_cleaned():
    hosts = ('<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
             '<hostnames><hostname name="evil&#10;host&#133;[31m"/></hostnames><ports>'
             '<port protocol="tcp" portid="80"><state state="open"/>'
             '<service name="http" product="&lt;script&gt;alert(1)&lt;/script&gt;"/>'
             f'<script id="http-title" output="x"><elem key="title">{"A" * 5000}</elem></script>'
             '</port></ports></host>')
    dev = parse_bytes(nmap_xml(hosts), "x.xml").devices[0]
    assert dev.hostname == "evil host [31m"
    web = dev.ports[0]
    assert web.product == "<script>alert(1)</script>"   # kept as text: escaping is the UI's job
    assert len(web.http_title) == 512


def test_characters_forbidden_in_xml_make_the_file_unreadable():
    hosts = ('<host><status state="up"/><address addr="10.0.0.7" addrtype="ipv4"/>'
             '<hostnames><hostname name="esc&#27;[31m"/></hostnames></host>')
    assert parse_bytes(nmap_xml(hosts), "x.xml").error == ERROR_UNREADABLE


def test_redirect_message_is_not_a_title():
    hosts = ('<host><status state="up"/><address addr="10.0.0.6" addrtype="ipv4"/><ports>'
             '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/>'
             '<script id="http-title" output="Did not follow redirect to http://10.0.0.6/login.html">'
             '<elem key="redirect_url">http://10.0.0.6/login.html</elem></script></port></ports></host>')
    assert parse_bytes(nmap_xml(hosts), "x.xml").devices[0].ports[0].http_title == ""


# ------------------------------------------------------------ structure edge cases

def test_down_hosts_and_hosts_without_ip_are_skipped():
    hosts = ('<host><status state="down"/><address addr="10.0.0.1" addrtype="ipv4"/></host>'
             '<host><address addr="10.0.0.3" addrtype="ipv4"/></host>'
             '<host><status state="up"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/></host>'
             '<host><status state="up"/><address addr="999.1.1.1" addrtype="ipv4"/></host>'
             '<host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/></host>')
    assert [d.ip for d in parse_bytes(nmap_xml(hosts), "x.xml").devices] == ["10.0.0.2"]


def test_invalid_port_numbers_are_skipped():
    hosts = ('<host><status state="up"/><address addr="10.0.0.3" addrtype="ipv4"/><ports>'
             '<port protocol="tcp" portid="70000"><state state="open"/></port>'
             '<port protocol="tcp" portid="abc"><state state="open"/></port>'
             '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
             '</ports></host>')
    assert [p.port for p in parse_bytes(nmap_xml(hosts), "x.xml").devices[0].ports] == [22]


def test_port_without_service_element():
    hosts = ('<host><status state="up"/><address addr="10.0.0.4" addrtype="ipv4"/><ports>'
             '<port protocol="tcp" portid="9999"><state state="open"/></port></ports></host>')
    bare = parse_bytes(nmap_xml(hosts), "x.xml").devices[0].ports[0]
    assert (bare.service, bare.product, bare.is_open) == ("", "", True)


@pytest.mark.parametrize("value, expected", [
    (None, ""), ("", ""), ("  a \t b\n c ", "a b c"), ("bell\x07end", "bell end"), ("x" * 600, "x" * 512),
])
def test_clean_text(value, expected):
    assert clean_text(value) == expected


# ------------------------------------------------------------ determinism (NFR-05)

@pytest.mark.parametrize("name", GOOD_FILES + ["V7_broken.xml"])
def test_same_file_same_result(name):
    assert scan(name) == scan(name) == scan(name)
