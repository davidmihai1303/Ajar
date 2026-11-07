"""Exercise the production CLI on the public fixtures and the broken-file path."""
import csv
from pathlib import Path

from netcheck import config
from netcheck.analysis import export
from netcheck.cli import main

FIXTURES = Path(__file__).parent / "fixtures" / "validation"


def test_public_csvs_match_byte_for_byte(tmp_path):
    assert main(["analyze", str(FIXTURES), "--out", str(tmp_path)]) == 0
    for name in ("findings.csv", "scores.csv"):
        assert (tmp_path / name).read_bytes() == (FIXTURES / f"expected_{name}").read_bytes()


def test_missing_input_fails_before_creating_output(tmp_path):
    missing = tmp_path / "missing"
    assert main(["analyze", str(missing)]) == 1
    assert not missing.exists()
    output = tmp_path / "elsewhere"
    assert main(["analyze", str(missing), "--out", str(output)]) == 1
    assert not output.exists()


def test_failed_nmap_run_and_redirect_are_handled_by_both_commands(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(config, "DEFAULT_LANG", "en")
    bad = tmp_path / "failed.xml"
    bad.write_text('<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>')
    good = tmp_path / "web.xml"
    good.write_text('<nmaprun><host><status state="up"/><address addrtype="ipv4" addr="192.0.2.1"/>'
                    '<hostnames><hostname name="router"/></hostnames><ports>'
                    '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/>'
                    '<script id="http-title" output="Did not follow redirect to /login">'
                    '<elem key="redirect_url">/login</elem></script></port></ports></host></nmaprun>')
    assert main(["analyze-file", str(bad)]) == 1
    assert "ERROR" in capsys.readouterr().err
    assert main(["analyze-file", str(good)]) == 0
    assert "Score: 100" in capsys.readouterr().out
    assert main(["analyze", str(tmp_path)]) == 0
    with (tmp_path / "scores.csv").open(newline="") as scores:
        assert list(csv.reader(scores))[1:] == [["failed.xml", "ERROR"], ["web.xml", "100"]]
    assert len((tmp_path / "findings.csv").read_text().splitlines()) == 1


def test_configured_size_limit_applies_to_both_commands(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MAX_XML_BYTES", 1)
    scan = tmp_path / "large.xml"
    scan.write_text("<nmaprun/>")
    assert main(["analyze-file", str(scan)]) == 1
    assert main(["analyze", str(tmp_path)]) == 0
    assert "large.xml,ERROR" in (tmp_path / "scores.csv").read_text()


def test_cli_masks_mac_in_filenames_even_on_errors(tmp_path, capsys):
    path = tmp_path / "printer-D8-43-AE-2E-C3-6D.xml"
    path.write_text("<nmaprun/>")
    assert main(["analyze-file", str(path)]) == 0
    assert "D8:43:AE:xx:xx:xx" in capsys.readouterr().out
    path.write_text("broken")
    assert main(["analyze-file", str(path)]) == 1
    assert "D8:43:AE:xx:xx:xx" in capsys.readouterr().err
    assert main(["analyze", str(tmp_path)]) == 0
    assert "printer-D8:43:AE:xx:xx:xx.xml,ERROR" in (tmp_path / "scores.csv").read_text()


def test_timestamp_and_mac_filenames_in_both_csvs_and_single_file_cli(tmp_path, capsys):
    original = (FIXTURES / "V1_home_basic.xml").read_bytes()
    with_mac = original.replace(b"50:C7:BF:39:0C:8C", b"20:26:11:08:12:00")
    inputs = [
        ("T5_202611081200.xml", original, "T5_202611081200.xml"),
        ("printer-D843AE2EC36D.xml", original, "printer-D8:43:AE:xx:xx:xx.xml"),
        ("router-202611081200.xml", with_mac, "router-20:26:11:xx:xx:xx (2).xml"),
        ("router-202611081201.xml", original, "router-202611081201.xml"),
        ("router-20-26-11-08-12-02.xml", original, "router-20:26:11:xx:xx:xx.xml"),
        ("mac-202611081200.xml", original, "mac-20:26:11:xx:xx:xx.xml"),
    ]
    for raw, data, _ in inputs:
        (tmp_path / raw).write_bytes(data)
    assert main(["analyze", str(tmp_path)]) == 0
    expected = {label for _, _, label in inputs}
    for name in ("scores.csv", "findings.csv"):
        with (tmp_path / name).open(newline="") as output:
            assert {row["file"] for row in csv.DictReader(output)} == expected
    capsys.readouterr()
    for raw, _, label in inputs:
        assert main(["analyze-file", str(tmp_path / raw)]) == 0
        assert capsys.readouterr().out.splitlines()[0].endswith(" " + label)


def test_changed_mac_evidence_cannot_publish_a_stale_filename(tmp_path, monkeypatch):
    assert main(["analyze", str(tmp_path)]) == 0
    path = tmp_path / "T5_202611081200.xml"
    path.write_text("<nmaprun/>")
    analyze = export.analyze_file

    def replace_before_analysis(path, max_bytes):
        path.write_text('<nmaprun><host><address addrtype="mac" addr="20:26:11:08:12:00"/></host></nmaprun>')
        return analyze(path, max_bytes)

    monkeypatch.setattr(export, "analyze_file", replace_before_analysis)
    assert main(["analyze", str(tmp_path)]) == 1
    for name in ("findings.csv", "scores.csv"):
        assert len((tmp_path / name).read_text().splitlines()) == 1


def test_masked_name_collisions_match_across_csvs_and_single_file_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "DEFAULT_LANG", "en")
    stem = "scan-02:00:00:xx:xx:xx"
    inputs = [
        ("scan-02-00-00-00-00-02.xml", "V3_small_office.xml", f"{stem} (3).xml", "45"),
        ("scan-02-00-00-00-00-01 (2).xml", "V7_broken.xml", f"{stem} (2).xml", "ERROR"),
        ("scan-02-00-00-00-00-01.xml", "V1_home_basic.xml", f"{stem}.xml", "90"),
    ]
    for raw, fixture, _, _ in inputs:
        (tmp_path / raw).write_bytes((FIXTURES / fixture).read_bytes())
    for _ in range(2):
        assert main(["analyze", str(tmp_path)]) == 0
        with (tmp_path / "scores.csv").open(newline="") as f:
            assert list(csv.reader(f))[1:] == sorted([[label, score] for _, _, label, score in inputs])
        with (tmp_path / "findings.csv").open(newline="") as f:
            rows = list(csv.DictReader(f))
        assert {row["file"] for row in rows} == {inputs[0][2], inputs[2][2]}
        assert all(row["file"] == inputs[2][2] for row in rows if row["finding_code"] == "HTTP_ADMIN_CLEARTEXT")
    capsys.readouterr()
    for raw, _, label, score in inputs:
        assert main(["analyze-file", str(tmp_path / raw)]) == (1 if score == "ERROR" else 0)
        result = capsys.readouterr()
        assert label in (result.err if score == "ERROR" else result.out)
