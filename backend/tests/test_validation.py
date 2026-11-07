"""Exercise the production CLI on the public fixtures and the broken-file path."""
import csv
from pathlib import Path

from netcheck import config
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
    # The CSV keeps the real file name so it matches the jury's answer key (see export.export_folder).
    assert "printer-D8-43-AE-2E-C3-6D.xml,ERROR" in (tmp_path / "scores.csv").read_text()
    assert "D8-43-AE-2E-C3-6D" not in capsys.readouterr().out


def read_rows(path: Path) -> list:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.reader(fh))


def test_csv_keeps_the_real_file_name_even_when_it_looks_like_a_mac(tmp_path):
    """A Test Set name with 12 hex digits must reach the CSV unchanged, or its rows miss the key."""
    names = ["T1_home.xml", "T5_202611081200.xml", "capture-0123456789ab.xml", "scan_aabbccddeeff.xml"]
    source = tmp_path / "in"
    source.mkdir()
    for name in names:
        (source / name).write_bytes((FIXTURES / "V1_home_basic.xml").read_bytes())
    (source / "broken_aabbccddeeff.xml").write_bytes((FIXTURES / "V7_broken.xml").read_bytes())

    assert main(["analyze", str(source), "--out", str(tmp_path / "out")]) == 0
    scores = read_rows(tmp_path / "out" / "scores.csv")[1:]
    assert [row[0] for row in scores] == sorted(names + ["broken_aabbccddeeff.xml"])
    assert dict(scores)["broken_aabbccddeeff.xml"] == "ERROR"
    assert {row[0] for row in read_rows(tmp_path / "out" / "findings.csv")[1:]} == set(names)


def test_analyze_accepts_a_single_file_for_the_live_rerun(tmp_path):
    """Live check #1: one Test Set file re-run gives exactly its rows of the full upload."""
    assert main(["analyze", str(FIXTURES), "--out", str(tmp_path / "all")]) == 0
    assert main(["analyze", str(FIXTURES / "V4_legacy.xml"), "--out", str(tmp_path / "one")]) == 0
    expected = [row for row in read_rows(tmp_path / "all" / "findings.csv")[1:] if row[0] == "V4_legacy.xml"]
    assert read_rows(tmp_path / "one" / "findings.csv")[1:] == expected
    assert read_rows(tmp_path / "one" / "scores.csv") == [["file", "network_score"], ["V4_legacy.xml", "25"]]
