"""A failed or concurrent exporter must never leave different runs at the two public paths."""
import os
import subprocess
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from netcheck.analysis.publication import CSV_NAMES, publish_csvs
from netcheck.analysis.export import export_folder


def stage(directory, label):
    directory.mkdir()
    for name in CSV_NAMES:
        (directory / name).write_text(f"{name},{label}\n")
    return directory


def contents(directory):
    return [(directory / name).read_text() for name in CSV_NAMES]


def assert_only_published_pair(output):
    physical = [p for p in output.rglob("*.csv") if not p.is_symlink()]
    assert set(physical) == {(output / name).resolve() for name in CSV_NAMES}


def test_archiving_reused_output_contains_only_latest_scan(tmp_path):
    fixtures = Path(__file__).parent / "fixtures" / "validation"
    output = tmp_path / "results"
    for label in ("internal-lab", "submission"):
        folder = tmp_path / label
        folder.mkdir()
        (folder / f"{label}.xml").write_bytes((fixtures / "V1_home_basic.xml").read_bytes())
        export_folder(folder, output)
    assert_only_published_pair(output)
    with tarfile.open(tmp_path / "results.tar", "w") as archive:
        archive.add(output, arcname="results")
    with tarfile.open(tmp_path / "results.tar") as archive:
        data = [archive.extractfile(m).read() for m in archive if m.isfile()]
    assert all(b"internal-lab" not in entry for entry in data)
    assert sum(b"submission.xml" in entry for entry in data) == 2


@pytest.mark.parametrize("failure_at", ["scores.csv", "public-scores", "current"])
def test_failed_migration_preserves_both_existing_regular_files(tmp_path, monkeypatch, failure_at):
    output = stage(tmp_path / "output", "old")
    old_pair = contents(output)
    staged = stage(tmp_path / "new", "new")
    replace = Path.replace

    def failing_replace(source, target):
        point = "public-scores" if target == output / "scores.csv" else target.name
        if point == failure_at:
            raise OSError("simulated publication error")
        return replace(source, target)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "replace", failing_replace)
        with pytest.raises(OSError, match="simulated"):
            publish_csvs(staged, output)
    assert contents(output) == old_pair
    retry = stage(tmp_path / "retry", "retry")
    expected = contents(retry)
    publish_csvs(retry, output)
    assert contents(output) == expected
    assert_only_published_pair(output)


@pytest.mark.parametrize("phase", ["before", "after"])
def test_exit_at_commit_recovers_without_retaining_old_csvs(tmp_path, phase):
    output = tmp_path / "output"
    output.mkdir()
    first = stage(tmp_path / "first", "first")
    first_pair = contents(first)
    publish_csvs(first, output)
    second = stage(tmp_path / "second", "second")
    second_pair = contents(second)
    script = """
import os, sys
from pathlib import Path
from netcheck.analysis.publication import publish_csvs
replace = Path.replace
def interrupt(source, target):
    if target.name == 'current':
        if sys.argv[3] == 'after':
            replace(source, target)
        os._exit(23)
    return replace(source, target)
Path.replace = interrupt
publish_csvs(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    result = subprocess.run([sys.executable, "-B", "-c", script, str(second), str(output), phase], env=env, timeout=10)
    assert result.returncode == 23
    assert contents(output) == (first_pair if phase == "before" else second_pair)
    retry = stage(tmp_path / "retry", "after exit")
    expected = contents(retry)
    publish_csvs(retry, output)
    assert contents(output) == expected
    assert_only_published_pair(output)


def test_concurrent_publishers_leave_one_complete_pair(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    stages = [stage(tmp_path / str(n), str(n)) for n in range(8)]
    pairs = [contents(directory) for directory in stages]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda directory: publish_csvs(directory, output), stages))
    assert contents(output) in pairs
    assert_only_published_pair(output)
