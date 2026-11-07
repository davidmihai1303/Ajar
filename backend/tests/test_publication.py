"""A failed or concurrent exporter must never leave different runs at the two public paths."""
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from netcheck.analysis.publication import CSV_NAMES, publish_csvs


def stage(directory, label):
    directory.mkdir()
    for name in CSV_NAMES:
        (directory / name).write_text(f"{name},{label}\n")
    return directory


def contents(directory):
    return [(directory / name).read_text() for name in CSV_NAMES]


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


def test_exit_just_before_commit_preserves_last_export_and_releases_lock(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    first = stage(tmp_path / "first", "first")
    expected = contents(first)
    publish_csvs(first, output)
    second = stage(tmp_path / "second", "second")
    script = """
import os, sys
from pathlib import Path
from netcheck.analysis.publication import publish_csvs
replace = Path.replace
def interrupt(source, target):
    if target.name == 'current':
        os._exit(23)
    return replace(source, target)
Path.replace = interrupt
publish_csvs(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    result = subprocess.run([sys.executable, "-B", "-c", script, str(second), str(output)], env=env, timeout=10)
    assert result.returncode == 23
    assert contents(output) == expected
    retry = stage(tmp_path / "retry", "after exit")
    expected = contents(retry)
    publish_csvs(retry, output)
    assert contents(output) == expected


def test_concurrent_publishers_leave_one_complete_pair(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    stages = [stage(tmp_path / str(n), str(n)) for n in range(8)]
    pairs = [contents(directory) for directory in stages]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda directory: publish_csvs(directory, output), stages))
    assert contents(output) in pairs
