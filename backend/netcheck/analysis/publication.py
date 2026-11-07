"""Publish both standard CSV names by switching one relative directory link."""
import os
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


CSV_NAMES = ("findings.csv", "scores.csv")
_STATE = ".netcheck-csv"


def _directory(path: Path) -> None:
    path.mkdir(exist_ok=True)
    if path.is_symlink():
        raise OSError(f"Unexpected directory link: {path}")


def _lock(file) -> None:
    # Closing the descriptor releases the lock, including after process termination.
    if os.name == "nt":
        import msvcrt
        file.seek(0)
        msvcrt.locking(file.fileno(), msvcrt.LK_LOCK, 1)
    else:
        import fcntl
        fcntl.flock(file.fileno(), fcntl.LOCK_EX)


def _clear_csvs(slot: Path) -> None:
    for name in CSV_NAMES:
        (slot / name).unlink(missing_ok=True)


def _install_public_links(output: Path, active: Path, pending: Path) -> None:
    # Preserve a legacy regular file's bytes until the new pair is committed.
    for name in CSV_NAMES:
        public = output / name
        link = Path(_STATE) / "current" / name
        if public.is_symlink() and public.readlink() == link:
            continue
        previous = active / name
        if public.is_file():
            shutil.copy(public, pending)
            pending.replace(previous)
        elif public.exists():
            raise OSError(f"Expected a CSV file: {public}")
        else:
            previous.unlink(missing_ok=True)
        pending.symlink_to(link)
        pending.replace(public)


@contextmanager
def csv_publication(output: Path) -> Iterator[Path]:
    """Write into the inactive slot; publish on success and discard all inactive CSVs."""
    state = output / _STATE
    _directory(state)
    with (state / "publish.lock").open("a+b") as lock:
        _lock(lock)
        current = state / "current"
        if not current.is_symlink():
            _directory(state / "a")
            current.symlink_to("a", target_is_directory=True)
        selected = current.readlink()
        if str(selected) not in ("a", "b"):
            raise OSError(f"Invalid CSV snapshot: {current}")
        active = state / selected
        standby = state / ("b" if active.name == "a" else "a")
        _directory(active)
        _directory(standby)
        # A killed writer may have left either a partial candidate or a retired pair.
        # Reuse only these known files; the export folder can also contain user data.
        pending = state / "pending"
        pending.unlink(missing_ok=True)
        _clear_csvs(standby)
        try:
            yield standby
            _install_public_links(output, active, pending)
            pending.symlink_to(standby.name, target_is_directory=True)
            pending.replace(current)
        finally:
            # Inspect the actual commit point, including if interrupted during replace().
            retired = active if current.readlink() == Path(standby.name) else standby
            _clear_csvs(retired)
            pending.unlink(missing_ok=True)


def publish_csvs(staged: Path, output: Path) -> None:
    """Publish a caller's already-staged pair using the same transaction as folder exports."""
    with csv_publication(output) as standby:
        for name in CSV_NAMES:
            (staged / name).replace(standby / name)
