"""Publish both standard CSV names by switching one relative directory link."""
import os
import shutil
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


def publish_csvs(staged: Path, output: Path) -> None:
    """Prepare the inactive pair, then make both files visible with one rename."""
    state = output / _STATE
    _directory(state)
    with (state / "publish.lock").open("a+b") as lock:
        _lock(lock)
        current = state / "current"
        if not current.is_symlink():
            _directory(state / "a")
            current.symlink_to("a", target_is_directory=True)
        active = current.readlink()
        if str(active) not in ("a", "b"):
            raise OSError(f"Invalid CSV snapshot: {current}")
        standby = state / ("b" if str(active) == "a" else "a")
        _directory(state / active)
        _directory(standby)
        for name in CSV_NAMES:
            (staged / name).replace(standby / name)

        # On the first run (or for preexisting regular CSVs), each public name
        # must still read its previous bytes until the whole new pair is ready.
        for name in CSV_NAMES:
            public = output / name
            link = Path(_STATE) / "current" / name
            if public.is_symlink() and public.readlink() == link:
                continue
            previous = state / active / name
            if public.is_file():
                backup = staged / "previous"
                shutil.copy(public, backup)
                backup.replace(previous)
            elif public.exists():
                raise OSError(f"Expected a CSV file: {public}")
            else:
                previous.unlink(missing_ok=True)
            alias = staged / name
            alias.symlink_to(link)
            alias.replace(public)

        switch = staged / "next"
        switch.symlink_to(standby.name, target_is_directory=True)
        switch.replace(current)
