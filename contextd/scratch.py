"""Hardened scratch space.

Everything contextd copies out of the archive to work on — a browser history
snapshot, a distiller's working directory, a restore drill's staging tree — is
plaintext personal data sitting outside the archive's protection. Three things
were wrong with the previous handling:

1. **Location and mode.** ``tempfile.mkdtemp()`` lands in the shared system
   temp directory. The directory is 0700, but files copied into it inherit the
   *source* file's mode, and the whole tree is readable by anything running as
   the same UID for as long as it exists.
2. **Cleanup on the failure path.** Cleanup ran only where the happy path
   reached it. A raised exception, a timeout, or a ``KeyboardInterrupt`` left a
   full copy of the user's browser history on disk indefinitely.
3. **Silence.** ``shutil.rmtree(..., ignore_errors=True)`` turns "the personal
   data is still on disk" into a no-op. Failing to clean up plaintext is
   exactly the event that must be loud.

This module fixes all three: scratch lives under the archive home (already
0700, and service-owned in a hardened deployment), directories are 0700 and
files 0600, removal happens in ``finally`` on every ordinary exit path, and a
removal that does not succeed raises :class:`ScratchCleanupError`.

Stale recovery removes **only** positively identified contextd scratch: a
non-symlink directory, directly under the scratch root, owned by this UID,
whose name matches the exact ``contextd-<purpose>-`` prefix pattern. There is
no glob-and-delete over a shared temp directory and no symlink following.
"""

import os
import re
import shutil
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from . import home

SCRATCH_DIRNAME = "scratch"
PREFIX = "contextd-"
_NAME_RX = re.compile(r"^contextd-[a-z0-9][a-z0-9_-]{0,31}-[A-Za-z0-9_]{6,}$")
STALE_AFTER_SECONDS = 6 * 3600


class ScratchCleanupError(RuntimeError):
    """Scratch could not be removed. Plaintext may still be on disk."""


def scratch_root() -> Path:
    root = home() / SCRATCH_DIRNAME
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root


def _is_own_scratch(path: Path, parent: Path | None = None) -> bool:
    """Positive identification. Every clause must hold before removal."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    expected = (parent or scratch_root()).resolve()
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.getuid()
        and _NAME_RX.match(path.name) is not None
        and path.parent.resolve() == expected
    )


def remove_scratch(path: Path, parent: Path | None = None) -> None:
    """Remove one positively identified scratch directory, loudly.

    Raises :class:`ScratchCleanupError` rather than ignoring errors: a tree of
    plaintext that could not be deleted is precisely the event a caller must
    not be allowed to miss.
    """
    if not _is_own_scratch(path, parent):
        raise ScratchCleanupError(
            f"refusing to remove {path}: not positively identified as this "
            f"user's contextd scratch"
        )
    shutil.rmtree(path)  # does not follow directory symlinks
    if path.exists():
        raise ScratchCleanupError(f"scratch survived removal: {path}")


def harden_file(path: Path) -> Path:
    """0600 a file written into scratch. Copies inherit the source's mode, so
    this is applied after every copy rather than trusted from the source."""
    os.chmod(path, 0o600)
    return path


def reap_stale(now: float | None = None) -> list[str]:
    """Remove scratch left behind by a killed process. Returns what was
    removed. Only positively identified, sufficiently old entries qualify —
    a concurrently running scan must not have its working directory deleted.
    """
    now = now if now is not None else time.time()
    removed = []
    root = scratch_root()
    for entry in root.iterdir():
        if not _is_own_scratch(entry):
            continue
        try:
            age = now - os.lstat(entry).st_mtime
        except OSError:
            continue
        if age < STALE_AFTER_SECONDS:
            continue
        remove_scratch(entry)
        removed.append(entry.name)
    return removed


@contextmanager
def scratch_dir(purpose: str, parent: Path | None = None):
    """A 0700 scratch directory removed in ``finally``.

    Cleanup runs on success, on any ordinary exception, and on
    ``KeyboardInterrupt``/``SystemExit`` (both derive from ``BaseException``,
    and ``finally`` covers them). A cleanup failure raises
    :class:`ScratchCleanupError` rather than being swallowed — if it fires
    during exception unwinding it chains to the original error, so neither
    failure is lost.
    """
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", purpose):
        raise ValueError(f"invalid scratch purpose {purpose!r}")
    # `parent` exists for the restore drill, which needs several times the
    # archive's size and so may be pointed at a larger volume. The same
    # naming, mode, ownership, and positive-identification rules apply there.
    if parent is None:
        parent = scratch_root()
    else:
        parent = Path(parent)
        parent.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=f"{PREFIX}{purpose}-", dir=parent))
    os.chmod(path, 0o700)
    try:
        yield path
    finally:
        remove_scratch(path, parent)
