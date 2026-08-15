"""Scratch must not survive any exit path, and a failed cleanup must be loud.

The failure this suite prevents: `_copy_locked_db` wrote a full plaintext copy
of the user's browser history into the shared system temp directory and removed
it only where the happy path reached the cleanup line. Every other exit —
a failed SQLite open, a malformed database, a timeout, a KeyboardInterrupt —
left the copy on disk indefinitely. The distiller hooks never cleaned up at
all, and the restore drill used `ignore_errors=True`, which turns "a full
plaintext archive is still on disk" into a silent no-op.
"""

import os
import sqlite3
import stat
import time
from pathlib import Path

import pytest

from contextd import home
from contextd.db import connect
from contextd.ingest import _scan_browser
from contextd.scratch import (
    STALE_AFTER_SECONDS,
    ScratchCleanupError,
    reap_stale,
    remove_scratch,
    scratch_dir,
    scratch_root,
)


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _scratch_entries() -> list[Path]:
    root = scratch_root()
    return [p for p in root.iterdir() if p.name.startswith("contextd-")]


# --- modes ------------------------------------------------------------------

def test_scratch_dir_is_0700_and_files_are_0600():
    with scratch_dir("probe") as workdir:
        assert _mode(workdir) == 0o700, oct(_mode(workdir))
        assert _mode(scratch_root()) == 0o700
        target = workdir / "copy.db"
        target.write_text("plaintext")
        os.chmod(target, 0o644)          # a copy inheriting a permissive mode
        from contextd.scratch import harden_file
        harden_file(target)
        assert _mode(target) == 0o600


def test_scratch_lives_under_the_archive_not_shared_temp():
    with scratch_dir("probe") as workdir:
        assert workdir.parent == scratch_root()
        assert str(workdir).startswith(str(home()))


# --- every exit path --------------------------------------------------------

def test_success_leaves_nothing():
    with scratch_dir("probe") as workdir:
        (workdir / "f").write_text("x")
        kept = workdir
    assert not kept.exists()
    assert _scratch_entries() == []


@pytest.mark.parametrize("failure", [
    RuntimeError("ordinary failure"),
    sqlite3.DatabaseError("malformed database"),
    OSError("copy failed"),
    KeyboardInterrupt(),
    SystemExit(2),
    TimeoutError("dispatch timed out"),
])
def test_every_failure_path_leaves_nothing(failure):
    kept = None
    with pytest.raises(type(failure)):
        with scratch_dir("probe") as workdir:
            kept = workdir
            (workdir / "secret").write_text("plaintext history")
            raise failure
    assert kept is not None and not kept.exists()
    assert _scratch_entries() == []


def test_cleanup_failure_is_loud_not_swallowed(monkeypatch):
    """The regression that matters: a cleanup that does not succeed must raise
    rather than pass silently."""
    import contextd.scratch as scratch

    def refuse(path):
        raise OSError("device busy")

    with pytest.raises(OSError):
        with scratch_dir("probe") as workdir:
            monkeypatch.setattr(scratch.shutil, "rmtree", refuse)
            (workdir / "secret").write_text("plaintext")
    # and the surviving directory is still identifiable, not orphaned garbage
    monkeypatch.undo()
    for entry in _scratch_entries():
        remove_scratch(entry)


def test_cleanup_failure_chains_to_the_original_error(monkeypatch):
    import contextd.scratch as scratch

    def refuse(*_args, **_kwargs):
        raise ScratchCleanupError("cannot remove")

    monkeypatch.setattr(scratch, "remove_scratch", refuse)
    with pytest.raises(ScratchCleanupError) as exc:
        with scratch_dir("probe"):
            raise RuntimeError("the original failure")
    # the original failure is still reachable, not replaced
    assert isinstance(exc.value.__context__, RuntimeError)
    assert "the original failure" in str(exc.value.__context__)


# --- the browser copy, end to end ------------------------------------------

def _fake_history(path: Path, rows: int = 3) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE urls (url TEXT, title TEXT, last_visit_time INT)")
    for i in range(rows):
        conn.execute(
            "INSERT INTO urls VALUES (?,?,?)",
            (f"https://example.invalid/p{i}", f"private page {i}", 1000 + i),
        )
    conn.commit()
    conn.close()


QUERY = ("SELECT url, title, last_visit_time FROM urls "
         "WHERE last_visit_time > ? ORDER BY last_visit_time")


def test_browser_scan_success_leaves_no_copy(tmp_path):
    conn = connect()
    src = tmp_path / "History"
    _fake_history(src)
    out = _scan_browser(conn, {"browser": {"skip_domains": [], "skip_domain_files": []}},
                        "chrome", str(src), QUERY, lambda t: float(t))
    assert out["page_visit"] == 3
    assert _scratch_entries() == []


def test_browser_scan_query_failure_leaves_no_copy(tmp_path):
    """A malformed/incompatible history DB used to leave the copy behind."""
    conn = connect()
    src = tmp_path / "History"
    _fake_history(src)
    out = _scan_browser(conn, {"browser": {"skip_domains": [], "skip_domain_files": []}},
                        "chrome", str(src), "SELECT no_such_column FROM urls WHERE x > ?",
                        lambda t: float(t))
    assert out["status"].startswith("no access")
    assert _scratch_entries() == [], "a failed query left a history copy on disk"


def test_browser_scan_open_failure_leaves_no_copy(tmp_path):
    conn = connect()
    src = tmp_path / "History"
    src.write_text("this is not a sqlite database")
    out = _scan_browser(conn, {"browser": {"skip_domains": [], "skip_domain_files": []}},
                        "chrome", str(src), QUERY, lambda t: float(t))
    assert out["status"].startswith("no access")
    assert _scratch_entries() == []


def test_browser_scan_interrupt_leaves_no_copy(tmp_path, monkeypatch):
    conn = connect()
    src = tmp_path / "History"
    _fake_history(src)
    import contextd.ingest as ingest

    real = ingest._copy_locked_db

    def copy_then_interrupt(source, workdir):
        real(source, workdir)
        raise KeyboardInterrupt

    monkeypatch.setattr(ingest, "_copy_locked_db", copy_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        _scan_browser(conn, {"browser": {"skip_domains": [], "skip_domain_files": []}},
                      "chrome", str(src), QUERY, lambda t: float(t))
    assert _scratch_entries() == []


def test_copied_history_is_0600_while_in_use(tmp_path):
    from contextd.ingest import _copy_locked_db
    src = tmp_path / "History"
    _fake_history(src)
    os.chmod(src, 0o644)                    # a world-readable source
    with scratch_dir("probe") as workdir:
        copy = _copy_locked_db(src, workdir)
        assert _mode(copy) == 0o600, oct(_mode(copy))


# --- stale recovery ---------------------------------------------------------

def test_stale_scratch_is_reaped_but_fresh_scratch_is_not():
    root = scratch_root()
    stale = root / "contextd-loop-scan-AAAAAAAA"
    stale.mkdir()
    os.utime(stale, (time.time() - STALE_AFTER_SECONDS - 60,) * 2)
    with scratch_dir("probe") as live:
        removed = reap_stale()
        assert stale.name in removed
        assert not stale.exists()
        assert live.exists(), "a concurrently running scan was deleted"


def test_reaper_refuses_anything_not_positively_identified():
    root = scratch_root()
    old = time.time() - STALE_AFTER_SECONDS - 60

    # a foreign directory in the scratch root
    foreign = root / "someone-elses-data"
    foreign.mkdir()
    os.utime(foreign, (old, old))

    # a symlink whose name would otherwise match
    target = root.parent / "important-data"
    target.mkdir(exist_ok=True)
    link = root / "contextd-loop-scan-BBBBBBBB"
    link.symlink_to(target)

    assert reap_stale() == []
    assert foreign.exists(), "reaper deleted a directory it did not create"
    assert target.exists(), "reaper followed a symlink out of the scratch root"
    assert link.is_symlink()

    with pytest.raises(ScratchCleanupError):
        remove_scratch(foreign)
    with pytest.raises(ScratchCleanupError):
        remove_scratch(link)

    link.unlink()


def test_startup_reaps_stale_scratch():
    root = scratch_root()
    stale = root / "contextd-checkpoint-distill-CCCCCCCC"
    stale.mkdir()
    (stale / "leftover").write_text("plaintext")
    os.utime(stale, (time.time() - STALE_AFTER_SECONDS - 60,) * 2)
    connect().close()
    assert not stale.exists(), "connect() did not reap stale scratch"


def test_purpose_must_be_a_safe_token():
    for bad in ("../escape", "Has Spaces", "UPPER", "", "x" * 40):
        with pytest.raises(ValueError):
            with scratch_dir(bad):
                pass
