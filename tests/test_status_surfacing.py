"""ctx status surfaces the authority and capture states an operator must see.

These are archive-derived senses on purpose: status never probes the live
filesystem, so a temp-archive test controls everything it asserts."""

import argparse
import contextlib
import io
import os
import sqlite3

from contextd import load_config
from contextd.cli import cmd_status
from contextd.db import connect, get_cursor, set_cursor


def _status() -> str:
    connect().close()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_status(argparse.Namespace())
    return buf.getvalue()


def test_status_names_the_unenrolled_signer(monkeypatch):
    monkeypatch.delenv("CONTEXTD_INSECURE_TEST_SIGNER")
    out = _status()
    assert "operator signer: NOT ENROLLED" in out
    assert "WARNING: every operator CLI act refuses" in out
    assert "ctx security key register" in out


def test_status_reports_test_mode_signer_without_warning():
    out = _status()
    assert "operator signer: test-mode software signer" in out
    assert "operator CLI act refuses" not in out


def test_status_warns_from_recorded_no_access_state():
    conn = connect()
    set_cursor(conn, "safari",
               {"watermark": 0, "last_status": "no access (OperationalError)"})
    out = _status()
    assert "WARNING: safari history is unreadable" in out
    assert "Full Disk Access" in out
    conn.close()


def test_scan_persists_then_clears_the_no_access_state(tmp_path, monkeypatch):
    import contextd.ingest as ingest

    db = tmp_path / "History.db"
    src = sqlite3.connect(db)
    src.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT)")
    src.execute("CREATE TABLE history_visits "
                "(history_item INTEGER, title TEXT, visit_time REAL)")
    src.commit()
    src.close()
    monkeypatch.setattr(ingest, "SAFARI_HISTORY", str(db))
    conn = connect()
    cfg = load_config()

    os.chmod(db, 0o000)
    out = ingest.scan_safari(conn, cfg)
    assert out["status"].startswith("no access")
    assert get_cursor(conn, "safari")["last_status"].startswith("no access")
    assert "WARNING: safari history is unreadable" in _status()

    os.chmod(db, 0o600)
    out = ingest.scan_safari(conn, cfg)
    assert "status" not in out
    assert "last_status" not in get_cursor(conn, "safari")
    assert "history is unreadable" not in _status()
    conn.close()
