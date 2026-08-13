"""Capture liveness: ledger-derived watermarks, threshold warnings, and the
loud staleness carriage on compiled checkpoints. All timestamps are injected —
no wall-clock dependence."""

import argparse
import json

import pytest

from contextd import load_config
from contextd.cli import cmd_status
from contextd.db import append_event, connect, verify_chain
from contextd.handoff import compile_checkpoint
from contextd.liveness import capture_liveness, format_age

OLD_TS = "2026-08-09T12:00:00+00:00"    # 96h before NOW
FRESH_TS = "2026-08-13T11:00:00+00:00"  # 1h before NOW
NOW = "2026-08-13T12:00:00+00:00"


def _append_at(conn, ts, *args, **kw):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("contextd.db.now_iso", lambda: ts)
        return append_event(conn, *args, **kw)


def _seed(conn):
    _append_at(conn, OLD_TS, "chrome", "page_visit",
               uri="https://x.test/a", content="old visit https://x.test/a")
    _append_at(conn, FRESH_TS, "claude_code", "message",
               content="fresh dialogue turn", meta={"role": "user"})
    _append_at(conn, FRESH_TS, "note", "note", content="a deliberate note",
               meta={"actor": "human"})


def _cfg(thresholds):
    cfg = load_config()
    cfg["liveness"]["stale_after_hours"] = thresholds
    return cfg


def test_ages_thresholds_and_note_exemption(isolated_contextd_home):
    conn = connect()
    _seed(conn)
    rows = {r["source"]: r for r in capture_liveness(
        conn, _cfg({"chrome": 48, "claude_code": 48}), now=NOW)}
    assert rows["chrome"]["age_hours"] == 96.0 and rows["chrome"]["stale"]
    assert rows["claude_code"]["age_hours"] == 1.0
    assert not rows["claude_code"]["stale"]
    # note has an age display but no threshold: silence, not malfunction
    assert rows["note"]["age_hours"] == 1.0
    assert rows["note"]["threshold_hours"] is None and not rows["note"]["stale"]
    assert [r["source"] for r in rows.values() if r["stale"]] == ["chrome"]


def test_removing_the_threshold_removes_the_warning(isolated_contextd_home):
    conn = connect()
    _seed(conn)
    rows = capture_liveness(conn, _cfg({"claude_code": 48}), now=NOW)
    assert not any(r["stale"] for r in rows)


def test_thresholded_source_with_no_events_ever_warns(isolated_contextd_home):
    conn = connect()
    _seed(conn)
    rows = {r["source"]: r for r in capture_liveness(
        conn, _cfg({"safari": 48, "claude_code": 48}), now=NOW)}
    assert rows["safari"]["last_ts"] is None and rows["safari"]["stale"]
    assert rows["safari"]["age_hours"] is None


def test_default_config_ships_thresholds(isolated_contextd_home):
    cfg = load_config()
    assert cfg["liveness"]["stale_after_hours"] == {
        "chrome": 48, "safari": 48, "claude_code": 48, "fs": 72}


def test_format_age():
    assert format_age(1.04) == "1.0h"
    assert format_age(47.9) == "47.9h"
    assert format_age(100.8) == "4.2d"


def test_status_prints_ages_and_exactly_one_warning(isolated_contextd_home,
                                                    capsys, monkeypatch):
    conn = connect()
    _seed(conn)
    conn.close()
    (isolated_contextd_home / "config.toml").write_text(
        "[liveness.stale_after_hours]\nchrome = 48\nclaude_code = 48\n")
    monkeypatch.setattr("contextd.liveness.now_iso", lambda: NOW)
    cmd_status(argparse.Namespace())
    out = capsys.readouterr().out
    assert "chrome: last event 4.0d ago" in out
    assert "claude_code: last event 1.0h ago" in out
    assert "note: last event 1.0h ago" in out
    assert ("WARNING: chrome last event 4.0d ago (threshold 48h) "
            "— capture may be stalled") in out
    assert out.count("WARNING") == 1


def test_checkpoint_carries_staleness_in_package_and_meta(
        isolated_contextd_home, monkeypatch):
    conn = connect()
    _seed(conn)
    monkeypatch.setattr("contextd.liveness.now_iso", lambda: NOW)
    out = compile_checkpoint(conn, _cfg({"chrome": 48, "claude_code": 48}),
                             budget=2000)
    assert out["package"].startswith(
        "CAPTURE STALENESS: chrome last event 4.0d ago (threshold 48h)\n\n")
    meta = json.loads(conn.execute(
        "SELECT meta FROM events WHERE id = ?",
        (out["egress_id"],)).fetchone()["meta"])
    assert meta["staleness"] == [{"source": "chrome", "age_hours": 96.0}]
    assert verify_chain(conn)["ok"]


def test_fresh_or_unthresholded_checkpoint_carries_nothing(
        isolated_contextd_home, monkeypatch):
    conn = connect()
    _seed(conn)
    monkeypatch.setattr("contextd.liveness.now_iso", lambda: NOW)
    out = compile_checkpoint(conn, _cfg({"claude_code": 48}), budget=2000)
    assert "CAPTURE STALENESS" not in out["package"]
    meta = json.loads(conn.execute(
        "SELECT meta FROM events WHERE id = ?",
        (out["egress_id"],)).fetchone()["meta"])
    assert "staleness" not in meta
