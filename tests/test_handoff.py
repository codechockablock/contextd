"""Checkpoint/restore kernel: frozen views are valid archives whose future is
unreachable by construction, and compilation is stratified, deduplicated,
gated, and anchored."""

import json

import pytest

from contextd import load_config
from contextd.db import append_event, connect, verify_chain
from contextd.gate import verify_anchors
from contextd.handoff import (HandoffError, compile_checkpoint, drop_view,
                              freeze_view, render_package,
                              select_checkpoint_context)


def _seed(conn, n_msgs=8):
    ids = {}
    ids["note_h"] = append_event(conn, "note", "note",
                                 content="decision: keep the gate an audit layer",
                                 meta={"actor": "human"})
    for i in range(n_msgs):
        role = "user" if i % 2 == 0 else "assistant"
        append_event(conn, "claude_code", "message", uri=f"claude://m{i}",
                     content=f"dialogue turn {i}: working on the frobnicator",
                     meta={"role": role, "session_id": "s1"})
    ids["egress"] = append_event(conn, "gate", "egress", content="disclosed",
                                 meta={"type": "recall", "items": [ids["note_h"]],
                                       "est_tokens": 2})
    ids["note_m"] = append_event(
        conn, "note", "note",
        content=f"episode: frobnicator design settled [{ids['note_h']}]",
        meta={"actor": "claude-code",
              "derivation": {"source_egress": ids["egress"],
                             "anchors": [ids["note_h"]]}})
    ids["future"] = append_event(conn, "note", "note",
                                 content="FUTURE: this must never be visible",
                                 meta={"actor": "human"})
    return ids


def test_frozen_view_is_valid_and_future_free(isolated_contextd_home, tmp_path,
                                              monkeypatch):
    conn = connect()
    ids = _seed(conn)
    cutoff = ids["note_m"]
    view_home = tmp_path / "view"
    info = freeze_view(isolated_contextd_home / "contextd.db", view_home, cutoff)
    assert info["tip"] == cutoff
    assert info["events"] == cutoff
    assert info["source_tip"] == ids["future"]

    monkeypatch.setenv("CONTEXTD_HOME", str(view_home))
    vconn = connect()
    r = verify_chain(vconn)
    assert r["ok"] and r["checked"] == cutoff
    assert vconn.execute("SELECT COUNT(*) c FROM events WHERE id > ?",
                         (cutoff,)).fetchone()["c"] == 0
    # FTS was rebuilt by triggers: the future note is unfindable
    from contextd.search import search
    assert search(vconn, "frobnicator")
    assert not search(vconn, "FUTURE")
    # a view is append-usable: its own egresses land in the copy, not the source
    from contextd.gate import assemble
    out = assemble(vconn, load_config(), "frobnicator", purpose="t")
    assert out["egress_id"] == cutoff + 1


def test_freeze_view_refuses_bad_targets(isolated_contextd_home, tmp_path):
    conn = connect()
    _seed(conn)
    db = isolated_contextd_home / "contextd.db"
    with pytest.raises(HandoffError):
        freeze_view(db, tmp_path / "v0", 0)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "x").write_text("data")
    with pytest.raises(HandoffError):
        freeze_view(db, occupied, 3)


def test_drop_view_only_removes_views(isolated_contextd_home, tmp_path):
    conn = connect()
    _seed(conn)
    view = tmp_path / "v"
    freeze_view(isolated_contextd_home / "contextd.db", view, 3)
    drop_view(view)
    assert not view.exists()
    notaview = tmp_path / "real"
    notaview.mkdir()
    (notaview / "config.toml").write_text("[gate]\n")
    with pytest.raises(HandoffError):
        drop_view(notaview)


def test_selection_stratifies_and_dedupes(isolated_contextd_home):
    conn = connect()
    ids = _seed(conn, n_msgs=8)
    cfg = load_config()
    sel = select_checkpoint_context(conn, cfg, budget=4000,
                                    task_hint="frobnicator design")
    picked = {k: [it["id"] for it in sel[k]] for k in
              ("tail", "episodes", "notes", "recall")}
    assert ids["note_h"] in picked["notes"] or ids["note_h"] in [
        i for i in picked["recall"]]
    assert ids["note_m"] in picked["episodes"] or ids["note_m"] in picked["recall"]
    all_ids = [i for v in picked.values() for i in v]
    assert len(all_ids) == len(set(all_ids)), "sections must not duplicate events"
    # tail is chronological and carries roles
    assert picked["tail"] == sorted(picked["tail"])
    assert any("role=user" in it["header"] for it in sel["tail"])


def test_compile_checkpoint_gates_and_anchors(isolated_contextd_home):
    conn = connect()
    _seed(conn)
    cfg = load_config()
    repo = {"branch": "master", "commit": "abc1234", "log": "abc1234 subject",
            "status": "M contextd/gate.py", "diffstat": "1 file changed",
            "tests": {"cmd": "pytest -q", "exit": 1, "last_lines": "1 failed"}}
    out = compile_checkpoint(conn, cfg, budget=4000, task_hint="gate audit",
                             repo=repo)
    assert out["egress_id"] is not None
    row = conn.execute("SELECT * FROM events WHERE id = ?",
                       (out["egress_id"],)).fetchone()
    meta = json.loads(row["meta"])
    assert row["kind"] == "egress" and meta["type"] == "checkpoint"
    assert meta["items"] == out["items"]
    # every event id present in the package resolves to a supplied item
    anchors = verify_anchors(out["package"], out["items"] + [out["tip"]])
    assert not anchors["invalid"]
    assert "REPOSITORY STATE" in out["package"]
    assert "M contextd/gate.py" in out["package"]
    assert "RAW DIALOGUE TAIL" in out["package"]


def test_render_package_orders_tail_last(isolated_contextd_home):
    conn = connect()
    _seed(conn)
    sel = select_checkpoint_context(conn, load_config(), budget=4000)
    pkg = render_package(sel, tip=99)
    assert pkg.index("OPERATOR NOTES") < pkg.index("RAW DIALOGUE TAIL")
    assert "tip #99" in pkg
