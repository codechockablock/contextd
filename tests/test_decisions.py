"""Decision supersession (docs/DECISIONS.md): append-only edges, deterministic
reduction, and the loud compile contract — a superseded item is never
checkpointed unmarked, and a carried chain's current version is carried or
named."""

import pytest

from contextd import load_config
from contextd.db import append_event, connect
from contextd.decisions import (DecisionError, current_version,
                                record_supersession, reduce_supersessions,
                                supersession_marker)
from contextd.handoff import compile_checkpoint, select_checkpoint_context


def _note(conn, text):
    return append_event(conn, "note", "note", content=text,
                        meta={"actor": "human"})


def _msgs(conn, n=6):
    for i in range(n):
        append_event(conn, "claude_code", "message", uri=f"claude://d{i}",
                     content=f"dialogue turn {i} about ordinary work",
                     meta={"role": "user" if i % 2 == 0 else "assistant",
                           "session_id": "s1"})


def test_record_reduce_idempotent_and_refusals():
    conn = connect()
    v1 = _note(conn, "decision: use the blue path")
    v2 = _note(conn, "revisited: use the green path instead")
    r = record_supersession(conn, v1, v2, reason="benchmarks")
    assert r["result"] == "created"
    again = record_supersession(conn, v1, v2)
    assert again["result"] == "existing"  # appends nothing
    red = reduce_supersessions(conn)
    assert red["edges"][v1]["new"] == v2 and not red["anomalies"]

    with pytest.raises(DecisionError):
        record_supersession(conn, v1, v1)
    with pytest.raises(DecisionError):
        record_supersession(conn, v1, 99999)
    egress = append_event(conn, "gate", "egress", content="x",
                          meta={"type": "recall", "items": []})
    with pytest.raises(DecisionError):
        record_supersession(conn, v1, egress)


def test_chain_walk_displacement_and_cycle():
    conn = connect()
    a, b, c = (_note(conn, t) for t in ("alpha v1", "alpha v2", "alpha v3"))
    record_supersession(conn, a, b)
    record_supersession(conn, b, c)
    red = reduce_supersessions(conn)
    walk = current_version(red["edges"], a)
    assert walk == {"current": c, "chain": [a, b, c], "cyclic": False}
    assert f"ev {c}" in supersession_marker(red["edges"], a)

    # displaced edge: a later edge from the same old wins, loudly
    d = _note(conn, "alpha v2-prime")
    record_supersession(conn, a, d)
    red = reduce_supersessions(conn)
    assert red["edges"][a]["new"] == d
    assert any("displaced" in x["why"] for x in red["anomalies"])

    # cycle: reduction stays deterministic and the marker says unresolvable
    # (a->b was displaced by a->d, so the loop is a->d->b->c->a)
    record_supersession(conn, c, a)
    record_supersession(conn, d, b)
    red = reduce_supersessions(conn)
    walk = current_version(red["edges"], b)
    assert walk["cyclic"] and walk["current"] is None
    assert "cyclic" in supersession_marker(red["edges"], b)


def test_compile_marks_superseded_and_carries_current():
    conn = connect()
    cfg = load_config()
    _msgs(conn)
    v1 = _note(conn, "decision: adopt the crimson-crate strategy for exports")
    _msgs(conn, 3)
    v2 = _note(conn, "revisited: the amber-hatch call replaces the earlier "
                     "crimson ruling")
    record_supersession(conn, v1, v2)
    # bury both versions beyond the notes slice so only the hint can reach
    # v1 and only the supersession contract can reach v2
    for i in range(30):
        _note(conn, f"filler note {i}: routine tidying, nothing settled")
    out = compile_checkpoint(conn, cfg, budget=2000,
                             task_hint="crimson-crate strategy exports")
    pkg = out["package"]
    assert v1 in out["items"] and v2 in out["items"]
    assert f"SUPERSEDED by ev {v2}" in pkg
    assert "CURRENT DECISION VERSIONS" in pkg
    # the marker rides the item, not the package tail: v1's block (header
    # line + text, blocks are separated by blank lines) carries it
    v1_block = pkg.split(f"[{v1}]")[1].split("\n\n")[0]
    assert f"SUPERSEDED by ev {v2}" in v1_block


def test_compile_current_already_carried_needs_no_section():
    conn = connect()
    cfg = load_config()
    _msgs(conn)
    v1 = _note(conn, "decision: keep the teal-ledger export ordering")
    v2 = _note(conn, "revisited: teal-ledger ordering reversed for exports")
    record_supersession(conn, v1, v2)
    # both versions are recent notes: the notes stratum carries both
    sel = select_checkpoint_context(conn, cfg, budget=2000)
    note_ids = {it["id"] for it in sel["notes"]}
    assert {v1, v2} <= note_ids
    assert sel["supersessions"] == [] and sel["supersessions_omitted"] == []
    marked = next(it for it in sel["notes"] if it["id"] == v1)
    assert f"SUPERSEDED by ev {v2}" in marked["text"]


def test_compile_loud_omission_when_current_cannot_fit():
    conn = connect()
    cfg = load_config()
    _msgs(conn)
    v1 = _note(conn, "decision: adopt the umbral-quay strategy for the sync")
    v2 = _note(conn, "revisited umbral-quay: " + "long replacement text " * 200)
    record_supersession(conn, v1, v2)
    # hint matches only v1; v2 is too large for the supersession reserve
    out = compile_checkpoint(conn, cfg, budget=2000,
                             task_hint="umbral-quay strategy sync")
    pkg = out["package"]
    assert v1 in out["items"] and v2 not in out["items"]
    assert f"SUPERSEDED by ev {v2}" in pkg
    assert f"SUPERSESSION OMITTED: current version ev {v2}" in pkg
    assert out["selection"]["supersessions_omitted"] == [
        {"carried": v1, "current": v2}]


def test_no_edges_means_no_reserve_and_no_section():
    conn = connect()
    cfg = load_config()
    _msgs(conn)
    _note(conn, "an ordinary decision, never superseded")
    sel = select_checkpoint_context(conn, cfg, budget=2000)
    assert sel["supersessions"] == [] and sel["supersessions_omitted"] == []
    pkg = compile_checkpoint(conn, cfg, budget=2000)["package"]
    assert "CURRENT DECISION VERSIONS" not in pkg
    assert "SUPERSEDED" not in pkg
