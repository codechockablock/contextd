"""The note tool's kernel-verified derivation binding, and the reconciler's
side of the contract: id-prefixed dialogue, binding env, receipted prompt."""

import json
from types import SimpleNamespace

import hooks.reconcile as reconciler
from contextd import load_config
from contextd.db import append_event, connect
from contextd.gate import disclose
from contextd.mcp_server import note
from contextd.provenance import closure


def _dialogue_egress(conn):
    cfg = load_config()
    ids = [
        append_event(conn, "claude_code", "message",
                     content="we decided to keep the gate model-free",
                     meta={"role": "user", "session_id": "s"}),
        append_event(conn, "claude_code", "message",
                     content="agreed; models call the kernel",
                     meta={"role": "assistant", "session_id": "s"}),
    ]
    payload = "\n\n".join(f"[{i}] line {i}" for i in ids)
    egress = disclose(conn, cfg, payload,
                      {"type": "reconcile_dialogue", "items": ids})["egress_id"]
    return ids, egress


def _note_row(conn, reply):
    assert reply.startswith("noted as event #"), reply
    eid = int(reply.rsplit("#", 1)[1])
    row = conn.execute("SELECT * FROM events WHERE id = ?", (eid,)).fetchone()
    return eid, json.loads(row["meta"])


def test_note_without_binding_is_unchanged():
    conn = connect()
    eid, meta = _note_row(conn, note("a plain model note"))
    assert "derivation" not in meta
    assert meta["actor"] == "mcp"


def test_bound_note_gets_kernel_verified_lineage(monkeypatch):
    conn = connect()
    ids, egress = _dialogue_egress(conn)
    monkeypatch.setenv("CONTEXTD_DERIVATION_SOURCE", str(egress))
    eid, meta = _note_row(
        conn, note(f"Gate stays model-free [{ids[0]}][{ids[1]}]."))
    assert meta["derivation"] == {"source_egress": egress, "anchors": ids}
    tree = closure(conn, eid)
    # the user message grounds; the assistant message is a model-inference
    # terminal — so the note is honestly 'mixed', never laundered to human
    assert tree["verdict"] == "mixed"
    assert set(tree["children"]) == set(ids)
    assert tree["children"][ids[0]]["verdict"] == "grounded"
    assert tree["children"][ids[1]]["verdict"] == "ungrounded"


def test_bound_note_with_unanchored_text_is_accepted_but_visible(monkeypatch):
    conn = connect()
    _, egress = _dialogue_egress(conn)
    monkeypatch.setenv("CONTEXTD_DERIVATION_SOURCE", str(egress))
    eid, meta = _note_row(conn, note("A note that cites nothing."))
    assert meta["derivation"] == {"source_egress": egress, "anchors": []}
    assert closure(conn, eid)["verdict"] == "ungrounded"


def test_invalid_anchor_refuses_the_note(monkeypatch):
    conn = connect()
    ids, egress = _dialogue_egress(conn)
    monkeypatch.setenv("CONTEXTD_DERIVATION_SOURCE", str(egress))
    before = conn.execute("SELECT COUNT(*) FROM events "
                          "WHERE kind='note'").fetchone()[0]
    reply = note("A claim laundering an undisclosed event [999999].")
    assert reply.startswith("REFUSED:")
    assert "999999" in reply
    after = conn.execute("SELECT COUNT(*) FROM events "
                         "WHERE kind='note'").fetchone()[0]
    assert after == before


def test_binding_to_a_non_disclosure_refuses(monkeypatch):
    conn = connect()
    plain = append_event(conn, "note", "note", content="not an egress",
                         meta={"actor": "human"})
    monkeypatch.setenv("CONTEXTD_DERIVATION_SOURCE", str(plain))
    assert note("any text").startswith("REFUSED:")
    monkeypatch.setenv("CONTEXTD_DERIVATION_SOURCE", "garbage")
    assert note("any text").startswith("REFUSED:")


def test_reconciler_dialogue_carries_ids_and_binding_env(monkeypatch):
    conn = connect()
    session = "derivation-env-session"
    mids = [append_event(conn, "claude_code", "message",
                         content=f"dialogue line {i}",
                         meta={"role": "user" if i % 2 == 0 else "assistant",
                               "session_id": session})
            for i in range(reconciler.MIN_MESSAGES)]
    epoch_meta = {"session_id": session, "start_event_id": mids[0] - 1,
                  "end_event_id": mids[-1]}
    epoch_id = append_event(conn, "claude_code", "epoch", meta=epoch_meta)

    observed = {}

    def fake_run(*args, **kwargs):
        observed["input"] = kwargs["input"]
        observed["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout="DONE", stderr="")

    monkeypatch.setattr(reconciler.subprocess, "run", fake_run)
    result = reconciler.reconcile(conn, epoch_id, epoch_meta)

    for mid in mids:
        assert f"[{mid}]" in observed["input"]
    assert observed["env"]["CONTEXTD_DERIVATION_SOURCE"] == \
        str(result["egress_id"])
    assert observed["env"]["CONTEXTD_CLIENT"] == "reconciler"
    assert "cite the bracketed event id" in observed["input"]
