"""The note tool's kernel-verified derivation binding, and the reconciler's
side of the contract: id-prefixed dialogue, binding env, receipted prompt."""

import json

import pytest
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


def _bind(monkeypatch, conn, egress, session="test-session"):
    """Issue a real dispatch capability and export it the way a harness does."""
    from contextd.capability import issue, token
    import os as _os
    cap = issue(conn, egress, principal_uid=_os.getuid(), dispatcher=session)
    monkeypatch.setenv("CONTEXTD_DISPATCH_CAPABILITY", token(cap))
    monkeypatch.setenv("CONTEXTD_DISPATCH_SESSION", session)
    monkeypatch.delenv("CONTEXTD_DERIVATION_SOURCE", raising=False)
    return cap


def _note_row(conn, reply):
    assert reply.startswith("noted as event #"), reply
    eid = int(reply.rsplit("#", 1)[1])
    row = conn.execute("SELECT * FROM events WHERE id = ?", (eid,)).fetchone()
    return eid, json.loads(row["meta"])


def test_note_without_binding_is_unchanged():
    conn = connect()
    eid, meta = _note_row(conn, note("a plain model note"))
    assert "derivation" not in meta
    # `actor` is gone: it was a caller-written string read back as identity.
    # What survives is the unverified claimed label plus an explicit level.
    assert meta["claimed_client"] == "mcp"
    assert meta["assurance"] == "unverified"


def test_bound_note_gets_kernel_verified_lineage(monkeypatch):
    conn = connect()
    ids, egress = _dialogue_egress(conn)
    cap = _bind(monkeypatch, conn, egress)
    eid, meta = _note_row(
        conn, note(f"Gate stays model-free [{ids[0]}][{ids[1]}]."))
    from contextd.capability import digest as capability_digest
    assert meta["derivation"] == {
        "source_egress": egress, "anchors": ids,
        "capability_id": capability_digest(cap["capability_id"])}
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
    _bind(monkeypatch, conn, egress)
    eid, meta = _note_row(conn, note("A note that cites nothing."))
    assert meta["derivation"]["source_egress"] == egress
    assert meta["derivation"]["anchors"] == []
    assert len(meta["derivation"]["capability_id"]) == 64
    assert closure(conn, eid)["verdict"] == "ungrounded"


def test_invalid_anchor_refuses_the_note(monkeypatch):
    conn = connect()
    ids, egress = _dialogue_egress(conn)
    _bind(monkeypatch, conn, egress)
    before = conn.execute("SELECT COUNT(*) FROM events "
                          "WHERE kind='note'").fetchone()[0]
    reply = note("A claim laundering an undisclosed event [999999].")
    assert reply.startswith("REFUSED:")
    assert "999999" in reply
    after = conn.execute("SELECT COUNT(*) FROM events "
                         "WHERE kind='note'").fetchone()[0]
    assert after == before


def test_binding_to_a_non_disclosure_refuses(monkeypatch):
    from contextd.capability import CapabilityError, issue
    import os as _os
    conn = connect()
    plain = append_event(conn, "note", "note", content="not an egress",
                         meta={"claimed_client": "cli"})
    # a capability cannot even be ISSUED against a non-disclosure
    with pytest.raises(CapabilityError):
        issue(conn, plain, principal_uid=_os.getuid(), dispatcher="s")
    monkeypatch.setenv("CONTEXTD_DISPATCH_CAPABILITY", "garbage")
    monkeypatch.setenv("CONTEXTD_DISPATCH_SESSION", "s")
    assert note("any text").startswith("REFUSED:")


def test_the_retired_env_binding_is_refused_not_ignored(monkeypatch):
    """A harness still exporting the old variable must fail loudly."""
    conn = connect()
    _ids, egress = _dialogue_egress(conn)
    monkeypatch.setenv("CONTEXTD_DERIVATION_SOURCE", str(egress))
    reply = note("any text")
    assert reply.startswith("REFUSED:")
    assert "retired" in reply


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
    reconciler.reconcile(conn, epoch_id, epoch_meta)

    for mid in mids:
        assert f"[{mid}]" in observed["input"]
    # the harness now exports an opaque capability, not an event id
    assert "CONTEXTD_DERIVATION_SOURCE" not in observed["env"]
    token = observed["env"]["CONTEXTD_DISPATCH_CAPABILITY"]
    # opaque: two 64-char random hex halves, carrying no event id to enumerate
    from contextd.capability import parse_token
    cap_id, _cap_secret = parse_token(token)
    assert len(cap_id) == 64 and int(cap_id, 16) >= 0
    assert token.count(".") == 1 and len(token) == 129
    assert observed["env"]["CONTEXTD_DISPATCH_SESSION"] == "reconcile"
    assert observed["env"]["CONTEXTD_CLIENT"] == "reconciler"
    assert "cite the bracketed event id" in observed["input"]
