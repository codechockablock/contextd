"""Delegation grants (docs/GRANTS.md): reduction correctness, refusal
without a covering grant, model-granted provenance, checkpoint loudness,
and immediate revocation."""

import json

import pytest

from contextd import load_config
from contextd.db import append_event, connect
from contextd.grants import (GrantError, active_grant_for, add_grant,
                             parse_duration, reduce_grants, revoke_grant)
from contextd.handoff import compile_checkpoint
from contextd.loops import add_candidate, make_scope, reduce_loops, scope_str
from contextd.mcp_server import decision_supersede, loop_confirm

GLOBAL = make_scope(None)
REPO_A = make_scope("/home/sim/aster")
REPO_B = make_scope("/home/sim/brontide")


def test_reduction_grant_revoke_expiry_idempotence():
    conn = connect()
    with pytest.raises(GrantError):
        add_grant(conn, "grant.grant", GLOBAL)  # no meta-grants, ever
    with pytest.raises(GrantError):
        add_grant(conn, "decision.supersede", REPO_A)  # global-only class
    g = add_grant(conn, "loop.confirm", REPO_A, reason="tired tonight")
    assert g["result"] == "created"
    again = add_grant(conn, "loop.confirm", REPO_A)
    assert again["result"] == "existing"  # appends nothing

    assert active_grant_for(conn, "loop.confirm", REPO_A) is not None
    assert active_grant_for(conn, "loop.confirm", REPO_B) is None
    assert active_grant_for(conn, "loop.dismiss", REPO_A) is None

    # expiry is evaluated at act time; expired == absent
    e = add_grant(conn, "loop.dismiss", GLOBAL,
                  expires="2026-01-01T00:00:00+00:00")
    assert active_grant_for(conn, "loop.dismiss", REPO_A,
                            now="2025-12-31T23:59:59+00:00") is not None
    assert active_grant_for(conn, "loop.dismiss", REPO_A,
                            now="2026-01-01T00:00:00+00:00") is None

    r = revoke_grant(conn, g["grant"]["id"], reason="back at keyboard")
    assert r["result"] == "revoked"
    assert active_grant_for(conn, "loop.confirm", REPO_A) is None
    assert revoke_grant(conn, g["grant"]["id"])["result"] == "already_revoked"
    assert e["grant"]["id"] != g["grant"]["id"]
    assert parse_duration("8h").total_seconds() == 8 * 3600
    with pytest.raises(GrantError):
        parse_duration("soon")


def test_model_cannot_grant_to_itself():
    conn = connect()
    append_event(conn, "grant", "grant", content="sneaky",
                 meta={"op": "grant", "class": "loop.confirm",
                       "scope": {"global": True}, "authority": "model",
                       "client": "model"})
    red = reduce_grants(conn)
    assert red["grants"] == []
    assert any("cannot grant to itself" in a["why"] for a in red["anomalies"])
    assert active_grant_for(conn, "loop.confirm", GLOBAL) is None


def test_refusal_without_grant_and_provenance_with():
    conn = connect()
    cand = add_candidate(conn, "wire the flange telemetry", REPO_A,
                         client="model")["loop"]
    # no grant: the MCP path refuses and names the operator act needed
    out = loop_confirm(cand["id"])
    assert out.startswith("REFUSED") and "ctx grant add loop.confirm" in out
    assert reduce_loops(conn)["loops"][cand["id"]]["state"] == "candidate"

    g = add_grant(conn, "loop.confirm", REPO_A)["grant"]
    out = loop_confirm(cand["id"], reason="matches the sprint plan")
    assert "model-granted" in out and f"grant ev {g['id']}" in out
    lp = reduce_loops(conn)["loops"][cand["id"]]
    assert lp["state"] == "open"
    assert lp["promoted_authority"] == "model-granted"  # never operator
    confirm = lp["history"][-1]
    row = conn.execute("SELECT meta FROM events WHERE id = ?",
                       (confirm["event"],)).fetchone()
    assert json.loads(row["meta"])["grant"] == g["id"]

    # revocation is immediate: identical act now refuses
    cand2 = add_candidate(conn, "expand the flange telemetry", REPO_A,
                          client="model")["loop"]
    revoke_grant(conn, g["id"])
    assert loop_confirm(cand2["id"]).startswith("REFUSED")


def test_decision_supersede_grant_gated():
    conn = connect()
    v1 = append_event(conn, "note", "note", content="decision: blue path",
                      meta={"actor": "human"})
    v2 = append_event(conn, "note", "note", content="revisited: green path",
                      meta={"actor": "human"})
    assert decision_supersede(v1, v2).startswith("REFUSED")
    g = add_grant(conn, "decision.supersede", GLOBAL,
                  reason="reconciler may link obvious replacements")["grant"]
    out = decision_supersede(v1, v2, reason="v2 explicitly replaces v1")
    assert "model-granted" in out
    edge_meta = json.loads(conn.execute(
        "SELECT meta FROM events WHERE kind='decision' "
        "ORDER BY id DESC LIMIT 1").fetchone()["meta"])
    assert edge_meta["authority"] == "model-granted"
    assert edge_meta["grant"] == g["id"]


def test_checkpoint_loudness():
    conn = connect()
    cfg = load_config()
    for i in range(4):
        append_event(conn, "claude_code", "message", uri=f"claude://g{i}",
                     content=f"dialogue turn {i}",
                     meta={"role": "user", "session_id": "s1"})
    # no active grant: no delegations line, no meta key
    out = compile_checkpoint(conn, cfg, budget=2000)
    assert "STANDING DELEGATIONS" not in out["package"]

    g = add_grant(conn, "loop.confirm", REPO_A, reason="overnight")["grant"]
    out = compile_checkpoint(conn, cfg, budget=2000)
    assert "STANDING DELEGATIONS" in out["package"]
    assert f"grant ev {g['id']}" in out["package"]
    assert f"ctx grant revoke {g['id']}" in out["package"]
    meta = json.loads(conn.execute(
        "SELECT meta FROM events WHERE id = ?",
        (out["egress_id"],)).fetchone()["meta"])
    assert meta["delegations"] == [
        {"class": "loop.confirm", "grant": g["id"],
         "scope": scope_str(REPO_A), "expires": None}]

    # a checkpoint for an uncovered repo does not carry the repo-A grant
    out_b = compile_checkpoint(conn, cfg, budget=2000,
                               repo={"path": "/home/sim/brontide"})
    assert "STANDING DELEGATIONS" not in out_b["package"]

    revoke_grant(conn, g["id"])
    out = compile_checkpoint(conn, cfg, budget=2000)
    assert "STANDING DELEGATIONS" not in out["package"]
