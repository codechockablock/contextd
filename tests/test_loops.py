"""The open-loops lifecycle, mechanically: append-only replay, idempotent
retry, invalid-transition refusal, authority separation, scope, checkpoint
carriage with crowd-out resistance and loud overflow, close/reopen,
dismissal suppression, the utterance binding, crash/retry, and the
byte-identical-dialogue boundary (docs/OPEN_LOOPS.md is the contract)."""

import json

from datetime import datetime, timedelta, timezone

import pytest


from contextd import load_config
from contextd.db import InjectedCrash, append_event, append_event_checked, connect
from contextd.gate import verify_anchors
from contextd.handoff import compile_checkpoint, select_checkpoint_context
from contextd.loops import (LoopError, add_candidate, add_loop, dedupe_key,
                            loops_for_scope, make_scope, reduce_loops,
                            scope_str, transition)
from experiments.open_loops.scoring import check_carriage


def _soon(hours: int = 8) -> str:
    """A finite, timezone-aware expiry. Grants without one are refused."""
    return (datetime.now(timezone.utc)
            + timedelta(hours=hours)).isoformat(timespec="seconds")

REPO_A = make_scope("/synthetic/amberlight")
REPO_B = make_scope("/synthetic/gaugepost")
GLOBAL = make_scope(None)


def _msg(conn, role, text):
    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return append_event(conn, "claude_code", "message", uri=f"claude://t{n}",
                        content=text, meta={"role": role, "session_id": "s"})


# --- lifecycle ---------------------------------------------------------------

def test_add_list_close_reopen_roundtrip(isolated_contextd_home):
    conn = connect()
    r = add_loop(conn, "re-run the drift correction on the July batch",
                 REPO_A, source_events=[3, 1])
    assert r["result"] == "created"
    lp = r["loop"]
    assert lp["state"] == "open" and lp["created_authority"] == "operator"
    assert lp["source_events"] == [1, 3]

    assert [x["id"] for x in loops_for_scope(conn, REPO_A)] == [lp["id"]]
    assert loops_for_scope(conn, REPO_B) == []
    assert loops_for_scope(conn, GLOBAL) == []

    closed = transition(conn, lp["id"], "close",
                        reason="ran clean")
    assert closed["loop"]["state"] == "closed"
    assert closed["loop"]["last_reason"] == "ran clean"
    assert loops_for_scope(conn, REPO_A) == []

    reopened = transition(conn, lp["id"], "reopen",
                          reason="numbers drifted again")
    assert reopened["loop"]["state"] == "open"
    assert reopened["loop"]["reopen_count"] == 1
    assert [x["id"] for x in loops_for_scope(conn, REPO_A)] == [lp["id"]]


def test_duplicate_retry_and_repeated_wording_are_idempotent(
        isolated_contextd_home):
    conn = connect()
    first = add_loop(conn, "Fix the banner hash collision.", REPO_A)
    again = add_loop(conn, "fix   the banner hash collision", REPO_A)
    assert again["result"] == "existing"
    assert again["loop"]["id"] == first["loop"]["id"]
    n_events = conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind='loop'").fetchone()[0]
    assert n_events == 1, "idempotent retry must append nothing"

    # transitions retry as no-ops without new events
    transition(conn, first["loop"]["id"], "close")
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    r = transition(conn, first["loop"]["id"], "close")
    assert r["result"] == "noop"
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before

    # same wording after closure is a deliberate new declaration
    fresh = add_loop(conn, "fix the banner hash collision", REPO_A)
    assert fresh["result"] == "created"
    assert fresh["loop"]["id"] != first["loop"]["id"]


def test_invalid_transitions_refuse_explicitly(isolated_contextd_home):
    conn = connect()
    lp = add_loop(conn, "rotate the SMTP app password", GLOBAL)["loop"]
    cand = add_candidate(conn, "audit the sitemap generator", REPO_A)["loop"]
    with pytest.raises(LoopError, match="closed, not dismissed|closed"):
        transition(conn, lp["id"], "dismiss")
    with pytest.raises(LoopError, match="confirmed or dismissed"):
        transition(conn, cand["id"], "close")
    with pytest.raises(LoopError, match="confirmed or dismissed"):
        transition(conn, cand["id"], "reopen")
    transition(conn, lp["id"], "close")
    with pytest.raises(LoopError, match="reopen instead"):
        transition(conn, lp["id"], "confirm")
    with pytest.raises(LoopError, match="no loop"):
        transition(conn, 999999, "close")
    with pytest.raises(LoopError, match="unknown transition"):
        transition(conn, lp["id"], "explode")


def test_candidate_lifecycle_and_dismissal_suppression(isolated_contextd_home):
    conn = connect()
    c = add_candidate(conn, "add a dead-letter shelf", REPO_B,
                      client="loop-scan")
    lp = c["loop"]
    assert lp["state"] == "candidate" and lp["created_authority"] == "model"
    # candidates never appear in the active listing
    assert loops_for_scope(conn, REPO_B, states=("open",)) == []

    dup = add_candidate(conn, "add a DEAD-LETTER shelf", REPO_B)
    assert dup["result"] == "suppressed_live"

    d = transition(conn, lp["id"], "dismiss", reason="noise")
    assert d["loop"]["state"] == "dismissed"

    resurrect = add_candidate(conn, "add a dead-letter shelf", REPO_B)
    assert resurrect["result"] == "suppressed_dismissed"
    assert resurrect["loop"]["id"] == lp["id"]

    # a closed loop is likewise not re-proposed (stale resurrection)
    done = add_loop(conn, "regenerate the fixture site", REPO_B)["loop"]
    transition(conn, done["id"], "close")
    again = add_candidate(conn, "regenerate the fixture site", REPO_B)
    assert again["result"] == "suppressed_closed"

    # but a direct operator add overrides suppression with a fresh loop
    fresh = add_loop(conn, "add a dead-letter shelf", REPO_B)
    assert fresh["result"] == "created"
    assert fresh["loop"]["state"] == "open"


def test_operator_add_promotes_matching_candidate(isolated_contextd_home):
    conn = connect()
    cand = add_candidate(conn, "dedupe entries across feed aliases",
                         REPO_A)["loop"]
    r = add_loop(conn, "dedupe entries across feed aliases", REPO_A)
    assert r["result"] == "confirmed_candidate"
    assert r["loop"]["id"] == cand["id"]
    assert r["loop"]["state"] == "open"
    assert r["loop"]["promoted_authority"] == "operator"


def test_scope_separation_and_dedupe_is_per_scope(isolated_contextd_home):
    conn = connect()
    a = add_loop(conn, "re-run the parity replay", REPO_A)["loop"]
    b = add_loop(conn, "re-run the parity replay", REPO_B)["loop"]
    g = add_loop(conn, "re-run the parity replay", GLOBAL)["loop"]
    assert len({a["id"], b["id"], g["id"]}) == 3
    assert dedupe_key(REPO_A, "x") != dedupe_key(REPO_B, "x")
    assert [x["id"] for x in loops_for_scope(conn, REPO_A)] == [a["id"]]
    assert [x["id"] for x in loops_for_scope(conn, GLOBAL)] == [g["id"]]


def test_reducer_replay_is_deterministic_and_anomaly_safe(
        isolated_contextd_home):
    conn = connect()
    lp = add_loop(conn, "verify the redirect map", REPO_A)["loop"]
    transition(conn, lp["id"], "close")
    # a direct (same-owner) append of an invalid transition must not corrupt
    append_event(conn, "loop", "loop", content=None,
                 meta={"op": "reopen", "loop": lp["id"],
                       "authority": "operator"})
    append_event(conn, "loop", "loop", content=None,
                 meta={"op": "dismiss", "loop": lp["id"],
                       "authority": "operator"})
    append_event(conn, "loop", "loop", content=None,
                 meta={"op": "close", "loop": 424242,
                       "authority": "operator"})
    out = reduce_loops(conn)
    got = out["loops"][lp["id"]]
    assert got["state"] == "closed" and got["reopen_count"] == 0
    assert [a["why"] for a in got["anomalies"]] == [
        "reopen lacks a verified authorization",
        "dismiss lacks a verified authorization",
    ]
    assert out["orphans"][0]["why"].startswith("close targets unknown")
    # replay twice: byte-identical result (pure reduction)
    assert json.dumps(reduce_loops(conn), sort_keys=True) == \
        json.dumps(out, sort_keys=True)


def test_crash_mid_add_then_blind_retry_yields_one_loop(
        isolated_contextd_home):
    conn = connect()
    scope = REPO_A
    text = "audit the naive datetime handling"

    def signed_crash_append(value, fault):
        from contextd.attest import (
            consume_nonce,
            reverify_for_use,
            test_mode_authorization,
        )

        authorization = test_mode_authorization(
            conn, "loop.add", scope_str(scope), content=value
        )
        meta = {
            "op": "add",
            "scope": scope,
            "authority": "operator",
            "assurance": authorization.assurance,
            "attestation": authorization.stored_block(),
            "client": "cli",
            "dedupe": dedupe_key(scope, value),
        }

        def bind(locked_conn, _ts, event_id):
            verified = reverify_for_use(
                locked_conn,
                authorization,
                action="loop.add",
                scope=scope_str(scope),
                content=value,
            )
            consume_nonce(locked_conn, verified, event_id)

        return append_event_checked(
            conn,
            "loop",
            "loop",
            content=value,
            meta=meta,
            bind=bind,
            fault=fault,
        )

    def boom(phase):
        if phase == "before_db_commit":
            raise InjectedCrash(phase)

    with pytest.raises(InjectedCrash):
        signed_crash_append(text, boom)
    conn.close()  # abrupt death: uncommitted row rolls back

    conn = connect()  # recovery runs on connect
    r = add_loop(conn, text, scope)   # the blind retry
    assert r["result"] == "created"
    assert len(loops_for_scope(conn, scope)) == 1

    # crash AFTER durability: retry must dedupe, not duplicate
    def late_boom(phase):
        if phase == "before_witness_finalize":
            raise InjectedCrash(phase)
    text2 = "re-validate the February archive"
    with pytest.raises(InjectedCrash):
        signed_crash_append(text2, late_boom)
    conn.close()
    conn = connect()
    r2 = add_loop(conn, text2, scope)
    assert r2["result"] == "existing", "committed append must not duplicate"
    assert len(loops_for_scope(conn, scope)) == 2


def test_loop_events_carry_epistemic_type_by_authority(isolated_contextd_home):
    from contextd.experiment import epistemic_type
    assert epistemic_type("loop", "loop",
                          {"op": "add", "authority": "operator"}) == \
        "claimed_human_assertion"
    assert epistemic_type("loop", "loop",
                          {"op": "candidate", "authority": "model"}) == \
        "model_inference"
    assert epistemic_type("loop", "loop",
                          {"op": "confirm",
                           "authority": "operator_via_model"}) == \
        "model_inference"


def test_locked_dedupe_stops_a_racing_duplicate(isolated_contextd_home):
    """The dedupe re-check runs inside the witness/append lock: a writer
    that (like a racing process) skipped the courtesy pre-check still cannot
    fork a second live loop for the same key."""
    from contextd.loops import _DuplicateRace, _no_live_dup
    conn = connect()
    add_loop(conn, "re-run the parity replay", REPO_A)
    meta = {"op": "add", "scope": REPO_A, "authority": "operator",
            "client": "cli", "dedupe": dedupe_key(REPO_A,
                                                  "re-run the parity replay")}
    with pytest.raises(_DuplicateRace):
        append_event_checked(conn, "loop", "loop",
                             content="re-run the parity replay", meta=meta,
                             check=_no_live_dup(REPO_A,
                                                "re-run the parity replay"))
    assert len(loops_for_scope(conn, REPO_A)) == 1
    # the refused append left no event behind
    assert conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind='loop'").fetchone()[0] == 1


# --- model-mediated promotion is grant-gated, never inferred -----------------

def test_no_ungated_promotion_path_exists(isolated_contextd_home):
    """The retired utterance binding verified utterance-occurrence, not
    assent (a rejecting operator message satisfied it), so the relay was
    removed rather than shipped — that negative result stands. What exists
    since docs/GRANTS.md is a different mechanism with no inference in it:
    loop_confirm/loop_dismiss refuse without an explicit operator-recorded
    grant, and a candidate stays a candidate under ANY amount of
    post-candidate operator dialogue. add/close/reopen remain absent from
    the registry entirely. Granted promotion is permanently
    distinguishable: authority model-granted, never operator."""
    from contextd.grants import add_grant
    from contextd.mcp_server import TOOLS, loop_confirm
    assert not {"loop_add", "loop_close", "loop_reopen"} & set(TOOLS)
    assert {"loop_confirm", "loop_dismiss"} <= set(TOOLS)

    conn = connect()
    cand = add_candidate(conn, "add a dead-letter shelf", REPO_B)["loop"]
    _msg(conn, "user", "yes — the dead-letter shelf is on the board")
    _msg(conn, "user", "actually no, drop the dead-letter idea entirely")
    # dialogue is never assent: without a grant the model path refuses
    assert loop_confirm(cand["id"]).startswith("REFUSED")
    assert reduce_loops(conn)["loops"][cand["id"]]["state"] == "candidate"

    r = transition(conn, cand["id"], "confirm", client="cli")
    assert r["loop"]["state"] == "open"
    assert r["loop"]["promoted_authority"] == "operator"

    # under a grant, promotion works and is distinguishable from operator
    cand2 = add_candidate(conn, "shelve the retry respins", REPO_B)["loop"]
    add_grant(conn, "loop.confirm", REPO_B, expires=_soon())
    assert "model-granted" in loop_confirm(cand2["id"])
    assert reduce_loops(conn)["loops"][cand2["id"]][
        "promoted_authority"] == "model-granted"


def test_identical_dialogues_reduce_identically(isolated_contextd_home,
                                                tmp_path, monkeypatch):
    """Two archives with byte-identical dialogue: the kernel produces
    byte-identical loop state (a candidate in both, open in neither) —
    the record cannot express the private difference, so nothing here may
    pretend to."""
    states = []
    for name in ("wa", "wb"):
        monkeypatch.setenv("CONTEXTD_HOME", str(tmp_path / name))
        conn = connect()
        _msg(conn, "user", "the retry queue drains slower than it fills")
        _msg(conn, "assistant", "a dead-letter shelf would stop the respins "
                                "- I have not built it")
        _msg(conn, "user", "mm")
        add_candidate(conn, "add a dead-letter shelf for poisoned items",
                      REPO_B)
        reduced = reduce_loops(conn)["loops"]
        states.append(json.dumps(
            [{k: lp[k] for k in ("text", "state", "created_authority")}
             for lp in reduced.values()], sort_keys=True))
        assert all(lp["state"] == "candidate" for lp in reduced.values())
    assert states[0] == states[1]


# --- checkpoint carriage -----------------------------------------------------

def _noise(conn, n_notes=40, n_msgs=60):
    for i in range(n_notes):
        append_event(conn, "note", "note",
                     content=f"note {i}: unrelated decision about widget {i}",
                     meta={"actor": "human"})
    for i in range(n_msgs):
        _msg(conn, "user" if i % 2 else "assistant",
             f"unrelated dialogue about the widget refactor step {i}")


def test_carriage_survives_crowd_out_and_excludes_by_state_and_scope(
        isolated_contextd_home):
    conn = connect()
    cfg = load_config()
    kept = add_loop(conn, "re-run the drift correction on the July batch",
                    REPO_A)["loop"]
    closed = add_loop(conn, "regenerate the fixture site", REPO_A)["loop"]
    transition(conn, closed["id"], "close")
    dismissed = add_candidate(conn, "build a plugin registry", REPO_A)["loop"]
    transition(conn, dismissed["id"], "dismiss")
    cand = add_candidate(conn, "learn per-feed cadence", REPO_A)["loop"]
    other = add_loop(conn, "rotate the DKIM keys", REPO_B)["loop"]
    glob = add_loop(conn, "renew the archive backup medium", GLOBAL)["loop"]
    _noise(conn)  # 100 newer events between the loop and the cutoff

    out = compile_checkpoint(conn, cfg, budget=4000,
                             task_hint="widget refactor",
                             repo={"path": "/synthetic/amberlight",
                                   "branch": "x", "commit": "y", "log": ""})
    r = check_carriage(
        out["package"],
        expect_present=[kept["text"]],
        expect_absent=[closed["text"], dismissed["text"], cand["text"],
                       other["text"], glob["text"]])
    assert r["pass"], r["problems"]
    assert kept["id"] in out["items"]
    # every bracketed id in the package resolves to a disclosed item
    anchors = verify_anchors(out["package"], out["items"] + [out["tip"]])
    assert not anchors["invalid"]
    meta = json.loads(conn.execute(
        "SELECT meta FROM events WHERE id=?",
        (out["egress_id"],)).fetchone()["meta"])
    assert meta["loops_omitted"] == []
    assert meta["loop_scope"] == "/synthetic/amberlight", \
        "carriage must be scorable from the ledger alone (trial.py)"

    # reopened loops return; re-closed ones leave again
    transition(conn, closed["id"], "reopen")
    out2 = compile_checkpoint(conn, cfg, budget=4000,
                              repo={"path": "/synthetic/amberlight"})
    assert check_carriage(out2["package"],
                          [kept["text"], closed["text"]], [])["pass"]

    # the global checkpoint carries only global loops
    out3 = compile_checkpoint(conn, cfg, budget=4000)
    r3 = check_carriage(out3["package"], [glob["text"]],
                        [kept["text"], other["text"]])
    assert r3["pass"], r3["problems"]


def test_overflow_names_omitted_ids_and_count(isolated_contextd_home):
    conn = connect()
    cfg = load_config()
    ids = []
    for i in range(30):
        ids.append(add_loop(
            conn, f"verify invariant {i:02d} of the long-running migration "
                  f"against the archived copy", REPO_A)["loop"]["id"])
    sel = select_checkpoint_context(conn, cfg, budget=600,
                                    repo_path="/synthetic/amberlight")
    carried = [it["id"] for it in sel["loops"] if it["id"] is not None]
    omitted = sel["loops_omitted"]
    assert carried and omitted, "tiny budget must split the set"
    assert sorted(carried + omitted) == sorted(ids), "silent loss forbidden"
    assert carried == sorted(carried), "oldest-first"
    from contextd.handoff import render_package
    pkg = render_package(sel, tip=1)
    r = check_carriage(pkg, [], [], expect_omitted_ids=omitted)
    assert r["pass"], r["problems"]


def test_candidates_and_empty_scope_render_no_section(isolated_contextd_home):
    conn = connect()
    cfg = load_config()
    add_candidate(conn, "an unconfirmed idea", REPO_A)
    sel = select_checkpoint_context(conn, cfg, budget=4000,
                                    repo_path="/synthetic/amberlight")
    assert sel["loops"] == []
    from contextd.handoff import render_package
    assert "ACTIVE OPEN LOOPS" not in render_package(sel, tip=1)


def test_distilled_checkpoint_reattaches_section_verbatim(
        isolated_contextd_home, monkeypatch):
    import hooks.checkpoint_compile as ckpt
    conn = connect()
    cfg = load_config()
    lp = add_loop(conn, "re-run the parity replay before the cutover",
                  REPO_A)["loop"]
    note_id = append_event(conn, "note", "note",
                           content="decision: cadence learning is deferred",
                           meta={"actor": "human"})
    monkeypatch.setattr(
        ckpt, "distill",
        lambda payload, model, timeout=600, cfg=None:
        (f"OBJECTIVE: continue [{note_id}]\nNEXT: finish the cutover, then "
         f"the replay [{lp['id']}]", 0.0))
    out = ckpt.compile_distilled(conn, cfg, raw_budget=4000,
                                 repo={"path": "/synthetic/amberlight"})
    assert lp["id"] in out["items"]
    r = check_carriage(out["package"], [lp["text"]], [])
    assert r["pass"], r["problems"]
    assert out["package"].index("OBJECTIVE") < \
        out["package"].index("ACTIVE OPEN LOOPS")
