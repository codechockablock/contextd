"""Commerce semantics: intent digests, three-state redemption, core refusals.

Four properties are pinned here, and each one fails against the pre-change
tree:

1. **The replay digest is not the action digest.** The signed action map is
   nonce-bound, so its digest differs on every retry by construction — that is
   what makes an authorization single-use. Replay detection needs the opposite
   property. There are therefore two digests under two domain separators, and
   the tests below assert that the intent-only one is stable across every
   envelope field and sensitive to every intent field.

2. **Redemption is three-state, not boolean.** unconsumed / replayed /
   in-flight, plus refusal. The in-flight state exists because the act happens
   outside the ledger: a process killed between the act and the outcome append
   leaves a result nobody knows, and the only honest answer is to say so.

3. **The core records its own refusals.** No test in this file ever appends a
   ``tx/refuse`` row, so every one it finds was written by contextd, inside the
   transaction that refused.

4. **A committed refusal does not look like tampering.** The recovery journal
   now enumerates every outcome an append may leave behind, so a crash between
   commit and witness-finalize resolves instead of raising the tamper alarm.
"""

import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, Lock

import pytest

from contextd import attest
from contextd.db import (
    ChainStateError,
    InjectedCrash,
    append_event,
    append_event_checked,
    chain_state_paths,
    connect,
    recover_chain_state,
    verify_chain,
)
from contextd.schemas import SchemaError
from tests.authorization_support import operator

ACT = "gate-proof commerce: transfer the one authorized amount"


def _refusals(conn):
    return [
        json.loads(row["meta"])
        for row in conn.execute(
            "SELECT meta FROM events WHERE source='tx' AND kind='refuse' "
            "ORDER BY id"
        )
    ]


def _kinds(conn):
    return [
        (row["source"], row["kind"])
        for row in conn.execute("SELECT source, kind FROM events ORDER BY id")
    ]


def _replay(conn, authorization):
    """The wire form a client would retry with, re-verified as a replay."""
    return attest.verify_replay(
        conn, dict(authorization.action), authorization.signature
    )


# --- E1: the intent digest is not, and cannot be, the action digest ---------

def test_two_independent_authorizations_for_one_act_share_an_intent_digest():
    """The property `prepare_action`'s digest structurally cannot have."""
    conn = connect()
    op = operator(conn)
    first = op.authorize("note.deliberate", "global", content=ACT)
    second = op.authorize("note.deliberate", "global", content=ACT)

    assert first.intent_digest == second.intent_digest
    # ...and the single-use digest still differs, which is the whole reason a
    # second digest had to exist. If this ever passes, single-use is broken.
    assert first.digest != second.digest
    assert first.nonce != second.nonce


def test_intent_digest_matches_the_digest_computed_from_the_act_alone():
    """A caller holding only the act — no authorization — gets the same value."""
    conn = connect()
    auth = operator(conn).authorize(
        "loop.add", "global", arguments={"loop": 7}, content=ACT, reason="why"
    )
    assert auth.intent_digest == attest.intent_digest(
        "loop.add", "global", arguments={"loop": 7}, content=ACT, reason="why"
    )


ENVELOPE_FIELDS = tuple(
    field for field in attest.ACTION_FIELDS if field not in attest.INTENT_FIELDS
)


def test_the_intent_digest_covers_intent_and_provably_excludes_the_envelope():
    """Enumerated over the real field list, not a hand-picked sample.

    ACTION_FIELDS is partitioned: every field is either intent (changing it
    must change the digest) or envelope (changing it must not). A field added
    to the action map later lands in one half or the other and is checked here
    automatically.
    """
    conn = connect()
    auth = operator(conn).authorize(
        "loop.add", "global", arguments={"loop": 1}, content=ACT, reason="r"
    )
    base = attest.action_intent_digest(auth.action)
    assert set(ENVELOPE_FIELDS) | set(attest.INTENT_FIELDS) == set(
        attest.ACTION_FIELDS
    )
    assert set(ENVELOPE_FIELDS) == {
        "domain", "version", "archive_uuid", "key_id", "nonce", "sequence",
        "issued_at", "expires_at",
    }

    mutations = {
        "domain": "contextd.SomethingElse",
        "version": 2,
        "archive_uuid": "f" * 32,
        "key_id": "a" * 64,
        "nonce": "b" * 64,
        "sequence": auth.action["sequence"] + 1000,
        "issued_at": auth.action["issued_at"] - 60,
        "expires_at": auth.action["expires_at"] + 60,
        "action": "loop.close",
        "scope": "repo:/tmp/elsewhere",
        "arguments": {"loop": 2},
        "content_digest": "c" * 64,
        "reason_digest": "d" * 64,
    }
    for field in ENVELOPE_FIELDS:
        moved = {**auth.action, field: mutations[field]}
        assert attest.action_intent_digest(moved) == base, field
    for field in attest.INTENT_FIELDS:
        moved = {**auth.action, field: mutations[field]}
        assert attest.action_intent_digest(moved) != base, field


def test_the_two_digests_use_different_domain_separators():
    """Same five fields under one separator would make them substitutable."""
    assert attest.INTENT_DOMAIN != attest.DOMAIN
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    assert auth.intent_digest != auth.digest


# --- the closed registry stays closed ---------------------------------------

def test_the_commerce_vocabulary_is_registered():
    from contextd.schemas import EVENT_SCHEMAS
    for pair in (
        ("mandate", "bind"), ("tx", "execute"), ("tx", "refuse"),
        ("tx", "inflight"),
    ):
        assert pair in EVENT_SCHEMAS, pair


def test_an_unregistered_commerce_type_still_refuses_metadata():
    """Adding four types must not open the registry."""
    conn = connect()
    with pytest.raises(SchemaError, match="no registered metadata schema"):
        append_event(conn, "tx", "settle", meta={"intent_digest": "a" * 64})
    with pytest.raises(SchemaError, match="no registered metadata schema"):
        append_event(conn, "mandate", "revoke", meta={"anything": 1})
    # ...and the same types are still appendable without metadata, so the
    # refusal is about the metadata channel, not about the label.
    assert append_event(conn, "tx", "settle", content="no meta") > 0


def test_a_registered_commerce_type_still_refuses_undeclared_fields():
    conn = connect()
    with pytest.raises(SchemaError, match="undeclared fields"):
        append_event(
            conn, "tx", "refuse",
            meta={"reason": "act_mismatch", "intent_digest": "a" * 64,
                  "stderr": "the widest channel there was"},
        )


def test_a_refusal_reason_outside_the_closed_set_is_refused():
    conn = connect()
    with pytest.raises(SchemaError, match="must be one of"):
        append_event(
            conn, "tx", "refuse",
            meta={"reason": "because I said so", "intent_digest": "a" * 64},
        )


# --- core-recorded refusal, with no caller cooperation ----------------------

def test_the_core_records_a_refusal_the_caller_never_appended():
    """The definition-of-done property, via the public API only."""
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content="the approved text")

    with pytest.raises(attest.ActMismatchError):
        attest.authorized_append(
            conn, "note", "note", auth, "note.deliberate", "global",
            content="a DIFFERENT text",
        )

    rows = _refusals(conn)
    assert len(rows) == 1
    assert rows[0]["reason"] == "act_mismatch"
    assert rows[0]["intent_digest"] == auth.intent_digest
    assert rows[0]["nonce"] == auth.nonce
    # the refused act never became durable
    assert _kinds(conn) == [("tx", "refuse")]
    assert verify_chain(conn)["ok"]


def test_a_refusal_row_never_carries_the_attestation_block():
    """A refused signature must not become durable as a live signed action."""
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content="a")
    with pytest.raises(attest.AttestationError):
        attest.authorized_append(
            conn, "note", "note", auth, "note.deliberate", "global", content="b",
        )
    meta = _refusals(conn)[0]
    assert "attestation" not in meta
    assert set(meta) <= {
        "reason", "intent_digest", "nonce", "key_id", "action", "scope",
        "mandate_event", "consumed_event",
    }


def test_a_second_redemption_is_refused_and_recorded_by_the_core():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content=ACT)
    attest.authorized_append(
        conn, "note", "note", auth, "note.deliberate", "global", content=ACT,
    )
    with pytest.raises(attest.AlreadyConsumedError):
        attest.authorized_append(
            conn, "note", "note", auth, "note.deliberate", "global", content=ACT,
        )
    assert [r["reason"] for r in _refusals(conn)] == ["already_consumed"]
    assert _kinds(conn) == [("note", "note"), ("tx", "refuse")]
    assert verify_chain(conn)["ok"]


def test_a_revoked_key_is_refused_and_recorded_as_unverifiable():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content=ACT)
    attest.revoke_key(op.key_id, conn=conn)
    with pytest.raises(attest.AttestationError):
        attest.authorized_append(
            conn, "note", "note", auth, "note.deliberate", "global", content=ACT,
        )
    assert [r["reason"] for r in _refusals(conn)] == ["unverifiable"]
    assert conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.nonce,),
    ).fetchone()["consumed_event"] is None
    assert verify_chain(conn)["ok"]


def test_exactly_one_of_the_act_and_the_refusal_is_durable():
    """The savepoint contract: the refused act leaves no partial effect."""
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content=ACT)
    attest.authorized_append(
        conn, "note", "note", auth, "note.deliberate", "global", content=ACT,
    )
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    with pytest.raises(attest.AttestationError):
        attest.authorized_append(
            conn, "note", "note", auth, "note.deliberate", "global", content=ACT,
        )
    after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert after == before + 1  # the refusal, and only the refusal
    ids = [r["id"] for r in conn.execute("SELECT id FROM events ORDER BY id")]
    assert ids == list(range(1, after + 1))  # no id was burned by the rollback
    assert verify_chain(conn)["ok"]


# --- three-state redemption -------------------------------------------------

def _redeem(conn, auth, calls, *, content=ACT, **kwargs):
    return attest.redeem(
        conn, auth, action="note.deliberate", scope="global", content=content,
        perform=lambda: calls.append(1) or {"transfer": "ok", "amount": 1200},
        **kwargs,
    )


def test_first_redemption_executes_and_records_the_outcome():
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    calls = []
    result = _redeem(conn, auth, calls)

    assert result.state == attest.REDEEM_EXECUTED
    assert result.outcome == {"transfer": "ok", "amount": 1200}
    assert calls == [1]
    assert _kinds(conn) == [("mandate", "bind"), ("tx", "execute")]
    assert verify_chain(conn)["ok"]


def test_replay_returns_the_stored_outcome_and_never_re_executes():
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    calls = []
    first = _redeem(conn, auth, calls)

    replayed = _redeem(conn, _replay(conn, auth), calls)

    assert replayed.state == attest.REDEEM_REPLAYED
    assert replayed.outcome == first.outcome
    assert replayed.outcome_event == first.outcome_event
    assert calls == [1], "the external act must run exactly once"
    # a replay is a lookup, not an append
    assert _kinds(conn) == [("mandate", "bind"), ("tx", "execute")]


def test_the_stored_outcome_is_the_result_itself_not_just_an_event_id():
    """Persisted, so a replay does not have to reconstruct anything."""
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    attest.redeem(
        conn, auth, action="note.deliberate", scope="global", content=ACT,
        perform=lambda: {"receipt": "R-99", "cents": 4200},
    )
    stored = conn.execute(
        "SELECT outcome FROM redemptions WHERE nonce = ?", (auth.nonce,)
    ).fetchone()["outcome"]
    assert json.loads(stored) == {"receipt": "R-99", "cents": 4200}
    # and the same bytes are chained into the ledger, not merely cached
    content = conn.execute(
        "SELECT content FROM events WHERE source='tx' AND kind='execute'"
    ).fetchone()["content"]
    assert json.loads(content) == {"receipt": "R-99", "cents": 4200}


def test_replay_with_a_different_act_is_refused_and_recorded():
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content=ACT)
    _redeem(conn, auth, [])

    with pytest.raises(attest.IntentMismatch):
        attest.redeem(
            conn, _replay(conn, auth), action="note.deliberate", scope="global",
            content="a completely different act",
            perform=lambda: pytest.fail("must not run"),
        )
    rows = _refusals(conn)
    assert [r["reason"] for r in rows] == ["intent_mismatch"]
    assert rows[0]["intent_digest"] == auth.intent_digest
    assert verify_chain(conn)["ok"]


def test_a_lapsed_replay_window_demands_re_authorization():
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    result = attest.redeem(
        conn, auth, action="note.deliberate", scope="global", content=ACT,
        perform=lambda: {"ok": True}, replay_ttl_seconds=1,
    )
    replay_until = conn.execute(
        "SELECT replay_until FROM redemptions WHERE nonce = ?", (auth.nonce,)
    ).fetchone()["replay_until"]

    with pytest.raises(attest.ReplayExpired):
        attest.redeem(
            conn, _replay(conn, auth), action="note.deliberate", scope="global",
            content=ACT, perform=lambda: pytest.fail("must not re-execute"),
            now=replay_until + 1,
        )

    assert [r["reason"] for r in _refusals(conn)] == ["replay_expired"]
    # The evidence is permanent; only the replayable result expired.
    assert conn.execute(
        "SELECT COUNT(*) FROM events WHERE id = ?", (result.outcome_event,)
    ).fetchone()[0] == 1
    assert json.loads(
        conn.execute(
            "SELECT outcome FROM redemptions WHERE nonce = ?", (auth.nonce,)
        ).fetchone()["outcome"]
    ) == {"ok": True}


def test_the_replay_ttl_is_configurable_and_bounded():
    conn = connect()
    op = operator(conn)
    short = op.authorize("note.deliberate", "global", content=ACT)
    attest.redeem(
        conn, short, action="note.deliberate", scope="global", content=ACT,
        perform=lambda: {"ok": True}, replay_ttl_seconds=60, now=1_000_000,
    )
    assert conn.execute(
        "SELECT replay_until FROM redemptions WHERE nonce = ?", (short.nonce,)
    ).fetchone()["replay_until"] == 1_000_060

    forever = op.authorize("note.deliberate", "global", content=ACT)
    with pytest.raises(attest.AttestationError, match="standing receipt"):
        attest.redeem(
            conn, forever, action="note.deliberate", scope="global", content=ACT,
            perform=lambda: {"ok": True},
            replay_ttl_seconds=attest.MAX_REPLAY_TTL_SECONDS + 1,
        )


def test_a_conclusively_failed_act_records_a_failed_receipt():
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)

    def perform():
        raise attest.ActFailed({"declined": "insufficient funds"})

    with pytest.raises(attest.ActFailed):
        attest.redeem(
            conn, auth, action="note.deliberate", scope="global", content=ACT,
            perform=perform,
        )
    meta = json.loads(
        conn.execute(
            "SELECT meta FROM events WHERE source='tx' AND kind='execute'"
        ).fetchone()["meta"]
    )
    assert meta["status"] == "failed"
    # ...and it is resolved, not in flight: a replay serves the failure receipt
    replayed = attest.redeem(
        conn, _replay(conn, auth), action="note.deliberate", scope="global",
        content=ACT, perform=lambda: pytest.fail("must not re-execute"),
    )
    assert replayed.state == attest.REDEEM_REPLAYED
    assert replayed.outcome == {"declined": "insufficient funds"}


def test_an_unknown_failure_leaves_the_mandate_in_flight():
    """A timeout is not evidence that nothing happened."""
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)

    def perform():
        raise TimeoutError("the payment network stopped answering")

    with pytest.raises(TimeoutError):
        attest.redeem(
            conn, auth, action="note.deliberate", scope="global", content=ACT,
            perform=perform,
        )
    resolved = attest.redeem(
        conn, _replay(conn, auth), action="note.deliberate", scope="global",
        content=ACT, perform=lambda: pytest.fail("must not re-execute"),
    )
    assert resolved.state == attest.REDEEM_INFLIGHT
    assert resolved.outcome is None


def test_a_consumed_nonce_with_no_mandate_is_refused_not_replayed():
    """A plain authorized_append is not a redemption and has no receipt.

    The authorization was spent, but by something that recorded no mandate, so
    there is nothing to serve. The core refuses it as already-consumed and
    writes that refusal — it does not invent a receipt, and it does not let the
    act run a second time.
    """
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    attest.authorized_append(
        conn, "note", "note", auth, "note.deliberate", "global", content=ACT,
    )
    with pytest.raises(attest.AlreadyConsumedError):
        attest.redeem(
            conn, _replay(conn, auth), action="note.deliberate", scope="global",
            content=ACT, perform=lambda: pytest.fail("must not run"),
        )
    assert [r["reason"] for r in _refusals(conn)] == ["already_consumed"]
    assert not conn.execute("SELECT 1 FROM redemptions").fetchone()


def test_replay_verification_cannot_be_used_to_spend():
    """The credential a replay returns must never reach a fresh append."""
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    _redeem(conn, auth, [])
    receipt_credential = _replay(conn, auth)
    with pytest.raises(attest.AlreadyConsumedError):
        attest.authorized_append(
            conn, "note", "note", receipt_credential, "note.deliberate",
            "global", content=ACT,
        )


def test_an_unredeemed_authorization_has_no_receipt_to_replay():
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    with pytest.raises(attest.AttestationError, match="never been redeemed"):
        _replay(conn, auth)


def test_an_oversized_outcome_is_refused_rather_than_stored():
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    with pytest.raises(attest.AttestationError, match="exceeds its bound"):
        attest.redeem(
            conn, auth, action="note.deliberate", scope="global", content=ACT,
            perform=lambda: {"blob": "x" * (attest.MAX_OUTCOME_CHARS + 1)},
        )
    # the mandate is bound and the act ran, so this is honestly in flight
    assert conn.execute(
        "SELECT state FROM redemptions WHERE nonce = ?", (auth.nonce,)
    ).fetchone()["state"] == "inflight"


# --- crash consistency ------------------------------------------------------

@pytest.mark.parametrize(
    "phase", ["before_db_commit", "after_db_commit", "before_witness_finalize"]
)
def test_a_crash_between_the_act_and_the_outcome_resolves_to_in_flight(phase):
    """The state must be in-flight — not a phantom success, not a re-run.

    The worker is killed inside the *outcome* append — after the external act
    has taken effect — at each of the three phases tests/test_crash_recovery.py
    uses for abrupt process death, via the same explicit ``fault`` hook. The
    archive is then reopened on a fresh connection and asked, through the public
    API, what happened. Nothing about the mandate is reconstructed by the test.

    ``before_db_commit`` is the case the requirement names: the act happened out
    in the world and no record of its outcome survived. The two post-commit
    phases are included because they must NOT resolve to in-flight — the outcome
    did commit, so recovery has to finish it, and a replay must serve it.
    """
    archive = os.environ["CONTEXTD_HOME"]
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    performed = []

    def perform():
        performed.append("the external act took effect out in the world")
        return {"transfer": "ok"}

    def crash(here):
        # Only after the act has run: this targets the outcome append, never
        # the bind that precedes it.
        if performed and here == phase:
            raise InjectedCrash(here)

    with pytest.raises(InjectedCrash):
        attest.redeem(
            conn, auth, action="note.deliberate", scope="global",
            content=ACT, perform=perform, fault=crash,
        )
    conn.close()  # abrupt death: an uncommitted row rolls back

    assert performed, "the act must actually have run before the crash"

    assert os.environ["CONTEXTD_HOME"] == archive
    recovered = connect()
    recover_chain_state(recovered)
    assert verify_chain(recovered)["ok"]

    if phase != "before_db_commit":
        # The outcome was durable before the kill. Recovery must complete it,
        # and the replay must serve the real receipt.
        settled = attest.redeem(
            recovered, _replay(recovered, auth), action="note.deliberate",
            scope="global", content=ACT,
            perform=lambda: pytest.fail("must never re-execute"),
        )
        assert settled.state == attest.REDEEM_REPLAYED
        assert settled.outcome == {"transfer": "ok"}
        assert len(performed) == 1
        return

    state = attest.redeem(
        recovered, _replay(recovered, auth), action="note.deliberate",
        scope="global", content=ACT,
        perform=lambda: pytest.fail("a crashed mandate must never re-execute"),
    )
    assert state.state == attest.REDEEM_INFLIGHT
    assert state.outcome is None
    # no phantom success is anywhere in the ledger
    assert not recovered.execute(
        "SELECT 1 FROM events WHERE source='tx' AND kind='execute'"
    ).fetchone()
    # and the observation itself is durable, written by the core
    assert state.inflight_event is not None
    assert recovered.execute(
        "SELECT COUNT(*) FROM events WHERE source='tx' AND kind='inflight'"
    ).fetchone()[0] == 1


@pytest.mark.parametrize("phase", ["before_db_commit", "before_witness_finalize"])
def test_a_crash_during_the_bind_is_all_or_nothing(phase):
    """The complement: if the mandate never bound, the act never ran.

    A crash inside the bind must leave either a fully bound mandate or nothing
    at all. It must never leave a spent authorization with no mandate, because
    the replay path would then have no receipt to serve and the operator would
    have to re-authorize an act that may already have happened.
    """
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    performed = []

    def crash(here):
        if here == phase:
            raise InjectedCrash(here)

    with pytest.raises(InjectedCrash):
        attest.redeem(
            conn, auth, action="note.deliberate", scope="global", content=ACT,
            perform=lambda: performed.append(1) or {"transfer": "ok"},
            fault=crash,
        )
    conn.close()

    assert performed == [], "perform must not run until the mandate is durable"

    recovered = connect()
    assert verify_chain(recovered)["ok"]
    consumed = recovered.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.nonce,),
    ).fetchone()["consumed_event"]
    bound = recovered.execute(
        "SELECT COUNT(*) FROM redemptions WHERE nonce = ?", (auth.nonce,)
    ).fetchone()[0]
    # Spent-and-bound, or neither. Never spent-and-unbound.
    assert (consumed is None) == (bound == 0), (consumed, bound)

    if consumed is None:
        # Rolled back: the authorization is still live and redeems normally.
        fresh = attest.verify_action(
            dict(auth.action), auth.signature, conn=recovered
        )
        result = attest.redeem(
            recovered, fresh, action="note.deliberate", scope="global",
            content=ACT, perform=lambda: performed.append(1) or {"t": "ok"},
        )
        assert result.state == attest.REDEEM_EXECUTED
        assert performed == [1]
    else:
        # Committed: the mandate is bound and unresolved, which is in-flight.
        state = attest.redeem(
            recovered, _replay(recovered, auth), action="note.deliberate",
            scope="global", content=ACT,
            perform=lambda: pytest.fail("must never re-execute"),
        )
        assert state.state == attest.REDEEM_INFLIGHT
    assert verify_chain(recovered)["ok"]


def test_the_in_flight_observation_is_recorded_at_most_once():
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)

    def perform():
        raise TimeoutError("no answer")

    with pytest.raises(TimeoutError):
        attest.redeem(
            conn, auth, action="note.deliberate", scope="global", content=ACT,
            perform=perform,
        )
    seen = [
        attest.redeem(
            conn, _replay(conn, auth), action="note.deliberate", scope="global",
            content=ACT, perform=lambda: pytest.fail("no"),
        ).inflight_event
        for _ in range(4)
    ]
    assert len(set(seen)) == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM events WHERE source='tx' AND kind='inflight'"
    ).fetchone()[0] == 1


# --- concurrency ------------------------------------------------------------

def test_sixteen_racing_redeemers_perform_the_act_exactly_once():
    """The invariant the whole design exists for, under contention.

    Sixteen barrier-synchronized workers redeem one authorization. Exactly one
    may bind the mandate and run the external act; every other one must be told
    either "in flight" (the winner had not finished yet) or "replayed" with the
    winner's own outcome. What must never happen is a second execution, a
    second mandate, or a refusal — a concurrent retry of the *same* act is
    benign, and treating it as an attack would be as wrong as double-spending.

    Measured caveat, so this test is not read as proving more than it does: with
    an instantaneous ``perform`` the winner finishes before any loser gets to
    read, so over 160 observed worker outcomes the split was 10 executed / 150
    replayed and the in-flight branch was never reached here. The next test
    reaches it deliberately.
    """
    connect().close()
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    action, signature = dict(auth.action), auth.signature
    conn.close()

    barrier = Barrier(16)
    performed = []
    lock = Lock()

    def perform():
        with lock:
            performed.append(1)
        return {"transfer": "ok", "amount": 1200}

    def worker(_i):
        worker_conn = connect()
        try:
            barrier.wait(timeout=60)
            try:
                credential = attest.verify_action(
                    action, signature, conn=worker_conn
                )
            except attest.AlreadyConsumedError:
                credential = attest.verify_replay(worker_conn, action, signature)
            return attest.redeem(
                worker_conn, credential, action="note.deliberate",
                scope="global", content=ACT, perform=perform,
            ).state
        finally:
            worker_conn.close()

    with ThreadPoolExecutor(max_workers=16) as pool:
        states = list(pool.map(worker, range(16)))

    assert len(performed) == 1, (performed, states)
    assert states.count(attest.REDEEM_EXECUTED) == 1, states
    assert set(states) <= {
        attest.REDEEM_EXECUTED, attest.REDEEM_REPLAYED, attest.REDEEM_INFLIGHT
    }, states

    final = connect()
    assert final.execute("SELECT COUNT(*) FROM redemptions").fetchone()[0] == 1
    assert final.execute(
        "SELECT COUNT(*) FROM events WHERE source='mandate' AND kind='bind'"
    ).fetchone()[0] == 1
    assert final.execute(
        "SELECT COUNT(*) FROM events WHERE source='tx' AND kind='execute'"
    ).fetchone()[0] == 1
    assert final.execute(
        "SELECT COUNT(*) FROM events WHERE source='tx' AND kind='refuse'"
    ).fetchone()[0] == 0, "a concurrent retry of the same act is not a refusal"
    assert final.execute(
        "SELECT COUNT(*) FROM events WHERE source='tx' AND kind='inflight'"
    ).fetchone()[0] <= 1
    assert verify_chain(final)["ok"]

    # Every straggler now replays the winner's outcome, byte for byte.
    replayed = attest.redeem(
        final, attest.verify_replay(final, action, signature),
        action="note.deliberate", scope="global", content=ACT,
        perform=lambda: pytest.fail("must not re-execute"),
    )
    assert replayed.state == attest.REDEEM_REPLAYED
    assert replayed.outcome == {"transfer": "ok", "amount": 1200}
    assert len(performed) == 1


def test_a_concurrent_reader_sees_in_flight_while_the_act_is_still_running():
    """The in-flight branch under contention, reached deterministically.

    The winner is held inside ``perform`` — i.e. the external act is genuinely
    mid-flight — until every other worker has observed the mandate. Those
    observers must be told in-flight: the outcome is not knowable yet, and
    neither a phantom success nor a re-execution is acceptable. No sleeps; the
    winner is released by the observers themselves.
    """
    connect().close()
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    action, signature = dict(auth.action), auth.signature
    conn.close()

    workers = 8
    barrier = Barrier(workers)
    release = Event()
    lock = Lock()
    performed, observers = [], []

    def perform():
        with lock:
            performed.append(1)
        # Held here, mid-act, until everyone else has looked at the mandate.
        assert release.wait(timeout=60), "observers never reported"
        return {"transfer": "ok"}

    def worker(_i):
        worker_conn = connect()
        try:
            barrier.wait(timeout=60)
            try:
                credential = attest.verify_action(
                    action, signature, conn=worker_conn
                )
            except attest.AlreadyConsumedError:
                credential = attest.verify_replay(worker_conn, action, signature)
            state = attest.redeem(
                worker_conn, credential, action="note.deliberate",
                scope="global", content=ACT, perform=perform,
            ).state
            if state != attest.REDEEM_EXECUTED:
                with lock:
                    observers.append(state)
                    if len(observers) == workers - 1:
                        release.set()
            return state
        finally:
            worker_conn.close()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        states = list(pool.map(worker, range(workers)))

    assert len(performed) == 1, performed
    assert states.count(attest.REDEEM_EXECUTED) == 1, states
    assert set(observers) == {attest.REDEEM_INFLIGHT}, observers

    final = connect()
    assert final.execute(
        "SELECT COUNT(*) FROM events WHERE source='tx' AND kind='execute'"
    ).fetchone()[0] == 1
    # observed-unresolved is recorded once, however many workers observed it
    assert final.execute(
        "SELECT COUNT(*) FROM events WHERE source='tx' AND kind='inflight'"
    ).fetchone()[0] == 1
    assert final.execute(
        "SELECT COUNT(*) FROM events WHERE source='tx' AND kind='refuse'"
    ).fetchone()[0] == 0
    assert verify_chain(final)["ok"]


def test_sixteen_racing_appenders_yield_one_act_and_fifteen_core_refusals():
    """The frozen demo's property, but with the refusals written by the core."""
    connect().close()
    conn = connect()
    auth = operator(conn).authorize("note.deliberate", "global", content=ACT)
    action, signature = dict(auth.action), auth.signature
    conn.close()

    barrier = Barrier(16)

    def worker(_i):
        worker_conn = connect()
        try:
            try:
                credential = attest.verify_action(
                    action, signature, conn=worker_conn
                )
            except attest.AttestationError:
                credential = None
            barrier.wait(timeout=60)
            if credential is None:
                return "preflight"
            try:
                attest.authorized_append(
                    worker_conn, "note", "note", credential, "note.deliberate",
                    "global", content=ACT,
                )
                return "appended"
            except attest.AttestationError:
                return "refused"
        finally:
            worker_conn.close()

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(worker, range(16)))

    assert outcomes.count("appended") == 1, outcomes
    assert outcomes.count("preflight") == 0, outcomes

    final = connect()
    assert final.execute(
        "SELECT COUNT(*) FROM events WHERE source='note' AND kind='note'"
    ).fetchone()[0] == 1
    refusals = _refusals(final)
    assert len(refusals) == 15, len(refusals)
    assert {r["reason"] for r in refusals} == {"already_consumed"}
    assert {r["intent_digest"] for r in refusals} == {auth.intent_digest}
    assert verify_chain(final)["ok"]


# --- E2: a committed refusal is not a tamper alarm --------------------------

@pytest.mark.parametrize("phase", ["after_db_commit", "before_witness_finalize"])
def test_a_refusal_committed_under_an_interrupted_append_recovers(phase):
    """The E2 regression, directly.

    Under the v1 journal this crash left a database tip matching neither
    ``previous`` nor ``target`` — because the committed bytes were the
    refusal's, not the act's — and the next open reported the whole ledger as
    tampered with.
    """
    conn = connect()
    op = operator(conn)
    auth = op.authorize("note.deliberate", "global", content=ACT)
    attest.authorized_append(
        conn, "note", "note", auth, "note.deliberate", "global", content=ACT,
    )

    from contextd.db import Refusal, append_event_checked

    def refusing_bind(_conn, _ts, _eid):
        raise Refusal("already_consumed", attest.AlreadyConsumedError("spent"))

    def crash(here):
        if here == phase:
            raise InjectedCrash(here)

    with pytest.raises(InjectedCrash):
        append_event_checked(
            conn, "note", "note", content="the act that lost the race",
            meta={"assurance": auth.assurance,
                  "attestation": auth.stored_block()},
            bind=refusing_bind, fault=crash,
            refusals=attest.declared_refusals(auth),
        )
    conn.close()

    recovered = connect()  # this call raised ChainStateError before the fix
    result = verify_chain(recovered)
    assert result["ok"], result
    rows = _refusals(recovered)
    assert [r["reason"] for r in rows] == ["already_consumed"]
    assert _kinds(recovered) == [("note", "note"), ("tx", "refuse")]
    # the archive is still writable and the chain still extends
    assert append_event(recovered, "test", "note", content="after") == 3
    assert verify_chain(recovered)["ok"]


def test_a_tip_outside_the_enumerated_outcomes_is_still_a_tamper_alarm():
    """The generalization must not have disarmed the check it generalized."""
    conn = connect()
    append_event(conn, "test", "note", content="one")
    paths = chain_state_paths()
    previous = json.loads(paths["witness"].read_text())

    # A journal that permits exactly one outcome, and a database that committed
    # a different event than any it named.
    append_event(conn, "test", "note", content="two")
    paths["recovery"].write_text(json.dumps({
        "version": 2,
        "previous": {"id": previous["id"], "chain_hash": previous["chain_hash"]},
        "outcomes": [{"id": 2, "chain_hash": "0" * 64}],
    }))
    paths["witness"].write_text(json.dumps({
        "version": 2, "id": previous["id"],
        "chain_hash": previous["chain_hash"],
    }))
    conn.close()

    with pytest.raises(ChainStateError, match="matches neither side"):
        connect()


def test_a_v1_recovery_journal_left_by_an_older_process_is_still_honoured():
    """An older build's journal must not become an unopenable archive."""
    conn = connect()
    append_event(conn, "test", "note", content="one")
    witness = json.loads(chain_state_paths()["witness"].read_text())

    def crash(here):
        if here == "after_db_commit":
            raise InjectedCrash(here)

    with pytest.raises(InjectedCrash):
        append_event_checked(conn, "test", "note", content="two", fault=crash)
    conn.close()

    committed = json.loads(
        json.dumps({"id": 2, "chain_hash": _tip_hash()})
    )
    chain_state_paths()["recovery"].write_text(json.dumps({
        "version": 1,
        "previous": {"id": witness["id"], "chain_hash": witness["chain_hash"]},
        "target": committed,
    }))

    recovered = connect()
    assert verify_chain(recovered)["ok"]
    assert recovered.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2
    assert json.loads(
        chain_state_paths()["witness"].read_text()
    )["version"] == 2


def _tip_hash() -> str:
    path = os.path.join(os.environ["CONTEXTD_HOME"], "contextd.db")
    probe = sqlite3.connect(path)
    try:
        return probe.execute(
            "SELECT chain_hash FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    finally:
        probe.close()


def test_a_v1_witness_is_restamped_without_moving_the_tip():
    conn = connect()
    append_event(conn, "test", "note", content="one")
    paths = chain_state_paths()
    current = json.loads(paths["witness"].read_text())
    paths["witness"].write_text(json.dumps({
        "version": 1, "id": current["id"], "chain_hash": current["chain_hash"],
    }))
    conn.close()

    reopened = connect()
    restamped = json.loads(paths["witness"].read_text())
    assert restamped["version"] == 2
    assert (restamped["id"], restamped["chain_hash"]) == (
        current["id"], current["chain_hash"]
    )
    assert verify_chain(reopened)["ok"]
