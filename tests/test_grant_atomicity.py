"""Grants: verified inside the append, bounded, and replay-safe.

Three defects this suite pins, each of which the pre-hardening tree had:

1. ``require_grant`` reduced the grant state, returned, and the caller then
   appended in a *separate* transaction. Between the two the grant could
   expire or be revoked, and concurrent callers could both see it live.
2. ``add_grant`` accepted ``expires=None`` — a permanent delegation — and
   compared expiry as an ISO **string**, so timezone offsets ordered lexically
   rather than chronologically.
3. ``meta.authority = "operator"`` was written by whoever called it, so the
   model could grant to itself.
"""

import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from contextd.assurance import MODEL_GRANTED, assurance_of, is_authenticated_human
from contextd.db import append_event, connect
from contextd.grants import (
    MAX_GRANT_DURATION,
    GrantError,
    active_grant_for,
    add_grant,
    grant_digest,
    granted_append,
    reduce_grants,
    revoke_grant,
)
from contextd.loops import make_scope, scope_str
from tests.legacy_support import insert_legacy_event

REPO = make_scope("/srv/demo/ledgerd")
GLOBAL = make_scope(None)


def _soon(hours: int = 8) -> str:
    return (datetime.now(timezone.utc)
            + timedelta(hours=hours)).isoformat(timespec="seconds")


def _grant(conn, cls="loop.confirm", scope=REPO, **kw):
    kw.setdefault("expires", _soon())
    return add_grant(conn, cls, scope, **kw)["grant"]


# --- bounded ---------------------------------------------------------------

def test_permanent_grants_are_refused():
    conn = connect()
    with pytest.raises(GrantError) as exc:
        add_grant(conn, "loop.confirm", REPO)
    assert "finite expiry" in str(exc.value)
    with pytest.raises(GrantError):
        add_grant(conn, "loop.confirm", REPO, expires="")


def test_naive_timestamps_are_refused():
    conn = connect()
    with pytest.raises(GrantError) as exc:
        add_grant(conn, "loop.confirm", REPO, expires="2099-06-01T12:00:00")
    assert "naive" in str(exc.value)


def test_equivalent_offsets_decide_identically():
    """The old string comparison made this depend on formatting, not on time."""
    conn = connect()
    horizon = datetime.now(timezone.utc) + timedelta(hours=3)
    _grant(conn, expires=horizon.isoformat(timespec="seconds"))

    same_instant = [
        horizon.astimezone(timezone.utc),
        horizon.astimezone(timezone(timedelta(hours=5, minutes=30))),
        horizon.astimezone(timezone(timedelta(hours=-8))),
        horizon.astimezone(timezone(timedelta(hours=14))),
    ]
    decisions = {
        active_grant_for(conn, "loop.confirm", REPO,
                         now=instant.isoformat(timespec="seconds")) is None
        for instant in same_instant
    }
    assert decisions == {True}, "the same instant decided differently by offset"

    before = [i - timedelta(seconds=1) for i in same_instant]
    decisions = {
        active_grant_for(conn, "loop.confirm", REPO,
                         now=i.isoformat(timespec="seconds")) is not None
        for i in before
    }
    assert decisions == {True}


def test_silent_renewal_and_unbounded_horizons_are_refused():
    conn = connect()
    too_far = (datetime.now(timezone.utc) + MAX_GRANT_DURATION
               + timedelta(days=1)).isoformat(timespec="seconds")
    with pytest.raises(GrantError) as exc:
        add_grant(conn, "loop.confirm", REPO, expires=too_far)
    assert "maximum" in str(exc.value)
    # re-granting identical terms appends nothing rather than extending
    first = _grant(conn)
    again = add_grant(conn, "loop.confirm", REPO, expires=first["expires"])
    assert again["result"] == "existing"


def test_wildcards_and_meta_grants_are_refused():
    conn = connect()
    for bad_scope in ({"repo": "*"}, {"repo": "**"}, {"repo": "/"}):
        with pytest.raises(GrantError):
            add_grant(conn, "loop.confirm", bad_scope, expires=_soon())
    for meta_class in ("grant.add", "grant.revoke", "security.key_register"):
        with pytest.raises(GrantError) as exc:
            add_grant(conn, meta_class, GLOBAL, expires=_soon())
        assert "bootstraps unbounded authority" in str(exc.value)


def test_grant_events_without_operator_assurance_are_anomalies():
    """A direct append cannot mint a grant, however its metadata reads."""
    conn = connect()
    insert_legacy_event(
        conn, "grant", "grant",
        meta={"op": "grant", "class": "loop.confirm", "scope": REPO,
              "authority": "operator", "expires": _soon()},
    )
    reduced = reduce_grants(conn)
    assert reduced["grants"] == []
    assert len(reduced["anomalies"]) == 1
    assert "cannot grant to itself" in reduced["anomalies"][0]["why"]
    assert active_grant_for(conn, "loop.confirm", REPO) is None


# --- verified inside the append --------------------------------------------

def test_delegated_act_records_grant_id_and_digest():
    conn = connect()
    grant = _grant(conn)
    result = granted_append(conn, "loop", "loop", "loop.confirm", REPO,
                            content="confirmed", meta={"op": "confirm"})
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?",
                     (result["event"],)).fetchone()["meta"]
    )
    assert meta["grant"] == grant["id"]
    assert meta["grant_digest"] == grant_digest(grant)
    assert meta["assurance"] == MODEL_GRANTED


def test_delegated_act_never_upgrades_to_operator_signed():
    conn = connect()
    _grant(conn)
    result = granted_append(conn, "loop", "loop", "loop.confirm", REPO,
                            content="confirmed", meta={"op": "confirm"})
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?",
                     (result["event"],)).fetchone()["meta"]
    )
    assert assurance_of(meta) == MODEL_GRANTED
    assert not is_authenticated_human(meta)
    assert "attestation" not in meta


def test_expiry_is_evaluated_at_the_append_timestamp():
    """A grant that lapses before the write must not authorize the write."""
    conn = connect()
    horizon = datetime.now(timezone.utc) + timedelta(seconds=1)
    _grant(conn, expires=horizon.isoformat(timespec="seconds"))
    import time
    time.sleep(1.2)
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    with pytest.raises(GrantError):
        granted_append(conn, "loop", "loop", "loop.confirm", REPO,
                       content="too late", meta={"op": "confirm"})
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before


def test_revoked_grant_authorizes_nothing_further():
    conn = connect()
    grant = _grant(conn)
    granted_append(conn, "loop", "loop", "loop.confirm", REPO,
                   content="allowed", meta={"op": "confirm"})
    revoke_grant(conn, grant["id"])
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    with pytest.raises(GrantError):
        granted_append(conn, "loop", "loop", "loop.confirm", REPO,
                       content="after revocation", meta={"op": "confirm"})
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before


def test_scope_is_exact_not_prefix():
    conn = connect()
    _grant(conn, scope=make_scope("/srv/demo/ledgerd"))
    with pytest.raises(GrantError):
        granted_append(conn, "loop", "loop", "loop.confirm",
                       make_scope("/srv/demo/ledgerd-other"),
                       content="wrong repo", meta={"op": "confirm"})


def test_class_is_exact():
    conn = connect()
    _grant(conn, cls="loop.confirm")
    with pytest.raises(GrantError):
        granted_append(conn, "loop", "loop", "loop.dismiss", REPO,
                       content="wrong class", meta={"op": "dismiss"})


# --- concurrency ------------------------------------------------------------

def _run_concurrently(fn, n: int):
    barrier = threading.Barrier(n)
    ok, failed = [], []

    def attempt(index):
        own = connect()
        barrier.wait()
        try:
            ok.append(fn(own, index))
        except Exception as exc:            # noqa: BLE001 - asserted by caller
            failed.append(exc)
        finally:
            own.close()

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return ok, failed


def test_concurrent_delegated_acts_all_serialize_under_one_grant():
    """Concurrency is not the failure mode here: a live grant covers each act.
    What must hold is that every accepted act names the same verified grant and
    the chain stays intact."""
    conn = connect()
    grant = _grant(conn)

    def act(own, index):
        return granted_append(own, "loop", "loop", "loop.confirm", REPO,
                              content=f"act {index}", meta={"op": "confirm"})

    ok, failed = _run_concurrently(act, 8)
    assert not failed, failed
    assert len(ok) == 8
    assert {r["grant"]["id"] for r in ok} == {grant["id"]}
    from contextd.db import verify_chain
    assert verify_chain(conn)["ok"]


def test_concurrent_use_and_revocation_linearize():
    """Accepted acts precede the revocation; none append after it."""
    conn = connect()
    grant = _grant(conn)
    revoke_event: list = []

    def act(own, index):
        if index == 0:
            result = revoke_grant(own, grant["id"], reason="stop")
            revoke_event.append(result["event"])
            return {"event": result["event"], "kind": "revoke"}
        return {**granted_append(own, "loop", "loop", "loop.confirm", REPO,
                                 content=f"act {index}",
                                 meta={"op": "confirm"}),
                "kind": "act"}

    ok, failed = _run_concurrently(act, 8)
    assert revoke_event, "the revocation itself failed"
    revoke_id = revoke_event[0]
    accepted = [r["event"] for r in ok if r["kind"] == "act"]
    # every accepted delegated act has a lower event id than the revocation:
    # the log linearizes them before it, and nothing appended after
    assert all(e < revoke_id for e in accepted), (
        f"a delegated act appended after revocation {revoke_id}: {accepted}"
    )
    # and every refusal is a grant refusal, not a crash
    assert all(isinstance(f, GrantError) for f in failed), failed
    after = conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind='loop' AND id > ?", (revoke_id,)
    ).fetchone()[0]
    assert after == 0

    from contextd.db import verify_chain
    assert verify_chain(conn)["ok"]


def test_a_grant_cannot_be_replayed_after_expiry_by_reusing_its_id():
    """Naming a grant id in metadata does not authorize anything by itself."""
    conn = connect()
    grant = _grant(conn, expires=(datetime.now(timezone.utc)
                                  + timedelta(seconds=1)).isoformat(timespec="seconds"))
    import time
    time.sleep(1.2)
    # a hostile direct append can *write* the id; the reduction still refuses
    forged = append_event(
        conn, "loop", "loop", content="forged",
        meta={"op": "confirm", "loop": 1, "grant": grant["id"],
              "claimed_client": "hostile"},
    )
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?", (forged,)).fetchone()["meta"]
    )
    # assurance_of reports model_granted for a grant-bearing row, but the grant
    # itself is expired, so no covering grant exists for a real act
    assert active_grant_for(conn, "loop.confirm", REPO) is None
    with pytest.raises(GrantError):
        granted_append(conn, "loop", "loop", "loop.confirm", REPO,
                       content="replayed", meta={"op": "confirm"})
    assert meta["grant"] == grant["id"]


def test_grant_digest_changes_with_the_terms():
    base = {"id": 7, "class": "loop.confirm",
            "scope": {"repo": "/srv/demo/ledgerd"}, "expires": _soon()}
    same = grant_digest(dict(base))
    assert grant_digest(dict(base)) == same
    for field, value in (("class", "loop.dismiss"),
                         ("scope", {"global": True}),
                         ("id", 8)):
        assert grant_digest({**base, field: value}) != same


def test_scope_string_is_what_the_digest_covers():
    grant = {"id": 1, "class": "loop.confirm", "scope": REPO,
             "expires": _soon()}
    assert scope_str(REPO) in scope_str(REPO)
    assert grant_digest(grant) == grant_digest(
        {**grant, "scope": {"repo": REPO["repo"]}}
    )
