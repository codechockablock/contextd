"""A forged derivation environment value has no authority.

The defect this suite pins: ``CONTEXTD_DERIVATION_SOURCE=<egress_id>`` was an
enumerable integer in an environment variable owned by the very process it was
supposed to constrain. Guessing a number, or overwriting the variable with a
disclosure that had a larger item list, bought lineage the process had not
earned — and nothing expired or was consumed, so one value worked forever.
"""

import json
import os
import threading
import time

import pytest

from contextd import load_config
from contextd.capability import (
    ALLOWED_WRITES,
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    CapabilityError,
    consume,
    digest,
    issue,
    mark_dispatched,
    parse_token,
    token,
    verify,
)
from contextd.db import append_event, connect
from contextd.gate import disclose
from contextd.ingest import ingest_note
from contextd.mcp_server import note

SESSION = "dispatch-session-1"


def _disclosure(conn, count: int = 2):
    cfg = load_config()
    ids = [
        append_event(conn, "claude_code", "message", content=f"line {i}",
                     meta={"role": "user", "session_id": "s"})
        for i in range(count)
    ]
    payload = "\n\n".join(
        f"--- [{i}] 2026-01-01T00:00:00+00:00 claude_code/message  ---\nline"
        for i in ids)
    egress = disclose(conn, cfg, payload,
                      {"type": "reconcile_dialogue", "items": ids})["egress_id"]
    return ids, egress


def _issue(conn, egress, **kw):
    kw.setdefault("principal_uid", os.getuid())
    kw.setdefault("dispatcher", SESSION)
    return issue(conn, egress, **kw)


def _bind(monkeypatch, cap, session=SESSION):
    monkeypatch.setenv("CONTEXTD_DISPATCH_CAPABILITY", token(cap))
    monkeypatch.setenv("CONTEXTD_DISPATCH_SESSION", session)
    monkeypatch.delenv("CONTEXTD_DERIVATION_SOURCE", raising=False)


# --- the retired binding ----------------------------------------------------

def test_forged_derivation_environment_value_has_no_authority(monkeypatch):
    conn = connect()
    _ids, egress = _disclosure(conn)
    monkeypatch.setenv("CONTEXTD_DERIVATION_SOURCE", str(egress))
    reply = note("a note claiming lineage it did not earn")
    assert reply.startswith("REFUSED:")
    assert "retired" in reply and "carries no authority" in reply


def test_guessing_an_event_id_buys_nothing(monkeypatch):
    """The whole enumeration attack, and it now gets nowhere."""
    conn = connect()
    _ids, egress = _disclosure(conn)
    for guess in range(1, egress + 5):
        monkeypatch.setenv("CONTEXTD_DERIVATION_SOURCE", str(guess))
        assert note(f"guessing {guess}").startswith("REFUSED:")


def test_a_capability_token_is_opaque():
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    raw = token(cap)
    assert str(egress) != raw
    capability_id, secret = parse_token(raw)
    assert len(capability_id) == 64 and len(secret) == 64
    int(capability_id, 16)                  # random hex, not a structure
    int(secret, 16)
    # the stored row keeps only a hash of the secret
    row = conn.execute(
        "SELECT secret_hash FROM dispatch_capabilities WHERE capability_id = ?",
        (capability_id,)).fetchone()
    assert row["secret_hash"] != secret


def test_malformed_tokens_are_refused():
    for raw in ("", "garbage", "a.b", "x" * 129, "1" * 64, f"{'a'*64}.{'b'*63}",
                None, 12345):
        with pytest.raises(CapabilityError):
            parse_token(raw)


# --- every binding is checked ----------------------------------------------

def test_wrong_principal_refuses():
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    with pytest.raises(CapabilityError) as exc:
        verify(conn, cap["capability_id"], cap["secret"],
               principal_uid=os.getuid() + 1, dispatcher=SESSION,
               write=("note", "note"))
    assert "different principal" in str(exc.value)


def test_wrong_session_refuses():
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    with pytest.raises(CapabilityError) as exc:
        verify(conn, cap["capability_id"], cap["secret"],
               principal_uid=os.getuid(), dispatcher="a-different-session",
               write=("note", "note"))
    assert "different dispatch session" in str(exc.value)


def test_wrong_write_refuses():
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    with pytest.raises(CapabilityError) as exc:
        verify(conn, cap["capability_id"], cap["secret"],
               principal_uid=os.getuid(), dispatcher=SESSION,
               write=("loop", "loop"))
    assert "permits note/note" in str(exc.value)


def test_wrong_secret_refuses():
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    with pytest.raises(CapabilityError):
        verify(conn, cap["capability_id"], "f" * 64, os.getuid(), SESSION,
               ("note", "note"))


def test_unknown_capability_refuses():
    conn = connect()
    with pytest.raises(CapabilityError) as exc:
        verify(conn, "a" * 64, "b" * 64, os.getuid(), SESSION, ("note", "note"))
    assert "cannot be constructed by a client" in str(exc.value)


def test_wrong_archive_refuses(tmp_path, monkeypatch):
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    monkeypatch.setenv("CONTEXTD_HOME", str(tmp_path / "other"))
    other = connect()
    # the capability row does not exist in the other archive at all, and even
    # transplanted it carries the first archive's uuid
    with pytest.raises(CapabilityError):
        verify(other, cap["capability_id"], cap["secret"], os.getuid(),
               SESSION, ("note", "note"))


def test_expired_capability_refuses():
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress, ttl_seconds=1)
    time.sleep(1.2)
    with pytest.raises(CapabilityError) as exc:
        verify(conn, cap["capability_id"], cap["secret"], os.getuid(),
               SESSION, ("note", "note"))
    assert "expired" in str(exc.value)


def test_unbounded_ttl_is_refused():
    conn = connect()
    _ids, egress = _disclosure(conn)
    for bad in (0, -1, MAX_TTL_SECONDS + 1):
        with pytest.raises(CapabilityError) as exc:
            _issue(conn, egress, ttl_seconds=bad)
        assert "ambient permission" in str(exc.value) or "ttl" in str(exc.value)


def test_failed_dispatch_invalidates_the_capability():
    """The model never saw the bytes, so nothing it writes derives from them."""
    conn = connect()
    _ids, egress = _disclosure(conn)
    for state in ("failed", "timeout"):
        cap = _issue(conn, egress)
        mark_dispatched(conn, cap["capability_id"], state)
        with pytest.raises(CapabilityError) as exc:
            verify(conn, cap["capability_id"], cap["secret"], os.getuid(),
                   SESSION, ("note", "note"))
        assert state in str(exc.value)


def test_capability_cannot_authorize_an_authority_bearing_write():
    conn = connect()
    _ids, egress = _disclosure(conn)
    assert ("grant", "grant") not in ALLOWED_WRITES
    assert ("decision", "decision") not in ALLOWED_WRITES
    for write in (("grant", "grant"), ("decision", "decision"),
                  ("gate", "egress")):
        with pytest.raises(CapabilityError) as exc:
            _issue(conn, egress, write=write)
        assert "authority-bearing" in str(exc.value)


def test_capability_cannot_be_issued_against_a_non_disclosure():
    conn = connect()
    plain = ingest_note(conn, "not an egress")
    with pytest.raises(CapabilityError):
        _issue(conn, plain)
    with pytest.raises(CapabilityError):
        _issue(conn, 999999)


def test_capability_is_bound_to_the_exact_disclosed_bytes():
    """A later disclosure reusing the id cannot inherit the capability."""
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    verify(conn, cap["capability_id"], cap["secret"], os.getuid(), SESSION,
           ("note", "note"))
    # rewrite the bound disclosure's content the way a tampering process would
    conn.execute("DROP TRIGGER events_no_update")
    conn.execute("UPDATE events SET content = ? WHERE id = ?",
                 ("substituted bytes", egress))
    conn.commit()
    with pytest.raises(CapabilityError) as exc:
        verify(conn, cap["capability_id"], cap["secret"], os.getuid(),
               SESSION, ("note", "note"))
    assert "bytes have changed" in str(exc.value)


# --- single use, atomically -------------------------------------------------

def test_replayed_capability_refuses(monkeypatch):
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    _bind(monkeypatch, cap)
    first = note("the first note")
    assert first.startswith("noted as event #")
    second = note("the second note")
    assert second.startswith("REFUSED:")
    assert "already consumed" in second


def test_consumption_is_atomic_with_the_append(monkeypatch):
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    _bind(monkeypatch, cap)
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    note("a bound note")
    after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    row = conn.execute(
        "SELECT consumed_event FROM dispatch_capabilities WHERE capability_id=?",
        (cap["capability_id"],)).fetchone()
    assert after == before + 1
    assert row["consumed_event"] is not None
    # the consumed event is exactly the note that was appended
    stored = conn.execute("SELECT meta FROM events WHERE id = ?",
                          (row["consumed_event"],)).fetchone()
    assert json.loads(stored["meta"])["derivation"]["source_egress"] == egress


def test_concurrent_use_of_one_capability_yields_exactly_one_write():
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    ok, refused = [], []
    barrier = threading.Barrier(6)

    def attempt(index):
        own = connect()
        barrier.wait()
        try:
            eid = append_event(own, "note", "note", content=f"racer {index}",
                               meta={"claimed_client": "racer"})
            consume(own, cap["capability_id"], eid)
            own.commit()
            ok.append(eid)
        except Exception as exc:            # noqa: BLE001
            refused.append(exc)
        finally:
            own.close()

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(ok) == 1, f"{len(ok)} writers consumed one capability"
    assert len(refused) == 5
    assert all(isinstance(e, CapabilityError) for e in refused), refused


# --- the preserved checks ---------------------------------------------------

def test_anchor_membership_is_still_enforced(monkeypatch):
    """A capability says the write may happen, never that the claims hold."""
    conn = connect()
    ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    _bind(monkeypatch, cap)
    outside = ids[0] + 10_000
    reply = note(f"citing something never disclosed [{outside}].")
    assert reply.startswith("REFUSED:")
    assert "were not in the supplied dialogue" in reply
    # and the capability was NOT consumed by a refused write
    row = conn.execute(
        "SELECT consumed_event FROM dispatch_capabilities WHERE capability_id=?",
        (cap["capability_id"],)).fetchone()
    assert row["consumed_event"] is None


def test_valid_anchors_are_recorded_with_the_capability_digest(monkeypatch):
    conn = connect()
    ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    _bind(monkeypatch, cap)
    reply = note(f"a grounded claim [{ids[0]}].")
    eid = int(reply.rsplit("#", 1)[1])
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?", (eid,)).fetchone()["meta"])
    assert meta["derivation"]["source_egress"] == egress
    assert meta["derivation"]["anchors"] == [ids[0]]
    # the recorded reference is a digest, not the usable capability
    assert meta["derivation"]["capability_id"] == digest(cap["capability_id"])
    assert cap["secret"] not in json.dumps(meta)
    assert cap["capability_id"] not in json.dumps(meta)


def test_default_ttl_is_short():
    assert DEFAULT_TTL_SECONDS <= 900
    assert MAX_TTL_SECONDS <= 3600


def test_capability_secret_never_reaches_the_archive():
    conn = connect()
    _ids, egress = _disclosure(conn)
    cap = _issue(conn, egress)
    rows = conn.execute("SELECT content, meta, uri FROM events").fetchall()
    blob = json.dumps([[r["content"], r["meta"], r["uri"]] for r in rows])
    assert cap["secret"] not in blob
