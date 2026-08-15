"""Recomputing the hash chain and witness does not make a forgery verify.

This is the claim in docs/SECURITY.md §3 that distinguishes integrity layer 3
from layers 1 and 2. The attacker in §1 owns the desktop UID, so it can:

  * rewrite any event row,
  * recompute every downstream ``chain_hash`` so ``ctx verify`` passes, and
  * rewrite ``chain-witness.json`` so the witness agrees.

After all three, everything the pre-hardening tree could check reports "ok".
The service signature is the thing it cannot produce, and each test below does
the full attack — including the chain and witness repair — before asserting
that the forgery is still caught.

Honest limit, stated once and tested at the end: the service key currently
lives beside the archive. In a **development** deployment the same UID owns
both, so a sufficiently thorough attacker re-signs too. This layer becomes
load-bearing when the service account owns the key; `ctx security doctor`
reports which case applies rather than letting the difference stay invisible.
"""

import json
import os


from contextd import home
from contextd.db import _chain_hash, _db_tip, append_event, connect, verify_chain
from contextd.ingest import ingest_note
from contextd.ledger_sig import (
    active_key_id,
    checkpoint_record,
    envelope,
    key_path,
    rotate_key,
    sign_event,
    sign_tip,
    verify_checkpoint,
    verify_event,
    verify_ledger,
    verify_tip,
    write_checkpoint,
)


def _rewrite_event(conn, event_id: int, content: str) -> None:
    """The full same-UID attack: rewrite a row, then repair the chain AND the
    witness so every pre-existing integrity check passes again."""
    import hashlib

    conn.execute("DROP TRIGGER IF EXISTS events_no_update")
    digest = hashlib.sha256(content.encode()).hexdigest()
    conn.execute(
        "UPDATE events SET content = ?, content_hash = ? WHERE id = ?",
        (content, digest, event_id))
    conn.commit()
    _recompute_chain(conn)


def _recompute_chain(conn) -> None:
    conn.execute("DROP TRIGGER IF EXISTS events_no_update")
    prev = ""
    for r in conn.execute(
        "SELECT id, ts, source, kind, uri, content, content_hash, meta "
        "FROM events ORDER BY id"
    ).fetchall():
        chain = _chain_hash(prev, r["id"], r["ts"], r["source"], r["kind"],
                            r["uri"], r["content"], r["content_hash"], r["meta"])
        conn.execute("UPDATE events SET prev_hash = ?, chain_hash = ? "
                     "WHERE id = ?", (prev, chain, r["id"]))
        prev = chain
    conn.commit()
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events "
        "BEGIN SELECT RAISE(ABORT, 'events are append-only'); END")
    # ... and repair the witness, which the attacker also owns
    tip = _db_tip(conn)
    (home() / "chain-witness.json").write_text(
        json.dumps({"version": 1, "id": tip["id"],
                    "chain_hash": tip["chain_hash"]},
                   sort_keys=True, separators=(",", ":")) + "\n")


# --- the core claim ---------------------------------------------------------

def test_chain_recomputation_defeats_the_old_checks():
    """Control: without service signatures the attack is undetectable.

    This test exists so the next one means something. If this ever starts
    failing, the chain got stronger and the framing below needs revisiting.
    """
    conn = connect()
    eid = ingest_note(conn, "the original claim")
    assert verify_chain(conn)["ok"]
    _rewrite_event(conn, eid, "the substituted claim")
    assert verify_chain(conn)["ok"], (
        "chain verification caught a recomputed chain — the premise of the "
        "service-signature layer has changed"
    )
    row = conn.execute("SELECT content FROM events WHERE id=?", (eid,)).fetchone()
    assert row["content"] == "the substituted claim"


def test_service_signature_catches_what_the_chain_cannot():
    conn = connect()
    eid = ingest_note(conn, "the original claim")
    sign_event(conn, eid)
    assert verify_event(conn, eid)["ok"]

    _rewrite_event(conn, eid, "the substituted claim")

    assert verify_chain(conn)["ok"]                 # chain repaired
    result = verify_event(conn, eid)
    assert result["ok"] is False
    assert "does not verify" in result["why"]


def test_forged_operator_event_does_not_verify():
    """An attacker appends an event that *looks* operator-authorized."""
    conn = connect()
    real = ingest_note(conn, "a genuine note")
    sign_event(conn, real)

    forged = append_event(
        conn, "note", "note", content="I, the operator, approve this",
        meta={"claimed_client": "cli", "authority": "operator",
              "assurance": "operator_authorized"},
    )
    _recompute_chain(conn)

    # the chain accepts it; the ledger does not, because it is unsigned
    assert verify_chain(conn)["ok"]
    assert verify_event(conn, forged)["signed"] is False
    ledger = verify_ledger(conn)
    assert ledger["ok"] is True          # no BAD signatures ...
    # ... but the forged event has none at all, which is the detectable state
    signed = {r["event_id"] for r in conn.execute(
        "SELECT event_id FROM service_signatures")}
    assert forged not in signed
    assert real in signed


def test_truncation_is_caught_by_the_signed_tip():
    conn = connect()
    for i in range(4):
        ingest_note(conn, f"event {i}")
    signed = sign_tip(conn)
    assert verify_tip(conn, signed["tip_id"])["ok"]

    conn.execute("DROP TRIGGER IF EXISTS events_no_delete")
    conn.execute("DELETE FROM events WHERE id = ?", (signed["tip_id"],))
    conn.commit()
    _recompute_chain(conn)

    result = verify_tip(conn, signed["tip_id"])
    assert result["ok"] is False
    assert "truncated" in result["why"]


def test_rewritten_history_is_caught_by_the_signed_tip():
    conn = connect()
    eid = ingest_note(conn, "original")
    signed = sign_tip(conn)
    _rewrite_event(conn, eid, "rewritten")
    result = verify_tip(conn, signed["tip_id"])
    assert result["ok"] is False
    assert "rewritten" in result["why"]


def test_verify_ledger_reports_every_bad_signature():
    conn = connect()
    a = ingest_note(conn, "first")
    b = ingest_note(conn, "second")
    sign_event(conn, a)
    sign_event(conn, b)
    sign_tip(conn)
    assert verify_ledger(conn)["ok"]

    _rewrite_event(conn, a, "tampered")
    report = verify_ledger(conn)
    assert report["ok"] is False
    assert [e["event"] for e in report["bad_events"]] == [a]


# --- key rotation -----------------------------------------------------------

def test_rotation_preserves_historical_verification():
    """Rotation must not make every past signature look like tampering."""
    conn = connect()
    old_event = ingest_note(conn, "signed under the old key")
    sign_event(conn, old_event)
    old_key = active_key_id(conn)

    new_key = rotate_key(conn)
    assert new_key != old_key

    new_event = ingest_note(conn, "signed under the new key")
    sign_event(conn, new_event)

    assert verify_event(conn, old_event)["ok"], "rotation broke history"
    assert verify_event(conn, old_event)["key_id"] == old_key
    assert verify_event(conn, new_event)["ok"]
    assert verify_event(conn, new_event)["key_id"] == new_key


def test_retired_key_is_marked_and_cannot_sign_new_events():
    conn = connect()
    old_key = active_key_id(conn)
    rotate_key(conn)
    row = conn.execute("SELECT retired FROM service_keys WHERE key_id = ?",
                       (old_key,)).fetchone()
    assert row["retired"] is not None
    eid = ingest_note(conn, "after rotation")
    assert sign_event(conn, eid)["key_id"] != old_key


# --- protected checkpoint ---------------------------------------------------

def test_checkpoint_contains_only_the_five_declared_fields():
    """A checkpoint goes somewhere the operator does not fully control, so it
    must not carry archive content."""
    conn = connect()
    ingest_note(conn, "a private note about something sensitive")
    record = checkpoint_record(conn)
    assert set(record) == {"archive_uuid", "tip_id", "chain_hash", "key_id",
                           "signature"}
    assert "private note" not in json.dumps(record)
    assert "sensitive" not in json.dumps(record)


def test_checkpoint_detects_rollback():
    conn = connect()
    for i in range(5):
        ingest_note(conn, f"event {i}")
    record = checkpoint_record(conn)
    assert verify_checkpoint(conn, record)["ok"]

    # roll the archive back: delete the tail and repair everything local
    conn.execute("DROP TRIGGER IF EXISTS events_no_delete")
    conn.execute("DELETE FROM events WHERE id >= ?", (record["tip_id"] - 1,))
    conn.commit()
    _recompute_chain(conn)
    assert verify_chain(conn)["ok"]          # locally consistent again

    result = verify_checkpoint(conn, record)
    assert result["ok"] is False
    assert result.get("rollback") is True
    assert "ROLLBACK" in result["why"]


def test_checkpoint_detects_rewritten_history():
    conn = connect()
    eid = ingest_note(conn, "original")
    for i in range(3):
        ingest_note(conn, f"later {i}")
    record = checkpoint_record(conn)
    _rewrite_event(conn, eid, "rewritten")
    result = verify_checkpoint(conn, record)
    assert result["ok"] is False
    assert result.get("rewritten") is True


def test_checkpoint_from_another_archive_is_refused(tmp_path, monkeypatch):
    conn = connect()
    ingest_note(conn, "here")
    record = checkpoint_record(conn)
    monkeypatch.setenv("CONTEXTD_HOME", str(tmp_path / "elsewhere"))
    other = connect()
    # the other archive does not know this key, so it cannot even verify it
    result = verify_checkpoint(other, record)
    assert result["ok"] is False


def test_malformed_checkpoints_are_refused():
    conn = connect()
    ingest_note(conn, "x")
    record = checkpoint_record(conn)
    for bad in ({}, {**record, "extra": 1},
                {k: v for k, v in record.items() if k != "signature"},
                {**record, "signature": "00" * 70}, "not-a-dict"):
        assert verify_checkpoint(conn, bad)["ok"] is False


def test_write_checkpoint_is_owner_only_readable(tmp_path):
    conn = connect()
    ingest_note(conn, "x")
    path = write_checkpoint(conn, tmp_path / "cp" / "checkpoint.json")
    assert (os.stat(path).st_mode & 0o777) == 0o600
    assert verify_checkpoint(conn, json.loads(path.read_text()))["ok"]


def test_doctor_reports_rollback_resistance_incomplete_without_a_destination():
    from contextd.doctor import run
    conn = connect()
    result = run(conn)["invariants"]["protected_checkpoint"]
    assert result["ok"] is False
    assert "rollback_resistance: incomplete" in result["detail"]


# --- cutover ----------------------------------------------------------------

def test_cutover_adopts_a_legacy_tip_without_authenticating_it():
    """The cutover signature says 'the service observed this tip', and that is
    all it may be read to say."""
    conn = connect()
    legacy = append_event(conn, "note", "note", content="a legacy row",
                          meta={"claimed_client": "cli", "authority": "operator"})
    signed = sign_tip(conn, cutover=True)
    assert verify_tip(conn, signed["tip_id"])["cutover"] is True

    # the legacy event itself gained no assurance from the cutover
    from contextd.assurance import LEGACY_UNVERIFIED, assurance_of
    meta = json.loads(
        conn.execute("SELECT meta FROM events WHERE id=?", (legacy,)).fetchone()["meta"])
    assert assurance_of(meta) == LEGACY_UNVERIFIED
    assert verify_event(conn, legacy)["signed"] is False


# --- the honest limit -------------------------------------------------------

def test_service_key_is_owner_only_and_its_limit_is_stated():
    """SIMULATED BOUNDARY.

    The key is 0600, which stops other users. It does NOT stop the desktop UID
    in a development deployment — that is what the service account is for, and
    until it exists this layer defends against a chain-recomputing attacker but
    not against one that also re-signs.
    """
    conn = connect()
    active_key_id(conn)
    assert (os.stat(key_path()).st_mode & 0o777) == 0o600
    from contextd.doctor import run
    fallback = run(conn)["invariants"]["no_insecure_fallback"]
    assert fallback["ok"] is False       # development mode is reported, not hidden


def test_envelope_covers_the_semantic_fields_not_the_chain_hash():
    conn = connect()
    eid = ingest_note(conn, "content")
    row = conn.execute(
        "SELECT id, ts, source, kind, uri, content_hash, meta FROM events "
        "WHERE id = ?", (eid,)).fetchone()
    payload = envelope(row)
    assert set(payload) == {"id", "ts", "source", "kind", "uri",
                            "content_hash", "meta"}
    assert "chain_hash" not in payload


def test_signed_events_survive_an_unrelated_append():
    """Signing must not be invalidated by the ledger simply growing."""
    conn = connect()
    eid = ingest_note(conn, "signed")
    sign_event(conn, eid)
    for i in range(3):
        ingest_note(conn, f"later {i}")
    assert verify_event(conn, eid)["ok"]
    assert verify_ledger(conn)["ok"]


# --- signed backup manifests ------------------------------------------------

def test_backup_manifest_is_service_signed(tmp_path):
    from contextd.backup import create_backup, verify_manifest_signature
    conn = connect()
    ingest_note(conn, "an event to back up")
    bundle = create_backup(conn, home(), tmp_path / "bk")["bundle"]
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["service_signature"]["signed"] is True
    assert verify_manifest_signature(conn, manifest)["ok"]


def test_tampered_backup_manifest_does_not_verify(tmp_path):
    """A rebuilt bundle rewrites the manifest hash; it cannot rewrite this."""
    from contextd.backup import create_backup, verify_manifest_signature
    conn = connect()
    ingest_note(conn, "an event to back up")
    bundle = create_backup(conn, home(), tmp_path / "bk")["bundle"]
    manifest = json.loads((bundle / "manifest.json").read_text())
    manifest["snapshot"]["events"] = manifest["snapshot"]["events"] + 1
    result = verify_manifest_signature(conn, manifest)
    assert result["ok"] is False
    assert "does not verify" in result["why"]


def test_unsigned_manifest_is_reported_as_unsigned_not_valid():
    from contextd.backup import verify_manifest_signature
    conn = connect()
    result = verify_manifest_signature(conn, {"service_signature": {"signed": False}})
    assert result["ok"] is False
    assert result["signed"] is False
