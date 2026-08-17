"""Crypto agility: every signature names its scheme, and checkpoints go PQ.

Evidence meant to settle a dispute in 2035 cannot rest on a scheme that may be
forgeable by then. Two facts shape everything here:

* An ML-DSA-44 signature is 2,420 bytes against roughly 64 for ECDSA P-256 —
  about 38x per event. A per-event ledger cannot carry that.
* The chain hash at event N already commits to every event beneath it, so one
  signature over a tip transitively covers the whole prefix.

So the per-append path stays classical and fast, and the post-quantum scheme
goes on *checkpoints* — the signed-tree-head model from Certificate
Transparency. What makes that survivable is the algorithm identifier: without
one, introducing a second scheme means guessing which existing records used
which, and there is no version of that guess that is safe.
"""

import json

import pytest

from contextd.db import _db_tip, append_event, connect
from contextd.ingest import ingest_note
from contextd.ledger_sig import (
    ALG_ECDSA_P256,
    ALG_MLDSA_44,
    CLASSICAL_ALG,
    SUPPORTED_ALGS,
    LedgerSignatureError,
    active_key_id,
    checkpoint_algorithms,
    checkpoint_interval,
    checkpoint_record,
    last_checkpoint_tip,
    pq_available,
    rotate_key,
    sign_tip,
    verify_checkpoint,
    verify_event,
    verify_ledger,
    verify_recorded_checkpoints,
    write_checkpoint,
)

requires_pq = pytest.mark.skipif(
    not pq_available(),
    reason="native ML-DSA needs cryptography>=47 on an OpenSSL that implements it",
)


def _configure(home, **security) -> None:
    """Write a [security] config block into the isolated archive home."""
    home.mkdir(parents=True, exist_ok=True)
    lines = ["[security]"]
    for key, value in security.items():
        lines.append(f"{key} = {json.dumps(value)}")
    (home / "config.toml").write_text("\n".join(lines) + "\n")


def _signed_archive():
    """An archive past the signed cutover, so appends are signed."""
    conn = connect()
    append_event(conn, "note", "note", content="before the cutover")
    sign_tip(conn, cutover=True)
    return conn


# --- the algorithm identifier ----------------------------------------------
#
# This is the piece that is expensive to retrofit. Everything else in this file
# is downstream of it.

def test_every_signature_record_names_the_scheme_that_made_it():
    conn = _signed_archive()
    ingest_note(conn, "signed after the cutover")

    for table in ("service_keys", "service_signatures", "service_tips"):
        columns = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        assert "alg" in columns, f"{table} has no algorithm identifier"
        rows = conn.execute(f"SELECT alg FROM {table}").fetchall()
        assert rows, f"{table} is empty; this test would prove nothing"
        for row in rows:
            assert row["alg"] in SUPPORTED_ALGS
            assert row["alg"] == ALG_ECDSA_P256, "per-append path must stay classical"


def test_verification_dispatches_on_the_recorded_algorithm():
    """A record whose `alg` disagrees with its key's registered `alg` is refused.

    The failure this prevents is subtle: if the verifier picked the scheme from
    the key it happened to load, an attacker who could get a record to point at
    a different key would choose which algorithm verified it. The identifier
    only helps if disagreement is an error rather than a preference.
    """
    conn = _signed_archive()
    eid = ingest_note(conn, "signed after the cutover")
    assert verify_event(conn, eid)["ok"]

    conn.execute("UPDATE service_signatures SET alg = ? WHERE event_id = ?",
                 (ALG_MLDSA_44, eid))
    conn.commit()
    result = verify_event(conn, eid)
    assert result["ok"] is False
    assert "does not verify" in result["why"]
    assert verify_ledger(conn)["ok"] is False


def test_an_unknown_algorithm_is_refused_rather_than_assumed():
    conn = _signed_archive()
    eid = ingest_note(conn, "signed after the cutover")
    conn.execute("UPDATE service_keys SET alg = 'dilithium-2'")
    conn.commit()
    assert verify_event(conn, eid)["ok"] is False


def test_verify_ledger_reports_the_schemes_present():
    conn = _signed_archive()
    ingest_note(conn, "signed after the cutover")
    report = verify_ledger(conn)
    assert report["ok"] is True
    assert report["algorithms"] == [ALG_ECDSA_P256]


def test_ddl_definitions_agree_across_both_files():
    """The signature DDL is duplicated in db.py and ledger_sig.py.

    Both are executed — db.py's by `connect()` for a fresh archive, and
    ledger_sig.py's by the security migration for an existing one. If they
    drift, a migrated archive and a fresh archive end up with different schemas
    while both report success, and the difference surfaces later as an
    unexplainable insert failure.
    """
    from contextd.db import SCHEMA as DB_SCHEMA
    from contextd.ledger_sig import SCHEMA as SIG_SCHEMA

    def tables(text):
        found = {}
        for block in text.split("CREATE TABLE IF NOT EXISTS ")[1:]:
            name = block.split("(", 1)[0].strip()
            body = block.split("(", 1)[1].rsplit(");", 1)[0]
            found[name] = " ".join(body.split())
        return found

    db_tables = tables(DB_SCHEMA)
    sig_tables = tables(SIG_SCHEMA)
    assert set(sig_tables) <= set(db_tables), "ledger_sig declares a table db.py lacks"
    for name, body in sig_tables.items():
        assert db_tables[name] == body, f"{name} DDL differs between the two files"


# --- migration --------------------------------------------------------------

def test_migration_adds_the_column_and_backfills_the_only_possible_scheme():
    """A pre-agility archive has no `alg` column at all.

    `executescript` of `CREATE TABLE IF NOT EXISTS` cannot add one, so this is
    real migration work. The backfill value is not a guess: every signature
    written before this change is ECDSA P-256, because nothing else existed.
    """
    from contextd.db import open_archive_for_migration
    from contextd.migrate import migrate, plan

    conn = _signed_archive()
    eid = ingest_note(conn, "signed under the old schema")
    # drop back to a version-2 archive: no alg column, no checkpoint table
    for table in ("service_keys", "service_signatures", "service_tips"):
        conn.execute(f"ALTER TABLE {table} DROP COLUMN alg")
    conn.execute("DROP TABLE service_checkpoints")
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()

    migration = open_archive_for_migration()
    proposed = plan(migration)
    assert sorted(proposed["columns_to_add"]) == [
        "service_keys.alg", "service_signatures.alg", "service_tips.alg",
    ]
    assert "service_checkpoints" in proposed["tables_to_create"]
    migrate(migration)
    migration.close()

    conn = connect()
    rows = conn.execute("SELECT alg FROM service_signatures").fetchall()
    assert rows and all(r["alg"] == ALG_ECDSA_P256 for r in rows)
    assert verify_event(conn, eid)["ok"], "migration must not invalidate history"
    assert verify_ledger(conn)["ok"]


def test_migration_is_idempotent_over_the_column_addition():
    from contextd.db import open_archive_for_migration
    from contextd.migrate import migrate

    conn = _signed_archive()
    ingest_note(conn, "signed")
    conn.close()
    for _ in range(2):
        migration = open_archive_for_migration()
        migrate(migration)
        migration.close()
    conn = connect()
    assert verify_ledger(conn)["ok"]


# --- checkpoints: interval and hybrid --------------------------------------

def test_checkpoint_interval_is_configurable(isolated_contextd_home):
    _configure(isolated_contextd_home, checkpoint_interval_events=3)
    assert checkpoint_interval() == 3
    conn = _signed_archive()
    cutover = _db_tip(conn)["id"]
    assert last_checkpoint_tip(conn) is None

    for _ in range(2):
        ingest_note(conn, "under the interval")
    assert last_checkpoint_tip(conn) is None, "checkpointed before the interval"

    ingest_note(conn, "this one lands on the boundary")
    recorded = last_checkpoint_tip(conn)
    assert recorded == cutover + 3
    assert verify_recorded_checkpoints(conn) == []


def test_a_zero_interval_disables_automatic_checkpointing(isolated_contextd_home):
    _configure(isolated_contextd_home, checkpoint_interval_events=0)
    conn = _signed_archive()
    for _ in range(5):
        ingest_note(conn, "no checkpoint should appear")
    assert last_checkpoint_tip(conn) is None


def test_checkpoint_is_written_inside_the_append_transaction(isolated_contextd_home):
    """A crash before commit leaves neither the event nor its checkpoint.

    Moving checkpoint signing after the commit would let a crash produce an
    accepted, chain-valid event whose checkpoint never happened, and recovery
    would report success because it only reconciles chain state.
    """
    from contextd.db import InjectedCrash, append_event_checked

    _configure(isolated_contextd_home, checkpoint_interval_events=2)
    conn = _signed_archive()
    ingest_note(conn, "first")
    before_tip = _db_tip(conn)["id"]
    before_checkpoint = last_checkpoint_tip(conn)

    def fault(stage):
        if stage == "before_db_commit":
            raise InjectedCrash(stage)

    with pytest.raises(InjectedCrash):
        append_event_checked(conn, "note", "note", content="crashes", fault=fault)
    conn.close()

    conn = connect()
    assert _db_tip(conn)["id"] == before_tip, "the crashed event must not survive"
    assert last_checkpoint_tip(conn) == before_checkpoint, \
        "a checkpoint outlived the transaction that should have contained it"


def test_base_install_checkpoint_record_is_unchanged(isolated_contextd_home):
    """With no scheme configured the record is exactly what it always was.

    A base install must not start emitting a shape older verifiers reject just
    because it upgraded.
    """
    _configure(isolated_contextd_home, checkpoint_algorithms=[])
    conn = _signed_archive()
    record = checkpoint_record(conn)
    assert set(record) == {
        "archive_uuid", "tip_id", "chain_hash", "key_id", "signature",
    }
    assert verify_checkpoint(conn, record)["ok"]


@requires_pq
def test_hybrid_checkpoint_carries_both_schemes(isolated_contextd_home):
    _configure(isolated_contextd_home, checkpoint_algorithms=[ALG_MLDSA_44])
    assert checkpoint_algorithms() == (ALG_MLDSA_44,)
    conn = _signed_archive()
    record = checkpoint_record(conn)

    assert record["alg"] == CLASSICAL_ALG
    assert [e["alg"] for e in record["hybrid"]] == [ALG_MLDSA_44]
    # FIPS 204 sizes, and the reason this is not on the per-event path
    assert len(bytes.fromhex(record["hybrid"][0]["signature"])) == 2420
    assert len(bytes.fromhex(record["signature"])) < 100

    result = verify_checkpoint(conn, record)
    assert result["ok"] is True
    assert result["algs"] == [CLASSICAL_ALG, ALG_MLDSA_44]


@requires_pq
def test_a_classical_only_verifier_still_reads_a_hybrid_checkpoint(
        isolated_contextd_home):
    """The transition guarantee: hybrid must not strand deployed verifiers.

    Stripping the post-quantum half leaves exactly the five-field record the
    pre-agility code produced, over exactly the same signed bytes.
    """
    _configure(isolated_contextd_home, checkpoint_algorithms=[ALG_MLDSA_44])
    conn = _signed_archive()
    record = checkpoint_record(conn)

    classical_only = {k: record[k] for k in
                      ("archive_uuid", "tip_id", "chain_hash", "key_id",
                       "signature")}
    assert verify_checkpoint(conn, classical_only)["ok"] is True


@requires_pq
def test_a_broken_post_quantum_half_fails_the_whole_checkpoint(
        isolated_contextd_home):
    """One good signature does not carry a hybrid record.

    A checkpoint whose ML-DSA half does not verify is a broken checkpoint, not
    a classical one — otherwise "hybrid" would mean "classical, with decoration".
    """
    _configure(isolated_contextd_home, checkpoint_algorithms=[ALG_MLDSA_44])
    conn = _signed_archive()
    record = checkpoint_record(conn)

    raw = bytearray(bytes.fromhex(record["hybrid"][0]["signature"]))
    raw[0] ^= 0xFF
    record["hybrid"][0]["signature"] = raw.hex()

    result = verify_checkpoint(conn, record)
    assert result["ok"] is False
    assert ALG_MLDSA_44 in result["why"]


@requires_pq
def test_a_post_quantum_signature_cannot_be_replayed_as_a_classical_one(
        isolated_contextd_home):
    """Cross-scheme confusion is structurally impossible, not merely unlikely.

    The two signatures cover different bytes — the non-classical payload
    carries an `alg` field, and the canonical encoding length-prefixes the
    field count, so a four-field map and a five-field map cannot collide.
    """
    _configure(isolated_contextd_home, checkpoint_algorithms=[ALG_MLDSA_44])
    conn = _signed_archive()
    record = checkpoint_record(conn)

    swapped = dict(record)
    swapped["signature"] = record["hybrid"][0]["signature"]
    swapped["key_id"] = record["hybrid"][0]["key_id"]
    assert verify_checkpoint(conn, swapped)["ok"] is False

    promoted = {k: record[k] for k in
                ("archive_uuid", "tip_id", "chain_hash", "signature")}
    promoted["key_id"] = record["hybrid"][0]["key_id"]
    assert verify_checkpoint(conn, promoted)["ok"] is False


@requires_pq
def test_hybrid_checkpoints_are_recorded_on_the_interval(isolated_contextd_home):
    _configure(isolated_contextd_home, checkpoint_interval_events=2,
               checkpoint_algorithms=[ALG_MLDSA_44])
    conn = _signed_archive()
    ingest_note(conn, "one")
    ingest_note(conn, "two")
    tip = last_checkpoint_tip(conn)
    assert tip is not None
    algs = [r["alg"] for r in conn.execute(
        "SELECT alg FROM service_checkpoints WHERE tip_id = ? ORDER BY alg",
        (tip,))]
    assert algs == [ALG_ECDSA_P256, ALG_MLDSA_44]
    assert verify_recorded_checkpoints(conn) == []
    assert verify_ledger(conn)["ok"]


@requires_pq
def test_a_rewritten_chain_is_caught_by_the_post_quantum_checkpoint(
        isolated_contextd_home):
    """The point of the whole exercise, stated as a test."""
    _configure(isolated_contextd_home, checkpoint_interval_events=2,
               checkpoint_algorithms=[ALG_MLDSA_44])
    conn = _signed_archive()
    ingest_note(conn, "one")
    ingest_note(conn, "two")
    tip = last_checkpoint_tip(conn)

    conn.execute("DROP TRIGGER IF EXISTS events_no_update")
    conn.execute("UPDATE events SET chain_hash = ? WHERE id = ?",
                 ("0" * 64, tip))
    conn.commit()
    bad = verify_recorded_checkpoints(conn)
    assert bad and all("rewritten" in b["why"] for b in bad)


# --- verification across an algorithm change --------------------------------

def test_history_verifies_across_a_key_rotation():
    conn = _signed_archive()
    first = ingest_note(conn, "signed under the first key")
    old_key = active_key_id(conn)
    rotate_key(conn)
    new_key = active_key_id(conn)
    assert new_key != old_key
    second = ingest_note(conn, "signed under the second key")

    assert verify_event(conn, first)["key_id"] == old_key
    assert verify_event(conn, second)["key_id"] == new_key
    assert verify_ledger(conn)["ok"], "rotation must not invalidate history"


@requires_pq
def test_history_verifies_across_an_algorithm_change(isolated_contextd_home):
    """Write under A, turn on B, verify the whole chain.

    This is the property the algorithm identifier exists to provide: an archive
    that contains records made under more than one scheme is normal, and a
    verifier reading it is never guessing which is which.
    """
    _configure(isolated_contextd_home, checkpoint_interval_events=2)
    conn = _signed_archive()
    ingest_note(conn, "under classical only")
    ingest_note(conn, "under classical only")
    classical_tip = last_checkpoint_tip(conn)
    assert classical_tip is not None
    conn.close()

    # ...the operator turns on ML-DSA and keeps appending
    _configure(isolated_contextd_home, checkpoint_interval_events=2,
               checkpoint_algorithms=[ALG_MLDSA_44])
    conn = connect()
    ingest_note(conn, "after the algorithm change")
    ingest_note(conn, "after the algorithm change")
    hybrid_tip = last_checkpoint_tip(conn)
    assert hybrid_tip is not None and hybrid_tip > classical_tip

    recorded = {
        (int(r["tip_id"]), r["alg"])
        for r in conn.execute("SELECT tip_id, alg FROM service_checkpoints")
    }
    assert (classical_tip, ALG_ECDSA_P256) in recorded
    assert (hybrid_tip, ALG_MLDSA_44) in recorded
    assert (classical_tip, ALG_MLDSA_44) not in recorded, \
        "turning a scheme on must not retroactively claim earlier coverage"

    assert verify_recorded_checkpoints(conn) == []
    report = verify_ledger(conn)
    assert report["ok"] is True


def test_an_unavailable_algorithm_is_a_refusal_not_a_silent_downgrade(
        isolated_contextd_home):
    """Asking for a scheme this build cannot make must not quietly sign classical."""
    _configure(isolated_contextd_home, checkpoint_algorithms=["ml-dsa-1024"])
    with pytest.raises(LedgerSignatureError):
        checkpoint_algorithms()


def test_written_checkpoint_round_trips(isolated_contextd_home, tmp_path):
    algs = [ALG_MLDSA_44] if pq_available() else []
    _configure(isolated_contextd_home, checkpoint_algorithms=algs)
    conn = _signed_archive()
    destination = tmp_path / "protected" / "checkpoint.json"
    write_checkpoint(conn, destination)
    record = json.loads(destination.read_text())
    assert verify_checkpoint(conn, record)["ok"] is True
