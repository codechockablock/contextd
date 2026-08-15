"""Migration preserves every historical byte, and says only what it can.

Two failure modes this suite exists to prevent:

1. **A migration that rewrites history.** An append-only archive whose own
   migration tool can rewrite it is not append-only. The tests fingerprint
   every historical column before and after and require the digest to be
   identical — not "equivalent", identical.

2. **A cutover that reads as retroactive authentication.** Signing a legacy
   tip attests that the service *observed* it. It is not evidence about who
   wrote anything before it, and every legacy authority label must still
   resolve `legacy_unverified` afterwards.

Plus the schema-version reversal: an archive from a newer build must be
refused **before** any filesystem or database change, not opened, upgraded in
place, and then discovered to be a problem.
"""

import json
import os
import sqlite3
import threading

import pytest

from contextd import home
from contextd.assurance import LEGACY_UNVERIFIED, assurance_of, is_authenticated_human
from contextd.db import (
    SCHEMA_VERSION,
    SchemaVersionError,
    assert_supported_schema,
    connect,
    verify_chain,
)
from contextd.ingest import ingest_note
from contextd.migrate import (
    HISTORICAL_COLUMNS,
    MigrationError,
    cutover_claim,
    fingerprint,
    legacy_label_report,
    migrate,
    plan,
)
from tests.legacy_support import FIXTURE, build_legacy_archive


@pytest.fixture
def legacy(isolated_contextd_home, monkeypatch):
    """A frozen, sanitized pre-hardening archive as this archive's home."""
    root = isolated_contextd_home
    monkeypatch.setenv("CONTEXTD_HOME", str(root))
    return build_legacy_archive(root)


def _raw_rows(root):
    """Read history without going through contextd, so the reader cannot be
    the thing that is wrong."""
    conn = sqlite3.connect(f"file:{root / 'contextd.db'}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [
            {c: r[c] for c in HISTORICAL_COLUMNS}
            for r in conn.execute(
                f"SELECT {', '.join(HISTORICAL_COLUMNS)} FROM events ORDER BY id")
        ]
    finally:
        conn.close()


# --- the fixture itself -----------------------------------------------------

def test_the_frozen_fixture_is_synthetic_and_scannable():
    """The fixture is data, not an opaque binary, so it can be reviewed.

    It deliberately reproduces session-URI and dialogue *shapes*, so the
    scanner flags it; that approval is recorded explicitly rather than by
    weakening a detector.
    """
    spec = json.loads(FIXTURE.read_text())
    assert spec["schema_version"] == 0
    assert spec["events"]

    from pathlib import Path as _Path
    allow = json.loads(
        (_Path(__file__).resolve().parent.parent / "scripts"
         / "repository_privacy_allow.json").read_text())
    entry = allow["tracked"]["tests/fixtures/legacy_archive.json"]
    assert entry["status"] == "synthetic"

    from scripts.audit_repository_privacy import scan_text
    found = set(scan_text(FIXTURE.read_text(), {"exampleowner"}))
    assert found <= set(entry["classes"]), f"unapproved classes: {found}"
    assert "credential" not in found
    assert "home_path" not in found


def test_the_fixture_loads_as_a_real_legacy_archive(legacy):
    conn = connect()
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == \
        legacy["events"]
    assert verify_chain(conn)["ok"]


def test_the_fixture_carries_the_shapes_that_mattered(legacy):
    """If these stop being present the migration tests prove nothing."""
    conn = connect()
    metas = [json.loads(r["meta"]) for r in
             conn.execute("SELECT meta FROM events WHERE meta IS NOT NULL")]
    assert any(m.get("authority") == "operator" for m in metas)
    assert any(m.get("actor") == "human" for m in metas)
    assert any("client" in m and "claimed_client" not in m for m in metas)
    assert any("query" in m for m in metas)          # a raw query in an egress
    assert any(m.get("role") == "user" for m in metas)


# --- history is untouched ---------------------------------------------------

def test_migration_changes_no_historical_byte(legacy):
    root = home()
    before = _raw_rows(root)
    conn = connect()
    result = migrate(conn)
    assert result["applied"] is True
    assert result["history_unchanged"] is True
    after = _raw_rows(root)
    assert after == before, "migration altered history"


def test_every_column_is_preserved_individually(legacy):
    """A digest match could in principle hide a compensating change; this
    checks the columns the Definition of Done names, one at a time."""
    root = home()
    before = {r["id"]: r for r in _raw_rows(root)}
    migrate(connect())
    after = {r["id"]: r for r in _raw_rows(root)}
    assert set(after) == set(before)
    for event_id, row in before.items():
        for column in ("id", "ts", "content", "content_hash", "meta",
                       "prev_hash", "chain_hash", "uri", "source", "kind"):
            assert after[event_id][column] == row[column], \
                f"{column} changed on event #{event_id}"


def test_witness_tip_is_preserved(legacy):
    witness = home() / "chain-witness.json"
    before = json.loads(witness.read_text())
    conn = connect()
    migrate(conn)
    after = json.loads(witness.read_text())
    assert after["id"] == before["id"]
    assert after["chain_hash"] == before["chain_hash"]
    assert verify_chain(conn)["ok"]


def test_migration_appends_no_events(legacy):
    conn = connect()
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    migrate(conn)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before


def test_a_migration_that_rewrote_history_would_be_caught(legacy, monkeypatch):
    """The check is real, not decorative: make migration tamper and watch."""
    import contextd.migrate as migrate_module

    conn = connect()
    real_sign_tip = migrate_module.sign_tip if hasattr(
        migrate_module, "sign_tip") else None
    del real_sign_tip

    def tampering_sign_tip(c, cutover=False):
        c.execute("DROP TRIGGER IF EXISTS events_no_update")
        c.execute("UPDATE events SET content = 'rewritten' WHERE id = 1")
        c.commit()
        return {"tip_id": 0, "chain_hash": "", "key_id": "", "signature": "",
                "cutover": True}

    import contextd.ledger_sig as ledger
    monkeypatch.setattr(ledger, "sign_tip", tampering_sign_tip)
    with pytest.raises(MigrationError) as exc:
        migrate(conn)
    assert "changed history" in str(exc.value)
    assert "event #1 changed" in str(exc.value)


# --- legacy labels stay legacy ----------------------------------------------

def test_legacy_authority_labels_still_resolve_legacy_unverified(legacy):
    conn = connect()
    before = legacy_label_report(conn)
    migrate(conn)
    after = legacy_label_report(conn)
    assert after == before, "migration changed how legacy labels resolve"
    assert after["by_assurance"].get(LEGACY_UNVERIFIED, 0) > 0
    for row in conn.execute(
        "SELECT meta FROM events WHERE json_extract(meta,'$.authority')='operator'"
    ):
        meta = json.loads(row["meta"])
        assert assurance_of(meta) == LEGACY_UNVERIFIED
        assert not is_authenticated_human(meta)


def test_no_legacy_event_becomes_operator_authorized(legacy):
    conn = connect()
    migrate(conn)
    rows = conn.execute(
        "SELECT COUNT(*) FROM events WHERE "
        "json_extract(meta,'$.assurance') = 'operator_authorized'"
    ).fetchone()[0]
    assert rows == 0


def test_legacy_events_are_not_silently_re_signed(legacy):
    from contextd.ledger_sig import verify_event
    conn = connect()
    migrate(conn)
    for row in conn.execute("SELECT id FROM events"):
        assert verify_event(conn, row["id"])["signed"] is False, (
            f"event #{row['id']} was re-signed by migration"
        )


def test_legacy_grant_does_not_authorize_after_migration(legacy):
    """A pre-hardening grant event must not become usable authority."""
    from contextd.grants import active_grant_for, reduce_grants
    conn = connect()
    migrate(conn)
    reduced = reduce_grants(conn)
    assert reduced["grants"] == []
    assert reduced["anomalies"], "a legacy grant was accepted"
    assert active_grant_for(conn, "loop.confirm", {"repo": "/srv/demo/ledgerd"}) is None


# --- the cutover ------------------------------------------------------------

def test_cutover_adopts_the_tip_and_claims_nothing_more(legacy):
    conn = connect()
    result = migrate(conn)
    tip_id = result["cutover"]["tip_id"]
    assert tip_id == legacy["tip"]["id"]
    claim = cutover_claim(conn, tip_id)
    assert claim["signature_valid"] is True
    assert "observed this chain tip" in claim["attests"]
    assert any("authored by the operator" in s
               for s in claim["does_not_attest"])


def test_cutover_signature_does_not_make_legacy_events_verify(legacy):
    from contextd.ledger_sig import verify_event, verify_tip
    conn = connect()
    result = migrate(conn)
    assert verify_tip(conn, result["cutover"]["tip_id"])["ok"] is True
    # the tip verifies; the events under it still carry no signature
    assert verify_event(conn, 1)["signed"] is False


# --- plan / dry run ---------------------------------------------------------

def test_plan_changes_nothing(legacy):
    root = home()
    # connect() itself applies the current schema; the claim under test is that
    # `plan` adds nothing on top of that, so the snapshot is taken after it
    conn = connect()
    before = _raw_rows(root)
    tables_before = _table_names(root)
    proposal = plan(conn)
    assert proposal["will_rewrite_history"] is False
    # connect() already stamps a version-0 archive, so plan() sees the stamped
    # value; what matters is that it is a version this build can migrate from
    from contextd.migrate import MIGRATABLE_FROM
    assert proposal["from_version"] in MIGRATABLE_FROM
    assert proposal["to_version"] == SCHEMA_VERSION
    assert _raw_rows(root) == before
    assert _table_names(root) == tables_before


def test_dry_run_changes_nothing(legacy):
    root = home()
    conn = connect()
    before = _raw_rows(root)
    tables_before = _table_names(root)
    result = migrate(conn, dry_run=True)
    assert _table_names(root) == tables_before
    assert result["applied"] is False
    assert _raw_rows(root) == before


def _table_names(root):
    conn = sqlite3.connect(f"file:{root / 'contextd.db'}?mode=ro", uri=True)
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


def test_migration_refuses_a_broken_chain(legacy):
    conn = connect()
    conn.execute("DROP TRIGGER IF EXISTS events_no_update")
    conn.execute("UPDATE events SET content = 'tampered' WHERE id = 2")
    conn.commit()
    assert not verify_chain(conn)["ok"]
    with pytest.raises(MigrationError) as exc:
        migrate(conn)
    assert "refusing to migrate a broken archive" in str(exc.value)


# --- idempotence and crash safety -------------------------------------------

def test_migration_is_idempotent(legacy):
    root = home()
    conn = connect()
    first = migrate(conn)
    snapshot = _raw_rows(root)
    second = migrate(conn)
    assert second["applied"] is True
    assert _raw_rows(root) == snapshot
    assert first["history_digest"] == second["history_digest"]


def test_interruption_at_any_step_leaves_history_intact(legacy, monkeypatch):
    """Crash safety by shape: no step mutates history, so an interruption
    anywhere leaves it byte-identical and the migration re-runnable."""
    import contextd.ledger_sig as ledger

    root = home()
    before = _raw_rows(root)

    class Boom(RuntimeError):
        pass

    def explode(*_a, **_k):
        raise Boom("interrupted mid-migration")

    monkeypatch.setattr(ledger, "sign_tip", explode)
    with pytest.raises(Boom):
        migrate(connect())
    assert _raw_rows(root) == before

    monkeypatch.undo()
    result = migrate(connect())          # re-running completes it
    assert result["applied"] is True
    assert _raw_rows(root) == before


def test_concurrent_migrations_do_not_corrupt_history(legacy):
    root = home()
    before = _raw_rows(root)
    errors, done = [], []

    def attempt():
        try:
            done.append(migrate(connect()))
        except Exception as exc:          # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert done, f"every concurrent migration failed: {errors}"
    assert _raw_rows(root) == before
    assert verify_chain(connect())["ok"]


def test_concurrent_appends_during_migration_preserve_older_history(legacy):
    """History that existed before migration stays byte-identical even while
    new events land."""
    root = home()
    before = {r["id"]: r for r in _raw_rows(root)}
    stop = threading.Event()

    def writer():
        conn = connect()
        i = 0
        while not stop.is_set() and i < 12:
            ingest_note(conn, f"concurrent note {i}")
            i += 1
        conn.close()

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        migrate(connect())
    finally:
        stop.set()
        thread.join(timeout=60)

    after = {r["id"]: r for r in _raw_rows(root)}
    for event_id, row in before.items():
        assert after[event_id] == row, f"event #{event_id} changed"
    assert verify_chain(connect())["ok"]


# --- schema version ---------------------------------------------------------

def test_future_schema_refuses_before_any_mutation(legacy):
    root = home()
    database = root / "contextd.db"
    conn = sqlite3.connect(database)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 5}")
    conn.commit()
    conn.close()

    before_rows = _raw_rows(root)
    before_mtime = os.stat(database).st_mtime_ns
    before_entries = sorted(p.name for p in root.iterdir())

    with pytest.raises(SchemaVersionError) as exc:
        connect()
    assert "newer contextd" in str(exc.value)
    assert "before any filesystem or database change" in str(exc.value)

    # nothing moved: not the rows, not the file, not the directory
    assert _raw_rows(root) == before_rows
    assert os.stat(database).st_mtime_ns == before_mtime
    assert sorted(p.name for p in root.iterdir()) == before_entries


def test_assert_supported_schema_accepts_current_and_older(legacy):
    assert assert_supported_schema() == 0          # the legacy fixture
    conn = connect()
    conn.close()
    assert assert_supported_schema() == SCHEMA_VERSION


def test_assert_supported_schema_on_a_missing_archive_is_not_an_error(tmp_path):
    assert assert_supported_schema(tmp_path / "nothing.db") == 0


def test_migration_refuses_an_unsupported_future_version(legacy):
    conn = connect()
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 3}")
    conn.commit()
    with pytest.raises(SchemaVersionError):
        plan(conn)


def test_schema_is_stamped_after_migration(legacy):
    conn = connect()
    migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


# --- the fingerprint itself -------------------------------------------------

def test_fingerprint_detects_a_change_in_every_historical_column(legacy):
    conn = connect()
    baseline = fingerprint(conn)["digest"]
    conn.execute("DROP TRIGGER IF EXISTS events_no_update")
    for column, value in (("ts", "1999-01-01T00:00:00+00:00"),
                          ("content", "different"),
                          ("meta", '{"actor": "changed"}'),
                          ("uri", "changed://uri"),
                          ("content_hash", "0" * 64),
                          ("prev_hash", "1" * 64),
                          ("chain_hash", "2" * 64),
                          ("source", "changed"),
                          ("kind", "changed")):
        original = conn.execute(
            f"SELECT {column} FROM events WHERE id = 3").fetchone()[0]
        conn.execute(f"UPDATE events SET {column} = ? WHERE id = 3", (value,))
        conn.commit()
        assert fingerprint(conn)["digest"] != baseline, column
        conn.execute(f"UPDATE events SET {column} = ? WHERE id = 3", (original,))
        conn.commit()
        assert fingerprint(conn)["digest"] == baseline, f"{column} restore"
