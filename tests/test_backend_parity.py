"""Backend-parity behaviour that must hold with no Postgres server present.

Two kinds of thing live here. The first is the SQLite half of a parity claim
whose Postgres half is in `test_postgres_backend.py` — asserting it here means
the claim is checked on every run, not only on runs that happen to have a
throwaway cluster. The second is a refusal that is *about* the Postgres backend
but needs nothing from it: `CONTEXTD_DATABASE_URL` alone selects the backend
(`backends/__init__.py`), so a refusal keyed on that selection is testable
anywhere, and a refusal that were only ever exercised alongside a live server
would be exactly the one to rot.
"""

import json
import types

import pytest

from contextd.db import (SCHEMA_VERSION, WITNESS_VERSION, SchemaVersionError,
                         append_event, connect, open_archive_for_migration)
from contextd.handoff import freeze_view, freeze_view_from_connection


def _seeded(events=4):
    conn = connect()
    for i in range(events):
        append_event(conn, "test", "note", content=f"parity event {i}")
    return conn


# --- migration is SQLite-only, and says so -------------------------------

def test_in_place_migration_refuses_a_postgres_archive(monkeypatch):
    """`migrate.py` drives ``PRAGMA user_version`` from its first line, which
    Postgres does not have. Before this refusal, `ctx security migrate` against
    a Postgres archive opened whatever ``contextd.db`` happened to sit in the
    same home — a different archive, or none — and either migrated the wrong
    file or died on a raw driver syntax error naming ``PRAGMA``.
    """
    from contextd.db import PostgresMigrationUnsupported

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", "postgresql://localhost/nope")
    with pytest.raises(PostgresMigrationUnsupported) as raised:
        open_archive_for_migration()
    message = str(raised.value)
    assert "in-place security migration is SQLite-only" in message
    assert f"created at schema version {SCHEMA_VERSION}" in message
    # The refusal names the substitute rather than leaving the operator stuck.
    assert "migrate_sqlite_to_postgres" in message
    # It is a schema-version refusal, so `ctx security migrate` already prints
    # it as a refusal instead of a traceback.
    assert isinstance(raised.value, SchemaVersionError)


def test_the_migrate_command_prints_the_postgres_refusal(monkeypatch, capsys):
    from contextd.cli import cmd_security

    monkeypatch.setenv("CONTEXTD_DATABASE_URL", "postgresql://localhost/nope")
    args = types.SimpleNamespace(
        security_action="migrate", dry_run=True, json=False)
    with pytest.raises(SystemExit) as exited:
        cmd_security(args)
    assert "in-place security migration is SQLite-only" in str(exited.value)
    assert str(exited.value).startswith("refused: ")


def test_migration_still_opens_a_sqlite_archive_named_explicitly(
    isolated_contextd_home, monkeypatch
):
    """A bundle database or a restored archive is a real SQLite file, and
    inspecting one is legitimate even in a process configured for Postgres.
    Only the default — "open *the* archive" — is ambiguous, so only it refuses.
    """
    conn = _seeded(events=1)
    conn.close()
    monkeypatch.setenv("CONTEXTD_DATABASE_URL", "postgresql://localhost/nope")
    opened = open_archive_for_migration(
        isolated_contextd_home / "contextd.db", read_only=True)
    try:
        assert opened.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    finally:
        opened.close()


# --- the frozen view's chain state ---------------------------------------

def test_a_frozen_view_witness_carries_the_current_protocol_version(
    isolated_contextd_home, tmp_path
):
    """The stamp was hardcoded to 1 while the build wrote 2. Nothing broke —
    version 1 is still read — but a view is built from the CURRENT schema by
    construction, which is exactly why `user_version` is stamped, so labelling
    its witness with an older protocol was a claim the file could not support.
    """
    conn = _seeded(events=3)
    conn.close()
    view = tmp_path / "view"
    freeze_view(isolated_contextd_home / "contextd.db", view, 2)
    witness = json.loads((view / "chain-witness.json").read_text())
    assert witness == {"version": WITNESS_VERSION, "id": 2,
                       "chain_hash": witness["chain_hash"]}
    assert witness["version"] == 2


def test_freeze_view_from_connection_agrees_with_freeze_view_on_sqlite(
    isolated_contextd_home, tmp_path
):
    """The connection-based entry point exists for Postgres, but it must not
    become a second, differently-behaving freezer for SQLite."""
    conn = _seeded(events=4)
    by_path = freeze_view(
        isolated_contextd_home / "contextd.db", tmp_path / "a", 3)
    by_conn = freeze_view_from_connection(conn, tmp_path / "b", 3)
    conn.close()

    assert by_path["events"] == by_conn["events"] == 3
    assert by_path["tip"] == by_conn["tip"] == 3
    assert by_path["source_tip"] == by_conn["source_tip"] == 4
    for name in ("chain-witness.json", "config.toml"):
        assert (tmp_path / "a" / name).read_text() == \
               (tmp_path / "b" / name).read_text()
    rows = []
    for side in ("a", "b"):
        import sqlite3

        db = sqlite3.connect(tmp_path / side / "contextd.db")
        rows.append(db.execute(
            "SELECT id, chain_hash FROM events ORDER BY id").fetchall())
        db.close()
    assert rows[0] == rows[1]


# --- the export path refuses to overwrite --------------------------------

def test_the_sqlite_export_refuses_an_existing_destination(tmp_path):
    """`export_postgres_to_sqlite` publishes an archive file. Writing into one
    that already exists would merge two histories into a file that then fails
    chain verification for reasons no message could explain."""
    from contextd.backends.transfer import ExportError, export_postgres_to_sqlite

    occupied = tmp_path / "contextd.db"
    occupied.write_bytes(b"not a database")
    with pytest.raises(ExportError, match="already exists"):
        export_postgres_to_sqlite(object(), occupied)
