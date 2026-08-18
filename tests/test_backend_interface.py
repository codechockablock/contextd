"""The storage-backend boundary, exercised without needing a server."""

import pytest

from contextd.backends import (
    SQLiteBackend,
    active_backend,
    backend_for,
    postgres_configured,
    table_names,
)
from contextd.backends.paramstyle import to_pyformat
from contextd.db import append_event, connect


# --- selection ------------------------------------------------------------

def test_sqlite_is_the_default_backend(monkeypatch):
    monkeypatch.delenv("CONTEXTD_DATABASE_URL", raising=False)
    assert not postgres_configured()
    assert isinstance(active_backend(), SQLiteBackend)


def test_postgres_is_selected_only_by_explicit_url(monkeypatch):
    monkeypatch.setenv("CONTEXTD_DATABASE_URL", "postgresql://localhost/x")
    assert postgres_configured()
    from contextd.backends.postgres import PostgresBackend

    assert isinstance(active_backend(), PostgresBackend)


def test_blank_url_does_not_select_postgres(monkeypatch):
    """An empty variable is an unset one; it must not half-select a backend."""
    monkeypatch.setenv("CONTEXTD_DATABASE_URL", "   ")
    assert not postgres_configured()
    assert isinstance(active_backend(), SQLiteBackend)


def test_backend_for_dispatches_on_the_connection(monkeypatch):
    """Even with Postgres configured, a SQLite connection routes to SQLite."""
    conn = connect()
    monkeypatch.setenv("CONTEXTD_DATABASE_URL", "postgresql://localhost/x")
    assert isinstance(backend_for(conn), SQLiteBackend)
    conn.close()


def test_sqlite_backend_reports_its_own_limits():
    backend = SQLiteBackend()
    assert backend.supports_search is True
    # SQLite's append-only triggers are droppable by any owner-level process,
    # so the backend must not claim database-enforced immutability.
    assert backend.enforces_append_only_in_db is False


def test_postgres_backend_claims_database_enforced_immutability():
    from contextd.backends.postgres import PostgresBackend

    backend = PostgresBackend(url="postgresql://localhost/x")
    assert backend.enforces_append_only_in_db is True
    # FTS5 has no equivalent; search is declared out of scope rather than
    # silently substituted with different ranking.
    assert backend.supports_search is False


def test_postgres_backend_refuses_without_a_url(monkeypatch):
    from contextd.backends.postgres import PostgresBackend, PostgresUnavailable

    monkeypatch.delenv("CONTEXTD_DATABASE_URL", raising=False)
    with pytest.raises(PostgresUnavailable):
        PostgresBackend()


# --- the shared surface ---------------------------------------------------

def test_table_names_probe_works_on_sqlite():
    conn = connect()
    names = table_names(conn)
    assert {"events", "operator_nonces", "service_keys"} <= names
    conn.close()


def test_sqlite_append_still_witnesses_to_local_files():
    """The default protocol is unchanged: journal cleared, witness at the tip."""
    from contextd.db import chain_state_paths

    conn = connect()
    eid = append_event(conn, "test", "note", content="hello")
    paths = chain_state_paths()
    assert paths["witness"].is_file()
    assert not paths["recovery"].exists()
    import json

    assert json.loads(paths["witness"].read_text())["id"] == eid
    conn.close()


# --- paramstyle translation ----------------------------------------------

def test_placeholders_become_pyformat():
    assert to_pyformat("SELECT 1 WHERE a = ? AND b = ?") == (
        "SELECT 1 WHERE a = %s AND b = %s"
    )


def test_literal_percent_is_escaped():
    """psycopg consumes ``%`` during binding, so a LIKE pattern must double it."""
    assert to_pyformat("SELECT 1 WHERE k LIKE '%refus%'") == (
        "SELECT 1 WHERE k LIKE '%%refus%%'"
    )


def test_question_mark_inside_a_string_literal_is_not_a_placeholder():
    assert to_pyformat("SELECT '?' , ?") == "SELECT '?' , %s"


def test_question_mark_inside_a_quoted_identifier_survives():
    assert to_pyformat('SELECT "od?d" FROM t WHERE x = ?') == (
        'SELECT "od?d" FROM t WHERE x = %s'
    )


def test_doubled_quote_escape_does_not_end_the_literal():
    assert to_pyformat("SELECT 'it''s ?' , ?") == "SELECT 'it''s ?' , %s"


def test_dollar_quoted_body_is_untouched():
    sql = "CREATE FUNCTION f() AS $fn$ BEGIN x := '?'; y := 5 % 2; END; $fn$"
    assert to_pyformat(sql) == (
        "CREATE FUNCTION f() AS $fn$ BEGIN x := '?'; y := 5 %% 2; END; $fn$"
    )


def test_line_comment_is_untouched_except_for_percent():
    assert to_pyformat("SELECT 1 -- is ? a placeholder\n, ?") == (
        "SELECT 1 -- is ? a placeholder\n, %s"
    )


def test_block_comment_is_untouched():
    assert to_pyformat("SELECT /* ? */ 1, ?") == "SELECT /* ? */ 1, %s"


def test_the_consume_nonce_predicate_translates_intact():
    """The single most security-relevant statement in the codebase."""
    sql = (
        "UPDATE operator_nonces SET consumed_event = ? "
        "WHERE nonce = ? AND consumed_event IS NULL"
    )
    assert to_pyformat(sql) == (
        "UPDATE operator_nonces SET consumed_event = %s "
        "WHERE nonce = %s AND consumed_event IS NULL"
    )


def test_translation_is_cached_and_stable():
    sql = "SELECT ? , '%'"
    assert to_pyformat(sql) == to_pyformat(sql) == "SELECT %s , '%%'"
