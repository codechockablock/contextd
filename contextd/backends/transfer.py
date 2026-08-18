"""Move an archive between SQLite and Postgres without breaking its chain.

Both directions live here, and they are deliberately asymmetric.

``migrate_sqlite_to_postgres`` is a *cutover*: the destination becomes the live
archive. ``export_postgres_to_sqlite`` is a *materialization*: it renders a
Postgres archive as one ordinary SQLite archive file, which is what makes the
`.ctxbackup` bundle and the frozen-view machinery work against a server-backed
archive without either of them growing a second format. A bundle is a bundle
whatever produced it, so `validate_bundle`, `restore_backup`, and every
adversarial-bundle test apply unchanged — see `backup.py`.


The chain hash covers ``(prev_hash, id, ts, source, kind, uri, content,
content_hash, meta)`` and nothing else — not the file it lives in, not the
backend, not the host. So a row-for-row copy that preserves those nine fields
byte-for-byte reproduces every `chain_hash` exactly, and the migrated archive
verifies against the same history it had before. That is what "preserving chain
verifiability" means here, and it is checked on both sides rather than asserted.

The pleasing part is that the migration needs no special trust. Events are
copied in ascending id order, through the ordinary ``INSERT`` path, so the
``events_chain_advance`` trigger validates continuity on **every** row exactly
as it does for a live append. A source archive with a forked, truncated, or
rewritten chain cannot be imported: the trigger rejects the first row that does
not extend the tip. The importer is not trusted to check the chain; it is
structurally unable to import a broken one.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

#: Authority-plane and bookkeeping tables, copied verbatim. Ordered so that
#: nothing depends on a table copied later.
#:
#: ``alg`` is carried on all three signature tables and `service_checkpoints` is
#: carried at all only since the Postgres schema gained them (schema version 3).
#: Dropping them was not cosmetic: a signature record whose scheme tag is lost
#: falls back to "the only scheme that existed when the column did not", so an
#: ML-DSA checkpoint key would have been silently relabelled P-256 and every
#: signature under it would have stopped verifying on the far side.
_CARRIED_TABLES = (
    ("archive_identity", ("singleton", "uuid")),
    ("operator_sequence", ("singleton", "value")),
    ("operator_keys", ("key_id", "public_der", "signer", "registered", "revoked")),
    ("operator_nonces", ("nonce", "key_id", "sequence", "issued_at", "expires_at",
                         "action", "digest", "consumed_event")),
    ("redemptions", ("nonce", "intent_digest", "mandate_event", "bound_at",
                     "replay_until", "state", "outcome", "outcome_event",
                     "inflight_event")),
    ("service_keys", ("key_id", "public_pem", "created", "retired", "alg")),
    ("service_tips", ("tip_id", "chain_hash", "key_id", "signature", "signed_at",
                      "cutover", "alg")),
    ("service_signatures", ("event_id", "key_id", "digest", "signature",
                            "signed_at", "alg")),
    ("service_checkpoints", ("tip_id", "alg", "chain_hash", "key_id", "signature",
                             "signed_at")),
    ("cursors", ("source", "state")),
)

_EVENT_COLUMNS = ("id", "ts", "source", "kind", "uri", "content", "content_hash",
                  "meta", "prev_hash", "chain_hash")


class MigrationError(RuntimeError):
    """The archive cannot be migrated without losing or forging evidence."""


def _placeholders(columns) -> str:
    return ", ".join("?" for _ in columns)


class ExportError(RuntimeError):
    """A Postgres archive could not be rendered as a SQLite archive."""


def _snapshot_scope(source):
    """Read everything below through ONE repeatable-read snapshot.

    Event rows are immutable, so a tip-bounded read of `events` would be stable
    even under ``READ COMMITTED``. The authority plane is not: nonces are
    consumed and redemptions transition while a backup runs, and a per-statement
    snapshot could copy `events` from before a redemption and `operator_nonces`
    from after it — producing a bundle in which an authorization looks spent
    with no act, or unspent after one. That is precisely the two-sided state the
    single-host protocol goes to such lengths to make unrepresentable, so it is
    not acceptable to reintroduce it in the backup path.

    Returns True if this call opened the transaction and must close it. A caller
    already inside one keeps its own snapshot; nesting would raise.
    """
    if source.in_transaction:
        return False
    source.execute("BEGIN")
    source.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
    return True


def export_postgres_to_sqlite(
    source, destination, *, up_to: int | None = None, carried: bool = True
) -> dict:
    """Render a Postgres archive as one standalone SQLite archive file.

    The result is not a lossy report about the archive; it is an archive. It
    carries `db.SCHEMA` verbatim — including the FTS index, which is rebuilt by
    the ordinary insert trigger rather than copied — is stamped with the current
    ``user_version``, and verifies with `db._verify_rows` before this function
    returns. That is what lets `backup.create_backup` emit the *same*
    `.ctxbackup` bundle from either backend instead of forking the format, and
    it is why a bundle taken from Postgres restores into a working SQLite
    archive rather than into something that merely inspects.

    ``up_to`` truncates at an event id, which the chain permits because it is
    prefix-closed (`handoff.freeze_view` relies on the same property).
    ``carried`` is False for a frozen view, which by contract copies history and
    nothing operational.

    **The reverse is out of scope.** Restoring a bundle *into* a Postgres
    archive is not supported: `restore_backup` publishes a directory with one
    rename, and there is no rename for a database cluster. Move a restored
    SQLite archive onto a server with `migrate_sqlite_to_postgres`, which
    re-inserts every row through the chain-continuity trigger — a fail-closed
    path, where a "restore straight into Postgres" would be a second, less
    checked way to populate `events`.
    """
    from ..db import SCHEMA as SQLITE_SCHEMA
    from ..db import SCHEMA_VERSION, _verify_rows

    destination = Path(destination)
    # Checked before the source is touched at all: opening a transaction on a
    # live archive only to refuse on a local path would be a needless snapshot.
    if destination.exists():
        raise ExportError(f"export destination already exists: {destination}")
    opened = _snapshot_scope(source)
    try:
        tip_sql = "SELECT id, chain_hash FROM events"
        params: tuple = ()
        if up_to is not None:
            tip_sql += " WHERE id <= ?"
            params = (up_to,)
        tip_row = source.execute(
            tip_sql + " ORDER BY id DESC LIMIT 1", params
        ).fetchone()
        tip = (
            {"id": int(tip_row["id"]), "chain_hash": tip_row["chain_hash"] or ""}
            if tip_row
            else {"id": 0, "chain_hash": ""}
        )

        # The tip the DATABASE attests, read inside the same snapshot as the
        # rows. A full export whose `chain_tip` disagrees with `events` is
        # refused here rather than rendered into a bundle: that disagreement is
        # the one signal a Postgres archive has that history was written with
        # the continuity trigger disabled (`postgres.py`, "The security
        # decision"), and a backup must not launder it into a bundle that
        # validates. A truncated export (`up_to`) is exempt, because its head is
        # deliberately behind the tip.
        attested = tip
        if up_to is None:
            from . import backend_for

            backend = backend_for(source)
            backend.verify_tip(source)
            attested = backend.db_tip(source)

        destination.parent.mkdir(parents=True, exist_ok=True)
        dest = sqlite3.connect(destination)
        try:
            os.chmod(destination, 0o600)
            dest.row_factory = sqlite3.Row
            dest.executescript(SQLITE_SCHEMA)
            # Written from the current schema by construction, so it is
            # current-version by definition. Without the stamp it reads as
            # version 0 and the migration guard refuses to open it.
            dest.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            dest.execute("BEGIN")

            counts: dict[str, int] = {}
            if carried:
                for table, columns in _CARRIED_TABLES:
                    rows = source.execute(
                        f"SELECT {', '.join(columns)} FROM {table}"
                    ).fetchall()
                    for row in rows:
                        dest.execute(
                            f"INSERT INTO {table} ({', '.join(columns)}) "
                            f"VALUES ({_placeholders(columns)})",
                            tuple(_sqlite_value(row[c]) for c in columns),
                        )
                    counts[table] = len(rows)

            events = 0
            for row in source.execute(
                f"SELECT {', '.join(_EVENT_COLUMNS)} FROM events "
                f"WHERE id <= ? ORDER BY id",
                (tip["id"],),
            ).fetchall():
                dest.execute(
                    f"INSERT INTO events ({', '.join(_EVENT_COLUMNS)}) "
                    f"VALUES ({_placeholders(_EVENT_COLUMNS)})",
                    tuple(_sqlite_value(row[c]) for c in _EVENT_COLUMNS),
                )
                events += 1
            # The witness bookkeeping row a SQLite archive carries. The
            # `chain-witness.json` file that pairs with it is the caller's to
            # write, because only the caller knows where the archive root is.
            dest.execute(
                "INSERT INTO chain_state(singleton, witness_initialized) "
                "VALUES (1, 1)"
            )
            dest.commit()

            verified = _verify_rows(dest)
            if not verified["ok"]:
                raise ExportError(
                    f"exported archive does not verify at #{verified['first_bad']}"
                )
            if verified["checked"] != events:
                raise ExportError(
                    f"exported archive verified {verified['checked']} events but "
                    f"{events} were written"
                )
        finally:
            dest.close()
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if opened:
            source.rollback()
    return {"events": events, "tip": tip, "attested_tip": attested,
            "carried": counts}


def _sqlite_value(value):
    """Adapt one psycopg value to something ``sqlite3`` will bind.

    ``bytea`` comes back as ``bytes`` on psycopg 3 but as ``memoryview`` under
    some binary-mode paths, and sqlite3 refuses the latter. Everything else the
    schema uses (TEXT, BIGINT, INTEGER, NULL) already maps one-to-one, which is
    what keeps the exported bytes — and therefore every chain hash — identical.
    """
    return bytes(value) if isinstance(value, memoryview) else value


def migrate_sqlite_to_postgres(source, dest, *, progress=None) -> dict:
    """Copy a verified SQLite archive into an empty Postgres archive.

    ``source`` is an open SQLite connection, ``dest`` an open Postgres one from
    :class:`~contextd.backends.postgres.PostgresBackend`. Returns a summary
    including the verification result on both sides.

    Refuses in three situations, all of which would otherwise produce an archive
    that verifies but is not the history it claims to be:

    * the source does not verify — migrating a broken chain would launder it
      into a chain that verifies on the destination, because the destination
      only ever sees the rows that arrived;
    * the destination already holds events — appending one history onto another
      re-parents rows onto a tip they were never chained to;
    * the copy does not verify afterwards.
    """
    from ..db import verify_chain_read_only

    before = verify_chain_read_only(source)
    if not before["ok"]:
        raise MigrationError(
            f"refusing to migrate: the source archive does not verify "
            f"({before}). Migrating it would launder a broken chain into one "
            f"that verifies on the destination."
        )

    existing = dest.execute("SELECT count(*) AS n FROM events").fetchone()["n"]
    if existing:
        raise MigrationError(
            f"refusing to migrate into a non-empty archive ({existing} events): "
            "the imported rows would be re-parented onto a tip they were never "
            "chained to."
        )

    carried: dict[str, int] = {}
    dest.execute("BEGIN")
    try:
        for table, columns in _CARRIED_TABLES:
            rows = source.execute(
                f"SELECT {', '.join(columns)} FROM {table}"
            ).fetchall()
            for row in rows:
                dest.execute(
                    f"INSERT INTO {table} ({', '.join(columns)}) "
                    f"VALUES ({_placeholders(columns)})",
                    tuple(row[c] for c in columns),
                )
            carried[table] = len(rows)

        copied = 0
        # Ascending id, one row at a time, through the ordinary INSERT path:
        # ``events_chain_advance`` therefore validates continuity on every row,
        # and a broken source fails here rather than importing silently.
        for row in source.execute(
            f"SELECT {', '.join(_EVENT_COLUMNS)} FROM events ORDER BY id"
        ).fetchall():
            dest.execute(
                f"INSERT INTO events ({', '.join(_EVENT_COLUMNS)}) "
                f"VALUES ({_placeholders(_EVENT_COLUMNS)})",
                tuple(row[c] for c in _EVENT_COLUMNS),
            )
            copied += 1
            if progress is not None and copied % 500 == 0:
                progress(copied)
        dest.commit()
    except BaseException:
        dest.rollback()
        raise

    after = verify_chain_read_only(dest)
    if not after["ok"]:
        raise MigrationError(f"migrated archive does not verify: {after}")
    if after["checked"] != before["checked"]:
        raise MigrationError(
            f"migrated archive verified {after['checked']} events but the "
            f"source had {before['checked']}"
        )
    return {
        "events": copied,
        "carried": carried,
        "source_verification": before,
        "destination_verification": after,
    }
