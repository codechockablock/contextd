"""Move an archive from SQLite to Postgres without breaking its chain.

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

#: Authority-plane and bookkeeping tables, copied verbatim. Ordered so that
#: nothing depends on a table copied later.
_CARRIED_TABLES = (
    ("archive_identity", ("singleton", "uuid")),
    ("operator_sequence", ("singleton", "value")),
    ("operator_keys", ("key_id", "public_der", "signer", "registered", "revoked")),
    ("operator_nonces", ("nonce", "key_id", "sequence", "issued_at", "expires_at",
                         "action", "digest", "consumed_event")),
    ("redemptions", ("nonce", "intent_digest", "mandate_event", "bound_at",
                     "replay_until", "state", "outcome", "outcome_event",
                     "inflight_event")),
    ("service_keys", ("key_id", "public_pem", "created", "retired")),
    ("service_tips", ("tip_id", "chain_hash", "key_id", "signature", "signed_at",
                      "cutover")),
    ("service_signatures", ("event_id", "key_id", "digest", "signature",
                            "signed_at")),
    ("cursors", ("source", "state")),
)

_EVENT_COLUMNS = ("id", "ts", "source", "kind", "uri", "content", "content_hash",
                  "meta", "prev_hash", "chain_hash")


class MigrationError(RuntimeError):
    """The archive cannot be migrated without losing or forging evidence."""


def _placeholders(columns) -> str:
    return ", ".join("?" for _ in columns)


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
