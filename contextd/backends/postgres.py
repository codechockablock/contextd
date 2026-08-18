"""Multi-host backend: the chain tip lives in the database that holds the chain.

# Why the single-host protocol could not simply be pointed at Postgres

The shipped protocol's three safety steps are all local to one machine, and each
one fails differently across two hosts. This is not a driver swap:

1. `db._connection_root` derives the archive root from ``PRAGMA database_list``.
   A Postgres connection has no filesystem path, so the *first* line of the
   append path raises. An explicit archive root had to exist before anything
   else was reachable — see `pgdriver.PGConnection.archive_root`.
2. `fcntl.flock` is a kernel-local advisory lock on a local inode, and
   `chain_state_paths` puts that inode under `home()`, a per-process
   environment variable. Two hosts lock *their own file* and both enter the
   critical section at once. The exclusion the whole protocol rests on is not
   weakened across hosts; it is absent.
3. The next event id and `prev_hash` both come from the local witness file, so
   two hosts compute the *same* ``previous["id"] + 1``. The lucky outcome is a
   primary-key violation. The unlucky one is a forked chain: two rows claiming
   id N+1 over the same `prev_hash`, which `_verify_rows` — walking ``ORDER BY
   id`` and demanding `prev_hash` continuity — cannot even represent.
4. Recovery then false-alarms on every *healthy* cross-host append. Host A
   commits event 5 and finalizes its witness; host B's witness still says 4, so
   B's next connect sees ``current=5`` against ``witnessed=4`` and raises
   `ChainStateError`. A working two-host system reports its own ledger as
   tampered, with no crash anywhere.
5. The v2 journal makes that worse rather than better. Its safety argument
   assumes the enumerated outcomes are the only tips *anyone* could have
   committed. Host B's commit is by construction outside host A's outcome set;
   and in the case where A's stale witness happens to name a tip B produced,
   ``if witnessed in outcomes and current == witnessed`` deletes the journal and
   **accepts a tip it did not write**.

Every one of those five passes a naive single-machine smoke test.

# The design: the tip is a row, and the database enforces the chain

Tip state moves into the database, and the append transaction that inserts an
event is the same transaction that advances the tip. Concretely:

* `chain_tip` is a singleton row holding ``(id, chain_hash)``.
* An appender calls ``contextd_acquire_tip()``, which takes a ``FOR UPDATE`` row
  lock and returns the tip. That row lock is the replacement for `flock`: it is
  held to end of transaction, it is visible to every host on the cluster, and it
  makes concurrent appenders queue instead of colliding.
* A ``BEFORE INSERT`` trigger on `events` re-checks that ``NEW.id`` is exactly
  ``tip.id + 1`` and ``NEW.prev_hash`` is exactly ``tip.chain_hash``, then
  advances the tip itself.

That last point is what makes this a protocol rather than a convention. Chain
continuity is **not** something the client is trusted to get right — a client
that computes the wrong id, replays a stale tip, or tries to fork gets an
exception from the database. The ``FOR UPDATE`` exists so that honest
concurrent appenders *queue* rather than all failing that check and needing a
retry loop the codebase does not have.

**There is no recovery journal and no witness file, because there is no
two-sided state left to adjudicate.** The single-host protocol needs them
precisely because the tip lives outside the transaction: a crash can land
between the commit and the witness write. Here the event row and the tip it
produces are one commit. A crash either takes both or neither, and the next
connection sees a consistent tip with nothing to reconcile. Removing an
interrupted-state adjudicator by removing the interrupted state is a real
simplification, not a shortcut.

# The security decision, stated plainly

Moving the tip into the database **collapses a two-artifact tamper check into
one**, and that is a genuine loss which no amount of Postgres machinery undoes.
Under the SQLite protocol an attacker who rewrites history must forge the ledger
*and* a file outside it. Here, an attacker with sufficient database privilege
can rewrite the chain and the thing that witnesses it in a single transaction,
and the result is internally consistent.

The ruling is that this trade is **worth taking, but only alongside the
privilege split below and an out-of-band checkpoint**, for three reasons.

*First, the separation being given up is weaker than it appears on SQLite.*
There, the witness file and the database are two files in one directory under
one uid. Any process that can rewrite `events` can rewrite `chain-witness.json`
a microsecond later. The check is real against a careless or protocol-ignorant
mutation and against non-malicious corruption; it was never a privilege boundary
against a deliberate same-uid attacker, and `_verify_rows` says as much —
*"tamper-evident, not tamper-proof."*

*Second, Postgres creates a separation that SQLite never had, along a different
axis.* On SQLite, "can write the database" and "can write the witness" are the
same capability, because the database **is** a file. On Postgres they are not:
a role reaching the archive over a socket has no filesystem on the application
host at all. So the honest accounting is not "two artifacts became one" but
"a filesystem-adjacency separation was traded for a privilege separation" —
and the privilege separation is enforced by the database on every statement,
where the file separation was enforced by nothing.

*Third, and decisively, the privilege separation can be made real, and is.*
`harden_roles` grants the application role ``INSERT`` and ``SELECT`` on `events`
and **not** ``UPDATE``, ``DELETE``, or ``TRUNCATE``; a PL/pgSQL trigger refuses
all three regardless; and the tip is advanced only by a ``SECURITY DEFINER``
function, so the application role holds no write privilege on `chain_tip`
either. The consequence is the property that actually matters: **the credential
contextd itself uses cannot rewrite history or forge the tip.** SQLite has no
counterpart — there, the appending process is the file's owner and can
``DROP TRIGGER`` at will.

What this does **not** defend against, stated without hedging: a Postgres
superuser, the table owner, or root on the database host can disable the
triggers, rewrite `events`, and set `chain_tip` to match. Against that actor the
in-database tip is worth nothing, and the SQLite deployment — where the same
actor would additionally need write access to a *different machine's*
filesystem — was strictly better. Closing that gap requires a tip attested
outside the database, which is a periodic signed checkpoint (`service_tips`,
Lane 3), not a per-append file. Per-append is exactly the shape that does not
port. This backend therefore treats the in-database tip as the concurrency and
continuity authority, and an external checkpoint as the anti-owner-tampering
authority, and does not pretend either one does the other's job.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .base import AppendScope, StorageBackend
from .pgdriver import PGConnection

#: Environment variable selecting this backend. Absent means SQLite, so an
#: existing single-host install is untouched and nothing is auto-migrated.
DATABASE_URL_ENV = "CONTEXTD_DATABASE_URL"

#: Version 3 added the ``alg`` column to the three signature tables and the
#: `service_checkpoints` table, bringing this schema level with `db.SCHEMA`.
#: Their absence was not cosmetic: `ledger_sig._load_or_create_key` inserts
#: ``alg`` unconditionally, so a Postgres archive could not register a service
#: key at all — which silently disabled **manifest signing for every backup
#: taken from one**, and would have crashed the append path of any archive
#: migrated in past its signed cutover.
SCHEMA_VERSION = 4

#: Arbitrary fixed key for the bootstrap advisory lock. Scoped to schema
#: creation only; the append path never takes it.
BOOTSTRAP_LOCK_KEY = 0x63747864_00000001

#: Enforcement that must be present before an archive may be opened at all.
REQUIRED_TRIGGERS = frozenset(
    {"events_no_update", "events_no_delete", "events_no_truncate",
     "events_chain_advance"}
)

#: `id` is assigned by the append protocol, never by a sequence: the chain
#: hash covers it, so it has to be known before the row exists. `meta` stays
#: TEXT holding JSON so the stored bytes — which the chain hash is computed
#: over — are byte-identical to what SQLite stores.
SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  version   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id           BIGINT PRIMARY KEY,
  ts           TEXT NOT NULL,
  source       TEXT NOT NULL,
  kind         TEXT NOT NULL,
  uri          TEXT,
  content      TEXT,
  content_hash TEXT,
  meta         TEXT,
  prev_hash    TEXT,
  chain_hash   TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_uri ON events(uri, id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_refusal_by_nonce
  ON events (((meta::jsonb) ->> 'nonce')) WHERE kind = 'refuse';
CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_outcome_once
  ON events (((meta::jsonb) ->> 'egress_id')) WHERE kind = 'egress_outcome';

CREATE TABLE IF NOT EXISTS chain_tip (
  singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
  id         BIGINT NOT NULL,
  chain_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cursors (
  source TEXT PRIMARY KEY,
  state  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operator_keys (
  key_id     TEXT PRIMARY KEY,
  public_der BYTEA NOT NULL,
  signer     TEXT NOT NULL,
  registered TEXT NOT NULL,
  revoked    TEXT
);
CREATE TABLE IF NOT EXISTS operator_nonces (
  nonce          TEXT PRIMARY KEY,
  key_id         TEXT NOT NULL,
  sequence       BIGINT NOT NULL,
  issued_at      BIGINT NOT NULL,
  expires_at     BIGINT NOT NULL,
  action         TEXT NOT NULL,
  digest         TEXT NOT NULL,
  consumed_event BIGINT
);
CREATE TABLE IF NOT EXISTS operator_sequence (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  value     BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS redemptions (
  nonce          TEXT PRIMARY KEY,
  intent_digest  TEXT NOT NULL,
  mandate_event  BIGINT NOT NULL,
  bound_at       BIGINT NOT NULL,
  replay_until   BIGINT NOT NULL,
  state          TEXT NOT NULL CHECK (state IN ('inflight', 'executed')),
  outcome        TEXT,
  outcome_event  BIGINT,
  inflight_event BIGINT
);
CREATE TABLE IF NOT EXISTS archive_identity (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  uuid      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_keys (
  key_id     TEXT PRIMARY KEY,
  public_pem TEXT NOT NULL,
  created    BIGINT NOT NULL,
  retired    BIGINT,
  alg        TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256'
);
CREATE TABLE IF NOT EXISTS service_signatures (
  event_id  BIGINT PRIMARY KEY,
  key_id    TEXT NOT NULL,
  digest    TEXT NOT NULL,
  signature TEXT NOT NULL,
  signed_at BIGINT NOT NULL,
  alg       TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256'
);
CREATE TABLE IF NOT EXISTS service_tips (
  tip_id     BIGINT PRIMARY KEY,
  chain_hash TEXT NOT NULL,
  key_id     TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_at  BIGINT NOT NULL,
  cutover    INTEGER NOT NULL DEFAULT 0,
  alg        TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256'
);
CREATE TABLE IF NOT EXISTS service_checkpoints (
  tip_id     BIGINT NOT NULL,
  alg        TEXT NOT NULL,
  chain_hash TEXT NOT NULL,
  key_id     TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_at  BIGINT NOT NULL,
  PRIMARY KEY (tip_id, alg)
);
"""

#: Additive DDL for an archive created by an older build, keyed by the version
#: it is being lifted *from*. Deliberately separate from ``SCHEMA`` and applied
#: **without** ``PROTOCOL``: re-running the trigger DDL on an initialized
#: archive would silently recreate a dropped append-only trigger and repair away
#: the only evidence that history was mutable — the exact hazard
#: ``_assert_protocol_installed`` exists to make loud.
UPGRADES = {
    version: """
ALTER TABLE service_keys
  ADD COLUMN IF NOT EXISTS alg TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256';
ALTER TABLE service_signatures
  ADD COLUMN IF NOT EXISTS alg TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256';
ALTER TABLE service_tips
  ADD COLUMN IF NOT EXISTS alg TEXT NOT NULL DEFAULT 'ecdsa-p256-sha256';
CREATE TABLE IF NOT EXISTS service_checkpoints (
  tip_id     BIGINT NOT NULL,
  alg        TEXT NOT NULL,
  chain_hash TEXT NOT NULL,
  key_id     TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_at  BIGINT NOT NULL,
  PRIMARY KEY (tip_id, alg)
);
"""
    for version in (1, 2)
}
UPGRADES[3] = """
CREATE INDEX IF NOT EXISTS idx_refusal_by_nonce
  ON events (((meta::jsonb) ->> 'nonce')) WHERE kind = 'refuse';
"""

#: Append-only is enforced by the database, and the trigger covers TRUNCATE as
#: well as UPDATE and DELETE — a row-level trigger alone would not fire for
#: TRUNCATE, which is exactly how an append-only table gets emptied in practice.
#:
#: ``contextd_chain_advance`` is where multi-host chain safety actually lives.
#: It re-derives continuity from the tip row under the caller's transaction, so
#: a client that computed the wrong id — because it raced, because it cached a
#: stale tip, or because it is hostile — is refused by the database rather than
#: forking the chain. It is SECURITY DEFINER so the application role needs no
#: write privilege on `chain_tip`, and its ``search_path`` is pinned because a
#: SECURITY DEFINER function with a caller-controlled search path is a classic
#: privilege-escalation shape.
PROTOCOL = """
CREATE OR REPLACE FUNCTION contextd_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
  RAISE EXCEPTION 'events are append-only';
END;
$fn$;

CREATE OR REPLACE TRIGGER events_no_update BEFORE UPDATE ON events
  FOR EACH ROW EXECUTE FUNCTION contextd_events_append_only();
CREATE OR REPLACE TRIGGER events_no_delete BEFORE DELETE ON events
  FOR EACH ROW EXECUTE FUNCTION contextd_events_append_only();
CREATE OR REPLACE TRIGGER events_no_truncate BEFORE TRUNCATE ON events
  FOR EACH STATEMENT EXECUTE FUNCTION contextd_events_append_only();

CREATE OR REPLACE FUNCTION contextd_acquire_tip()
RETURNS chain_tip
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
  tip chain_tip;
BEGIN
  SELECT * INTO tip FROM chain_tip WHERE singleton = 1 FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'chain tip row is missing';
  END IF;
  RETURN tip;
END;
$fn$;

CREATE OR REPLACE FUNCTION contextd_chain_advance() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
  tip chain_tip;
BEGIN
  SELECT * INTO tip FROM chain_tip WHERE singleton = 1 FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'chain tip row is missing';
  END IF;
  IF NEW.id <> tip.id + 1 THEN
    RAISE EXCEPTION 'event id % does not extend chain tip %', NEW.id, tip.id;
  END IF;
  IF coalesce(NEW.prev_hash, '') <> tip.chain_hash THEN
    RAISE EXCEPTION 'event % does not chain onto the current tip', NEW.id;
  END IF;
  UPDATE chain_tip SET id = NEW.id, chain_hash = coalesce(NEW.chain_hash, '')
   WHERE singleton = 1;
  RETURN NEW;
END;
$fn$;

CREATE OR REPLACE TRIGGER events_chain_advance BEFORE INSERT ON events
  FOR EACH ROW EXECUTE FUNCTION contextd_chain_advance();
"""


class PostgresUnavailable(RuntimeError):
    """psycopg is not installed, or no database URL is configured."""


def database_url() -> str | None:
    url = os.environ.get(DATABASE_URL_ENV, "").strip()
    return url or None


def _psycopg():
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise PostgresUnavailable(
            "the postgres backend requires psycopg 3 (pip install 'psycopg[binary]')"
        ) from exc
    return psycopg


class PostgresAppendScope(AppendScope):
    """Append under a tip row lock, with the tip advanced by the same commit."""

    def __init__(self, conn: PGConnection):
        self._conn = conn
        self.previous = {"id": 0, "chain_hash": ""}

    def acquire(self) -> dict:
        # BEGIN first: the row lock must belong to the append's own transaction,
        # or it is released before the INSERT it is supposed to protect.
        self._conn.execute("BEGIN")
        row = self._conn.execute(
            "SELECT (t).id AS id, (t).chain_hash AS chain_hash "
            "FROM contextd_acquire_tip() AS t"
        ).fetchone()
        self.previous = {"id": int(row["id"]), "chain_hash": row["chain_hash"] or ""}
        return self.previous

    def declare(self, outcomes: list[dict]) -> None:
        """No-op: nothing durable is written outside the transaction."""

    def open_transaction(self) -> None:
        """No-op: :meth:`acquire` already opened it, and had to."""

    def record_tip(self, tip: dict) -> None:
        """No-op: ``events_chain_advance`` advanced the tip during the INSERT.

        Deliberately not a client-side ``UPDATE chain_tip``. If advancing the tip
        were the client's job, a client could advance it inconsistently with the
        row it inserted; doing it in the insert trigger makes the tip a
        *derivation* of the chain rather than a claim about it.
        """

    def publish(self, tip: dict) -> None:
        """No-op: the tip became durable with the event, in one commit."""

    def abandon(self, *, committed: bool) -> None:
        if not committed:
            self._conn.rollback()


class PostgresBackend(StorageBackend):
    name = "postgres"
    #: FTS5 has no equivalent here and `ts_rank` is not `bm25`. Declared out of
    #: scope rather than silently substituted — see `base.py`.
    supports_search = False
    #: REVOKE plus a trigger the application role cannot drop. This is the one
    #: place Postgres is unambiguously stronger than SQLite.
    enforces_append_only_in_db = True

    def __init__(self, url: str | None = None, archive_root: Path | None = None):
        self._url = url or database_url()
        if not self._url:
            raise PostgresUnavailable(
                f"the postgres backend requires {DATABASE_URL_ENV} to be set"
            )
        self._archive_root = archive_root

    # -- connection -------------------------------------------------------

    def raw_connect(self) -> PGConnection:
        """Connect and apply nothing. Used by the version probe and by tests."""
        from .. import home

        psycopg = _psycopg()
        connection = psycopg.connect(self._url, autocommit=True)
        return PGConnection(
            connection, archive_root=self._archive_root or home()
        )

    def connect(self) -> PGConnection:
        """Open, bootstrapping schema exactly once even if two hosts start together.

        Bootstrap is the one place the single-host protocol got mutual exclusion
        for free — `flock` serialized it — and losing that is not theoretical.
        Two hosts calling ``connect`` simultaneously both run ``CREATE OR
        REPLACE``, and Postgres aborts one with *"tuple concurrently updated"*
        on the shared catalog row. The multi-host proof hit this on its first
        run with two hosts.

        The fix is a transaction-scoped advisory lock around the whole
        bootstrap. That is the database serializing its own DDL, not added
        coordination infrastructure — and note it is confined to bootstrap: the
        **append** path takes no advisory lock, only the `chain_tip` row lock.
        """
        conn = self.raw_connect()
        # A server-backed archive still has a filesystem side: the blob store,
        # scratch, the service signing key, config.toml, and the directory a
        # backup names as its source all live under the archive root.
        # `connect_sqlite` creates it as a side effect of creating the database
        # file; nothing did here, so a fresh Postgres archive worked until the
        # first oversized ingest or the first backup and then failed on a
        # missing directory.
        try:
            root = Path(conn.archive_root)
            root.mkdir(parents=True, exist_ok=True)
            os.chmod(root, 0o700)
        except BaseException:
            conn.close()
            raise
        try:
            conn.execute("BEGIN")
            conn.execute("SELECT pg_advisory_xact_lock(?)", (BOOTSTRAP_LOCK_KEY,))
            version = self._assert_supported_schema(conn)
            # The discriminator is whether this archive was ever initialized,
            # **not** whether the enforcement is currently present. Re-running
            # the DDL because a trigger is missing would silently recreate a
            # dropped append-only trigger and repair away the only evidence that
            # history was mutable. An initialized archive therefore gets no DDL
            # and is checked instead, below.
            if version == 0:
                conn.run_ddl(SCHEMA)
                conn.run_ddl(PROTOCOL)
            elif version < SCHEMA_VERSION:
                # An initialized archive gets additive DDL only, so lifting its
                # schema version can never resurrect enforcement it lost.
                conn.run_ddl(UPGRADES[version])
            if version < SCHEMA_VERSION:
                conn.execute(
                    "INSERT INTO schema_meta (singleton, version) VALUES (1, ?) "
                    "ON CONFLICT (singleton) DO UPDATE SET version = excluded.version",
                    (SCHEMA_VERSION,),
                )
            self._bootstrap_tip(conn)
            self._assert_protocol_installed(conn)
            conn.commit()
        except BaseException:
            conn.close()
            raise
        return conn

    @staticmethod
    def _installed_triggers(conn: PGConnection) -> set[str]:
        return {
            row[0]
            for row in conn.execute(
                "SELECT tgname FROM pg_trigger t JOIN pg_class c "
                "ON c.oid = t.tgrelid WHERE c.relname = 'events' "
                "AND NOT t.tgisinternal"
            )
        }

    def _assert_protocol_installed(self, conn: PGConnection) -> None:
        """Refuse to open an archive whose enforcement triggers are missing.

        The append-only and chain-continuity triggers are the enforcement, not a
        convenience. If one has been dropped, the correct response is to refuse
        the connection loudly — recreating it would erase the only signal that
        history was writable in the interval.
        """
        from ..db import ChainStateError

        missing = REQUIRED_TRIGGERS - self._installed_triggers(conn)
        if missing:
            raise ChainStateError(
                "the archive's append-only enforcement is not installed: "
                f"missing trigger(s) {', '.join(sorted(missing))}. Refusing to "
                "open; recreating them would hide that history was mutable."
            )

    def _assert_supported_schema(self, conn: PGConnection) -> int:
        """Refuse a newer archive **before** any DDL runs.

        SQLite reads ``PRAGMA user_version``, which exists on an empty file.
        Postgres has no such slot, so the version lives in a `schema_meta` table
        — and that table is itself schema this refusal is supposed to precede.
        The way out is that ``to_regclass`` is a catalog lookup: it answers
        "does this table exist" without creating it and without erroring when it
        does not. A NULL answer means a fresh database, which is not a version
        problem, exactly as a missing file is not one for SQLite.
        """
        from ..db import SchemaVersionError

        exists = conn.execute("SELECT to_regclass('schema_meta') AS t").fetchone()
        if exists["t"] is None:
            return 0
        row = conn.execute(
            "SELECT version FROM schema_meta WHERE singleton = 1"
        ).fetchone()
        version = int(row["version"]) if row else 0
        if version > SCHEMA_VERSION:
            raise SchemaVersionError(
                f"archive was written by a newer contextd (schema version "
                f"{version}; this build supports {SCHEMA_VERSION}). Refusing "
                f"before any schema change."
            )
        return version

    def _bootstrap_tip(self, conn: PGConnection) -> None:
        """Create the tip row, deriving it from history if there is any."""
        if conn.execute("SELECT 1 FROM chain_tip WHERE singleton = 1").fetchone():
            return
        tip = self.db_tip(conn)
        conn.execute(
            "INSERT INTO chain_tip (singleton, id, chain_hash) VALUES (1, ?, ?) "
            "ON CONFLICT (singleton) DO NOTHING",
            (tip["id"], tip["chain_hash"]),
        )

    # -- protocol ---------------------------------------------------------

    def db_tip(self, conn) -> dict:
        row = conn.execute(
            "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return (
            {"id": int(row["id"]), "chain_hash": row["chain_hash"] or ""}
            if row
            else {"id": 0, "chain_hash": ""}
        )

    def json_field(self, column: str, key: str) -> str:
        # An explicit raise, not an assert: asserts vanish under python -O,
        # and this check is the whole injection contract for the f-string.
        if not key.isidentifier():
            raise ValueError("json_field key must be a static identifier")
        return f"(({column})::jsonb ->> '{key}')"

    def table_names(self, conn) -> set[str]:
        return {
            row[0]
            for row in conn.execute(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname = ANY(current_schemas(false))"
            )
        }

    @contextmanager
    def append_scope(self, conn) -> Iterator[PostgresAppendScope]:
        yield PostgresAppendScope(conn)

    def verify_tip(self, conn, root: Path | None = None) -> None:
        """Cross-check the recorded tip against the chain's actual last row.

        These are maintained in lockstep by ``events_chain_advance``, so a
        divergence means someone wrote to `events` with that trigger disabled or
        dropped — i.e. the table owner or a superuser, the actors named in the
        module docstring. It is a weaker check than the SQLite witness against a
        filesystem-adjacent attacker and a stronger one against an application
        -role attacker, and it is not a substitute for a signed external
        checkpoint.
        """
        from ..db import ChainStateError

        row = conn.execute(
            "SELECT id, chain_hash FROM chain_tip WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise ChainStateError("chain tip row is missing")
        recorded = {"id": int(row["id"]), "chain_hash": row["chain_hash"] or ""}
        current = self.db_tip(conn)
        if current != recorded:
            raise ChainStateError(
                f"database tip {current['id']} does not match recorded tip "
                f"{recorded['id']}"
            )

    def reconcile(self, conn, root: Path | None = None) -> dict:
        """Nothing to reconcile: an append is one transaction, so it is atomic.

        Returning the tip after verifying it keeps the call site identical to
        SQLite's, where this genuinely does complete an interrupted append.
        """
        self.verify_tip(conn, root)
        return self.db_tip(conn)


APPENDER_GRANTS = """
GRANT USAGE ON SCHEMA public TO {role};
GRANT SELECT, INSERT ON events TO {role};
GRANT SELECT ON chain_tip TO {role};
GRANT SELECT ON schema_meta TO {role};
GRANT SELECT, INSERT, UPDATE, DELETE ON
  cursors, operator_keys, operator_nonces, operator_sequence, redemptions,
  archive_identity, service_keys, service_signatures, service_tips,
  service_checkpoints TO {role};
GRANT EXECUTE ON FUNCTION contextd_acquire_tip() TO {role};
REVOKE UPDATE, DELETE, TRUNCATE ON events FROM {role};
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON chain_tip FROM {role};
"""


def harden_roles(conn: PGConnection, role: str) -> None:
    """Give ``role`` the least privilege an appender can actually run on.

    The point of this function is the two ``REVOKE`` lines, and the property
    they buy is the one the module docstring rests on: **the credential contextd
    uses cannot rewrite history or forge the tip.** It can add events and it can
    consume nonces, which is all the append protocol needs. Chain continuity is
    checked, and the tip advanced, by SECURITY DEFINER code the role may execute
    but not modify.

    SQLite has no counterpart. There the appending process owns the file and can
    ``DROP TRIGGER events_no_update`` before its next statement.
    """
    if not role.replace("_", "").isalnum():
        raise ValueError("role name must be alphanumeric")
    conn.executescript(APPENDER_GRANTS.format(role=role))
