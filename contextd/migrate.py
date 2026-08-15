"""Migrate a pre-hardening archive, without changing a single historical byte.

The contract, and the reason it is stated this strongly: an append-only
personal archive whose history can be rewritten by its own migration tool is
not append-only. So this module's central design choice is that **it never
issues an UPDATE or DELETE against `events`**. Everything it does is either

* creating/inserting auxiliary authority tables,
* privacy-cleaning mutable scanner cursors transactionally, or
* validating the content-addressed blob store and tightening its modes,

and the event rows are read exactly twice: once to fingerprint them before,
once to prove the fingerprint is unchanged after.

What migration therefore *is*: the archive gains the authority-plane tables, a
signed cutover checkpoint adopting its existing tip, privacy-clean operational
state, private blob modes, and a schema stamp.

What migration is **not**, and must never be read as:

* it does not re-sign, re-label, or re-interpret any historical event;
* the cutover signature attests "the service observed this tip at this time"
  and says nothing whatsoever about anything before it;
* every historical `actor` / `authority` / `role` / `client` label keeps its
  bytes and keeps resolving `legacy_unverified` (contextd/assurance.py).

Crash safety falls out of the same choice. No step mutates event history;
cursor replacement is one SQLite transaction and permission tightening is
idempotent. An interruption leaves either the prior cursor set or the complete
new one, and re-running finishes any remaining auxiliary/permission work.
"""

import hashlib
import json
import os
import stat

from .canonical import canonical_digest
from .db import SCHEMA as DB_SCHEMA
from .db import SCHEMA_VERSION, SchemaVersionError, verify_chain_read_only

#: Schema versions this build can migrate *from*.
MIGRATABLE_FROM = (0, 1, 2)

HISTORICAL_COLUMNS = (
    "id", "ts", "source", "kind", "uri", "content", "content_hash",
    "meta", "prev_hash", "chain_hash",
)


class MigrationError(RuntimeError):
    """The archive cannot be migrated safely."""


def fingerprint(conn, up_to: int | None = None) -> dict:
    """A byte-level fingerprint of history, optionally bounded at an event id.

    Every column that carries historical meaning is folded in, in id order, so
    a change to any one of them — a rewritten timestamp, a re-serialized meta
    blob, a recomputed chain hash — changes the digest. The per-row digests are
    kept too, so a mismatch can name the first row that moved instead of only
    saying "something changed".

    ``up_to`` matters because the archive is live. Migration must guarantee
    that *pre-existing* history is unchanged, not that nothing may be appended
    while it runs — a daemon ingesting browser history mid-migration is normal
    and must not be reported as tampering. Bounding the comparison at the tip
    observed when migration started separates the two.
    """
    digest = hashlib.sha256()
    rows = {}
    count = 0
    query = f"SELECT {', '.join(HISTORICAL_COLUMNS)} FROM events"
    params: tuple = ()
    if up_to is not None:
        query += " WHERE id <= ?"
        params = (up_to,)
    for row in conn.execute(query + " ORDER BY id", params):
        per_row = hashlib.sha256()
        for column in HISTORICAL_COLUMNS:
            value = row[column]
            per_row.update(b"\x00" if value is None
                           else str(value).encode("utf-8"))
            per_row.update(b"\x1f")
        rows[int(row["id"])] = per_row.hexdigest()
        digest.update(per_row.digest())
        count += 1
    return {"events": count, "digest": digest.hexdigest(), "rows": rows}


def _first_difference(before: dict, after: dict) -> str:
    if before["events"] != after["events"]:
        return (f"event count changed: {before['events']} -> "
                f"{after['events']}")
    for event_id, row_digest in sorted(before["rows"].items()):
        if after["rows"].get(event_id) != row_digest:
            return f"event #{event_id} changed"
    return "history changed in a way the fingerprint cannot localize"


def _witness_tip(conn) -> dict:
    from .db import _db_tip
    return _db_tip(conn)


def plan(conn) -> dict:
    """What migration would do. Changes nothing.

    Run this first. It is the same inspection the migration itself performs,
    so a plan that reports a problem is a migration that would have refused.
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise SchemaVersionError(
            f"archive schema version {version} is newer than this build "
            f"supports ({SCHEMA_VERSION})"
        )
    if version not in MIGRATABLE_FROM:
        raise MigrationError(
            f"no migration path from schema version {version}"
        )
    chain = verify_chain_read_only(conn)
    tip = _witness_tip(conn)
    existing = _table_names(conn)
    missing = sorted(_REQUIRED_TABLES - existing)
    cursor_plan = _cursor_hardening_plan(conn)
    store_plan = _store_hardening_plan(conn)
    legacy_labels = conn.execute(
        "SELECT COUNT(*) FROM events WHERE "
        "json_extract(meta,'$.authority') IS NOT NULL "
        "OR json_extract(meta,'$.actor') IS NOT NULL"
    ).fetchone()[0]
    return {
        "from_version": version,
        "to_version": SCHEMA_VERSION,
        "events": fingerprint(conn)["events"],
        "tip": tip,
        "chain_ok": chain["ok"],
        "tables_to_create": missing,
        "cursors_to_sanitize": cursor_plan["changed"],
        "blob_entries_to_harden": store_plan["entries"],
        "legacy_labelled_events": legacy_labels,
        "will_rewrite_history": False,
        "cutover": "a signed checkpoint adopting the existing tip; it does "
                   "not authenticate anything before it",
    }


_REQUIRED_TABLES = {
    "operator_keys", "operator_nonces", "operator_sequence",
    "archive_identity", "dispatch_capabilities", "service_keys",
    "service_signatures", "service_tips",
}


def _table_names(conn) -> set:
    return {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _cursor_hardening_plan(conn) -> dict:
    """Return privacy-clean operational cursor rows without writing them."""
    if "cursors" not in _table_names(conn):
        return {"rows": [], "changed": 0}
    from .db import _append_config, _sanitize_cursor_value
    from .redact import sanitize_content
    from .schemas import SchemaError

    cfg = _append_config()
    rows = []
    changed = 0
    seen_sources = set()
    for row in conn.execute("SELECT source, state FROM cursors ORDER BY source"):
        source = row["source"]
        if not isinstance(source, str) or not source or len(source) > 4096:
            raise MigrationError("legacy cursor source is invalid")
        safe_source = sanitize_content(cfg, source, max_len=4096)
        if not safe_source or safe_source in seen_sources:
            raise MigrationError("legacy cursor sources collide after sanitization")
        seen_sources.add(safe_source)
        try:
            state = json.loads(row["state"])
            if not isinstance(state, dict):
                raise SchemaError("cursor state must be a mapping")
            safe_state = _sanitize_cursor_value(cfg, state)
        except (TypeError, ValueError, json.JSONDecodeError, SchemaError) as exc:
            raise MigrationError("legacy cursor state is malformed") from exc
        encoded = json.dumps(
            safe_state, allow_nan=False, separators=(",", ":")
        )
        changed += int(safe_source != source or encoded != row["state"])
        rows.append((safe_source, encoded))
    return {"rows": rows, "changed": changed}


def _store_hardening_plan(conn, *, apply: bool = False) -> dict:
    """Validate the content-addressed store and optionally tighten its modes."""
    from .db import _connection_root

    store = _connection_root(conn) / "store"
    if not store.exists():
        return {"entries": 0}
    try:
        top = os.lstat(store)
    except OSError as exc:
        raise MigrationError("blob store cannot be inspected") from exc
    if (
        stat.S_ISLNK(top.st_mode)
        or not stat.S_ISDIR(top.st_mode)
        or top.st_uid != os.geteuid()
    ):
        raise MigrationError("blob store boundary is unsafe")
    entries = 0
    for current, directories, files in os.walk(store, followlinks=False):
        current_path = type(store)(current)
        current_info = os.lstat(current_path)
        if not stat.S_ISDIR(current_info.st_mode) or current_info.st_uid != os.geteuid():
            raise MigrationError("blob store directory boundary is unsafe")
        if apply:
            os.chmod(current_path, 0o700, follow_symlinks=False)
        for name in directories:
            path = current_path / name
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise MigrationError("blob store contains an unsafe directory entry")
            if info.st_uid != os.geteuid():
                raise MigrationError("blob store contains an unowned directory")
        for name in files:
            path = current_path / name
            info = os.lstat(path)
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
            ):
                raise MigrationError("blob store contains an unsafe object")
            relative = path.relative_to(store)
            if (
                len(relative.parts) != 2
                or len(relative.parts[0]) != 2
                or len(name) != 64
                or relative.parts[0] != name[:2]
                or any(ch not in "0123456789abcdef" for ch in name)
            ):
                raise MigrationError("blob store contains a non-addressed object")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != name:
                raise MigrationError("blob store object digest does not verify")
            if apply:
                os.chmod(path, 0o600, follow_symlinks=False)
            entries += 1
    return {"entries": entries}


def migrate(conn, dry_run: bool = False) -> dict:
    """Migrate in place. Append-only, idempotent, and crash-safe by shape.

    Refuses before any change if the schema is unsupported or the chain does
    not verify: migrating an archive that is already broken would bury the
    evidence under a successful-looking migration.
    """
    proposed = plan(conn)
    if not proposed["chain_ok"]:
        raise MigrationError(
            "the event chain does not verify; refusing to migrate a broken "
            "archive — investigate the break first, because migrating it "
            "would make the result look intentional"
        )
    if dry_run:
        return {**proposed, "applied": False}

    before_tip = _witness_tip(conn)
    # everything that existed when this migration started; later appends by a
    # concurrent writer are not this function's business
    before = fingerprint(conn, up_to=before_tip["id"])

    # 1. current schema and auxiliary tables. CREATE IF NOT EXISTS, so
    # re-running is a no-op. Applying the schema never rewrites an event row.
    from .capability import SCHEMA as CAPABILITY_SCHEMA
    from .ledger_sig import SCHEMA as LEDGER_SCHEMA
    conn.executescript(DB_SCHEMA)
    conn.executescript(CAPABILITY_SCHEMA)
    conn.executescript(LEDGER_SCHEMA)
    conn.commit()

    # Cursors are mutable scanner checkpoints, not historical evidence.  They
    # nevertheless live in the plaintext archive and used to accept arbitrary
    # nested strings, so the cutover privacy-cleans them transactionally.  No
    # event row is touched.
    cursor_plan = _cursor_hardening_plan(conn)
    if cursor_plan["changed"]:
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM cursors")
            conn.executemany(
                "INSERT INTO cursors(source, state) VALUES (?, ?)",
                cursor_plan["rows"],
            )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
    _store_hardening_plan(conn, apply=True)

    # 2. archive identity, so signatures bind to *this* archive
    from .attest import archive_uuid
    uuid = archive_uuid(conn)

    # 3. the cutover: the service records that it observed this tip. This is
    #    an INSERT into service_tips, never a change to an event.
    from .ledger_sig import LedgerSignatureError, sign_tip, verify_tip
    cutover_rows = conn.execute(
        "SELECT * FROM service_tips WHERE cutover = 1 ORDER BY tip_id"
    ).fetchall()
    if len(cutover_rows) > 1:
        raise MigrationError("multiple signed cutovers exist; refusing ambiguity")
    if cutover_rows:
        stored = cutover_rows[0]
        verified = verify_tip(conn, int(stored["tip_id"]))
        if not verified["ok"]:
            raise MigrationError(
                "the existing signed cutover does not verify; refusing to replace it"
            )
        cutover = {
            "tip_id": int(stored["tip_id"]),
            "chain_hash": stored["chain_hash"],
            "key_id": stored["key_id"],
            "signature": stored["signature"],
            "cutover": True,
        }
    else:
        try:
            cutover = sign_tip(conn, cutover=True)
        except LedgerSignatureError as exc:
            raise MigrationError(f"could not establish signed cutover: {exc}") from exc

    # 4. stamp the schema version. A pragma touches no event bytes.
    if proposed["from_version"] < SCHEMA_VERSION:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()

    # 5. prove the promise rather than asserting it
    after = fingerprint(conn, up_to=before_tip["id"])
    if after["digest"] != before["digest"]:
        raise MigrationError(
            f"migration changed history, which is a bug: "
            f"{_first_difference(before, after)}"
        )
    # the tip observed at the start must still be present with the same chain
    # hash. It may no longer be the *last* row — a concurrent writer may have
    # appended past it — but it must not have moved or vanished.
    anchor = conn.execute("SELECT chain_hash FROM events WHERE id = ?",
                          (before_tip["id"],)).fetchone()
    if before_tip["id"] and (
        anchor is None or anchor["chain_hash"] != before_tip["chain_hash"]
    ):
        raise MigrationError(
            f"the chain tip observed at the start (#{before_tip['id']}) was "
            f"{'removed' if anchor is None else 'rewritten'} during migration"
        )

    return {
        **proposed,
        "applied": True,
        "history_digest": after["digest"],
        "cutover": cutover,
        "archive_uuid": uuid,
        "history_unchanged": True,
    }


def cutover_claim(conn, tip_id: int) -> dict:
    """Exactly what a cutover signature may be read to mean.

    Returned as data so a caller cannot paraphrase it into something stronger.
    """
    from .ledger_sig import verify_tip
    result = verify_tip(conn, tip_id)
    return {
        "tip_id": tip_id,
        "signature_valid": result["ok"],
        "attests": "the authority service observed this chain tip at the "
                   "recorded time",
        "does_not_attest": [
            "that any event before this tip was authored by the operator",
            "that any historical authority/actor/role label is authenticated",
            "that historical content is true, complete, or unmodified before "
            "the service began observing",
        ],
    }


def legacy_label_report(conn) -> dict:
    """Every historical authority label, and what it now resolves to.

    Useful before and after migration: the counts must be identical, because
    migration does not touch them.
    """
    from .assurance import assurance_of
    counts: dict = {}
    for row in conn.execute(
        "SELECT meta FROM events WHERE meta IS NOT NULL"
    ):
        try:
            meta = json.loads(row["meta"])
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict):
            continue
        if meta.get("authority") is None and meta.get("actor") is None:
            continue
        level = assurance_of(meta)
        counts[level] = counts.get(level, 0) + 1
    return {"by_assurance": counts,
            "digest": canonical_digest("contextd.LegacyLabelReportV1",
                                       {"counts": {k: int(v) for k, v
                                                   in sorted(counts.items())}})}
