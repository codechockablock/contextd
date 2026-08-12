"""Complete, self-verifying backup bundles and fail-closed restore.

A bundle is a directory whose payload is named by ``manifest.json``.  The
manifest is canonical JSON and has a detached SHA-256 digest.  Restore treats
both the manifest and the directory as hostile input: paths are checked before
use, symlinks and unexpected files are refused, every byte is hashed again
after staging, and the destination is published with one rename only after the
SQLite snapshot and event chain verify.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from . import db as db_module

BUNDLE_FORMAT = "contextd-backup"
BUNDLE_VERSION = 1
BUNDLE_SUFFIX = ".ctxbackup"
MANIFEST_NAME = "manifest.json"
MANIFEST_HASH_NAME = "manifest.sha256"
DATABASE_NAME = "contextd.db"
OPTIONAL_STATE_NAMES = (
    "config.toml",
    "chain-witness.json",
    "chain-recovery.json",
)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_BUNDLE_NAME_RE = re.compile(
    r"contextd-(?P<stamp>\d{8}-\d{6})(?:-(?P<sequence>\d+))?\.ctxbackup"
)


class BackupError(RuntimeError):
    """A backup or restore was refused without publishing partial state."""


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(path)
    _fsync_directory(root)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _safe_relative(raw: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise BackupError(f"unsafe bundle path: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise BackupError(f"unsafe bundle path: {raw!r}")
    if path.as_posix() != raw:
        raise BackupError(f"non-canonical bundle path: {raw!r}")
    return path


def _add_manifest_file(files: list[dict[str, Any]], root: Path, relative: str) -> None:
    path = root.joinpath(*PurePosixPath(relative).parts)
    files.append(
        {
            "path": relative,
            "sha256": _sha256(path),
            "size": path.stat().st_size,
        }
    )


def _copy_private(source: Path, destination: Path) -> None:
    missing = []
    cursor = destination.parent
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for directory in missing:
        os.chmod(directory, 0o700)
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o600)


def _snapshot_database(conn: sqlite3.Connection, destination: Path) -> None:
    snapshot = sqlite3.connect(destination)
    try:
        conn.backup(snapshot)
    finally:
        snapshot.close()
    os.chmod(destination, 0o600)


def _referenced_blobs(database: Path) -> set[str]:
    conn = sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True)
    try:
        rows = conn.execute("SELECT meta FROM events WHERE meta IS NOT NULL")
        digests: set[str] = set()
        for (raw_meta,) in rows:
            try:
                meta = json.loads(raw_meta)
            except (TypeError, json.JSONDecodeError) as exc:
                raise BackupError("snapshot contains invalid event metadata") from exc
            digest = meta.get("blob") if isinstance(meta, dict) else None
            if digest is None:
                continue
            if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
                raise BackupError(f"invalid blob reference in snapshot: {digest!r}")
            digests.add(digest)
        return digests
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"cannot inspect snapshot blobs: {exc}") from exc
    finally:
        conn.close()


def _validate_database(database: Path) -> dict[str, Any]:
    conn = sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise BackupError(f"SQLite integrity check failed: {integrity}")
        try:
            conn.execute(
                "SELECT rowid FROM events_fts WHERE events_fts MATCH 'x' LIMIT 1"
            )
        except sqlite3.DatabaseError as exc:
            raise BackupError(f"FTS index check failed: {exc}") from exc
        chain = db_module._verify_rows(conn)
        if not chain["ok"]:
            raise BackupError(f"event chain is broken at #{chain['first_bad']}")
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        head = conn.execute(
            "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return {
            "events": count,
            "head_id": head["id"] if head else None,
            "head_hash": head["chain_hash"] if head else "",
        }
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"invalid SQLite snapshot: {exc}") from exc
    finally:
        conn.close()


def _validate_chain_state(root: Path, snapshot: dict[str, Any]) -> None:
    witness_path = root / "chain-witness.json"
    recovery_path = root / "chain-recovery.json"
    if not witness_path.exists():
        if recovery_path.exists():
            raise BackupError("chain recovery journal has no witness")
        return
    try:
        witness = json.loads(witness_path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("chain witness is invalid") from exc
    if not isinstance(witness, dict) or set(witness) != {
        "version",
        "id",
        "chain_hash",
    }:
        raise BackupError("chain witness is malformed")
    if (
        type(witness.get("version")) is not int
        or witness["version"] != db_module.WITNESS_VERSION
    ):
        raise BackupError("chain witness has an unsupported version")
    witnessed = {
        "id": witness.get("id"),
        "chain_hash": witness.get("chain_hash"),
    }
    _validate_tip(witnessed, "chain witness")
    current = {"id": snapshot["head_id"] or 0, "chain_hash": snapshot["head_hash"]}
    if not recovery_path.exists():
        if witnessed != current:
            raise BackupError("snapshot tip does not match its chain witness")
        return
    try:
        recovery = json.loads(recovery_path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("chain recovery journal is invalid") from exc
    if not isinstance(recovery, dict) or set(recovery) != {
        "version",
        "previous",
        "target",
    }:
        raise BackupError("chain recovery journal is malformed")
    if (
        type(recovery.get("version")) is not int
        or recovery["version"] != db_module.WITNESS_VERSION
    ):
        raise BackupError("chain recovery journal has an unsupported version")
    previous, target = recovery.get("previous"), recovery.get("target")
    _validate_tip(previous, "chain recovery previous tip")
    _validate_tip(target, "chain recovery target tip")
    if target["id"] != previous["id"] + 1:
        raise BackupError("chain recovery journal does not describe one append")
    recoverable = (previous == witnessed and current in (previous, target)) or (
        target == witnessed and current == witnessed
    )
    if not recoverable:
        raise BackupError("snapshot, witness, and recovery journal cannot reconcile")


def _validate_tip(value: Any, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"id", "chain_hash"}:
        raise BackupError(f"{label} is malformed")
    event_id, chain_hash = value["id"], value["chain_hash"]
    if not isinstance(event_id, int) or isinstance(event_id, bool) or event_id < 0:
        raise BackupError(f"{label} has an invalid event id")
    valid_hash = (
        chain_hash == ""
        if event_id == 0
        else (isinstance(chain_hash, str) and _DIGEST_RE.fullmatch(chain_hash))
    )
    if not valid_hash:
        raise BackupError(f"{label} has an invalid chain hash")


def _new_bundle_path(destination: Path, stamp: str) -> Path:
    candidate = destination / f"contextd-{stamp}{BUNDLE_SUFFIX}"
    index = 0
    while candidate.exists():
        index += 1
        candidate = destination / f"contextd-{stamp}-{index}{BUNDLE_SUFFIX}"
    return candidate


def _is_bundle(path: Path) -> bool:
    candidate = (
        _BUNDLE_NAME_RE.fullmatch(path.name) is not None
        and path.is_dir()
        and not path.is_symlink()
        and (path / MANIFEST_NAME).is_file()
        and (path / MANIFEST_HASH_NAME).is_file()
    )
    if not candidate:
        return False
    try:
        validate_bundle(path)
    except Exception:
        # Retention is deliberately fail-closed: anything we cannot prove is
        # a complete bundle is preserved for operator inspection.
        return False
    return True


def prune_bundles(destination: Path, keep: int) -> list[Path]:
    """Remove only complete verified bundles, never partial or legacy state."""
    if keep < 0:
        raise BackupError("retention count cannot be negative")
    if keep == 0:
        return []

    def creation_key(path: Path) -> tuple[str, int]:
        match = _BUNDLE_NAME_RE.fullmatch(path.name)
        assert match is not None
        return match["stamp"], int(match["sequence"] or 0)

    bundles = sorted(
        (path for path in destination.iterdir() if _is_bundle(path)),
        key=creation_key,
    )
    old = bundles[:-keep]
    for path in old:
        shutil.rmtree(path)
    if old:
        _fsync_directory(destination)
    return old


def create_backup(
    conn: sqlite3.Connection,
    source_home: Path,
    destination: Path,
    *,
    keep: int = 0,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Create and atomically publish a complete archive backup bundle."""
    source_home = Path(source_home).expanduser()
    destination = Path(destination).expanduser()
    if keep < 0:
        raise BackupError("retention count cannot be negative")
    database_row = conn.execute("PRAGMA database_list").fetchone()
    database_file = (
        database_row["file"]
        if isinstance(database_row, sqlite3.Row)
        else database_row[2]
    )
    if (
        not database_file
        or Path(database_file).resolve() != (source_home / DATABASE_NAME).resolve()
    ):
        raise BackupError("database connection does not belong to the source archive")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination, 0o700)
    when = created_at or datetime.now(timezone.utc)
    stamp = when.astimezone(timezone.utc).strftime("%Y%m%d-%H%M%S")
    bundle = _new_bundle_path(destination, stamp)
    stage = Path(tempfile.mkdtemp(prefix=".contextd-backup-", dir=destination))
    os.chmod(stage, 0o700)
    try:
        database = stage / DATABASE_NAME
        # The witness lock is the global append lock. Hold it across the online
        # SQLite snapshot and external-state copy so the three artifacts
        # describe one exact, recoverable tip even with concurrent writers.
        # Do not consume a recovery journal here: it is part of the state a
        # complete backup must preserve, and bundle validation proves that the
        # copied database/witness/journal triple can reconcile.
        with db_module._chain_lock(source_home):
            _snapshot_database(conn, database)
            for name in OPTIONAL_STATE_NAMES:
                source = source_home / name
                if source.is_symlink():
                    raise BackupError(f"refusing symlinked archive state: {source}")
                if source.exists():
                    if not source.is_file():
                        raise BackupError(f"archive state is not a file: {source}")
                    _copy_private(source, stage / name)
        snapshot = _validate_database(database)
        _validate_chain_state(stage, snapshot)

        blobs = sorted(_referenced_blobs(database))
        for digest in blobs:
            source = source_home / "store" / digest[:2] / digest
            if source.is_symlink() or not source.is_file():
                raise BackupError(f"missing referenced blob: {digest}")
            if _sha256(source) != digest:
                raise BackupError(f"corrupt referenced blob: {digest}")
            _copy_private(source, stage / "store" / digest[:2] / digest)

        payload = sorted(
            path.relative_to(stage).as_posix()
            for path in stage.rglob("*")
            if path.is_file()
        )
        files: list[dict[str, Any]] = []
        for relative in payload:
            _add_manifest_file(files, stage, relative)
        manifest = {
            "format": BUNDLE_FORMAT,
            "version": BUNDLE_VERSION,
            "created_at": when.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "snapshot": snapshot,
            "blobs": blobs,
            "files": files,
        }
        manifest_bytes = _canonical_json(manifest)
        (stage / MANIFEST_NAME).write_bytes(manifest_bytes)
        os.chmod(stage / MANIFEST_NAME, 0o600)
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        (stage / MANIFEST_HASH_NAME).write_text(manifest_hash + "\n")
        os.chmod(stage / MANIFEST_HASH_NAME, 0o600)
        validate_bundle(stage)
        _fsync_tree(stage)
        stage.rename(bundle)
        _fsync_directory(destination)
        pruned = prune_bundles(destination, keep)
        return {
            "bundle": bundle,
            "events": snapshot["events"],
            "blobs": len(blobs),
            "manifest_sha256": manifest_hash,
            "pruned": pruned,
        }
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        raise


def _manifest(bundle: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise BackupError(f"backup bundle is not a directory: {bundle}")
    manifest_path = bundle / MANIFEST_NAME
    digest_path = bundle / MANIFEST_HASH_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise BackupError("bundle is missing a regular manifest.json")
    if not digest_path.is_file() or digest_path.is_symlink():
        raise BackupError("bundle is missing a regular manifest.sha256")
    try:
        raw = manifest_path.read_bytes()
        recorded = digest_path.read_text().strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise BackupError("bundle manifest files are unreadable") from exc
    if not _DIGEST_RE.fullmatch(recorded):
        raise BackupError("manifest.sha256 is malformed")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != recorded:
        raise BackupError("manifest hash mismatch")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("manifest.json is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise BackupError("manifest.json root must be an object")
    if _canonical_json(manifest) != raw:
        raise BackupError("manifest.json is not canonical JSON")
    if (
        manifest.get("format") != BUNDLE_FORMAT
        or type(manifest.get("version")) is not int
        or manifest["version"] != BUNDLE_VERSION
    ):
        raise BackupError("unsupported backup bundle format or version")
    if not isinstance(manifest.get("files"), list):
        raise BackupError("manifest files must be a list")
    entries: dict[str, dict[str, Any]] = {}
    for entry in manifest["files"]:
        if not isinstance(entry, dict):
            raise BackupError("invalid manifest file entry")
        relative = entry.get("path")
        _safe_relative(relative)
        if relative in entries:
            raise BackupError(f"duplicate manifest path: {relative}")
        if (
            not isinstance(entry.get("size"), int)
            or isinstance(entry["size"], bool)
            or entry["size"] < 0
        ):
            raise BackupError(f"invalid size for {relative}")
        if not isinstance(entry.get("sha256"), str) or not _DIGEST_RE.fullmatch(
            entry["sha256"]
        ):
            raise BackupError(f"invalid hash for {relative}")
        entries[relative] = entry
    if DATABASE_NAME not in entries:
        raise BackupError("bundle does not contain contextd.db")
    if "chain-witness.json" not in entries:
        raise BackupError("bundle does not contain its chain witness")
    return manifest, entries


def validate_bundle(bundle: Path) -> dict[str, Any]:
    """Validate structure, byte inventory, hashes, SQLite, chain, and blobs."""
    bundle = Path(bundle).expanduser()
    manifest, entries = _manifest(bundle)
    actual_files: set[str] = set()
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise BackupError(f"bundle contains a symlink: {path.relative_to(bundle)}")
        if path.is_file():
            actual_files.add(path.relative_to(bundle).as_posix())
        elif not path.is_dir():
            raise BackupError(f"bundle contains a special file: {path}")
    expected_files = set(entries) | {MANIFEST_NAME, MANIFEST_HASH_NAME}
    missing = expected_files - actual_files
    unexpected = actual_files - expected_files
    if missing:
        raise BackupError(f"bundle is missing files: {', '.join(sorted(missing))}")
    if unexpected:
        raise BackupError(
            f"bundle has unexpected files: {', '.join(sorted(unexpected))}"
        )

    allowed = {DATABASE_NAME, *OPTIONAL_STATE_NAMES}
    for relative, entry in entries.items():
        path = bundle.joinpath(*PurePosixPath(relative).parts)
        if relative not in allowed and not relative.startswith("store/"):
            raise BackupError(f"unsupported archive payload path: {relative}")
        if path.stat().st_size != entry["size"] or _sha256(path) != entry["sha256"]:
            raise BackupError(f"payload hash or size mismatch: {relative}")
    config = bundle / "config.toml"
    if config.exists():
        try:
            tomllib.loads(config.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise BackupError("config.toml is invalid") from exc

    snapshot = _validate_database(bundle / DATABASE_NAME)
    if manifest.get("snapshot") != snapshot:
        raise BackupError("snapshot metadata does not match contextd.db")
    _validate_chain_state(bundle, snapshot)
    referenced = _referenced_blobs(bundle / DATABASE_NAME)
    listed = manifest.get("blobs")
    if not isinstance(listed, list) or listed != sorted(referenced):
        raise BackupError("manifest blob inventory does not match the snapshot")
    blob_payloads = {relative for relative in entries if relative.startswith("store/")}
    expected_blobs = {f"store/{digest[:2]}/{digest}" for digest in referenced}
    if blob_payloads != expected_blobs:
        raise BackupError("bundle blob payload does not match referenced blobs")
    for digest in referenced:
        path = bundle / "store" / digest[:2] / digest
        if _sha256(path) != digest:
            raise BackupError(f"blob content digest mismatch: {digest}")
    return {"manifest": manifest, "snapshot": snapshot, "files": entries}


def restore_backup(bundle: Path, destination: Path) -> dict[str, Any]:
    """Verify into a sibling stage and atomically publish an archive home."""
    bundle = Path(bundle).expanduser()
    destination = Path(destination).expanduser()
    bundle_root = bundle.resolve()
    destination_root = destination.resolve(strict=False)
    if bundle_root == destination_root or bundle_root in destination_root.parents:
        raise BackupError("restore destination cannot be inside the backup bundle")
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise BackupError(f"restore destination already exists: {destination}")
        if any(destination.iterdir()):
            raise BackupError(f"restore destination is not empty: {destination}")
    verified = validate_bundle(bundle)
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.restore-", dir=destination.parent)
    )
    os.chmod(stage, 0o700)
    try:
        for relative, entry in verified["files"].items():
            source = bundle.joinpath(*PurePosixPath(relative).parts)
            target = stage.joinpath(*PurePosixPath(relative).parts)
            _copy_private(source, target)
            if (
                target.stat().st_size != entry["size"]
                or _sha256(target) != entry["sha256"]
            ):
                raise BackupError(f"staged payload failed verification: {relative}")
        staged_snapshot = _validate_database(stage / DATABASE_NAME)
        if staged_snapshot != verified["snapshot"]:
            raise BackupError("staged database does not match the verified snapshot")
        _validate_chain_state(stage, staged_snapshot)
        if _referenced_blobs(stage / DATABASE_NAME) != set(
            verified["manifest"]["blobs"]
        ):
            raise BackupError("staged blob inventory changed during restore")
        if destination.exists():
            if any(destination.iterdir()):
                raise BackupError(f"restore destination became nonempty: {destination}")
            destination.rmdir()
        _fsync_tree(stage)
        stage.rename(destination)
        _fsync_directory(destination.parent)
        return {
            "destination": destination,
            "events": staged_snapshot["events"],
            "blobs": len(verified["manifest"]["blobs"]),
        }
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        raise
