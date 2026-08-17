import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from contextd import load_config
from contextd.backup import (
    BackupError,
    LegacyBundlePolicy,
    ManifestTrustStore,
    _sign_manifest,
    _signable_v1,
    bundle_identity,
    create_backup,
    restore_backup,
    validate_bundle,
)
from contextd.db import (
    InjectedCrash,
    append_event,
    append_event_checked,
    connect,
    store_blob,
    verify_chain,
)
from contextd.gate import assemble
from contextd.search import search


def _seed_archive() -> tuple[Path, sqlite3.Connection, str, bytes]:
    archive = Path(os.environ["CONTEXTD_HOME"])
    conn = connect()
    append_event(conn, "note", "note", content="durable narwhal decision")
    blob_bytes = b"blob payload that must survive restore\x00\xff"
    digest = store_blob(blob_bytes)
    append_event(
        conn,
        "fs",
        "file_write",
        uri="/archive/large.bin",
        content_hash=digest,
        meta={"blob": digest, "size": len(blob_bytes)},
    )
    (archive / "config.toml").write_text("[gate]\ndaily_token_budget = 200000\n")
    return archive, conn, digest, blob_bytes


def _bundle(tmp_path: Path) -> tuple[Path, str, bytes]:
    archive, conn, digest, blob_bytes = _seed_archive()
    result = create_backup(conn, archive, tmp_path / "backups")
    conn.close()
    return result["bundle"], digest, blob_bytes


def _rewrite_manifest(bundle: Path, mutate, *, resign: bool = True) -> None:
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    mutate(manifest)
    if resign:
        conn = connect()
        try:
            manifest["service_signature"] = _sign_manifest(conn, manifest)
        finally:
            conn.close()
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest_path.write_bytes(raw)
    (bundle / "manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")


def _refresh_entry(bundle: Path, relative: str) -> None:
    path = bundle / relative

    def mutate(manifest):
        entry = next(item for item in manifest["files"] if item["path"] == relative)
        entry["size"] = path.stat().st_size
        entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    _rewrite_manifest(bundle, mutate)


def test_complete_bundle_restores_search_recall_chain_witness_blobs_and_append(
    tmp_path, monkeypatch
):
    bundle, digest, blob_bytes = _bundle(tmp_path)
    manifest = validate_bundle(bundle)["manifest"]
    paths = {entry["path"] for entry in manifest["files"]}
    assert {
        "contextd.db",
        "config.toml",
        "chain-witness.json",
        f"store/{digest[:2]}/{digest}",
    } <= paths

    destination = tmp_path / "restored"
    destination.mkdir()
    result = restore_backup(bundle, destination)
    assert result["events"] == 2
    assert result["blobs"] == 1
    assert (destination / "store" / digest[:2] / digest).read_bytes() == blob_bytes

    monkeypatch.setenv("CONTEXTD_HOME", str(destination))
    conn = connect()
    assert verify_chain(conn)["ok"]
    assert search(conn, "narwhal decision")[0]["id"] == 1
    recalled = assemble(
        conn, load_config(), "narwhal decision", purpose="restore verification"
    )
    assert "durable narwhal decision" in recalled["bundle"]
    appended = append_event(conn, "note", "note", content="post restore append")
    assert appended == recalled["egress_id"] + 1
    assert verify_chain(conn)["ok"]


def test_online_snapshot_contains_committed_wal_rows(tmp_path):
    archive, conn, _, _ = _seed_archive()
    writer = connect()
    append_event(writer, "note", "note", content="committed in the WAL")
    writer.close()

    result = create_backup(conn, archive, tmp_path / "backups")
    snapshot = sqlite3.connect(result["bundle"] / "contextd.db")
    assert (
        snapshot.execute(
            "SELECT COUNT(*) FROM events WHERE content='committed in the WAL'"
        ).fetchone()[0]
        == 1
    )
    snapshot.close()


def test_backup_refuses_if_authorized_snapshot_tip_has_drifted(tmp_path):
    archive, conn, _, _ = _seed_archive()
    authorized = conn.execute(
        "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    append_event(conn, "note", "note", content="arrived after authorization")
    backups = tmp_path / "backups"

    with pytest.raises(BackupError, match="tip changed after backup authorization"):
        create_backup(
            conn,
            archive,
            backups,
            expected_head_id=authorized["id"],
            expected_head_hash=authorized["chain_hash"],
        )
    assert not list(backups.glob("*.ctxbackup"))

    current = conn.execute(
        "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    result = create_backup(
        conn,
        archive,
        backups,
        expected_head_id=current["id"],
        expected_head_hash=current["chain_hash"],
    )
    assert result["events"] == current["id"]
    conn.close()


@pytest.mark.parametrize(
    ("phase", "expected_events"),
    [("before_db_commit", 0), ("after_db_commit", 1)],
)
def test_backup_preserves_and_restores_recoverable_crash_state(
    tmp_path, monkeypatch, phase, expected_events
):
    archive = Path(os.environ["CONTEXTD_HOME"])
    conn = connect()

    def fault(current):
        if current == phase:
            raise InjectedCrash(current)

    with pytest.raises(InjectedCrash):
        append_event_checked(
            conn, "test", "note", content="interrupted append", fault=fault
        )
    # An abrupt process close rolls back the pre-commit case. Mirror that
    # SQLite effect while retaining this connection so create_backup receives
    # the recovery file before the normal connect-time recovery path consumes it.
    if conn.in_transaction:
        conn.rollback()
    recovery = archive / "chain-recovery.json"
    original_recovery = recovery.read_bytes()

    result = create_backup(conn, archive, tmp_path / "backups")
    conn.close()
    bundle = result["bundle"]
    assert recovery.read_bytes() == original_recovery
    assert (bundle / "chain-recovery.json").read_bytes() == original_recovery
    assert "chain-recovery.json" in {
        entry["path"] for entry in validate_bundle(bundle)["manifest"]["files"]
    }

    destination = tmp_path / "restored"
    restore_backup(bundle, destination)
    monkeypatch.setenv("CONTEXTD_HOME", str(destination))
    restored = connect()
    assert verify_chain(restored)["ok"]
    assert (
        restored.execute("SELECT COUNT(*) FROM events").fetchone()[0] == expected_events
    )
    assert not (destination / "chain-recovery.json").exists()
    assert (
        append_event(restored, "test", "note", content="after restore")
        == expected_events + 1
    )


def test_ctx_restore_cli_publishes_verified_bundle(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    destination = tmp_path / "cli-restored"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "contextd.cli",
            "restore",
            str(bundle),
            str(destination),
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "restored 2 events and 1 blobs" in result.stdout
    assert (destination / "contextd.db").is_file()


@pytest.mark.parametrize(
    "relative",
    [
        "manifest.json",
        "manifest.sha256",
        "contextd.db",
        "config.toml",
        "chain-witness.json",
    ],
)
def test_corrupt_manifest_or_payload_is_refused_without_publish(tmp_path, relative):
    bundle, _, _ = _bundle(tmp_path)
    path = bundle / relative
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 1
    path.write_bytes(data)
    destination = tmp_path / "not-published"

    with pytest.raises(BackupError):
        restore_backup(bundle, destination)

    assert not destination.exists()


def test_rehashed_nonobject_manifest_is_a_controlled_cli_refusal(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    raw = b"[]\n"
    (bundle / "manifest.json").write_bytes(raw)
    (bundle / "manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")
    destination = tmp_path / "not-published"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "contextd.cli",
            "restore",
            str(bundle),
            str(destination),
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=False,
    )

    assert result.returncode != 0
    assert "restore refused: manifest.json root must be an object" in result.stderr
    assert "Traceback" not in result.stderr
    assert not destination.exists()


def test_rehashed_nonobject_witness_is_refused_without_publish(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    witness = bundle / "chain-witness.json"
    witness.write_text('["version","id","chain_hash"]\n')
    _refresh_entry(bundle, "chain-witness.json")
    destination = tmp_path / "not-published"

    with pytest.raises(BackupError, match="chain witness is malformed"):
        restore_backup(bundle, destination)

    assert not destination.exists()


def test_one_byte_blob_corruption_is_refused_without_publish(tmp_path):
    bundle, digest, _ = _bundle(tmp_path)
    blob = bundle / "store" / digest[:2] / digest
    data = bytearray(blob.read_bytes())
    data[0] ^= 1
    blob.write_bytes(data)
    destination = tmp_path / "not-published"

    with pytest.raises(BackupError):
        restore_backup(bundle, destination)

    assert not destination.exists()


def test_semantically_corrupt_db_is_refused_even_with_updated_file_hash(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    conn = sqlite3.connect(bundle / "contextd.db")
    conn.execute("DROP TRIGGER events_no_update")
    conn.execute("UPDATE events SET content='rewritten' WHERE id=1")
    conn.commit()
    conn.close()
    _refresh_entry(bundle, "contextd.db")

    with pytest.raises(BackupError, match="event chain is broken"):
        restore_backup(bundle, tmp_path / "restored")


def test_semantically_corrupt_config_witness_recovery_and_blob_are_refused(tmp_path):
    bundle, digest, _ = _bundle(tmp_path)

    (bundle / "config.toml").write_text("[unterminated")
    _refresh_entry(bundle, "config.toml")
    with pytest.raises(BackupError, match="config.toml is invalid"):
        validate_bundle(bundle)

    bundle, digest, _ = _bundle(tmp_path / "witness-case")
    (bundle / "chain-witness.json").write_text("{}\n")
    _refresh_entry(bundle, "chain-witness.json")
    with pytest.raises(BackupError, match="chain witness"):
        validate_bundle(bundle)

    bundle, digest, _ = _bundle(tmp_path / "recovery-case")
    recovery = bundle / "chain-recovery.json"
    recovery.write_text('{"version":1,"previous":{},"target":{}}\n')

    def add_recovery(manifest):
        manifest["files"].append(
            {
                "path": "chain-recovery.json",
                "size": recovery.stat().st_size,
                "sha256": hashlib.sha256(recovery.read_bytes()).hexdigest(),
            }
        )
        manifest["files"].sort(key=lambda item: item["path"])

    _rewrite_manifest(bundle, add_recovery)
    with pytest.raises(BackupError, match="chain recovery"):
        validate_bundle(bundle)

    bundle, digest, _ = _bundle(tmp_path / "blob-case")
    blob = bundle / "store" / digest[:2] / digest
    blob.write_bytes(b"different bytes")
    _refresh_entry(bundle, f"store/{digest[:2]}/{digest}")
    with pytest.raises(BackupError, match="blob content digest mismatch"):
        validate_bundle(bundle)


@pytest.mark.parametrize("relative", ["contextd.db", "config.toml"])
def test_missing_payload_is_refused(tmp_path, relative):
    bundle, _, _ = _bundle(tmp_path)
    (bundle / relative).unlink()
    with pytest.raises(BackupError, match="missing files"):
        restore_backup(bundle, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_manifest_cannot_legitimize_a_missing_witness(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    (bundle / "chain-witness.json").unlink()

    def omit_witness(manifest):
        manifest["files"] = [
            entry
            for entry in manifest["files"]
            if entry["path"] != "chain-witness.json"
        ]

    _rewrite_manifest(bundle, omit_witness)

    with pytest.raises(BackupError, match="chain witness"):
        restore_backup(bundle, tmp_path / "restored")


def test_unexpected_file_and_path_traversal_are_refused(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    (bundle / "surprise.txt").write_text("not in the inventory")
    with pytest.raises(BackupError, match="unexpected files"):
        validate_bundle(bundle)

    bundle, _, _ = _bundle(tmp_path / "traversal-case")

    def add_traversal(manifest):
        manifest["files"].append({"path": "../escape", "size": 0, "sha256": "0" * 64})

    _rewrite_manifest(bundle, add_traversal)
    with pytest.raises(BackupError, match="unsafe bundle path"):
        restore_backup(bundle, tmp_path / "escape-destination")
    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "escape-destination").exists()


def test_nonempty_destination_is_refused_and_left_unchanged(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "keep.txt"
    sentinel.write_text("untouched")

    with pytest.raises(BackupError, match="not empty"):
        restore_backup(bundle, destination)

    assert sentinel.read_text() == "untouched"
    assert list(destination.iterdir()) == [sentinel]


def test_destination_inside_bundle_is_refused_without_mutating_bundle(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    before = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in bundle.rglob("*")
        if path.is_file()
    }

    with pytest.raises(BackupError, match="cannot be inside"):
        restore_backup(bundle, bundle / "restored-inside-bundle")

    after = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    assert after == before
    validate_bundle(bundle)


def test_retention_prunes_only_complete_bundles_without_sleeps(tmp_path):
    archive, conn, _, _ = _seed_archive()
    backups = tmp_path / "backups"
    legacy = backups / "contextd-legacy.db"
    note = backups / "operator-note.txt"
    backups.mkdir()
    legacy.write_bytes(b"legacy")
    note.write_text("keep")
    start = datetime(2026, 8, 12, tzinfo=timezone.utc)
    for offset in range(3):
        create_backup(
            conn,
            archive,
            backups,
            keep=2,
            created_at=start + timedelta(seconds=offset),
        )

    assert len(list(backups.glob("*.ctxbackup"))) == 2
    assert legacy.read_bytes() == b"legacy"
    assert note.read_text() == "keep"


def test_retention_preserves_incomplete_bundle_directories(tmp_path):
    archive, conn, _, _ = _seed_archive()
    backups = tmp_path / "backups"
    backups.mkdir()
    partial = backups / "contextd-20200101-000000.ctxbackup"
    partial.mkdir()
    raw = b"{}\n"
    (partial / "manifest.json").write_bytes(raw)
    (partial / "manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")

    result = create_backup(
        conn,
        archive,
        backups,
        keep=1,
        created_at=datetime(2026, 8, 12, tzinfo=timezone.utc),
    )

    assert partial.is_dir()
    assert result["bundle"].is_dir()
    assert result["pruned"] == []


def test_same_second_retention_keeps_newest_sequence_numbers(tmp_path):
    archive, conn, _, _ = _seed_archive()
    backups = tmp_path / "backups"
    when = datetime(2026, 8, 12, tzinfo=timezone.utc)
    created = []
    for index in range(3):
        if index:
            append_event(conn, "note", "note", content=f"later {index}")
        created.append(
            create_backup(conn, archive, backups, keep=2, created_at=when)["bundle"]
        )

    assert not created[0].exists()
    assert created[1].exists() and created[2].exists()


def test_same_second_sequence_never_reuses_a_pruned_name(tmp_path):
    """Regression (found by the restore drill's smoke alarm): pruning freed
    the bare-stamp name, a later same-second backup took it again, and
    (stamp, sequence) ordering — which retention and the drill's
    newest-bundle pick both rely on — stopped matching creation order.
    Retention could then delete the newest bundle and keep stale ones."""
    archive, conn, _, _ = _seed_archive()
    backups = tmp_path / "backups"
    when = datetime(2026, 8, 12, tzinfo=timezone.utc)
    create_backup(conn, archive, backups, keep=0, created_at=when)  # plain
    create_backup(conn, archive, backups, keep=2, created_at=when)  # -1
    create_backup(conn, archive, backups, keep=2, created_at=when)  # -2 (prunes plain)
    assert not (backups / "contextd-20260812-000000.ctxbackup").exists()

    append_event(conn, "note", "note", content="newest durable state")
    newest = create_backup(conn, archive, backups, keep=0, created_at=when)["bundle"]
    assert newest.name == "contextd-20260812-000000-3.ctxbackup", \
        "a freed bundle name must never be reallocated"

    latest = create_backup(conn, archive, backups, keep=2, created_at=when)
    assert newest.exists() and latest["bundle"].exists(), \
        "retention pruned a newer bundle in favor of a stale one"


def test_negative_retention_is_refused_before_bundle_publish(tmp_path):
    archive, conn, _, _ = _seed_archive()
    backups = tmp_path / "backups"

    with pytest.raises(BackupError, match="cannot be negative"):
        create_backup(conn, archive, backups, keep=-1)

    assert not backups.exists()


def test_backup_refuses_database_and_state_from_different_archives(tmp_path):
    archive, conn, _, _ = _seed_archive()

    with pytest.raises(BackupError, match="does not belong"):
        create_backup(conn, archive / "different", tmp_path / "backups")

    assert not (tmp_path / "backups").exists()


def test_loop_state_survives_backup_and_restore(tmp_path, monkeypatch):
    """Open-loops carriage across archive death: the reduced lifecycle in a
    restored archive is byte-identical to the source, and the restored
    archive keeps enforcing the same transition rules."""
    from contextd.loops import (LoopError, add_candidate, add_loop,
                                make_scope, reduce_loops, transition)

    archive = Path(os.environ["CONTEXTD_HOME"])
    conn = connect()
    scope = make_scope("/synthetic/amberlight")
    kept = add_loop(conn, "re-run the drift correction", scope)["loop"]
    gone = add_loop(conn, "regenerate the fixture site", scope)["loop"]
    transition(conn, gone["id"], "close", reason="done")
    transition(conn, gone["id"], "reopen", reason="regressed")
    cand = add_candidate(conn, "learn per-feed cadence", scope)["loop"]
    transition(conn, cand["id"], "dismiss", reason="noise")
    before = json.dumps(reduce_loops(conn), sort_keys=True)

    result = create_backup(conn, archive, tmp_path / "backups")
    conn.close()
    destination = tmp_path / "restored"
    restore_backup(result["bundle"], destination)
    monkeypatch.setenv("CONTEXTD_HOME", str(destination))

    rconn = connect()
    assert json.dumps(reduce_loops(rconn), sort_keys=True) == before
    assert verify_chain(rconn)["ok"]
    with pytest.raises(LoopError):
        transition(rconn, cand["id"], "reopen")
    assert transition(rconn, kept["id"], "close",
                      reason="verified post-restore")["loop"]["state"] == \
        "closed"
    rconn.close()


def test_recomputed_tampered_bundle_with_stale_signature_fails_closed(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    config = bundle / "config.toml"
    config.write_text("[gate]\ndaily_token_budget = 1\n")

    def launder_payload_hash(manifest):
        entry = next(item for item in manifest["files"] if item["path"] == "config.toml")
        entry["size"] = config.stat().st_size
        entry["sha256"] = hashlib.sha256(config.read_bytes()).hexdigest()

    _rewrite_manifest(bundle, launder_payload_hash, resign=False)
    destination = tmp_path / "must-not-publish"

    with pytest.raises(BackupError, match="manifest signature does not verify"):
        validate_bundle(bundle)
    with pytest.raises(BackupError, match="manifest signature does not verify"):
        restore_backup(bundle, destination)
    assert not destination.exists()


def test_unsigned_bundle_fails_closed_by_default(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    _rewrite_manifest(
        bundle,
        lambda manifest: manifest.update(
            service_signature={"signed": False, "why": "removed"}
        ),
        resign=False,
    )

    with pytest.raises(BackupError, match="unsigned"):
        validate_bundle(bundle)
    with pytest.raises(BackupError, match="unsigned"):
        restore_backup(bundle, tmp_path / "must-not-publish")


def test_exact_legacy_manifest_pin_is_explicit_and_never_signature_fallback(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    _rewrite_manifest(
        bundle,
        lambda manifest: manifest.update(service_signature={"signed": False}),
        resign=False,
    )
    digest = hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
    policy = LegacyBundlePolicy(frozenset({digest}))
    verified = validate_bundle(bundle, legacy_policy=policy)
    assert verified["authentication"] == {
        "authenticated": False,
        "signed": False,
        "legacy_manifest_pin": digest,
    }

    # A stale signed block is never downgraded to the legacy exception, even
    # when an operator pins that exact tampered manifest.
    bundle, _, _ = _bundle(tmp_path / "stale-signed")
    _rewrite_manifest(
        bundle,
        lambda manifest: manifest["snapshot"].update(
            events=manifest["snapshot"]["events"] + 1
        ),
        resign=False,
    )
    digest = hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
    with pytest.raises(BackupError, match="signature does not verify"):
        validate_bundle(
            bundle, legacy_policy=LegacyBundlePolicy(frozenset({digest}))
        )


def test_unsigned_post_cutover_bundle_cannot_use_legacy_policy(tmp_path):
    from contextd.ledger_sig import sign_tip

    archive, conn, _, _ = _seed_archive()
    sign_tip(conn, cutover=True)
    bundle = create_backup(conn, archive, tmp_path / "backups")["bundle"]
    conn.close()
    _rewrite_manifest(
        bundle,
        lambda manifest: manifest.update(service_signature={"signed": False}),
        resign=False,
    )
    digest = hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()

    with pytest.raises(BackupError, match="post-cutover"):
        validate_bundle(
            bundle, legacy_policy=LegacyBundlePolicy(frozenset({digest}))
        )


def test_fresh_home_restore_uses_external_pinned_trust_root(
    tmp_path, monkeypatch
):
    bundle, _, _ = _bundle(tmp_path)
    archive = Path(os.environ["CONTEXTD_HOME"])
    pins_dir = tmp_path / "offline-pins"
    pins_dir.mkdir(mode=0o700)
    pin_path = pins_dir / "backup-trust.json"
    pin_path.write_bytes((archive / "backup-trust.json").read_bytes())
    pin_path.chmod(0o600)
    fresh_home = tmp_path / "fresh-home"
    monkeypatch.setenv("CONTEXTD_HOME", str(fresh_home))

    result = restore_backup(bundle, fresh_home, trust_store=pin_path)
    assert result["manifest_sha256"] == hashlib.sha256(
        (bundle / "manifest.json").read_bytes()
    ).hexdigest()
    assert (fresh_home / "contextd.db").is_file()
    assert not (fresh_home / "backup-trust.json").exists()


def test_manifest_trust_store_rotation_keeps_old_and_new_bundles_valid(tmp_path):
    from contextd.ledger_sig import rotate_key

    archive, conn, _, _ = _seed_archive()
    first = create_backup(conn, archive, tmp_path / "backups")["bundle"]
    old_key = json.loads((first / "manifest.json").read_text())["service_signature"][
        "key_id"
    ]
    new_key = rotate_key(conn)
    second = create_backup(conn, archive, tmp_path / "backups")["bundle"]
    conn.close()

    pins = ManifestTrustStore.load(archive / "backup-trust.json")
    assert set(pins.pem_map) >= {old_key, new_key}
    assert (archive / "backup-trust.json").stat().st_mode & 0o777 == 0o600
    assert not list(archive.glob(".backup-trust.json.*.tmp"))
    assert validate_bundle(first, trust_store=pins)["authentication"]["ok"]
    assert validate_bundle(second, trust_store=pins)["authentication"]["ok"]


def test_manifest_pin_update_is_atomic_on_publish_failure(tmp_path, monkeypatch):
    import contextd.backup as backup_module
    from contextd.ledger_sig import rotate_key

    archive, conn, _, _ = _seed_archive()
    create_backup(conn, archive, tmp_path / "backups")
    trust_path = archive / "backup-trust.json"
    before = trust_path.read_bytes()
    rotate_key(conn)
    real_rename = backup_module.os.rename

    def fail_trust_publish(source, destination, *args, **kwargs):
        if destination == "backup-trust.json":
            raise OSError("injected trust-store publish failure")
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(backup_module.os, "rename", fail_trust_publish)
    with pytest.raises(OSError, match="injected trust-store publish failure"):
        create_backup(conn, archive, tmp_path / "backups")
    assert trust_path.read_bytes() == before
    assert not list(archive.glob(".backup-trust.json.*.tmp"))
    conn.close()


def test_pinned_legacy_signature_scheme_remains_verifiable(tmp_path):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from contextd.canonical import canonical_bytes
    from contextd.ledger_sig import _load_or_create_key

    bundle, _, _ = _bundle(tmp_path)
    manifest = json.loads((bundle / "manifest.json").read_text())
    conn = connect()
    try:
        private, key_id = _load_or_create_key(conn)
    finally:
        conn.close()
    signature = private.sign(
        canonical_bytes("contextd.BackupManifestV1", _signable_v1(manifest)),
        ec.ECDSA(hashes.SHA256()),
    )
    manifest["service_signature"] = {
        "signed": True,
        "key_id": key_id,
        "signature": signature.hex(),
    }
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (bundle / "manifest.json").write_bytes(raw)
    (bundle / "manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")

    verified = validate_bundle(bundle)
    assert verified["authentication"]["signature_scheme"] == 1


def test_manifest_trust_store_rejects_unsafe_files_parents_and_key_ids(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    archive = Path(os.environ["CONTEXTD_HOME"])
    trusted_bytes = (archive / "backup-trust.json").read_bytes()

    loose_file = tmp_path / "loose-pins.json"
    loose_file.write_bytes(trusted_bytes)
    loose_file.chmod(0o644)
    with pytest.raises(BackupError, match="group/world-accessible"):
        ManifestTrustStore.load(loose_file)

    loose_parent = tmp_path / "loose-parent"
    loose_parent.mkdir(mode=0o777)
    loose_parent.chmod(0o777)
    parent_pin = loose_parent / "pins.json"
    parent_pin.write_bytes(trusted_bytes)
    parent_pin.chmod(0o600)
    with pytest.raises(BackupError, match="parent .*group/world-writable"):
        ManifestTrustStore.load(parent_pin)

    symlink_pin = tmp_path / "symlink-pins.json"
    symlink_pin.symlink_to(archive / "backup-trust.json")
    with pytest.raises(BackupError, match="symlinked"):
        ManifestTrustStore.load(symlink_pin)

    document = json.loads(trusted_bytes)
    document["keys"].append(dict(document["keys"][0]))
    duplicate = tmp_path / "duplicate-pins.json"
    duplicate.write_bytes(
        (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    duplicate.chmod(0o600)
    with pytest.raises(BackupError, match="duplicate"):
        ManifestTrustStore.load(duplicate)

    document["keys"][-1]["public_pem"] = "different key bytes"
    conflict = tmp_path / "conflicting-pins.json"
    conflict.write_bytes(
        (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    conflict.chmod(0o600)
    with pytest.raises(BackupError, match="conflicting"):
        ManifestTrustStore.load(conflict)

    document["keys"] = document["keys"][:1]
    document["keys"][0]["key_id"] = "0" * 32
    mismatch = tmp_path / "mismatched-pins.json"
    mismatch.write_bytes(
        (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    mismatch.chmod(0o600)
    with pytest.raises(BackupError, match="does not match"):
        ManifestTrustStore.load(mismatch)
    assert validate_bundle(bundle)["authentication"]["authenticated"]

    bundled_pin = bundle / "attacker-selected-pins.json"
    bundled_pin.write_bytes(trusted_bytes)
    bundled_pin.chmod(0o600)
    with pytest.raises(BackupError, match="cannot come from the backup bundle"):
        validate_bundle(bundle, trust_store=str(bundled_pin))

    hardlink_pin = tmp_path / "hardlink-pins.json"
    os.link(archive / "backup-trust.json", hardlink_pin)
    with pytest.raises(BackupError, match="must not be hard-linked"):
        ManifestTrustStore.load(hardlink_pin)


def test_restore_refuses_approved_path_symlink_redirect(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    approved = tmp_path / "approved"
    approved.symlink_to(outside, target_is_directory=True)

    with pytest.raises(BackupError, match="symlinked or unsafe directory"):
        restore_backup(bundle, approved / "restored")
    assert list(outside.iterdir()) == []


def test_backup_refuses_symlinked_destination_parent(tmp_path):
    archive, conn, _, _ = _seed_archive()
    outside = tmp_path / "outside-backups"
    outside.mkdir()
    approved = tmp_path / "approved-backups"
    approved.symlink_to(outside, target_is_directory=True)

    with pytest.raises(BackupError, match="symlinked or unsafe directory"):
        create_backup(conn, archive, approved)
    conn.close()
    assert list(outside.iterdir()) == []


def test_backup_detects_destination_parent_swap_before_snapshot(
    tmp_path, monkeypatch
):
    import contextd.backup as backup_module

    archive, conn, _, _ = _seed_archive()
    approved = tmp_path / "approved-backups"
    approved.mkdir()
    moved = tmp_path / "approved-backups-moved"
    outside = tmp_path / "outside-backups"
    outside.mkdir()
    real_assert = backup_module._assert_path_matches_fd
    checks = 0

    def swap_before_snapshot(path, descriptor, label):
        nonlocal checks
        if label == "backup destination":
            checks += 1
            if checks == 3:
                approved.rename(moved)
                approved.symlink_to(outside, target_is_directory=True)
        return real_assert(path, descriptor, label)

    monkeypatch.setattr(backup_module, "_assert_path_matches_fd", swap_before_snapshot)
    with pytest.raises(BackupError, match="backup destination changed"):
        create_backup(conn, archive, approved)
    conn.close()
    assert list(outside.iterdir()) == []
    assert not list(moved.glob(".contextd-backup-*"))


def test_restore_detects_parent_swap_and_never_publishes_to_redirect(
    tmp_path, monkeypatch
):
    import contextd.backup as backup_module

    bundle, _, _ = _bundle(tmp_path)
    approved = tmp_path / "approved"
    approved.mkdir()
    moved = tmp_path / "approved-moved"
    outside = tmp_path / "outside"
    outside.mkdir()
    real_assert = backup_module._assert_path_matches_fd
    checks = 0

    def swap_before_second_check(path, descriptor, label):
        nonlocal checks
        if label == "restore parent":
            checks += 1
            if checks == 2:
                approved.rename(moved)
                approved.symlink_to(outside, target_is_directory=True)
        return real_assert(path, descriptor, label)

    monkeypatch.setattr(
        backup_module, "_assert_path_matches_fd", swap_before_second_check
    )
    with pytest.raises(BackupError, match="restore parent changed"):
        restore_backup(bundle, approved / "restored")
    assert list(outside.iterdir()) == []
    assert not (moved / "restored").exists()


def test_restore_rejects_special_file_in_bundle(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO test requires mkfifo")
    bundle, _, _ = _bundle(tmp_path)
    os.mkfifo(bundle / "hostile.fifo", 0o600)

    with pytest.raises(BackupError, match="special file: hostile.fifo"):
        restore_backup(bundle, tmp_path / "must-not-publish")


def test_restore_rejects_unlisted_empty_directory(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    (bundle / "unlisted-empty").mkdir()

    with pytest.raises(BackupError, match="unexpected directory: unlisted-empty"):
        restore_backup(bundle, tmp_path / "must-not-publish")


def test_bundle_identity_binds_normalized_paths_and_authenticated_manifest(tmp_path):
    bundle, _, _ = _bundle(tmp_path)
    destination = tmp_path / "future" / ".." / "restored"
    identity = bundle_identity(bundle / ".", destination=destination)

    assert identity["bundle_path"] == str(bundle)
    assert identity["destination_path"] == str(tmp_path / "restored")
    assert identity["authenticated"] is True
    assert identity["manifest_sha256"] == hashlib.sha256(
        (bundle / "manifest.json").read_bytes()
    ).hexdigest()


def test_restore_enforces_manifest_digest_bound_by_prior_authorization(tmp_path):
    first, _, _ = _bundle(tmp_path / "first")
    first_identity = bundle_identity(first, destination=tmp_path / "restored")
    second, _, _ = _bundle(tmp_path / "second")

    with pytest.raises(BackupError, match="authorized manifest digest"):
        restore_backup(
            second,
            tmp_path / "restored",
            expected_manifest_sha256=first_identity["manifest_sha256"],
        )
    assert not (tmp_path / "restored").exists()


def test_backup_survives_a_post_quantum_checkpoint_key(tmp_path):
    """A PQ checkpoint key must not disable backups.

    Post-quantum checkpoint keys share ``service_keys`` with the classical
    signing key, but the backup manifest is signed with ECDSA and its trust
    store asserts every pin is P-256. Pinning the whole registry meant the first
    ML-DSA key an archive minted made every later ``create_backup`` raise — so
    turning on the strongest signature the ledger offers silently disabled the
    weekly restore drill. Caught only in the merged tree: the lane that added PQ
    keys and the lane that wrote this trust store never ran together.
    """
    from contextd import ledger_sig

    archive, conn, _digest, _blob = _seed_archive()
    ledger_sig._load_or_create_key(conn)
    ledger_sig._load_or_create_key(conn, ledger_sig.ALG_MLDSA_44)
    algs = {row[0] for row in conn.execute("SELECT alg FROM service_keys")}
    assert ledger_sig.ALG_MLDSA_44 in algs and ledger_sig.CLASSICAL_ALG in algs

    # The trust store pins the classical key and ignores the PQ one...
    store = ManifestTrustStore.from_connection(conn)
    pinned = set(store.pem_map)
    pq_ids = {
        row[0]
        for row in conn.execute(
            "SELECT key_id FROM service_keys WHERE alg = ?",
            (ledger_sig.ALG_MLDSA_44,),
        )
    }
    assert pinned and not (pinned & pq_ids)

    # ...and a real backup still completes and validates.
    result = create_backup(conn, archive, tmp_path / "backups")
    conn.close()
    validate_bundle(Path(result["bundle"]), trust_store=store)
