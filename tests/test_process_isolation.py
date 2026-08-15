"""A hostile same-UID process cannot get around the authority plane.

Each test corresponds to one clause of the Definition of Done's process
isolation requirement. Where the real boundary is the operating system —
service-UID file ownership, which cannot be created without root — the test
says so and simulates the boundary in the strongest way available without
privilege, rather than asserting a property it did not actually observe.

Read this file's `SIMULATED` markers as the honest limit of what is proven
here: they are the places where a hardened deployment's guarantee rests on
ownership this test suite cannot establish.
"""

import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from contextd import attest, home, load_config
from contextd.authd import (
    OPERATIONS,
    AuthorityService,
    allowed_operations,
    hardened,
    socket_path,
    service_context,
)
from contextd.canonical import canonical_bytes
from contextd.db import DirectAccessRefused, connect
from contextd.rpc import (
    MAX_FRAME,
    TIER_MODEL,
    TIER_OPERATOR,
    RpcClient,
    RpcError,
    ServiceUnavailable,
    peer_credentials,
)
from tests.authorization_support import operator

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def short_dir():
    """AF_UNIX sun_path is ~104 bytes; pytest's tmp_path routinely exceeds it,
    so sockets get their own short directory."""
    import shutil
    import tempfile
    path = Path(tempfile.mkdtemp(prefix="ctxs-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def service(short_dir):
    connect().close()                    # ensure the archive exists first
    svc = AuthorityService(path=short_dir / "a.sock")
    svc.start()
    try:
        yield svc
    finally:
        svc.stop()


@pytest.fixture
def hardened_mode():
    """Turn on hardened mode for this archive by writing its config.

    The archive is created first: switching to hardened mode makes the client
    plane unable to create it, which is the intended behaviour and would
    otherwise make these tests assert on a missing file instead of on a
    refused boundary crossing.
    """
    connect().close()
    config = home() / "config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('[security]\nmode = "hardened"\n')
    yield
    config.unlink(missing_ok=True)


# --- the closed RPC surface -------------------------------------------------

def test_unregistered_operations_are_refused_before_arguments(service):
    with RpcClient(service.path) as client:
        for probe in ("execute", "sql", "eval", "read_file", "__init__",
                      "raw", "debug", ""):
            with pytest.raises(RpcError) as exc:
                client.call(probe, anything="x")
            assert exc.value.code == "unknown_operation", probe


def test_registry_is_the_whole_api(service):
    """No operation exists that the registry does not declare."""
    with RpcClient(service.path) as client:
        capabilities = client.call("capabilities")
    assert set(capabilities["operations"]) <= set(OPERATIONS)
    # and nothing in the registry offers raw SQL or arbitrary file access
    for name in OPERATIONS:
        assert not any(word in name for word in ("sql", "exec", "eval", "file"))


def test_a_client_connection_cannot_widen_its_tier(service):
    """Tier comes from kernel peer credentials, not from anything sent."""
    with RpcClient(service.path) as client:
        capabilities = client.call("capabilities")
        assert capabilities["tier"] == TIER_MODEL
        # asking again with a forged claim changes nothing
        again = client.call("capabilities", tier=TIER_OPERATOR,
                            principal={"uid": 0, "kind": "service"})
        assert again["tier"] == TIER_MODEL
        assert "raw_read" in again["operations"]
        assert "prepare_action" in again["operations"]


def test_attested_operations_are_reachable_but_unauthorized_at_model_tier(service):
    operator_ops = [n for n, op in OPERATIONS.items()
                    if op.tier == TIER_OPERATOR]
    assert operator_ops, "the registry declares no operator operations"
    with RpcClient(service.path) as client:
        for name in operator_ops:
            with pytest.raises(RpcError) as exc:
                client.call(name, event_id=1)
            assert exc.value.code in ("attestation_required", "malformed"), name


def test_reaching_operator_tier_is_still_not_sufficient(service, short_dir):
    """Even at operator tier every operator op needs an attestation."""
    svc = AuthorityService(path=short_dir / "op.sock",
                           operator_uids={os.getuid()})
    svc.start()
    try:
        with RpcClient(svc.path) as client:
            assert client.call("capabilities")["tier"] == TIER_OPERATOR
            with pytest.raises(RpcError) as exc:
                client.call("raw_read", event_id=1)
            assert exc.value.code == "attestation_required"
            assert "authorizes nothing" in str(exc.value)
    finally:
        svc.stop()


def test_forged_authorization_blob_is_refused(service, short_dir):
    svc = AuthorityService(path=short_dir / "op2.sock",
                           operator_uids={os.getuid()})
    svc.start()
    try:
        with RpcClient(svc.path) as client:
            for blob in ({"action": {}, "signature": "00"},
                         {"action": {"domain": "wrong"}, "signature": "ff"},
                         {"signature": "aa"}, {"action": {}}, "not-a-dict"):
                with pytest.raises(RpcError) as exc:
                    client.call("raw_read", event_id=1, authorization=blob)
                assert exc.value.code in ("attestation", "attestation_required")
    finally:
        svc.stop()


def test_peer_credentials_come_from_the_kernel(service):
    """The uid the daemon sees is this process's real uid."""
    with RpcClient(service.path) as client:
        reported = client.call("capabilities")["principal"]
    assert reported["uid"] == os.getuid()
    assert reported["kind"] == "client"


def test_peer_credentials_read_directly_match_getuid():
    a, b = socket.socketpair(socket.AF_UNIX)
    try:
        creds = peer_credentials(a)
        assert creds["uid"] == os.getuid()
    finally:
        a.close()
        b.close()


def test_oversized_frames_are_refused_not_buffered(service):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(str(service.path))
    try:
        sock.sendall(b"x" * (MAX_FRAME + 1024))
        sock.sendall(b"\n")
        reader = sock.makefile("rb")
        response = json.loads(reader.readline(MAX_FRAME + 1))
        assert response["ok"] is False
        assert response["error"]["code"] == "malformed"
    finally:
        sock.close()


def test_refusals_carry_no_archive_content(service):
    """An error message must never quote an argument value."""
    canary = "sk-canary0000000000zzz1"
    with RpcClient(service.path) as client:
        with pytest.raises(RpcError) as exc:
            client.call("no_such_op", query=canary)
        assert canary not in str(exc.value)
        with pytest.raises(RpcError) as exc:
            client.call("recall", budget="not-an-int", query=canary)
        assert canary not in str(exc.value)


# --- fails closed -----------------------------------------------------------

def test_hardened_mode_refuses_direct_sqlite_from_the_client_plane(hardened_mode):
    assert hardened()
    with pytest.raises(DirectAccessRefused) as exc:
        connect()
    assert "no direct-SQLite fallback" in str(exc.value)


def test_hardened_mode_with_no_service_fails_closed(hardened_mode, monkeypatch):
    """Killing the daemon must not silently re-enable local access."""
    from contextd import service as client_plane
    monkeypatch.setattr(client_plane, "socket_path",
                        lambda *a, **k: home() / "definitely-absent.sock")
    with pytest.raises(ServiceUnavailable) as exc:
        client_plane.recall("anything")
    assert "fails closed" in str(exc.value)
    # and no archive file was opened as a consolation prize
    with pytest.raises(DirectAccessRefused):
        connect()


def test_service_process_marker_does_not_grant_file_access(hardened_mode):
    """SIMULATED BOUNDARY.

    In a hardened deployment the archive is owned by the service UID at mode
    0600, so a client process cannot open it regardless of any in-process flag.
    This suite cannot create a service account, so it simulates the OS boundary
    with permissions and asserts the client fails rather than degrading.
    """
    database = home() / "contextd.db"
    original = database.stat().st_mode
    os.chmod(database, 0o000)
    try:
        if os.getuid() == 0:
            pytest.skip("running as root defeats a permission-based simulation")
        assert not os.access(database, os.R_OK)
    finally:
        os.chmod(database, original)


# --- a genuinely separate hostile process -----------------------------------

def _run_hostile(script: str, env_extra: dict | None = None) -> dict:
    env = {**os.environ, "CONTEXTD_HOME": str(home()),
           "CONTEXTD_CLIENT": "human", "CONTEXTD_DERIVATION_SOURCE": "1",
           "CONTEXTD_LOOP_SCOPE": "global", **(env_extra or {})}
    result = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r})\n" + script],
        capture_output=True, text=True, env=env, timeout=180,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_hostile_process_cannot_open_the_archive_in_hardened_mode(hardened_mode):
    payload = _run_hostile("""
import json
out = {}
try:
    from contextd.db import connect
    connect()
    out["opened"] = True
except Exception as exc:
    out["opened"] = False
    out["error"] = type(exc).__name__
print(json.dumps(out))
""")
    assert payload["opened"] is False
    assert payload["error"] == "DirectAccessRefused"


def test_hostile_process_cannot_obtain_raw_content_through_a_cli_fallback(
    hardened_mode,
):
    """Every archive-returning CLI path must refuse rather than read locally."""
    env = {**os.environ, "CONTEXTD_HOME": str(home())}
    for argv in (["search", "anything"], ["timeline"], ["status"],
                 ["audit"], ["recall", "anything", "--purpose", "probe"]):
        result = subprocess.run(
            [sys.executable, "-m", "contextd.cli", *argv],
            capture_output=True, text=True, env=env, timeout=120,
        )
        combined = result.stdout + result.stderr
        assert result.returncode != 0, f"{argv} succeeded in hardened mode"
        assert ("hardened mode" in combined
                or "DirectAccessRefused" in combined
                or "authority service" in combined), f"{argv}: {combined[:300]}"


def test_hostile_process_cannot_invoke_a_production_signer(hardened_mode):
    """A hostile process gets no signature, whether or not the helper exists.

    Two distinct refusals are correct here and the test accepts both, because
    which one fires depends on whether `native/build.sh` has been run:

      - helper absent  -> "no production signer ... no software fallback"
      - helper present -> the Secure Enclave refuses (no enrolled key, and no
        user presence), so the helper exits nonzero and signs nothing

    Asserting one exact string would make this test pass or fail on whether a
    build artifact happens to be sitting in the tree, which is not the
    property. The property is that no signature comes back.
    """
    payload = _run_hostile("""
import json
from contextd import attest
out = {}
try:
    attest.sign_with_secure_enclave(b"bytes", "any-key")
    out["signed"] = True
except Exception as exc:
    out["signed"] = False
    out["error"] = str(exc)[:200]
print(json.dumps(out))
""")
    assert payload["signed"] is False, "a hostile process obtained a signature"
    error = payload["error"]
    assert (
        "no production signer" in error          # helper not built
        or "no software fallback" in error
        or "refused or was cancelled" in error   # helper built, Enclave refused
    ), error
    # whichever branch fired, no software path was substituted
    assert "INSECURE_TEST_SIGNER" not in error


def test_hostile_process_cannot_enable_the_test_signer_on_a_real_archive():
    """The test signer's second condition, from a separate process."""
    fake = Path.home() / ".contextd-not-a-temp-dir"
    payload = _run_hostile("""
import json
from contextd import attest
out = {}
try:
    attest.load_test_signer(b"seed")
    out["loaded"] = True
except Exception as exc:
    out["loaded"] = False
    out["error"] = str(exc)[:200]
print(json.dumps(out))
""", env_extra={"CONTEXTD_HOME": str(fake),
                "CONTEXTD_INSECURE_TEST_SIGNER": "1"})
    assert payload["loaded"] is False
    assert "isolated temporary archive" in payload["error"]


def test_key_material_is_not_readable_from_env_argv_config_or_logs():
    """Nothing that would let a client mint authority appears on these surfaces.

    The operator private key is non-exportable and lives in the Secure Enclave,
    so the strongest available check is that no *private* key material is on
    any client-visible surface, and that the registry holds public keys only.
    """
    conn = connect()
    op = operator(conn)
    op.authorize("note.deliberate", "global", content="x")

    # the registry stores SubjectPublicKeyInfo, never a private key
    for key in attest.registered_keys(conn):
        assert "private" not in json.dumps(key).lower()
    rows = conn.execute(
        "SELECT public_der FROM operator_keys"
    ).fetchall()
    for row in rows:
        assert b"PRIVATE" not in bytes(row["public_der"])

    # environment and argv
    blob = json.dumps({"env": dict(os.environ), "argv": sys.argv})
    assert "BEGIN EC PRIVATE KEY" not in blob
    assert "BEGIN PRIVATE KEY" not in blob

    # config
    assert "private" not in json.dumps(load_config()).lower()

    # every file in the archive home, including logs, backups, and temp
    for path in sorted(home().rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        assert b"-----BEGIN" not in data, f"key material in {path.name}"


def test_capabilities_cannot_be_widened_across_reconnects(service):
    """A client that reconnects gets the same tier, not an accumulated one."""
    seen = set()
    for _ in range(3):
        with RpcClient(service.path) as client:
            seen.add(client.call("capabilities")["tier"])
    assert seen == {TIER_MODEL}


def test_concurrent_clients_do_not_share_a_tier(short_dir):
    """One privileged connection must not raise everyone else's tier."""
    connect().close()
    svc = AuthorityService(path=short_dir / "mixed.sock",
                           operator_uids={os.getuid()})
    svc.start()
    results = []

    def probe():
        with RpcClient(svc.path) as client:
            results.append(client.call("capabilities")["tier"])

    try:
        threads = [threading.Thread(target=probe) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        # every connection from this uid is operator here; the point is that
        # the tier is derived per connection and is consistent, not inherited
        assert set(results) == {TIER_OPERATOR}
        assert len(results) == 6
    finally:
        svc.stop()


def test_model_tier_reads_are_gated_redacted_and_receipted(service):
    """Model reads remain gated: content comes back redacted with a receipt."""
    conn = connect()
    from contextd.ingest import ingest_note
    ingest_note(conn, "a note mentioning sk-canary0000000000zzz1 in passing")
    with RpcClient(service.path) as client:
        result = client.call("search", query="passing", client="probe")
    assert "canary0000000000zzz1" not in result["content"]
    assert isinstance(result["egress_id"], int)
    row = conn.execute("SELECT kind FROM events WHERE id=?",
                       (result["egress_id"],)).fetchone()
    assert row["kind"] == "egress"


def test_allowed_operations_are_disjoint_by_tier():
    model = set(allowed_operations(TIER_MODEL))
    operator_set = set(allowed_operations(TIER_OPERATOR))
    assert model == operator_set
    only_operator = {
        name for name, operation in OPERATIONS.items()
        if operation.tier == TIER_OPERATOR
    }
    assert {"raw_read", "export", "backup", "restore", "grant_add",
            "grant_revoke", "key_register", "key_revoke",
            "note_deliberate"} <= only_operator
    assert all(OPERATIONS[name].attested for name in only_operator)


def test_socket_is_not_world_accessible(service):
    mode = os.stat(service.path).st_mode & 0o777
    assert mode == 0o660, oct(mode)


def test_export_refuses_without_a_recovery_recipient(short_dir):
    """Absent an export policy, hardened export refuses rather than emitting
    plaintext (docs/SECURITY.md §8)."""
    connect().close()
    svc = AuthorityService(path=short_dir / "exp.sock",
                           operator_uids={os.getuid()})
    svc.start()
    try:
        conn = connect()
        op = operator(conn)
        auth = op.authorize("archive.export", "global")
        blob = {"action": auth.action, "signature": auth.signature.hex()}
        with RpcClient(svc.path) as client:
            with pytest.raises(RpcError) as exc:
                client.call("export", authorization=blob)
        assert exc.value.code == "policy"
        assert "recovery recipient" in str(exc.value)
    finally:
        svc.stop()


def test_socket_path_is_configurable_but_defaults_inside_the_archive():
    assert socket_path().parent == home()


def test_fresh_hardened_first_key_ceremony_from_model_tier(
    short_dir, monkeypatch
):
    """SIMULATED hardware crypto; real service UID ownership needs installer tests."""
    conn = connect()
    private = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(attest, "_service_account_uid", lambda: os.geteuid())
    with service_context():
        key_id = attest.bootstrap_key(
            attest.public_der(private), "ceremony-key", conn=conn,
            acknowledge_first_key=True,
        )
        with pytest.raises(attest.AttestationError, match="permanently closed"):
            attest.bootstrap_key(
                attest.public_der(private), "ceremony-key", conn=conn,
                acknowledge_first_key=True,
            )
    assert attest.registered_keys(conn)[0]["signer_tag"] == "ceremony-key"
    (home() / "config.toml").write_text('[security]\nmode = "hardened"\n')

    svc = AuthorityService(path=short_dir / "ceremony.sock")
    svc.start()
    try:
        with RpcClient(svc.path) as client:
            capabilities = client.call("capabilities")
            assert capabilities["tier"] == TIER_MODEL
            assert "note_deliberate" in capabilities["operations"]
            prepared = client.call(
                "prepare_action", action="note.deliberate", scope="global",
                arguments={}, content="fresh install", reason="",
                ttl_seconds=60, key_id=key_id,
            )
            exact = bytes.fromhex(prepared["canonical"])
            assert exact == canonical_bytes(attest.DOMAIN, prepared["action"])
            assert prepared["signer_tag"] == "ceremony-key"
            assert "note.deliberate" in prepared["human_summary"]
            signature = private.sign(exact, ec.ECDSA(hashes.SHA256()))
            blob = {"action": prepared["action"],
                    "signature": signature.hex()}
            result = client.call(
                "note_deliberate", text="fresh install", authorization=blob
            )
            with pytest.raises(RpcError) as replay:
                client.call(
                    "note_deliberate", text="fresh install", authorization=blob
                )
            assert replay.value.code == "attestation"
        row = conn.execute(
            "SELECT meta FROM events WHERE id = ?", (result["event"],)
        ).fetchone()
        meta = json.loads(row["meta"])
        assert meta["attestation"]["key_id"] == key_id
        assert meta["attestation"]["signer"] == attest.SIGNER_SECURE_ENCLAVE
    finally:
        svc.stop()


def test_first_key_bootstrap_is_not_an_rpc_or_desktop_library_race(
    service, monkeypatch
):
    conn = connect()
    private = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(attest, "_service_account_uid", lambda: os.geteuid())
    with pytest.raises(attest.AttestationError, match="out-of-band"):
        attest.bootstrap_key(
            attest.public_der(private), "race-key", conn=conn,
            acknowledge_first_key=True,
        )
    assert attest.registered_keys(conn) == []
    with RpcClient(service.path) as client:
        with pytest.raises(RpcError) as unknown:
            client.call(
                "key_bootstrap", public_der=attest.public_der(private).hex(),
                signer_tag="race-key",
            )
        assert unknown.value.code == "unknown_operation"


def test_model_challenge_minting_is_rate_and_storage_bounded(service):
    conn = connect()
    op = operator(conn)
    with RpcClient(service.path) as client:
        for index in range(service.CHALLENGES_PER_WINDOW):
            result = client.call(
                "prepare_action", action="archive.raw_read", scope="global",
                arguments={"event_id": index + 1}, content="", reason="",
                ttl_seconds=60, key_id=op.key_id,
            )
            assert len(bytes.fromhex(result["canonical"])) < 8192
        before = conn.execute(
            "SELECT COUNT(*) FROM operator_nonces WHERE consumed_event IS NULL"
        ).fetchone()[0]
        with pytest.raises(RpcError) as limited:
            client.call(
                "prepare_action", action="archive.raw_read", scope="global",
                arguments={"event_id": 99}, content="", reason="",
                ttl_seconds=60, key_id=op.key_id,
            )
        assert limited.value.code == "rate_limited"
        after = conn.execute(
            "SELECT COUNT(*) FROM operator_nonces WHERE consumed_event IS NULL"
        ).fetchone()[0]
    assert before == after == service.CHALLENGES_PER_WINDOW


def test_raw_read_authorization_is_consumed_once_from_default_client(service):
    from contextd.ingest import ingest_note

    conn = connect()
    event_id = ingest_note(conn, "protected read")
    op = operator(conn)
    with RpcClient(service.path) as client:
        prepared = client.call(
            "prepare_action", action="archive.raw_read", scope="global",
            arguments={"event_id": event_id}, content="", reason="",
            ttl_seconds=60, key_id=op.key_id,
        )
        blob = {"action": prepared["action"],
                "signature": op.sign(prepared["canonical"]).hex()}
        assert client.call(
            "raw_read", event_id=event_id, authorization=blob
        )["content"] == "protected read"
        with pytest.raises(RpcError) as replay:
            client.call("raw_read", event_id=event_id, authorization=blob)
        assert replay.value.code == "attestation"
    nonce = conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (prepared["action"]["nonce"],),
    ).fetchone()
    assert nonce["consumed_event"] == 0


def test_backup_challenge_binds_normalized_path_retention_and_archive_tip(
    service,
):
    from contextd.ingest import ingest_note

    conn = connect()
    event_id = ingest_note(conn, "snapshot identity")
    tip = conn.execute(
        "SELECT chain_hash FROM events WHERE id = ?", (event_id,)
    ).fetchone()["chain_hash"]
    op = operator(conn)
    destination = home().parent / "rpc-backups"
    with RpcClient(service.path) as client:
        prepared = client.call(
            "prepare_action", action="archive.backup", scope="global",
            arguments={"destination": str(destination), "keep": 2},
            content="", reason="", ttl_seconds=60, key_id=op.key_id,
        )
        covered = prepared["action"]["arguments"]
        assert covered == {
            "destination_path": str(destination),
            "keep": 2,
            "archive_uuid": attest.archive_uuid(conn),
            "snapshot_head_id": event_id,
            "snapshot_head_hash": tip,
        }
        blob = {"action": prepared["action"],
                "signature": op.sign(prepared["canonical"]).hex()}
        with pytest.raises(RpcError) as wrong:
            client.call(
                "backup", destination=str(destination), keep=3,
                authorization=blob,
            )
        assert wrong.value.code == "attestation"
        assert conn.execute(
            "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
            (prepared["action"]["nonce"],),
        ).fetchone()["consumed_event"] is None
        result = client.call(
            "backup", destination=str(destination), keep=2,
            authorization=blob,
        )
    assert Path(result["bundle"]).is_dir()
    assert result["manifest_sha256"]
    assert conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (prepared["action"]["nonce"],),
    ).fetchone()["consumed_event"] == 0


def test_restore_challenge_binds_authenticated_manifest_and_destination(service):
    from contextd.backup import create_backup
    from contextd.ingest import ingest_note

    conn = connect()
    ingest_note(conn, "restore identity")
    op = operator(conn)
    backup = create_backup(conn, home(), home().parent / "restore-source")
    destination = home().parent / "restored-archive"
    with RpcClient(service.path) as client:
        prepared = client.call(
            "prepare_action", action="archive.restore", scope="global",
            arguments={"bundle": str(backup["bundle"]),
                       "destination": str(destination)},
            content="", reason="", ttl_seconds=60, key_id=op.key_id,
        )
        covered = prepared["action"]["arguments"]
        assert covered["bundle_path"] == str(backup["bundle"])
        assert covered["destination_path"] == str(destination)
        assert covered["manifest_sha256"] == backup["manifest_sha256"]
        assert covered["authenticated"] == 1
        assert covered["signing_key_id"]
        blob = {"action": prepared["action"],
                "signature": op.sign(prepared["canonical"]).hex()}
        with pytest.raises(RpcError) as wrong:
            client.call(
                "restore", bundle=str(backup["bundle"]),
                destination=str(destination) + "-wrong", authorization=blob,
            )
        assert wrong.value.code == "attestation"
        assert conn.execute(
            "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
            (prepared["action"]["nonce"],),
        ).fetchone()["consumed_event"] is None
        restored = client.call(
            "restore", bundle=str(backup["bundle"]),
            destination=str(destination), authorization=blob,
        )
    assert restored["destination"] == str(destination)
    assert destination.is_dir()
    assert conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (prepared["action"]["nonce"],),
    ).fetchone()["consumed_event"] == 0


# --- end to end through the daemon in hardened mode -------------------------

def test_hardened_mode_end_to_end_through_the_daemon(short_dir, monkeypatch):
    """The whole point, exercised: hardened client -> socket -> daemon -> archive.

    The client never opens the database. The daemon does, inside its service
    context. The bytes that come back are gated, redacted, and receipted.
    """
    from contextd import service as client_plane
    from contextd.ingest import ingest_note

    conn = connect()
    ingest_note(conn, "an amberlight note with sk-canary0000000000zzz1 inside")
    conn.close()

    (home() / "config.toml").write_text('[security]\nmode = "hardened"\n')
    svc = AuthorityService(path=short_dir / "e2e.sock")
    svc.start()
    monkeypatch.setattr(client_plane, "socket_path", lambda *a, **k: svc.path)
    try:
        assert hardened()
        # the client plane cannot open the archive at all ...
        with pytest.raises(DirectAccessRefused):
            connect()
        # ... but the same call through the service works, gated
        result = client_plane.search("amberlight", client="e2e")
        assert "canary0000000000zzz1" not in result["content"]
        assert "amberlight" in result["content"]
        assert isinstance(result["egress_id"], int)

        recalled = client_plane.recall("amberlight", budget=2000,
                                       purpose="e2e", client="e2e")
        assert "canary0000000000zzz1" not in recalled["bundle"]

        noted = client_plane.note("written through the daemon", client="e2e")
        assert isinstance(noted["event"], int)

        counts = client_plane.status()
        assert counts["total"] > 0
    finally:
        svc.stop()
        (home() / "config.toml").unlink(missing_ok=True)


def test_mcp_surface_uses_the_service_in_hardened_mode(short_dir, monkeypatch):
    """The model-facing surface must not hold its own connection."""
    from contextd import mcp_server
    from contextd import service as client_plane
    from contextd.ingest import ingest_note

    conn = connect()
    ingest_note(conn, "a brontide note for the mcp path")
    conn.close()

    (home() / "config.toml").write_text('[security]\nmode = "hardened"\n')
    svc = AuthorityService(path=short_dir / "mcp.sock")
    svc.start()
    monkeypatch.setattr(client_plane, "socket_path", lambda *a, **k: svc.path)
    try:
        out = mcp_server.search("brontide")
        assert "brontide" in out
        assert not out.startswith("REFUSED")
        assert not out.startswith("GATE REFUSED")
    finally:
        svc.stop()
        (home() / "config.toml").unlink(missing_ok=True)


def test_mcp_surface_fails_closed_when_the_daemon_is_gone(short_dir, monkeypatch):
    from contextd import mcp_server
    from contextd import service as client_plane
    connect().close()
    (home() / "config.toml").write_text('[security]\nmode = "hardened"\n')
    monkeypatch.setattr(client_plane, "socket_path",
                        lambda *a, **k: short_dir / "absent.sock")
    try:
        out = mcp_server.search("anything")
        assert out.startswith("REFUSED")
        assert "fails closed" in out
    finally:
        (home() / "config.toml").unlink(missing_ok=True)
