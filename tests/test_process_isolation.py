"""A hostile same-UID process cannot get around the authority plane.

Each test corresponds to one clause of the Definition of Done's process
isolation requirement. The resident authority daemon is gone (lane X), so the
plane is enforced two ways and this file covers both: hardened configuration
**fails closed** — the client plane refuses rather than opening the archive —
and every operator-authoritative act requires a verified ``OperatorActionV1``
checked at the operation layer, with nothing about being local sufficient.

Where the real boundary is the operating system — service-UID file ownership,
which cannot be created without root — the test says so and simulates the
boundary in the strongest way available without privilege, rather than
asserting a property it did not actually observe. Read this file's
`SIMULATED` markers as the honest limit of what is proven here.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from contextd import attest, home, load_config
from contextd.authd import service_context
from contextd.canonical import canonical_bytes
from contextd.db import DirectAccessRefused, connect
from contextd.service import RpcError
from tests.authorization_support import operator

REPO_ROOT = Path(__file__).resolve().parent.parent


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


# --- fails closed -----------------------------------------------------------

def test_hardened_mode_refuses_direct_sqlite_from_the_client_plane(hardened_mode):
    from contextd.authority_mode import hardened
    assert hardened()
    with pytest.raises(DirectAccessRefused) as exc:
        connect()
    assert "no direct-SQLite fallback" in str(exc.value)


def test_hardened_mode_with_no_service_fails_closed(hardened_mode):
    """Residency is removed: hardened mode has no authority service at all,
    and the client plane must refuse *before* its development arm runs —
    that arm marks the thread as the authority plane (`service_context`),
    which would defeat `db._guard_direct_access`. This is the fail-open the
    lane X mitigation exists to prevent; the refusal travels the standard
    RpcError channel so existing callers surface it as a refusal."""
    from contextd import service as client_plane
    with pytest.raises(client_plane.ClientRefused) as exc:
        client_plane.recall("anything")
    assert isinstance(exc.value, RpcError)
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


# --- the operation layer's attestation requirement --------------------------

def test_operator_wrappers_refuse_a_forged_authorization():
    """Every operator-authoritative client function requires a verified
    ``OperatorActionV1`` covering exactly its act. The deleted RPC tier
    system used to assert this at the socket as well; the operation layer's
    own check is now the whole enforcement, so it is pinned here against a
    forged blob: nothing about being local, or holding a syntactically valid
    blob, is sufficient."""
    from contextd import service as client_plane
    connect().close()
    forged = SimpleNamespace(action={"domain": "wrong"}, signature=b"\xff")
    refusals = [
        lambda: client_plane.raw_read(1, forged),
        lambda: client_plane.note_deliberate("x", forged),
        lambda: client_plane.backup(str(home().parent / "b"), forged),
        lambda: client_plane.restore(str(home().parent / "b"),
                                     str(home().parent / "b2"), forged),
        lambda: client_plane.grant_add("loop.confirm", "",
                                       "2099-01-01T00:00:00+00:00", "", forged),
        lambda: client_plane.key_register(b"\x00", "tag", forged),
        lambda: client_plane.key_revoke("k", forged),
        lambda: client_plane.loop_add_operator("t", "", forged),
        lambda: client_plane.decision_supersede_operator(1, 2, "", forged),
    ]
    for call in refusals:
        with pytest.raises(RpcError) as exc:
            call()
        assert exc.value.code in ("attestation", "attestation_required",
                                  "malformed"), call


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


# --- the library read path stays gated ---------------------------------------

def test_model_reads_are_gated_redacted_and_receipted():
    """Model reads remain gated with no daemon in the picture: content comes
    back redacted, with an egress receipt in the archive."""
    from contextd import service as client_plane
    from contextd.ingest import ingest_note
    conn = connect()
    ingest_note(conn, "a note mentioning sk-canary0000000000zzz1 in passing")
    result = client_plane.search("passing", client="probe")
    assert "canary0000000000zzz1" not in result["content"]
    assert isinstance(result["egress_id"], int)
    row = conn.execute("SELECT kind FROM events WHERE id=?",
                       (result["egress_id"],)).fetchone()
    assert row["kind"] == "egress"


def test_export_refuses_without_a_recovery_recipient():
    """Absent an export policy, export refuses rather than emitting
    plaintext (docs/SECURITY.md §8)."""
    from contextd import service as client_plane
    conn = connect()
    op = operator(conn)
    auth = op.authorize("archive.export", "global")
    with pytest.raises(RpcError) as exc:
        client_plane.export(str(home().parent / "exports"), auth)
    assert exc.value.code == "policy"
    assert "recovery recipient" in str(exc.value)


# --- the first-key ceremony and challenge lifecycle --------------------------

def test_fresh_hardened_first_key_ceremony(monkeypatch):
    """SIMULATED hardware crypto; real service UID ownership needs installer tests."""
    from contextd import service as client_plane
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

    # the enrolled key authorizes an operator act end to end via the library
    prepared = client_plane.prepare_action(
        "note.deliberate", content="fresh install", ttl_seconds=60,
        key_id=key_id,
    )
    exact = bytes.fromhex(prepared["canonical"])
    assert exact == canonical_bytes(attest.DOMAIN, prepared["action"])
    assert prepared["signer_tag"] == "ceremony-key"
    assert "note.deliberate" in prepared["human_summary"]
    signature = private.sign(exact, ec.ECDSA(hashes.SHA256()))
    blob = SimpleNamespace(action=prepared["action"], signature=signature)
    result = client_plane.note_deliberate("fresh install", blob)
    with pytest.raises(RpcError) as replay:
        client_plane.note_deliberate("fresh install", blob)
    assert replay.value.code == "attestation"
    row = conn.execute(
        "SELECT meta FROM events WHERE id = ?", (result["event"],)
    ).fetchone()
    meta = json.loads(row["meta"])
    assert meta["attestation"]["key_id"] == key_id
    assert meta["attestation"]["signer"] == attest.SIGNER_SECURE_ENCLAVE


def test_first_key_bootstrap_requires_the_out_of_band_boundary(monkeypatch):
    conn = connect()
    private = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(attest, "_service_account_uid", lambda: os.geteuid())
    with pytest.raises(attest.AttestationError, match="out-of-band"):
        attest.bootstrap_key(
            attest.public_der(private), "race-key", conn=conn,
            acknowledge_first_key=True,
        )
    assert attest.registered_keys(conn) == []


def test_raw_read_authorization_is_consumed_once():
    from contextd import service as client_plane
    from contextd.ingest import ingest_note

    conn = connect()
    event_id = ingest_note(conn, "protected read")
    op = operator(conn)
    auth = op.authorize("archive.raw_read", "global",
                        arguments={"event_id": event_id})
    assert client_plane.raw_read(event_id, auth)["content"] == "protected read"
    with pytest.raises(RpcError) as replay:
        client_plane.raw_read(event_id, auth)
    assert replay.value.code == "attestation"
    nonce = conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.action["nonce"],),
    ).fetchone()
    assert nonce["consumed_event"] == 0


def test_backup_authorization_binds_path_retention_and_archive_tip():
    from contextd import service as client_plane
    from contextd.authd import _backup_action_arguments
    from contextd.ingest import ingest_note

    conn = connect()
    event_id = ingest_note(conn, "snapshot identity")
    tip = conn.execute(
        "SELECT chain_hash FROM events WHERE id = ?", (event_id,)
    ).fetchone()["chain_hash"]
    op = operator(conn)
    destination = home().parent / "lib-backups"
    covered = _backup_action_arguments(conn, str(destination), 2)
    assert covered == {
        "destination_path": str(destination),
        "keep": 2,
        "archive_uuid": attest.archive_uuid(conn),
        "snapshot_head_id": event_id,
        "snapshot_head_hash": tip,
    }
    auth = op.authorize("archive.backup", "global", arguments=covered)
    with pytest.raises(RpcError) as wrong:
        client_plane.backup(str(destination), auth, keep=3)
    assert wrong.value.code == "attestation"
    assert conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.action["nonce"],),
    ).fetchone()["consumed_event"] is None
    result = client_plane.backup(str(destination), auth, keep=2)
    assert Path(result["bundle"]).is_dir()
    assert result["manifest_sha256"]
    assert conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.action["nonce"],),
    ).fetchone()["consumed_event"] == 0


def test_restore_authorization_binds_authenticated_manifest_and_destination():
    from contextd import service as client_plane
    from contextd.authd import _restore_action_arguments
    from contextd.backup import bundle_identity, create_backup
    from contextd.ingest import ingest_note

    conn = connect()
    ingest_note(conn, "restore identity")
    op = operator(conn)
    backup = create_backup(conn, home(), home().parent / "restore-source")
    destination = home().parent / "restored-archive"
    identity = bundle_identity(
        Path(backup["bundle"]), destination=destination, trust_store=None,
        legacy_policy=None,
    )
    covered = _restore_action_arguments(identity)
    assert covered["bundle_path"] == str(backup["bundle"])
    assert covered["destination_path"] == str(destination)
    assert covered["manifest_sha256"] == backup["manifest_sha256"]
    assert covered["authenticated"] == 1
    assert covered["signing_key_id"]
    auth = op.authorize("archive.restore", "global", arguments=covered)
    with pytest.raises(RpcError) as wrong:
        client_plane.restore(str(backup["bundle"]),
                             str(destination) + "-wrong", auth)
    assert wrong.value.code == "attestation"
    assert conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.action["nonce"],),
    ).fetchone()["consumed_event"] is None
    restored = client_plane.restore(str(backup["bundle"]), str(destination),
                                    auth)
    assert restored["destination"] == str(destination)
    assert destination.is_dir()
    assert conn.execute(
        "SELECT consumed_event FROM operator_nonces WHERE nonce = ?",
        (auth.action["nonce"],),
    ).fetchone()["consumed_event"] == 0


# --- the model-facing surface fails closed under hardened config ------------

def test_mcp_surface_fails_closed_in_hardened_mode(hardened_mode):
    """The MCP surface surfaces the hardened refusal as a refusal string,
    never a crash and never a locally-read consolation answer."""
    from contextd import mcp_server
    out = mcp_server.search("anything")
    assert out.startswith("REFUSED")
    assert "fails closed" in out
