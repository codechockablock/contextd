"""Encrypted export: sealing, recovery, and the substitution attack it stops.

The interesting test in this file is
`test_a_swapped_config_recipient_refuses_rather_than_redirecting`. Everything
else checks that export works; that one checks that it fails in the one way it
must, because the failure it describes is silent, total, and fully available to
the attacker this project models: rewrite `config.toml`, wait for an operator
to approve an export they believe is addressed to themselves, receive a
readable copy of the entire archive.
"""

import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from contextd import home
from contextd.authd import _export_action_arguments
from contextd.db import append_event, connect
from contextd.export import (
    ExportError,
    create_sealed_export,
    open_sealed_export,
    pack_bundle,
    unpack_bundle,
)
from contextd.export_crypto import (
    MAGIC,
    SUITE,
    ExportCryptoError,
    load_recipient,
    open_sealed,
    peek,
    recipient_digest,
    seal,
)
from contextd.service import RpcError
from tests.authorization_support import operator

_ENC = serialization.Encoding
_PF = serialization.PublicFormat


def _keypair(encoding=_ENC.PEM):
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(encoding, _PF.SubjectPublicKeyInfo)
    return private, public


def _archive_with(count: int):
    conn = connect()
    for index in range(count):
        append_event(conn, "note", "note", content=f"private note {index}")
    return conn


# --------------------------------------------------------------------------
# recipient parsing
# --------------------------------------------------------------------------


def test_der_and_pem_are_the_same_recipient():
    private, pem = _keypair(_ENC.PEM)
    der = private.public_key().public_bytes(_ENC.DER, _PF.SubjectPublicKeyInfo)
    assert load_recipient(pem)[1] == load_recipient(der)[1]
    assert load_recipient(der)[1] == recipient_digest(private.public_key())


def test_der_keys_ending_in_a_whitespace_byte_load_intact():
    """A DER key is binary: stripping it truncates about one key in forty.

    This is a regression test for a real bug in this module's first draft,
    which called `.strip()` on the file bytes before parsing. An X25519
    SubjectPublicKeyInfo ends in 32 bytes of key material, so whenever the last
    byte was 0x20/0x09/0x0a/0x0d/0x0b/0x0c the key silently lost a byte and
    failed to parse -- intermittently, on about 4% of freshly generated keys.
    """
    seen = 0
    for _ in range(600):
        private = X25519PrivateKey.generate()
        der = private.public_key().public_bytes(_ENC.DER, _PF.SubjectPublicKeyInfo)
        if der[-1:] not in b" \t\n\r\x0b\x0c":
            continue
        seen += 1
        assert load_recipient(der)[1] == recipient_digest(private.public_key())
    assert seen, "no whitespace-tailed key generated; test proved nothing"


@pytest.mark.parametrize(
    "payload, because",
    [
        (b"", "empty file"),
        (b"\x01" * 32, "raw key bytes carry no algorithm identifier"),
        (b"-----BEGIN PUBLIC KEY-----\nnot base64\n-----END PUBLIC KEY-----", "junk PEM"),
    ],
)
def test_unusable_recipient_files_are_refused(payload, because):
    with pytest.raises(ExportCryptoError):
        load_recipient(payload)


def test_a_non_x25519_key_is_refused_by_name():
    der = Ed25519PrivateKey.generate().public_key().public_bytes(
        _ENC.DER, _PF.SubjectPublicKeyInfo
    )
    with pytest.raises(ExportCryptoError, match="X25519"):
        load_recipient(der)


# --------------------------------------------------------------------------
# the sealed container
# --------------------------------------------------------------------------


def test_seal_round_trips_and_binds_the_manifest():
    private, public = _keypair()
    recipient, _ = load_recipient(public)
    digest = "b" * 64
    blob = seal(b"payload", recipient, manifest_sha256=digest,
                created_at="2026-08-15T00:00:00Z")
    plaintext, header = open_sealed(blob, private)
    assert plaintext == b"payload"
    assert header["manifest_sha256"] == digest
    assert header["suite"] == SUITE
    assert blob.startswith(MAGIC)


def test_the_plaintext_is_not_present_in_the_sealed_bytes():
    private, public = _keypair()
    recipient, _ = load_recipient(public)
    blob = seal(b"the quick brown fox", recipient, manifest_sha256="c" * 64,
                created_at="2026-08-15T00:00:00Z")
    assert b"the quick brown fox" not in blob


def test_each_seal_uses_a_fresh_ephemeral_key():
    _, public = _keypair()
    recipient, _ = load_recipient(public)
    kwargs = {"manifest_sha256": "d" * 64, "created_at": "2026-08-15T00:00:00Z"}
    first = peek(seal(b"same", recipient, **kwargs))
    second = peek(seal(b"same", recipient, **kwargs))
    assert first["ephemeral_public"] != second["ephemeral_public"]


def test_a_different_key_cannot_open_it():
    _, public = _keypair()
    recipient, _ = load_recipient(public)
    blob = seal(b"payload", recipient, manifest_sha256="e" * 64,
                created_at="2026-08-15T00:00:00Z")
    with pytest.raises(ExportCryptoError, match="different recipient"):
        open_sealed(blob, X25519PrivateKey.generate())


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda b: b[:-1] + bytes([b[-1] ^ 1]), id="ciphertext_bit"),
    pytest.param(lambda b: b[:40] + bytes([b[40] ^ 1]) + b[41:], id="header_bit"),
    pytest.param(lambda b: b[:len(b) // 2], id="truncated"),
    pytest.param(lambda b: b"x" * len(b), id="not_an_export"),
])
def test_tampering_is_refused(mutate):
    private, public = _keypair()
    recipient, _ = load_recipient(public)
    blob = seal(b"payload" * 100, recipient, manifest_sha256="f" * 64,
                created_at="2026-08-15T00:00:00Z")
    with pytest.raises(ExportCryptoError):
        open_sealed(mutate(blob), private)


def test_an_unknown_suite_fails_closed_rather_than_guessing():
    """Forward compatibility must refuse, not improvise."""
    import json
    import struct

    private, public = _keypair()
    recipient, _ = load_recipient(public)
    blob = seal(b"payload", recipient, manifest_sha256="a" * 64,
                created_at="2026-08-15T00:00:00Z")
    head = len(MAGIC) + 4
    (length,) = struct.unpack(">I", blob[len(MAGIC):head])
    header = json.loads(blob[head:head + length])
    header["suite"] = "X25519-SOMETHING-ELSE"
    forged = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    rebuilt = MAGIC + struct.pack(">I", len(forged)) + forged + blob[head + length:]
    with pytest.raises(ExportCryptoError, match="unsupported suite"):
        open_sealed(rebuilt, private)


# --------------------------------------------------------------------------
# packing
# --------------------------------------------------------------------------


def test_packing_is_deterministic(tmp_path):
    bundle = tmp_path / "b"
    bundle.mkdir()
    (bundle / "one.json").write_text("{}")
    (bundle / "two.db").write_bytes(b"\x00\x01\x02")
    assert pack_bundle(bundle) == pack_bundle(bundle)


def test_packing_refuses_a_symlinked_entry(tmp_path):
    bundle = tmp_path / "b"
    bundle.mkdir()
    (bundle / "real.json").write_text("{}")
    (tmp_path / "outside").write_text("elsewhere")
    (bundle / "link.json").symlink_to(tmp_path / "outside")
    with pytest.raises(ExportError, match="non-regular"):
        pack_bundle(bundle)


@pytest.mark.parametrize("name", ["/etc/passwd", "../escape", "a/../../escape"])
def test_unpacking_refuses_traversal(tmp_path, name):
    """A hostile export must not write outside the recovery directory."""
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size = 3
        tar.addfile(info, io.BytesIO(b"bad"))
    with pytest.raises(ExportError, match="unsafe entry path"):
        unpack_bundle(buffer.getvalue(), tmp_path / "out")


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------


def test_export_seals_the_archive_and_recovers_it(tmp_path):
    private, public = _keypair()
    conn = _archive_with(5)
    result = create_sealed_export(conn, home(), tmp_path / "out",
                                  recipient_key=public)

    sealed = (tmp_path / "out").glob("*.ctxexport")
    path = next(sealed)
    blob = path.read_bytes()
    assert b"private note 3" not in blob
    assert path.stat().st_mode & 0o777 == 0o600
    assert result["recipient_sha256"] == recipient_digest(private.public_key())

    opened = open_sealed_export(blob, private, tmp_path / "recovered")
    assert opened["manifest_sha256"] == result["manifest_sha256"]
    recovered = sqlite3.connect(tmp_path / "recovered" / "contextd.db")
    assert recovered.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 5


def test_export_leaves_no_plaintext_scratch(tmp_path):
    from contextd.scratch import scratch_root

    _, public = _keypair()
    create_sealed_export(_archive_with(3), home(), tmp_path / "out",
                         recipient_key=public)
    root = scratch_root()
    assert not (list(root.iterdir()) if root.exists() else [])


def test_export_refuses_an_unusable_recipient(tmp_path):
    with pytest.raises(ExportCryptoError):
        create_sealed_export(_archive_with(1), home(), tmp_path / "out",
                             recipient_key=b"not a key")


# --------------------------------------------------------------------------
# the substitution attack
# --------------------------------------------------------------------------


@pytest.fixture
def short_dir():
    """AF_UNIX sun_path is ~104 bytes; pytest's tmp_path routinely exceeds it."""
    import shutil
    import tempfile
    path = Path(tempfile.mkdtemp(prefix="ctxs-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _write_recipient(path: Path, public: bytes) -> Path:
    path.write_bytes(public)
    path.chmod(0o600)
    return path


def _export_call(conn, destination, *, arguments):
    """Authorize an export covering `arguments`, then run it via the library."""
    from contextd import service as client_plane
    op = operator(conn)
    auth = op.authorize("archive.export", "global", arguments=arguments)
    return client_plane.export(str(destination), auth)


def test_a_swapped_config_recipient_refuses_rather_than_redirecting(
    short_dir, tmp_path, monkeypatch
):
    """The attack this whole binding exists to stop.

    The modeled attacker can write config.toml. If the recipient were merely
    read from config at export time, they would swap in their own key, wait for
    the operator to approve an export they believe is addressed to themselves,
    and receive a readable copy of the archive -- with a valid signature on the
    action, because the action never mentioned a recipient.

    So the operator's signature covers the recipient's sha256. Here the
    authorization is built against the HONEST recipient, the config is then
    repointed at the attacker's key, and the export must refuse. Redirecting
    silently is the failure this asserts against.
    """
    conn = _archive_with(3)
    honest_private, honest_public = _keypair()
    attacker_private, attacker_public = _keypair()

    honest_path = _write_recipient(short_dir / "honest.pem", honest_public)
    attacker_path = _write_recipient(short_dir / "attacker.pem", attacker_public)

    # The operator signs an export to the recipient they actually chose.
    monkeypatch.setattr(
        "contextd.authd.load_config",
        lambda: {"security": {"export_recipient": str(honest_path)}},
    )
    honest_digest = load_recipient(honest_public)[1]
    covered = _export_action_arguments(conn, str(tmp_path / "out"),
                                       honest_digest)

    # The attacker now repoints config.toml at their own key.
    monkeypatch.setattr(
        "contextd.authd.load_config",
        lambda: {"security": {"export_recipient": str(attacker_path)}},
    )
    with pytest.raises(RpcError) as caught:
        _export_call(conn, tmp_path / "out", arguments=covered)

    assert caught.value.code == "attestation"
    # and nothing was written for the attacker to collect
    assert not list((tmp_path / "out").glob("*")) \
        if (tmp_path / "out").exists() else True

    # The honest recipient's key must not open anything, because nothing exists;
    # assert the attacker's key did not receive an export either.
    assert not list(tmp_path.rglob("*.ctxexport"))
    del honest_private, attacker_private


def test_export_succeeds_when_the_configured_recipient_is_the_signed_one(
    short_dir, tmp_path, monkeypatch
):
    """The same path, unmolested: the positive control for the test above.

    Without this, the refusal test would still pass if export were simply
    broken.
    """
    conn = _archive_with(4)
    private, public = _keypair()
    path = _write_recipient(short_dir / "honest.pem", public)

    monkeypatch.setattr(
        "contextd.authd.load_config",
        lambda: {"security": {"export_recipient": str(path)}},
    )
    covered = _export_action_arguments(conn, str(tmp_path / "out"),
                                       load_recipient(public)[1])
    result = _export_call(conn, tmp_path / "out", arguments=covered)

    sealed = Path(result["export"]).read_bytes()
    assert b"private note 2" not in sealed
    opened = open_sealed_export(sealed, private, tmp_path / "recovered")
    assert opened["manifest_sha256"] == result["manifest_sha256"]
    recovered = sqlite3.connect(tmp_path / "recovered" / "contextd.db")
    assert recovered.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 4


def test_a_passphrase_wrapped_identity_opens_an_export(tmp_path, monkeypatch):
    """Recovery keys are meant to be stored wrapped, so the tool must read one.

    The storage advice in docs/DEPLOYMENT.md §7 is to keep the private key
    passphrase-wrapped, which is what makes it safe to hold somewhere
    convenient. If `export-open` only accepted bare keys, following that advice
    would produce an export nothing could open -- discovered during a recovery,
    which is the worst possible time.
    """
    from cryptography.hazmat.primitives import serialization

    from contextd.cli import _load_identity

    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(_ENC.PEM, _PF.SubjectPublicKeyInfo)
    wrapped = private.private_bytes(
        _ENC.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"correct horse"),
    )
    path = tmp_path / "wrapped.key"
    path.write_bytes(wrapped)

    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "correct horse")
    identity = _load_identity(path)

    result = create_sealed_export(_archive_with(2), home(), tmp_path / "out",
                                  recipient_key=public)
    opened = open_sealed_export(Path(result["export"]).read_bytes(), identity,
                                tmp_path / "rec")
    assert opened["manifest_sha256"] == result["manifest_sha256"]


def test_a_wrong_passphrase_is_a_clean_refusal(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization

    from contextd.cli import _load_identity

    private = X25519PrivateKey.generate()
    path = tmp_path / "wrapped.key"
    path.write_bytes(private.private_bytes(
        _ENC.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"correct horse"),
    ))
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "wrong horse")
    with pytest.raises(SystemExit) as caught:
        _load_identity(path)
    assert "wrong passphrase" in str(caught.value)


def test_export_refuses_a_group_readable_recipient_file(
    short_dir, tmp_path, monkeypatch
):
    """A 0644 key file is one another local account can substitute."""
    conn = _archive_with(1)
    _, public = _keypair()
    path = short_dir / "loose.pem"
    path.write_bytes(public)
    path.chmod(0o644)

    monkeypatch.setattr(
        "contextd.authd.load_config",
        lambda: {"security": {"export_recipient": str(path)}},
    )
    from contextd import service as client_plane
    op = operator(conn)
    auth = op.authorize("archive.export", "global")
    with pytest.raises(RpcError) as caught:
        client_plane.export(str(tmp_path / "out"), auth)
    assert caught.value.code == "policy"
    assert "0600" in str(caught.value)
