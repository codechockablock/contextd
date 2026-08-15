"""Encrypted export: sealing an archive bundle to an off-host recipient.

**What this defends against, and what it does not.** The adversary this project
is built around is a hostile process running as the desktop UID
(`docs/SECURITY.md` §1). Encryption does not stop that attacker from reading
the archive — it already can, because it *is* the owner. What encryption
protects is the bundle **after it leaves this host**: on backup media, in a
sync folder, on a disk that outlives the machine, in transit to a second
party. That is a real and different exposure, and it is the only one this
module addresses.

It follows that the value of an encrypted export is entirely determined by
where the private key lives. A recipient key whose private half sits in this
host's filesystem or login keychain buys nothing: the modeled attacker reads
it and decrypts. The recipient is expected to be generated on **another
machine** and only its public half brought here. `docs/SECURITY.md` says this
in the deployment section, and `ctx security export` says it again at the
point of use, because it is the assumption most likely to be quietly broken.

**Construction.** A sealed-box built from primitives already in this project's
dependency set — no new dependency, and the same `cryptography` package that
backs the P-256 ledger signatures:

    ephemeral X25519 keypair (esk, epk)      fresh for every seal
    shared   = X25519(esk, recipient_public)
    key      = HKDF-SHA256(ikm=shared, salt=MAGIC, info=header)
    sealed   = MAGIC || u32be(len(header)) || header || nonce ||
               ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad=prefix)

The header is canonical, domain-separated bytes (`contextd.ExportHeaderV1`)
carrying the suite, the recipient digest, the ephemeral public key, and the
sha256 of the enclosed bundle's service-signed manifest. It is fed to HKDF as
`info` *and* covered as AEAD associated data, which is what makes the pieces
non-transplantable: a ciphertext cannot be re-labelled with a different
recipient, a different manifest, or a different suite without the tag failing.
The manifest digest in particular means a decryptor learns which signed
snapshot it is holding before it trusts a byte of the plaintext.

A fresh ephemeral key per seal makes the derived key unique per message, so
nonce reuse is structurally impossible; the nonce is random regardless, so
that property does not silently depend on a future refactor preserving it.

**Forward compatibility fails closed.** An unknown format, version, or suite is
refused rather than best-effort decoded. A decryptor that cannot name the
construction has no business guessing at it.
"""

import hashlib
import hmac
import json
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#: Versioned file magic. Changing the construction changes these bytes, so an
#: old decryptor refuses a new file instead of misreading it. It is also the
#: HKDF salt and the first bytes of the AEAD associated data, which is what
#: separates this construction's derived keys from any other use of X25519 in
#: this project.
MAGIC = b"contextd-export\x01"

FORMAT = "contextd-export"
VERSION = 1
SUITE = "X25519-HKDF-SHA256-CHACHA20POLY1305"

NONCE_BYTES = 12
KEY_BYTES = 32
#: X25519 raw public keys are exactly 32 bytes; anything else is not one.
RAW_PUBLIC_BYTES = 32

#: A hostile file must not be able to make us allocate arbitrarily. The header
#: is a handful of fixed fields; 64 KiB is orders of magnitude of slack.
MAX_HEADER_BYTES = 64 * 1024

_PREFIX_STRUCT = struct.Struct(">I")


class ExportCryptoError(RuntimeError):
    """Sealing or opening failed. Never carries key material in its message."""


def _digest_of_raw(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def recipient_digest(public: X25519PublicKey) -> str:
    """Identify a recipient by its raw public key, independent of encoding.

    DER and PEM spellings of the same key produce the same digest, so an
    operator who re-exports their public key in the other format does not
    appear to be a different recipient.
    """
    raw = public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _digest_of_raw(raw)


def load_recipient(data: bytes) -> tuple[X25519PublicKey, str]:
    """Parse a recipient public key. Returns the key and its digest.

    Accepts DER or PEM `SubjectPublicKeyInfo`, because the recipient is
    generated on another machine and PEM is what survives being pasted into a
    message or a password manager. Both are parsed by `cryptography`, which
    validates the structure; a raw 32-byte blob is deliberately NOT accepted,
    since it carries no algorithm identifier and so cannot be distinguished
    from an Ed25519 key, a truncated file, or 32 bytes of noise.
    """
    if not isinstance(data, bytes | bytearray):
        raise ExportCryptoError("recipient key must be bytes")
    data = bytes(data)
    if not data.strip():
        raise ExportCryptoError("recipient key file is empty")
    try:
        # Strip whitespace ONLY on the PEM path. DER is binary: an X25519
        # SubjectPublicKeyInfo is 44 bytes ending in 32 bytes of key material,
        # so its last byte is whitespace-valued for about one key in forty --
        # stripping would silently truncate those keys and nothing else.
        if data.lstrip().startswith(b"-----BEGIN"):
            public = serialization.load_pem_public_key(data.strip())
        else:
            public = serialization.load_der_public_key(data)
    except Exception as exc:  # noqa: BLE001 - any parse failure is one refusal
        raise ExportCryptoError(
            "recipient key is not a valid DER or PEM public key"
        ) from exc
    if not isinstance(public, X25519PublicKey):
        raise ExportCryptoError(
            f"recipient key must be X25519, got "
            f"{type(public).__name__.replace('PublicKey', '')}"
        )
    return public, recipient_digest(public)


def _header_bytes(payload: dict) -> bytes:
    """Deterministic JSON.

    Deliberately NOT `contextd.canonical`: that encoding exists to produce the
    exact bytes a signature covers and is write-only by design — its verifiers
    re-encode rather than decode (see the module note in `canonical.py`).
    A decryptor genuinely must *read* this header, because it carries the
    ephemeral public key needed to derive the key at all, so it needs a format
    with a decoder. Determinism still matters here — the bytes are covered by
    the AEAD tag and fed to HKDF — hence sorted keys and fixed separators.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _derive(shared: bytes, header: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=MAGIC,
        info=header,
    ).derive(shared)


def _frame(header: bytes) -> bytes:
    return MAGIC + _PREFIX_STRUCT.pack(len(header)) + header


def seal(
    plaintext: bytes,
    recipient: X25519PublicKey,
    *,
    manifest_sha256: str,
    created_at: str,
) -> bytes:
    """Seal `plaintext` to `recipient`, binding it to a signed manifest.

    `manifest_sha256` is the digest of the enclosed bundle's service-signed
    manifest. Binding it here means the ciphertext and the integrity claim
    travel as one object: a decryptor that opens this file knows exactly which
    signed snapshot it got, and a ciphertext cannot be moved under a different
    manifest without the AEAD tag failing.
    """
    if not isinstance(plaintext, bytes | bytearray):
        raise ExportCryptoError("plaintext must be bytes")
    if not isinstance(recipient, X25519PublicKey):
        raise ExportCryptoError("recipient must be an X25519 public key")
    if not (isinstance(manifest_sha256, str) and len(manifest_sha256) == 64):
        raise ExportCryptoError("manifest_sha256 must be a sha256 hex digest")

    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(recipient)
    header = _header_bytes({
        "format": FORMAT,
        "version": VERSION,
        "suite": SUITE,
        "recipient_sha256": recipient_digest(recipient),
        "ephemeral_public": ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex(),
        "manifest_sha256": manifest_sha256,
        "created_at": created_at,
    })
    key = _derive(shared, header)
    nonce = os.urandom(NONCE_BYTES)
    prefix = _frame(header)
    ciphertext = ChaCha20Poly1305(key).encrypt(
        nonce, bytes(plaintext), prefix
    )
    return prefix + nonce + ciphertext


def peek(blob: bytes) -> dict:
    """Read the header without decrypting. Nothing here is yet authenticated.

    Useful for reporting which recipient a file is addressed to before asking
    for a key. Every field it returns is attacker-chosen until `open_sealed`
    succeeds, so callers must not act on it as though it were verified — it is
    a label on the outside of the envelope, not its contents.
    """
    if not isinstance(blob, bytes | bytearray):
        raise ExportCryptoError("sealed export must be bytes")
    blob = bytes(blob)
    head = len(MAGIC) + _PREFIX_STRUCT.size
    if len(blob) < head or not blob.startswith(MAGIC):
        raise ExportCryptoError("not a contextd sealed export")
    (header_len,) = _PREFIX_STRUCT.unpack(blob[len(MAGIC):head])
    if header_len > MAX_HEADER_BYTES:
        raise ExportCryptoError("sealed export header is implausibly large")
    if len(blob) < head + header_len + NONCE_BYTES:
        raise ExportCryptoError("sealed export is truncated")
    try:
        payload = json.loads(blob[head:head + header_len].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExportCryptoError("sealed export header is unreadable") from exc
    if not isinstance(payload, dict):
        raise ExportCryptoError("sealed export header is not an object")
    return payload


def open_sealed(blob: bytes, private: X25519PrivateKey) -> tuple[bytes, dict]:
    """Open a sealed export. Returns the plaintext and the verified header.

    The header is only trustworthy on the path that returns it: reaching the
    return means the AEAD tag verified over both the ciphertext and the exact
    header bytes, so every field is as the sealer wrote it.
    """
    if not isinstance(private, X25519PrivateKey):
        raise ExportCryptoError("identity must be an X25519 private key")
    payload = peek(blob)
    blob = bytes(blob)

    if payload.get("format") != FORMAT:
        raise ExportCryptoError("not a contextd sealed export")
    if payload.get("version") != VERSION:
        raise ExportCryptoError(
            f"unsupported sealed export version {payload.get('version')!r}; "
            f"this build understands version {VERSION}"
        )
    if payload.get("suite") != SUITE:
        raise ExportCryptoError(
            f"unsupported suite {payload.get('suite')!r}; this build "
            f"understands {SUITE}"
        )

    mine = recipient_digest(private.public_key())
    theirs = payload.get("recipient_sha256")
    if not isinstance(theirs, str) or not hmac.compare_digest(mine, theirs):
        raise ExportCryptoError(
            "this export is addressed to a different recipient"
        )

    raw = payload.get("ephemeral_public")
    if not isinstance(raw, str):
        raise ExportCryptoError("sealed export header has no ephemeral key")
    try:
        ephemeral_raw = bytes.fromhex(raw)
    except ValueError as exc:
        raise ExportCryptoError("sealed export ephemeral key is malformed") from exc
    if len(ephemeral_raw) != RAW_PUBLIC_BYTES:
        raise ExportCryptoError("sealed export ephemeral key is the wrong size")
    try:
        ephemeral = X25519PublicKey.from_public_bytes(ephemeral_raw)
    except ValueError as exc:
        raise ExportCryptoError("sealed export ephemeral key is not on the curve") from exc

    head = len(MAGIC) + _PREFIX_STRUCT.size
    (header_len,) = _PREFIX_STRUCT.unpack(blob[len(MAGIC):head])
    header = blob[head:head + header_len]
    nonce = blob[head + header_len:head + header_len + NONCE_BYTES]
    ciphertext = blob[head + header_len + NONCE_BYTES:]
    if not ciphertext:
        raise ExportCryptoError("sealed export has no ciphertext")

    key = _derive(private.exchange(ephemeral), header)
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(
            nonce, ciphertext, _frame(header)
        )
    except InvalidTag as exc:
        raise ExportCryptoError(
            "sealed export failed authentication: it was altered, truncated, "
            "or sealed to a different key"
        ) from exc
    return plaintext, payload
