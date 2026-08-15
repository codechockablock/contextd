"""Encrypted export: a signed bundle, packed deterministically, sealed off-host.

The flow is deliberately built out of parts that already exist and are already
tested, rather than a second path to the same data:

    create_backup(...)   the existing bundle, with its service-signed manifest
    pack_bundle(...)     that directory -> one deterministic byte stream
    seal(...)            sealed to the recipient (contextd/export_crypto.py)

The plaintext bundle exists only inside `scratch_dir`, which is 0700 and is
removed in a `finally` that raises rather than swallowing a cleanup failure
(`contextd/scratch.py`). "No plaintext scratch" is one of the conditions
`ctx security doctor --strict` checks, so export must not be the thing that
leaves plaintext behind.

**Packing refuses anything that is not a regular file.** A bundle is four
regular files by construction. Honouring a symlink or a device node found in
one would turn "open this export" into arbitrary filesystem writes on whatever
machine performs the recovery — which is, by design, not this one and not
necessarily as careful. Both directions enforce it: packing refuses to write
such an entry, unpacking refuses to read one.

The tar is deterministic (sorted names, zeroed uid/gid/mtime, normalized mode)
so that the same bundle packs to the same bytes. That is not required for
correctness — the AEAD covers whatever bytes are produced — but it means an
operator comparing two exports of the same snapshot sees them differ only
where the encryption is *supposed* to differ.
"""

import io
import tarfile
from datetime import UTC, datetime
from pathlib import Path

from .backup import _atomic_private_write, create_backup
from .export_crypto import ExportCryptoError, load_recipient, seal
from .scratch import scratch_dir

EXPORT_SUFFIX = ".ctxexport"

#: A bundle is small (a SQLite file and three small JSON documents). This bound
#: exists so a hostile export cannot make a recovery machine allocate without
#: limit while unpacking, and is far above any real archive.
MAX_UNPACK_BYTES = 4 * 1024 * 1024 * 1024

#: Fixed epoch for deterministic packing.
_FIXED_MTIME = 0


class ExportError(RuntimeError):
    """Export could not be produced or opened."""


def _deterministic(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = _FIXED_MTIME
    info.mode = 0o600
    return info


def pack_bundle(bundle: Path) -> bytes:
    """Pack a bundle directory into one deterministic, uncompressed tar."""
    bundle = Path(bundle)
    if not bundle.is_dir():
        raise ExportError(f"not a bundle directory: {bundle}")
    members = sorted(p for p in bundle.rglob("*"))
    if not members:
        raise ExportError(f"bundle is empty: {bundle}")

    buffer = io.BytesIO()
    # No compression: the payload is a SQLite file whose compressibility is a
    # property of its contents, and a compressed-then-encrypted stream leaks
    # that property through its length.
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in members:
            if path.is_symlink() or not path.is_file():
                raise ExportError(
                    f"refusing to pack a non-regular entry: "
                    f"{path.relative_to(bundle)}"
                )
            info = _deterministic(
                tar.gettarinfo(str(path), arcname=str(path.relative_to(bundle)))
            )
            with open(path, "rb") as stream:
                tar.addfile(info, stream)
    return buffer.getvalue()


def unpack_bundle(data: bytes, destination: Path) -> Path:
    """Unpack a packed bundle into `destination`. Used on the recovery host.

    Every member name is validated before anything is written: absolute paths,
    `..` traversal, and non-regular entries are refused outright rather than
    sanitized, because a bundle that contains one is not a bundle this project
    produced and guessing at its intent is not recovery.
    """
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        for info in tar.getmembers():
            if not info.isfile():
                raise ExportError(f"refusing non-regular entry: {info.name}")
            name = Path(info.name)
            if name.is_absolute() or ".." in name.parts:
                raise ExportError(f"refusing unsafe entry path: {info.name}")
            total += info.size
            if total > MAX_UNPACK_BYTES:
                raise ExportError("packed bundle exceeds the unpack size limit")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tar.extractfile(info)
            if extracted is None:
                raise ExportError(f"unreadable entry: {info.name}")
            with open(target, "wb") as stream:
                stream.write(extracted.read())
            target.chmod(0o600)
    return destination


def export_name(created_at: datetime) -> str:
    return f"contextd-{created_at.strftime('%Y%m%d-%H%M%S')}{EXPORT_SUFFIX}"


def create_sealed_export(
    conn,
    source_home: Path,
    destination: Path,
    *,
    recipient_key: bytes,
    created_at: datetime | None = None,
    expected_head_id: int | None = None,
    expected_head_hash: str | None = None,
) -> dict:
    """Produce one sealed export file. Returns a summary with no key material.

    `recipient_key` is the DER or PEM public key bytes, passed in rather than
    read here: the caller is responsible for having established WHICH recipient
    is authorized, and under this threat model that decision comes from a
    signed operator action, never from a config file the attacker can rewrite.
    """
    recipient, digest = load_recipient(recipient_key)
    created_at = created_at or datetime.now(UTC)
    destination = Path(destination).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / export_name(created_at)
    if target.exists():
        raise ExportError(f"export already exists: {target}")

    with scratch_dir("export") as work:
        result = create_backup(
            conn, Path(source_home), work,
            expected_head_id=expected_head_id,
            expected_head_hash=expected_head_hash,
        )
        packed = pack_bundle(Path(result["bundle"]))
        sealed = seal(
            packed, recipient,
            manifest_sha256=result["manifest_sha256"],
            created_at=created_at.isoformat().replace("+00:00", "Z"),
        )
        _atomic_private_write(target, sealed)

    return {
        "export": str(target),
        "events": result["events"],
        "blobs": result["blobs"],
        "manifest_sha256": result["manifest_sha256"],
        "recipient_sha256": digest,
        "sealed_bytes": len(sealed),
        "plaintext_bytes": len(packed),
    }


def open_sealed_export(
    sealed: bytes, identity, destination: Path
) -> dict:
    """Open a sealed export into `destination`. For the RECOVERY host.

    This exists so an encrypted export is actually recoverable — an export
    nobody can open is not a backup. It expects the private key to be supplied
    by its caller from wherever the operator keeps it, which is meant to be a
    different machine than the one that produced the export.
    """
    from .export_crypto import open_sealed

    packed, header = open_sealed(sealed, identity)
    unpack_bundle(packed, destination)
    return {
        "destination": str(destination),
        "manifest_sha256": header["manifest_sha256"],
        "recipient_sha256": header["recipient_sha256"],
        "created_at": header["created_at"],
    }


__all__ = [
    "EXPORT_SUFFIX",
    "ExportCryptoError",
    "ExportError",
    "create_sealed_export",
    "export_name",
    "open_sealed_export",
    "pack_bundle",
    "unpack_bundle",
]
