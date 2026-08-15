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
import secrets
import sqlite3
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import db as db_module
from . import home

BUNDLE_FORMAT = "contextd-backup"
BUNDLE_VERSION = 1
BUNDLE_SUFFIX = ".ctxbackup"
MANIFEST_NAME = "manifest.json"
MANIFEST_HASH_NAME = "manifest.sha256"
DATABASE_NAME = "contextd.db"
TRUST_STORE_FORMAT = "contextd-backup-trust"
TRUST_STORE_VERSION = 1
DEFAULT_TRUST_STORE_NAME = "backup-trust.json"
MANIFEST_SIGNATURE_SCHEME = 2
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_HASH_BYTES = 128
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


@dataclass(frozen=True)
class ManifestTrustStore:
    """Immutable public-key pins used to authenticate backup manifests.

    A trust store is deliberately external to the bundle and restored SQLite
    database.  Loading a public key from either of those attacker-controlled
    inputs would turn a signature check into self-attestation.
    """

    _keys: tuple[tuple[str, ec.EllipticCurvePublicKey, str], ...]

    def __post_init__(self) -> None:
        if not isinstance(self._keys, tuple) or not self._keys:
            raise BackupError("manifest trust store contains no public-key pins")
        normalized: list[tuple[str, ec.EllipticCurvePublicKey, str]] = []
        seen: set[str] = set()
        for entry in self._keys:
            if not isinstance(entry, tuple) or len(entry) != 3:
                raise BackupError("manifest trust store contains a malformed key")
            key_id, supplied_key, public_pem = entry
            if key_id in seen:
                raise BackupError(f"duplicate manifest trust key id: {key_id}")
            seen.add(key_id)
            parsed = _parse_trust_pin(key_id, public_pem)
            if (
                not isinstance(supplied_key, ec.EllipticCurvePublicKey)
                or supplied_key.public_numbers() != parsed[1].public_numbers()
            ):
                raise BackupError(
                    f"parsed manifest trust key does not match its pin: {key_id}"
                )
            normalized.append(parsed)
        object.__setattr__(
            self, "_keys", tuple(sorted(normalized, key=lambda item: item[0]))
        )

    @classmethod
    def from_pem_map(cls, pins: Mapping[str, str]) -> ManifestTrustStore:
        parsed: list[tuple[str, ec.EllipticCurvePublicKey, str]] = []
        seen: set[str] = set()
        for key_id, public_pem in pins.items():
            if key_id in seen:
                raise BackupError(f"duplicate manifest trust key id: {key_id}")
            seen.add(key_id)
            parsed.append(_parse_trust_pin(key_id, public_pem))
        if not parsed:
            raise BackupError("manifest trust store contains no public-key pins")
        return cls(tuple(sorted(parsed, key=lambda item: item[0])))

    @classmethod
    def from_connection(cls, conn: sqlite3.Connection) -> ManifestTrustStore:
        """Pin keys from an already-trusted live archive, never a bundle DB."""
        try:
            rows = conn.execute(
                "SELECT key_id, public_pem FROM service_keys ORDER BY key_id"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise BackupError("trusted archive has no service signing keys") from exc
        pins: dict[str, str] = {}
        for row in rows:
            key_id, public_pem = row[0], row[1]
            if key_id in pins:
                raise BackupError(f"duplicate manifest trust key id: {key_id}")
            pins[key_id] = public_pem
        return cls.from_pem_map(pins)

    @classmethod
    def load(cls, path: Path) -> ManifestTrustStore:
        path = Path(path).expanduser()
        try:
            raw = _read_secure_file(path, "manifest trust store")
            document = json.loads(raw)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
        ) as exc:
            raise BackupError("manifest trust store is unreadable or invalid") from exc
        if _canonical_json(document) != raw:
            raise BackupError("manifest trust store is not canonical JSON")
        if not isinstance(document, dict) or set(document) != {
            "format",
            "version",
            "keys",
        }:
            raise BackupError("manifest trust store is malformed")
        if (
            document["format"] != TRUST_STORE_FORMAT
            or type(document["version"]) is not int
            or document["version"] != TRUST_STORE_VERSION
            or not isinstance(document["keys"], list)
        ):
            raise BackupError("unsupported manifest trust store format or version")
        pins: dict[str, str] = {}
        for entry in document["keys"]:
            if not isinstance(entry, dict) or set(entry) != {"key_id", "public_pem"}:
                raise BackupError("manifest trust store contains a malformed key")
            key_id, public_pem = entry["key_id"], entry["public_pem"]
            if key_id in pins:
                if pins[key_id] != public_pem:
                    raise BackupError(
                        f"conflicting manifest trust key id: {key_id}"
                    )
                raise BackupError(f"duplicate manifest trust key id: {key_id}")
            pins[key_id] = public_pem
        return cls.from_pem_map(pins)

    @property
    def pem_map(self) -> dict[str, str]:
        return {key_id: public_pem for key_id, _key, public_pem in self._keys}

    def public_key(self, key_id: str) -> ec.EllipticCurvePublicKey:
        for pinned_id, key, _pem in self._keys:
            if pinned_id == key_id:
                return key
        raise BackupError(f"manifest signing key is not pinned: {key_id}")

    def merged(self, other: ManifestTrustStore) -> ManifestTrustStore:
        pins = self.pem_map
        for key_id, public_pem in other.pem_map.items():
            existing = pins.get(key_id)
            if existing is not None and existing != public_pem:
                raise BackupError(f"conflicting manifest trust key id: {key_id}")
            pins[key_id] = public_pem
        return type(self).from_pem_map(pins)

    def canonical_bytes(self) -> bytes:
        return _canonical_json(
            {
                "format": TRUST_STORE_FORMAT,
                "version": TRUST_STORE_VERSION,
                "keys": [
                    {"key_id": key_id, "public_pem": public_pem}
                    for key_id, _key, public_pem in self._keys
                ],
            }
        )


@dataclass(frozen=True)
class LegacyBundlePolicy:
    """Explicit pins for intentionally accepted unsigned legacy bundles.

    The pin is the SHA-256 of the exact canonical manifest.  This exception is
    suitable only for a one-time operator-reviewed migration; hardened RPCs
    must never construct or accept this policy.
    """

    allowed_manifest_sha256: frozenset[str]

    def __post_init__(self) -> None:
        if not self.allowed_manifest_sha256 or any(
            not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest)
            for digest in self.allowed_manifest_sha256
        ):
            raise BackupError("legacy bundle policy requires exact manifest pins")


def _parse_trust_pin(
    key_id: str, public_pem: str
) -> tuple[str, ec.EllipticCurvePublicKey, str]:
    from .canonical import canonical_digest

    if not isinstance(key_id, str) or not re.fullmatch(r"[0-9a-f]{32}", key_id):
        raise BackupError(f"invalid manifest trust key id: {key_id!r}")
    if not isinstance(public_pem, str):
        raise BackupError(f"invalid public key for manifest trust pin {key_id}")
    try:
        key = serialization.load_pem_public_key(public_pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise BackupError(f"invalid public key for manifest trust pin {key_id}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise BackupError(f"manifest trust pin {key_id} is not a P-256 key")
    expected = canonical_digest("contextd.ServiceKeyV1", {"pem": public_pem})[:32]
    if key_id != expected:
        raise BackupError(f"manifest trust key id does not match public key: {key_id}")
    return key_id, key, public_pem


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


_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
    os, "O_CLOEXEC", 0
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _absolute(path: Path) -> Path:
    """Lexically normalize a path without following attacker-controlled links."""
    absolute = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    # Darwin exposes fixed, root-owned compatibility links such as /var ->
    # /private/var. Normalize only those OS aliases; resolving arbitrary path
    # components here would reintroduce the symlink-redirection vulnerability.
    if sys.platform == "darwin" and len(absolute.parts) >= 2:
        aliases = {
            "var": Path("/private/var"),
            "tmp": Path("/private/tmp"),
            "etc": Path("/private/etc"),
        }
        replacement = aliases.get(absolute.parts[1])
        link = Path("/") / absolute.parts[1]
        if (
            replacement is not None
            and link.is_symlink()
            and link.resolve(strict=True) == replacement
        ):
            absolute = replacement.joinpath(*absolute.parts[2:])
    return absolute


def normalized_path(path: Path | str | os.PathLike[str]) -> str:
    """Canonical lexical identity shared by authorization and execution."""
    return str(_absolute(Path(path)))


def _secure_mode(stat_result: os.stat_result, label: str) -> None:
    mode = stat_result.st_mode
    if mode & 0o022:
        # Test archives live below the platform temp root. Production does not
        # get the sticky-directory exception: a pin below a writable ancestor
        # is not an independent trust anchor.
        sticky_root = bool(mode & 0o1000) and stat_result.st_uid == 0
        temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
        test_home = _absolute(home())
        isolated_test = (
            os.environ.get("CONTEXTD_INSECURE_TEST_SIGNER") == "1"
            and (test_home == temp_root or temp_root in test_home.parents)
        )
        if not (sticky_root and isolated_test):
            raise BackupError(f"{label} is group/world-writable")


def _open_directory(
    path: Path, *, create: bool = False, require_secure_modes: bool = False
) -> int:
    """Open a directory one component at a time without following symlinks."""
    absolute = _absolute(path)
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        if require_secure_modes:
            _secure_mode(os.fstat(descriptor), "manifest trust store parent /")
        current = Path("/")
        for part in absolute.parts[1:]:
            current /= part
            try:
                child = os.open(part, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise BackupError(f"directory does not exist: {current}") from None
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                try:
                    child = os.open(
                        part, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=descriptor
                    )
                except OSError as exc:
                    raise BackupError(
                        f"cannot safely create directory component: {current}"
                    ) from exc
            except OSError as exc:
                raise BackupError(
                    f"refusing symlinked or unsafe directory component: {current}"
                ) from exc
            os.close(descriptor)
            descriptor = child
            if require_secure_modes:
                _secure_mode(os.fstat(descriptor), f"manifest trust store parent {current}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _assert_path_matches_fd(path: Path, descriptor: int, label: str) -> None:
    try:
        actual = os.stat(_absolute(path), follow_symlinks=False)
    except OSError as exc:
        raise BackupError(f"{label} changed while it was in use") from exc
    pinned = os.fstat(descriptor)
    if (actual.st_dev, actual.st_ino) != (pinned.st_dev, pinned.st_ino):
        raise BackupError(f"{label} changed while it was in use")


def _read_secure_file(path: Path, label: str) -> bytes:
    absolute = _absolute(path)
    parent_fd = _open_directory(
        absolute.parent, create=False, require_secure_modes=True
    )
    try:
        try:
            descriptor = os.open(
                absolute.name,
                os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise BackupError(f"{label} is missing, symlinked, or unreadable") from exc
        try:
            stat_result = os.fstat(descriptor)
            import stat

            if not stat.S_ISREG(stat_result.st_mode):
                raise BackupError(f"{label} is not a regular file")
            if stat_result.st_nlink != 1:
                raise BackupError(f"{label} must not be hard-linked")
            if stat_result.st_mode & 0o077:
                raise BackupError(f"{label} is group/world-accessible")
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                payload = stream.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise BackupError(f"{label} is unreasonably large")
            return payload
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _assert_secure_regular_file(path: Path, label: str) -> None:
    _read_secure_file(path, label)


def _atomic_private_write(path: Path, payload: bytes) -> None:
    absolute = _absolute(path)
    parent_fd = _open_directory(
        absolute.parent, create=False, require_secure_modes=True
    )
    temporary = f".{absolute.name}.{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | _NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent_fd,
            )
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.rename(
                temporary,
                absolute.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(parent_fd)


def write_manifest_trust_store(
    conn: sqlite3.Connection, path: Path | None = None
) -> ManifestTrustStore:
    """Atomically persist append-only pins from a trusted live archive."""
    trust_path = _absolute(path or (home() / DEFAULT_TRUST_STORE_NAME))
    current = ManifestTrustStore.from_connection(conn)
    try:
        existing = ManifestTrustStore.load(trust_path)
    except BackupError:
        if trust_path.exists() or trust_path.is_symlink():
            raise
        combined = current
    else:
        combined = existing.merged(current)
    _atomic_private_write(trust_path, combined.canonical_bytes())
    return combined


def _coerce_trust_store(
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None,
) -> ManifestTrustStore:
    if isinstance(trust_store, ManifestTrustStore):
        return trust_store
    return ManifestTrustStore.load(
        Path(trust_store) if trust_store is not None else home() / DEFAULT_TRUST_STORE_NAME
    )


def _trust_store_is_inside_bundle(
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None,
    bundle: Path,
) -> bool:
    if trust_store is None or isinstance(trust_store, ManifestTrustStore):
        return False
    trust_path = _absolute(Path(trust_store))
    return trust_path == bundle or bundle in trust_path.parents


def _random_directory_at(parent_fd: int, prefix: str) -> tuple[str, int]:
    for _attempt in range(128):
        name = f"{prefix}{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        descriptor = os.open(name, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=parent_fd)
        return name, descriptor
    raise BackupError("could not allocate a private staging directory")


def _remove_tree_at(
    parent_fd: int,
    name: str,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    """Remove one private staging tree without following links."""
    import stat

    try:
        directory_fd = os.open(name, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        opened = os.fstat(directory_fd)
        if expected_identity is not None and (
            opened.st_dev,
            opened.st_ino,
        ) != expected_identity:
            raise BackupError(f"refusing to remove replaced directory: {name}")
        for child in os.listdir(directory_fd):
            child_stat = os.stat(child, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(child_stat.st_mode):
                _remove_tree_at(
                    directory_fd,
                    child,
                    expected_identity=(child_stat.st_dev, child_stat.st_ino),
                )
            else:
                os.unlink(child, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        raise BackupError(f"refusing to remove replaced directory: {name}")
    os.rmdir(name, dir_fd=parent_fd)


def _copy_regular_fd(source_fd: int, destination_fd: int) -> None:
    while True:
        block = os.read(source_fd, 1024 * 1024)
        if not block:
            break
        view = memoryview(block)
        while view:
            written = os.write(destination_fd, view)
            view = view[written:]
    os.fsync(destination_fd)


def _copy_named_regular(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
    label: str,
) -> None:
    """Copy one regular file without a lookup/open substitution window."""
    import stat

    before = os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        raise BackupError(f"refusing symlinked {label}")
    if not stat.S_ISREG(before.st_mode):
        raise BackupError(f"{label} is not a regular file")
    try:
        source_fd = os.open(
            source_name,
            os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=source_parent_fd,
        )
    except OSError as exc:
        raise BackupError(f"{label} changed while it was opened") from exc
    destination_fd: int | None = None
    try:
        opened = os.fstat(source_fd)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise BackupError(f"{label} changed while it was opened")
        destination_fd = os.open(
            destination_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | _NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=destination_parent_fd,
        )
        _copy_regular_fd(source_fd, destination_fd)
        after = os.fstat(source_fd)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise BackupError(f"{label} changed during copy")
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)


def _open_child_directory(parent_fd: int, name: str, *, create: bool = False) -> int:
    try:
        return os.open(name, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        try:
            return os.open(name, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=parent_fd)
        except OSError as exc:
            raise BackupError(f"unsafe directory component: {name}") from exc
    except OSError as exc:
        raise BackupError(f"unsafe directory component: {name}") from exc


def _copy_tree_from_fd(
    source_fd: int,
    destination_fd: int,
    prefix: str = "",
    *,
    expected_sizes: Mapping[str, int] | None = None,
) -> None:
    """Snapshot a hostile tree through pinned descriptors and O_NOFOLLOW."""
    import stat

    for name in sorted(os.listdir(source_fd)):
        if not name or name in {".", ".."} or "/" in name:
            raise BackupError(f"unsafe bundle entry name: {name!r}")
        relative = f"{prefix}/{name}" if prefix else name
        before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            if expected_sizes is not None and not any(
                expected.startswith(relative + "/") for expected in expected_sizes
            ):
                raise BackupError(f"bundle has unexpected directory: {relative}")
            try:
                child_source = os.open(
                    name, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=source_fd
                )
            except OSError as exc:
                raise BackupError(f"bundle directory changed during copy: {relative}") from exc
            try:
                opened = os.fstat(child_source)
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise BackupError(f"bundle directory changed during copy: {relative}")
                os.mkdir(name, 0o700, dir_fd=destination_fd)
                child_destination = os.open(
                    name, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=destination_fd
                )
                try:
                    _copy_tree_from_fd(
                        child_source,
                        child_destination,
                        relative,
                        expected_sizes=expected_sizes,
                    )
                    os.fsync(child_destination)
                finally:
                    os.close(child_destination)
            finally:
                os.close(child_source)
        elif stat.S_ISREG(before.st_mode):
            if expected_sizes is not None:
                if relative not in expected_sizes:
                    raise BackupError(f"bundle has unexpected file: {relative}")
                if before.st_size != expected_sizes[relative]:
                    raise BackupError(f"payload size mismatch: {relative}")
            try:
                child_source = os.open(
                    name,
                    os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=source_fd,
                )
            except OSError as exc:
                raise BackupError(f"bundle file changed during copy: {relative}") from exc
            child_destination: int | None = None
            try:
                opened = os.fstat(child_source)
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise BackupError(f"bundle file changed during copy: {relative}")
                child_destination = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | _NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=destination_fd,
                )
                _copy_regular_fd(child_source, child_destination)
                after = os.fstat(child_source)
                if (
                    (opened.st_dev, opened.st_ino, opened.st_size)
                    != (after.st_dev, after.st_ino, after.st_size)
                    or opened.st_mtime_ns != after.st_mtime_ns
                ):
                    raise BackupError(f"bundle file changed during copy: {relative}")
            finally:
                if child_destination is not None:
                    os.close(child_destination)
                os.close(child_source)
        elif stat.S_ISLNK(before.st_mode):
            raise BackupError(f"bundle contains a symlink: {relative}")
        else:
            raise BackupError(f"bundle contains a special file: {relative}")


def _inventory_tree_fd(directory_fd: int, prefix: str = "") -> dict[str, int]:
    """Inventory regular files without following or copying hostile entries."""
    import stat

    inventory: dict[str, int] = {}
    for name in sorted(os.listdir(directory_fd)):
        if not name or name in {".", ".."} or "/" in name:
            raise BackupError(f"unsafe bundle entry name: {name!r}")
        relative = f"{prefix}/{name}" if prefix else name
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(entry.st_mode):
            child_fd = _open_child_directory(directory_fd, name)
            try:
                inventory.update(_inventory_tree_fd(child_fd, relative))
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(entry.st_mode):
            inventory[relative] = entry.st_size
        elif stat.S_ISLNK(entry.st_mode):
            raise BackupError(f"bundle contains a symlink: {relative}")
        else:
            raise BackupError(f"bundle contains a special file: {relative}")
    return inventory


def _preflight_bundle_fd(
    source_fd: int,
    stage: Path,
    stage_fd: int,
    *,
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None,
    legacy_policy: LegacyBundlePolicy | None,
) -> dict[str, Any]:
    """Authenticate the small envelope and inventory before payload copying."""
    for name in (MANIFEST_NAME, MANIFEST_HASH_NAME):
        try:
            source_stat = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise BackupError(f"bundle is missing {name}") from exc
        maximum = (
            MAX_MANIFEST_BYTES if name == MANIFEST_NAME else MAX_MANIFEST_HASH_BYTES
        )
        if source_stat.st_size > maximum:
            raise BackupError(f"bundle {name} is unreasonably large")
        _copy_named_regular(source_fd, name, stage_fd, name, f"bundle {name}")
    manifest, entries = _manifest(stage)
    manifest_sha256 = _sha256(stage / MANIFEST_NAME)
    authentication = _authenticate_manifest(
        manifest, manifest_sha256, trust_store, legacy_policy
    )
    inventory = _inventory_tree_fd(source_fd)
    expected = set(entries) | {MANIFEST_NAME, MANIFEST_HASH_NAME}
    actual = set(inventory)
    missing, unexpected = expected - actual, actual - expected
    if missing:
        raise BackupError(f"bundle is missing files: {', '.join(sorted(missing))}")
    if unexpected:
        raise BackupError(
            f"bundle has unexpected files: {', '.join(sorted(unexpected))}"
        )
    for relative, entry in entries.items():
        if inventory[relative] != entry["size"]:
            raise BackupError(f"payload size mismatch: {relative}")
    os.unlink(MANIFEST_NAME, dir_fd=stage_fd)
    os.unlink(MANIFEST_HASH_NAME, dir_fd=stage_fd)
    return {
        "manifest_sha256": manifest_sha256,
        "signing_key_id": (manifest.get("service_signature") or {}).get("key_id"),
        "authentication": authentication,
        "expected_sizes": {
            **{relative: entry["size"] for relative, entry in entries.items()},
            MANIFEST_NAME: inventory[MANIFEST_NAME],
            MANIFEST_HASH_NAME: inventory[MANIFEST_HASH_NAME],
        },
    }


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


def _signable_v1(manifest: dict) -> dict:
    """Compatibility payload for already-created signed v1 bundles."""
    payload = {
        key: _signature_scrub(manifest[key])
        for key in ("format", "version", "created_at", "snapshot")
    }
    payload["files"] = [entry["sha256"] for entry in manifest["files"]]
    payload["blobs"] = list(manifest["blobs"])
    return payload


def _signature_scrub(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, dict):
        return {key: _signature_scrub(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_signature_scrub(item) for item in value]
    return value


def _signable(manifest: dict) -> dict:
    """The manifest fields a signature covers, in a canonically encodable form.

    An empty archive has a null tip, and the canonical encoder refuses None on
    purpose (absence must be an omitted key, not a value) — so nulls are mapped
    to the empty string here rather than the encoder being loosened for one
    caller.
    """
    payload = {
        key: _signature_scrub(manifest[key])
        for key in ("format", "version", "created_at", "snapshot")
    }
    # Bind paths and sizes as well as hashes. Provenance must not depend on
    # semantic validators deciding that two differently named inventories are
    # equivalent.
    payload["files"] = [_signature_scrub(entry) for entry in manifest["files"]]
    payload["blobs"] = list(manifest["blobs"])
    return payload


def _sign_manifest(conn, manifest: dict) -> dict:
    """Sign the manifest with the service key, if one is available.

    Returns ``{"signed": false, "why": ...}`` rather than raising when the
    archive has no service key: a backup must still be creatable in an archive
    that has never run the authority plane, and `validate_bundle` reports the
    difference instead of treating unsigned as signed.
    """
    from .canonical import canonical_bytes
    from .ledger_sig import _load_or_create_key
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    try:
        private, key_id = _load_or_create_key(conn)
    except Exception as exc:                    # noqa: BLE001
        return {"signed": False, "why": type(exc).__name__}
    payload = _signable(manifest)
    signature = private.sign(
        canonical_bytes("contextd.BackupManifestV1", payload),
        _ec.ECDSA(_hashes.SHA256()))
    return {
        "signed": True,
        "scheme": MANIFEST_SIGNATURE_SCHEME,
        "key_id": key_id,
        "signature": signature.hex(),
    }


def verify_manifest_signature(
    trust_store: ManifestTrustStore
    | str
    | os.PathLike[str]
    | sqlite3.Connection,
    manifest: dict,
) -> dict:
    """Verify a manifest against explicit pins or a trusted live connection.

    Passing a connection is retained for callers that already hold a trusted
    live archive.  Restore and validation never construct this argument from
    the bundle database.
    """
    from .canonical import canonical_bytes

    block = manifest.get("service_signature")
    if not isinstance(block, dict) or block.get("signed") is not True:
        return {
            "ok": False,
            "signed": False,
            "why": "the bundle manifest carries no service signature",
        }
    scheme = block.get("scheme", 1)
    expected_fields = {"signed", "key_id", "signature"}
    if scheme == MANIFEST_SIGNATURE_SCHEME:
        expected_fields.add("scheme")
    if (
        set(block) != expected_fields
        or type(scheme) is not int
        or scheme not in (1, MANIFEST_SIGNATURE_SCHEME)
    ):
        return {
            "ok": False,
            "signed": True,
            "why": "manifest signature block is malformed",
        }
    try:
        if isinstance(trust_store, sqlite3.Connection):
            pins = ManifestTrustStore.from_connection(trust_store)
        else:
            pins = _coerce_trust_store(trust_store)
    except BackupError as exc:
        return {
            "ok": False,
            "signed": True,
            "why": f"manifest signature trust failed: {exc}",
        }
    key_id, signature = block["key_id"], block["signature"]
    if (
        not isinstance(key_id, str)
        or not re.fullmatch(r"[0-9a-f]{32}", key_id)
        or not isinstance(signature, str)
        or not re.fullmatch(r"[0-9a-f]+", signature)
        or len(signature) % 2
    ):
        return {
            "ok": False,
            "signed": True,
            "why": "manifest signature block is malformed",
        }
    try:
        payload = (
            _signable(manifest)
            if scheme == MANIFEST_SIGNATURE_SCHEME
            else _signable_v1(manifest)
        )
    except (KeyError, TypeError, ValueError) as exc:
        return {
            "ok": False,
            "signed": True,
            "why": f"manifest signed payload is malformed: {type(exc).__name__}",
        }
    try:
        pins.public_key(key_id).verify(
            bytes.fromhex(signature),
            canonical_bytes("contextd.BackupManifestV1", payload),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError, BackupError) as exc:
        return {
            "ok": False,
            "signed": True,
            "why": "manifest signature does not verify: "
            f"{type(exc).__name__}{f': {exc}' if str(exc) else ''}",
        }
    return {
        "ok": True,
        "signed": True,
        "key_id": key_id,
        "signature_scheme": scheme,
    }


def _authenticate_manifest(
    manifest: dict[str, Any],
    manifest_sha256: str,
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None,
    legacy_policy: LegacyBundlePolicy | None,
) -> dict[str, Any]:
    block = manifest.get("service_signature")
    if isinstance(block, dict) and block.get("signed") is True:
        verification = verify_manifest_signature(
            _coerce_trust_store(trust_store), manifest
        )
        if not verification["ok"]:
            raise BackupError(verification["why"])
        return {"authenticated": True, **verification}
    if legacy_policy is not None and (
        manifest_sha256 in legacy_policy.allowed_manifest_sha256
    ):
        return {
            "authenticated": False,
            "signed": False,
            "legacy_manifest_pin": manifest_sha256,
        }
    raise BackupError(
        "bundle manifest is unsigned; an exact LegacyBundlePolicy pin is required"
    )


def _snapshot_has_signature_cutover(database: Path) -> bool:
    conn = sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True)
    try:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='service_tips'"
        ).fetchone()
        if table is None:
            return False
        return (
            conn.execute("SELECT 1 FROM service_tips WHERE cutover = 1 LIMIT 1").fetchone()
            is not None
        )
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"cannot inspect snapshot signature cutover: {exc}") from exc
    finally:
        conn.close()


def _new_bundle_path(destination: Path, stamp: str) -> Path:
    # Never reuse a freed name. Retention and the restore drill both order
    # bundles by (stamp, sequence); if pruning frees the bare-stamp name and
    # a same-second backup takes it again, that ordering disagrees with
    # creation order — retention would prune the newest bundle and the drill
    # would restore a stale one. The sequence within a stamp only rises.
    taken = [
        int(match["sequence"] or 0)
        for path in destination.iterdir()
        if (match := _BUNDLE_NAME_RE.fullmatch(path.name))
        and match["stamp"] == stamp
    ]
    index = max(taken) + 1 if taken else 0
    if index == 0:
        return destination / f"contextd-{stamp}{BUNDLE_SUFFIX}"
    return destination / f"contextd-{stamp}-{index}{BUNDLE_SUFFIX}"


def _is_bundle(
    path: Path,
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None = None,
) -> bool:
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
        validate_bundle(path, trust_store=trust_store)
    except Exception:
        # Retention is deliberately fail-closed: anything we cannot prove is
        # a complete bundle is preserved for operator inspection.
        return False
    return True


def prune_bundles(
    destination: Path,
    keep: int,
    *,
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None = None,
) -> list[Path]:
    """Remove only complete verified bundles, never partial or legacy state."""
    if keep < 0:
        raise BackupError("retention count cannot be negative")
    if keep == 0:
        return []

    def creation_key(path: Path) -> tuple[str, int]:
        match = _BUNDLE_NAME_RE.fullmatch(path.name)
        assert match is not None
        return match["stamp"], int(match["sequence"] or 0)

    destination = _absolute(destination)
    destination_fd = _open_directory(destination)
    try:
        _assert_path_matches_fd(destination, destination_fd, "backup destination")
        bundles: list[tuple[Path, tuple[int, int]]] = []
        for name in os.listdir(destination_fd):
            path = destination / name
            try:
                before = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not _is_bundle(path, trust_store=trust_store):
                continue
            try:
                after = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            identity = (before.st_dev, before.st_ino)
            if identity == (after.st_dev, after.st_ino):
                bundles.append((path, identity))
        bundles.sort(key=lambda item: creation_key(item[0]))
        old = bundles[:-keep]
        for path, identity in old:
            _remove_tree_at(destination_fd, path.name, expected_identity=identity)
        if old:
            os.fsync(destination_fd)
        return [path for path, _identity in old]
    finally:
        os.close(destination_fd)


def create_backup(
    conn: sqlite3.Connection,
    source_home: Path,
    destination: Path,
    *,
    keep: int = 0,
    created_at: datetime | None = None,
    expected_head_id: int | None = None,
    expected_head_hash: str | None = None,
) -> dict[str, Any]:
    """Create and atomically publish a complete archive backup bundle."""
    source_home = Path(source_home).expanduser()
    destination = Path(destination).expanduser()
    if keep < 0:
        raise BackupError("retention count cannot be negative")
    if (expected_head_id is None) != (expected_head_hash is None):
        raise BackupError("expected backup head id and hash must be supplied together")
    if expected_head_id is not None:
        if (
            type(expected_head_id) is not int
            or expected_head_id < 0
            or not isinstance(expected_head_hash, str)
            or (
                expected_head_hash != ""
                and not _DIGEST_RE.fullmatch(expected_head_hash)
            )
            or (expected_head_id == 0) != (expected_head_hash == "")
        ):
            raise BackupError("expected backup head is malformed")
    database_row = conn.execute("PRAGMA database_list").fetchone()
    database_file = (
        database_row["file"]
        if isinstance(database_row, sqlite3.Row)
        else database_row[2]
    )
    if not database_file:
        raise BackupError("database connection does not belong to the source archive")
    try:
        source_fd = _open_directory(source_home)
    except BackupError as exc:
        raise BackupError(
            "database connection does not belong to the source archive"
        ) from exc
    try:
        import stat

        source_database = os.stat(
            DATABASE_NAME, dir_fd=source_fd, follow_symlinks=False
        )
        connected_database = os.stat(database_file, follow_symlinks=False)
        if (
            not stat.S_ISREG(source_database.st_mode)
            or not stat.S_ISREG(connected_database.st_mode)
            or (source_database.st_dev, source_database.st_ino)
            != (connected_database.st_dev, connected_database.st_ino)
        ):
            raise BackupError(
                "database connection does not belong to the source archive"
            )
    except OSError as exc:
        os.close(source_fd)
        raise BackupError(
            "database connection does not belong to the source archive"
        ) from exc
    except BackupError:
        os.close(source_fd)
        raise
    try:
        destination_fd = _open_directory(destination, create=True)
    except BaseException:
        os.close(source_fd)
        raise
    try:
        os.fchmod(destination_fd, 0o700)
        when = created_at or datetime.now(timezone.utc)
        stamp = when.astimezone(timezone.utc).strftime("%Y%m%d-%H%M%S")
        _assert_path_matches_fd(destination, destination_fd, "backup destination")
        bundle = _new_bundle_path(destination, stamp)
        stage_name, stage_fd = _random_directory_at(
            destination_fd, ".contextd-backup-"
        )
    except BaseException:
        os.close(source_fd)
        os.close(destination_fd)
        raise
    stage = destination / stage_name
    try:
        _assert_path_matches_fd(source_home, source_fd, "source archive")
        _assert_path_matches_fd(destination, destination_fd, "backup destination")
        database = stage / DATABASE_NAME
        # The witness lock is the global append lock. Hold it across the online
        # SQLite snapshot and external-state copy so the three artifacts
        # describe one exact, recoverable tip even with concurrent writers.
        # Do not consume a recovery journal here: it is part of the state a
        # complete backup must preserve, and bundle validation proves that the
        # copied database/witness/journal triple can reconcile.
        with db_module._chain_lock(source_home):
            if expected_head_id is not None:
                current_tip = db_module._db_tip(conn)
                expected_tip = {
                    "id": expected_head_id,
                    "chain_hash": expected_head_hash,
                }
                if current_tip != expected_tip:
                    raise BackupError(
                        "archive tip changed after backup authorization: "
                        f"expected #{expected_head_id} {expected_head_hash}, "
                        f"found #{current_tip['id']} {current_tip['chain_hash']}"
                    )
            _assert_path_matches_fd(destination, destination_fd, "backup destination")
            _assert_path_matches_fd(stage, stage_fd, "backup staging directory")
            _snapshot_database(conn, database)
            for name in OPTIONAL_STATE_NAMES:
                try:
                    os.stat(name, dir_fd=source_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _copy_named_regular(
                    source_fd,
                    name,
                    stage_fd,
                    name,
                    f"archive state {name}",
                )
        snapshot = _validate_database(database)
        _validate_chain_state(stage, snapshot)

        blobs = sorted(_referenced_blobs(database))
        source_store_fd: int | None = None
        stage_store_fd: int | None = None
        if blobs:
            try:
                source_store_fd = _open_child_directory(source_fd, "store")
            except FileNotFoundError as exc:
                raise BackupError("archive blob store is missing") from exc
            stage_store_fd = _open_child_directory(stage_fd, "store", create=True)
        try:
            for digest in blobs:
                assert source_store_fd is not None and stage_store_fd is not None
                try:
                    source_shard_fd = _open_child_directory(
                        source_store_fd, digest[:2]
                    )
                except FileNotFoundError as exc:
                    raise BackupError(f"missing referenced blob: {digest}") from exc
                stage_shard_fd: int | None = None
                try:
                    stage_shard_fd = _open_child_directory(
                        stage_store_fd, digest[:2], create=True
                    )
                    try:
                        _copy_named_regular(
                            source_shard_fd,
                            digest,
                            stage_shard_fd,
                            digest,
                            f"referenced blob {digest}",
                        )
                    except FileNotFoundError as exc:
                        raise BackupError(f"missing referenced blob: {digest}") from exc
                finally:
                    os.close(source_shard_fd)
                    if stage_shard_fd is not None:
                        os.close(stage_shard_fd)
                copied_blob = stage / "store" / digest[:2] / digest
                if _sha256(copied_blob) != digest:
                    raise BackupError(f"corrupt referenced blob: {digest}")
        finally:
            if source_store_fd is not None:
                os.close(source_store_fd)
            if stage_store_fd is not None:
                os.close(stage_store_fd)

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
        # A manifest hash proves the bundle is internally consistent; it proves
        # nothing about who made it, because whoever rewrote the bundle also
        # rewrote the hash. The service signature is what an attacker who
        # rebuilds a bundle cannot produce.
        manifest["service_signature"] = _sign_manifest(conn, manifest)
        trust_store = write_manifest_trust_store(
            conn, source_home / DEFAULT_TRUST_STORE_NAME
        )
        manifest_bytes = _canonical_json(manifest)
        (stage / MANIFEST_NAME).write_bytes(manifest_bytes)
        os.chmod(stage / MANIFEST_NAME, 0o600)
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        (stage / MANIFEST_HASH_NAME).write_text(manifest_hash + "\n")
        os.chmod(stage / MANIFEST_HASH_NAME, 0o600)
        _validate_bundle_tree(
            stage, trust_store=trust_store, legacy_policy=None
        )
        _fsync_tree(stage)
        _assert_path_matches_fd(destination, destination_fd, "backup destination")
        try:
            os.stat(bundle.name, dir_fd=destination_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise BackupError(f"backup bundle destination already exists: {bundle}")
        os.rename(
            stage_name,
            bundle.name,
            src_dir_fd=destination_fd,
            dst_dir_fd=destination_fd,
        )
        os.fsync(destination_fd)
        pruned = prune_bundles(destination, keep, trust_store=trust_store)
        return {
            "bundle": bundle,
            "events": snapshot["events"],
            "blobs": len(blobs),
            "manifest_sha256": manifest_hash,
            "pruned": pruned,
        }
    except BaseException:
        _remove_tree_at(destination_fd, stage_name)
        raise
    finally:
        os.close(stage_fd)
        os.close(source_fd)
        os.close(destination_fd)


def _manifest(
    bundle: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise BackupError(f"backup bundle is not a directory: {bundle}")
    manifest_path = bundle / MANIFEST_NAME
    digest_path = bundle / MANIFEST_HASH_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise BackupError("bundle is missing a regular manifest.json")
    if not digest_path.is_file() or digest_path.is_symlink():
        raise BackupError("bundle is missing a regular manifest.sha256")
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise BackupError("bundle manifest.json is unreasonably large")
    if digest_path.stat().st_size > MAX_MANIFEST_HASH_BYTES:
        raise BackupError("bundle manifest.sha256 is unreasonably large")
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
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
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
        # Name the exact skew: a bundle from a future contextd must be
        # refused as "too new", never half-attempted with today's reader.
        raise BackupError(
            "unsupported backup bundle format or version: "
            f"format={manifest.get('format')!r} "
            f"version={manifest.get('version')!r} "
            f"(this contextd reads {BUNDLE_FORMAT} v{BUNDLE_VERSION})"
        )
    required_keys = {
        "format",
        "version",
        "created_at",
        "snapshot",
        "blobs",
        "files",
    }
    if set(manifest) not in (required_keys, required_keys | {"service_signature"}):
        raise BackupError("manifest.json contains missing or unsupported fields")
    created_at = manifest["created_at"]
    if not isinstance(created_at, str):
        raise BackupError("manifest created_at is invalid")
    try:
        parsed_created_at = datetime.fromisoformat(created_at)
    except ValueError as exc:
        raise BackupError("manifest created_at is invalid") from exc
    if parsed_created_at.tzinfo is None:
        raise BackupError("manifest created_at must carry a timezone")
    snapshot = manifest["snapshot"]
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "events",
        "head_id",
        "head_hash",
    }:
        raise BackupError("manifest snapshot is malformed")
    if (
        type(snapshot["events"]) is not int
        or snapshot["events"] < 0
        or (
            snapshot["head_id"] is not None
            and (type(snapshot["head_id"]) is not int or snapshot["head_id"] < 1)
        )
        or not isinstance(snapshot["head_hash"], str)
        or (
            snapshot["head_hash"] != ""
            and not _DIGEST_RE.fullmatch(snapshot["head_hash"])
        )
    ):
        raise BackupError("manifest snapshot is malformed")
    if (snapshot["head_id"] is None) != (snapshot["events"] == 0):
        raise BackupError("manifest snapshot is internally inconsistent")
    blobs = manifest["blobs"]
    if (
        not isinstance(blobs, list)
        or any(not isinstance(item, str) or not _DIGEST_RE.fullmatch(item) for item in blobs)
        or blobs != sorted(set(blobs))
    ):
        raise BackupError("manifest blobs must be sorted unique SHA-256 digests")
    if not isinstance(manifest.get("files"), list):
        raise BackupError("manifest files must be a list")
    entries: dict[str, dict[str, Any]] = {}
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
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
    if list(entries) != sorted(entries):
        raise BackupError("manifest file entries are not in canonical path order")
    if DATABASE_NAME not in entries:
        raise BackupError("bundle does not contain contextd.db")
    if "chain-witness.json" not in entries:
        raise BackupError("bundle does not contain its chain witness")
    return manifest, entries


def _validate_bundle_tree(
    bundle: Path,
    *,
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None,
    legacy_policy: LegacyBundlePolicy | None,
) -> dict[str, Any]:
    manifest, entries = _manifest(bundle)
    manifest_sha256 = _sha256(bundle / MANIFEST_NAME)
    authentication = _authenticate_manifest(
        manifest, manifest_sha256, trust_store, legacy_policy
    )
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
    if (
        not authentication["authenticated"]
        and _snapshot_has_signature_cutover(bundle / DATABASE_NAME)
    ):
        raise BackupError(
            "unsigned legacy policy cannot authorize a post-cutover snapshot"
        )
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
    return {
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "authentication": authentication,
        "snapshot": snapshot,
        "files": entries,
    }


def validate_bundle(
    bundle: Path,
    *,
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None = None,
    legacy_policy: LegacyBundlePolicy | None = None,
) -> dict[str, Any]:
    """Authenticate and validate a hostile bundle from a descriptor snapshot."""
    bundle = _absolute(bundle)
    if _trust_store_is_inside_bundle(trust_store, bundle):
        raise BackupError("manifest trust store cannot come from the backup bundle")
    # Load and parse pins before touching the bundle database.  The returned
    # store holds immutable key objects and remains independent of restore input.
    pins = _coerce_trust_store(trust_store) if legacy_policy is None else trust_store
    source_fd = _open_directory(bundle)
    try:
        trusted_tmp = Path(tempfile.gettempdir()).resolve(strict=True)
        with tempfile.TemporaryDirectory(
            prefix=".contextd-bundle-verify-", dir=trusted_tmp
        ) as raw:
            stage = Path(raw)
            os.chmod(stage, 0o700)
            stage_fd = _open_directory(stage)
            try:
                preflight = _preflight_bundle_fd(
                    source_fd,
                    stage,
                    stage_fd,
                    trust_store=pins,
                    legacy_policy=legacy_policy,
                )
                _copy_tree_from_fd(
                    source_fd,
                    stage_fd,
                    expected_sizes=preflight["expected_sizes"],
                )
            finally:
                os.close(stage_fd)
            return _validate_bundle_tree(
                stage, trust_store=pins, legacy_policy=legacy_policy
            )
    finally:
        os.close(source_fd)


def bundle_identity(
    bundle: Path,
    *,
    destination: Path | None = None,
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None = None,
    legacy_policy: LegacyBundlePolicy | None = None,
) -> dict[str, Any]:
    """Return the exact authenticated identity authorization should bind."""
    verified = validate_bundle(
        bundle, trust_store=trust_store, legacy_policy=legacy_policy
    )
    signature = verified["manifest"].get("service_signature") or {}
    identity: dict[str, Any] = {
        "bundle_path": normalized_path(bundle),
        "manifest_sha256": verified["manifest_sha256"],
        "snapshot": verified["snapshot"],
        "signing_key_id": signature.get("key_id"),
        "authenticated": verified["authentication"]["authenticated"],
    }
    if destination is not None:
        identity["destination_path"] = normalized_path(destination)
    return identity


def _empty_destination_identity(parent_fd: int, name: str, display: Path):
    import stat

    try:
        candidate = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(candidate.st_mode):
        raise BackupError(f"restore destination already exists: {display}")
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=parent_fd)
    except OSError as exc:
        raise BackupError(f"restore destination is symlinked or unsafe: {display}") from exc
    try:
        opened = os.fstat(descriptor)
        if (candidate.st_dev, candidate.st_ino) != (opened.st_dev, opened.st_ino):
            raise BackupError(f"restore destination changed during validation: {display}")
        if os.listdir(descriptor):
            raise BackupError(f"restore destination is not empty: {display}")
        return candidate.st_dev, candidate.st_ino
    finally:
        os.close(descriptor)


def restore_backup(
    bundle: Path,
    destination: Path,
    *,
    trust_store: ManifestTrustStore | str | os.PathLike[str] | None = None,
    legacy_policy: LegacyBundlePolicy | None = None,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Authenticate through external pins, then publish through pinned dir FDs."""
    bundle = _absolute(bundle)
    destination = _absolute(destination)
    if not destination.name or destination.name in {".", ".."}:
        raise BackupError("restore destination must name one archive directory")
    if expected_manifest_sha256 is not None and (
        not isinstance(expected_manifest_sha256, str)
        or not _DIGEST_RE.fullmatch(expected_manifest_sha256)
    ):
        raise BackupError("expected manifest digest is malformed")
    if bundle == destination or bundle in destination.parents:
        raise BackupError("restore destination cannot be inside the backup bundle")
    if _trust_store_is_inside_bundle(trust_store, bundle):
        raise BackupError("manifest trust store cannot come from the backup bundle")
    pins = _coerce_trust_store(trust_store) if legacy_policy is None else trust_store
    source_fd = _open_directory(bundle)
    try:
        parent_fd = _open_directory(destination.parent, create=True)
    except BaseException:
        os.close(source_fd)
        raise
    try:
        stage_name, stage_fd = _random_directory_at(
            parent_fd, f".{destination.name}.restore-"
        )
    except BaseException:
        os.close(parent_fd)
        os.close(source_fd)
        raise
    stage = destination.parent / stage_name
    published = False
    replaced_empty = False
    try:
        _assert_path_matches_fd(destination.parent, parent_fd, "restore parent")
        original_destination = _empty_destination_identity(
            parent_fd, destination.name, destination
        )
        preflight = _preflight_bundle_fd(
            source_fd,
            stage,
            stage_fd,
            trust_store=pins,
            legacy_policy=legacy_policy,
        )
        if (
            expected_manifest_sha256 is not None
            and preflight["manifest_sha256"] != expected_manifest_sha256
        ):
            raise BackupError(
                "backup bundle no longer matches the authorized manifest digest"
            )
        _copy_tree_from_fd(
            source_fd,
            stage_fd,
            expected_sizes=preflight["expected_sizes"],
        )
        os.fsync(stage_fd)
        _assert_path_matches_fd(destination.parent, parent_fd, "restore parent")
        _assert_path_matches_fd(stage, stage_fd, "restore staging directory")
        verified = _validate_bundle_tree(
            stage, trust_store=pins, legacy_policy=legacy_policy
        )
        # The authenticated manifest is an envelope, not archive state.
        os.unlink(MANIFEST_NAME, dir_fd=stage_fd)
        os.unlink(MANIFEST_HASH_NAME, dir_fd=stage_fd)
        os.fsync(stage_fd)

        staged_snapshot = _validate_database(stage / DATABASE_NAME)
        if staged_snapshot != verified["snapshot"]:
            raise BackupError("staged database does not match the verified snapshot")
        _validate_chain_state(stage, staged_snapshot)
        if _referenced_blobs(stage / DATABASE_NAME) != set(
            verified["manifest"]["blobs"]
        ):
            raise BackupError("staged blob inventory changed during restore")

        _assert_path_matches_fd(destination.parent, parent_fd, "restore parent")
        current_destination = _empty_destination_identity(
            parent_fd, destination.name, destination
        )
        if current_destination != original_destination:
            raise BackupError("restore destination changed before publication")
        if current_destination is not None:
            os.rmdir(destination.name, dir_fd=parent_fd)
            replaced_empty = True
        os.rename(
            stage_name,
            destination.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        published = True
        os.fsync(parent_fd)
        try:
            _assert_path_matches_fd(destination.parent, parent_fd, "restore parent")
        except BaseException:
            _remove_tree_at(parent_fd, destination.name)
            published = False
            if replaced_empty:
                os.mkdir(destination.name, 0o700, dir_fd=parent_fd)
            raise
        return {
            "destination": destination,
            "destination_path": str(destination),
            "manifest_sha256": verified["manifest_sha256"],
            "signing_key_id": (verified["manifest"].get("service_signature") or {}).get(
                "key_id"
            ),
            "events": staged_snapshot["events"],
            "blobs": len(verified["manifest"]["blobs"]),
        }
    except BaseException:
        if not published:
            _remove_tree_at(parent_fd, stage_name)
            if replaced_empty:
                try:
                    os.stat(
                        destination.name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    os.mkdir(destination.name, 0o700, dir_fd=parent_fd)
        raise
    finally:
        os.close(stage_fd)
        os.close(parent_fd)
        os.close(source_fd)
