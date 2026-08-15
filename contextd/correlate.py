"""Keyed correlation identifiers.

Some fields exist only so two records can be recognised as being about the
same thing — a query, a task hint, a session id. Storing them raw is a
disclosure surface. Storing ``sha256(value)`` is *not* a fix: these values are
low-entropy (a search query is a handful of words, a session id comes from a
small enumerable space), so anyone who can guess a candidate can confirm it by
hashing. The attacker in docs/SECURITY.md §1 can guess and can hash.

A keyed identifier removes that: ``HMAC-SHA256(key, label || value)`` is
unforgeable and unguessable without the key.

**Where the key lives determines what this is worth.**

- *hardened*: the key file is owned by the service UID and is unreadable by
  the client plane. The property above holds against the modeled attacker.
- *development* (this tree): the key file is owned by the desktop UID, so the
  attacker can read it and recover the mapping by brute force exactly as with
  a plain SHA. It is still strictly better than storing the raw value — the
  value never lands in SQLite, WAL, backups, or `ctx audit` output — but it is
  **not** a confidentiality claim against a same-UID attacker.

`ctx security doctor` reports which of the two states applies rather than
letting the difference stay invisible.
"""

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from . import home

KEY_NAME = "correlation.key"
KEY_BYTES = 32

_cache: dict[str, bytes] = {}


def key_path() -> Path:
    return home() / KEY_NAME


def _load_key() -> bytes:
    path = key_path()
    cached = _cache.get(str(path))
    if cached is not None:
        return cached
    if path.exists():
        raw = path.read_bytes()
        if len(raw) != KEY_BYTES:
            raise ValueError(
                f"{path} is not a {KEY_BYTES}-byte correlation key; refusing to "
                f"guess. Move it aside to regenerate (old identifiers stop "
                f"correlating, which is visible, not silent)."
            )
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        raw = secrets.token_bytes(KEY_BYTES)
        # O_EXCL: two processes racing to create the key must not end up with
        # different keys for the same archive
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raw = path.read_bytes()
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
    _cache[str(path)] = raw
    return raw


def keyed_id(label: str, value) -> str:
    """A stable, unguessable correlation id for one (label, value) pair.

    The label is part of the MAC input so the same string used as a query and
    as a session id does not correlate across fields.
    """
    if value is None:
        value = ""
    if not isinstance(value, str):
        value = str(value)
    message = label.encode("utf-8") + b"\x1f" + value.encode("utf-8")
    return hmac.new(_load_key(), message, hashlib.sha256).hexdigest()


def reset_cache() -> None:
    """Test hook: forget cached keys after CONTEXTD_HOME changes."""
    _cache.clear()
