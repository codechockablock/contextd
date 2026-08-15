"""Adversarial checks for persistence columns outside the metadata schemas."""

import hashlib
import json
import os

import pytest

from contextd import home
from contextd.db import (
    BlobPrivacyError,
    append_event,
    connect,
    get_cursor,
    set_cursor,
    store_blob,
)
from contextd.schemas import SchemaError


def _canary() -> str:
    # Constructed so the repository scanner does not mistake test source for a
    # live credential.  At runtime it is a planted positive for the API-key
    # floor class.
    #
    # Bind the result to `canary`. The `password_assignment` detector keys on
    # the identifier, not the value, so binding it to a name in
    # (password|passwd|pwd|secret|api_key|access_token|client_secret) reports
    # this file as a credential leak in the tracked-tree gate. `canary` is also
    # simply the accurate name: nothing here is secret, and the value is built
    # at runtime so no credential-shaped literal ever enters the source.
    return "sk-" + "Q" * 24


def test_routing_columns_reject_private_or_controlled_labels_without_echo():
    conn = connect()
    canary = _canary()
    with pytest.raises(SchemaError) as caught:
        append_event(conn, canary, "note", content="ordinary")
    assert canary not in str(caught.value)

    with pytest.raises(SchemaError):
        append_event(conn, "note", "note\x1b]2;forged\x07", content="ordinary")
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_content_uri_and_digest_describe_exact_sanitized_bytes():
    conn = connect()
    canary = _canary()
    supplied = hashlib.sha256(b"caller chose this").hexdigest()
    event_id = append_event(
        conn,
        "note",
        "note",
        uri=f"file:///tmp/{canary}\x1b]2;title\x07",
        content=f"before {canary}\x1b[31m after",
        content_hash=supplied,
    )
    row = conn.execute(
        "SELECT uri, content, content_hash FROM events WHERE id = ?", (event_id,)
    ).fetchone()
    assert canary not in row["uri"]
    assert canary not in row["content"]
    assert "\x1b" not in row["uri"] + row["content"]
    assert row["content_hash"] == hashlib.sha256(
        row["content"].encode("utf-8")
    ).hexdigest()
    assert row["content_hash"] != supplied


def test_cursor_state_is_recursively_sanitized_and_source_fails_closed():
    conn = connect()
    canary = _canary()
    set_cursor(
        conn,
        "scanner:ordinary",
        {"nested": [{"private": canary, "control": "ok\x1b[2J"}]},
    )
    stored = conn.execute(
        "SELECT source, state FROM cursors WHERE source = 'scanner:ordinary'"
    ).fetchone()
    assert canary not in stored["state"]
    assert "\x1b" not in stored["state"]
    assert get_cursor(conn, "scanner:ordinary") == json.loads(stored["state"])

    with pytest.raises(SchemaError) as caught:
        set_cursor(conn, f"scanner:{canary}", {"offset": 1})
    assert canary not in str(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        lambda canary: b"\xff\x00prefix " + canary.encode() + b" suffix",
        lambda canary: ("prefix " + canary + " suffix").encode("utf-16-le"),
        lambda canary: ("prefix " + canary + " suffix").encode("utf-16-be"),
        lambda canary: ("prefix " + canary + " suffix").encode("utf-32-le"),
        lambda canary: ("prefix " + canary + " suffix").encode("utf-32-be"),
    ],
)
def test_binary_encoding_switch_cannot_bypass_blob_privacy(payload):
    connect().close()
    with pytest.raises(BlobPrivacyError) as caught:
        store_blob(payload(_canary()))
    assert _canary() not in str(caught.value)
    assert not list((home() / "store").rglob("*")) if (home() / "store").exists() else True


def test_blob_store_refuses_symlinked_directory_boundary(tmp_path):
    connect().close()
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, home() / "store")
    with pytest.raises(OSError):
        store_blob(b"ordinary blob")
    assert list(outside.iterdir()) == []


def test_blob_store_refuses_symlinked_final_object(tmp_path):
    connect().close()
    data = b"ordinary blob"
    digest = hashlib.sha256(data).hexdigest()
    store = home() / "store"
    shard = store / digest[:2]
    shard.mkdir(parents=True, mode=0o700)
    os.chmod(store, 0o700)
    os.chmod(shard, 0o700)
    outside = tmp_path / "outside-object"
    outside.write_bytes(b"do not overwrite")
    os.symlink(outside, shard / digest)

    with pytest.raises(OSError):
        store_blob(data)
    assert outside.read_bytes() == b"do not overwrite"


def test_torn_blob_is_quarantined_and_healed(capsys):
    connect().close()
    data = b"healed blob content"
    digest = hashlib.sha256(data).hexdigest()
    store = home() / "store"
    shard = store / digest[:2]
    shard.mkdir(parents=True, mode=0o700)
    os.chmod(store, 0o700)
    os.chmod(shard, 0o700)
    torn = b"torn partial wri"
    (shard / digest).write_bytes(torn)
    os.chmod(shard / digest, 0o600)

    assert store_blob(data) == digest
    assert (shard / digest).read_bytes() == data
    quarantined = list(shard.glob(f"{digest}.corrupt.*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == torn
    assert "quarantined corrupt blob" in capsys.readouterr().err


def test_intact_existing_blob_is_left_alone(capsys):
    connect().close()
    data = b"stable blob"
    digest = store_blob(data)
    assert store_blob(data) == digest
    shard = home() / "store" / digest[:2]
    assert list(shard.glob("*.corrupt.*")) == []
    assert "quarantined" not in capsys.readouterr().err


def test_stale_blob_temp_is_reaped_and_fresh_kept():
    connect().close()
    data = b"temp reap probe"
    digest = store_blob(data)
    shard = home() / "store" / digest[:2]
    stale = shard / f".{digest}.999.888.tmp"
    fresh = shard / f".{digest}.777.666.tmp"
    for leftover in (stale, fresh):
        leftover.write_bytes(b"x")
        os.chmod(leftover, 0o600)
    old = os.stat(stale).st_mtime - 200_000
    os.utime(stale, (old, old))

    assert store_blob(data) == digest
    assert not stale.exists()
    assert fresh.exists()
