"""Race-safe, no-follow boundaries for filesystem and transcript ingestion."""

import json
from pathlib import Path

from contextd import load_config
from contextd.db import connect
from contextd.ingest import _SecureRoot, scan_claude, scan_fs


def _fs_cfg(root: Path) -> dict:
    cfg = load_config()
    cfg["ingest"]["watch_dirs"] = [str(root)]
    cfg["ingest"]["text_extensions"] = [".md"]
    cfg["ingest"]["never_ingest"] = []
    cfg["ingest"]["max_file_bytes"] = 1024 * 1024
    return cfg


def test_fs_rejects_symlink_file_and_symlinked_parent(tmp_path):
    conn = connect()
    watched = tmp_path / "watched"
    outside = tmp_path / "outside"
    watched.mkdir()
    outside.mkdir()
    (outside / "private.md").write_text("outside canary phrase")
    (watched / "file.md").symlink_to(outside / "private.md")
    (watched / "parent").symlink_to(outside, target_is_directory=True)

    result = scan_fs(conn, _fs_cfg(watched))

    assert result["file_write"] == 0
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_secure_root_pins_original_directory_across_path_swap(tmp_path):
    root = tmp_path / "root"
    replacement = tmp_path / "replacement"
    root.mkdir()
    replacement.mkdir()
    (root / "item.md").write_text("pinned bytes")
    (replacement / "item.md").write_text("attacker bytes")

    with _SecureRoot(root) as secure:
        moved = tmp_path / "moved-root"
        root.rename(moved)
        root.symlink_to(replacement, target_is_directory=True)
        data, _ = secure.read_regular("item.md")

    assert data == b"pinned bytes"


def test_claude_rejects_symlink_transcript_and_parent(tmp_path):
    conn = connect()
    projects = tmp_path / "projects"
    repo = projects / "repo"
    outside = tmp_path / "outside"
    repo.mkdir(parents=True)
    outside.mkdir()
    line = json.dumps(
        {
            "type": "user",
            "message": {"content": "outside transcript canary"},
            "uuid": "abc123",
        }
    ) + "\n"
    (outside / "session.jsonl").write_text(line)
    (repo / "session.jsonl").symlink_to(outside / "session.jsonl")
    (projects / "linked-repo").symlink_to(outside, target_is_directory=True)
    cfg = load_config()
    cfg["claude"]["projects_dir"] = str(projects)
    cfg["claude"]["enabled"] = True

    result = scan_claude(conn, cfg)

    assert result["message"] == 0
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_symlinked_watch_root_is_unavailable_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "private.md").write_text("root alias canary")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    result = scan_fs(connect(), _fs_cfg(alias))

    assert result == {"file_write": 0, "file_delete": 0, "watched": 0}


def test_malformed_fs_cursor_cannot_generate_deletions(tmp_path):
    conn = connect()
    watched = tmp_path / "watched"
    watched.mkdir()
    conn.execute(
        "INSERT INTO cursors(source, state) VALUES ('fs', ?)",
        ("not-json",),
    )
    conn.commit()

    result = scan_fs(conn, _fs_cfg(watched))

    assert result["file_delete"] == 0
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_malformed_claude_cursor_and_rows_are_ignored(tmp_path):
    conn = connect()
    projects = tmp_path / "projects"
    repo = projects / "repo"
    repo.mkdir(parents=True)
    transcript = repo / "session.jsonl"
    transcript.write_text(
        "[]\n"
        + json.dumps({"type": "user", "message": "bad-message"})
        + "\n"
        + json.dumps(
            {
                "type": "assistant",
                "message": {
                    "content": [1, {"type": "text", "text": 7}],
                },
            }
        )
        + "\n"
        + json.dumps(
            {
                "type": "user",
                "message": {"content": "valid row"},
                "uuid": "valid-id",
            }
        )
        + "\n"
    )
    conn.execute(
        "INSERT INTO cursors(source, state) VALUES (?, ?)",
        ("claude_code:repo/session.jsonl", "not-json"),
    )
    conn.commit()
    cfg = load_config()
    cfg["claude"]["projects_dir"] = str(projects)

    result = scan_claude(conn, cfg)

    assert result["message"] == 1
    row = conn.execute(
        "SELECT content FROM events WHERE source='claude_code' AND kind='message'"
    ).fetchone()
    assert row["content"] == "valid row"
