"""Four ingesters, on purpose: watched text files, deliberate notes, browser
history, and Claude Code dialogue. Every additional ingester must be earned by
a documented retrieval failure."""

import fnmatch
import json
import os
import shutil
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .db import append_event, get_cursor, last_hash, set_cursor, store_blob
from .domains import blocked, load_skip_domains
from .assurance import UNVERIFIED, refuse_forged_authority
from .redact import redact
from .scratch import harden_file, scratch_dir

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".obsidian", ".Trash"}

CHROME_HISTORY = "~/Library/Application Support/Google/Chrome/Default/History"
SAFARI_HISTORY = "~/Library/Safari/History.db"
CHROME_EPOCH_OFFSET = 11_644_473_600  # WebKit time: µs since 1601-01-01
SAFARI_EPOCH_OFFSET = 978_307_200  # Core Data time: s since 2001-01-01


def _never(cfg, path: str) -> bool:
    return any(
        fnmatch.fnmatch(path, os.path.expanduser(p)) for p in cfg["ingest"]["never_ingest"]
    )


def ingest_note(conn, text: str, tags=None, claimed_client: str = "",
                derivation: dict | None = None, authorization=None,
                actor: str | None = None, bind=None) -> int:
    """Append a note.

    The old signature took ``actor="human"`` as a free-form string, which is
    how a caller minted human provenance for itself. It now takes an optional
    verified ``authorization`` (contextd/attest.py) and records the resulting
    assurance level; without one the note is ``unverified``, whatever label the
    caller would have liked to write. See docs/SECURITY.md §3.
    """
    # `actor` is kept in the signature ONLY so the retired call shape fails
    # loudly with a message that names the replacement, instead of silently
    # being accepted or raising an opaque TypeError.
    if actor is not None:
        refuse_forged_authority(actor=actor)
        claimed_client = claimed_client or actor
    refuse_forged_authority(claimed_client=claimed_client)
    meta = {"assurance": UNVERIFIED}
    if claimed_client:
        meta["claimed_client"] = claimed_client
    if tags:
        meta["tags"] = tags
    if derivation:
        # kernel-verified lineage (see mcp_server.note); never model-asserted
        meta["derivation"] = derivation
    if authorization is not None:
        meta["assurance"] = authorization.assurance
        meta["attestation"] = authorization.stored_block()
    if bind is not None:
        # `bind` runs inside the append transaction; the dispatch capability
        # is consumed there so the note and its authorization commit together
        from .db import append_event_checked
        return append_event_checked(conn, "note", "note", content=text,
                                    meta=meta, bind=bind)
    return append_event(conn, "note", "note", content=text, meta=meta)


def scan_fs(conn, cfg) -> dict:
    exts = set(cfg["ingest"]["text_extensions"])
    max_bytes = cfg["ingest"]["max_file_bytes"]
    seen, new, deleted = set(), 0, 0
    unavailable = []
    for top in cfg["ingest"]["watch_dirs"]:
        top = Path(top).expanduser()
        if not top.is_dir():
            # an unreachable root is not a mass deletion; keep its files as-seen
            unavailable.append(str(top).rstrip(os.sep) + os.sep)
            continue
        for root, dirs, files in os.walk(top):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                path = Path(root) / name
                uri = str(path)
                if path.is_symlink():
                    # an alias can smuggle a never_ingest target past path rules
                    continue
                if path.suffix.lower() not in exts or _never(cfg, uri):
                    continue
                try:
                    size = path.stat().st_size
                    data = path.read_bytes()
                except OSError:
                    continue
                seen.add(uri)
                if size > max_bytes:
                    digest = store_blob(data)
                    if last_hash(conn, uri) != digest:
                        append_event(conn, "fs", "file_write", uri=uri,
                                     content_hash=digest, meta={"size": size, "blob": digest})
                        new += 1
                    continue
                text = data.decode("utf-8", errors="replace")
                import hashlib
                digest = hashlib.sha256(text.encode()).hexdigest()
                if last_hash(conn, uri) == digest:
                    continue
                append_event(conn, "fs", "file_write", uri=uri, content=text,
                             content_hash=digest, meta={"size": size})
                new += 1
    cursor = get_cursor(conn, "fs")
    for gone in set(cursor.get("seen", [])) - seen:
        if any(gone.startswith(u) for u in unavailable):
            seen.add(gone)
            continue
        append_event(conn, "fs", "file_delete", uri=gone)
        deleted += 1
    set_cursor(conn, "fs", {"seen": sorted(seen)})
    return {"file_write": new, "file_delete": deleted, "watched": len(seen)}


def _copy_locked_db(src: Path, workdir: Path) -> Path:
    """Copy a live browser history DB (plus WAL/SHM) into caller-owned scratch.

    The copy is a full plaintext dump of the user's browsing history, so it is
    written 0600 into a 0700 directory the caller removes in ``finally``. It
    used to be left in the shared system temp directory with the source file's
    own mode, and was only cleaned up when the read succeeded.
    """
    tmp = workdir / src.name
    shutil.copy(src, tmp)
    harden_file(tmp)
    for suffix in ("-wal", "-shm"):
        side = src.with_name(src.name + suffix)
        if side.exists():
            try:
                shutil.copy(side, tmp.with_name(tmp.name + suffix))
            except OSError:
                pass
            else:
                harden_file(tmp.with_name(tmp.name + suffix))
    return tmp


KEEP_PARAMS = {"q", "v"}  # search terms and video ids are recall signal


def clean_url(url: str) -> str:
    """Strip query params (tracking blobs, auth tokens) and fragments before
    anything is stored: the append-only archive must never hold credentials,
    and every stored byte is paid for again at every disclosure."""
    parts = urlsplit(url)
    kept = [(k, val) for k, val in parse_qsl(parts.query) if k.lower() in KEEP_PARAMS]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), ""))


def _scan_browser(conn, cfg, name, src_path, query, to_unix) -> dict:
    src = Path(src_path).expanduser()
    if not src.exists():
        return {"status": "not found"}
    cursor = get_cursor(conn, name)
    watermark = cursor.get("watermark", 0)
    # scratch_dir removes the copy in `finally`, so a failed open, a failed
    # query, a timeout, or a KeyboardInterrupt cannot leave a plaintext copy
    # of browser history behind. A cleanup that does not succeed raises.
    try:
        with scratch_dir(f"{name}-history") as workdir:
            bconn = sqlite3.connect(_copy_locked_db(src, workdir))
            try:
                rows = bconn.execute(query, (watermark,)).fetchall()
            finally:
                bconn.close()
    except (OSError, sqlite3.Error) as e:
        # the exception text can name a path but never row content; it is not
        # persisted, only returned as a status string to the caller
        return {"status": f"no access ({e})"}
    skip = load_skip_domains(cfg)
    new = skipped = 0
    for url, title, raw_time in rows:
        # advance past skipped rows too, or a blocked tail stalls the cursor
        watermark = max(watermark, raw_time)
        if blocked(skip, url):
            skipped += 1
            continue
        url = clean_url(url)
        append_event(conn, name, "page_visit", uri=url,
                     content=f"{title or ''} {url}".strip(),
                     meta={"visited_unix": to_unix(raw_time)})
        new += 1
    set_cursor(conn, name, {"watermark": watermark})
    return {"page_visit": new, "skipped": skipped}


def scan_chrome(conn, cfg) -> dict:
    return _scan_browser(
        conn, cfg, "chrome", CHROME_HISTORY,
        "SELECT url, title, last_visit_time FROM urls "
        "WHERE last_visit_time > ? ORDER BY last_visit_time LIMIT 5000",
        lambda t: t / 1_000_000 - CHROME_EPOCH_OFFSET,
    )


def scan_safari(conn, cfg) -> dict:
    return _scan_browser(
        conn, cfg, "safari", SAFARI_HISTORY,
        "SELECT i.url, v.title, v.visit_time FROM history_visits v "
        "JOIN history_items i ON i.id = v.history_item "
        "WHERE v.visit_time > ? ORDER BY v.visit_time LIMIT 5000",
        lambda t: t + SAFARI_EPOCH_OFFSET,
    )


# --- Claude Code dialogue ---------------------------------------------------
# Transcripts are JSONL under ~/.claude/projects. The filter is mechanical:
# user text, assistant text, delegation prompts, and subagent reports — no
# tool dumps, no thinking, no sidechain interiors. Content is redacted before
# storage (the archive never holds credentials) and role-tagged forever.

CLAUDE_NOISE = ("<system-reminder", "<local-command", "<command-name",
                "Caveat: The messages")


def _result_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content
                         if isinstance(b, dict) and b.get("type") == "text")
    return ""


def _claude_dialogue(obj, task_ids):
    """Yield (role, text) worth archiving from one transcript line."""
    if obj.get("isSidechain"):
        return
    content = (obj.get("message") or {}).get("content")
    if obj.get("type") == "assistant":
        for b in content or []:
            if b.get("type") == "text" and (b.get("text") or "").strip():
                yield "assistant", b["text"]
            elif b.get("type") == "tool_use" and b.get("name") in ("Task", "Agent"):
                task_ids[b.get("id") or ""] = 1
                prompt = (b.get("input") or {}).get("prompt")
                if prompt:
                    yield "delegation", prompt
    elif obj.get("type") == "user":
        if isinstance(content, str):
            if content.strip() and not content.startswith(CLAUDE_NOISE):
                yield "user", content
            return
        for b in content or []:
            if b.get("type") == "text":
                t = b.get("text") or ""
                if t.strip() and not t.startswith(CLAUDE_NOISE):
                    yield "user", t
            elif b.get("type") == "tool_result" and b.get("tool_use_id") in task_ids:
                # a delegate's report is a finding, not tool noise
                task_ids.pop(b["tool_use_id"], None)
                t = _result_text(b.get("content"))
                if t.strip():
                    yield "subagent", t


def _parse_claude(path: Path, offset: int, task_ids: dict):
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    end = data.rfind(b"\n") + 1  # never consume a partially written line
    msgs = []
    for i, raw in enumerate(data[:end].splitlines()):
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        ts_unix = None
        if obj.get("timestamp"):
            try:
                ts_unix = datetime.fromisoformat(
                    obj["timestamp"].replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass
        uid = (obj.get("uuid") or "")[:16] or f"{path.stem[:8]}-{offset + i}"
        # one line can yield several messages (text + delegation); disambiguate
        for j, (role, text) in enumerate(_claude_dialogue(obj, task_ids)):
            msgs.append((role, text, ts_unix, uid if j == 0 else f"{uid}-{j}"))
    return msgs, offset + end


def _claude_cursors(conn) -> dict:
    rows = conn.execute(
        "SELECT source, state FROM cursors WHERE source LIKE 'claude_code:%'"
    ).fetchall()
    return {r["source"][12:]: json.loads(r["state"]) for r in rows}


def scan_claude(conn, cfg) -> dict:
    ccfg = cfg["claude"]
    root = Path(os.path.expanduser(ccfg["projects_dir"]))
    if not root.is_dir():
        return {"status": "not found"}
    states = _claude_cursors(conn)
    now = time.time()
    new = epochs = 0
    for path in root.glob("*/*.jsonl"):
        key = str(path.relative_to(root))
        try:
            size = path.stat().st_size
        except OSError:
            continue
        s = states.get(key)
        first_seen = s is None
        if first_seen:
            s = {"o": 0, "e": 0, "z": 0, "open": False, "g": now, "t": {}}
        if size > s["o"]:
            msgs, s["o"] = _parse_claude(path, s["o"], s["t"])
            sid = path.stem
            for role, text, ts_unix, uid in msgs:
                uri = f"claude://{uid}"
                if conn.execute("SELECT 1 FROM events WHERE uri = ? LIMIT 1",
                                (uri,)).fetchone():
                    continue  # resumed/forked sessions replay earlier messages
                meta = {"role": role, "session_id": sid}
                if ts_unix:
                    meta["visited_unix"] = ts_unix
                s["e"] = append_event(conn, "claude_code", "message", uri=uri,
                                      content=redact(cfg, text)[: ccfg["max_message_chars"]],
                                      meta=meta)
                new += 1
            s["g"] = now
            # a file first seen already-written was quiet history, not a live
            # episode: ingest it as evidence but never open an epoch for it
            s["open"] = not first_seen
            if first_seen:
                s["z"] = s["e"]
            set_cursor(conn, "claude_code:" + key, s)
        elif s["open"] and now - s["g"] >= ccfg["quiet_seconds"]:
            append_event(conn, "claude_code", "epoch",
                         meta={"session_id": path.stem,
                               "start_event_id": s["z"],
                               "end_event_id": s["e"]})
            s["open"], s["z"] = False, s["e"]
            epochs += 1
            set_cursor(conn, "claude_code:" + key, s)
    return {"message": new, "epoch": epochs}


def run_all(conn, cfg) -> dict:
    results = {"fs": scan_fs(conn, cfg)}
    if cfg["browser"]["chrome"]:
        results["chrome"] = scan_chrome(conn, cfg)
    if cfg["browser"]["safari"]:
        results["safari"] = scan_safari(conn, cfg)
    if cfg["claude"]["enabled"]:
        results["claude_code"] = scan_claude(conn, cfg)
    return results
