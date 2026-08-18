"""Four ingesters, on purpose: watched text files, deliberate notes, browser
history, and Claude Code dialogue. Every additional ingester must be earned by
a documented retrieval failure.

**On `sqlite3` in this module, and why it is not a backend leak.** The three
uses below are all one thing: reading a *browser's* history database, which is
a SQLite file belonging to Chrome or Safari and has nothing to do with where
this archive stores its events. Every write this module makes to the archive
goes through `db.append_event`, `db.get_cursor`, `db.set_cursor`,
`db.last_hash`, and `db.store_blob`, all of which are already backend-neutral —
so the ingest surface runs against a Postgres archive unchanged, including the
cursor/watermark machinery that decides what has already been ingested. That is
asserted by `tests/test_postgres_backend.py` rather than assumed, because "it
imports sqlite3" is exactly the shape that looks like a gap and is not one.

What genuinely does not follow the archive to a second host is `store_blob`:
oversized payloads are content-addressed under `home()/store`, which is local
to the host that ingested them (see `create_backup`'s "missing referenced
blob"). That is a real limit of a multi-host archive, and a loud one — never a
silent partial backup."""

import fnmatch
import hashlib
import json
import math
import os
import shutil
import sqlite3
import sys
import stat
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .db import append_event, get_cursor, last_hash, set_cursor, store_blob
from .domains import blocked, load_skip_domains
from .assurance import UNVERIFIED, refuse_forged_authority
from .redact import sanitize_content
from .schemas import SchemaError
from .scratch import harden_file, scratch_dir

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".obsidian", ".Trash"}

CHROME_HISTORY = "~/Library/Application Support/Google/Chrome/Default/History"
SAFARI_HISTORY = "~/Library/Safari/History.db"
CHROME_EPOCH_OFFSET = 11_644_473_600  # WebKit time: µs since 1601-01-01
SAFARI_EPOCH_OFFSET = 978_307_200  # Core Data time: s since 2001-01-01


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class UnsafeIngestPath(OSError):
    """An ingest source could not be opened without following path aliases."""


def _open_directory_nofollow(path: Path) -> int:
    """Open an absolute directory one component at a time, following no links.

    Each successful open pins the next lookup to a directory descriptor.  A
    check-then-open sequence on path strings cannot provide this guarantee.
    """
    if not _NOFOLLOW or not _DIRECTORY:
        raise UnsafeIngestPath("platform lacks safe no-follow directory opens")
    absolute = Path(os.path.abspath(os.fspath(path)))
    fd = os.open(os.sep, os.O_RDONLY | _DIRECTORY | _CLOEXEC)
    try:
        for part in absolute.parts[1:]:
            if part in ("", ".", ".."):
                raise UnsafeIngestPath("unsafe path component")
            next_fd = os.open(
                part,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


class _SecureRoot:
    """A pinned, symlink-free root for race-safe ingest reads."""

    def __init__(self, root: Path):
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.fd = -1

    def __enter__(self):
        self.fd = _open_directory_nofollow(self.root)
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def open_regular(self, relative: Path | str) -> tuple[int, os.stat_result]:
        parts = Path(relative).parts
        if not parts or Path(relative).is_absolute() or any(
            p in ("", ".", "..") for p in parts
        ):
            raise UnsafeIngestPath("source is outside the ingest root")
        parent_fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                    dir_fd=parent_fd,
                )
                os.close(parent_fd)
                parent_fd = next_fd
            fd = os.open(
                parts[-1], os.O_RDONLY | _NOFOLLOW | _CLOEXEC, dir_fd=parent_fd
            )
        finally:
            os.close(parent_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafeIngestPath("ingest source is not a regular file")
            return fd, info
        except BaseException:
            os.close(fd)
            raise

    def read_regular(self, relative: Path | str, offset: int = 0) -> tuple[bytes, os.stat_result]:
        fd, info = self.open_regular(relative)
        try:
            if offset:
                os.lseek(fd, offset, os.SEEK_SET)
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks), info
        finally:
            os.close(fd)

    def copy_regular(self, relative: Path | str, destination: Path) -> None:
        src_fd, _ = self.open_regular(relative)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW
        try:
            dst_fd = os.open(destination, flags, 0o600)
        except BaseException:
            os.close(src_fd)
            raise
        try:
            with os.fdopen(src_fd, "rb") as source, os.fdopen(dst_fd, "wb") as dest:
                shutil.copyfileobj(source, dest, length=1024 * 1024)
        except BaseException:
            # scratch_dir owns cleanup; never broaden deletion from here.
            raise


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
        top = Path(os.path.abspath(os.fspath(Path(top).expanduser())))
        try:
            secure_root = _SecureRoot(top)
            secure_root.__enter__()
        except OSError:
            # an unreachable root is not a mass deletion; keep its files as-seen
            unavailable.append(str(top).rstrip(os.sep) + os.sep)
            continue
        walk_errors = []
        try:
            for root, dirs, files in os.walk(top, onerror=walk_errors.append):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for name in files:
                    path = Path(root) / name
                    uri = str(path)
                    if sanitize_content(cfg, uri, max_len=4096) != uri:
                        continue
                    if path.suffix.lower() not in exts or _never(cfg, uri):
                        continue
                    try:
                        relative = path.relative_to(top)
                        data, info = secure_root.read_regular(relative)
                    except (OSError, ValueError):
                        continue
                    size = len(data)
                    seen.add(uri)
                    if size > max_bytes:
                        digest = store_blob(data)
                        if last_hash(conn, uri) != digest:
                            append_event(
                                conn,
                                "fs",
                                "file_write",
                                uri=uri,
                                content_hash=digest,
                                meta={"size": size, "blob": digest},
                            )
                            new += 1
                        continue
                    text = sanitize_content(
                        cfg, data.decode("utf-8", errors="replace")
                    )
                    digest = hashlib.sha256(text.encode()).hexdigest()
                    if last_hash(conn, uri) == digest:
                        continue
                    append_event(
                        conn,
                        "fs",
                        "file_write",
                        uri=uri,
                        content=text,
                        content_hash=digest,
                        meta={"size": size},
                    )
                    new += 1
        finally:
            secure_root.__exit__(None, None, None)
        if walk_errors:
            unavailable.append(str(top).rstrip(os.sep) + os.sep)
    try:
        cursor = get_cursor(conn, "fs")
    except (SchemaError, json.JSONDecodeError, TypeError):
        # An unreadable cursor is treated as NO prior state, which is what
        # makes spurious deletions structurally impossible: the delete pass
        # derives from `prior_seen`, and an empty one can name nothing. It is
        # reported rather than swallowed — a corrupt cursor is either damage
        # or tampering, and neither should pass in silence.
        print("contextd: WARNING fs cursor unreadable; rescanning from empty "
              "(no deletions can be derived)", file=sys.stderr)
        cursor = {}
    prior_seen = cursor.get("seen", []) if isinstance(cursor, dict) else []
    if (
        not isinstance(prior_seen, list)
        or len(prior_seen) > 100_000
        or any(not isinstance(item, str) for item in prior_seen)
    ):
        prior_seen = []
    for gone in set(prior_seen) - seen:
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
    with _SecureRoot(src.parent) as secure_root:
        secure_root.copy_regular(src.name, tmp)
        harden_file(tmp)
        for suffix in ("-wal", "-shm"):
            try:
                secure_root.copy_regular(
                    src.name + suffix, tmp.with_name(tmp.name + suffix)
                )
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
    try:
        cursor = get_cursor(conn, name)
    except (SchemaError, json.JSONDecodeError, TypeError):
        # watermark 0 => rescan this browser's history from the beginning.
        # Costs time, loses nothing, invents nothing.
        print(f"contextd: WARNING {name} cursor unreadable; rescanning from "
              f"the beginning", file=sys.stderr)
        cursor = {}
    watermark = cursor.get("watermark", 0) if isinstance(cursor, dict) else 0
    if (
        isinstance(watermark, bool)
        or not isinstance(watermark, (int, float))
        or not math.isfinite(watermark)
    ):
        watermark = 0
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
    except FileNotFoundError:
        return {"status": "not found"}
    except (OSError, sqlite3.Error) as e:
        # Exception strings are attacker- and environment-controlled display
        # input.  Retain only the exception class, never paths or row bytes.
        status = f"no access ({type(e).__name__})"
        # Persist the failure in this browser's cursor so `ctx status` can
        # warn from archive state (Full Disk Access denials otherwise die in
        # a log nobody reads); the next successful scan replaces the cursor
        # wholesale, which clears it.
        state = dict(cursor) if isinstance(cursor, dict) else {}
        state["last_status"] = status
        set_cursor(conn, name, state)
        return {"status": status}
    skip = load_skip_domains(cfg)
    new = skipped = 0
    for url, title, raw_time in rows:
        if (
            not isinstance(url, str)
            or isinstance(raw_time, bool)
            or not isinstance(raw_time, (int, float))
            or not math.isfinite(raw_time)
        ):
            continue
        # advance past skipped rows too, or a blocked tail stalls the cursor
        watermark = max(watermark, raw_time)
        if blocked(skip, url):
            skipped += 1
            continue
        url = clean_url(url)
        title = title if isinstance(title, str) else ""
        append_event(
            conn,
            name,
            "page_visit",
            uri=sanitize_content(cfg, url, max_len=4096),
            content=sanitize_content(cfg, f"{title} {url}".strip()),
            meta={"visited_unix": to_unix(raw_time)},
        )
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
    message = obj.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if obj.get("type") == "assistant":
        for b in content if isinstance(content, list) else []:
            if not isinstance(b, dict):
                continue
            text = b.get("text")
            if b.get("type") == "text" and isinstance(text, str) and text.strip():
                yield "assistant", text
            elif b.get("type") == "tool_use" and b.get("name") in ("Task", "Agent"):
                task_id = b.get("id")
                if not isinstance(task_id, str) or not task_id:
                    continue
                task_ids[hashlib.sha256(task_id.encode()).hexdigest()] = 1
                tool_input = b.get("input")
                prompt = tool_input.get("prompt") if isinstance(tool_input, dict) else None
                if isinstance(prompt, str) and prompt:
                    yield "delegation", prompt
    elif obj.get("type") == "user":
        if isinstance(content, str):
            if content.strip() and not content.startswith(CLAUDE_NOISE):
                yield "user", content
            return
        for b in content if isinstance(content, list) else []:
            if not isinstance(b, dict):
                continue
            if b.get("type") == "text":
                t = b.get("text") or ""
                if isinstance(t, str) and t.strip() and not t.startswith(CLAUDE_NOISE):
                    yield "user", t
            elif (
                b.get("type") == "tool_result"
                and isinstance(b.get("tool_use_id"), str)
                and hashlib.sha256(b["tool_use_id"].encode()).hexdigest()
                in task_ids
            ):
                # a delegate's report is a finding, not tool noise
                task_ids.pop(hashlib.sha256(b["tool_use_id"].encode()).hexdigest())
                t = _result_text(b.get("content"))
                if t.strip():
                    yield "subagent", t


def _parse_claude(data: bytes, offset: int, stem: str, task_ids: dict):
    """Parse bytes read from one already-verified regular transcript file."""
    end = data.rfind(b"\n") + 1  # never consume a partially written line
    msgs = []
    for i, raw in enumerate(data[:end].splitlines()):
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(obj, dict):
            continue
        ts_unix = None
        if isinstance(obj.get("timestamp"), str):
            try:
                ts_unix = datetime.fromisoformat(
                    obj["timestamp"].replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass
        raw_uid = obj.get("uuid")
        uid = raw_uid[:16] if isinstance(raw_uid, str) else ""
        uid = uid or f"{stem[:8]}-{offset + i}"
        # one line can yield several messages (text + delegation); disambiguate
        for j, (role, text) in enumerate(_claude_dialogue(obj, task_ids)):
            msgs.append((role, text, ts_unix, uid if j == 0 else f"{uid}-{j}"))
    return msgs, offset + end


def _claude_cursors(conn) -> dict:
    rows = conn.execute(
        "SELECT source, state FROM cursors WHERE source LIKE 'claude_code:%'"
    ).fetchall()
    states = {}
    for row in rows:
        raw = row["state"]
        if not isinstance(raw, str) or len(raw) > 1_000_000:
            continue
        try:
            state = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(state, dict):
            continue
        if not all(
            isinstance(state.get(key), int) and not isinstance(state.get(key), bool)
            for key in ("o", "e", "z")
        ):
            continue
        if any(state[key] < 0 for key in ("o", "e", "z")):
            continue
        if not isinstance(state.get("open"), bool):
            continue
        if not isinstance(state.get("g"), (int, float)) or not math.isfinite(
            state["g"]
        ):
            continue
        if not isinstance(state.get("t"), dict) or len(state["t"]) > 1024:
            continue
        tasks = {}
        task_version = state.get("tv")
        task_ids_are_hashed = (
            isinstance(task_version, int)
            and not isinstance(task_version, bool)
            and task_version == 1
        )
        for task_id, marker in state["t"].items():
            if not isinstance(task_id, str) or marker != 1:
                continue
            if (
                task_ids_are_hashed
                and len(task_id) == 64
                and not (set(task_id) - set("0123456789abcdef"))
            ):
                digest = task_id
            else:
                digest = hashlib.sha256(task_id.encode()).hexdigest()
            tasks[digest] = 1
        state["t"] = tasks
        state["tv"] = 1
        states[row["source"][12:]] = state
    return states


def scan_claude(conn, cfg) -> dict:
    ccfg = cfg["claude"]
    root = Path(os.path.abspath(os.path.expanduser(ccfg["projects_dir"])))
    try:
        secure_root = _SecureRoot(root)
        secure_root.__enter__()
    except OSError:
        return {"status": "not found"}
    states = _claude_cursors(conn)
    now = time.time()
    new = epochs = 0
    try:
        for path in root.glob("*/*.jsonl"):
            key = str(path.relative_to(root))
            if len(key) > 4096 or sanitize_content(cfg, key, max_len=4096) != key:
                continue
            s = states.get(key)
            first_seen = s is None
            if first_seen:
                s = {
                    "o": 0,
                    "e": 0,
                    "z": 0,
                    "open": False,
                    "g": now,
                    "t": {},
                    "tv": 1,
                }
            try:
                data, info = secure_root.read_regular(key, offset=s["o"])
            except OSError:
                continue
            size = info.st_size
            if size > s["o"]:
                msgs, s["o"] = _parse_claude(data, s["o"], path.stem, s["t"])
                sid = path.stem
                for role, text, ts_unix, uid in msgs:
                    safe_uid = sanitize_content(cfg, uid, max_len=128)
                    if safe_uid != uid:
                        safe_uid = hashlib.sha256(uid.encode()).hexdigest()[:16]
                    uri = f"claude://{safe_uid}"
                    if conn.execute(
                        "SELECT 1 FROM events WHERE uri = ? LIMIT 1", (uri,)
                    ).fetchone():
                        continue  # resumed/forked sessions replay earlier messages
                    meta = {"role": role, "session_id": sid}
                    if ts_unix:
                        meta["visited_unix"] = ts_unix
                    s["e"] = append_event(
                        conn,
                        "claude_code",
                        "message",
                        uri=uri,
                        content=sanitize_content(
                            cfg, text, max_len=ccfg["max_message_chars"]
                        ),
                        meta=meta,
                    )
                    new += 1
                s["g"] = now
                # a file first seen already-written was quiet history, not a live
                # episode: ingest it as evidence but never open an epoch for it
                s["open"] = not first_seen
                if first_seen:
                    s["z"] = s["e"]
                set_cursor(conn, "claude_code:" + key, s)
            elif s["open"] and now - s["g"] >= ccfg["quiet_seconds"]:
                append_event(
                    conn,
                    "claude_code",
                    "epoch",
                    meta={
                        "session_id": path.stem,
                        "start_event_id": s["z"],
                        "end_event_id": s["e"],
                    },
                )
                s["open"], s["z"] = False, s["e"]
                epochs += 1
                set_cursor(conn, "claude_code:" + key, s)
    finally:
        secure_root.__exit__(None, None, None)
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
