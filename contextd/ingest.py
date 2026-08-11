"""Three ingesters, on purpose: watched text files, deliberate notes, browser history.
Every additional ingester must be earned by a documented retrieval failure."""

import fnmatch
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

from .db import append_event, get_cursor, last_hash, set_cursor, store_blob
from .domains import blocked, load_skip_domains

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".obsidian", ".Trash"}

CHROME_HISTORY = "~/Library/Application Support/Google/Chrome/Default/History"
SAFARI_HISTORY = "~/Library/Safari/History.db"
CHROME_EPOCH_OFFSET = 11_644_473_600  # WebKit time: µs since 1601-01-01
SAFARI_EPOCH_OFFSET = 978_307_200  # Core Data time: s since 2001-01-01


def _never(cfg, path: str) -> bool:
    return any(
        fnmatch.fnmatch(path, os.path.expanduser(p)) for p in cfg["ingest"]["never_ingest"]
    )


def ingest_note(conn, text: str, tags=None, actor: str = "human") -> int:
    meta = {"actor": actor}
    if tags:
        meta["tags"] = tags
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


def _copy_locked_db(src: Path) -> Path:
    tmp = Path(tempfile.mkdtemp()) / src.name
    shutil.copy(src, tmp)
    for suffix in ("-wal", "-shm"):
        side = src.with_name(src.name + suffix)
        if side.exists():
            try:
                shutil.copy(side, tmp.with_name(tmp.name + suffix))
            except OSError:
                pass
    return tmp


def _scan_browser(conn, cfg, name, src_path, query, to_unix) -> dict:
    src = Path(src_path).expanduser()
    if not src.exists():
        return {"status": "not found"}
    cursor = get_cursor(conn, name)
    watermark = cursor.get("watermark", 0)
    try:
        copy = _copy_locked_db(src)
        bconn = sqlite3.connect(copy)
        rows = bconn.execute(query, (watermark,)).fetchall()
        bconn.close()
        shutil.rmtree(copy.parent, ignore_errors=True)
    except (OSError, sqlite3.Error) as e:
        return {"status": f"no access ({e})"}
    skip = load_skip_domains(cfg)
    new = skipped = 0
    for url, title, raw_time in rows:
        # advance past skipped rows too, or a blocked tail stalls the cursor
        watermark = max(watermark, raw_time)
        if blocked(skip, url):
            skipped += 1
            continue
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


def run_all(conn, cfg) -> dict:
    results = {"fs": scan_fs(conn, cfg)}
    if cfg["browser"]["chrome"]:
        results["chrome"] = scan_chrome(conn, cfg)
    if cfg["browser"]["safari"]:
        results["safari"] = scan_safari(conn, cfg)
    return results
