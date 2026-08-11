"""The gate: every byte that leaves for a model passes through here, and the
disclosure itself is logged back into the archive as an egress event."""

import fnmatch
import os
import re

from .db import append_event, now_iso
from .domains import blocked, load_skip_domains
from .search import search


class GateError(Exception):
    pass


def _patterns(cfg):
    return [(name, re.compile(pat)) for name, pat in cfg["gate"]["redact"].items()]


def redact(cfg, text: str) -> str:
    for name, rx in _patterns(cfg):
        text = rx.sub(f"[REDACTED:{name}]", text)
    return text


def never_leave(cfg, uri) -> bool:
    if not uri:
        return False
    if uri.startswith(("http://", "https://")) and blocked(load_skip_domains(cfg), uri):
        return True
    path = os.path.expanduser(uri)
    return any(
        fnmatch.fnmatch(path, os.path.expanduser(p)) for p in cfg["gate"]["never_leave"]
    )


def est_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def spent_today(conn) -> int:
    day = now_iso()[:10]
    row = conn.execute(
        "SELECT COALESCE(SUM(json_extract(meta, '$.est_tokens')), 0) AS v "
        "FROM events WHERE kind = 'egress' AND ts LIKE ?",
        (day + "%",),
    ).fetchone()
    return int(row["v"] or 0)


def check_budget(conn, cfg, upcoming: int = 0):
    spent, daily = spent_today(conn), cfg["gate"]["daily_token_budget"]
    if spent + upcoming >= daily:
        raise GateError(f"daily egress budget exhausted "
                        f"({spent} spent + {upcoming} requested / {daily} est. tokens)")


def log_egress(conn, cfg, content: str, meta: dict) -> int:
    # the choke point: nothing is logged, and so nothing leaves, unredacted
    content = redact(cfg, content)
    meta = {"est_tokens": est_tokens(content), **meta}
    return append_event(conn, "gate", "egress", content=content, meta=meta)


def assemble(conn, cfg, query: str, budget: int = 8000, purpose: str = "") -> dict:
    budget = min(budget, cfg["gate"]["max_recall_budget"])
    check_budget(conn, cfg, upcoming=budget)
    parts, ids, used = [], [], 0
    for hit in search(conn, query, limit=40):
        if never_leave(cfg, hit["uri"]):
            continue
        ev = conn.execute("SELECT * FROM events WHERE id = ?", (hit["id"],)).fetchone()
        text = redact(cfg, ev["content"] or "")
        header = redact(
            cfg, f"--- [{ev['id']}] {ev['ts']} {ev['source']}/{ev['kind']} {ev['uri'] or ''} ---"
        )
        cost = est_tokens(header + text)
        truncated = False
        if used + cost > budget:
            room = (budget - used) * 4 - len(header) - 32
            if room < 200:
                continue
            text = text[:room] + "\n[truncated]"
            cost = est_tokens(header + text)
            truncated = True
        parts.append(header + "\n" + text)
        ids.append(ev["id"])
        used += cost
        if truncated or used >= budget:
            break
    bundle = "\n\n".join(parts) if parts else "(no matching events)"
    egress_id = log_egress(
        conn, cfg, bundle,
        {"type": "recall", "query": query, "purpose": purpose, "budget": budget, "items": ids},
    )
    return {"bundle": bundle, "items": ids, "est_tokens": used, "egress_id": egress_id}
