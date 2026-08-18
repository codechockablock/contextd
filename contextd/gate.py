"""The gate: every byte that leaves for a model passes through here, and the
disclosure itself is logged back into the archive as an egress event."""

import fnmatch
import os
import re

from .db import append_event, append_event_checked, now_iso
from .domains import blocked, load_skip_domains
from .redact import redact

#: How the gate finds candidate events to consider disclosing. The daemon
#: registers contextd.search here at its own import time; the evidence core
#: does not name it, because retrieval is a consumer of the record rather than
#: part of its lifecycle (lane T, ruling R1/R5).
#:
#: **No provider is the fail-closed state.** With nothing registered there are
#: no candidates, so `select_items` returns nothing and `disclose` has nothing
#: to disclose or to log. That is the safe direction for a gate: it discloses
#: LESS, never more. Contrast contextd/domains.py, whose no-op default would
#: have discloses MORE and is therefore core rather than a hook.
_RETRIEVAL = None


def register_retrieval_provider(provider) -> None:
    """Declare how candidate events are found.

    `provider(conn, query, *, limit, since, until) -> list[row]`, each row
    carrying at least `id` and `uri`. Last registration wins.
    """
    global _RETRIEVAL
    _RETRIEVAL = provider


def _search(conn, query, *, limit, since, until):
    if _RETRIEVAL is None:
        return []
    return _RETRIEVAL(conn, query, limit=limit, since=since, until=until)


__all__ = [
    "GateError",
    "assemble",
    "check_budget",
    "disclose",
    "est_tokens",
    "log_egress",
    "never_leave",
    "record_dispatch_outcome",
    "redact",
    "select_items",
    "spent_on_day",
    "spent_today",
    "verify_anchors",
]


class GateError(Exception):
    pass


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


ANCHOR_RX = re.compile(r"\[(\d+)\]")


def verify_anchors(text: str, allowed_ids) -> dict:
    """Anchor integrity for compressed disclosures. Measured basis (ledger
    exps #41325..#41485): a distilled bundle carries synthesis capability if
    and only if its claims keep bracketed event ids that resolve — and an
    anchor pointing at an event that was never supplied is worse than none,
    because it launders authority the archive never granted. Callers serving
    distilled bundles must refuse on any invalid anchor."""
    allowed = set(allowed_ids)
    uniq = sorted({int(m) for m in ANCHOR_RX.findall(text)})
    return {
        "ids": uniq,
        "valid": [i for i in uniq if i in allowed],
        "invalid": [i for i in uniq if i not in allowed],
    }


def spent_today(conn) -> int:
    return spent_on_day(conn, now_iso()[:10])


def spent_on_day(conn, day: str) -> int:
    row = conn.execute(
        "SELECT COALESCE(SUM(json_extract(meta, '$.est_tokens')), 0) AS v "
        "FROM events WHERE kind = 'egress' AND ts LIKE ?",
        (day + "%",),
    ).fetchone()
    return int(row["v"] or 0)


def check_budget(conn, cfg, upcoming: int = 0, day: str | None = None):
    spent = spent_on_day(conn, day) if day else spent_today(conn)
    daily = cfg["gate"]["daily_token_budget"]
    if spent + upcoming > daily:
        raise GateError(
            f"daily egress budget exhausted "
            f"({spent} spent + {upcoming} requested / {daily} est. tokens)"
        )


def disclose(conn, cfg, payload: str, intent: dict) -> dict:
    """Atomically redact, meter, and receipt exact archive-derived bytes.

    The returned ``content`` is the only payload a caller may dispatch. The
    budget callback runs under the same write lock as the chained egress
    insert, so concurrent callers cannot all pass against a stale spend total.
    Refusal appends nothing and exposes only numeric accounting in its error.

    ``intent`` is validated against the closed schema for its disclosure type
    (contextd/schemas.py) *before* anything is appended. It used to be written
    verbatim, which made every disclosure an arbitrary-content write into the
    archive by whoever controlled the caller. An undeclared field is refused,
    not dropped.
    """
    content = redact(cfg, payload)
    tokens = est_tokens(content)
    meta = {**(intent or {}), "est_tokens": tokens}

    def within_budget(locked_conn, event_ts):
        check_budget(locked_conn, cfg, upcoming=tokens, day=event_ts[:10])

    egress_id = append_event_checked(
        conn,
        "gate",
        "egress",
        content=content,
        meta=meta,
        check=within_budget,
    )
    return {"content": content, "egress_id": egress_id, "est_tokens": tokens}


def log_egress(conn, cfg, content: str, meta: dict) -> int:
    """Compatibility wrapper; new production code calls :func:`disclose`."""
    return disclose(conn, cfg, content, meta)["egress_id"]


DISPATCH_STATUSES = frozenset({"succeeded", "failed", "timeout"})


def record_dispatch_outcome(
    conn,
    egress_id: int,
    status: str,
    *,
    exit: int | None = None,
    timeout_seconds: int | None = None,
    duration_ms: int | None = None,
) -> int:
    """Append an immutable result linked to a pre-dispatch egress receipt.

    This used to take ``**details`` and persist them verbatim, which is how
    exception text, stderr, and command output reached the archive unbounded
    and unredacted. The outcome record now carries only integers: an exit
    code, a configured timeout, and a measured duration. A *class* of failure
    is representable, and so is how long it took; the failing process's own
    bytes are not.
    """
    if status not in DISPATCH_STATUSES:
        raise ValueError(f"invalid dispatch status: {status}")
    if not conn.execute(
        "SELECT 1 FROM events WHERE id = ? AND kind = 'egress'", (egress_id,)
    ).fetchone():
        raise ValueError(f"no egress event #{egress_id}")
    meta = {"egress_id": egress_id, "status": status}
    if exit is not None:
        meta["exit"] = int(exit)
    if timeout_seconds is not None:
        meta["timeout_seconds"] = int(timeout_seconds)
    if duration_ms is not None:
        meta["duration_ms"] = int(duration_ms)
    return append_event(conn, "gate", "egress_outcome", meta=meta)


def select_items(
    conn,
    cfg,
    query: str,
    budget: int,
    since: str = "",
    until: str = "",
    ranked_ids=None,
) -> list:
    """The one selection walk behind every recall: ranked search hits, filtered
    by never_leave, deduped by uri, redacted, greedily packed to budget. Each
    item is returned fully rendered so a caller (or an experiment) holds the
    exact bytes a bundle would carry.

    ranked_ids optionally replaces bm25 order with an externally computed one
    — restricted to ids the search actually matched, so a ranking can reorder
    the candidate pool but never smuggle events into it. The ranking policies
    themselves live outside the kernel until an experiment earns them."""
    items, used = [], 0
    seen_uris = set()
    hits = _search(conn, query, limit=40, since=since or None,
                   until=until or None)
    if ranked_ids is not None:
        by_id = {h["id"]: h for h in hits}
        hits = [by_id[i] for i in ranked_ids if i in by_id]
    for hit in hits:
        if never_leave(cfg, hit["uri"]):
            continue
        if hit["uri"] and hit["uri"] in seen_uris:
            continue
        ev = conn.execute("SELECT * FROM events WHERE id = ?", (hit["id"],)).fetchone()
        text = ev["content"] or ""
        if ev["uri"]:
            seen_uris.add(ev["uri"])
            # the header carries the uri; don't pay for it again in the body
            text = text.replace(ev["uri"], "").strip()
        text = redact(cfg, text)
        header = redact(
            cfg,
            f"--- [{ev['id']}] {ev['ts']} {ev['source']}/{ev['kind']} {ev['uri'] or ''} ---",
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
        items.append(
            {
                "id": ev["id"],
                "ts": ev["ts"],
                "source": ev["source"],
                "kind": ev["kind"],
                "uri": ev["uri"],
                "meta": ev["meta"],
                "header": header,
                "text": text,
                "est_tokens": cost,
            }
        )
        used += cost
        if truncated or used >= budget:
            break
    return items


def assemble(
    conn,
    cfg,
    query: str,
    budget: int = 8000,
    purpose: str = "",
    since: str = "",
    until: str = "",
    client: str = "cli",
) -> dict:
    budget = min(budget, cfg["gate"]["max_recall_budget"])
    items = select_items(conn, cfg, query, budget, since, until)
    ids = [it["id"] for it in items]
    bundle = (
        "\n\n".join(it["header"] + "\n" + it["text"] for it in items)
        if items
        else "(no matching events)"
    )
    # the raw query is not persisted: it is caller-controlled, unbounded, and
    # is usually the most revealing string in the request. The schema keys it
    # (contextd/correlate.py) so two recalls of the same query still correlate.
    meta = {
        "type": "recall",
        "query": query,
        "purpose": purpose,
        "budget": budget,
        "items": ids,
        "client": client,
    }
    if since or until:
        meta["window"] = [since, until]
    disclosure = disclose(conn, cfg, bundle, meta)
    return {
        "bundle": disclosure["content"],
        "items": ids,
        "est_tokens": disclosure["est_tokens"],
        "egress_id": disclosure["egress_id"],
    }
