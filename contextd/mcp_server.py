"""MCP surface: four tools. Every read that leaves through MCP is an egress
event in the archive — the log records what the log disclosed."""

import json
import os

from mcp.server.mcpserver import MCPServer

from . import load_config
from .db import append_event, connect
from .gate import (GateError, assemble, check_budget, est_tokens, log_egress,
                   never_leave, redact)
from .ingest import ingest_note
from .search import search as do_search
from .search import timeline as do_timeline

mcp = MCPServer("contextd")

# each connecting client identifies itself so the audit trail records who drew
# on the archive; a stdio client sets it per-subprocess via CONTEXTD_CLIENT
CLIENT = os.environ.get("CONTEXTD_CLIENT", "mcp").strip() or "mcp"


@mcp.tool()
def recall(query: str, budget: int = 8000, purpose: str = "",
           since: str = "", until: str = "") -> str:
    """Assemble a redacted, budget-capped context bundle from the personal archive.
    State the purpose; the disclosure is logged. Optional since/until (ISO dates,
    until exclusive) filter by occurrence time — visit time for browser history."""
    conn = connect()
    try:
        return assemble(conn, load_config(), query, budget, purpose,
                        since, until, client=CLIENT)["bundle"]
    except GateError as e:
        return f"GATE REFUSED: {e}"


@mcp.tool()
def search(query: str, limit: int = 10) -> str:
    """Search the archive; returns redacted snippets with event ids (logged, budgeted)."""
    conn = connect()
    cfg = load_config()
    hits = do_search(conn, query, max(1, min(limit, 50)), highlight=False)
    seen, lines = set(), []
    for h in hits:
        if never_leave(cfg, h["uri"]) or (h["uri"] and h["uri"] in seen):
            continue
        seen.add(h["uri"])
        lines.append(f"[{h['id']}] {h['ts']} {h['source']}/{h['kind']} {h['uri'] or ''} :: {h['snip']}")
    out = "\n".join(lines)
    out = redact(cfg, out) if out else "(no hits)"
    try:
        check_budget(conn, cfg, upcoming=est_tokens(out))
    except GateError as e:
        return f"GATE REFUSED: {e}"
    log_egress(conn, cfg, out, {"type": "search", "query": query, "client": CLIENT})
    return out


@mcp.tool()
def note(text: str) -> str:
    """Append a note event, stamped with this client's identity. Model-written
    notes pass capture-side redaction: the archive never stores credentials.
    (Human CLI notes stay raw on purpose; the gate still redacts them at egress.)"""
    return f"noted as event #{ingest_note(connect(), redact(load_config(), text), actor=CLIENT)}"


@mcp.tool()
def timeline(since: str = "", until: str = "", source: str = "", limit: int = 30) -> str:
    """Browse recent events by time window (redacted briefs, logged).
    Egress events are excluded unless source='gate' (disclosure audit)."""
    conn = connect()
    cfg = load_config()
    rows = do_timeline(conn, since or None, until or None, source or None,
                       limit=max(1, min(limit, 200)), exclude_egress=(source != "gate"))

    def brief(r):
        c = r["content"] or ""
        if r["uri"]:
            c = c.replace(r["uri"], "")
        return redact(cfg, c.strip())[:120]

    out = "\n".join(
        f"[{r['id']}] {r['ts']} {r['source']}/{r['kind']} {r['uri'] or ''} {brief(r)}"
        for r in rows if not never_leave(cfg, r["uri"])
    )
    out = redact(cfg, out) if out else "(no events)"
    try:
        check_budget(conn, cfg, upcoming=est_tokens(out))
    except GateError as e:
        return f"GATE REFUSED: {e}"
    log_egress(conn, cfg, out, {"type": "timeline", "client": CLIENT,
                                "window": json.dumps([since, until, source])})
    return out


def main():
    mcp.run()


if __name__ == "__main__":
    main()
