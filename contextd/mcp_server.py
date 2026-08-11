"""MCP surface: four tools. Every read that leaves through MCP is an egress
event in the archive — the log records what the log disclosed."""

import json

from mcp.server.mcpserver import MCPServer

from . import load_config
from .db import append_event, connect
from .gate import (GateError, assemble, check_budget, est_tokens, log_egress,
                   never_leave, redact)
from .ingest import ingest_note
from .search import search as do_search
from .search import timeline as do_timeline

mcp = MCPServer("contextd")


@mcp.tool()
def recall(query: str, budget: int = 8000, purpose: str = "") -> str:
    """Assemble a redacted, budget-capped context bundle from the personal archive.
    State the purpose; the disclosure is logged."""
    conn = connect()
    try:
        return assemble(conn, load_config(), query, budget, purpose)["bundle"]
    except GateError as e:
        return f"GATE REFUSED: {e}"


@mcp.tool()
def search(query: str, limit: int = 10) -> str:
    """Search the archive; returns redacted snippets with event ids (logged, budgeted)."""
    conn = connect()
    cfg = load_config()
    hits = do_search(conn, query, max(1, min(limit, 50)), highlight=False)
    out = "\n".join(
        f"[{h['id']}] {h['ts']} {h['source']}/{h['kind']} {h['uri'] or ''} :: {h['snip']}"
        for h in hits if not never_leave(cfg, h["uri"])
    )
    out = redact(cfg, out) if out else "(no hits)"
    try:
        check_budget(conn, cfg, upcoming=est_tokens(out))
    except GateError as e:
        return f"GATE REFUSED: {e}"
    log_egress(conn, cfg, out, {"type": "search", "query": query})
    return out


@mcp.tool()
def note(text: str) -> str:
    """Append a note event to the archive, stamped as model-written (actor=mcp)."""
    return f"noted as event #{ingest_note(connect(), text, actor='mcp')}"


@mcp.tool()
def timeline(since: str = "", until: str = "", source: str = "", limit: int = 30) -> str:
    """Browse recent events by time window (redacted briefs, logged).
    Egress events are excluded unless source='gate' (disclosure audit)."""
    conn = connect()
    cfg = load_config()
    rows = do_timeline(conn, since or None, until or None, source or None,
                       limit=max(1, min(limit, 200)), exclude_egress=(source != "gate"))
    out = "\n".join(
        f"[{r['id']}] {r['ts']} {r['source']}/{r['kind']} {r['uri'] or ''} "
        f"{redact(cfg, r['content'] or '')[:120]}"
        for r in rows if not never_leave(cfg, r["uri"])
    )
    out = redact(cfg, out) if out else "(no events)"
    try:
        check_budget(conn, cfg, upcoming=est_tokens(out))
    except GateError as e:
        return f"GATE REFUSED: {e}"
    log_egress(conn, cfg, out, {"type": "timeline",
                                "window": json.dumps([since, until, source])})
    return out


def main():
    mcp.run()


if __name__ == "__main__":
    main()
