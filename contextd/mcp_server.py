"""MCP surface: four tools. Every read that leaves through MCP is an egress
event in the archive — the log records what the log disclosed."""

import json
import os
from collections.abc import Iterable

from mcp.server.mcpserver import MCPServer

from . import load_config
from .db import connect
from .gate import GateError, assemble, disclose, never_leave, redact, verify_anchors
from .ingest import ingest_note
from .search import search as do_search
from .search import timeline as do_timeline

# each connecting client identifies itself so the audit trail records who drew
# on the archive; a stdio client sets it per-subprocess via CONTEXTD_CLIENT
CLIENT = os.environ.get("CONTEXTD_CLIENT", "mcp").strip() or "mcp"


def _derivation_binding(conn, text: str):
    """Kernel-verified derivation for notes written under a dispatch binding.

    A harness that feeds a model a gated disclosure (the reconciler) exports
    CONTEXTD_DERIVATION_SOURCE=<egress_id> into the model subprocess; every
    note written during that dispatch is then bound to the exact disclosed
    bytes. The kernel — not the model — verifies the note's bracketed anchors
    against the egress item list and stamps meta.derivation itself, so a note
    can never claim more lineage than the record supports. Like
    CONTEXTD_CLIENT this is same-owner attribution, not authentication.

    Returns (derivation, error): derivation may be None (no binding active);
    a non-None error means the note must be refused so the model can retry
    with valid anchors — an anchor pointing at an undisclosed event launders
    authority and is worse than no note this round (the epoch stays
    retryable).
    """
    raw = os.environ.get("CONTEXTD_DERIVATION_SOURCE", "").strip()
    if not raw:
        return None, None
    if not raw.isdigit():
        return None, f"REFUSED: invalid derivation binding {raw!r}"
    egress_id = int(raw)
    row = conn.execute(
        "SELECT kind, meta FROM events WHERE id = ?", (egress_id,)).fetchone()
    meta = json.loads(row["meta"]) if row and row["meta"] else {}
    if not row or row["kind"] != "egress" or not isinstance(meta.get("items"), list):
        return None, (f"REFUSED: derivation binding #{egress_id} is not a "
                      "disclosure with an item list")
    anchors = verify_anchors(text, meta["items"])
    if anchors["invalid"]:
        return None, (f"REFUSED: anchors {anchors['invalid']} were not in the "
                      "supplied dialogue; cite only bracketed event ids that "
                      "appear in the input, then retry")
    return {"source_egress": egress_id, "anchors": anchors["valid"]}, None


def recall(
    query: str, budget: int = 8000, purpose: str = "", since: str = "", until: str = ""
) -> str:
    """Assemble a redacted, budget-capped context bundle from the personal archive.
    State the purpose; the disclosure is logged. Optional since/until (ISO dates,
    until exclusive) filter by occurrence time — visit time for browser history."""
    conn = connect()
    try:
        return assemble(
            conn, load_config(), query, budget, purpose, since, until, client=CLIENT
        )["bundle"]
    except GateError as e:
        return f"GATE REFUSED: {e}"


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
        lines.append(
            f"[{h['id']}] {h['ts']} {h['source']}/{h['kind']} {h['uri'] or ''} :: {h['snip']}"
        )
    out = "\n".join(lines)
    out = out or "(no hits)"
    try:
        receipt = disclose(
            conn,
            cfg,
            out,
            {"type": "search", "query": query, "client": CLIENT},
        )
    except GateError as e:
        return f"GATE REFUSED: {e}"
    return receipt["content"]


def note(text: str) -> str:
    """Append a note event, stamped with this client's identity. Model-written
    notes pass capture-side redaction: the archive never stores credentials.
    (Human CLI notes stay raw on purpose; the gate still redacts them at egress.)
    Under a CONTEXTD_DERIVATION_SOURCE binding, the note's bracketed anchors
    are kernel-verified against that disclosure and recorded as lineage;
    invalid anchors refuse the note so the model can retry."""
    conn = connect()
    text = redact(load_config(), text)
    derivation, err = _derivation_binding(conn, text)
    if err:
        return err
    return f"noted as event #{ingest_note(conn, text, actor=CLIENT, derivation=derivation)}"


def timeline(
    since: str = "", until: str = "", source: str = "", limit: int = 30
) -> str:
    """Browse recent events by time window (redacted briefs, logged).
    Egress events are excluded unless source='gate' (disclosure audit)."""
    conn = connect()
    cfg = load_config()
    rows = do_timeline(
        conn,
        since or None,
        until or None,
        source or None,
        limit=max(1, min(limit, 200)),
        exclude_egress=(source != "gate"),
    )

    def brief(r):
        c = r["content"] or ""
        if r["uri"]:
            c = c.replace(r["uri"], "")
        return redact(cfg, c.strip())[:120]

    out = "\n".join(
        f"[{r['id']}] {r['ts']} {r['source']}/{r['kind']} {r['uri'] or ''} {brief(r)}"
        for r in rows
        if not never_leave(cfg, r["uri"])
    )
    out = out or "(no events)"
    try:
        receipt = disclose(
            conn,
            cfg,
            out,
            {
                "type": "timeline",
                "client": CLIENT,
                "window": json.dumps([since, until, source]),
            },
        )
    except GateError as e:
        return f"GATE REFUSED: {e}"
    return receipt["content"]


TOOLS = {
    "recall": recall,
    "search": search,
    "note": note,
    "timeline": timeline,
}


def create_server(allowed_tools: Iterable[str] | None = None) -> MCPServer:
    """Build the actual MCP registry for this process.

    The allowlist is an operator-selected capability boundary, not client
    authentication: ``CONTEXTD_CLIENT`` remains self-asserted attribution.
    Omitting a tool here means it is absent from ``tools/list`` and therefore
    cannot be invoked through this server process.
    """
    allowed = set(TOOLS) if allowed_tools is None else set(allowed_tools)
    unknown = allowed - set(TOOLS)
    if unknown:
        raise ValueError(f"unknown contextd MCP tool(s): {', '.join(sorted(unknown))}")
    server = MCPServer("contextd")
    for name, fn in TOOLS.items():
        if name in allowed:
            server.add_tool(fn, name=name)
    return server


# Backward-compatible all-tools object for embedders. The CLI constructs its
# own registry so an operator allowlist changes the advertised surface itself.
mcp = create_server()


def main(allowed_tools: Iterable[str] | None = None):
    create_server(allowed_tools).run()


if __name__ == "__main__":
    main()
