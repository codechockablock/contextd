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


def _loop_scope(scope_repo: str) -> dict:
    """CONTEXTD_LOOP_SCOPE (set by a harness) pins the scope server-side so
    a spawned generator cannot scope-spray; otherwise the tool argument
    picks a repo scope, empty meaning global. Attribution, not
    authentication, like every env binding here."""
    from .loops import make_scope
    pinned = os.environ.get("CONTEXTD_LOOP_SCOPE", "").strip()
    if pinned:
        return make_scope(None if pinned == "global" else pinned)
    return make_scope(scope_repo.strip() or None)


def loop_candidate(text: str, scope_repo: str = "") -> str:
    """Propose a candidate open loop (non-authoritative; an operator must
    confirm it before it carries anywhere). Under a derivation binding the
    bracketed anchors in the text are kernel-verified against the disclosed
    dialogue and recorded as source events; invalid anchors refuse the
    candidate so you can retry with ids that were actually supplied.
    Candidates duplicating a live loop, or re-proposing a closed or
    dismissed one, are suppressed and say so."""
    from .loops import LoopError, add_candidate
    conn = connect()
    text = redact(load_config(), text)
    derivation, err = _derivation_binding(conn, text)
    if err:
        return err
    source_events = derivation["anchors"] if derivation else None
    try:
        r = add_candidate(conn, text, _loop_scope(scope_repo), client=CLIENT,
                          source_events=source_events, derivation=derivation)
    except LoopError as e:
        return f"REFUSED: {e}"
    lp = r["loop"]
    if r["result"] == "created":
        return (f"candidate loop#{lp['id']} recorded (state: candidate; an "
                "operator confirm is required before it becomes active)")
    if r["result"] == "suppressed_live":
        return (f"already tracked as loop#{lp['id']} ({lp['state']}); "
                "not re-proposing")
    return (f"previously {lp['state']} as loop#{lp['id']}; suppressed — "
            "dismissed or completed loops are not re-proposed. The operator "
            "can re-add directly with 'ctx loop add' if this is a real "
            "priority again.")


def loop_list(scope_repo: str = "", include_candidates: bool = True) -> str:
    """List active loops (and pending candidates) for a scope. The listing
    is archive content leaving through MCP, so it is disclosed through the
    gate and logged like any read."""
    from .loops import loops_for_scope
    conn = connect()
    cfg = load_config()
    scope = _loop_scope(scope_repo)
    states = ("open", "candidate") if include_candidates else ("open",)
    rows = loops_for_scope(conn, scope, states=states)
    lines = []
    for lp in rows:
        tag = lp["state"] + (" reopened" if lp["reopen_count"] else "")
        lines.append(f"[loop#{lp['id']}] {tag} since {lp['created_ts'][:10]}"
                     f" :: {lp['text']}")
    out = "\n".join(lines) or "(no loops for this scope)"
    try:
        receipt = disclose(conn, cfg, out, {
            "type": "loop_list", "client": CLIENT,
            "scope": "global" if scope.get("global") else scope["repo"]})
    except GateError as e:
        return f"GATE REFUSED: {e}"
    return receipt["content"]


def _bound_transition(op: str, candidate_id: int, operator_quote: str,
                      reason: str = "") -> str:
    from .loops import LoopError, transition, verify_operator_utterance
    conn = connect()
    ev = verify_operator_utterance(conn, candidate_id, operator_quote)
    if not ev["ok"]:
        prefix = "RETRY LATER" if ev.get("retryable") else "REFUSED"
        return f"{prefix}: {ev['why']}"
    try:
        r = transition(conn, candidate_id, op,
                       authority="operator_via_model", client=CLIENT,
                       reason=reason,
                       confirmation={"user_event": ev["user_event"],
                                     "quote": operator_quote})
    except LoopError as e:
        return f"REFUSED: {e}"
    lp = r["loop"]
    if r["result"] == "noop":
        return f"loop#{lp['id']} already {lp['state']}"
    return (f"loop#{lp['id']} -> {lp['state']} (model-mediated operator "
            f"{op}, bound to user message event #{ev['user_event']})")


def loop_confirm(candidate_id: int, operator_quote: str) -> str:
    """Promote a candidate to an active open loop, ONLY as a relay of the
    operator's own words: operator_quote must be a verbatim span (>= 12
    chars) of a user message the archive ingested AFTER the candidate was
    created. The kernel verifies the quote itself; your claim that the user
    agreed is not evidence. If ingestion has not caught up yet, this refuses
    retryably — the operator can always run 'ctx loop confirm' directly."""
    return _bound_transition("confirm", candidate_id, operator_quote)


def loop_dismiss(candidate_id: int, operator_quote: str,
                 reason: str = "") -> str:
    """Dismiss a candidate (it will not be re-proposed), under the same
    post-candidate operator-utterance binding as loop_confirm."""
    return _bound_transition("dismiss", candidate_id, operator_quote, reason)


TOOLS = {
    "recall": recall,
    "search": search,
    "note": note,
    "timeline": timeline,
    "loop_candidate": loop_candidate,
    "loop_list": loop_list,
    "loop_confirm": loop_confirm,
    "loop_dismiss": loop_dismiss,
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
