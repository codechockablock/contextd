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


# loop_confirm/loop_dismiss/decision_supersede are grant-gated
# (docs/GRANTS.md): without an active operator-recorded delegation for the
# matching authority class and scope they refuse, and with one they record
# authority 'model-granted' plus the grant id — never 'operator'. This is a
# DIFFERENT mechanism from the retired utterance-binding relay (which
# inferred per-item assent from operator text and was mechanically unsound;
# negative result in docs/OPEN_LOOPS.md): a grant is explicit class-level
# assent recorded as its own operator CLI act, and nothing is inferred.


def loop_confirm(loop_id: int, reason: str = "") -> str:
    """Confirm a candidate loop UNDER A STANDING DELEGATION. Refuses unless
    the operator has an active grant for loop.confirm covering the loop's
    scope; the confirmation is recorded as model-granted, traceable to the
    grant."""
    from .grants import GrantError, require_grant
    from .loops import LoopError, reduce_loops, transition
    conn = connect()
    lp = reduce_loops(conn)["loops"].get(int(loop_id))
    if lp is None:
        return f"REFUSED: no loop #{loop_id}"
    try:
        g = require_grant(conn, "loop.confirm", lp["scope"])
        r = transition(conn, int(loop_id), "confirm",
                       authority="model-granted", client=CLIENT,
                       reason=redact(load_config(), reason),
                       grant=g["id"])
    except (GrantError, LoopError) as e:
        return f"REFUSED: {e}"
    return (f"loop#{r['loop']['id']} -> {r['loop']['state']} "
            f"(model-granted under grant ev {g['id']})")


def loop_dismiss(loop_id: int, reason: str = "") -> str:
    """Dismiss a candidate loop UNDER A STANDING DELEGATION (grant class
    loop.dismiss); recorded as model-granted, traceable to the grant."""
    from .grants import GrantError, require_grant
    from .loops import LoopError, reduce_loops, transition
    conn = connect()
    lp = reduce_loops(conn)["loops"].get(int(loop_id))
    if lp is None:
        return f"REFUSED: no loop #{loop_id}"
    try:
        g = require_grant(conn, "loop.dismiss", lp["scope"])
        r = transition(conn, int(loop_id), "dismiss",
                       authority="model-granted", client=CLIENT,
                       reason=redact(load_config(), reason),
                       grant=g["id"])
    except (GrantError, LoopError) as e:
        return f"REFUSED: {e}"
    return (f"loop#{r['loop']['id']} -> {r['loop']['state']} "
            f"(model-granted under grant ev {g['id']})")


def decision_supersede(old: int, new: int, reason: str = "") -> str:
    """Record that event NEW supersedes event OLD, UNDER A STANDING
    DELEGATION (grant class decision.supersede, global scope only);
    recorded as model-granted, traceable to the grant."""
    from .decisions import DecisionError, record_supersession
    from .grants import GrantError, require_grant
    conn = connect()
    try:
        g = require_grant(conn, "decision.supersede", None)
        r = record_supersession(conn, int(old), int(new),
                                reason=redact(load_config(), reason),
                                client=CLIENT,
                                authority="model-granted", grant=g["id"])
    except (GrantError, DecisionError) as e:
        return f"REFUSED: {e}"
    e = r["edge"]
    word = {"created": "recorded", "existing": "already recorded"}
    return (f"{word[r['result']]}: ev {e['old']} superseded by ev {e['new']} "
            f"(edge ev {e['edge']}, model-granted under grant ev {g['id']})")


TOOLS = {
    "recall": recall,
    "search": search,
    "note": note,
    "timeline": timeline,
    "loop_candidate": loop_candidate,
    "loop_list": loop_list,
    "loop_confirm": loop_confirm,
    "loop_dismiss": loop_dismiss,
    "decision_supersede": decision_supersede,
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
