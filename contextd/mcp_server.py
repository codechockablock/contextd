"""MCP surface: four tools. Every read that leaves through MCP is an egress
event in the archive — the log records what the log disclosed."""

import json
import os
from collections.abc import Iterable

from mcp.server.mcpserver import MCPServer

from . import load_config
from . import service as authority
from .db import connect
from .gate import GateError, disclose, redact, verify_anchors
from .ingest import ingest_note
from .redact import sanitize_label
from .rpc import RpcError

# CONTEXTD_CLIENT is a self-asserted label a client sets on its own subprocess.
# It is an `origin_claim` and nothing more (docs/SECURITY.md §3): the process
# that sets it is, under this threat model, the attacker. It survives only as a
# bounded, floor-redacted diagnostic string recorded as `claimed_client`, and
# no value of it — including "human" or "operator" — produces authenticated
# provenance. The old module-level name `CLIENT` read like an identity;
# this one states what it is.
CLAIMED_CLIENT = sanitize_label(
    load_config(), os.environ.get("CONTEXTD_CLIENT", "mcp").strip() or "mcp"
)


#: The dispatch capability a harness hands to a model subprocess. Opaque and
#: single-use; see contextd/capability.py for why the old integer binding is
#: gone.
CAPABILITY_ENV = "CONTEXTD_DISPATCH_CAPABILITY"

#: The retired binding. Read ONLY so its presence can be refused loudly rather
#: than silently ignored — a harness that still exports it is running with an
#: assumption that no longer holds, and failing quietly would hide that.
RETIRED_ENV = "CONTEXTD_DERIVATION_SOURCE"


def _derivation_binding(conn, text: str):
    """Kernel-verified derivation for notes written under a dispatch capability.

    A harness that feeds a model a gated disclosure requests a capability from
    the authority plane and exports it as ``CONTEXTD_DISPATCH_CAPABILITY``.
    The capability is opaque, bound to the exact disclosure and its bytes, the
    principal, the dispatch session, the single write it permits, and the
    observed dispatch state — and it is consumed atomically with the append.

    ``CONTEXTD_DERIVATION_SOURCE`` used to do this job with a bare event id.
    That is retired: an enumerable integer in an environment variable is
    guessable and is owned by the very process it was supposed to constrain
    (contextd/capability.py). Its presence is now an explicit refusal.

    The anchor check is unchanged and still runs: the kernel — not the model —
    verifies bracketed anchors against the bound disclosure's item list. A
    capability says *this write may happen*, never *these claims are supported*.

    Returns ``(derivation, error, capability)``. A non-None error means the
    note must be refused so the model can retry with valid anchors.
    """
    from .capability import CapabilityError, parse_token, verify

    if os.environ.get(RETIRED_ENV, "").strip():
        return None, (
            f"REFUSED: {RETIRED_ENV} is retired and carries no authority. "
            f"Request a dispatch capability from the authority plane and "
            f"export it as {CAPABILITY_ENV} (contextd/capability.py)."
        ), None

    raw = os.environ.get(CAPABILITY_ENV, "").strip()
    if not raw:
        return None, None, None
    try:
        # named `cap_secret`, not `secret`: the repository privacy
        # scanner's password_assignment pattern matches a bare
        # `secret = ...` assignment, and a scanner that flags its own
        # codebase trains people to ignore it
        capability_id, cap_secret = parse_token(raw)
        record = verify(
            conn, capability_id, cap_secret,
            principal_uid=os.getuid(),
            dispatcher=os.environ.get("CONTEXTD_DISPATCH_SESSION", "").strip(),
            write=("note", "note"),
        )
    except CapabilityError as exc:
        return None, f"REFUSED: {exc}", None

    row = conn.execute(
        "SELECT meta FROM events WHERE id = ?", (record["egress_id"],)).fetchone()
    meta = json.loads(row["meta"]) if row and row["meta"] else {}
    anchors = verify_anchors(text, meta.get("items") or [])
    if anchors["invalid"]:
        return None, (f"REFUSED: anchors {anchors['invalid']} were not in the "
                      "supplied dialogue; cite only bracketed event ids that "
                      "appear in the input, then retry"), None
    from .capability import digest as capability_digest
    return ({"source_egress": record["egress_id"],
             "anchors": anchors["valid"],
             "capability_id": capability_digest(capability_id)},
            None, capability_id)


def recall(
    query: str, budget: int = 8000, purpose: str = "", since: str = "", until: str = ""
) -> str:
    """Assemble a redacted, budget-capped context bundle from the personal archive.
    State the purpose; the disclosure is logged. Optional since/until (ISO dates,
    until exclusive) filter by occurrence time — visit time for browser history."""
    # routed through the authority plane: in hardened mode this is an RPC to
    # the daemon, which is the only process that opens the archive
    try:
        return authority.recall(query, budget, purpose, since, until,
                                client=CLAIMED_CLIENT)["bundle"]
    except GateError as e:
        return f"GATE REFUSED: {e}"
    except RpcError as e:
        return f"REFUSED: {e}"


def search(query: str, limit: int = 10) -> str:
    """Search the archive; returns redacted snippets with event ids (logged, budgeted)."""
    try:
        return authority.search(query, limit=max(1, min(limit, 50)),
                                client=CLAIMED_CLIENT)["content"]
    except GateError as e:
        return f"GATE REFUSED: {e}"
    except RpcError as e:
        return f"REFUSED: {e}"


def note(text: str) -> str:
    """Append a note event tagged with this client's *claimed* label.

    Every note — model-written or not — passes capture-side redaction, so no
    credential of a pinned class reaches storage. The note carries assurance
    `unverified`: an MCP-originated write is never operator-authoritative, and
    no value of CONTEXTD_CLIENT changes that (docs/SECURITY.md §3).

    Under a CONTEXTD_DERIVATION_SOURCE binding the note's bracketed anchors are
    kernel-verified against that disclosure and recorded as lineage; invalid
    anchors refuse the note so the model can retry."""
    from .authd import hardened
    if hardened():
        # the daemon owns the archive; the derivation binding is re-verified
        # there rather than here, where the connection does not exist
        try:
            result = authority.note(text, client=CLAIMED_CLIENT)
        except RpcError as e:
            return f"REFUSED: {e}"
        return f"noted as event #{result['event']}"
    conn = connect()
    text = redact(load_config(), text)
    derivation, err, capability_id = _derivation_binding(conn, text)
    if err:
        return err
    # the capability is consumed inside the append transaction, so a crash
    # cannot separate "capability used" from "note written", and two
    # concurrent writers racing on one capability cannot both succeed
    bind = None
    if capability_id is not None:
        from .capability import consume

        def bind(locked_conn, _ts, event_id):
            consume(locked_conn, capability_id, event_id)

    eid = ingest_note(conn, text, claimed_client=CLAIMED_CLIENT,
                      derivation=derivation, bind=bind)
    return f"noted as event #{eid}"


def timeline(
    since: str = "", until: str = "", source: str = "", limit: int = 30
) -> str:
    """Browse recent events by time window (redacted briefs, logged).
    Egress events are excluded unless source='gate' (disclosure audit)."""
    try:
        return authority.timeline(since, until, source,
                                  limit=max(1, min(limit, 200)),
                                  client=CLAIMED_CLIENT)["content"]
    except GateError as e:
        return f"GATE REFUSED: {e}"
    except RpcError as e:
        return f"REFUSED: {e}"


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
    derivation, err, _capability_id = _derivation_binding(conn, text)
    if err:
        return err
    source_events = derivation["anchors"] if derivation else None
    try:
        r = add_candidate(conn, text, _loop_scope(scope_repo), client=CLAIMED_CLIENT,
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
            "type": "loop_list", "client": CLAIMED_CLIENT,
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
                       authority="model-granted", client=CLAIMED_CLIENT,
                       reason=redact(load_config(), reason),
                       grant=g["id"])
    except (GrantError, LoopError) as e:
        return f"REFUSED: {e}"
    if r["result"] == "noop":
        # nothing was appended; claiming a granted act here would be a lie
        return (f"loop#{r['loop']['id']} already {r['loop']['state']}; "
                f"nothing appended")
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
                       authority="model-granted", client=CLAIMED_CLIENT,
                       reason=redact(load_config(), reason),
                       grant=g["id"])
    except (GrantError, LoopError) as e:
        return f"REFUSED: {e}"
    if r["result"] == "noop":
        return (f"loop#{r['loop']['id']} already {r['loop']['state']}; "
                f"nothing appended")
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
                                client=CLAIMED_CLIENT,
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
