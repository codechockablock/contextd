"""Open loops: operator-confirmed prospective state, event-sourced.

Contract: docs/OPEN_LOOPS.md (frozen before this module was written).
Everything here is deterministic and model-free. A loop is introduced by an
`add` (operator) or `candidate` (model) event of kind `loop`; its identity
is that event's id; every later transition is another append-only `loop`
event referencing it. Current state exists only as the reduction of those
events in id order — no UPDATE or DELETE is part of loop semantics (the
events table forbids both by trigger).

Authority labels are recorded, never inferred: `operator` (human CLI act),
`model` (proposal), `operator_via_model` (a relay carrying a kernel-verified
post-candidate operator utterance — attribution, not authentication; see the
contract's threat model). Invalid transitions refuse; retries of an already-
holding op are no-ops that append nothing."""

import hashlib
import json
import re
from pathlib import Path

from .db import append_event, append_event_checked

MIN_QUOTE_CHARS = 12    # policy constant (contract: chosen, not measured)
LOOP_SHARE = 0.15       # checkpoint slice; policy constant under test
LOOP_SLICE_MIN = 200    # est. tokens; policy constant under test
OMISSION_RESERVE = 48   # est. tokens held back so omission is always loud

CREATING_OPS = ("add", "candidate")
TRANSITION_OPS = ("confirm", "close", "reopen", "dismiss")


class LoopError(RuntimeError):
    """Invalid transition, unknown loop, or refused evidence."""


class _DuplicateRace(Exception):
    """A concurrent writer created the same-key loop between our reduce and
    the locked append; the caller returns the winner instead of forking."""


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip().rstrip(".")


def scope_str(scope: dict) -> str:
    if scope.get("global"):
        return "global"
    return f"repo:{scope['repo']}"


def make_scope(repo: str | None) -> dict:
    if repo is None:
        return {"global": True}
    return {"repo": str(Path(repo).expanduser().resolve())}


def dedupe_key(scope: dict, text: str) -> str:
    raw = scope_str(scope) + "\x1f" + normalize_text(text)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _rows(conn):
    return conn.execute(
        "SELECT id, ts, content, meta FROM events WHERE kind='loop' "
        "ORDER BY id").fetchall()


def reduce_loops(conn) -> dict:
    """Rebuild every loop's current state from the append-only record.

    Returns {"loops": {loop_id: state}, "orphans": [...]}. The write path
    refuses invalid transitions, so anomalies normally stay empty — but a
    direct append (same-owner, always possible) must never corrupt the
    reduction: historically invalid transitions are skipped and surfaced
    under the loop's `anomalies`, and transitions targeting a nonexistent
    loop land in `orphans`."""
    loops: dict = {}
    orphans: list = []
    for r in _rows(conn):
        meta = json.loads(r["meta"] or "{}")
        op = meta.get("op")
        if op in CREATING_OPS:
            state = "open" if op == "add" else "candidate"
            loops[r["id"]] = {
                "id": r["id"],
                "text": (r["content"] or "").strip(),
                "scope": meta.get("scope") or {"global": True},
                "state": state,
                "created_state": state,
                "created_authority": meta.get("authority") or (
                    "operator" if op == "add" else "model"),
                "created_client": meta.get("client", ""),
                "created_ts": r["ts"],
                "updated_ts": r["ts"],
                "reopen_count": 0,
                "promoted_authority": None,
                "last_reason": "",
                "source_events": meta.get("source_events") or [],
                "confirmation": None,
                "dedupe": meta.get("dedupe") or dedupe_key(
                    meta.get("scope") or {"global": True}, r["content"] or ""),
                "history": [{"event": r["id"], "op": op, "ts": r["ts"],
                             "authority": meta.get("authority")}],
                "anomalies": [],
            }
            continue
        if op not in TRANSITION_OPS:
            orphans.append({"event": r["id"], "why": f"unknown op {op!r}"})
            continue
        target = meta.get("loop")
        loop = loops.get(target)
        if loop is None:
            orphans.append({"event": r["id"],
                            "why": f"{op} targets unknown loop {target!r}"})
            continue
        allowed = {"confirm": ("candidate",), "close": ("open",),
                   "reopen": ("closed",), "dismiss": ("candidate",)}[op]
        entry = {"event": r["id"], "op": op, "ts": r["ts"],
                 "authority": meta.get("authority"),
                 "reason": (r["content"] or "").strip()}
        if loop["state"] not in allowed:
            loop["anomalies"].append(
                {**entry, "why": f"{op} recorded while {loop['state']}"})
            continue
        loop["history"].append(entry)
        loop["updated_ts"] = r["ts"]
        loop["last_reason"] = entry["reason"]
        if op == "confirm":
            loop["state"] = "open"
            loop["promoted_authority"] = meta.get("authority")
            if meta.get("confirmation"):
                loop["confirmation"] = meta["confirmation"]
        elif op == "close":
            loop["state"] = "closed"
        elif op == "reopen":
            loop["state"] = "open"
            loop["reopen_count"] += 1
        elif op == "dismiss":
            loop["state"] = "dismissed"
    return {"loops": loops, "orphans": orphans}


def _scope_matches(loop: dict, scope: dict | None) -> bool:
    if scope is None:
        return True
    return scope_str(loop["scope"]) == scope_str(scope)


def loops_for_scope(conn, scope: dict | None = None,
                    states: tuple = ("open",)) -> list:
    reduced = reduce_loops(conn)["loops"]
    out = [lp for lp in reduced.values()
           if lp["state"] in states and _scope_matches(lp, scope)]
    return sorted(out, key=lambda lp: lp["id"])


def _live_by_key(reduced: dict, scope: dict, text: str) -> dict | None:
    key = dedupe_key(scope, text)
    live = [lp for lp in reduced.values()
            if lp["dedupe"] == key and _scope_matches(lp, scope)
            and lp["state"] in ("candidate", "open")]
    return max(live, key=lambda lp: lp["id"]) if live else None


def _terminal_by_key(reduced: dict, scope: dict, text: str) -> dict | None:
    key = dedupe_key(scope, text)
    dead = [lp for lp in reduced.values()
            if lp["dedupe"] == key and _scope_matches(lp, scope)
            and lp["state"] in ("closed", "dismissed")]
    return max(dead, key=lambda lp: lp["id"]) if dead else None


def _no_live_dup(scope: dict, text: str):
    """Check callback re-verifying the dedupe INSIDE the witness/append
    lock: two concurrent same-key writers cannot both pass (the loser sees
    the winner's committed row and raises _DuplicateRace)."""
    def check(locked_conn, _ts):
        if _live_by_key(reduce_loops(locked_conn)["loops"], scope, text):
            raise _DuplicateRace
    return check


def add_loop(conn, text: str, scope: dict, client: str = "cli",
             source_events: list | None = None) -> dict:
    """Operator-declared open loop. Idempotent against live duplicates; a
    matching pending candidate is promoted instead (the operator said the
    thing the model proposed — one loop, operator authority)."""
    text = (text or "").strip()
    if not text:
        raise LoopError("empty loop text")
    reduced = reduce_loops(conn)["loops"]
    live = _live_by_key(reduced, scope, text)
    if live is not None:
        if live["state"] == "open":
            return {"result": "existing", "loop": live}
        eid = append_event(conn, "loop", "loop", content="",
                           meta={"op": "confirm", "loop": live["id"],
                                 "authority": "operator", "client": client})
        live = reduce_loops(conn)["loops"][live["id"]]
        return {"result": "confirmed_candidate", "loop": live, "event": eid}
    meta = {"op": "add", "scope": scope, "authority": "operator",
            "client": client, "dedupe": dedupe_key(scope, text)}
    if source_events:
        meta["source_events"] = sorted(int(i) for i in source_events)
    try:
        eid = append_event_checked(conn, "loop", "loop", content=text,
                                   meta=meta, check=_no_live_dup(scope, text))
    except _DuplicateRace:
        return {"result": "existing",
                "loop": _live_by_key(reduce_loops(conn)["loops"], scope, text)}
    return {"result": "created",
            "loop": reduce_loops(conn)["loops"][eid], "event": eid}


def add_candidate(conn, text: str, scope: dict, client: str = "model",
                  source_events: list | None = None,
                  derivation: dict | None = None) -> dict:
    """Model-proposed candidate. Never authoritative; suppressed against any
    same-key loop that is live (already tracked) or terminal (dismissal is a
    promise not to re-propose; a closed loop re-proposed is resurrection)."""
    text = (text or "").strip()
    if not text:
        raise LoopError("empty candidate text")
    reduced = reduce_loops(conn)["loops"]
    live = _live_by_key(reduced, scope, text)
    if live is not None:
        return {"result": "suppressed_live", "loop": live}
    dead = _terminal_by_key(reduced, scope, text)
    if dead is not None:
        return {"result": f"suppressed_{dead['state']}", "loop": dead}
    meta = {"op": "candidate", "scope": scope, "authority": "model",
            "client": client, "dedupe": dedupe_key(scope, text)}
    if source_events:
        meta["source_events"] = sorted(int(i) for i in source_events)
    if derivation:
        # kernel-verified lineage (mcp_server._derivation_binding); never
        # model-asserted — same rule as note derivation
        meta["derivation"] = derivation
    try:
        eid = append_event_checked(conn, "loop", "loop", content=text,
                                   meta=meta, check=_no_live_dup(scope, text))
    except _DuplicateRace:
        return {"result": "suppressed_live",
                "loop": _live_by_key(reduce_loops(conn)["loops"], scope, text)}
    return {"result": "created",
            "loop": reduce_loops(conn)["loops"][eid], "event": eid}


_TABLE = {
    "confirm": {"from": ("candidate",), "noop": ("open",),
                "refuse": {"closed": "closed; reopen instead",
                           "dismissed": "dismissed; re-add directly if it "
                                        "is a real priority"}},
    "close": {"from": ("open",), "noop": ("closed",),
              "refuse": {"candidate": "candidates are confirmed or "
                                      "dismissed, not closed",
                         "dismissed": "dismissed loops stay dismissed"}},
    "reopen": {"from": ("closed",), "noop": ("open",),
               "refuse": {"candidate": "candidates are confirmed or "
                                       "dismissed, not reopened",
                          "dismissed": "dismissed loops are re-added, "
                                       "not reopened"}},
    "dismiss": {"from": ("candidate",), "noop": ("dismissed",),
                "refuse": {"open": "open loops are closed, not dismissed",
                           "closed": "closed loops stay closed"}},
}


def transition(conn, loop_id: int, op: str, authority: str,
               client: str = "cli", reason: str = "",
               confirmation: dict | None = None) -> dict:
    """One lifecycle transition per the frozen table. No-ops append nothing;
    refusals raise LoopError with the exact rule violated."""
    if op not in _TABLE:
        raise LoopError(f"unknown transition {op!r}")
    loop = reduce_loops(conn)["loops"].get(loop_id)
    if loop is None:
        raise LoopError(f"no loop #{loop_id}")
    rules = _TABLE[op]
    if loop["state"] in rules["noop"]:
        return {"result": "noop", "loop": loop}
    if loop["state"] not in rules["from"]:
        raise LoopError(
            f"loop#{loop_id} is {loop['state']}: {rules['refuse'][loop['state']]}")
    meta = {"op": op, "loop": loop_id, "authority": authority,
            "client": client}
    if confirmation:
        meta["confirmation"] = confirmation
    eid = append_event(conn, "loop", "loop", content=reason.strip() or None,
                       meta=meta)
    return {"result": op, "loop": reduce_loops(conn)["loops"][loop_id],
            "event": eid}


def verify_operator_utterance(conn, candidate_id: int, quote: str) -> dict:
    """Mechanical evidence for model-mediated confirmation: the quote must
    occur verbatim (whitespace-normalized) inside an ingested role=user
    dialogue event appended AFTER the candidate. Returns the newest matching
    event id, or a structured refusal — never a guess. Proves the operator
    typed these words after the candidate existed; does NOT prove the words
    referred to this candidate (contract: the semantic gap stays open)."""
    norm = normalize_text(quote)
    if len(norm) < MIN_QUOTE_CHARS:
        return {"ok": False, "retryable": False,
                "why": f"quote under {MIN_QUOTE_CHARS} chars is insufficient "
                       "evidence; supply a longer verbatim span"}
    rows = conn.execute(
        "SELECT id, content FROM events WHERE source='claude_code' "
        "AND kind='message' AND id > ? "
        "AND json_extract(meta,'$.role')='user' ORDER BY id DESC LIMIT 500",
        (candidate_id,)).fetchall()
    for r in rows:
        if norm in normalize_text(r["content"] or ""):
            return {"ok": True, "user_event": r["id"]}
    return {"ok": False, "retryable": True,
            "why": "no ingested post-candidate operator message contains "
                   "that quote; ingestion lags by up to one scan interval — "
                   "retry shortly, or the operator can run "
                   "'ctx loop confirm' directly"}


# --- checkpoint carriage -----------------------------------------------------

def _loop_line(loop: dict) -> str:
    opened = loop["created_ts"][:10]
    tag = f"[loop#{loop['id']}] opened {opened}"
    if loop["reopen_count"]:
        reopen_ts = next((h["ts"][:10] for h in reversed(loop["history"])
                          if h["op"] == "reopen"), "")
        tag += f", reopened {reopen_ts}"
    line = f"{tag}: {loop['text']}"
    if loop["source_events"]:
        refs = ", ".join(f"ev {i}" for i in loop["source_events"])
        line += f" (from {refs})"   # non-bracketed: content not disclosed
    return line


def select_loop_section(conn, budget: int, repo_path: str | None) -> dict:
    """The dedicated checkpoint stratum. Lifecycle + scope selection only:
    open (incl. reopened) loops for the requested repo, or global-scoped
    when no repo is requested. Oldest-first. If the slice cannot carry all,
    the omission line names every omitted id and the count — silent loss is
    structurally impossible (the reserve is subtracted before packing)."""
    from .gate import est_tokens
    scope = make_scope(repo_path) if repo_path else {"global": True}
    active = loops_for_scope(conn, scope, states=("open",))
    if not active:
        return {"items": [], "ids": [], "omitted": [], "used": 0, "slice": 0}
    slice_budget = max(int(budget * LOOP_SHARE), LOOP_SLICE_MIN)
    lines, ids, used = [], [], 0
    omitted = []
    packing = slice_budget - OMISSION_RESERVE
    for lp in active:
        line = _loop_line(lp)
        cost = est_tokens(line)
        if used + cost > packing:
            omitted.append(lp)
            continue
        lines.append(line)
        ids.append(lp["id"])
        used += cost
    items = [{"id": i, "header": "", "text": line}
             for i, line in zip(ids, lines)]
    if omitted:
        names = ", ".join(f"loop#{lp['id']}" for lp in omitted)
        items.append({"id": None, "header": "",
                      "text": f"BUDGET OMITTED: {len(omitted)} active "
                              f"loop(s): {names} — run 'ctx loop list'"})
    return {"items": items, "ids": ids,
            "omitted": [lp["id"] for lp in omitted],
            "used": used, "slice": slice_budget}
