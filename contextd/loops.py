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

from .assurance import (
    INSECURE_TEST_SIGNER, LEGACY_UNVERIFIED, MODEL_GRANTED, OPERATOR_AUTHORIZED,
    UNVERIFIED, assurance_for_event, assurance_of, refuse_forged_authority,
)


from .db import append_event_checked


def _authority_label(assurance: str, op: str = "") -> str | None:
    """The derived legacy `authority` string written beside the real level.

    It exists so the open-loops benchmark corpus and its scorers — which read
    raw event metadata and which this pass must not rewrite — keep working.
    It is DERIVED from the verified assurance level, never accepted from a
    caller, and `assurance_of()` refuses to promote it: a row carrying
    `authority="operator"` without an attestation resolves `legacy_unverified`.
    Enforcement reads `assurance`; this field is for display and legacy readers.
    """
    if assurance in (OPERATOR_AUTHORIZED, INSECURE_TEST_SIGNER):
        return "operator"
    if assurance == MODEL_GRANTED:
        return "model-granted"
    return "model" if op == "candidate" else None


def _legacy_authority_view(meta: dict, op: str,
                           level: str | None = None) -> str | None:
    """The pre-hardening `authority` vocabulary, derived from real assurance.

    Kept because the open-loops benchmark corpus and its scorers read these
    exact strings, and rewriting recorded benchmark inputs would alter results.
    It is a *view*: enforcement never consults it, `created_assurance` /
    `promoted_assurance` carry the honest level beside it, and a legacy row
    reports whatever string it was written with — which authenticates nothing
    (docs/SECURITY.md §3).
    """
    level = assurance_of(meta) if level is None else level
    if level in (OPERATOR_AUTHORIZED, INSECURE_TEST_SIGNER):
        return "operator"
    if level == MODEL_GRANTED:
        return "model-granted"
    if level == LEGACY_UNVERIFIED:
        return meta.get("authority")
    return "model" if op == "candidate" else meta.get("authority")


def _require_authorization(authorization, action: str, scope, conn=None,
                           **covered):
    """Every operator-authoritative loop act goes through here.

    With no authorization the act is refused — unless the process is in the
    explicitly-marked test-only signing mode on an isolated temporary archive,
    in which case one is minted and the event is stamped INSECURE_TEST_SIGNER.
    In production the test-mode check refuses first, so this is not a fallback.
    """
    from .attest import AttestationError, AttestationError as _AE, test_mode_authorization
    canonical = scope if isinstance(scope, str) else scope_str(scope)
    if authorization is None:
        try:
            return test_mode_authorization(conn, action, canonical, **covered)
        except _AE as exc:
            raise LoopError(
                f"{action} is an operator act and requires a verified "
                f"authorization (contextd/attest.py). There is no string a "
                f"caller can pass to obtain one. ({exc})"
            ) from exc
    if not authorization.matches(action, canonical, **covered):
        raise AttestationError(
            f"the authorization does not cover exactly {action} on {canonical}"
        )
    return authorization

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


def _loop_event_assurance(conn, row, meta: dict, loop: dict | None) -> str:
    """Resolve a loop event only against the act that could have produced it."""
    op = meta.get("op")
    if op == "candidate":
        return assurance_of(meta)

    if meta.get("grant") is not None:
        if loop is None or op not in TRANSITION_OPS:
            return UNVERIFIED
        from .grants import covering_grant_for_event

        grant = covering_grant_for_event(
            conn, row, f"loop.{op}", loop["scope"]
        )
        return MODEL_GRANTED if grant is not None else UNVERIFIED

    body = row["content"] or None
    if op == "add":
        scope = meta.get("scope")
        if not isinstance(scope, dict):
            return UNVERIFIED
        return assurance_for_event(
            conn,
            row,
            action="loop.add",
            scope=scope_str(scope),
            content=body,
        )
    if loop is None or op not in TRANSITION_OPS:
        return assurance_of(meta)

    # Adding wording identical to a candidate records a confirm transition but
    # is authorized as loop.add over the wording, not as loop.confirm over a
    # loop id. Try that exact ceremony first; a fabricated action selector does
    # not help because assurance_for_event cryptographically verifies it.
    if op == "confirm":
        promoted = assurance_for_event(
            conn,
            row,
            action="loop.add",
            scope=scope_str(loop["scope"]),
            content=body,
        )
        if promoted in (OPERATOR_AUTHORIZED, INSECURE_TEST_SIGNER):
            return promoted
    return assurance_for_event(
        conn,
        row,
        action=f"loop.{op}",
        scope=scope_str(loop["scope"]),
        arguments={"loop": int(loop["id"])},
        content=None,
        reason=body,
    )


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
            level = _loop_event_assurance(conn, r, meta, None)
            if op == "add" and level not in (
                OPERATOR_AUTHORIZED,
                INSECURE_TEST_SIGNER,
            ):
                orphans.append({
                    "event": r["id"],
                    "why": "loop add lacks a verified operator authorization",
                })
                continue
            state = "open" if op == "add" else "candidate"
            loops[r["id"]] = {
                "id": r["id"],
                "text": (r["content"] or "").strip(),
                "scope": meta.get("scope") or {"global": True},
                "state": state,
                "created_state": state,
                # resolved, never read raw: a stored `authority` string is a
                # legacy label with no authentication behind it
                "created_assurance": level,
                "created_authority": _legacy_authority_view(meta, op, level),
                # `claimed_client` since the rename; legacy rows carry the
                # old `client` key. Either way it is an unverified self-report
                # (docs/SECURITY.md §3), never a principal.
                "created_client": meta.get("claimed_client",
                                           meta.get("client", "")),
                "created_ts": r["ts"],
                "updated_ts": r["ts"],
                "reopen_count": 0,
                "promoted_assurance": None,
                "promoted_authority": None,
                "last_reason": "",
                "source_events": meta.get("source_events") or [],
                "dedupe": meta.get("dedupe") or dedupe_key(
                    meta.get("scope") or {"global": True}, r["content"] or ""),
                "history": [{"event": r["id"], "op": op, "ts": r["ts"],
                             "assurance": level,
                             "authority": _legacy_authority_view(
                                 meta, op, level
                             )}],
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
        level = _loop_event_assurance(conn, r, meta, loop)
        if level not in (
            OPERATOR_AUTHORIZED,
            INSECURE_TEST_SIGNER,
            MODEL_GRANTED,
        ):
            loop["anomalies"].append({
                "event": r["id"],
                "op": op,
                "ts": r["ts"],
                "assurance": level,
                "authority": _legacy_authority_view(meta, op, level),
                "reason": (r["content"] or "").strip(),
                "why": f"{op} lacks a verified authorization",
            })
            continue
        allowed = {"confirm": ("candidate",), "close": ("open",),
                   "reopen": ("closed",), "dismiss": ("candidate",)}[op]
        entry = {"event": r["id"], "op": op, "ts": r["ts"],
                 "assurance": level,
                 "authority": _legacy_authority_view(meta, op, level),
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
            loop["promoted_assurance"] = level
            loop["promoted_authority"] = _legacy_authority_view(meta, op, level)
        elif op == "close":
            loop["state"] = "closed"
        elif op == "reopen":
            loop["state"] = "open"
            loop["reopen_count"] += 1
        elif op == "dismiss":
            loop["state"] = "dismissed"
    return {"loops": loops, "orphans": orphans}


def stored_loop_assurance(conn, event_id: int) -> str:
    """Return the reducer-verified assurance for one loop event."""
    event_id = int(event_id)
    reduced = reduce_loops(conn)
    for loop in reduced["loops"].values():
        if loop["id"] == event_id:
            return loop["created_assurance"]
        for entry in (*loop["history"], *loop["anomalies"]):
            if entry["event"] == event_id:
                return entry.get("assurance", UNVERIFIED)
    row = conn.execute(
        "SELECT meta FROM events WHERE id = ? AND kind = 'loop'", (event_id,)
    ).fetchone()
    if row is None:
        return UNVERIFIED
    try:
        return assurance_of(json.loads(row["meta"] or "{}"))
    except (TypeError, json.JSONDecodeError):
        return UNVERIFIED


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
             source_events: list | None = None, authorization=None) -> dict:
    """Operator-declared open loop.

    Requires a verified authorization (contextd/attest.py) covering exactly
    ``loop.add`` on this scope with this text. It used to write
    ``authority="operator"`` on the strength of being called, which under the
    current threat model means the attacker declaring itself the operator.

    Idempotent against live duplicates; a matching pending candidate is
    promoted instead (the operator said the thing the model proposed — one
    loop, one authorization).
    """
    authorization = _require_authorization(
        authorization, "loop.add", scope, conn=conn, content=text)
    text = (text or "").strip()
    if not text:
        raise LoopError("empty loop text")
    reduced = reduce_loops(conn)["loops"]
    live = _live_by_key(reduced, scope, text)
    if live is not None:
        if live["state"] == "open":
            return {"result": "existing", "loop": live}
        from .attest import authorized_append
        eid = authorized_append(
            conn, "loop", "loop", authorization, "loop.add",
            scope=scope_str(scope), content=text,
            meta={"op": "confirm", "loop": live["id"],
                  "authority": _authority_label(authorization.assurance),
                  "claimed_client": client},
        )
        live = reduce_loops(conn)["loops"][live["id"]]
        return {"result": "confirmed_candidate", "loop": live, "event": eid}
    meta = {"op": "add", "scope": scope,
            "assurance": authorization.assurance,
            "authority": _authority_label(authorization.assurance),
            "attestation": authorization.stored_block(),
            "claimed_client": client, "dedupe": dedupe_key(scope, text)}
    if source_events:
        meta["source_events"] = sorted(int(i) for i in source_events)

    def _consume(locked_conn, _ts, event_id):
        from .attest import consume_nonce, reverify_for_use

        verified = reverify_for_use(
            locked_conn,
            authorization,
            action="loop.add",
            scope=scope_str(scope),
            content=text,
        )
        consume_nonce(locked_conn, verified, event_id)

    try:
        eid = append_event_checked(conn, "loop", "loop", content=text,
                                   meta=meta, check=_no_live_dup(scope, text),
                                   bind=_consume)
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
            "assurance": UNVERIFIED, "claimed_client": client,
            "dedupe": dedupe_key(scope, text)}
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


def transition(conn, loop_id: int, op: str, authority: str | None = None,
               client: str = "cli", reason: str = "",
               grant: int | None = None, authorization=None) -> dict:
    """One lifecycle transition per the frozen table. No-ops append nothing;
    refusals raise LoopError with the exact rule violated.

    There is deliberately NO model-mediated promotion path. A candidate
    utterance-binding was built and retired before any field use: verifying
    that quoted words occur in a post-candidate operator message proves
    utterance-occurrence, not assent — a rejecting message satisfies it —
    so it laundered arbitrary operator bytes into operator authority. The
    negative result is recorded in docs/OPEN_LOOPS.md; confirmation is a
    human CLI act."""
    # `authority` was a free-form string any caller could set to "operator".
    # It is refused outright now; a lifecycle transition is either operator-
    # authorized (verified signature) or model-granted (verified grant).
    refuse_forged_authority(authority=authority)
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
    meta = {"op": op, "loop": loop_id, "claimed_client": client}
    body = reason.strip() or None
    if grant is None:
        authorization = _require_authorization(
            authorization, f"loop.{op}", loop["scope"], conn=conn,
            arguments={"loop": loop_id}, reason=body)
        meta["assurance"] = authorization.assurance
        meta["authority"] = _authority_label(authorization.assurance)
        meta["attestation"] = authorization.stored_block()
    else:
        meta["assurance"] = MODEL_GRANTED
        meta["authority"] = _authority_label(MODEL_GRANTED)
    if grant is not None:
        # act taken under a delegation: provenance resolves act -> grant ->
        # operator reason (docs/GRANTS.md); never recorded as operator
        meta["grant"] = grant
    if grant is not None:
        # delegated act: the covering grant is re-verified inside the append
        # transaction, not merely at the caller's pre-flight check
        from .grants import granted_append
        meta.pop("grant", None)
        meta.pop("assurance", None)
        meta.pop("authority", None)
        eid = granted_append(
            conn, "loop", "loop", f"loop.{op}", loop["scope"],
            content=body, meta=meta,
        )["event"]
    else:
        def _consume(locked_conn, _ts, event_id):
            from .attest import consume_nonce, reverify_for_use

            verified = reverify_for_use(
                locked_conn,
                authorization,
                action=f"loop.{op}",
                scope=scope_str(loop["scope"]),
                arguments={"loop": loop_id},
                reason=body,
            )
            consume_nonce(locked_conn, verified, event_id)
        eid = append_event_checked(conn, "loop", "loop",
                                   content=body, meta=meta,
                                   bind=_consume)
    return {"result": op, "loop": reduce_loops(conn)["loops"][loop_id],
            "event": eid}


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
