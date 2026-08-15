"""Decision supersession: append-only edges + a loud compile contract.

Contract: docs/DECISIONS.md (frozen before this module was written).
Everything here is deterministic and model-free. An edge is one event
(source `decision`, kind `decision`, meta op=supersede) recording that NEW
supersedes OLD; current state exists only as the reduction of edge events
in id order. Recording an edge is a human CLI act — there is deliberately
no model-mediated path, the same authority boundary open loops settled.

The compile contract lives in handoff.py and uses this module's reduction:
a superseded item is never rendered unmarked, and a carried chain's current
version is carried or loudly named. The mechanism never infers edges from
text, recency, or anything else; that refusal is the authority boundary.
"""

import json

from .assurance import refuse_forged_authority

SUPERSEDE_RESERVE_SHARE = 0.06   # of budget, when any edge exists
SUPERSEDE_RESERVE_MIN = 120      # est. tokens; keeps the loud line affordable


class DecisionError(RuntimeError):
    """Invalid edge or unknown event."""


def _require_authorization(conn, authorization, reason, old, new):
    """Operator authorization covering exactly this edge."""
    from .attest import AttestationError, test_mode_authorization
    arguments = {"old": int(old), "new": int(new)}
    body = reason.strip() or None
    if authorization is None:
        try:
            return test_mode_authorization(
                conn, "decision.supersede", "global", arguments, body, reason)
        except AttestationError as exc:
            raise DecisionError(
                f"recording a supersession is an operator act and requires a "
                f"verified authorization (contextd/attest.py). ({exc})"
            ) from exc
    if not authorization.matches("decision.supersede", "global", arguments,
                                 body, reason):
        raise DecisionError(
            "the authorization does not cover exactly this supersession edge"
        )
    return authorization


def record_supersession(conn, old: int, new: int, reason: str = "",
                        client: str = "cli", authority: str | None = None,
                        grant: int | None = None, authorization=None) -> dict:
    """Recorded edge: NEW supersedes OLD. Operator CLI act by default; the
    model path passes authority='model-granted' with the covering grant id
    (docs/GRANTS.md) — enforcement lives at that path's entry, and the
    provenance is permanently distinguishable. Idempotent against an
    identical live edge (appends nothing); refuses ids that do not name
    content-bearing archive events."""
    refuse_forged_authority(authority=authority)
    old, new = int(old), int(new)
    if old == new:
        raise DecisionError("an event cannot supersede itself")
    for label, eid in (("old", old), ("new", new)):
        row = conn.execute(
            "SELECT kind, content FROM events WHERE id = ?", (eid,)).fetchone()
        if row is None:
            raise DecisionError(f"no event #{eid} ({label})")
        if row["kind"] == "egress" or row["content"] is None:
            raise DecisionError(
                f"event #{eid} ({label}) is {row['kind']} without content; "
                f"an egress or blob can never be a decision version")
    reduced = reduce_supersessions(conn)
    existing = reduced["edges"].get(old)
    if existing and existing["new"] == new:
        return {"result": "existing", "edge": existing}
    meta = {"op": "supersede", "old": old, "new": new,
            "claimed_client": client}
    if grant is not None:
        # delegated act: the covering grant is verified inside the append
        # transaction, so a revoke that commits first is seen
        from .grants import granted_append
        eid = granted_append(
            conn, "decision", "decision", "decision.supersede", None,
            content=reason.strip() or None, meta=meta,
        )["event"]
    else:
        authorization = _require_authorization(conn, authorization, reason,
                                               old, new)
        from .attest import authorized_append
        eid = authorized_append(
            conn, "decision", "decision", authorization, "decision.supersede",
            "global", arguments={"old": old, "new": new},
            content=reason.strip() or None, reason=reason, meta=meta,
        )
    return {"result": "created",
            "edge": reduce_supersessions(conn)["edges"][old], "event": eid}


def reduce_supersessions(conn) -> dict:
    """Rebuild edge state from the append-only record.

    Returns {"edges": {old: {"new", "edge"}}, "anomalies": [...]}. If one
    event accumulates several outgoing edges, the latest edge wins and the
    displaced one is an anomaly; unknown ops under kind='decision' are
    anomalies too (a direct append must never corrupt the reduction)."""
    edges: dict = {}
    anomalies: list = []
    rows = conn.execute(
        "SELECT id, content, meta FROM events WHERE kind='decision' "
        "ORDER BY id").fetchall()
    for r in rows:
        meta = json.loads(r["meta"] or "{}")
        if meta.get("op") != "supersede":
            anomalies.append({"event": r["id"],
                              "why": f"unknown op {meta.get('op')!r}"})
            continue
        old, new = meta.get("old"), meta.get("new")
        if not isinstance(old, int) or not isinstance(new, int) or old == new:
            anomalies.append({"event": r["id"], "why": "malformed edge"})
            continue
        if old in edges:
            anomalies.append({"event": edges[old]["edge"],
                              "why": f"displaced by later edge {r['id']}"})
        edges[old] = {"new": new, "edge": r["id"], "old": old}
    return {"edges": edges, "anomalies": anomalies}


def current_version(edges: dict, event_id: int) -> dict:
    """Follow the chain from event_id to its terminal current version.

    Returns {"current", "chain", "cyclic"}. A cycle stops at the first
    repeated node and reports cyclic=True; the compile contract treats a
    cyclic chain as superseded-with-unresolvable-current (marked, never
    silently served)."""
    seen = [event_id]
    node = event_id
    while node in edges:
        node = edges[node]["new"]
        if node in seen:
            return {"current": None, "chain": seen, "cyclic": True}
        seen.append(node)
    return {"current": node, "chain": seen, "cyclic": False}


def superseded_ids(edges: dict) -> set:
    return set(edges.keys())


def supersession_marker(edges: dict, event_id: int) -> str:
    """The loud marker for a superseded item, per the contract. References
    use the non-bracketed `ev N` form (loops precedent): a bracketed [id]
    asserts disclosed content, and the current version may live outside
    this package's budget."""
    e = edges[event_id]
    walk = current_version(edges, event_id)
    if walk["cyclic"]:
        return (f"SUPERSEDED — edge ev {e['edge']} names ev {e['new']} but "
                f"the chain is cyclic; no resolvable current version")
    return f"SUPERSEDED by ev {walk['current']} (edge ev {e['edge']})"
