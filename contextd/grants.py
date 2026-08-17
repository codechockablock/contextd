"""Delegation grants: recorded, scoped, revocable model authority.

Contract: docs/GRANTS.md (frozen before this module was written).
Everything here is deterministic and model-free. A grant is one append-only
event; current state is the reduction of grant events in id order. Granting
is a human CLI act — grant events without operator authority are anomalies
the reduction ignores, so the model cannot grant to itself (attribution,
not authentication: the ledger's usual trust model).

Acts enabled by a grant are recorded with authority ``model-granted`` and
the grant's event id in their meta — never ``operator``. Nothing a grant
enables is indistinguishable from a human act.
"""

import json
from datetime import datetime, timedelta, timezone

from .db import append_event, now_iso
from .loops import scope_str

# closed registry: class -> allowed scope kinds (docs/GRANTS.md)
CLASSES = {
    "loop.confirm": ("repo", "global"),
    "loop.dismiss": ("repo", "global"),
    "decision.supersede": ("global",),
}

GRANTED_AUTHORITY = "model-granted"


class GrantError(RuntimeError):
    """Unknown class, bad scope, unknown grant, or refused act."""


def _scope_kind(scope: dict) -> str:
    return "global" if scope.get("global") else "repo"


def parse_duration(text: str) -> timedelta:
    """'90m' / '8h' / '3d' — the only supported forms."""
    units = {"m": "minutes", "h": "hours", "d": "days"}
    if len(text) >= 2 and text[-1] in units and text[:-1].isdigit():
        return timedelta(**{units[text[-1]]: int(text[:-1])})
    raise GrantError(f"cannot parse duration {text!r} (use e.g. 90m, 8h, 3d)")


def _instant(text) -> datetime | None:
    """ISO timestamp -> aware UTC datetime, or None if it cannot be read.

    A naive timestamp is read as UTC, matching now_iso()'s own form. That is
    the fail-closed reading: for an operator west of UTC it retires the grant
    earlier than a local-time reading would, never later.
    """
    try:
        dt = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize_expiry(text: str) -> str:
    """Canonical UTC form, so a stored expiry sorts the way it compares and
    every display of it agrees. Granting is the one place that can still
    reject a bad timestamp loudly; after this the value is trusted bytes."""
    dt = _instant(text)
    if dt is None:
        raise GrantError(f"cannot parse expiry {text!r} (use an ISO 8601 "
                         f"timestamp, e.g. 2026-08-16T23:00:00+00:00)")
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def add_grant(conn, cls: str, scope: dict, expires: str | None = None,
              reason: str = "", client: str = "cli") -> dict:
    """Operator-recorded delegation. Idempotent against an identical active
    grant (appends nothing)."""
    if cls not in CLASSES:
        raise GrantError(f"unknown authority class {cls!r} "
                         f"(registry: {', '.join(sorted(CLASSES))})")
    if _scope_kind(scope) not in CLASSES[cls]:
        raise GrantError(f"{cls} does not accept {_scope_kind(scope)} scope "
                         f"(allowed: {', '.join(CLASSES[cls])})")
    if expires is not None:
        expires = normalize_expiry(expires)  # validate now, fail loudly
    for g in active_grants(conn):
        if (g["class"] == cls and scope_str(g["scope"]) == scope_str(scope)
                and _same_expiry(g["expires"], expires)):
            return {"result": "existing", "grant": g}
    meta = {"op": "grant", "class": cls, "scope": scope,
            "authority": "operator", "client": client}
    if expires:
        meta["expires"] = expires
    eid = append_event(conn, "grant", "grant",
                       content=reason.strip() or None, meta=meta)
    return {"result": "created",
            "grant": next(g for g in reduce_grants(conn)["grants"]
                          if g["id"] == eid)}


def revoke_grant(conn, grant_id: int, reason: str = "",
                 client: str = "cli") -> dict:
    reduced = reduce_grants(conn)
    grant = next((g for g in reduced["grants"] if g["id"] == grant_id), None)
    if grant is None:
        raise GrantError(f"no grant ev {grant_id}")
    if grant["revoked_by"] is not None:
        return {"result": "already_revoked", "grant": grant}
    eid = append_event(conn, "grant", "grant",
                       content=reason.strip() or None,
                       meta={"op": "revoke", "grant": grant_id,
                             "authority": "operator", "client": client})
    grant = next(g for g in reduce_grants(conn)["grants"]
                 if g["id"] == grant_id)
    return {"result": "revoked", "grant": grant, "event": eid}


def reduce_grants(conn) -> dict:
    """{"grants": [...], "anomalies": [...]}, id order. A grant event
    without operator authority, an unknown op/class, or a revoke of an
    unknown grant is an anomaly — a direct append never corrupts the
    reduction, it just gets named."""
    grants: dict[int, dict] = {}
    anomalies: list = []
    rows = conn.execute(
        "SELECT id, ts, content, meta FROM events WHERE kind='grant' "
        "ORDER BY id").fetchall()
    for r in rows:
        meta = json.loads(r["meta"] or "{}")
        op = meta.get("op")
        if meta.get("authority") != "operator":
            anomalies.append({"event": r["id"],
                              "why": "grant event without operator "
                                     "authority — the model cannot grant "
                                     "to itself"})
            continue
        if op == "grant":
            if meta.get("class") not in CLASSES:
                anomalies.append({"event": r["id"],
                                  "why": f"unknown class "
                                         f"{meta.get('class')!r}"})
                continue
            grants[r["id"]] = {
                "id": r["id"], "class": meta["class"],
                "scope": meta.get("scope") or {"global": True},
                "expires": meta.get("expires"), "granted_ts": r["ts"],
                "reason": (r["content"] or "").strip(),
                "client": meta.get("client", ""),
                "revoked_by": None, "revoke_reason": ""}
        elif op == "revoke":
            target = grants.get(meta.get("grant"))
            if target is None:
                anomalies.append({"event": r["id"],
                                  "why": f"revoke targets unknown grant "
                                         f"{meta.get('grant')!r}"})
                continue
            if target["revoked_by"] is None:
                target["revoked_by"] = r["id"]
                target["revoke_reason"] = (r["content"] or "").strip()
        else:
            anomalies.append({"event": r["id"], "why": f"unknown op {op!r}"})
    return {"grants": list(grants.values()), "anomalies": anomalies}


def _same_expiry(a: str | None, b: str | None) -> bool:
    """Two stored expiries naming the same moment, however each was written."""
    if a is None or b is None:
        return a is b
    ia, ib = _instant(a), _instant(b)
    return ia == ib if (ia and ib) else a == b


def is_expired(grant: dict, now: str | None = None) -> bool:
    """Expiry compares *instants*, never ISO strings.

    A lexical compare is not a temporal one once offsets differ: the string
    '2026-08-16T23:00:00+05:00' sorts after a UTC now it actually precedes by
    two hours, so a dead grant kept reading as live and the model went on
    acting under it. An expiry that cannot be read at all counts as expired —
    the one gate bounding delegated authority fails closed.
    """
    if not grant["expires"]:
        return False
    expires, current = _instant(grant["expires"]), _instant(now or now_iso())
    if expires is None or current is None:
        return True
    return expires <= current


def active_grants(conn, now: str | None = None) -> list[dict]:
    now = now or now_iso()
    return [g for g in reduce_grants(conn)["grants"]
            if g["revoked_by"] is None and not is_expired(g, now)]


def _covers(grant: dict, scope: dict | None) -> bool:
    if grant["scope"].get("global"):
        return True
    return scope is not None and scope_str(grant["scope"]) == scope_str(scope)


def active_grant_for(conn, cls: str, scope: dict | None = None,
                     now: str | None = None) -> dict | None:
    """The covering active grant for an act, or None. A global grant covers
    every target in its class; a repo grant covers only that repo's."""
    for g in active_grants(conn, now):
        if g["class"] == cls and _covers(g, scope):
            return g
    return None


def require_grant(conn, cls: str, scope: dict | None = None,
                  now: str | None = None) -> dict:
    """The model-path gate: the covering grant, or a refusal that names
    exactly the operator act that would authorize this."""
    g = active_grant_for(conn, cls, scope, now)
    if g is None:
        where = ("--global" if scope is None or scope.get("global")
                 else f"--repo {scope['repo']}")
        raise GrantError(
            f"REFUSED: no active grant for {cls}. This is an operator "
            f"decision — to delegate it: ctx grant add {cls} {where}")
    return g


def grant_line(grant: dict) -> str:
    """The standing-delegations line, per the loudness contract."""
    tail = f", expires {grant['expires']}" if grant["expires"] else ""
    return (f"model holds {grant['class']} for {scope_str(grant['scope'])} "
            f"(grant ev {grant['id']}{tail}) — revoke: "
            f"ctx grant revoke {grant['id']}")
