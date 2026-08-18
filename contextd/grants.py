"""Delegation grants: recorded, scoped, expiring, revocable model authority.

Contract: docs/GRANTS.md. Everything here is deterministic and model-free. A
grant is one append-only event; current state is the reduction of grant events
in id order.

Three defects the hardening pass fixed, each exploitable by the attacker in
docs/SECURITY.md §1:

1. **Granting was authorized by a string.** ``meta.authority == "operator"``
   was written by whoever called ``add_grant``, so the model could grant to
   itself. Granting and revoking now require a verified ``OperatorActionV1``.

2. **Verification and use were not atomic.** ``require_grant`` reduced the
   grant state, returned, and the caller then appended — a separate
   transaction. In between, the grant could expire or be revoked, and two
   concurrent uses could both see a live grant. Verification now runs *inside*
   the append transaction against the same locked connection, so the delegated
   event and its authorization check commit or fail together.

3. **Expiry was a string comparison, and optional.** ``expires <= now`` over
   ISO strings compares timezone offsets lexically, so ordering depended on
   formatting rather than on time. Expiry is now a timezone-aware UTC instant
   evaluated at the append timestamp, and a grant without one is refused: a
   permanent delegation is not a delegation.

A delegated act stays delegated. It records the covering grant's id and digest
and assurance ``model_granted`` — it never becomes operator-signed.
"""

import json
from datetime import datetime, timedelta, timezone

from .assurance import (
    MODEL_GRANTED,
    assurance_for_event,
    refuse_forged_authority,
)
from .attest import AttestationError, authorized_append, test_mode_authorization
from .canonical import canonical_digest
from .db import append_event_checked, now_iso

# closed registry: class -> allowed scope kinds (docs/GRANTS.md)
CLASSES = {
    "loop.confirm": ("repo", "global"),
    "loop.dismiss": ("repo", "global"),
    "decision.supersede": ("global",),
}

GRANTED_AUTHORITY = "model-granted"


def scope_str(scope: dict) -> str:
    """Render a scope dict as the exact string a grant is recorded under.

    This lives here, beside the closed class registry that constrains which
    scope kinds each class accepts, because its output is not a display
    string: it is what `canonical` covers in a signed grant act and what
    `covering_grant` compares. `contextd/loops.py` re-exports it for the
    daemon-side callers that have always imported it from there.
    """
    if scope.get("global"):
        return "global"
    return f"repo:{scope['repo']}"


#: A grant may never delegate the power to grant. Without this, one delegation
#: bootstraps unbounded authority.
META_CLASSES = frozenset({
    "grant.add", "grant.revoke", "security.policy",
    "security.key_register", "security.key_revoke",
})

MAX_GRANT_DURATION = timedelta(days=90)

OPERATOR_LEVELS = ("operator_authorized", "INSECURE_TEST_SIGNER")


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


def _utc_instant(value: str, field: str = "expires") -> datetime:
    """Parse a timezone-aware instant, normalized to UTC.

    A naive timestamp is refused rather than assumed local or assumed UTC:
    both assumptions are wrong somewhere, and an expiry that means different
    instants on different machines is not an expiry.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise GrantError(f"{field} is not a valid ISO-8601 instant: {exc}") from exc
    if parsed.tzinfo is None:
        raise GrantError(
            f"{field}={value!r} is a naive timestamp. A timezone-aware UTC "
            f"instant is required so one grant expires at one moment "
            f"everywhere."
        )
    return parsed.astimezone(timezone.utc)


def grant_digest(grant: dict) -> str:
    """A stable digest of exactly what a grant permits.

    Recorded on every delegated act, so the act names not just the grant's id
    but the terms in force when it was used.
    """
    return canonical_digest("contextd.GrantV1", {
        "id": int(grant["id"]),
        "class": str(grant["class"]),
        "scope": scope_str(grant["scope"]),
        "expires": str(grant["expires"]),
    })


def _authorize(conn, authorization, action: str, scope: str, **covered):
    """Operator authorization for a change to the grant registry itself."""
    if authorization is None:
        try:
            return test_mode_authorization(conn, action, scope, **covered)
        except AttestationError as exc:
            raise GrantError(
                f"{action} is an operator act and requires a verified "
                f"authorization (contextd/attest.py). The model cannot grant "
                f"to itself. ({exc})"
            ) from exc
    if not authorization.matches(action, scope, **covered):
        raise GrantError(
            f"the authorization does not cover exactly {action} on {scope}"
        )
    return authorization


def add_grant(conn, cls: str, scope: dict, expires: str | None = None,
              reason: str = "", client: str = "cli", authorization=None) -> dict:
    """Operator-recorded delegation, requiring a verified operator authorization.

    Idempotent against an identical active grant (appends nothing).
    """
    if cls in META_CLASSES:
        raise GrantError(
            f"{cls} cannot be delegated: a grant conferring the power to grant "
            f"bootstraps unbounded authority"
        )
    if cls not in CLASSES:
        raise GrantError(f"unknown authority class {cls!r} "
                         f"(registry: {', '.join(sorted(CLASSES))})")
    if _scope_kind(scope) not in CLASSES[cls]:
        raise GrantError(f"{cls} does not accept {_scope_kind(scope)} scope "
                         f"(allowed: {', '.join(CLASSES[cls])})")
    if str(scope.get("repo", "")).strip() in ("*", "**", "/"):
        raise GrantError("wildcard repo scopes are refused; name the repository")
    if not expires:
        raise GrantError(
            "a grant requires a finite expiry. A permanent delegation is not a "
            "delegation — use e.g. --for 8h."
        )
    instant = _utc_instant(expires)
    now = datetime.now(timezone.utc)
    if instant <= now:
        raise GrantError(f"expiry {instant.isoformat()} is already past")
    if instant - now > MAX_GRANT_DURATION:
        raise GrantError(
            f"expiry exceeds the {MAX_GRANT_DURATION.days}-day maximum; "
            f"re-granting is an operator act and silent renewal is not one"
        )
    normalized = instant.isoformat(timespec="seconds")

    for g in active_grants(conn):
        if (g["class"] == cls and scope_str(g["scope"]) == scope_str(scope)
                and g["expires"] == normalized):
            return {"result": "existing", "grant": g}

    canonical = scope_str(scope)
    arguments = {"class": cls, "expires": normalized}
    # the authorization must cover the exact bytes that will be written, so it
    # is prepared with the same content the append passes
    body = reason.strip() or None
    authorization = _authorize(conn, authorization, "grant.add", canonical,
                               arguments=arguments, content=body, reason=body)
    eid = authorized_append(
        conn, "grant", "grant", authorization, "grant.add", canonical,
        arguments=arguments, content=body, reason=body,
        meta={"op": "grant", "class": cls, "scope": scope,
              "expires": normalized, "claimed_client": client},
    )
    return {"result": "created",
            "grant": next(g for g in reduce_grants(conn)["grants"]
                          if g["id"] == eid)}


def revoke_grant(conn, grant_id: int, reason: str = "",
                 client: str = "cli", authorization=None) -> dict:
    reduced = reduce_grants(conn)
    grant = next((g for g in reduced["grants"] if g["id"] == grant_id), None)
    if grant is None:
        raise GrantError(f"no grant ev {grant_id}")
    if grant["revoked_by"] is not None:
        return {"result": "already_revoked", "grant": grant}
    canonical = scope_str(grant["scope"])
    arguments = {"grant": int(grant_id)}
    body = reason.strip() or None
    authorization = _authorize(conn, authorization, "grant.revoke", canonical,
                               arguments=arguments, content=body, reason=body)
    eid = authorized_append(
        conn, "grant", "grant", authorization, "grant.revoke", canonical,
        arguments=arguments, content=body, reason=body,
        meta={"op": "revoke", "grant": grant_id, "claimed_client": client},
    )
    grant = next(g for g in reduce_grants(conn)["grants"]
                 if g["id"] == grant_id)
    return {"result": "revoked", "grant": grant, "event": eid}


def reduce_grants(conn, up_to_event: int | None = None) -> dict:
    """{"grants": [...], "anomalies": [...]}, id order.

    A grant event whose assurance is not operator-authorized, an unknown
    op/class, a missing or naive expiry, or a revoke of an unknown grant is an
    anomaly — a direct append never corrupts the reduction, it just gets named
    and ignored.
    """
    grants: dict[int, dict] = {}
    anomalies: list = []
    query = "SELECT id, ts, content, meta FROM events WHERE kind='grant'"
    parameters: tuple = ()
    if up_to_event is not None:
        query += " AND id <= ?"
        parameters = (int(up_to_event),)
    rows = conn.execute(query + " ORDER BY id", parameters).fetchall()
    for r in rows:
        meta = json.loads(r["meta"] or "{}")
        op = meta.get("op")
        if not isinstance(meta.get("attestation"), dict):
            anomalies.append({
                "event": r["id"],
                "why": "grant event lacks a verified operator authorization; "
                "the model cannot grant to itself",
            })
            continue
        if op == "grant":
            if meta.get("class") not in CLASSES:
                anomalies.append({"event": r["id"],
                                  "why": "unknown grant class"})
                continue
            expires = meta.get("expires")
            if not expires:
                anomalies.append({"event": r["id"],
                                  "why": "grant without a finite expiry"})
                continue
            scope = meta.get("scope")
            if not isinstance(scope, dict) or _scope_kind(scope) not in \
                    CLASSES[meta["class"]]:
                anomalies.append({"event": r["id"],
                                  "why": "grant has an invalid scope"})
                continue
            try:
                expiry = _utc_instant(expires)
                granted_at = _utc_instant(r["ts"], "event timestamp")
            except GrantError as exc:
                anomalies.append({"event": r["id"], "why": str(exc)})
                continue
            if expiry <= granted_at or expiry - granted_at > MAX_GRANT_DURATION:
                anomalies.append({
                    "event": r["id"],
                    "why": "grant expiry is outside the bounded delegation window",
                })
                continue
            body = r["content"] or None
            level = assurance_for_event(
                conn,
                r,
                action="grant.add",
                scope=scope_str(scope),
                arguments={"class": meta["class"], "expires": expires},
                content=body,
                reason=body,
            )
            if level not in OPERATOR_LEVELS:
                anomalies.append({
                    "event": r["id"],
                    "why": "grant event lacks a verified operator authorization; "
                    "the model cannot grant to itself",
                })
                continue
            grants[r["id"]] = {
                "id": r["id"], "class": meta["class"],
                "scope": scope,
                "expires": expires, "granted_ts": r["ts"],
                "reason": (r["content"] or "").strip(),
                "client": meta.get("claimed_client", meta.get("client", "")),
                "assurance": level,
                "revoked_by": None, "revoke_reason": ""}
        elif op == "revoke":
            target = grants.get(meta.get("grant"))
            if target is None:
                anomalies.append({"event": r["id"],
                                  "why": f"revoke targets unknown grant "
                                         f"{meta.get('grant')!r}"})
                continue
            body = r["content"] or None
            level = assurance_for_event(
                conn,
                r,
                action="grant.revoke",
                scope=scope_str(target["scope"]),
                arguments={"grant": int(target["id"])},
                content=body,
                reason=body,
            )
            if level not in OPERATOR_LEVELS:
                anomalies.append({
                    "event": r["id"],
                    "why": "revoke event lacks a verified operator authorization",
                })
                continue
            if target["revoked_by"] is None:
                target["revoked_by"] = r["id"]
                target["revoke_reason"] = (r["content"] or "").strip()
        else:
            anomalies.append({"event": r["id"], "why": "unknown grant operation"})
    return {"grants": list(grants.values()), "anomalies": anomalies}


def _expired(grant: dict, now: str) -> bool:
    """Expiry as an instant comparison, never a string comparison.

    ``"2026-01-01T00:00:00+02:00" <= "2026-01-01T00:00:00+00:00"`` is True
    lexically and False in time. Both sides are parsed to UTC first, so two
    equivalent offsets decide identically.
    """
    if not grant["expires"]:
        return True                      # no expiry -> never usable
    return _utc_instant(grant["expires"]) <= _utc_instant(now, "now")


def active_grants(conn, now: str | None = None) -> list[dict]:
    now = now or now_iso()
    return [g for g in reduce_grants(conn)["grants"]
            if g["revoked_by"] is None and not _expired(g, now)]


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


def covering_grant_for_event(conn, event_row, cls: str,
                             scope: dict | None) -> dict | None:
    """Verify the exact delegation that covered a historical event.

    Reduction is bounded immediately before the event, so a later revoke does
    not retroactively erase an act that was valid when appended.  Conversely,
    a grant created later can never authorize an earlier forged row.
    """
    try:
        meta = json.loads(event_row["meta"] or "{}")
        grant_id = meta.get("grant")
        recorded_digest = meta.get("grant_digest")
        if isinstance(grant_id, bool) or not isinstance(grant_id, int):
            return None
        grants = reduce_grants(conn, up_to_event=int(event_row["id"]) - 1)[
            "grants"
        ]
        grant = next((item for item in grants if item["id"] == grant_id), None)
        if (
            grant is None
            or grant["revoked_by"] is not None
            or grant["class"] != cls
            or not _covers(grant, scope)
            or _expired(grant, event_row["ts"])
            or recorded_digest != grant_digest(grant)
        ):
            return None
        return grant
    except (GrantError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def require_grant(conn, cls: str, scope: dict | None = None,
                  now: str | None = None) -> dict:
    """Pre-flight check: the covering grant, or a refusal naming exactly the
    operator act that would authorize this.

    This is **not** the security boundary — it exists to fail fast with a good
    message. :func:`granted_append` re-runs the same check inside the append
    transaction, because anything checked outside the lock can change before
    the write lands.
    """
    g = active_grant_for(conn, cls, scope, now)
    if g is None:
        where = ("--global" if scope is None or scope.get("global")
                 else f"--repo {scope['repo']}")
        raise GrantError(
            f"REFUSED: no active grant for {cls}. This is an operator "
            f"decision — to delegate it: ctx grant add {cls} {where}")
    return g


def granted_append(conn, source: str, kind: str, cls: str, scope: dict | None,
                   content: str | None = None, meta: dict | None = None) -> dict:
    """Append a delegated act, verifying the grant inside the same transaction.

    The check runs against the locked connection at the append timestamp, so:

    * a grant that expired between a caller's pre-flight check and the write
      refuses, instead of authorizing an act after its own expiry;
    * a revocation that commits first is seen, so no act appends after it;
    * concurrent uses serialize on the same lock the hash chain uses.

    Returns ``{"event": id, "grant": grant}``.
    """
    refuse_forged_authority(**{k: v for k, v in (meta or {}).items()
                               if k in ("authority", "actor")})
    holder: dict = {}
    payload = {**(meta or {}), "assurance": MODEL_GRANTED,
               "authority": GRANTED_AUTHORITY}

    def resolve(locked_conn, event_ts):
        """Runs under the chain lock, at the append timestamp, before hashing."""
        grant = active_grant_for(locked_conn, cls, scope, now=event_ts)
        if grant is None:
            raise GrantError(
                f"REFUSED: no active grant for {cls} at {event_ts}. This is an "
                f"operator decision — to delegate it: ctx grant add {cls}"
            )
        holder["grant"] = grant
        # the grant id and digest are part of the row this append writes, so
        # the act names the exact terms that authorized it
        return {"grant": grant["id"], "grant_digest": grant_digest(grant)}

    eid = append_event_checked(
        conn, source, kind, content=content, meta=payload, prepare=resolve,
    )
    return {"event": eid, "grant": holder["grant"]}


def grant_line(grant: dict) -> str:
    """The standing-delegations line, per the loudness contract."""
    tail = f", expires {grant['expires']}" if grant["expires"] else ""
    return (f"model holds {grant['class']} for {scope_str(grant['scope'])} "
            f"(grant ev {grant['id']}{tail}) — revoke: "
            f"ctx grant revoke {grant['id']}")
