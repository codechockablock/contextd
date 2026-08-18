"""Client-plane access to the archive.

Every client — CLI, MCP server, hook — goes through here instead of calling
``db.connect()`` itself. What that buys:

* **In hardened mode** the call becomes an RPC to the authority plane, which is
  the only process that opens the database. If no service is listening, or the
  trust material is missing, the call **fails closed**: there is no
  direct-SQLite fallback, because a fallback is exactly the thing an attacker
  arranges by killing the daemon.
* **In development mode** it calls the kernel in-process, as before, and says
  so. The point is that the client code is identical in both, so the hardened
  path is the one that is actually exercised rather than a branch nobody runs.

The distinction is never inferred from whether a connection happened to
succeed. It is read from configuration and reported by `ctx security doctor`.
"""

from . import load_config
from .authd import hardened, socket_path
from .rpc import RpcClient, RpcError, ServiceUnavailable

# Assurance resolvers register at import time (contextd/assurance.py). Importing
# them here, at module scope, is what guarantees a daemon process never reads a
# loop or decision event through a half-populated registry: every daemon process
# starts at one of the four entry points that carry this import.
from . import decisions, loops  # noqa: F401

__all__ = [
    "ClientRefused", "RpcError", "ServiceUnavailable",
    "backup", "grant_add", "grant_revoke", "hardened", "key_register",
    "key_revoke", "loop_candidate", "loop_confirm", "loop_dismiss",
    "loop_list", "loop_add_operator", "loop_transition_operator", "note",
    "note_deliberate", "operator_keys", "decision_supersede_operator",
    "prepare_action", "raw_read", "recall", "restore", "search", "status",
    "timeline",
]


class ClientRefused(RuntimeError):
    """The client plane cannot satisfy this call without the authority plane."""


def _client() -> RpcClient:
    return RpcClient(socket_path())


def _call(op: str, **args):
    with _client() as client:
        return client.call(op, **args)


def _direct(fn, *a, **kw):
    """Run a kernel function in-process. Development mode only."""
    if hardened():
        raise ClientRefused(
            f"hardened mode: {fn.__name__} must go through the authority "
            f"service, not an in-process call. This is a bug in the caller."
        )
    from .db import connect
    conn = connect()
    try:
        return fn(conn, *a, **kw)
    finally:
        conn.close()


# --- model-tier operations --------------------------------------------------

def recall(query: str, budget: int = 8000, purpose: str = "", since: str = "",
           until: str = "", client: str = "cli") -> dict:
    if hardened():
        return _call("recall", query=query, budget=budget, purpose=purpose,
                     since=since, until=until, client=client)
    from .gate import assemble
    return _direct(lambda conn: assemble(conn, load_config(), query, budget,
                                         purpose, since, until, client=client))


def search(query: str, limit: int = 10, client: str = "cli") -> dict:
    if hardened():
        return _call("search", query=query, limit=limit, client=client)
    from .authd import AuthorityService, op_search, service_context
    with service_context():
        return op_search(AuthorityService.__new__(AuthorityService), None,
                         "model", {"query": query, "limit": limit,
                                   "client": client})


def timeline(since: str = "", until: str = "", source: str = "",
             limit: int = 30, client: str = "cli") -> dict:
    if hardened():
        return _call("timeline", since=since, until=until, source=source,
                     limit=limit, client=client)
    from .authd import AuthorityService, op_timeline, service_context
    with service_context():
        return op_timeline(AuthorityService.__new__(AuthorityService), None,
                           "model", {"since": since, "until": until,
                                     "source": source, "limit": limit,
                                     "client": client})


def note(text: str, client: str = "cli") -> dict:
    if hardened():
        return _call("note", text=text, client=client)
    from .ingest import ingest_note
    return {"event": _direct(lambda conn: ingest_note(conn, text,
                                                      claimed_client=client))}


def loop_candidate(text: str, scope_repo: str = "") -> dict:
    if hardened():
        return _call("loop_candidate", text=text, scope_repo=scope_repo)
    from .authd import AuthorityService, op_loop_candidate, service_context
    with service_context():
        return op_loop_candidate(AuthorityService.__new__(AuthorityService),
                                 None, "model",
                                 {"text": text, "scope_repo": scope_repo})


def loop_list(scope_repo: str = "", include_candidates: bool = True) -> dict:
    if hardened():
        return _call("loop_list", scope_repo=scope_repo,
                     include_candidates=include_candidates)
    from .authd import AuthorityService, op_loop_list, service_context
    with service_context():
        return op_loop_list(AuthorityService.__new__(AuthorityService), None,
                            "model", {"scope_repo": scope_repo,
                                      "include_candidates": include_candidates})


def loop_confirm(loop_id: int, reason: str = "") -> dict:
    if hardened():
        return _call("loop_confirm", loop_id=loop_id, reason=reason)
    from .authd import AuthorityService, op_loop_confirm, service_context
    with service_context():
        return op_loop_confirm(AuthorityService.__new__(AuthorityService),
                               None, "model",
                               {"loop_id": loop_id, "reason": reason})


def loop_dismiss(loop_id: int, reason: str = "") -> dict:
    if hardened():
        return _call("loop_dismiss", loop_id=loop_id, reason=reason)
    from .authd import AuthorityService, op_loop_dismiss, service_context
    with service_context():
        return op_loop_dismiss(AuthorityService.__new__(AuthorityService),
                               None, "model",
                               {"loop_id": loop_id, "reason": reason})


def status() -> dict:
    if hardened():
        return _call("status")
    from .authd import AuthorityService, op_status, service_context
    with service_context():
        return op_status(AuthorityService.__new__(AuthorityService), None,
                         "model", {})


# --- operator-tier operations -----------------------------------------------

def _authorization_blob(authorization) -> dict:
    return {
        "action": dict(authorization.action),
        "signature": authorization.signature.hex(),
    }


def prepare_action(action: str, scope: str = "global",
                   arguments: dict | None = None,
                   content: str | None = None, reason: str | None = None,
                   ttl_seconds: int = 300, key_id: str = "") -> dict:
    if hardened():
        return _call(
            "prepare_action", action=action, scope=scope,
            arguments=arguments or {}, content=content or "",
            reason=reason or "", ttl_seconds=ttl_seconds, key_id=key_id,
        )
    from .attest import prepare_action as direct_prepare, registered_keys
    from .db import connect
    conn = connect()
    try:
        keys = [key for key in registered_keys(conn) if not key["revoked"]]
        selected = next((key for key in keys if key["key_id"] == key_id), None) \
            if key_id else (keys[-1] if keys else None)
        if selected is None:
            raise ClientRefused("no active operator key matches this challenge")
        prepared = direct_prepare(
            selected["key_id"], action, scope=scope, arguments=arguments,
            content=content, reason=reason, ttl_seconds=ttl_seconds, conn=conn,
        )
        return {**prepared, "signer": selected["signer"],
                "signer_tag": selected["signer_tag"]}
    finally:
        conn.close()


def operator_keys() -> list[dict]:
    if hardened():
        return _call("operator_keys")["keys"]
    from .attest import registered_keys
    return _direct(registered_keys)


def note_deliberate(text: str, authorization) -> dict:
    blob = _authorization_blob(authorization)
    if hardened():
        return _call("note_deliberate", text=text, authorization=blob)
    from .authd import AuthorityService, op_note_deliberate, service_context
    with service_context():
        return op_note_deliberate(
            AuthorityService.__new__(AuthorityService), None, "operator",
            {"text": text, "authorization": blob},
        )

def raw_read(event_id: int, authorization) -> dict:
    """Unredacted event content. Always requires an attestation, in both modes.

    This is the read that bypasses the gate, so it is the one that must never
    become reachable by being on the right machine.
    """
    blob = _authorization_blob(authorization)
    if hardened():
        return _call("raw_read", event_id=event_id, authorization=blob)
    from .authd import AuthorityService, op_raw_read, service_context
    with service_context():
        return op_raw_read(AuthorityService.__new__(AuthorityService), None,
                           "operator", {"event_id": event_id,
                                        "authorization": blob})


def backup(destination: str, authorization, keep: int = 0) -> dict:
    blob = _authorization_blob(authorization)
    if hardened():
        return _call("backup", destination=destination, keep=keep,
                     authorization=blob)
    from .authd import AuthorityService, op_backup, service_context
    with service_context():
        return op_backup(AuthorityService.__new__(AuthorityService), None,
                         "operator", {"destination": destination, "keep": keep,
                                      "authorization": blob})


def export(destination: str, authorization) -> dict:
    blob = _authorization_blob(authorization)
    if hardened():
        return _call("export", destination=destination, authorization=blob)
    from .authd import AuthorityService, op_export, service_context
    with service_context():
        return op_export(AuthorityService.__new__(AuthorityService), None,
                         "operator",
                         {"destination": destination, "authorization": blob})


def restore(bundle: str, destination: str, authorization) -> dict:
    blob = _authorization_blob(authorization)
    if hardened():
        return _call("restore", bundle=bundle, destination=destination,
                     authorization=blob)
    from .authd import AuthorityService, op_restore, service_context
    with service_context():
        return op_restore(
            AuthorityService.__new__(AuthorityService), None, "operator",
            {"bundle": bundle, "destination": destination,
             "authorization": blob},
        )


def grant_add(cls: str, scope_repo: str, expires: str, reason: str,
              authorization) -> dict:
    payload = {
        "class": cls, "scope_repo": scope_repo, "expires": expires,
        "reason": reason, "authorization": _authorization_blob(authorization),
    }
    if hardened():
        return _call("grant_add", **payload)
    from .authd import AuthorityService, op_grant_add, service_context
    with service_context():
        return op_grant_add(
            AuthorityService.__new__(AuthorityService), None, "operator", payload
        )


def grant_revoke(grant_id: int, reason: str, authorization) -> dict:
    payload = {
        "grant_id": grant_id, "reason": reason,
        "authorization": _authorization_blob(authorization),
    }
    if hardened():
        return _call("grant_revoke", **payload)
    from .authd import AuthorityService, op_grant_revoke, service_context
    with service_context():
        return op_grant_revoke(
            AuthorityService.__new__(AuthorityService), None, "operator", payload
        )


def key_register(public_der: bytes, signer_tag: str, authorization) -> dict:
    payload = {
        "public_der": public_der.hex(), "signer_tag": signer_tag,
        "authorization": _authorization_blob(authorization),
    }
    if hardened():
        return _call("key_register", **payload)
    from .authd import AuthorityService, op_key_register, service_context
    with service_context():
        return op_key_register(
            AuthorityService.__new__(AuthorityService), None, "operator", payload
        )


def key_revoke(key_id: str, authorization) -> dict:
    payload = {
        "key_id": key_id,
        "authorization": _authorization_blob(authorization),
    }
    if hardened():
        return _call("key_revoke", **payload)
    from .authd import AuthorityService, op_key_revoke, service_context
    with service_context():
        return op_key_revoke(
            AuthorityService.__new__(AuthorityService), None, "operator", payload
        )


def loop_add_operator(text: str, scope_repo: str, authorization,
                      source_events: list[int] | None = None) -> dict:
    payload = {
        "text": text, "scope_repo": scope_repo,
        "source_events": source_events or [],
        "authorization": _authorization_blob(authorization),
    }
    if hardened():
        return _call("loop_add_operator", **payload)
    from .authd import AuthorityService, op_loop_add_operator, service_context
    with service_context():
        return op_loop_add_operator(
            AuthorityService.__new__(AuthorityService), None, "operator", payload
        )


def loop_transition_operator(loop_id: int, transition: str, reason: str,
                             authorization) -> dict:
    payload = {
        "loop_id": loop_id, "transition": transition, "reason": reason,
        "authorization": _authorization_blob(authorization),
    }
    if hardened():
        return _call("loop_transition_operator", **payload)
    from .authd import (AuthorityService, op_loop_transition_operator,
                        service_context)
    with service_context():
        return op_loop_transition_operator(
            AuthorityService.__new__(AuthorityService), None, "operator", payload
        )


def decision_supersede_operator(old: int, new: int, reason: str,
                                authorization) -> dict:
    payload = {
        "old": old, "new": new, "reason": reason,
        "authorization": _authorization_blob(authorization),
    }
    if hardened():
        return _call("decision_supersede_operator", **payload)
    from .authd import (AuthorityService, op_decision_supersede_operator,
                        service_context)
    with service_context():
        return op_decision_supersede_operator(
            AuthorityService.__new__(AuthorityService), None, "operator", payload
        )
