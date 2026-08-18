"""The operation layer over the evidence core.

This module used to be the authority/storage daemon: a resident Unix-socket
server that alone opened the production database. The daemon — its socket,
its tier system, its dispatch loop — was removed (lane X, residency
dissolution); what remains is the layer both it and development mode always
shared: one ``op_*`` function per client operation, each of which opens the
archive, validates its arguments, verifies any required operator
authorization, acts, and closes. Every call is request-scoped; nothing here
runs continuously.

Two properties survive the daemon and are still this module's to keep:

1. **Operator acts require a verified ``OperatorActionV1``.** Each operator
   operation checks a signed authorization covering exactly its act
   (`_needs_attestation`). Nothing about being local is sufficient.

2. **Refusals leak nothing.** A `_Refusal` carries a code and a bounded
   message built from the operation's own vocabulary, never archive content
   and never the offending argument's value.

With residency gone, hardened configuration fails closed before any of this
runs: `contextd/service.py` refuses hardened calls outright, and
`db._guard_direct_access` refuses the archive open even if something reaches
further. These functions therefore execute only in development mode, as
short-lived library calls.
"""

from pathlib import Path

from . import home, load_config

# Assurance resolvers register at import time (contextd/assurance.py). Importing
# them here, at module scope, is what guarantees a process never reads a
# loop or decision event through a half-populated registry: every entry point
# into the operation layer carries this import.
from . import decisions, loops  # noqa: F401
# aliased: mcp_server and service define their own `search` function
from . import search as _search_registration  # noqa: F401


# `hardened`, `is_service_process` and `service_context` live in
# contextd/authority_mode.py: they answer authority-plane questions that the
# core itself must ask before it opens the archive or accepts a first-key
# bootstrap. Re-exported here because operation-layer and test call sites
# import them from `.authd`.
from .authority_mode import (  # noqa: E402, F401
    _SERVICE_PROCESS,
    hardened,
    is_service_process,
    service_context,
)


class RpcError(RuntimeError):
    """A request was refused.

    Moved verbatim in behaviour from the deleted ``contextd/rpc.py``: this is
    the refusal type every client caller catches (`except RpcError` in the
    CLI and MCP server). It outlives the RPC transport because the operation
    layer's `_Refusal` and the client plane's `ClientRefused` both subclass
    it — the refusal channel is the surviving contract, not the wire.
    """

    def __init__(self, message: str, code: str = "refused"):
        super().__init__(message)
        self.code = code


class _Refusal(RpcError):
    """A handler refusing for a stated, content-free reason."""


def _archive(service):
    """The one place the operation layer opens the archive.

    ``service`` is vestigial: it carried the daemon instance whose rate
    state one deleted handler used. Callers pass None; the parameter stays
    so every handler keeps the (service, principal, tier, args) signature.
    """
    from .db import connect
    return connect()


def _needs_attestation(args: dict, action: str, scope: str = "global",
                       conn=None, **covered):
    """Verify the caller's OperatorActionV1 for exactly this act."""
    from .attest import AttestationError, verify_action
    blob = args.get("authorization")
    if not isinstance(blob, dict):
        raise _Refusal(
            f"{action} requires a verified operator authorization; being "
            f"able to invoke this operation authorizes nothing",
            code="attestation_required",
        )
    action_map = blob.get("action")
    signature = blob.get("signature")
    if not isinstance(action_map, dict) or not isinstance(signature, str):
        raise _Refusal("malformed authorization", code="attestation_required")
    try:
        authorization = verify_action(
            action_map, bytes.fromhex(signature), conn=conn
        )
    except (AttestationError, ValueError) as exc:
        raise _Refusal(f"authorization refused: {exc}", code="attestation") from exc
    if not authorization.matches(action, scope, **covered):
        raise _Refusal(
            f"the authorization does not cover exactly {action} on {scope}",
            code="attestation",
        )
    return authorization


# --- handlers ---------------------------------------------------------------
# Each returns JSON-serializable data. None of them accepts SQL, a table name,
# a file path outside the archive, or a callable.

def op_status(service, principal, tier, args):
    conn = _archive(service)
    try:
        rows = conn.execute(
            "SELECT source, kind, COUNT(*) AS n FROM events "
            "GROUP BY source, kind ORDER BY n DESC"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return {"total": total,
                "by_kind": [{"source": r["source"], "kind": r["kind"],
                             "n": r["n"]} for r in rows]}
    finally:
        conn.close()


def _int(args, name, default=None, low=None, high=None):
    value = args.get(name, default)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise _Refusal(f"{name} must be an integer", code="malformed")
    if low is not None and value < low:
        raise _Refusal(f"{name} is below its bound", code="malformed")
    if high is not None and value > high:
        raise _Refusal(f"{name} is above its bound", code="malformed")
    return value


def _text(args, name, default="", limit=2000):
    value = args.get(name, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise _Refusal(f"{name} must be a string", code="malformed")
    if len(value) > limit:
        raise _Refusal(f"{name} exceeds its bound", code="malformed")
    return value


def _backup_action_arguments(conn, destination: str, keep: int) -> dict:
    from .attest import archive_uuid
    from .backup import normalized_path

    tip = conn.execute(
        "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return {
        "destination_path": normalized_path(destination),
        "keep": keep,
        "archive_uuid": archive_uuid(conn),
        "snapshot_head_id": tip["id"] if tip else 0,
        "snapshot_head_hash": tip["chain_hash"] if tip else "",
    }


def _export_action_arguments(conn, destination: str, recipient_sha256: str) -> dict:
    """The arguments an export authorization must cover.

    `recipient_sha256` is in here, and that is the point. The recipient is
    named by `security.export_recipient` in config.toml, and config.toml is
    writable by the modeled attacker — the same-UID process. If the recipient
    were read from config at export time and not covered by the signature, the
    attack is trivial and total: swap the configured key, wait for the operator
    to approve an export they believe is going to themselves, and receive a
    readable copy of the archive. Binding the digest here means a swapped
    recipient produces an authorization that no longer matches, and the export
    refuses instead.
    """
    from .attest import archive_uuid
    from .backup import normalized_path

    tip = conn.execute(
        "SELECT id, chain_hash FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return {
        "destination_path": normalized_path(destination),
        "recipient_sha256": recipient_sha256,
        "archive_uuid": archive_uuid(conn),
        "snapshot_head_id": tip["id"] if tip else 0,
        "snapshot_head_hash": tip["chain_hash"] if tip else "",
    }


def _restore_action_arguments(identity: dict) -> dict:
    snapshot = identity.get("snapshot")
    if (identity.get("authenticated") is not True
            or not isinstance(identity.get("signing_key_id"), str)
            or not identity["signing_key_id"]
            or not isinstance(snapshot, dict)):
        raise _Refusal(
            "restore requires a manifest authenticated by the external trust store",
            code="policy",
        )
    return {
        "bundle_path": identity["bundle_path"],
        "destination_path": identity["destination_path"],
        "manifest_sha256": identity["manifest_sha256"],
        "signing_key_id": identity["signing_key_id"],
        "snapshot_events": int(snapshot["events"]),
        "snapshot_head_id": int(snapshot["head_id"] or 0),
        "snapshot_head_hash": str(snapshot["head_hash"] or ""),
        "authenticated": 1,
    }


def op_search(service, principal, tier, args):
    from .gate import GateError, disclose, never_leave
    from .search import search as do_search
    conn = _archive(service)
    cfg = load_config()
    try:
        hits = do_search(conn, _text(args, "query"),
                         _int(args, "limit", 10, 1, 50), highlight=False)
        seen, lines = set(), []
        for h in hits:
            if never_leave(cfg, h["uri"]) or (h["uri"] and h["uri"] in seen):
                continue
            seen.add(h["uri"])
            lines.append(f"[{h['id']}] {h['ts']} {h['source']}/{h['kind']} "
                         f"{h['uri'] or ''} :: {h['snip']}")
        out = "\n".join(lines) or "(no hits)"
        receipt = disclose(conn, cfg, out, {
            "type": "search", "query": _text(args, "query"),
            "client": _text(args, "client", "rpc", limit=64)})
        return {"content": receipt["content"], "egress_id": receipt["egress_id"]}
    except GateError as exc:
        raise _Refusal(str(exc), code="gate") from exc
    finally:
        conn.close()


def op_timeline(service, principal, tier, args):
    from .gate import GateError, disclose, never_leave, redact
    from .search import timeline as do_timeline
    conn = _archive(service)
    cfg = load_config()
    source = _text(args, "source", limit=64)
    try:
        rows = do_timeline(
            conn, _text(args, "since", limit=64) or None,
            _text(args, "until", limit=64) or None, source or None,
            limit=_int(args, "limit", 30, 1, 200),
            exclude_egress=(source != "gate"))

        def brief(r):
            c = r["content"] or ""
            if r["uri"]:
                c = c.replace(r["uri"], "")
            return redact(cfg, c.strip())[:120]

        out = "\n".join(
            f"[{r['id']}] {r['ts']} {r['source']}/{r['kind']} "
            f"{r['uri'] or ''} {brief(r)}"
            for r in rows if not never_leave(cfg, r["uri"])) or "(no events)"
        receipt = disclose(conn, cfg, out, {
            "type": "timeline",
            "client": _text(args, "client", "rpc", limit=64),
            "window": [_text(args, "since", limit=64),
                       _text(args, "until", limit=64), source]})
        return {"content": receipt["content"], "egress_id": receipt["egress_id"]}
    except GateError as exc:
        raise _Refusal(str(exc), code="gate") from exc
    finally:
        conn.close()


def op_note_deliberate(service, principal, tier, args):
    from .attest import authorized_append
    text = _text(args, "text", limit=100_000)
    conn = _archive(service)
    try:
        authorization = _needs_attestation(
            args, "note.deliberate", "global", conn=conn, content=text
        )
        return {"event": authorized_append(
            conn, "note", "note", authorization, "note.deliberate", "global",
            content=text, meta={"claimed_client": "operator-cli"},
        )}
    finally:
        conn.close()


def op_loop_candidate(service, principal, tier, args):
    from .loops import LoopError, add_candidate, make_scope
    conn = _archive(service)
    try:
        repo = _text(args, "scope_repo", limit=4096)
        result = add_candidate(conn, _text(args, "text", limit=8000),
                               make_scope(repo or None), client="rpc")
        return {"result": result["result"], "loop": result["loop"]["id"],
                "state": result["loop"]["state"]}
    except LoopError as exc:
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


def op_loop_list(service, principal, tier, args):
    from .gate import GateError, disclose
    from .loops import loops_for_scope, make_scope
    conn = _archive(service)
    cfg = load_config()
    try:
        repo = _text(args, "scope_repo", limit=4096)
        scope = make_scope(repo or None)
        states = ("open", "candidate") if args.get("include_candidates", True) \
            else ("open",)
        rows = loops_for_scope(conn, scope, states=states)
        out = "\n".join(
            f"[loop#{lp['id']}] {lp['state']} since {lp['created_ts'][:10]} "
            f":: {lp['text']}" for lp in rows) or "(no loops for this scope)"
        receipt = disclose(conn, cfg, out, {
            "type": "loop_list", "client": "rpc",
            "scope": "global" if scope.get("global") else scope["repo"]})
        return {"content": receipt["content"], "egress_id": receipt["egress_id"]}
    except GateError as exc:
        raise _Refusal(str(exc), code="gate") from exc
    finally:
        conn.close()


def _granted_transition(service, args, op_name, grant_class):
    from .grants import GrantError, require_grant
    from .loops import LoopError, reduce_loops, transition
    conn = _archive(service)
    try:
        loop_id = _int(args, "loop_id", low=1)
        loop = reduce_loops(conn)["loops"].get(loop_id)
        if loop is None:
            raise _Refusal(f"no loop #{loop_id}", code="refused")
        grant = require_grant(conn, grant_class, loop["scope"])
        result = transition(conn, loop_id, op_name, client="rpc",
                            reason=_text(args, "reason", limit=2000),
                            grant=grant["id"])
        return {"result": result["result"], "state": result["loop"]["state"],
                "grant": grant["id"]}
    except (GrantError, LoopError) as exc:
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


def op_loop_confirm(service, principal, tier, args):
    return _granted_transition(service, args, "confirm", "loop.confirm")


def op_loop_dismiss(service, principal, tier, args):
    return _granted_transition(service, args, "dismiss", "loop.dismiss")


def op_loop_add_operator(service, principal, tier, args):
    from .loops import LoopError, add_loop, make_scope, scope_str

    text = _text(args, "text", limit=8000)
    repo = _text(args, "scope_repo", limit=4096)
    source_events = args.get("source_events", [])
    if (not isinstance(source_events, list) or len(source_events) > 64
            or any(isinstance(item, bool) or not isinstance(item, int)
                   or item < 1 for item in source_events)):
        raise _Refusal("source_events must be bounded event ids", code="malformed")
    if source_events:
        raise _Refusal(
            "operator RPC loop.add refuses unsigned source-event metadata",
            code="malformed",
        )
    scope = make_scope(repo or None)
    conn = _archive(service)
    try:
        authorization = _needs_attestation(
            args, "loop.add", scope_str(scope), conn=conn, content=text
        )
        result = add_loop(
            conn, text, scope, client="operator-cli",
            source_events=source_events, authorization=authorization,
        )
        return {"result": result["result"], "loop": result["loop"]}
    except LoopError as exc:
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


def op_loop_transition_operator(service, principal, tier, args):
    from .loops import LoopError, reduce_loops, scope_str, transition

    loop_id = _int(args, "loop_id", low=1)
    operation = _text(args, "transition", limit=16)
    if operation not in {"confirm", "close", "reopen", "dismiss"}:
        raise _Refusal("unknown loop transition", code="malformed")
    reason = _text(args, "reason", limit=2000)
    conn = _archive(service)
    try:
        loop = reduce_loops(conn)["loops"].get(loop_id)
        if loop is None:
            raise _Refusal("no such loop", code="not_found")
        authorization = _needs_attestation(
            args, f"loop.{operation}", scope_str(loop["scope"]), conn=conn,
            arguments={"loop": loop_id}, reason=reason,
        )
        result = transition(
            conn, loop_id, operation, client="operator-cli", reason=reason,
            authorization=authorization,
        )
        return {"result": result["result"], "loop": result["loop"]}
    except LoopError as exc:
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


def op_decision_supersede_operator(service, principal, tier, args):
    from .decisions import DecisionError, record_supersession

    old = _int(args, "old", low=1)
    new = _int(args, "new", low=1)
    reason = _text(args, "reason", limit=2000)
    conn = _archive(service)
    try:
        authorization = _needs_attestation(
            args, "decision.supersede", "global", conn=conn,
            arguments={"old": old, "new": new},
            content=reason or None, reason=reason,
        )
        result = record_supersession(
            conn, old, new, reason=reason, client="operator-cli",
            authorization=authorization,
        )
        return {"result": result["result"], "edge": result["edge"]}
    except DecisionError as exc:
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


def op_raw_read(service, principal, tier, args):
    """Unredacted event content. The one read that bypasses the gate, and
    therefore the one that always requires an attestation."""
    event_id = _int(args, "event_id", low=1)
    from .attest import consume_nonce, reverify_for_use
    conn = _archive(service)
    try:
        authorization = _needs_attestation(
            args, "archive.raw_read", "global", conn=conn,
            arguments={"event_id": event_id},
        )
        if conn.in_transaction:
            conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        verified = reverify_for_use(
            conn, authorization, action="archive.raw_read", scope="global",
            arguments={"event_id": event_id},
        )
        row = conn.execute(
            "SELECT id, ts, source, kind, uri, content, meta FROM events "
            "WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            conn.rollback()
            raise _Refusal(f"no event #{event_id}", code="not_found")
        consume_nonce(conn, verified, 0)
        conn.commit()
        return {k: row[k] for k in row.keys()}
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def op_backup(service, principal, tier, args):
    from .attest import consume_authorization
    from .backup import create_backup
    destination = _text(args, "destination", limit=4096)
    keep = _int(args, "keep", 0, 0, 1000)
    conn = _archive(service)
    try:
        covered = _backup_action_arguments(conn, destination, keep)
        authorization = _needs_attestation(
            args, "archive.backup", "global", conn=conn,
            arguments=covered,
        )
        consume_authorization(
            conn, authorization, action="archive.backup", scope="global",
            arguments=covered,
        )
        result = create_backup(
            conn, home(), Path(covered["destination_path"]), keep=keep,
            expected_head_id=covered["snapshot_head_id"],
            expected_head_hash=covered["snapshot_head_hash"],
        )
        return {
            **result,
            "bundle": str(result["bundle"]),
            "pruned": [str(path) for path in result.get("pruned", [])],
        }
    finally:
        conn.close()


def op_restore(service, principal, tier, args):
    from .attest import consume_authorization
    from .backup import BackupError, bundle_identity, restore_backup
    bundle = _text(args, "bundle", limit=4096)
    destination = _text(args, "destination", limit=4096)
    conn = _archive(service)
    try:
        blob = args.get("authorization") or {}
        signed_action = blob.get("action") if isinstance(blob, dict) else None
        signed_arguments = signed_action.get("arguments") \
            if isinstance(signed_action, dict) else None
        if not isinstance(signed_arguments, dict):
            raise _Refusal("malformed authorization", code="attestation_required")
        authorization = _needs_attestation(
            args, "archive.restore", "global", conn=conn,
            arguments=signed_arguments,
        )
        identity = bundle_identity(
            Path(bundle), destination=Path(destination), trust_store=None,
            legacy_policy=None,
        )
        covered = _restore_action_arguments(identity)
        if not authorization.matches(
            "archive.restore", "global", arguments=covered
        ):
            raise _Refusal(
                "authorization does not match the authenticated bundle identity",
                code="attestation",
            )
        consume_authorization(
            conn, authorization, action="archive.restore", scope="global",
            arguments=covered,
        )
    except BackupError as exc:
        raise _Refusal(
            "restore bundle failed authenticated preflight", code="policy"
        ) from exc
    finally:
        conn.close()
    result = restore_backup(
        Path(covered["bundle_path"]), Path(covered["destination_path"]),
        trust_store=None, legacy_policy=None,
        expected_manifest_sha256=covered["manifest_sha256"],
    )
    return {**result, "destination": str(result["destination"])}


def op_export(service, principal, tier, args):
    """Export the archive sealed to the configured recovery recipient.

    Export never emits plaintext outside service-owned storage: with no
    recipient configured it refuses, and the only bytes it writes are sealed
    (docs/SECURITY.md §8). The plaintext bundle exists solely inside 0700
    scratch, which is removed before this returns.

    What encryption here does and does not buy is stated in
    `contextd/export_crypto.py`: it protects the bundle after it leaves this
    host, and it is worth nothing if the private half of the recipient key
    lives on this host, because the modeled attacker owns this host.
    """
    from .attest import consume_authorization
    from .backup import BackupError, _read_secure_file
    from .export import ExportError, create_sealed_export
    from .export_crypto import ExportCryptoError, load_recipient

    # The recipient policy is checked FIRST, before the destination, because
    # it is the gate that must hold unconditionally: "there is no recovery
    # policy, so export refuses" is true whether or not the caller got as far
    # as naming somewhere to write. Checking the destination first would let a
    # usage error mask a policy refusal.
    configured = ((load_config().get("security") or {}).get("export_recipient")
                  or "").strip()
    if not configured:
        raise _Refusal(
            "export refuses: hardened mode requires an explicitly configured "
            "recovery recipient, and none is set. Plaintext export outside "
            "service-owned storage is not a fallback. Set "
            "security.export_recipient to the path of an X25519 public key "
            "whose private half is NOT on this host.",
            code="policy",
        )
    try:
        recipient_key = _read_secure_file(Path(configured).expanduser(),
                                          "export recipient")
        _, digest = load_recipient(recipient_key)
    except ExportCryptoError as exc:
        raise _Refusal(f"configured export recipient is unusable: {exc}",
                       code="policy") from exc
    except BackupError as exc:
        # `_read_secure_file` also refuses a group/world-accessible file. That
        # is an INTEGRITY requirement, not a secrecy one — a public key is not
        # secret, but a 0644 key file in a shared directory is one another
        # local account can swap, which is exactly the substitution the signed
        # recipient digest exists to prevent. Say so, since being told a public
        # key is "too readable" is otherwise baffling.
        raise _Refusal(
            f"configured export recipient at {configured} is unusable: {exc}. "
            f"The recipient must be a regular, non-symlinked file at mode 0600 "
            f"(chmod 600) — not because a public key is secret, but so no other "
            f"local account can substitute one.",
            code="policy",
        ) from exc

    destination = _text(args, "destination", limit=4096)
    if not destination:
        raise _Refusal("export requires a destination", code="policy")

    conn = _archive(service)
    try:
        covered = _export_action_arguments(conn, destination, digest)
        authorization = _needs_attestation(
            args, "archive.export", "global", conn=conn, arguments=covered,
        )
        consume_authorization(
            conn, authorization, action="archive.export", scope="global",
            arguments=covered,
        )
        try:
            result = create_sealed_export(
                conn, home(), Path(covered["destination_path"]),
                recipient_key=recipient_key,
                expected_head_id=covered["snapshot_head_id"],
                expected_head_hash=covered["snapshot_head_hash"],
            )
        except (ExportError, ExportCryptoError) as exc:
            raise _Refusal(f"export failed: {exc}", code="policy") from exc
        return result
    finally:
        conn.close()


def op_grant_add(service, principal, tier, args):
    from .grants import GrantError, _utc_instant, add_grant
    from .loops import make_scope
    cls = _text(args, "class", limit=64)
    repo = _text(args, "scope_repo", limit=4096)
    try:
        expires = _utc_instant(
            _text(args, "expires", limit=64)
        ).isoformat(timespec="seconds")
    except GrantError as exc:
        raise _Refusal(str(exc), code="refused") from exc
    scope = make_scope(repo or None)
    from .loops import scope_str
    conn = _archive(service)
    try:
        authorization = _needs_attestation(
            args, "grant.add", scope_str(scope), conn=conn,
            arguments={"class": cls, "expires": expires},
            content=_text(args, "reason", limit=2000) or None,
            reason=_text(args, "reason", limit=2000))
        result = add_grant(conn, cls, scope, expires=expires,
                           reason=_text(args, "reason", limit=2000),
                           client="operator-cli", authorization=authorization)
        return {"result": result["result"], "grant": result["grant"]["id"]}
    except GrantError as exc:
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


def op_grant_revoke(service, principal, tier, args):
    from .grants import GrantError, reduce_grants, revoke_grant
    from .loops import scope_str
    grant_id = _int(args, "grant_id", low=1)
    conn = _archive(service)
    try:
        grant = next((g for g in reduce_grants(conn)["grants"]
                      if g["id"] == grant_id), None)
        if grant is None:
            raise _Refusal(f"no grant ev {grant_id}", code="not_found")
        authorization = _needs_attestation(
            args, "grant.revoke", scope_str(grant["scope"]), conn=conn,
            arguments={"grant": grant_id},
            content=_text(args, "reason", limit=2000) or None,
            reason=_text(args, "reason", limit=2000))
        result = revoke_grant(conn, grant_id,
                              reason=_text(args, "reason", limit=2000),
                              client="operator-cli",
                              authorization=authorization)
        return {"result": result["result"]}
    except GrantError as exc:
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


def op_key_register(service, principal, tier, args):
    from .attest import (AttestationError, SIGNER_SECURE_ENCLAVE,
                         consume_nonce, register_key, reverify_for_use)
    der_hex = _text(args, "public_der", limit=8192)
    signer_tag = _text(args, "signer_tag", limit=64)
    conn = _archive(service)
    try:
        covered = {"public_der": der_hex, "signer_tag": signer_tag}
        authorization = _needs_attestation(
            args, "security.key_register", "global", conn=conn,
            arguments=covered,
        )
        if conn.in_transaction:
            conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        verified = reverify_for_use(
            conn, authorization, action="security.key_register", scope="global",
            arguments=covered,
        )
        consume_nonce(conn, verified, 0)
        key_id = register_key(
            bytes.fromhex(der_hex), SIGNER_SECURE_ENCLAVE, conn=conn,
            signer_tag=signer_tag, commit=False,
        )
        conn.commit()
        return {"key_id": key_id}
    except (AttestationError, ValueError) as exc:
        conn.rollback()
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


def op_key_revoke(service, principal, tier, args):
    from .attest import (AttestationError, consume_nonce, reverify_for_use,
                         revoke_key)
    key_id = _text(args, "key_id", limit=128)
    conn = _archive(service)
    try:
        authorization = _needs_attestation(
            args, "security.key_revoke", "global", conn=conn,
            arguments={"key_id": key_id},
        )
        if conn.in_transaction:
            conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        verified = reverify_for_use(
            conn, authorization, action="security.key_revoke", scope="global",
            arguments={"key_id": key_id},
        )
        consume_nonce(conn, verified, 0)
        revoke_key(key_id, conn=conn, commit=False)
        conn.commit()
        return {"revoked": key_id}
    except AttestationError as exc:
        conn.rollback()
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


# --- deployment inspection --------------------------------------------------

