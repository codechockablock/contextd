"""The authority/storage daemon.

Intended to run as a **dedicated service UID from root-owned installed code**
(docs/DEPLOYMENT.md §4). It alone opens the production database, the blob
store, the chain witness, the operator key registry, and plaintext backup
staging. The client plane — CLI, MCP server, hooks, the ``contextd`` package as
imported by anything else — reaches it only through the closed RPC surface
below.

Three properties this module is responsible for:

1. **A closed operation namespace.** ``OPERATIONS`` is the whole API. An
   unregistered name is refused before any argument is examined. There is no
   "run this SQL", no passthrough, and no debug op.

2. **Tier is assigned, never requested.** Each connection gets exactly one tier
   at accept time, derived from kernel-reported peer credentials. Nothing a
   client sends can widen it. Operator-tier operations additionally require a
   verified ``OperatorActionV1`` covering that exact act — being on the socket
   is never sufficient.

3. **Refusals leak nothing.** An error carries a code and a bounded message
   built from the operation's own vocabulary, never archive content and never
   the offending argument's value.

What this module does **not** do: it does not install itself, create accounts,
or change ownership. In development it runs as the desktop UID, which means the
isolation is *simulated* — `ctx security doctor` reports that rather than
letting it read as though the boundary were real.
"""

import json
import os
import socket
import stat
import threading
import time
import traceback
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

from . import home, load_config
from .assurance import Principal
from .rpc import (
    TIER_MODEL,
    TIER_OPERATOR,
    RpcError,
    peer_credentials,
    read_frame,
    send_frame,
)

# Assurance resolvers register at import time (contextd/assurance.py). Importing
# them here, at module scope, is what guarantees a daemon process never reads a
# loop or decision event through a half-populated registry: every daemon process
# starts at one of the four entry points that carry this import.
from . import decisions, loops  # noqa: F401
# aliased: mcp_server and service define their own `search` function
from . import search as _search_registration  # noqa: F401

SOCKET_NAME = "authd.sock"

#: Operations at this tier return archive-derived bytes only through the gate:
#: redacted, budgeted, and receipted as an egress event.
#: Operations at operator tier additionally require an attestation.


@dataclass(frozen=True)
class Operation:
    """One entry in the closed registry."""

    handler: str            # name of the module-level implementation
    tier: str               # the minimum tier that may invoke it
    attested: bool = False  # requires a verified OperatorActionV1 as well
    summary: str = ""


OPERATIONS: dict[str, Operation] = {
    # --- model tier: gated, redacted, receipted -------------------------
    "recall": Operation("op_recall", TIER_MODEL,
                        summary="gated context bundle; logged as egress"),
    "search": Operation("op_search", TIER_MODEL,
                        summary="redacted snippets; logged as egress"),
    "timeline": Operation("op_timeline", TIER_MODEL,
                          summary="redacted briefs; logged as egress"),
    "note": Operation("op_note", TIER_MODEL,
                      summary="append an unverified note"),
    "loop_candidate": Operation("op_loop_candidate", TIER_MODEL,
                                summary="propose a non-authoritative loop"),
    "loop_list": Operation("op_loop_list", TIER_MODEL,
                           summary="loops for a scope; logged as egress"),
    "loop_confirm": Operation("op_loop_confirm", TIER_MODEL,
                              summary="confirm under a verified grant"),
    "loop_dismiss": Operation("op_loop_dismiss", TIER_MODEL,
                              summary="dismiss under a verified grant"),
    "decision_supersede": Operation("op_decision_supersede", TIER_MODEL,
                                    summary="supersede under a verified grant"),
    "status": Operation("op_status", TIER_MODEL,
                        summary="counts only; no archive content"),
    "prepare_action": Operation(
        "op_prepare_action", TIER_MODEL,
        summary="mint one bounded, expiring operator challenge",
    ),
    "operator_keys": Operation(
        "op_operator_keys", TIER_MODEL,
        summary="contentless operator key identifiers and enrollment tags",
    ),

    # --- operator tier: each needs a verified OperatorActionV1 ----------
    "raw_read": Operation("op_raw_read", TIER_OPERATOR, attested=True,
                          summary="unredacted event content"),
    "export": Operation("op_export", TIER_OPERATOR, attested=True,
                        summary="archive export"),
    "backup": Operation("op_backup", TIER_OPERATOR, attested=True,
                        summary="create a backup bundle"),
    "restore": Operation("op_restore", TIER_OPERATOR, attested=True,
                         summary="restore into an empty home"),
    "note_deliberate": Operation("op_note_deliberate", TIER_OPERATOR,
                                 attested=True,
                                 summary="append an operator-authorized note"),
    "grant_add": Operation("op_grant_add", TIER_OPERATOR, attested=True,
                           summary="record a delegation"),
    "grant_revoke": Operation("op_grant_revoke", TIER_OPERATOR, attested=True,
                              summary="revoke a delegation"),
    "key_register": Operation("op_key_register", TIER_OPERATOR, attested=True,
                              summary="register an operator key"),
    "key_revoke": Operation("op_key_revoke", TIER_OPERATOR, attested=True,
                            summary="revoke an operator key"),
    "loop_add_operator": Operation(
        "op_loop_add_operator", TIER_OPERATOR, attested=True,
        summary="open an operator-authorized loop",
    ),
    "loop_transition_operator": Operation(
        "op_loop_transition_operator", TIER_OPERATOR, attested=True,
        summary="perform an operator-authorized loop transition",
    ),
    "decision_supersede_operator": Operation(
        "op_decision_supersede_operator", TIER_OPERATOR, attested=True,
        summary="record an operator-authorized supersession",
    ),

    # --- unauthenticated, deliberately contentless ----------------------
    "ping": Operation("op_ping", TIER_MODEL,
                      summary="liveness; returns no archive state"),
    "capabilities": Operation("op_capabilities", TIER_MODEL,
                              summary="the ops THIS connection may call"),
}

ATTESTED_ACTIONS = {
    "raw_read": {"archive.raw_read"},
    "export": {"archive.export"},
    "backup": {"archive.backup"},
    "restore": {"archive.restore"},
    "note_deliberate": {"note.deliberate"},
    "grant_add": {"grant.add"},
    "grant_revoke": {"grant.revoke"},
    "key_register": {"security.key_register"},
    "key_revoke": {"security.key_revoke"},
    "loop_add_operator": {"loop.add"},
    "loop_transition_operator": {
        "loop.confirm", "loop.close", "loop.reopen", "loop.dismiss",
    },
    "decision_supersede_operator": {"decision.supersede"},
}


def socket_path(root: Path | None = None) -> Path:
    configured = ((load_config().get("security") or {}).get("socket") or "").strip()
    if configured:
        return Path(configured).expanduser()
    return (root or home()) / SOCKET_NAME


# `hardened`, `is_service_process` and `service_context` now live in
# contextd/authority_mode.py: they answer authority-plane questions that the
# core itself must ask before it opens the archive or accepts a first-key
# bootstrap. Re-exported here because ~20 daemon and test call sites import
# them from `.authd`, and because this is still where the marker gets set.
from .authority_mode import (  # noqa: E402, F401
    _SERVICE_PROCESS,
    hardened,
    is_service_process,
    service_context,
)


def _tier_for(principal: Principal) -> str:
    """Assign a capability tier from kernel-reported credentials.

    Everyone who can reach the socket starts at model tier. Operator tier is
    reachable only from the service UID itself (a local admin path) — and even
    then every operator operation still requires an attestation, so reaching
    the tier is necessary and never sufficient.
    """
    if principal.uid == os.getuid() and principal.kind == "service":
        return TIER_OPERATOR
    return TIER_MODEL


def allowed_operations(tier: str) -> list[str]:
    if tier == TIER_OPERATOR:
        return sorted(OPERATIONS)
    # Per-action hardware signatures authorize attested operations. Requiring
    # a privileged peer tier as well would make the intended desktop ceremony
    # impossible without adding any cryptographic protection.
    return sorted(
        n for n, op in OPERATIONS.items()
        if op.tier == TIER_MODEL or op.attested
    )


class AuthorityService:
    """A minimal, closed-surface Unix-socket server."""

    def __init__(self, path=None, root=None, operator_uids=None):
        self.root = Path(root) if root else home()
        self.path = Path(path) if path else socket_path(self.root)
        # uids permitted operator tier. Empty in the intended deployment: the
        # service account is the only one, and operators act through
        # attestations rather than through a privileged socket peer.
        self.operator_uids = set(operator_uids or ())
        self._server = None
        self._thread = None
        self._stop = threading.Event()
        self._challenge_lock = threading.Lock()
        self._challenge_times = defaultdict(deque)

    # -- lifecycle --------------------------------------------------------
    #: `sun_path` is 104 bytes on macOS and 108 on Linux. Exceeding it fails
    #: with a bare EINVAL/ENAMETOOLONG that reads like a bug in the caller, so
    #: it is checked here with the actual limit named.
    MAX_SOCKET_PATH = 100
    CHALLENGES_PER_WINDOW = 8
    CHALLENGE_WINDOW_SECONDS = 60
    MAX_OUTSTANDING_CHALLENGES = 32

    def start(self) -> "AuthorityService":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if len(str(self.path).encode()) > self.MAX_SOCKET_PATH:
            raise RpcError(
                f"socket path is {len(str(self.path))} bytes, over the "
                f"{self.MAX_SOCKET_PATH}-byte AF_UNIX limit: {self.path}. "
                f"Set [security] socket to a shorter path."
            )
        if self.path.exists() or self.path.is_socket():
            self.path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.path))
        # 0660: the desktop UID may connect; the world may not. In the intended
        # deployment the socket directory is `_contextd:staff 0750`, so group
        # membership is the gate and the DB behind it stays 0600 service-owned.
        os.chmod(self.path, 0o660)
        server.listen(16)
        server.settimeout(0.2)
        self._server = server
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._session, args=(client,),
                             daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._server is not None:
            self._server.close()
        try:
            self.path.unlink()
        except OSError:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *_exc):
        self.stop()

    # -- one connection ---------------------------------------------------
    def _principal(self, client) -> Principal:
        creds = peer_credentials(client)
        kind = "service" if creds["uid"] in self.operator_uids else "client"
        return Principal(uid=creds["uid"], pid=creds["pid"], kind=kind)

    def _session(self, client):
        client.settimeout(30)
        reader = client.makefile("rb")
        try:
            principal = self._principal(client)
            # Tier is fixed here, once, from kernel-reported credentials. It is
            # not re-derived per request and no request field can influence it.
            tier = _tier_for(principal)
            while True:
                try:
                    request = read_frame(reader)
                except RpcError as exc:
                    send_frame(client, _error("malformed", str(exc)))
                    break
                if request is None:
                    break
                send_frame(client, self._dispatch(principal, tier, request))
        except (OSError, RpcError):
            pass
        finally:
            try:
                reader.close()
                client.close()
            except OSError:
                pass

    def _dispatch(self, principal: Principal, tier: str, request: dict) -> dict:
        op_name = request.get("op")
        if not isinstance(op_name, str) or op_name not in OPERATIONS:
            # refused before arguments are read: an unregistered name is not a
            # request for a feature, it is a probe
            return _error("unknown_operation",
                          f"no such operation; this connection may call: "
                          f"{', '.join(allowed_operations(tier))}")
        operation = OPERATIONS[op_name]
        if (operation.tier == TIER_OPERATOR and tier != TIER_OPERATOR
                and not operation.attested):
            return _error(
                "tier",
                f"{op_name} is an operator operation and this connection holds "
                f"{tier} tier. A connection's tier is assigned from kernel "
                f"peer credentials and cannot be widened by a request.",
            )
        args = request.get("args")
        if args is not None and not isinstance(args, dict):
            return _error("malformed", "args must be an object")
        args = args or {}
        if len(args) > 32:
            return _error("malformed", "too many arguments")

        handler = globals().get(operation.handler)
        if handler is None:                       # pragma: no cover - registry bug
            return _error("unimplemented",
                          f"{op_name} is registered but not implemented")
        try:
            with service_context():
                if operation.attested:
                    _preflight_attestation(args, ATTESTED_ACTIONS[op_name])
                result = handler(self, principal, tier, args)
        except _Refusal as exc:
            return _error(exc.code, str(exc))
        except Exception as exc:                  # noqa: BLE001
            # The message is the exception's type and the operation name only.
            # Formatting the exception itself risks putting an argument value —
            # a query, a path, a row — into a log line.
            traceback.clear_frames(exc.__traceback__)
            return _error("error", f"{op_name} failed: {type(exc).__name__}")
        return {"ok": True, "result": result}


class _Refusal(RpcError):
    """A handler refusing for a stated, content-free reason."""


def _error(code: str, message: str) -> dict:
    return {"ok": False, "error": {"code": code, "message": message[:512]}}


def _archive(service: "AuthorityService"):
    """The one place the daemon opens the archive."""
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
            f"connected to this socket authorizes nothing",
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


def _preflight_attestation(args: dict, allowed_actions: set[str]) -> None:
    """Cryptographically refuse before an operator handler examines its intent."""
    from .attest import AttestationError, verify_action

    blob = args.get("authorization")
    if not isinstance(blob, dict):
        raise _Refusal(
            "a fresh verified operator authorization is required; socket "
            "reachability authorizes nothing",
            code="attestation_required",
        )
    action_map, signature = blob.get("action"), blob.get("signature")
    if not isinstance(action_map, dict) or not isinstance(signature, str):
        raise _Refusal("malformed authorization", code="attestation_required")
    conn = _archive(None)
    try:
        authorization = verify_action(
            action_map, bytes.fromhex(signature), conn=conn
        )
        if authorization.action["action"] not in allowed_actions:
            raise AttestationError("authorization is for another operation")
    except (AttestationError, ValueError) as exc:
        raise _Refusal(f"authorization refused: {exc}", code="attestation") from exc
    finally:
        conn.close()


# --- handlers ---------------------------------------------------------------
# Each returns JSON-serializable data. None of them accepts SQL, a table name,
# a file path outside the archive, or a callable.

def op_ping(service, principal, tier, args):
    return {"ok": True, "protocol": 1, "tier": tier}


def op_capabilities(service, principal, tier, args):
    return {
        "tier": tier,
        "operations": allowed_operations(tier),
        "principal": {"uid": principal.uid, "kind": principal.kind},
    }


def op_prepare_action(service, principal, tier, args):
    """Mint canonical bytes; callers never choose nonce, sequence, or expiry."""
    from .attest import (ACTION_CLASSES, AttestationError, prepare_action,
                         registered_keys)
    from .backup import BackupError
    from .grants import GrantError

    action = _text(args, "action", limit=64)
    if action not in ACTION_CLASSES:
        raise _Refusal("unknown operator action class", code="malformed")
    scope = _text(args, "scope", "global", limit=4096)
    arguments = args.get("arguments", {})
    if not isinstance(arguments, dict) or len(arguments) > 16:
        raise _Refusal("arguments must be a bounded object", code="malformed")
    content = _text(args, "content", limit=100_000) or None
    reason = _text(args, "reason", limit=2_000) or None
    ttl = _int(args, "ttl_seconds", 300, 1, 900)
    requested_key = _text(args, "key_id", limit=64)

    monotonic_now = time.monotonic()
    # Count attempts, not only successful preparations. Otherwise an attacker
    # can force unlimited DB opens or manifest parsing with invalid proposals
    # while never consuming the rate budget.
    with service._challenge_lock:
        recent = service._challenge_times[principal.uid]
        cutoff = monotonic_now - service.CHALLENGE_WINDOW_SECONDS
        while recent and recent[0] <= cutoff:
            recent.popleft()
        if len(recent) >= service.CHALLENGES_PER_WINDOW:
            raise _Refusal(
                "operator challenge rate limit reached; retry after the "
                "bounded challenge window",
                code="rate_limited",
            )
        recent.append(monotonic_now)
    conn = _archive(service)
    try:
        if action == "grant.add":
            from .grants import _utc_instant
            if set(arguments) != {"class", "expires"}:
                raise _Refusal(
                    "grant.add requires exactly class and expires",
                    code="malformed",
                )
            arguments = {
                "class": arguments["class"],
                "expires": _utc_instant(arguments["expires"]).isoformat(
                    timespec="seconds"
                ),
            }
        elif action == "grant.revoke":
            from .grants import reduce_grants
            from .loops import scope_str
            if set(arguments) != {"grant"} or isinstance(
                arguments.get("grant"), bool
            ) or not isinstance(arguments.get("grant"), int):
                raise _Refusal(
                    "grant.revoke requires exactly an integer grant",
                    code="malformed",
                )
            grant = next(
                (item for item in reduce_grants(conn)["grants"]
                 if item["id"] == arguments["grant"]),
                None,
            )
            if grant is None:
                raise _Refusal("no such grant", code="not_found")
            scope = scope_str(grant["scope"])
        elif action in {
            "loop.confirm", "loop.close", "loop.reopen", "loop.dismiss"
        }:
            from .loops import reduce_loops, scope_str
            if set(arguments) != {"loop"} or isinstance(
                arguments.get("loop"), bool
            ) or not isinstance(arguments.get("loop"), int):
                raise _Refusal(
                    "loop transition requires exactly an integer loop",
                    code="malformed",
                )
            loop = reduce_loops(conn)["loops"].get(arguments["loop"])
            if loop is None:
                raise _Refusal("no such loop", code="not_found")
            scope = scope_str(loop["scope"])
        elif action == "archive.backup":
            if set(arguments) != {"destination", "keep"}:
                raise _Refusal(
                    "archive.backup requires exactly destination and keep",
                    code="malformed",
                )
            if (not isinstance(arguments["destination"], str)
                    or isinstance(arguments["keep"], bool)
                    or not isinstance(arguments["keep"], int)
                    or not 0 <= arguments["keep"] <= 1000):
                raise _Refusal("invalid backup intent", code="malformed")
            arguments = _backup_action_arguments(
                conn, arguments["destination"], arguments["keep"]
            )
        elif action == "archive.restore":
            from .backup import bundle_identity
            if set(arguments) != {"bundle", "destination"} or not all(
                isinstance(arguments[name], str)
                for name in ("bundle", "destination")
            ):
                raise _Refusal(
                    "archive.restore requires exactly bundle and destination",
                    code="malformed",
                )
            identity = bundle_identity(
                Path(arguments["bundle"]),
                destination=Path(arguments["destination"]),
                trust_store=None,
                legacy_policy=None,
            )
            arguments = _restore_action_arguments(identity)
        with service._challenge_lock:
            conn.execute(
                "DELETE FROM operator_nonces WHERE consumed_event IS NULL "
                "AND expires_at <= ?", (int(time.time()),)
            )
            conn.commit()
            outstanding = conn.execute(
                "SELECT COUNT(*) FROM operator_nonces "
                "WHERE consumed_event IS NULL"
            ).fetchone()[0]
            if outstanding >= service.MAX_OUTSTANDING_CHALLENGES:
                raise _Refusal(
                    "too many outstanding operator challenges; wait for one "
                    "to expire or complete it",
                    code="rate_limited",
                )
            keys = [key for key in registered_keys(conn) if not key["revoked"]]
            selected = next(
                (key for key in keys if key["key_id"] == requested_key), None
            ) if requested_key else (keys[-1] if keys else None)
            if selected is None:
                raise _Refusal(
                    "no active operator key matches this challenge",
                    code="attestation",
                )
            prepared = prepare_action(
                selected["key_id"], action, scope=scope,
                arguments=arguments, content=content, reason=reason,
                ttl_seconds=ttl, conn=conn,
            )
        return {
            **prepared,
            "signer": selected["signer"],
            "signer_tag": selected["signer_tag"],
        }
    except BackupError as exc:
        raise _Refusal(
            "backup/restore intent failed authenticated preflight",
            code="policy",
        ) from exc
    except (AttestationError, GrantError) as exc:
        raise _Refusal(f"challenge refused: {exc}", code="attestation") from exc
    finally:
        conn.close()


def op_operator_keys(service, principal, tier, args):
    from .attest import registered_keys

    conn = _archive(service)
    try:
        return {"keys": registered_keys(conn)}
    finally:
        conn.close()


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


def op_recall(service, principal, tier, args):
    from .gate import GateError, assemble
    conn = _archive(service)
    try:
        return assemble(
            conn, load_config(), _text(args, "query"),
            budget=_int(args, "budget", 8000, 1, 200_000),
            purpose=_text(args, "purpose", limit=512),
            since=_text(args, "since", limit=64),
            until=_text(args, "until", limit=64),
            client=_text(args, "client", "rpc", limit=64),
        )
    except GateError as exc:
        raise _Refusal(str(exc), code="gate") from exc
    finally:
        conn.close()


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


def op_note(service, principal, tier, args):
    """An unverified note. Never operator-authoritative, whatever the caller
    calls itself."""
    from .ingest import ingest_note
    conn = _archive(service)
    try:
        return {"event": ingest_note(
            conn, _text(args, "text", limit=100_000),
            claimed_client=_text(args, "client", "rpc", limit=64))}
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


def op_decision_supersede(service, principal, tier, args):
    from .decisions import DecisionError, record_supersession
    from .grants import GrantError, require_grant
    conn = _archive(service)
    try:
        grant = require_grant(conn, "decision.supersede", None)
        result = record_supersession(
            conn, _int(args, "old", low=1), _int(args, "new", low=1),
            reason=_text(args, "reason", limit=2000), client="rpc",
            grant=grant["id"])
        return {"result": result["result"], "edge": result["edge"]["edge"],
                "grant": grant["id"]}
    except (GrantError, DecisionError) as exc:
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


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

def inspect_deployment(root: Path | None = None) -> dict:
    """What the doctor needs to know about the on-disk boundary.

    Reports facts, not verdicts: ownership and modes of the archive, socket,
    and installed code. `contextd/doctor.py` turns these into pass/fail.
    """
    root = root or home()
    out = {"uid": os.getuid(), "root": str(root)}

    def describe(path: Path) -> dict:
        try:
            info = os.stat(path)
        except OSError:
            return {"exists": False}
        return {"exists": True, "uid": info.st_uid, "gid": info.st_gid,
                "mode": oct(stat.S_IMODE(info.st_mode)),
                "owned_by_caller": info.st_uid == os.getuid()}

    out["archive"] = describe(root / "contextd.db")
    out["socket"] = describe(socket_path(root))
    out["installed_code"] = describe(Path("/usr/local/libexec/contextd"))
    out["service_uid_present"] = _service_account_exists()
    return out


def _service_account_exists() -> bool:
    try:
        import pwd
        pwd.getpwnam("_contextd")
        return True
    except (KeyError, ImportError):
        return False


def main(argv=None) -> int:
    """Run the daemon in the foreground. Installation is a separate,
    operator-performed step (docs/DEPLOYMENT.md §4)."""
    import argparse
    import signal

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--socket", default=None)
    args = parser.parse_args(argv)

    service = AuthorityService(path=args.socket)
    service.start()
    print(json.dumps({"listening": str(service.path), "uid": os.getuid(),
                      "operations": sorted(OPERATIONS)}))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        stop.wait()
    finally:
        service.stop()
    return 0
