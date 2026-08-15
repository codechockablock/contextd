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
import traceback
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

    # --- unauthenticated, deliberately contentless ----------------------
    "ping": Operation("op_ping", TIER_MODEL,
                      summary="liveness; returns no archive state"),
    "capabilities": Operation("op_capabilities", TIER_MODEL,
                              summary="the ops THIS connection may call"),
}


def socket_path(root: Path | None = None) -> Path:
    configured = ((load_config().get("security") or {}).get("socket") or "").strip()
    if configured:
        return Path(configured).expanduser()
    return (root or home()) / SOCKET_NAME


def hardened() -> bool:
    """Whether this archive is configured to require the authority plane."""
    return ((load_config().get("security") or {}).get("mode") or
            "development") == "hardened"


# --- the service process ----------------------------------------------------

#: Set only inside the daemon process, before it opens the archive. It is a
#: *marker*, not a security control: a hostile same-UID process can set it too.
#: The real boundary in a hardened deployment is filesystem ownership — the DB
#: is owned by the service UID and mode 0600, so a client cannot open it at all.
#: This flag exists so development mode can simulate the boundary and so the
#: failure is a clear refusal instead of an opaque permission error.
_SERVICE_PROCESS = threading.local()


def is_service_process() -> bool:
    return getattr(_SERVICE_PROCESS, "value", False)


class service_context:
    """Mark the current thread as the authority plane."""

    def __enter__(self):
        self._previous = getattr(_SERVICE_PROCESS, "value", False)
        _SERVICE_PROCESS.value = True
        return self

    def __exit__(self, *_exc):
        _SERVICE_PROCESS.value = self._previous


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
    return sorted(n for n, op in OPERATIONS.items() if op.tier == TIER_MODEL)


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

    # -- lifecycle --------------------------------------------------------
    #: `sun_path` is 104 bytes on macOS and 108 on Linux. Exceeding it fails
    #: with a bare EINVAL/ENAMETOOLONG that reads like a bug in the caller, so
    #: it is checked here with the actual limit named.
    MAX_SOCKET_PATH = 100

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
        if operation.tier == TIER_OPERATOR and tier != TIER_OPERATOR:
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
                       **covered):
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
        authorization = verify_action(action_map, bytes.fromhex(signature))
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

def op_ping(service, principal, tier, args):
    return {"ok": True, "protocol": 1, "tier": tier}


def op_capabilities(service, principal, tier, args):
    return {
        "tier": tier,
        "operations": allowed_operations(tier),
        "principal": {"uid": principal.uid, "kind": principal.kind},
    }


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
    from .ingest import ingest_note
    text = _text(args, "text", limit=100_000)
    authorization = _needs_attestation(args, "note.deliberate", "global",
                                       content=text)
    conn = _archive(service)
    try:
        return {"event": ingest_note(conn, text, authorization=authorization,
                                     claimed_client="operator-cli")}
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


def op_raw_read(service, principal, tier, args):
    """Unredacted event content. The one read that bypasses the gate, and
    therefore the one that always requires an attestation."""
    event_id = _int(args, "event_id", low=1)
    _needs_attestation(args, "archive.raw_read", "global",
                       arguments={"event_id": event_id})
    conn = _archive(service)
    try:
        row = conn.execute(
            "SELECT id, ts, source, kind, uri, content, meta FROM events "
            "WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            raise _Refusal(f"no event #{event_id}", code="not_found")
        return {k: row[k] for k in row.keys()}
    finally:
        conn.close()


def op_backup(service, principal, tier, args):
    from .backup import create_backup
    destination = _text(args, "destination", limit=4096)
    _needs_attestation(args, "archive.backup", "global",
                       arguments={"destination": destination})
    conn = _archive(service)
    try:
        result = create_backup(conn, home(), Path(destination),
                               keep=_int(args, "keep", 0, 0, 1000))
        return {"bundle": str(result["bundle"]), "events": result.get("events")}
    finally:
        conn.close()


def op_restore(service, principal, tier, args):
    from .backup import restore_backup
    bundle = _text(args, "bundle", limit=4096)
    destination = _text(args, "destination", limit=4096)
    _needs_attestation(args, "archive.restore", "global",
                       arguments={"bundle": bundle, "destination": destination})
    return restore_backup(Path(bundle), Path(destination))


def op_export(service, principal, tier, args):
    """Hardened export requires an explicitly configured recovery recipient.

    None has been selected, so this refuses rather than emitting plaintext
    outside service-owned storage (docs/SECURITY.md §8).
    """
    _needs_attestation(args, "archive.export", "global")
    recipient = ((load_config().get("security") or {}).get("export_recipient")
                 or "").strip()
    if not recipient:
        raise _Refusal(
            "export refuses: hardened mode requires an explicitly configured "
            "recovery recipient, and none is set. Plaintext export outside "
            "service-owned storage is not a fallback.",
            code="policy",
        )
    raise _Refusal("encrypted export is not implemented", code="unimplemented")


def op_grant_add(service, principal, tier, args):
    from .grants import GrantError, add_grant
    from .loops import make_scope
    cls = _text(args, "class", limit=64)
    repo = _text(args, "scope_repo", limit=4096)
    expires = _text(args, "expires", limit=64)
    scope = make_scope(repo or None)
    from .loops import scope_str
    authorization = _needs_attestation(
        args, "grant.add", scope_str(scope),
        arguments={"class": cls, "expires": expires},
        content=_text(args, "reason", limit=2000) or None,
        reason=_text(args, "reason", limit=2000))
    conn = _archive(service)
    try:
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
            args, "grant.revoke", scope_str(grant["scope"]),
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
    from .attest import AttestationError, SIGNER_SECURE_ENCLAVE, register_key
    der_hex = _text(args, "public_der", limit=8192)
    _needs_attestation(args, "security.key_register", "global",
                       arguments={"public_der": der_hex})
    conn = _archive(service)
    try:
        return {"key_id": register_key(bytes.fromhex(der_hex),
                                       SIGNER_SECURE_ENCLAVE, conn=conn)}
    except (AttestationError, ValueError) as exc:
        raise _Refusal(str(exc), code="refused") from exc
    finally:
        conn.close()


def op_key_revoke(service, principal, tier, args):
    from .attest import revoke_key
    key_id = _text(args, "key_id", limit=128)
    _needs_attestation(args, "security.key_revoke", "global",
                       arguments={"key_id": key_id})
    conn = _archive(service)
    try:
        revoke_key(key_id, conn=conn)
        return {"revoked": key_id}
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
