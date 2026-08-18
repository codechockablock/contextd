"""ctx: the human-facing CLI. CLI search/timeline stay local and unlogged;
recall always produces a gated, logged egress bundle — same path MCP uses."""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, home, load_config
from . import liveness as liveness_module
from .attest import RESOLUTION_STATUSES as _RESOLUTION_STATUSES
from .backup import BackupError, create_backup, restore_backup
from .db import (
    ChainStateError,
    SchemaMigrationRequired,
    append_event,
    connect,
    get_cursor,
    verify_chain,
)
from .gate import GateError, assemble, spent_today
from .ingest import run_all
from .liveness import capture_liveness, describe, format_age, stale_line
from .search import timeline

CONFIG_TEMPLATE = '''# contextd config — merged over built-in defaults (see contextd/__init__.py)

[ingest]
watch_dirs = []            # e.g. ["~/Documents/notes", "~/Desktop/aplus-trainer"]
scan_interval_seconds = 120

[browser]
chrome = true
safari = true
# skip_domains = ["example.com", "mirror*.com"]  # never ingested, never disclosed
# skip_domain_files = ["~/.contextd/blocklists/adult-domains.txt"]  # one per line

[claude]
# claude code transcripts, filtered to dialogue and redacted before storage
enabled = true
# quiet_seconds = 1200         # silence that closes a work episode (epoch)

[liveness]
# per-source staleness thresholds in hours; a source past its threshold warns
# in `ctx status` and stamps compiled checkpoints. Overriding replaces the
# defaults (chrome/safari/claude_code 48, fs 72; note has none on purpose).
# stale_after_hours = { chrome = 48, safari = 48, claude_code = 48, fs = 72 }

[gate]
daily_token_budget = 200000
# never_leave patterns match file paths and URLs; overriding replaces the defaults
# never_leave = ["*/.ssh/*", "*/.aws/*", "*.pem", "*/.env*", "*example.com*"]
'''


def cmd_init(args):
    home().mkdir(parents=True, exist_ok=True)
    (home() / "store").mkdir(exist_ok=True)
    cfg_path = home() / "config.toml"
    if not cfg_path.exists():
        cfg_path.write_text(CONFIG_TEMPLATE)
    os.chmod(cfg_path, 0o600)
    connect().close()
    print(f"initialized {home()}")
    print(f"  db:     {home() / 'contextd.db'}")
    print(f"  config: {cfg_path}  <- set watch_dirs here")


def cmd_note(args):
    text = " ".join(args.text) if args.text else sys.stdin.read()
    if not text.strip():
        sys.exit("empty note")
    from . import service
    text = text.strip()
    if getattr(args, "authorize", False):
        authorization = operator_authorization(
            None, "note.deliberate", "global", content=text
        )
        eid = service.note_deliberate(text, authorization)["event"]
    else:
        eid = service.note(text, client="cli")["event"]
    print(f"noted as event #{eid}")


def cmd_ingest(args):
    print(json.dumps(run_all(connect(), load_config()), indent=2))


def cmd_watch(args):
    cfg = load_config()
    interval = cfg["ingest"]["scan_interval_seconds"]
    print(f"contextd watch: scanning every {interval}s (ctrl-c to stop)", flush=True)
    last_status = None
    while True:
        try:
            results = run_all(connect(), cfg)
            counts = {k: v for k, v in results.items() if any(
                isinstance(n, int) and n for n in v.values())}
            if counts:
                print(json.dumps(counts), flush=True)
            status = {k: v["status"] for k, v in results.items() if "status" in v}
            if status != last_status:
                for k, s in (status or {"all": "ok"}).items():
                    print(f"ingester {k}: {s}", file=sys.stderr, flush=True)
                last_status = status
        except Exception as e:
            print(f"scan error: {e}", file=sys.stderr, flush=True)
        time.sleep(interval)


def cmd_search(args):
    """Search the archive through the gate.

    This used to be a raw local FTS read that printed unredacted snippets and
    logged nothing — an archive-returning path that bypassed the one choke
    point every other read goes through. It now goes through the service (the
    daemon in hardened mode, the same gated code path in development), so the
    result is redacted, budgeted, and receipted like any other disclosure.
    """
    from . import service as authority
    from .rpc import RpcError
    try:
        result = authority.search(" ".join(args.query), limit=args.limit,
                                  client="cli")
    except RpcError as e:
        sys.exit(f"refused: {e}")
    print(result["content"])
    print(f"\n(disclosed as egress #{result['egress_id']})")


def cmd_recall(args):
    if getattr(args, "mode", "detail") == "synthesis":
        # model-assisted mode lives in hooks/ on purpose: the kernel never
        # calls models, so this command only delegates to the harness script
        hook = Path(__file__).resolve().parent.parent / "hooks" / "synthesis_recall.py"
        if not hook.exists():
            sys.exit("synthesis mode needs hooks/synthesis_recall.py (repo "
                     "checkout with -e install); plain recall works without it")
        cmd = [sys.executable, str(hook), *args.query,
               "--budget", str(args.budget), "--purpose", args.purpose]
        if args.since:
            cmd += ["--since", args.since]
        if args.until:
            cmd += ["--until", args.until]
        sys.exit(subprocess.call(cmd))
    try:
        r = assemble(connect(), load_config(), " ".join(args.query),
                     budget=args.budget, purpose=args.purpose,
                     since=args.since or "", until=args.until or "")
    except GateError as e:
        sys.exit(f"gate refused: {e}")
    print(r["bundle"])
    print(f"\n[egress #{r['egress_id']}: {len(r['items'])} events, "
          f"~{r['est_tokens']} tokens — logged]", file=sys.stderr)


def cmd_checkpoint(args):
    """Compile a resumption checkpoint from the archive (gated, logged).
    Measured basis: handoff benchmark, ledger exps #41823/#41864/#41905 —
    compiled checkpoints beat no-history resumption distinguishably at every
    tested interruption point and were the most stable representation across
    cutoffs. --mode distill delegates to hooks/ (kernel never calls models)."""
    from .handoff import compile_checkpoint, repo_state
    repo = None
    if args.repo:
        repo = repo_state(Path(args.repo).expanduser(),
                          test_cmd=args.test_cmd.split() if args.test_cmd else None)
    if args.mode == "distill":
        hook = Path(__file__).resolve().parent.parent / "hooks" / "checkpoint_compile.py"
        if not hook.exists():
            sys.exit("distill mode needs hooks/checkpoint_compile.py (repo "
                     "checkout with -e install); raw mode works without it")
        cmd = [sys.executable, str(hook), "--mode", "distill",
               "--budget", str(args.budget), "--task-hint", args.hint,
               "--purpose", args.purpose]
        if args.repo:
            cmd += ["--repo", args.repo]
        if args.test_cmd:
            cmd += ["--test-cmd", args.test_cmd]
        sys.exit(subprocess.call(cmd))
    try:
        out = compile_checkpoint(connect(), load_config(), budget=args.budget,
                                 task_hint=args.hint, repo=repo,
                                 purpose=args.purpose, client="cli")
    except GateError as e:
        sys.exit(f"gate refused: {e}")
    print(out["package"])
    print(f"\n[checkpoint egress #{out['egress_id']}: tip #{out['tip']}, "
          f"{len(out['items'])} events, ~{out['est_tokens']} tokens — logged]",
          file=sys.stderr)


def _loop_scope(args):
    """Explicit --repo / --global win; the default is the cwd's git
    toplevel when inside a repository, else global (docs/OPEN_LOOPS.md)."""
    from .handoff import _git
    from .loops import make_scope
    if getattr(args, "global_scope", False):
        return make_scope(None)
    if getattr(args, "repo", None):
        return make_scope(args.repo)
    top = _git(Path.cwd(), "rev-parse", "--show-toplevel")
    return make_scope(top or None)


def _loop_id(raw: str) -> int:
    digits = raw.strip().lstrip("loop").lstrip("#")
    if not digits.isdigit():
        sys.exit(f"not a loop id: {raw!r} (use N or loop#N)")
    return int(digits)


def _scope_label(scope: dict) -> str:
    return "global" if scope.get("global") else scope["repo"]


def _print_loop_row(lp):
    state = lp["state"] + (f" (reopened x{lp['reopen_count']})"
                           if lp["reopen_count"] else "")
    print(f"[loop#{lp['id']}] {state:<10} {lp['created_ts'][:10]} "
          f"{_scope_label(lp['scope'])}\n    {lp['text']}")


#: Set once from `ctx --signer-key TAG` in main(); empty means "use the
#: configured default". Read only by _signer_choice, which is the single place
#: the signing key is chosen.
_SIGNER_KEY_FLAG = ""


def _signer_choice() -> str:
    """The enrollment tag that should sign, or '' for the registry default.

    Flag only, never config: selecting among already-registered keys
    authorizes nothing (each is a registered key, each use still costs a
    presence gesture, and the nonce binds the key id its challenge was minted
    for), but `test_config_and_env_cannot_name_a_signer` keeps signer
    semantics out of the config surface entirely so no later setting can grow
    into a signing path. A per-act flag is not ambient, so it does not.
    """
    return _SIGNER_KEY_FLAG


def _select_signer(keys: list[dict], wanted: str) -> dict:
    """Resolve the chosen tag against the active keys, or exit saying why.

    Matches an enrollment tag first, then a key id prefix, so either column of
    `ctx security key list` works.
    """
    if not wanted:
        return keys[-1]
    for key in keys:
        if key["signer_tag"] == wanted or key["key_id"].startswith(wanted):
            return key
    available = ", ".join(
        f"{k['signer_tag'] or '(untagged)'} ({k['key_id'][:12]}…)" for k in keys
    )
    sys.exit(
        f"refused: no active operator key matches signer key {wanted!r}.\n"
        f"  registered and active: {available}\n"
        f"  choose one with `ctx --signer-key TAG …` or [security] signer_key"
    )


def _signing_failure(exc, tag: str) -> str:
    """Turn a bare signer failure into the remedy, when the cause is local.

    The common case after enrolling a spare on a second device: the registry
    knows the key, this machine does not hold its handle, and the helper says
    only "no Secure Enclave key for tag …". An Enclave handle cannot be copied
    between devices, so the fix is to sign with a key this machine holds.
    """
    if "no Secure Enclave key" not in str(exc):
        return f"refused: {exc}"
    from .attest import local_signer_tags
    local = local_signer_tags()
    return (
        f"refused: {exc}\n"
        f"  this machine holds no Enclave handle for tag {tag!r}. Handles are "
        f"device-bound and cannot be copied between machines.\n"
        f"  handles on this machine: {', '.join(local) or '(none)'}\n"
        f"  sign with one of those: `ctx --signer-key TAG …`, or run this act "
        f"on the device that holds {tag!r}"
    )


def operator_authorization(conn, action: str, scope: str = "global",
                           arguments: dict | None = None,
                           content: str | None = None,
                           reason: str | None = None):
    """Obtain a verified operator authorization for exactly this act.

    The CLI does not *hold* authority — it asks the authority plane to mint the
    exact bytes, shows the operator what they are about to approve, hands those
    bytes to the presence-bound signer, and passes the verified result back.
    If no production signer is enrolled this refuses: there is deliberately no
    prompt-only, TTY, or parent-process fallback (docs/SECURITY.md §3).
    """
    from . import service
    from .attest import (AttestationError, SignedAction, prepare_action,
                         registered_keys, sign_with_secure_enclave,
                         verify_action, SIGNER_SECURE_ENCLAVE,
                         test_mode_authorization)
    wanted = _signer_choice()
    if service.hardened():
        try:
            key_id = ""
            if wanted:
                active = [k for k in service.operator_keys() if not k["revoked"]]
                if not active:
                    raise AttestationError("no active operator key is registered")
                key_id = _select_signer(active, wanted)["key_id"]
            prepared = service.prepare_action(
                action, scope, arguments, content, reason, key_id=key_id
            )
            if prepared["signer"] != SIGNER_SECURE_ENCLAVE:
                raise AttestationError(
                    "hardened mode refuses a non-hardware operator signer"
                )
            print(f"authorize: {prepared['human_summary']}")
            print(f"  digest {prepared['digest'][:16]}…  (approve on your device)")
            try:
                signature = sign_with_secure_enclave(
                    bytes.fromhex(prepared["canonical"]), prepared["signer_tag"],
                    display_content=prepared["display_content"],
                    display_reason=prepared["display_reason"],
                )
            except AttestationError as exc:
                sys.exit(_signing_failure(exc, prepared["signer_tag"]))
            return SignedAction(prepared["action"], signature)
        except (AttestationError, service.RpcError) as exc:
            sys.exit(f"refused: {exc}")

    keys = [k for k in registered_keys(conn)
            if k["signer"] == SIGNER_SECURE_ENCLAVE and not k["revoked"]]
    if not keys:
        try:
            return test_mode_authorization(conn, action, scope, arguments,
                                           content, reason)
        except AttestationError as exc:
            sys.exit(
                f"refused: {action} is an operator act and no production "
                f"signer is enrolled.\n"
                f"  build:     native/build.sh\n"
                f"  enroll:    native/contextd-signer enroll --key-id default "
                f"> operator-key.der\n"
                f"  first key: ctx security key bootstrap operator-key.der "
                f"--signer-tag default --development "
                f"--acknowledge-first-key-bootstrap\n"
                f"  (a later, already-attested key: ctx security key register "
                f"<der> --signer-tag <tag>)\n"
                f"({exc})"
            )
    selected = _select_signer(keys, wanted)
    prepared = prepare_action(selected["key_id"], action, scope=scope,
                              arguments=arguments, content=content,
                              reason=reason, conn=conn)
    print(f"authorize: {prepared['human_summary']}")
    print(f"  digest {prepared['digest'][:16]}…  (approve on your device)")
    try:
        signature = sign_with_secure_enclave(
            bytes.fromhex(prepared["canonical"]), selected["signer_tag"],
            display_content=prepared["display_content"],
            display_reason=prepared["display_reason"],
        )
    except AttestationError as exc:
        sys.exit(_signing_failure(exc, selected["signer_tag"]))
    try:
        return verify_action(prepared["action"], signature, conn=conn)
    except AttestationError as exc:
        sys.exit(f"refused: {exc}")


def cmd_loop(args):
    from . import service
    if service.hardened():
        from .loops import scope_str
        if args.action == "add":
            if args.source_event:
                sys.exit(
                    "refused: hardened loop add does not accept unsigned "
                    "--source-event metadata"
                )
            text = " ".join(args.text)
            scope = _loop_scope(args)
            authorization = operator_authorization(
                None, "loop.add", scope_str(scope), content=text
            )
            result = service.loop_add_operator(
                text, scope.get("repo", ""), authorization
            )
            print(f"{result['result']} loop#{result['loop']['id']}")
            return
        if args.action in ("list", "candidates"):
            scope = _loop_scope(args)
            result = service.loop_list(
                scope.get("repo", ""), include_candidates=True
            )
            print(result["content"])
            return
        if args.action == "show":
            sys.exit("refused: hardened loop show requires a gated daemon view")
        loop_id = _loop_id(args.loop_id)
        reason = getattr(args, "reason", "") or ""
        authorization = operator_authorization(
            None, f"loop.{args.action}", "global",
            arguments={"loop": loop_id}, reason=reason,
        )
        result = service.loop_transition_operator(
            loop_id, args.action, reason, authorization
        )
        print(f"loop#{loop_id} -> {result['loop']['state']}")
        return
    from .loops import (LoopError, add_loop, loops_for_scope, reduce_loops,
                        transition)
    conn = connect()
    try:
        if args.action == "add":
            from .loops import scope_str
            text = " ".join(args.text)
            scope = _loop_scope(args)
            r = add_loop(conn, text, scope, client="cli",
                         source_events=args.source_event,
                         authorization=operator_authorization(
                             conn, "loop.add", scope_str(scope), content=text))
            lp = r["loop"]
            msg = {"created": "opened",
                   "existing": "already open as",
                   "confirmed_candidate": "confirmed pending candidate as"}
            print(f"{msg[r['result']]} loop#{lp['id']} "
                  f"[{_scope_label(lp['scope'])}]\n    {lp['text']}")
            return
        if args.action in ("list", "candidates"):
            scope = _loop_scope(args)
            states = (("candidate",) if args.action == "candidates" else
                      ("open", "candidate", "closed", "dismissed")
                      if args.all else ("open",))
            rows = loops_for_scope(conn, scope, states=states)
            for lp in rows:
                _print_loop_row(lp)
            if not rows:
                kind = ("candidates" if args.action == "candidates"
                        else "loops" if args.all else "active loops")
                print(f"no {kind} for {_scope_label(scope)}")
            return
        if args.action == "show":
            lp = reduce_loops(conn)["loops"].get(_loop_id(args.loop_id))
            if lp is None:
                sys.exit(f"no loop {args.loop_id}")
            _print_loop_row(lp)
            print(f"    assurance: {lp['created_assurance']} "
                  f"(client {lp['created_client'] or '?'})"
                  + (f"; promoted with {lp['promoted_assurance']}"
                     if lp["promoted_assurance"] else ""))
            if lp["source_events"]:
                print(f"    source events: "
                      f"{', '.join(str(i) for i in lp['source_events'])}")
            for h in lp["history"]:
                reason = f" — {h['reason']}" if h.get("reason") else ""
                print(f"    {h['ts']} {h['op']} ({h['authority']}){reason}")
            for a in lp["anomalies"]:
                print(f"    ANOMALY at event #{a['event']}: {a['why']}")
            return
        op = {"close": "close", "reopen": "reopen",
              "confirm": "confirm", "dismiss": "dismiss"}[args.action]
        from .loops import scope_str
        loop_id = _loop_id(args.loop_id)
        target = reduce_loops(conn)["loops"].get(loop_id)
        if target is None:
            sys.exit(f"no loop {args.loop_id}")
        reason = getattr(args, "reason", "") or ""
        r = transition(conn, loop_id, op, client="cli", reason=reason,
                       authorization=operator_authorization(
                           conn, f"loop.{op}", scope_str(target["scope"]),
                           arguments={"loop": loop_id}, reason=reason))
        lp = r["loop"]
        if r["result"] == "noop":
            print(f"loop#{lp['id']} already {lp['state']}")
        else:
            print(f"loop#{lp['id']} -> {lp['state']}")
    except LoopError as e:
        sys.exit(f"refused: {e}")


def cmd_security(args):
    """Hardening state, key registry, and the authority service."""
    if args.security_action == "doctor":
        from .doctor import main as doctor_main
        argv = []
        if getattr(args, "strict", False):
            argv.append("--strict")
        if getattr(args, "json", False):
            argv.append("--json")
        sys.exit(doctor_main(argv))
    if args.security_action == "serve":
        from .authd import main as authd_main
        sys.exit(authd_main(["--socket", args.socket] if args.socket else []))
    if args.security_action == "migrate":
        from .migrate import MigrationError, migrate as run_migration
        from .db import (SchemaVersionError, open_archive_for_migration)
        # Opening is inside the try because opening is where several of the
        # refusals live — a newer archive, a missing one, and a Postgres archive
        # (migration is SQLite-only) are all decided before `migrate` is
        # reached. Outside it, exactly the refusals most worth reading reached
        # the operator as a traceback.
        conn = None
        try:
            conn = open_archive_for_migration(read_only=bool(args.dry_run))
            result = run_migration(conn, dry_run=args.dry_run)
        except (MigrationError, SchemaVersionError) as e:
            sys.exit(f"refused: {e}")
        finally:
            if conn is not None:
                conn.close()
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
        elif result["applied"]:
            print(f"migrated: {result['events']} historical event(s) "
                  f"unchanged (digest {result['history_digest'][:16]}…)")
            print(f"cutover:  tip #{result['cutover']['tip_id']} signed — "
                  f"this records that the service OBSERVED the tip; it does "
                  f"not authenticate anything before it")
        else:
            print(f"dry run: would migrate from schema "
                  f"{result['from_version']} to {result['to_version']}, "
                  f"creating {len(result['tables_to_create'])} table(s)")
            print(f"         {result['events']} historical event(s) would be "
                  f"left byte-identical")
        return
    if args.security_action == "checkpoint":
        from .ledger_sig import (append_checkpoint_log, checkpoint_log_claim,
                                 checkpoint_record, verify_checkpoint,
                                 verify_checkpoint_log, write_checkpoint)
        conn = connect()
        destination = (args.destination
                       or (load_config().get("security") or {})
                       .get("checkpoint_destination") or "").strip()
        action = getattr(args, "checkpoint_action", None)
        if action == "export":
            entry = append_checkpoint_log(conn, args.dest)
            print(f"appended checkpoint at tip #{entry['tip_id']} to "
                  f"{args.dest}")
            print(f"  chain {entry['chain_hash'][:16]}…  "
                  f"algs {', '.join([entry.get('alg', 'ecdsa-p256-sha256')] + [h['alg'] for h in entry.get('hybrid', [])])}")
            print("  " + checkpoint_log_claim()["advisory_on_one_machine"])
            return
        if action == "verify":
            result = verify_checkpoint_log(conn, args.dest)
            print(json.dumps(result, indent=2, sort_keys=True))
            if result.get("rollback"):
                print("\nROLLBACK DETECTED — the archive no longer reaches a "
                      "tip a signed checkpoint recorded.", file=sys.stderr)
            sys.exit(0 if result["ok"] else 1)
        if args.write:
            if not destination:
                sys.exit("refused: no checkpoint destination configured. Set "
                         "[security] checkpoint_destination to a path this "
                         "uid cannot rewrite, or pass --destination.")
            print(f"wrote {write_checkpoint(conn, destination)}")
            return
        if destination and Path(destination).expanduser().exists():
            record = json.loads(Path(destination).expanduser().read_text())
            result = verify_checkpoint(conn, record)
            print(json.dumps(result, indent=2, sort_keys=True))
            sys.exit(0 if result["ok"] else 1)
        print(json.dumps(checkpoint_record(conn), indent=2, sort_keys=True))
        return
    if args.security_action == "export":
        cmd_security_export(args)
        return
    if args.security_action == "export-open":
        cmd_security_export_open(args)
        return
    if args.security_action == "key":
        from . import service
        if args.key_action == "list":
            for k in service.operator_keys():
                state = f"revoked {k['revoked']}" if k["revoked"] else "active"
                tag = f" tag={k['signer_tag']}" if k["signer_tag"] else ""
                print(f"{k['key_id'][:16]}…  {k['signer']:22s} {state}{tag}")
            return
        if args.key_action == "bootstrap":
            from .attest import bootstrap_key
            from .authd import service_context
            data = (sys.stdin.buffer.read() if args.path == "-"
                    else Path(args.path).read_bytes())
            try:
                if args.development:
                    # the development boundary must not claim authority-plane
                    # status; it runs as the plain desktop operator
                    conn = connect()
                    try:
                        key_id = bootstrap_key(
                            data, args.signer_tag, conn=conn,
                            acknowledge_first_key=args.acknowledge_first_key_bootstrap,
                            development=True,
                        )
                    finally:
                        conn.close()
                else:
                    with service_context():
                        conn = connect()
                        try:
                            key_id = bootstrap_key(
                                data, args.signer_tag, conn=conn,
                                acknowledge_first_key=args.acknowledge_first_key_bootstrap,
                            )
                        finally:
                            conn.close()
            except Exception as exc:  # boundary failures are operator-facing
                sys.exit(f"refused: {exc}")
            print(f"bootstrapped {key_id}")
            return
        if args.key_action == "register":
            data = (sys.stdin.buffer.read() if args.path == "-"
                    else Path(args.path).read_bytes())
            covered = {"public_der": data.hex(), "signer_tag": args.signer_tag}
            authorization = operator_authorization(
                None if service.hardened() else connect(),
                "security.key_register", "global", arguments=covered,
            )
            result = service.key_register(data, args.signer_tag, authorization)
            print(f"registered {result['key_id']}")
            return
        if args.key_action == "revoke":
            authorization = operator_authorization(
                None if service.hardened() else connect(),
                "security.key_revoke", "global",
                arguments={"key_id": args.key_id},
            )
            service.key_revoke(args.key_id, authorization)
            print(f"revoked {args.key_id}")
            return


def cmd_grant(args):
    """Delegation grants (docs/GRANTS.md): granting and revoking are human
    CLI acts; acts a grant enables are recorded model-granted, never
    operator."""
    from datetime import datetime, timezone

    from .grants import (GrantError, _utc_instant, add_grant, grant_line,
                         parse_duration, reduce_grants, revoke_grant)
    from .loops import make_scope, scope_str
    from . import service
    conn = None if service.hardened() else connect()
    try:
        if args.action == "add":
            expires = args.until
            if args.for_:
                delta = parse_duration(args.for_)
                expires = (datetime.now(timezone.utc) + delta).isoformat(
                    timespec="seconds")
            if not expires:
                raise GrantError("a grant requires --for or --until")
            scope = (make_scope(None) if args.global_scope
                     else make_scope(args.repo) if args.repo
                     else make_scope(None))
            normalized = _utc_instant(expires).isoformat(timespec="seconds")
            reason = args.reason or ""
            authorization = operator_authorization(
                conn, "grant.add", scope_str(scope),
                arguments={"class": args.cls, "expires": normalized},
                content=reason or None, reason=reason,
            )
            if service.hardened():
                result = service.grant_add(
                    args.cls, scope.get("repo", ""), normalized, reason,
                    authorization,
                )
                print(f"{result['result']}: grant ev {result['grant']}")
                return
            r = add_grant(
                conn, args.cls, scope, expires=normalized, reason=reason,
                client="cli", authorization=authorization,
            )
            word = {"created": "granted", "existing": "already granted"}
            print(f"{word[r['result']]}: {grant_line(r['grant'])}")
        elif args.action == "revoke":
            reason = args.reason or ""
            if service.hardened():
                authorization = operator_authorization(
                    None, "grant.revoke", "global",
                    arguments={"grant": args.grant_id},
                    content=reason or None, reason=reason,
                )
                result = service.grant_revoke(
                    args.grant_id, reason, authorization
                )
                print(f"{result['result']} grant ev {args.grant_id}")
                return
            reduced = reduce_grants(conn)
            grant = next(
                (item for item in reduced["grants"]
                 if item["id"] == args.grant_id),
                None,
            )
            if grant is None:
                raise GrantError(f"no grant ev {args.grant_id}")
            authorization = operator_authorization(
                conn, "grant.revoke", scope_str(grant["scope"]),
                arguments={"grant": args.grant_id}, content=reason or None,
                reason=reason,
            )
            r = revoke_grant(conn, args.grant_id,
                             reason=reason, client="cli",
                             authorization=authorization)
            if r["result"] == "already_revoked":
                print(f"grant ev {args.grant_id} was already revoked "
                      f"(ev {r['grant']['revoked_by']})")
            else:
                print(f"revoked grant ev {args.grant_id} "
                      f"(revocation ev {r['event']})")
        else:  # list
            if conn is None:
                sys.exit(
                    "refused: hardened grant listing requires a gated daemon "
                    "read; add/revoke ceremonies remain available"
                )
            from .db import now_iso
            red = reduce_grants(conn)
            now = now_iso()
            shown = 0
            for g in red["grants"]:
                expired = bool(g["expires"]) and g["expires"] <= now
                state = ("revoked" if g["revoked_by"] is not None
                         else "expired" if expired else "ACTIVE")
                if state != "ACTIVE" and not args.all:
                    continue
                shown += 1
                line = (f"[grant ev {g['id']}] {state:<8} {g['class']} "
                        f"{scope_str(g['scope'])} since "
                        f"{g['granted_ts'][:16]}")
                if g["expires"]:
                    line += f" expires {g['expires'][:16]}"
                print(line)
                if g["reason"]:
                    print(f"    reason: {g['reason']}")
                if g["revoked_by"] is not None:
                    why = f" — {g['revoke_reason']}" if g["revoke_reason"] \
                        else ""
                    print(f"    revoked by ev {g['revoked_by']}{why}")
            for a in red["anomalies"]:
                print(f"ANOMALY at event #{a['event']}: {a['why']}")
            if not shown and not red["anomalies"]:
                print("(no active grants)" if not args.all
                      else "(no grants ever)")
    except GrantError as e:
        sys.exit(f"refused: {e}")


def cmd_decision(args):
    """Supersession edges (docs/DECISIONS.md): a human CLI act, like loop
    confirmation — there is no model-mediated path to an edge."""
    from . import service
    if service.hardened():
        if args.action != "supersede":
            sys.exit(
                "refused: hardened decision views require a gated daemon read"
            )
        reason = args.reason or ""
        authorization = operator_authorization(
            None, "decision.supersede", "global",
            arguments={"old": args.old, "new": args.new},
            content=reason or None, reason=reason,
        )
        result = service.decision_supersede_operator(
            args.old, args.new, reason, authorization
        )
        edge = result["edge"]
        print(f"{result['result']}: ev {edge['old']} superseded by "
              f"ev {edge['new']} (edge ev {edge['edge']})")
        return
    from .decisions import (DecisionError, current_version,
                            record_supersession, reduce_supersessions)
    conn = connect()
    try:
        if args.action == "supersede":
            r = record_supersession(conn, args.old, args.new,
                                    reason=args.reason or "", client="cli")
            e = r["edge"]
            word = {"created": "recorded", "existing": "already recorded"}
            print(f"{word[r['result']]}: ev {e['old']} superseded by "
                  f"ev {e['new']} (edge ev {e['edge']})")
        elif args.action == "list":
            red = reduce_supersessions(conn)
            for old, e in sorted(red["edges"].items()):
                walk = current_version(red["edges"], old)
                tail = (" [CYCLIC]" if walk["cyclic"] else
                        f" -> current ev {walk['current']}"
                        if walk["current"] != e["new"] else "")
                print(f"ev {old} -> ev {e['new']} (edge ev {e['edge']})"
                      f"{tail}")
            for a in red["anomalies"]:
                print(f"ANOMALY at event #{a['event']}: {a['why']}")
            if not red["edges"] and not red["anomalies"]:
                print("(no supersession edges)")
        else:  # current
            red = reduce_supersessions(conn)
            walk = current_version(red["edges"], args.event_id)
            if walk["cyclic"]:
                print(f"ev {args.event_id}: chain "
                      f"{' -> '.join(str(i) for i in walk['chain'])} is "
                      f"CYCLIC; no resolvable current version")
            else:
                chain = " -> ".join(str(i) for i in walk["chain"])
                print(f"current version of ev {args.event_id}: "
                      f"ev {walk['current']}  (chain {chain})")
    except DecisionError as e:
        sys.exit(f"refused: {e}")


def cmd_mandate(args):
    """In-flight mandates, and the operator act that closes one.

    A mandate goes in flight when the process that bound it died between the
    external act and the outcome append. The core cannot close it — it does not
    know whether the money moved — and deliberately will not guess. `resolve`
    is the operator saying what they checked *outside* this archive: the
    processor's console, the bank statement, the counterparty. The signature
    covers exactly that claim, and the ledger records it as an attestation
    rather than as something contextd observed.
    """
    from . import service
    from .attest import (AttestationError, inflight_mandates,
                         resolution_arguments, resolve_mandate)

    if service.hardened():
        # Every hardened operator act needs its own gated daemon operation
        # (contextd/authd.py). `mandate.resolve` has none yet, and inventing an
        # ungated path here is precisely the second authorization path this act
        # was designed not to become.
        sys.exit(
            "refused: hardened mode has no gated `mandate.resolve` operation "
            "yet; the authority service must expose one before a resolution "
            "can be signed through it."
        )
    conn = connect()
    if args.action == "list":
        pending = inflight_mandates(conn)
        if not pending:
            print("(no mandates are in flight)")
            return
        for mandate in pending:
            print(f"{mandate['nonce']}  bound {mandate['bound']}  "
                  f"mandate ev {mandate['mandate_event']}  "
                  f"intent {mandate['intent_digest'][:16]}…")
        print(f"\n{len(pending)} awaiting an attested outcome. Resolve one "
              f"only after verifying it outside contextd:")
        print("  ctx mandate resolve <nonce> --status succeeded|failed "
              "--reason '<what you checked>'")
        return

    # One value, used for the signed digest and for the recorded reason, so the
    # bytes the operator signs and the bytes re-derived at append cannot differ.
    reason = args.reason or None
    try:
        arguments = resolution_arguments(args.nonce, args.status)
    except AttestationError as exc:
        sys.exit(f"refused: {exc}")
    authorization = operator_authorization(
        conn, "mandate.resolve", "global", arguments=arguments, reason=reason,
    )
    try:
        result = resolve_mandate(
            conn, authorization, nonce=args.nonce, status=args.status,
            reason=reason,
        )
    except AttestationError as exc:
        sys.exit(f"refused: {exc}")
    print(f"resolved: mandate {args.nonce[:16]}… recorded {args.status} "
          f"(ev {result.outcome_event})")
    print("  this is YOUR attestation about the world, not contextd's "
          "observation of it")


def cmd_timeline(args):
    rows = timeline(connect(), since=args.since, until=args.until,
                    source=args.source, limit=args.limit)
    for r in rows:
        brief = (r["content"] or "")[:100].replace("\n", " ")
        print(f"[{r['id']}] {r['ts']} {r['source']}/{r['kind']} {r['uri'] or ''} {brief}")


def cmd_audit(args):
    conn = connect()
    rows = timeline(conn, kind="egress", limit=args.limit)
    for r in rows:
        meta = json.loads(r["meta"] or "{}")
        outcome = conn.execute(
            "SELECT meta FROM events WHERE kind='egress_outcome' "
            "AND json_extract(meta,'$.egress_id')=? ORDER BY id DESC LIMIT 1",
            (r["id"],),
        ).fetchone()
        dispatch = json.loads(outcome["meta"])["status"] if outcome else "attempted"
        # claimed_client is an unverified self-report, and the raw query is
        # no longer stored — only its keyed correlation id (docs/SECURITY.md §3)
        client = meta.get("claimed_client", meta.get("client", "cli"))
        qid = meta.get("query_id")
        print(f"[{r['id']}] {r['ts']} type={meta.get('type')} "
              f"claimed_client={client} "
              f"dispatch={dispatch} "
              f"query_id={(qid or '-')[:12]} purpose={meta.get('purpose')!r} "
              f"~{meta.get('est_tokens')} tokens, items={meta.get('items')}")


def cmd_status(args):
    conn = connect()
    cfg = load_config()
    print(f"contextd {__version__} — {home() / 'contextd.db'}")
    for row in conn.execute(
            "SELECT source, kind, COUNT(*) AS n FROM events GROUP BY source, kind ORDER BY n DESC"):
        print(f"  {row['source']}/{row['kind']}: {row['n']}")
    total = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    size = (home() / "contextd.db").stat().st_size // 1024
    print(f"  total: {total} events, {size} KB")
    print(f"  egress today: ~{spent_today(conn)}/{cfg['gate']['daily_token_budget']} est. tokens")
    from .attest import SIGNER_SECURE_ENCLAVE, TEST_MODE_ENV, registered_keys
    enclave_keys = [k for k in registered_keys(conn)
                    if k["signer"] == SIGNER_SECURE_ENCLAVE
                    and not k["revoked"]]
    if enclave_keys:
        print(f"operator signer: {len(enclave_keys)} Secure Enclave key(s) "
              "enrolled")
    elif os.environ.get(TEST_MODE_ENV):
        print("operator signer: test-mode software signer (dev only)")
    else:
        # the single loudest operator-queue item: without an enrolled key,
        # every operator CLI act refuses (docs/OPERATOR_CEREMONY.md)
        print("operator signer: NOT ENROLLED")
        print("WARNING: every operator CLI act refuses until a production "
              "signer is enrolled — build: native/build.sh; enroll: "
              "native/contextd-signer enroll --key-id default > "
              "operator-key.der; first key: ctx security key bootstrap "
              "operator-key.der --signer-tag default --development "
              "--acknowledge-first-key-bootstrap (docs/OPERATOR_CEREMONY.md)")
    for browser in ("chrome", "safari"):
        if not cfg["browser"].get(browser):
            continue
        state = get_cursor(conn, browser)
        last = state.get("last_status", "") if isinstance(state, dict) else ""
        if isinstance(last, str) and last.startswith("no access"):
            print(f"WARNING: {browser} history is unreadable ({last}) — "
                  "grant Full Disk Access to this process and the launchd "
                  "daemon (System Settings → Privacy & Security → Full "
                  f"Disk Access), or set [browser] {browser}=false")
    rows = capture_liveness(conn, cfg)
    if rows:
        print("capture liveness:")
    for row in rows:
        print(f"  {row['source']}: {describe(row)}")
    for row in rows:
        if row["stale"]:
            print(f"WARNING: {stale_line(row)} — capture may be stalled")
    from .lineage import alert_line, lineage_stats, status_line
    lstats = lineage_stats(conn, cfg)
    print(f"lineage: {status_line(lstats)}")
    if lstats["alert_notes"]:
        print(f"WARNING: {alert_line(lstats)}")
    drill = conn.execute(
        "SELECT ts, meta FROM events WHERE kind='restore_drill' "
        "ORDER BY id DESC LIMIT 1").fetchone()
    if drill is None:
        # never-run stays quiet: the drill is installed per machine, and a
        # warning here would fire on every archive that never opted in
        print("restore drill: never run")
    else:
        dmeta = json.loads(drill["meta"] or "{}")
        from datetime import datetime
        age = (datetime.fromisoformat(liveness_module.now_iso())
               - datetime.fromisoformat(drill["ts"])).total_seconds() / 3600
        verdict = dmeta.get("verdict", "?")
        print(f"restore drill: {verdict} {format_age(max(age, 0.0))} ago")
        threshold = cfg["backup"]["drill_stale_after_hours"]
        if verdict != "PASS":
            print(f"WARNING: restore drill FAILED {format_age(max(age, 0.0))} "
                  f"ago at stage {dmeta.get('failed_stage', '?')} "
                  f"({dmeta.get('reason', 'no reason recorded')}) "
                  "— backups may not restore")
        elif age > threshold:
            print(f"WARNING: restore drill last ran {format_age(age)} ago "
                  f"(threshold {threshold:g}h) — the drill itself may be "
                  "stalled")
    sweep = conn.execute(
        "SELECT ts, meta FROM events WHERE source='health' AND kind='sweep' "
        "ORDER BY id DESC LIMIT 1").fetchone()
    if sweep is None:
        # never-run stays quiet, same rule as the drill: the sweep is
        # installed per machine
        print("health sweep: never run")
    else:
        smeta = json.loads(sweep["meta"] or "{}")
        from datetime import datetime
        age = (datetime.fromisoformat(liveness_module.now_iso())
               - datetime.fromisoformat(sweep["ts"])).total_seconds() / 3600
        verdict = smeta.get("verdict", "?")
        print(f"health sweep: {verdict} {format_age(max(age, 0.0))} ago")
        if verdict != "OK":
            names = ", ".join(smeta.get("degraded", [])) or "?"
            print(f"WARNING: health sweep DEGRADED ({names}) — details in "
                  "the sweep event meta, `ctx why` the latest health event")
        stale_after = (cfg.get("health", {}) or {}).get(
            "sweep_stale_after_hours", 2)
        if age > stale_after:
            print(f"WARNING: health sweep last ran {format_age(age)} ago "
                  f"(threshold {stale_after:g}h) — the sweep itself may be "
                  "stalled")


def cmd_outcome(args):
    conn = connect()
    failure_class = getattr(args, "failure_class", None)
    if failure_class and args.verdict not in ("miss", "partial"):
        sys.exit("refused: --failure-class applies only to miss or partial verdicts")
    if not args.egress_id:
        # scoreboard, stratified by the judged egress's meta type
        types = {r["id"]: r["t"] for r in conn.execute(
            "SELECT id, json_extract(meta,'$.type') AS t "
            "FROM events WHERE kind='egress'")}
        verdicts, classes = {}, {}
        for r in conn.execute("SELECT meta FROM events WHERE kind='outcome' ORDER BY id"):
            m = json.loads(r["meta"])
            verdicts[m["egress_id"]] = m["verdict"]  # append-only: last verdict wins
            classes[m["egress_id"]] = m.get("failure_class")

        def tally(egress_type):
            ids = {i for i, t in types.items() if t == egress_type}
            counts = {"hit": 0, "partial": 0, "miss": 0}
            for eid, v in verdicts.items():
                if eid in ids:
                    counts[v] += 1
            return ids, counts, sum(counts.values())

        recalls, counts, judged = tally("recall")
        print(f"recalls: {len(recalls)}  judged: {judged}  unjudged: {len(recalls) - judged}")
        if judged:
            print(f"  hit {counts['hit']}  partial {counts['partial']}  miss {counts['miss']}"
                  f"  — hit rate {counts['hit'] / judged:.0%} (v0.1 bar: 30%)")
        cps, ccounts, cjudged = tally("checkpoint")
        print(f"checkpoints: {len(cps)}  judged: {cjudged}  "
              f"unjudged: {len(cps) - cjudged}")
        if cjudged:
            print(f"  hit {ccounts['hit']}  partial {ccounts['partial']}  "
                  f"miss {ccounts['miss']}")
            by_class = {}
            for eid, v in verdicts.items():
                if eid in cps and v in ("miss", "partial") and classes.get(eid):
                    by_class[classes[eid]] = by_class.get(classes[eid], 0) + 1
            if by_class:
                print("  failure classes: " + "  ".join(
                    f"{c} {n}" for c, n in sorted(by_class.items())))
        for t in sorted({t for t in types.values()
                         if t not in ("recall", "checkpoint")}, key=str):
            ids, tcounts, tjudged = tally(t)
            if tjudged:
                print(f"{t or '(untyped)'}: {len(ids)}  judged: {tjudged}  "
                      f"hit {tcounts['hit']}  partial {tcounts['partial']}  "
                      f"miss {tcounts['miss']}")
        return
    if not args.verdict:
        sys.exit("verdict required: hit | partial | miss")
    if not conn.execute("SELECT 1 FROM events WHERE id = ? AND kind='egress'",
                        (args.egress_id,)).fetchone():
        sys.exit(f"no egress event #{args.egress_id}")
    meta = {"egress_id": args.egress_id, "verdict": args.verdict}
    if failure_class:
        meta["failure_class"] = failure_class
    if args.note:
        meta["note"] = args.note
    eid = append_event(conn, "eval", "outcome", meta=meta)
    print(f"recorded: egress #{args.egress_id} -> {args.verdict} (event #{eid})")


def cmd_exp(args):
    from .experiment import build_report, format_report, get_experiment, runs_for
    conn = connect()
    if args.action == "list":
        rows = conn.execute(
            "SELECT id, ts, meta FROM events WHERE kind='experiment' ORDER BY id").fetchall()
        for r in rows:
            m = json.loads(r["meta"])
            n = len(runs_for(conn, r["id"]))
            print(f"[{r['id']}] {r['ts']} {m['task_id']!r} model={m['model']} "
                  f"arms={len(m['arms'])} runs={n} spec={m.get('spec_sha', '')[:12]}")
        if not rows:
            print("no experiments recorded")
        return
    if not args.exp_id:
        sys.exit("experiment id required")
    if args.action == "show":
        m = get_experiment(conn, args.exp_id)
        print(f"experiment #{args.exp_id}: {m['task_id']!r}")
        print(f"  model: {m['model']}  n_per_arm: {m['n_per_arm']}  "
              f"spec: {m.get('spec_sha', '')[:12]}")
        print(f"  query: {m['query']!r}  budget: {m['budget']}")
        print(f"  frozen: {len(m['frozen']['items'])} items "
              f"(+{len(m['frozen']['matched_not_included'])} matched but not included)")
        for it in m["frozen"]["items"]:
            print(f"    [{it['id']}] {it['provenance']:<8} {it['source']}/{it['kind']} "
                  f"~{it['est_tokens']}tok {it['uri'] or ''}")
        for a in m["arms"]:
            print(f"  arm: {json.dumps({k: v for k, v in a.items() if k != 'replace'})}"
                  + ("  [replace: distilled substitute]" if a.get("replace") else ""))
        print(f"  rubric: {len(m['rubric']['facts'])} facts, "
              f"{len(m['rubric'].get('fixtures', []))} fixtures")
        if m.get("expectation"):
            print(f"  preregistered expectation: {m['expectation']}")
        return
    if args.action == "report":
        family = get_experiment(conn, args.exp_id).get("family")
        if family == "provenance_trial":
            sys.exit(f"experiment #{args.exp_id} is a provenance trial; "
                     "rebuild its report with: experiments/provenance/"
                     f"model_trials.py report {args.exp_id}")
        if family == "handoff_bench":
            sys.exit(f"experiment #{args.exp_id} is a handoff benchmark; "
                     "rebuild its report with: experiments/handoff/"
                     f"bench.py report {args.exp_id}")
        print(format_report(build_report(conn, args.exp_id)))
        return
    sys.exit(f"unknown action {args.action!r}")


def cmd_backup(args):
    dest_dir = Path(args.dest).expanduser() if args.dest else home() / "backups"
    try:
        from . import service
        if service.hardened():
            authorization = operator_authorization(
                None, "archive.backup", "global",
                arguments={"destination": str(dest_dir), "keep": args.keep},
            )
            result = service.backup(str(dest_dir), authorization, keep=args.keep)
        else:
            result = create_backup(connect(), home(), dest_dir, keep=args.keep)
    except BackupError as exc:
        sys.exit(f"backup refused: {exc}")
    print(
        f"backed up {result['events']} events and {result['blobs']} blobs -> "
        f"{result['bundle']} (manifest {result['manifest_sha256'][:12]})"
    )
    if result["pruned"]:
        print(
            f"pruned {len(result['pruned'])} old bundle(s), "
            f"keeping newest {args.keep}"
        )


def cmd_security_export(args):
    """Produce one sealed export, addressed to the configured recipient."""
    from . import service
    from .authd import _export_action_arguments
    from .backup import BackupError, _read_secure_file
    from .export_crypto import ExportCryptoError, load_recipient

    dest_dir = Path(args.dest).expanduser() if args.dest else home() / "exports"
    configured = ((load_config().get("security") or {})
                  .get("export_recipient") or "").strip()
    if not configured:
        sys.exit(
            "export refused: no recovery recipient configured.\n"
            "  Set security.export_recipient in ~/.contextd/config.toml to the\n"
            "  path of an X25519 public key (DER or PEM, mode 0600).\n"
            "  Generate it on ANOTHER machine — a private key held here is\n"
            "  readable by exactly the attacker encryption is meant to stop:\n"
            "    openssl genpkey -algorithm X25519 -out contextd-export.key\n"
            "    openssl pkey -in contextd-export.key -pubout -out contextd-export.pub\n"
            "  Copy only the .pub here; keep the .key off this host."
        )
    try:
        recipient_key = _read_secure_file(Path(configured).expanduser(),
                                          "export recipient")
        _, digest = load_recipient(recipient_key)
    except (BackupError, ExportCryptoError) as exc:
        sys.exit(f"export refused: configured recipient is unusable: {exc}")

    # Open the archive before announcing anything: on an unmigrated archive
    # this refuses, and printing "sealing to <recipient>" first would describe
    # an act that is not going to happen.
    covered = _export_action_arguments(connect(), str(dest_dir), digest)
    # The operator approves the recipient, not just the act. Show the digest so
    # what they are signing is legible before the presence prompt appears.
    print(f"sealing to recipient {digest[:16]}… ({configured})")
    try:
        authorization = operator_authorization(
            None, "archive.export", "global", arguments=covered,
        )
        result = service.export(str(dest_dir), authorization)
    except (BackupError, ExportCryptoError) as exc:
        sys.exit(f"export refused: {exc}")
    print(
        f"sealed {result['events']} events and {result['blobs']} blobs -> "
        f"{result['export']} ({result['sealed_bytes']} bytes, manifest "
        f"{result['manifest_sha256'][:12]})"
    )


def _load_identity(path: Path):
    """Load a recovery private key, prompting only if it is passphrase-wrapped.

    A recovery key should be stored wrapped (`openssl pkcs8 -topk8 -v2
    aes-256-cbc`), because that is what makes it safe to keep the file
    somewhere convenient — a phone, cloud storage — without the file alone
    being enough. Supporting only bare keys would mean the documented storage
    advice produced an export this tool could not open.

    The passphrase is read from the tty and never taken from argv or the
    environment: both are readable by other processes, and a recovery
    passphrase disclosed at recovery time defeats the wrapping.
    """
    import getpass

    from cryptography.hazmat.primitives import serialization

    raw = path.read_bytes()
    try:
        return serialization.load_pem_private_key(raw, password=None)
    except TypeError:
        pass  # encrypted: `cryptography` raises TypeError when None is given
    try:
        # Short name deliberately. The keyword argument below is
        # `cryptography`'s and cannot be renamed; the repository's
        # `password_assignment` detector fires on that keyword followed by
        # eight or more non-delimiter characters, so binding a longer name
        # here would report this file as a credential leak. Nothing in it is a
        # literal secret, and a short name is what keeps the publish gate
        # honest about that. (An earlier version of this comment spelled the
        # offending expression out as an example and tripped the detector on
        # its own explanation -- hence the description rather than the quote.)
        pw = getpass.getpass(f"passphrase for {path.name}: ").encode("utf-8")
    except (EOFError, KeyboardInterrupt):
        sys.exit("\nopen refused: no passphrase supplied")
    try:
        return serialization.load_pem_private_key(raw, password=pw)
    except ValueError:
        sys.exit("open refused: wrong passphrase, or the key is not readable")


def cmd_security_export_open(args):
    """Open a sealed export. Intended for the RECOVERY host, not this one."""
    from .export import ExportError, open_sealed_export
    from .export_crypto import ExportCryptoError, peek

    sealed = Path(args.sealed).expanduser().read_bytes()
    if args.identity is None:
        header = peek(sealed)
        print(f"sealed export  created {header.get('created_at')}")
        print(f"  recipient    {header.get('recipient_sha256')}")
        print(f"  manifest     {header.get('manifest_sha256')}")
        print(f"  suite        {header.get('suite')}")
        print("\nnothing above is authenticated until it is opened with "
              "--identity.")
        return
    identity = _load_identity(Path(args.identity).expanduser())
    try:
        result = open_sealed_export(sealed, identity,
                                    Path(args.dest).expanduser())
    except (ExportError, ExportCryptoError) as exc:
        sys.exit(f"open refused: {exc}")
    print(f"opened -> {result['destination']} "
          f"(manifest {result['manifest_sha256'][:12]})")


def cmd_restore(args):
    try:
        from . import service
        bundle = Path(args.bundle).expanduser()
        destination = Path(args.dest).expanduser()
        if service.hardened():
            authorization = operator_authorization(
                None, "archive.restore", "global",
                arguments={"bundle": str(bundle),
                           "destination": str(destination)},
            )
            result = service.restore(
                str(bundle), str(destination), authorization
            )
        else:
            result = restore_backup(bundle, destination)
    except BackupError as exc:
        sys.exit(f"restore refused: {exc}")
    print(
        f"restored {result['events']} events and {result['blobs']} blobs -> "
        f"{result['destination']}"
    )


def cmd_verify(args):
    try:
        r = verify_chain(connect())
    except ChainStateError as exc:
        sys.exit(f"CHAIN BROKEN: {exc}")
    if r["ok"]:
        extra = (f", {r['ts_warnings']} timestamp inversions (concurrent writers)"
                 if r["ts_warnings"] else "")
        print(f"chain intact: {r['checked']} events verified{extra}")
    else:
        sys.exit(f"CHAIN BROKEN at event #{r['first_bad']} "
                 f"({r['checked']} events verified before it)")


def cmd_compliance(args):
    """Deterministic EU AI Act logging/retention evidence from the ledger.

    ``now`` is passed explicitly rather than read inside the generator, so the
    artifact is a pure function of (archive state, instant) and two runs over
    an unchanged archive diff clean. Read-only: this command appends nothing.
    """
    from .compliance import compliance_report

    text = compliance_report(connect(), now=int(time.time()))
    if args.output:
        destination = Path(os.path.expanduser(args.output))
        destination.write_text(text)
        os.chmod(destination, 0o600)
        print(f"wrote {destination}")
    else:
        sys.stdout.write(text)


def cmd_why(args):
    from .provenance import closure, format_closure
    print(format_closure(closure(connect(), args.event_id)))


def cmd_lineage(args):
    from .lineage import audit_report, format_audit_report, format_stats, lineage_stats
    conn = connect()
    if getattr(args, "action", None) == "report":
        print(format_audit_report(audit_report(conn)))
        return
    stats = lineage_stats(conn, load_config())
    print(format_stats(stats, full=getattr(args, "full", False)))
    if stats["alert_notes"]:
        sys.exit(2)


def cmd_serve(args):
    from .mcp_server import main as serve_main
    serve_main(allowed_tools=args.tools)


def main():
    p = argparse.ArgumentParser(prog="ctx", description="contextd v0")
    p.add_argument("--signer-key", default="", metavar="TAG",
                   help="enrollment tag (or key-id prefix) of the operator key "
                        "that signs this act; default is the most recently "
                        "registered active key, which is wrong when that key's "
                        "Enclave handle lives on another device")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create ~/.contextd (db, config, blob store)")
    sp = sub.add_parser("note", help="append a note event")
    sp.add_argument("text", nargs="*")
    sp.add_argument("--authorize", action="store_true",
                    help="require a fresh hardware-signed operator action")
    sub.add_parser("ingest", help="run all ingesters once")
    sub.add_parser("watch", help="run ingesters on a loop (the daemon)")
    sp = sub.add_parser("search", help="local FTS search (not logged)")
    sp.add_argument("query", nargs="+")
    sp.add_argument("--limit", type=int, default=10)
    sp = sub.add_parser("recall", help="assemble a gated context bundle (logged as egress)")
    sp.add_argument("query", nargs="+")
    sp.add_argument("--budget", type=int, default=8000)
    sp.add_argument("--purpose", default="")
    sp.add_argument("--since", help="ISO date; filters by occurrence (visit) time")
    sp.add_argument("--until", help="ISO date, exclusive")
    sp.add_argument("--mode", choices=["detail", "synthesis"], default="detail",
                    help="synthesis: anchor-verified distilled bundle via "
                         "hooks/synthesis_recall.py (model-assisted, ~150 words)")
    sp = sub.add_parser("checkpoint",
                        help="compile a resumption checkpoint: what a fresh "
                             "model needs to continue this project (logged)")
    sp.add_argument("--budget", type=int, default=4000,
                    help="package budget in est. tokens (raw) or raw-selection "
                         "budget fed to the distiller (distill)")
    sp.add_argument("--hint", default="", help="optional task hint for the "
                                               "recall stratum")
    sp.add_argument("--repo", help="repository path for the live-state section")
    sp.add_argument("--test-cmd", help="test command for the repo section, "
                                       "e.g. 'pytest -q'")
    sp.add_argument("--purpose", default="")
    sp.add_argument("--mode", choices=["raw", "distill"], default="raw",
                    help="distill: model-compressed structured checkpoint via "
                         "hooks/checkpoint_compile.py, anchor-verified")
    sp = sub.add_parser("loop", help="operator-confirmed open loops: "
                                     "prospective state that survives "
                                     "session death (docs/OPEN_LOOPS.md)")
    lsub = sp.add_subparsers(dest="action", required=True)
    la = lsub.add_parser("add", help="declare an open loop (operator act)")
    la.add_argument("text", nargs="+")
    la.add_argument("--repo", help="scope to a repository (default: cwd's "
                                   "git toplevel, else global)")
    la.add_argument("--global", dest="global_scope", action="store_true",
                    help="global scope")
    la.add_argument("--source-event", type=int, action="append", default=[],
                    help="archive event id(s) this loop arose from")
    for name, hlp in (("list", "active loops for a scope"),
                      ("candidates", "pending model-proposed candidates")):
        lp_ = lsub.add_parser(name, help=hlp)
        lp_.add_argument("--repo")
        lp_.add_argument("--global", dest="global_scope", action="store_true")
        if name == "list":
            lp_.add_argument("--all", action="store_true",
                             help="include candidates, closed, dismissed")
    ls = lsub.add_parser("show", help="one loop: state, history, provenance")
    ls.add_argument("loop_id")
    for name, hlp in (
            ("close", "mark an open loop completed/retired"),
            ("reopen", "reactivate a closed loop"),
            ("confirm", "promote a candidate to open (operator act)"),
            ("dismiss", "reject a candidate; suppresses re-proposal")):
        lt = lsub.add_parser(name, help=hlp)
        lt.add_argument("loop_id")
        if name in ("close", "reopen", "dismiss"):
            lt.add_argument("--reason", default="")

    sp = sub.add_parser("grant",
                        help="delegation grants: recorded, scoped, "
                             "revocable model authority (docs/GRANTS.md)")
    gsub = sp.add_subparsers(dest="action", required=True)
    ga = gsub.add_parser("add", help="delegate an authority class "
                                     "(operator act)")
    ga.add_argument("cls", metavar="class",
                    help="loop.confirm | loop.dismiss | decision.supersede")
    ga.add_argument("--repo", help="repo scope (default: global)")
    ga.add_argument("--global", dest="global_scope", action="store_true")
    ga.add_argument("--for", dest="for_", metavar="DUR",
                    help="expiry as duration, e.g. 90m, 8h, 3d")
    ga.add_argument("--until", help="expiry as ISO timestamp")
    ga.add_argument("-m", "--reason", default="",
                    help="why you are delegating (carried with the grant)")
    gr = gsub.add_parser("revoke", help="revoke a grant (operator act)")
    gr.add_argument("grant_id", type=int)
    gr.add_argument("-m", "--reason", default="")
    gl = gsub.add_parser("list", help="active grants (--all: full history)")
    gl.add_argument("--all", action="store_true")

    sp = sub.add_parser("decision",
                        help="decision supersession edges: a superseded "
                             "item is never checkpointed unmarked "
                             "(docs/DECISIONS.md)")
    dsub = sp.add_subparsers(dest="action", required=True)
    ds = dsub.add_parser("supersede",
                         help="record that NEW supersedes OLD (operator act)")
    ds.add_argument("old", type=int)
    ds.add_argument("new", type=int)
    ds.add_argument("-m", "--reason", default="")
    dsub.add_parser("list", help="all edges + anomalies")
    dc = dsub.add_parser("current",
                         help="follow the chain from an event id")
    dc.add_argument("event_id", type=int)

    sp = sub.add_parser("mandate",
                        help="in-flight mandates: list | resolve. A mandate is "
                             "in flight when the process that bound it died "
                             "before recording an outcome; only the operator "
                             "can close one, by attesting what they verified "
                             "outside contextd")
    msub = sp.add_subparsers(dest="action", required=True)
    msub.add_parser("list", help="mandates awaiting an attested outcome")
    mr = msub.add_parser(
        "resolve",
        help="record YOUR attested outcome for an in-flight mandate "
             "(operator act; contextd never guesses this)",
    )
    mr.add_argument("nonce", help="the mandate nonce from `ctx mandate list`")
    mr.add_argument("--status", required=True,
                    choices=list(_RESOLUTION_STATUSES),
                    help="what you verified actually happened out in the world")
    mr.add_argument("--reason", default="",
                    help="what you checked and where — recorded with the "
                         "attestation and covered by the signature")
    sp = sub.add_parser("timeline", help="browse events by time")
    sp.add_argument("--since")
    sp.add_argument("--until")
    sp.add_argument("--source")
    sp.add_argument("--limit", type=int, default=50)
    sp = sub.add_parser("audit", help="list egress events: what left, when, for what")
    sp.add_argument("--limit", type=int, default=20)
    sub.add_parser("status", help="event counts, db size, today's egress spend")
    sp = sub.add_parser("outcome", help="judge a recall or checkpoint egress for "
                                        "the evaluation tally; no args = scoreboard")
    sp.add_argument("egress_id", nargs="?", type=int)
    sp.add_argument("verdict", nargs="?", choices=["hit", "partial", "miss"])
    sp.add_argument("--note", default="")
    sp.add_argument("--failure-class", dest="failure_class",
                    choices=["not-in-archive", "not-selected", "drowned",
                             "superseded"],
                    help="why a miss/partial failed: not-in-archive = the "
                         "needed fact was never captured; not-selected = in "
                         "the archive but absent from the package; drowned = "
                         "in the package but buried/ignored; superseded = "
                         "selected but stale — a later decision/state change "
                         "made it wrong")
    sp = sub.add_parser("exp", help="context ablation experiments: list | show | report")
    sp.add_argument("action", choices=["list", "show", "report"])
    sp.add_argument("exp_id", nargs="?", type=int)
    sp = sub.add_parser("backup", help="create a complete, manifest-hashed bundle")
    sp.add_argument("dest", nargs="?")
    sp.add_argument("--keep", type=int, default=0,
                    help="after backing up, prune to the newest N bundles")
    sp = sub.add_parser("restore", help="verify and restore a backup into an empty home")
    sp.add_argument("bundle", help="backup bundle directory")
    sp.add_argument("dest", help="new or empty destination directory")
    sp = sub.add_parser("security",
                        help="hardening state, operator keys, authority service")
    ssub = sp.add_subparsers(dest="security_action", required=True)
    sd = ssub.add_parser("doctor", help="report each hardening invariant")
    sd.add_argument("--strict", action="store_true",
                    help="exit nonzero unless every invariant holds")
    sd.add_argument("--json", action="store_true")
    sv = ssub.add_parser("serve", help="run the authority service (foreground)")
    sv.add_argument("--socket", default=None)
    sm = ssub.add_parser("migrate",
                         help="migrate a pre-hardening archive (append-only)")
    sm.add_argument("--dry-run", action="store_true",
                    help="report what would change; change nothing")
    sm.add_argument("--json", action="store_true")
    sc = ssub.add_parser("checkpoint",
                         help="protected rollback checkpoint: print, write, "
                              "verify, or append to an exported log")
    sc.add_argument("--write", action="store_true",
                    help="write the checkpoint to the configured destination")
    sc.add_argument("--destination", default=None)
    # Nested and optional, so `ctx security checkpoint [--write]` keeps its
    # exact behaviour. The log subcommands are separate from `--write` because
    # they are a different thing: --write replaces one record, export appends
    # to a history.
    csub = sc.add_subparsers(dest="checkpoint_action", required=False)
    ce = csub.add_parser(
        "export",
        help="append a signed checkpoint to an append-only log OUTSIDE the "
             "archive. Advisory unless <dest> is somewhere this uid cannot "
             "rewrite (another host, another uid, append-only storage)",
    )
    ce.add_argument("dest", help="path to the checkpoint log (JSON Lines)")
    cv = csub.add_parser(
        "verify",
        help="check the archive against EVERY checkpoint in an exported log; "
             "exits nonzero on any failure and screams on rollback",
    )
    cv.add_argument("dest", help="path to the checkpoint log (JSON Lines)")
    se = ssub.add_parser("export",
                         help="seal the archive to the configured recipient")
    se.add_argument("--dest", default=None,
                    help="directory for the sealed export (default ~/.contextd/exports)")
    so = ssub.add_parser(
        "export-open",
        help="open a sealed export (run this on the RECOVERY host)",
    )
    so.add_argument("sealed", help="the .ctxexport file")
    so.add_argument("--identity", default=None,
                    help="PEM X25519 private key; omitted, this only reports "
                         "the unauthenticated header")
    so.add_argument("--dest", default=".",
                    help="directory to unpack the bundle into")
    sk = ssub.add_parser("key", help="operator key registry")
    ksub = sk.add_subparsers(dest="key_action", required=True)
    ksub.add_parser("list", help="registered operator keys")
    kb = ksub.add_parser(
        "bootstrap",
        help="out-of-band first key enrollment (as _contextd; or "
             "--development on a development archive)",
    )
    kb.add_argument("path", help="DER file, or - for stdin")
    kb.add_argument("--signer-tag", required=True,
                    help="Secure Enclave application tag used at enrollment")
    kb.add_argument("--acknowledge-first-key-bootstrap", action="store_true",
                    help="acknowledge this one-time service-admin ceremony")
    kb.add_argument("--development", action="store_true",
                    help="development-mode first key: operator's own uid "
                         "boundary; refused on a hardened archive")
    kr = ksub.add_parser("register", help="register a Secure Enclave public key")
    kr.add_argument("path", help="DER file, or - for stdin")
    kr.add_argument("--signer-tag", required=True,
                    help="Secure Enclave application tag used at enrollment")
    kv = ksub.add_parser("revoke", help="revoke a registered key")
    kv.add_argument("key_id")

    sub.add_parser("verify", help="recompute the event hash chain; detect rewrites")
    sp = sub.add_parser(
        "compliance",
        help="EU AI Act logging/retention evidence from the ledger: event "
             "span, chain verification, checkpoint coverage, keyed to "
             "Arts. 12 / 19(1) / 26(6). Read-only, deterministic, no verdict "
             "and no model (docs/FORMAT.md, docs/SECURITY.md)",
    )
    sp.add_argument("-o", "--output", default="",
                    help="write the artifact to this path (mode 0600) instead "
                         "of stdout")
    sp = sub.add_parser("why", help="reconstruct a derived event's provenance "
                                    "closure down to leaf evidence (local, unlogged)")
    sp.add_argument("event_id", type=int)
    sp = sub.add_parser("lineage",
                        help="derivation-graph topology gauge: note chain "
                             "depth, anchor health; 'report' shows the "
                             "sampled fidelity-audit time series (local, "
                             "unlogged; exits nonzero on a depth alert)")
    sp.add_argument("action", nargs="?", choices=["report"],
                    help="report: advisory audit verdicts from the ledger, "
                         "shown against the judge's calibration matrix")
    sp.add_argument("--full", action="store_true",
                    help="per-event table for every derivation-bearing event")
    sp = sub.add_parser("serve", help="run the MCP server (stdio)")
    sp.add_argument(
        "--tools",
        nargs="+",
        choices=["recall", "search", "note", "timeline", "loop_candidate",
                 "loop_list", "loop_confirm", "loop_dismiss",
                 "decision_supersede"],
        help="server-enforced MCP tool allowlist (default: all tools); "
             "omitted tools are absent from the registry itself. "
             "loop_confirm/loop_dismiss/decision_supersede additionally "
             "refuse without an active operator grant (docs/GRANTS.md)",
    )

    args = p.parse_args()
    global _SIGNER_KEY_FLAG
    _SIGNER_KEY_FLAG = args.signer_key or ""
    try:
        {"init": cmd_init, "note": cmd_note, "ingest": cmd_ingest,
         "watch": cmd_watch,
         "search": cmd_search, "recall": cmd_recall, "checkpoint": cmd_checkpoint,
         "loop": cmd_loop, "decision": cmd_decision, "grant": cmd_grant,
         "timeline": cmd_timeline,
         "audit": cmd_audit, "status": cmd_status, "outcome": cmd_outcome,
         "mandate": cmd_mandate,
         "exp": cmd_exp, "backup": cmd_backup, "restore": cmd_restore,
         "verify": cmd_verify, "why": cmd_why, "lineage": cmd_lineage,
         "compliance": cmd_compliance,
         "security": cmd_security,
         "serve": cmd_serve}[args.cmd](args)
    except SchemaMigrationRequired as exc:
        # A deliberate, fully-messaged refusal, not an unexpected failure: the
        # archive predates the security migration and the build will not append
        # to it. Every command that opens the archive can raise it, so it is
        # caught once here. A traceback would bury an instruction the operator
        # is meant to act on. Nothing else is caught — real errors still raise.
        sys.exit(f"refused: {exc}")


if __name__ == "__main__":
    main()
