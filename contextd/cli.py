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
from .backup import BackupError, create_backup, restore_backup
from .db import ChainStateError, append_event, connect, verify_chain
from .gate import GateError, assemble, spent_today
from .ingest import ingest_note, run_all
from .liveness import capture_liveness, describe, format_age, stale_line
from .search import search, timeline

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
    eid = ingest_note(connect(), text.strip())
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
    for h in search(connect(), " ".join(args.query), limit=args.limit):
        print(f"[{h['id']}] {h['ts']} {h['source']}/{h['kind']} {h['uri'] or ''}")
        print(f"    {h['snip']}")


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


def cmd_loop(args):
    from .loops import (LoopError, add_loop, loops_for_scope, reduce_loops,
                        transition)
    conn = connect()
    try:
        if args.action == "add":
            r = add_loop(conn, " ".join(args.text), _loop_scope(args),
                         client="cli", source_events=args.source_event)
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
            print(f"    authority: {lp['created_authority']} "
                  f"(client {lp['created_client'] or '?'})"
                  + (f"; promoted by {lp['promoted_authority']}"
                     if lp["promoted_authority"] else ""))
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
        r = transition(conn, _loop_id(args.loop_id), op,
                       authority="operator", client="cli",
                       reason=getattr(args, "reason", "") or "")
        lp = r["loop"]
        if r["result"] == "noop":
            print(f"loop#{lp['id']} already {lp['state']}")
        else:
            print(f"loop#{lp['id']} -> {lp['state']}")
    except LoopError as e:
        sys.exit(f"refused: {e}")


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
        print(f"[{r['id']}] {r['ts']} type={meta.get('type')} "
              f"client={meta.get('client', 'cli')} "
              f"dispatch={dispatch} "
              f"query={meta.get('query')!r} purpose={meta.get('purpose')!r} "
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
        result = create_backup(
            connect(), home(), dest_dir, keep=args.keep
        )
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


def cmd_restore(args):
    try:
        result = restore_backup(
            Path(args.bundle).expanduser(), Path(args.dest).expanduser()
        )
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
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create ~/.contextd (db, config, blob store)")
    sp = sub.add_parser("note", help="append a note event")
    sp.add_argument("text", nargs="*")
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
    sub.add_parser("verify", help="recompute the event hash chain; detect rewrites")
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
                 "loop_list"],
        help="server-enforced MCP tool allowlist (default: all tools); "
             "omitted tools are absent from the registry itself. Loop "
             "confirm/dismiss are deliberately CLI-only (docs/OPEN_LOOPS.md)",
    )

    args = p.parse_args()
    {"init": cmd_init, "note": cmd_note, "ingest": cmd_ingest, "watch": cmd_watch,
     "search": cmd_search, "recall": cmd_recall, "checkpoint": cmd_checkpoint,
     "loop": cmd_loop, "timeline": cmd_timeline,
     "audit": cmd_audit, "status": cmd_status, "outcome": cmd_outcome,
     "exp": cmd_exp, "backup": cmd_backup, "restore": cmd_restore,
     "verify": cmd_verify, "why": cmd_why, "lineage": cmd_lineage,
     "serve": cmd_serve}[args.cmd](args)


if __name__ == "__main__":
    main()
