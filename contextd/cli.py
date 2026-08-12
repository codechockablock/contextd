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
from .db import append_event, connect, verify_chain
from .gate import GateError, assemble, spent_today
from .ingest import ingest_note, run_all
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


def cmd_timeline(args):
    rows = timeline(connect(), since=args.since, until=args.until,
                    source=args.source, limit=args.limit)
    for r in rows:
        brief = (r["content"] or "")[:100].replace("\n", " ")
        print(f"[{r['id']}] {r['ts']} {r['source']}/{r['kind']} {r['uri'] or ''} {brief}")


def cmd_audit(args):
    rows = timeline(connect(), kind="egress", limit=args.limit)
    for r in rows:
        meta = json.loads(r["meta"] or "{}")
        print(f"[{r['id']}] {r['ts']} type={meta.get('type')} "
              f"client={meta.get('client', 'cli')} "
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


def cmd_outcome(args):
    conn = connect()
    if not args.egress_id:
        recalls = {r["id"] for r in conn.execute(
            "SELECT id FROM events WHERE kind='egress' "
            "AND json_extract(meta,'$.type')='recall'")}
        verdicts = {}
        for r in conn.execute("SELECT meta FROM events WHERE kind='outcome' ORDER BY id"):
            m = json.loads(r["meta"])
            verdicts[m["egress_id"]] = m["verdict"]  # append-only: last verdict wins
        counts = {"hit": 0, "partial": 0, "miss": 0}
        for eid, v in verdicts.items():
            if eid in recalls:
                counts[v] += 1
        judged = sum(counts.values())
        print(f"recalls: {len(recalls)}  judged: {judged}  unjudged: {len(recalls) - judged}")
        if judged:
            print(f"  hit {counts['hit']}  partial {counts['partial']}  miss {counts['miss']}"
                  f"  — hit rate {counts['hit'] / judged:.0%} (v0.1 bar: 30%)")
        return
    if not args.verdict:
        sys.exit("verdict required: hit | partial | miss")
    if not conn.execute("SELECT 1 FROM events WHERE id = ? AND kind='egress'",
                        (args.egress_id,)).fetchone():
        sys.exit(f"no egress event #{args.egress_id}")
    meta = {"egress_id": args.egress_id, "verdict": args.verdict}
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
        print(format_report(build_report(conn, args.exp_id)))
        return
    sys.exit(f"unknown action {args.action!r}")


def cmd_backup(args):
    conn = connect()
    dest_dir = Path(args.dest).expanduser() if args.dest else home() / "backups"
    dest_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_dir, 0o700)
    stamp, i = time.strftime("%Y%m%d-%H%M%S"), 0
    dest = dest_dir / f"contextd-{stamp}.db"
    while dest.exists():
        i += 1
        dest = dest_dir / f"contextd-{stamp}-{i}.db"
    conn.execute("VACUUM INTO ?", (str(dest),))  # WAL-safe consistent snapshot
    os.chmod(dest, 0o600)
    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"backed up {n} events -> {dest} ({dest.stat().st_size // 1024} KB)")
    if args.keep:
        old = sorted(dest_dir.glob("contextd-*.db"))[:-args.keep]
        for f in old:
            f.unlink()
        if old:
            print(f"pruned {len(old)} old backup(s), keeping newest {args.keep}")
    if any((home() / "store").rglob("*")):
        print("note: blob store not included — copy ~/.contextd/store separately")


def cmd_verify(args):
    r = verify_chain(connect())
    if r["ok"]:
        extra = (f", {r['ts_warnings']} timestamp inversions (concurrent writers)"
                 if r["ts_warnings"] else "")
        print(f"chain intact: {r['checked']} events verified{extra}")
    else:
        sys.exit(f"CHAIN BROKEN at event #{r['first_bad']} "
                 f"({r['checked']} events verified before it)")


def cmd_serve(args):
    from .mcp_server import main as serve_main
    serve_main()


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
    sp = sub.add_parser("timeline", help="browse events by time")
    sp.add_argument("--since")
    sp.add_argument("--until")
    sp.add_argument("--source")
    sp.add_argument("--limit", type=int, default=50)
    sp = sub.add_parser("audit", help="list egress events: what left, when, for what")
    sp.add_argument("--limit", type=int, default=20)
    sub.add_parser("status", help="event counts, db size, today's egress spend")
    sp = sub.add_parser("outcome", help="judge a recall for the evaluation tally; no args = scoreboard")
    sp.add_argument("egress_id", nargs="?", type=int)
    sp.add_argument("verdict", nargs="?", choices=["hit", "partial", "miss"])
    sp.add_argument("--note", default="")
    sp = sub.add_parser("exp", help="context ablation experiments: list | show | report")
    sp.add_argument("action", choices=["list", "show", "report"])
    sp.add_argument("exp_id", nargs="?", type=int)
    sp = sub.add_parser("backup", help="WAL-safe snapshot via VACUUM INTO")
    sp.add_argument("dest", nargs="?")
    sp.add_argument("--keep", type=int, default=0,
                    help="after backing up, prune to the newest N snapshots")
    sub.add_parser("verify", help="recompute the event hash chain; detect rewrites")
    sub.add_parser("serve", help="run the MCP server (stdio)")

    args = p.parse_args()
    {"init": cmd_init, "note": cmd_note, "ingest": cmd_ingest, "watch": cmd_watch,
     "search": cmd_search, "recall": cmd_recall, "timeline": cmd_timeline,
     "audit": cmd_audit, "status": cmd_status, "outcome": cmd_outcome,
     "exp": cmd_exp, "backup": cmd_backup, "verify": cmd_verify,
     "serve": cmd_serve}[args.cmd](args)


if __name__ == "__main__":
    main()
