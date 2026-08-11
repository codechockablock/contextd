"""ctx: the human-facing CLI. CLI search/timeline stay local and unlogged;
recall always produces a gated, logged egress bundle — same path MCP uses."""

import argparse
import json
import os
import sys
import time

from . import __version__, home, load_config
from .db import connect
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
    sp = sub.add_parser("timeline", help="browse events by time")
    sp.add_argument("--since")
    sp.add_argument("--until")
    sp.add_argument("--source")
    sp.add_argument("--limit", type=int, default=50)
    sp = sub.add_parser("audit", help="list egress events: what left, when, for what")
    sp.add_argument("--limit", type=int, default=20)
    sub.add_parser("status", help="event counts, db size, today's egress spend")
    sub.add_parser("serve", help="run the MCP server (stdio)")

    args = p.parse_args()
    {"init": cmd_init, "note": cmd_note, "ingest": cmd_ingest, "watch": cmd_watch,
     "search": cmd_search, "recall": cmd_recall, "timeline": cmd_timeline,
     "audit": cmd_audit, "status": cmd_status, "serve": cmd_serve}[args.cmd](args)


if __name__ == "__main__":
    main()
