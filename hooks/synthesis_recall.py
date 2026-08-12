#!/usr/bin/env python
"""Synthesis-mode recall: a gated, anchor-verified, distilled context bundle.

Harness-side tooling, deliberately outside the contextd package (same rule
as reconcile.py): this script invokes a distiller model via `claude -p` on
your existing subscription; the kernel never calls models. The kernel
supplies everything model-free — item selection (the same walk plain recall
uses), both gate disclosures, and anchor verification.

Measured basis (ledger experiments #41325, #41386, #41408, #41428, #41454,
#41485): synthesis capability survives compression and even fusion into one
narrative, but dies without per-claim event-id anchors. A fused-with-ids
distillate matched the granular representation at ~12% of raw-detail tokens
and ~5x the score-per-token. Anchors are therefore load-bearing: this script
refuses to serve a distillate whose anchors do not all resolve to events
actually supplied to the distiller.

Two egress events per invocation, both on the record:
  1. mode=synthesis_source — the raw selected bundle disclosed to the
     distiller model;
  2. mode=synthesis — the verified distillate actually served, with its
     anchors, distiller model, and a link back to (1).
Judge it like any recall: ctx outcome <egress-id> hit|partial|miss."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd import load_config  # noqa: E402
from contextd.db import connect  # noqa: E402
from contextd.gate import (GateError, disclose, record_dispatch_outcome,  # noqa: E402
                           select_items, verify_anchors)

CLAUDE_BIN = os.environ.get("SYNTH_CLAUDE_BIN", "claude")

# The fused-with-ids objective, validated in exp #41485. Keep in sync with
# experiments/runner.py FUSED_IDS_DISTILL_PROMPT — the experiment owns the
# canonical copy; change it there first and re-measure.
DISTILL_PROMPT = """Distill the following context items into ONE
flowing summary of at most 150 words. Write continuous prose — no lists, no
per-item entries, no headers. Prioritize causal rationale, rejected
alternatives, negative results, and recurring principles. Immediately after
each claim, attach the bracketed event id of the item that supports it,
exactly as given (e.g. [37820]). Reply with only the summary.

{bundle}"""


class DistillError(RuntimeError):
    def __init__(self, message: str, exit_code: int | None = None):
        super().__init__(message)
        self.exit_code = exit_code


def distill(payload: str, model: str, timeout: int = 300):
    env = os.environ.copy()
    env["MCP_CONNECTION_NONBLOCKING"] = "false"
    env["ENABLE_TOOL_SEARCH"] = "off"
    r = subprocess.run(
        [CLAUDE_BIN, "-p", "--model", model, "--tools", "",
         "--strict-mcp-config", "--no-session-persistence",
         "--setting-sources", "", "--output-format", "json",
         "--max-budget-usd", "0.50"],
        input=payload, capture_output=True,
        text=True, timeout=timeout, cwd=tempfile.mkdtemp(prefix="ctx-synth-"),
        env=env)
    if r.returncode != 0:
        raise DistillError(
            f"distiller failed (exit {r.returncode}): {r.stderr[-500:]}",
            exit_code=r.returncode,
        )
    try:
        out = json.loads(r.stdout)
    except json.JSONDecodeError:
        raise DistillError("distiller returned unparseable output", exit_code=0)
    return (out.get("result") or "").strip(), out.get("total_cost_usd")


def main():
    p = argparse.ArgumentParser(
        description="synthesis-mode recall: distilled, anchor-verified, gated")
    p.add_argument("query", nargs="+")
    p.add_argument("--budget", type=int, default=6000,
                   help="raw-selection budget fed to the distiller (est. tokens)")
    p.add_argument("--model", default=os.environ.get("SYNTH_MODEL", "haiku"))
    p.add_argument("--purpose", default="")
    p.add_argument("--since", default="")
    p.add_argument("--until", default="")
    p.add_argument("--retries", type=int, default=1,
                   help="re-distill attempts when anchor verification fails")
    args = p.parse_args()
    query = " ".join(args.query)

    conn, cfg = connect(), load_config()
    budget = min(args.budget, cfg["gate"]["max_recall_budget"])
    items = select_items(conn, cfg, query, budget, args.since, args.until)
    if not items:
        sys.exit("(no matching events)")
    ids = [it["id"] for it in items]
    bundle = "\n\n".join(it["header"] + "\n" + it["text"] for it in items)

    text = cost = None
    anchors = None
    src_egress = None
    for attempt in range(args.retries + 1):
        try:
            source = disclose(conn, cfg, DISTILL_PROMPT.format(bundle=bundle), {
                "type": "recall", "mode": "synthesis_source", "query": query,
                "purpose": args.purpose, "items": ids, "distiller": args.model,
                "attempt": attempt, "client": "synthesis-recall",
            })
        except GateError as e:
            sys.exit(f"gate refused: {e}")
        src_egress = source["egress_id"]
        try:
            text, cost = distill(source["content"], args.model)
        except subprocess.TimeoutExpired:
            record_dispatch_outcome(
                conn, src_egress, "timeout", timeout_seconds=300,
            )
            sys.exit("distiller timed out after 300 seconds")
        except DistillError as e:
            record_dispatch_outcome(
                conn, src_egress, "failed", exit=e.exit_code,
                error_type=type(e).__name__,
            )
            sys.exit(str(e))
        except BaseException as e:
            record_dispatch_outcome(
                conn, src_egress, "failed", error_type=type(e).__name__,
            )
            raise
        record_dispatch_outcome(conn, src_egress, "succeeded", exit=0)
        anchors = verify_anchors(text, ids)
        if not anchors["invalid"] and len(anchors["valid"]) >= 2:
            break
        text = None
    if text is None:
        sys.exit(f"distillate failed anchor verification after "
                 f"{args.retries + 1} attempt(s) (invalid={anchors['invalid']}, "
                 f"valid={anchors['valid']}); nothing served — "
                 f"use plain `ctx recall` for this query")

    meta = {"type": "recall", "mode": "synthesis", "query": query,
            "purpose": args.purpose, "items": ids,
            "anchors": anchors["valid"], "distiller": args.model,
            "source_egress": src_egress, "client": "synthesis-recall"}
    if cost is not None:
        meta["distill_cost_usd"] = cost
    try:
        served = disclose(conn, cfg, text, meta)
    except GateError as e:
        sys.exit(f"gate refused: {e}")
    print(served["content"])
    print(f"\n[synthesis egress #{served['egress_id']}: {len(ids)} events distilled to "
          f"~{served['est_tokens']} tokens, anchors {anchors['valid']}; "
          f"raw-to-distiller egress #{src_egress} — both logged]",
          file=sys.stderr)


if __name__ == "__main__":
    main()
