#!/usr/bin/env python
"""Distilled checkpoint: model-compressed resumption state, anchor-verified.

Harness-side tooling, deliberately outside the contextd package (same rule as
reconcile.py and synthesis_recall.py): this script invokes a distiller model
via `claude -p`; the kernel never calls models. The kernel supplies everything
model-free — the frozen-view guarantee, stratified selection, repo state,
both gate disclosures, and anchor verification.

The distiller is asked for the shape the mission cares about — objective,
current state, settled decisions with WHY, rejected paths with WHY NOT, open
loops, next action — with a bracketed archive event id after every claim that
has one. Anchors are load-bearing (measured: #41325..#41485, synthesis dies
without resolvable per-claim ids), so a distillate whose anchors do not all
resolve to supplied events is refused and retried, never served.

Two egress events, both on the record, exactly like synthesis recall:
  1. mode=checkpoint_source — the raw compiled package disclosed to the
     distiller;
  2. mode=checkpoint — the verified distillate, with anchors, distiller
     model, and a link back to (1); `ctx why` walks it like any derivation.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd import load_config  # noqa: E402
from contextd.db import connect  # noqa: E402
from contextd.scratch import scratch_dir  # noqa: E402
from contextd.redact import sanitize_content  # noqa: E402
from contextd.gate import (GateError, disclose, record_dispatch_outcome,  # noqa: E402
                           verify_anchors)
from contextd.handoff import (compile_checkpoint, render_package,  # noqa: E402
                              repo_state, select_checkpoint_context)

CLAUDE_BIN = os.environ.get("CKPT_CLAUDE_BIN", "claude")

DISTILL_PROMPT = """The working session on this project was destroyed. Below is
context compiled from the project archive. Compress it into a CHECKPOINT that
lets a fresh model CONTINUE the work. Use exactly these sections:

OBJECTIVE: what the project is currently trying to achieve (1-2 sentences).
STATE: what is already done and what the repository looks like now.
DECISIONS: settled decisions, each with its WHY.
REJECTED: alternatives that were tried or considered and rejected, with WHY
NOT — these must not be re-proposed.
OPEN: unresolved questions, active hypotheses with their status, known risks.
NEXT: the single most likely next concrete action, and what would verify it.

At most 500 words total. After every claim that a context item supports,
attach that item's bracketed event id exactly as given (e.g. [37820]). Do not
invent ids. Preserve uncertainty as uncertainty — never harden a hypothesis
into a fact. Reply with only the checkpoint.

{package}"""


def distill(payload: str, model: str, timeout: int = 600, cfg=None):
    env = os.environ.copy()
    env["MCP_CONNECTION_NONBLOCKING"] = "false"
    env["ENABLE_TOOL_SEARCH"] = "off"
    # working directory removed in `finally` on every exit path
    with scratch_dir("checkpoint-distill") as workdir:
        r = subprocess.run(
            [CLAUDE_BIN, "-p", "--model", model, "--tools", "",
             "--strict-mcp-config", "--no-session-persistence",
             "--setting-sources", "", "--output-format", "json",
             "--max-budget-usd", "0.50"],
            input=payload, capture_output=True, text=True, timeout=timeout,
            cwd=workdir, env=env)
    if r.returncode != 0:
        raise RuntimeError(f"distiller failed (exit {r.returncode}): "
                           f"{sanitize_content(cfg, r.stderr, max_len=500)}")
    try:
        out = json.loads(r.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("distiller returned unparseable output")
    result = sanitize_content(cfg, out.get("result") or "", max_len=20_000)
    return result.strip(), out.get("total_cost_usd")


def compile_distilled(conn, cfg, raw_budget: int, task_hint: str = "",
                      repo: dict | None = None, model: str = "haiku",
                      retries: int = 1, client: str = "checkpoint-distill",
                      purpose: str = "") -> dict:
    """Select at raw_budget, distill, verify anchors, disclose. Returns the
    served checkpoint dict or raises on refusal. The ACTIVE OPEN LOOPS
    section is re-attached verbatim after the distillate: loop carriage is
    deterministic by contract (docs/OPEN_LOOPS.md) and never depends on the
    distiller model choosing to preserve it."""
    selection = select_checkpoint_context(conn, cfg, raw_budget, task_hint,
                                          repo_path=repo.get("path")
                                          if repo else None)
    from contextd.db import _db_tip
    tip = _db_tip(conn)["id"]
    package = render_package(selection, repo=repo, tip=tip)
    ids = sorted({it["id"]
                  for k in ("loops", "tail", "episodes", "notes", "recall")
                  for it in selection[k] if it["id"] is not None})
    text = None
    anchors = src_egress = None
    for attempt in range(retries + 1):
        source = disclose(conn, cfg, DISTILL_PROMPT.format(package=package), {
            "type": "checkpoint", "mode": "checkpoint_source", "tip": tip,
            "task_hint": task_hint, "purpose": purpose, "items": ids,
            "distiller": model, "attempt": attempt, "client": client})
        src_egress = source["egress_id"]
        try:
            text, cost = distill(source["content"], model, cfg=cfg)
        except subprocess.TimeoutExpired:
            record_dispatch_outcome(conn, src_egress, "timeout")
            raise
        except BaseException:
            # the exception's own text is deliberately not persisted: a
            # failing subprocess must not be a channel into the archive
            record_dispatch_outcome(conn, src_egress, "failed")
            raise
        record_dispatch_outcome(conn, src_egress, "succeeded", exit=0)
        anchors = verify_anchors(text, ids)
        if not anchors["invalid"] and len(anchors["valid"]) >= 2:
            break
        text = None
    if text is None:
        raise RuntimeError(
            f"distilled checkpoint failed anchor verification after "
            f"{retries + 1} attempt(s) (invalid={anchors['invalid']})")
    if selection.get("loops"):
        start = package.index("== ACTIVE OPEN LOOPS")
        end = package.find("\n== ", start + 1)
        section = package[start:end if end != -1 else len(package)].rstrip()
        text = f"{text}\n\n{section}"
    meta = {"type": "checkpoint", "mode": "checkpoint", "tip": tip,
            "task_hint": task_hint, "purpose": purpose, "items": ids,
            "anchors": anchors["valid"], "distiller": model,
            "source_egress": src_egress, "client": client}
    if cost is not None:
        meta["distill_cost_usd"] = cost
    served = disclose(conn, cfg, text, meta)
    return {"package": served["content"], "items": ids, "tip": tip,
            "egress_id": served["egress_id"], "source_egress": src_egress,
            "anchors": anchors["valid"], "est_tokens": served["est_tokens"]}


def main():
    p = argparse.ArgumentParser(
        description="compile a checkpoint from the archive (CONTEXTD_HOME "
                    "selects live archive or frozen view)")
    p.add_argument("--budget", type=int, default=4000,
                   help="final package budget (raw mode) or raw-selection "
                        "budget fed to the distiller (distill mode)")
    p.add_argument("--task-hint", default="")
    p.add_argument("--repo", help="repository path for the live-state section")
    p.add_argument("--test-cmd", help="shell-split test command to run for "
                                      "the repo section, e.g. 'pytest -q'")
    p.add_argument("--mode", choices=["raw", "distill"], default="raw")
    p.add_argument("--model", default=os.environ.get("CKPT_MODEL", "haiku"))
    p.add_argument("--purpose", default="")
    args = p.parse_args()

    conn, cfg = connect(), load_config()
    repo = None
    if args.repo:
        repo = repo_state(Path(args.repo),
                          test_cmd=args.test_cmd.split() if args.test_cmd else None)
    try:
        if args.mode == "raw":
            out = compile_checkpoint(conn, cfg, args.budget, args.task_hint,
                                     repo=repo, purpose=args.purpose)
        else:
            out = compile_distilled(conn, cfg, args.budget, args.task_hint,
                                    repo=repo, model=args.model,
                                    purpose=args.purpose)
    except GateError as e:
        sys.exit(f"gate refused: {e}")
    print(out["package"])
    print(f"\n[checkpoint egress #{out['egress_id']}: tip #{out['tip']}, "
          f"{len(out['items'])} events, ~{out['est_tokens']} tokens — logged]",
          file=sys.stderr)


if __name__ == "__main__":
    main()
