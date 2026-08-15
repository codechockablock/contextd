#!/usr/bin/env python
"""Open-loops candidate scanner: harness-side candidate generation.

Deliberately outside the contextd package (the kernel never calls models —
same rule as reconcile.py). The scanner reads one session's ingested
dialogue plus the scope's existing loop board, discloses both through the
real gate, and spawns a model whose ONLY tool is `loop_candidate` on a
server pointed at the same archive:

- the spawned server's registry contains loop_candidate alone, so promotion
  is mechanically impossible whatever the model outputs;
- a single-use dispatch capability binds every candidate to the exact disclosed
  bytes — bracketed anchors are kernel-verified, invalid ones refused;
- CONTEXTD_LOOP_SCOPE pins the scope server-side;
- kernel dedupe suppresses re-proposal of live, closed, and dismissed loops
  regardless of what the model does;
- the dispatch outcome (succeeded/failed/timeout) is recorded against the
  scan's egress receipt, so a hung or dead scan is visible in `ctx audit`.

The model may also emit nothing ("DONE") — an explicit uncertainty channel;
silence costs the operator nothing. Candidates are proposals only: an
operator confirms via `ctx loop confirm` (or the utterance-bound MCP relay,
docs/OPEN_LOOPS.md)."""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextd import load_config  # noqa: E402
from contextd.db import connect  # noqa: E402
from contextd.capability import issue as issue_capability  # noqa: E402
from contextd.capability import token as capability_token  # noqa: E402
from contextd.gate import disclose, record_dispatch_outcome  # noqa: E402
from contextd.scratch import harden_file, scratch_dir  # noqa: E402
from contextd.redact import sanitize_content  # noqa: E402

CLAUDE_BIN = os.environ.get("LOOP_SCAN_CLAUDE_BIN", "claude")
MODEL = os.environ.get("LOOP_SCAN_MODEL", "haiku")
MAX_DIALOGUE_CHARS = 200_000
REPO_ROOT = Path(__file__).resolve().parent.parent

PROMPT = """You are the open-loops scanner for a personal context daemon. \
Below is the dialogue from one work session on the project at {repo}, each \
message prefixed with its bracketed archive event id and role, followed by \
the loops already tracked for this project.

Identify commitments the OPERATOR (the human user) explicitly recognized as \
unresolved future work: things they directly asked for, agreed to, put "on \
the board", or explicitly kept open — and that were NOT completed within \
this dialogue and are not already tracked.

For each one, call the loop_candidate tool once. The candidate text must \
quote the operator's own wording as closely as possible and end with the \
bracketed event id(s) of the supporting message(s), e.g. "re-run the drift \
correction on the July batch [1234]".

Strict rules:
- Propose ONLY items the operator treated as their own priority. An \
assistant suggestion the operator did not clearly accept is not a loop; if \
one is genuinely ambiguous, you may propose it with text starting \
"UNCERTAIN:" so the operator sees the doubt.
- Never propose speculative musings ("someday", "wild idea", "just \
daydreaming"), work already completed in the dialogue, or items listed \
below as already tracked or dismissed.
- Cite only event ids that appear in this dialogue; never invent one.
- Candidates are proposals. You cannot open loops, and you must never \
claim the operator already confirmed anything.

If nothing qualifies, call no tools. When finished, reply with only: DONE"""


def session_dialogue(conn, session_id: str | None):
    if session_id:
        rows = conn.execute(
            "SELECT id, content, json_extract(meta,'$.role') AS role "
            "FROM events WHERE source='claude_code' AND kind='message' "
            "AND json_extract(meta,'$.session_id') = ? ORDER BY id",
            (session_id,)).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, content, json_extract(meta,'$.role') AS role "
            "FROM events WHERE source='claude_code' AND kind='message' "
            "ORDER BY id DESC LIMIT 400").fetchall()[::-1]
    return rows


def board_lines(conn, repo: str) -> tuple[list, list]:
    from contextd.loops import loops_for_scope, make_scope
    tracked = loops_for_scope(
        conn, make_scope(repo),
        states=("open", "candidate", "closed", "dismissed"))
    lines = [f"[loop#{lp['id']}] {lp['state']}: {lp['text']}"
             for lp in tracked]
    return lines, [lp["id"] for lp in tracked]


def _mcp_config(dest: Path, archive: Path, client: str) -> Path:
    cfg = {"mcpServers": {"contextd": {
        "command": str(REPO_ROOT / ".venv" / "bin" / "ctx"),
        "args": ["serve", "--tools", "loop_candidate"],
        "env": {"CONTEXTD_HOME": str(Path(archive).resolve()),
                "CONTEXTD_CLIENT": client},
    }}}
    dest.write_text(json.dumps(cfg, indent=2))
    return dest


def scan(conn, cfg, repo: str, session_id: str | None = None,
         model: str = MODEL, client: str = "loop-scan",
         timeout: int = 600) -> dict:
    """One scan pass. Returns dispatch status plus the created/suppressed
    candidate summary; every side effect is in the archive the connection
    points at."""
    from contextd import home as archive_home
    msgs = session_dialogue(conn, session_id)
    if not msgs:
        return {"dispatch_status": "skipped", "why": "no dialogue",
                "exit": None, "duration_ms": 0, "candidates": 0}
    board, board_ids = board_lines(conn, repo)
    dialogue = "\n\n".join(
        f"[{m['id']}] {m['role']}: {m['content']}" for m in msgs)
    dialogue = dialogue[:MAX_DIALOGUE_CHARS]
    board_text = ("\n\nAlready tracked for this project:\n"
                  + "\n".join(board)) if board else \
        "\n\nAlready tracked for this project: (nothing)"
    payload = PROMPT.format(repo=repo) + "\n\n" + dialogue + board_text
    disclosure = disclose(conn, cfg, payload, {
        "type": "loop_scan", "repo": repo, "session_id": session_id,
        "model": model, "items": [m["id"] for m in msgs] + board_ids,
        "client": client})
    before = conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind='loop'").fetchone()[0]
    env = os.environ.copy()
    # a dispatch capability, not an event id: opaque, bound to this
    # disclosure's exact bytes and this session, single-use, expiring
    # (contextd/capability.py). The old integer binding is retired.
    _cap = issue_capability(conn, disclosure["egress_id"], os.getuid(),
                            "loop-scan")
    env["CONTEXTD_DISPATCH_CAPABILITY"] = capability_token(_cap)
    env["CONTEXTD_DISPATCH_SESSION"] = "loop-scan"
    env.pop("CONTEXTD_DERIVATION_SOURCE", None)
    env["CONTEXTD_CLIENT"] = client
    env["CONTEXTD_LOOP_SCOPE"] = repo
    env["MCP_CONNECTION_NONBLOCKING"] = "false"
    env["ENABLE_TOOL_SEARCH"] = "off"
    tool = "mcp__contextd__loop_candidate"
    t0 = time.time()
    # the MCP config written here names the archive path; the working
    # directory is removed in `finally` on success, timeout, and interrupt
    with scratch_dir("loop-scan") as tmp:
        mcp_cfg = _mcp_config(tmp / "mcp.json", archive_home(), client)
        harden_file(mcp_cfg)
        cmd = [CLAUDE_BIN, "-p", "--model", model,
               "--setting-sources", "", "--output-format", "json",
               "--max-budget-usd", "0.50", "--no-session-persistence",
               "--strict-mcp-config", "--mcp-config", str(mcp_cfg),
               "--tools", tool, "--allowedTools", tool,
               "--max-turns", "16"]
        try:
            r = subprocess.run(cmd, input=disclosure["content"],
                               capture_output=True, text=True, timeout=timeout,
                               cwd=tmp, env=env)
        except subprocess.TimeoutExpired:
            record_dispatch_outcome(conn, disclosure["egress_id"], "timeout",
                                    timeout_seconds=timeout)
            return {"dispatch_status": "timeout", "exit": None,
                    "duration_ms": int((time.time() - t0) * 1000),
                    "candidates": 0, "egress_id": disclosure["egress_id"]}
        except BaseException:
            record_dispatch_outcome(conn, disclosure["egress_id"], "failed")
            raise
    duration_ms = int((time.time() - t0) * 1000)
    status = "succeeded" if r.returncode == 0 else "failed"
    record_dispatch_outcome(conn, disclosure["egress_id"], status,
                            exit=r.returncode)
    after = conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind='loop'").fetchone()[0]
    text = ""
    if r.stdout.strip():
        try:
            parsed = json.loads(r.stdout)
            text = parsed.get("result") or "" if isinstance(parsed, dict) else ""
        except json.JSONDecodeError:
            text = r.stdout
    if not isinstance(text, str):
        text = ""
    return {"dispatch_status": status, "exit": r.returncode,
            "duration_ms": duration_ms, "candidates": after - before,
            "egress_id": disclosure["egress_id"],
            "stderr": sanitize_content(cfg, r.stderr, max_len=2000)
            if r.returncode else "",
            "text": sanitize_content(cfg, text, max_len=5000)}


def main():
    p = argparse.ArgumentParser(
        description="scan one session's dialogue for open-loop candidates "
                    "(CONTEXTD_HOME selects the archive)")
    p.add_argument("--repo", required=True,
                   help="repository path the candidates are scoped to")
    p.add_argument("--session", default=None,
                   help="session id to scan (default: the recent tail)")
    p.add_argument("--model", default=MODEL)
    args = p.parse_args()
    conn = connect()
    out = scan(conn, load_config(), repo=args.repo, session_id=args.session,
               model=args.model)
    print(json.dumps(out, indent=2))
    sys.exit(0 if out["dispatch_status"] in ("succeeded", "skipped") else 1)


if __name__ == "__main__":
    main()
