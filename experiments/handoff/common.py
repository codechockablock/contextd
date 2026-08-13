"""Shared machinery for the checkpoint/resume benchmark.

Harness-side (invokes models); the kernel supplies frozen views, compilation,
gating, scoring, and statistics. Zero-hidden-continuity rules enforced here:

- every fresh arm runs `claude -p` with --no-session-persistence, no tools,
  no settings, fresh tempdir cwd — no native history can exist;
- the continuous-control arm is the ONE arm allowed native history: it
  resumes the predecessor session by id (that is what it measures);
- the interactive arm gets exactly one MCP server: contextd serving a FROZEN
  VIEW truncated at the interruption event — the future is absent from the
  database it queries, and every read it makes is a metered, logged egress
  in that view;
- prereg/run/report records land in the LIVE ledger as content-NULL events
  (family=handoff_bench), so benchmark artifacts can never enter FTS and
  feed a later recall or contaminate the next experiment.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

CLAUDE_BIN = os.environ.get("EXP_CLAUDE_BIN", "claude")
CODEX_BIN = os.environ.get("EXP_CODEX_BIN", "codex")
RESULTS = REPO / "experiments" / "results"


@contextmanager
def contextd_home(path):
    """Point the in-process contextd at an archive home (a frozen view or a
    synthetic archive). Restores the previous binding on exit."""
    old = os.environ.get("CONTEXTD_HOME")
    os.environ["CONTEXTD_HOME"] = str(path)
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("CONTEXTD_HOME", None)
        else:
            os.environ["CONTEXTD_HOME"] = old


def live_conn():
    """The live ledger, for content-NULL benchmark records only."""
    home = Path(os.environ.get("CONTEXTD_LIVE_HOME", "~/.contextd")).expanduser()
    with contextd_home(home):
        from contextd.db import connect
        return connect()


def view_conn(view_home):
    with contextd_home(view_home):
        from contextd.db import connect
        from contextd import load_config
        return connect(), load_config()


# --- model runners -----------------------------------------------------------

def run_claude(prompt: str, model: str, resume: str | None = None,
               persist: bool = False, timeout: int = 900,
               mcp_config: Path | None = None, allowed_tools: str = "",
               env_extra: dict | None = None, max_turns: int | None = None) -> dict:
    """One claude -p call. Fresh arms: persist=False, no tools. Continuous
    arm: resume=<session-id>, persist=True. Interactive arm: mcp_config +
    allowed_tools naming only the contextd MCP tools."""
    sid = str(uuid.uuid4())
    tmp = tempfile.mkdtemp(prefix="ctx-handoff-")
    env = os.environ.copy()
    env["MCP_CONNECTION_NONBLOCKING"] = "false"
    env["ENABLE_TOOL_SEARCH"] = "off"
    env.update(env_extra or {})
    cmd = [CLAUDE_BIN, "-p", "--model", model,
           "--setting-sources", "", "--output-format", "json",
           "--max-budget-usd", "1.00"]
    if mcp_config is not None:
        cmd += ["--strict-mcp-config", "--mcp-config", str(mcp_config),
                "--tools", allowed_tools, "--allowedTools", allowed_tools]
    else:
        cmd += ["--tools", "", "--strict-mcp-config"]
    if resume:
        # fork on every resume: runs must never see each other's phase-2
        # turns, and the predecessor transcript must stay unmutated
        cmd += ["--resume", resume, "--fork-session"]
    else:
        cmd += ["--session-id", sid]
    if not persist:
        cmd += ["--no-session-persistence"]
    if max_turns:
        cmd += ["--max-turns", str(max_turns)]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, input=prompt, capture_output=True, text=True,
                           timeout=timeout, cwd=tmp, env=env)
    except subprocess.TimeoutExpired:
        return {"text": "", "session_id": resume or sid, "exit": None,
                "duration_ms": int((time.time() - t0) * 1000),
                "cost_usd": None, "stderr": "timeout",
                "dispatch_status": "timeout"}
    duration_ms = int((time.time() - t0) * 1000)
    text, cost = "", None
    if r.stdout.strip():
        try:
            out = json.loads(r.stdout)
            text = out.get("result") or ""
            cost = out.get("total_cost_usd")
        except json.JSONDecodeError:
            text = r.stdout
    return {"text": text, "session_id": resume or sid, "exit": r.returncode,
            "duration_ms": duration_ms, "cost_usd": cost,
            "stderr": r.stderr[-2000:] if r.returncode else "",
            "dispatch_status": "succeeded" if r.returncode == 0 else "failed"}


def run_codex(prompt: str, timeout: int = 900) -> dict:
    """One codex exec call (cross-vendor). Read-only sandbox, fresh cwd; codex
    keeps its own session files but each exec is a fresh conversation."""
    tmp = tempfile.mkdtemp(prefix="ctx-handoff-codex-")
    last = Path(tmp) / "last-message.txt"
    t0 = time.time()
    try:
        r = subprocess.run(
            [CODEX_BIN, "exec", "--sandbox", "read-only",
             "--skip-git-repo-check", "--output-last-message", str(last), "-"],
            input=prompt, capture_output=True, text=True, timeout=timeout,
            cwd=tmp)
    except subprocess.TimeoutExpired:
        return {"text": "", "exit": None, "dispatch_status": "timeout",
                "duration_ms": int((time.time() - t0) * 1000), "stderr": "timeout"}
    text = last.read_text().strip() if last.exists() else r.stdout.strip()
    return {"text": text, "exit": r.returncode,
            "duration_ms": int((time.time() - t0) * 1000),
            "stderr": r.stderr[-2000:] if r.returncode else "",
            "dispatch_status": "succeeded" if r.returncode == 0 else "failed"}


# --- context builders on a frozen view --------------------------------------

def render_tail(conn, cfg, budget: int) -> tuple[str, list]:
    """Naive maximal history: the most recent dialogue, verbatim, newest-last,
    packed to budget. This is the 'raw transcript' arm — the brute-force
    baseline the checkpoint has to beat on cost."""
    from contextd.gate import est_tokens, redact
    rows = conn.execute(
        "SELECT * FROM events WHERE source='claude_code' AND kind='message' "
        "ORDER BY id DESC LIMIT 2000").fetchall()
    items, used = [], 0
    for r in rows:
        meta = json.loads(r["meta"] or "{}")
        text = redact(cfg, (r["content"] or "").strip())
        header = f"--- [{r['id']}] {r['ts']} {meta.get('role', '?')} ---"
        cost = est_tokens(header + text)
        if used + cost > budget:
            break
        items.append((r["id"], header, text))
        used += cost
    items.reverse()
    ids = [i for i, _, _ in items]
    return "\n\n".join(h + "\n" + t for _, h, t in items), ids


def disclose_text(conn, cfg, text: str, meta: dict) -> dict:
    from contextd.gate import disclose
    return disclose(conn, cfg, text, meta)


def egress_spent_by_client(conn, client: str) -> dict:
    """Meter interactive-arm disclosure from the view's own ledger."""
    rows = conn.execute(
        "SELECT meta FROM events WHERE kind='egress'").fetchall()
    total = n = 0
    for r in rows:
        m = json.loads(r["meta"] or "{}")
        if m.get("client") == client:
            total += int(m.get("est_tokens") or 0)
            n += 1
    return {"queries": n, "est_tokens": total}


def write_mcp_config(dest: Path, view_home: Path, client: str) -> Path:
    # absolute, always: the MCP server is spawned with the model run's
    # tempdir as cwd, where a relative CONTEXTD_HOME silently becomes a
    # fresh empty archive (found the hard way in r1's interactive arm)
    cfg = {"mcpServers": {"contextd": {
        "command": str(REPO / ".venv" / "bin" / "ctx"),
        "args": ["serve", "--tools", "recall", "search", "timeline"],
        "env": {"CONTEXTD_HOME": str(Path(view_home).resolve()),
                "CONTEXTD_CLIENT": client},
    }}}
    dest.write_text(json.dumps(cfg, indent=2))
    return dest


# --- ledger records (live, content-NULL) -------------------------------------

def record(kind: str, meta: dict) -> int:
    conn = live_conn()
    from contextd.db import append_event
    return append_event(conn, "eval", kind, meta={"family": "handoff_bench", **meta})


def extract_citations(text: str, supplied: list) -> dict:
    cited = sorted({int(m) for m in re.findall(r"(?:\[|#)(\d{3,6})\]?", text)})
    supplied_set = {i for i in supplied if i is not None}
    return {"cited": cited, "valid": [c for c in cited if c in supplied_set]}


def code_blocks(text: str) -> dict:
    """Pull fenced python blocks tagged with a path comment, plus untagged
    ones. Returns {path_or_index: code}."""
    out = {}
    for i, m in enumerate(re.finditer(
            r"```(?:python|py)?\s*\n(.*?)```", text, re.S)):
        code = m.group(1)
        first = code.strip().splitlines()[0] if code.strip() else ""
        path = None
        pm = re.match(r"#\s*([\w./-]+\.py)\s*$", first)
        if pm:
            path = pm.group(1)
        out[path or f"block_{i}"] = code
    return out
