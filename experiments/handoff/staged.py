"""Staged two-phase task: real work, real interruption, objective resumption.

Session A (a real model) designs and partially implements a small library in
a scratch repo, making genuine decisions along the way. The operator's turns
plant two constraints that exist ONLY in the dialogue — a backwards-clock
rule and an oversized-request rule — which the public test suite deliberately
does not encode. Session A is then interrupted mid-implementation (refill
logic explicitly deferred to the next step that never comes).

Phase 2 resumes under each arm. Scoring is three-layered and preregistered:

  - public tests (visible in the repo): competence, mostly history-free;
  - HOLDOUT tests (harness-only): the dialogue-borne constraints — the
    objective measure of continuity, because the repository alone cannot
    reveal them;
  - a lexical rubric on the model's resumption brief: did it know the
    objective, the rejected alternative and its why-not, the constraints —
    with penalties for resurrecting the rejected approach or asking the
    operator for information the context already held.

The dialogue is ingested into a synthetic archive (a dedicated CONTEXTD_HOME,
never the live ledger) in the exact claude_code/message shape the live
ingester produces, so the checkpoint compiler runs unmodified.
"""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .common import code_blocks, contextd_home, run_claude

README = """# ratelimit

A tiny in-process rate limiter for the ingestion daemon.

Hard requirements (from the project brief):
- O(1) memory per key: state per key must not grow with request count.
- Deterministic and testable: the clock is injected (a zero-arg callable
  returning seconds as float); never call time.time()/time.monotonic()
  directly inside the library.
- No background threads, no timers: all bookkeeping happens inside calls.

API:
    RateLimiter(capacity: int, refill_rate: float, clock=...)
    .allow(key: str, tokens: int = 1) -> bool
    .remaining(key: str) -> float
"""

PUBLIC_TESTS = '''"""Public test suite for ratelimit (fixed; do not modify)."""
from ratelimit import RateLimiter


class FakeClock:
    def __init__(self, value=0.0):
        self.value = float(value)

    def __call__(self):
        return self.value


def test_allows_within_capacity_then_denies():
    rl = RateLimiter(capacity=2, refill_rate=1.0, clock=FakeClock(0.0))
    assert rl.allow("k") is True
    assert rl.allow("k") is True
    assert rl.allow("k") is False


def test_keys_are_isolated():
    rl = RateLimiter(capacity=1, refill_rate=1.0, clock=FakeClock(0.0))
    assert rl.allow("a") is True
    assert rl.allow("b") is True
    assert rl.allow("a") is False


def test_refill_after_elapsed_time():
    c = FakeClock(0.0)
    rl = RateLimiter(capacity=1, refill_rate=1.0, clock=c)
    assert rl.allow("k") is True
    assert rl.allow("k") is False
    c.value = 1.0
    assert rl.allow("k") is True


def test_refill_caps_at_capacity():
    c = FakeClock(0.0)
    rl = RateLimiter(capacity=2, refill_rate=1.0, clock=c)
    assert rl.allow("k") and rl.allow("k")
    c.value = 100.0
    assert rl.allow("k") and rl.allow("k")
    assert rl.allow("k") is False


def test_fractional_refill_accumulates():
    c = FakeClock(0.0)
    rl = RateLimiter(capacity=1, refill_rate=1.0, clock=c)
    assert rl.allow("k") is True
    c.value = 0.5
    assert rl.allow("k") is False
    c.value = 1.0
    assert rl.allow("k") is True


def test_remaining_reports_tokens():
    c = FakeClock(0.0)
    rl = RateLimiter(capacity=3, refill_rate=1.0, clock=c)
    assert rl.remaining("k") == 3.0
    rl.allow("k")
    assert rl.remaining("k") == 2.0


def test_multi_token_consumption():
    rl = RateLimiter(capacity=3, refill_rate=1.0, clock=FakeClock(0.0))
    assert rl.allow("k", tokens=2) is True
    assert rl.allow("k", tokens=2) is False
    assert rl.allow("k", tokens=1) is True
'''

HOLDOUT_TESTS = '''"""Holdout suite: constraints that exist only in the session-A dialogue.
Never shown to any model; applied by the harness at scoring time."""
from ratelimit import RateLimiter


class FakeClock:
    def __init__(self, value=0.0):
        self.value = float(value)

    def __call__(self):
        return self.value


def test_backwards_clock_grants_nothing_and_does_not_crash():
    c = FakeClock(100.0)
    rl = RateLimiter(capacity=2, refill_rate=1.0, clock=c)
    assert rl.allow("k") and rl.allow("k")
    c.value = 50.0  # NTP slew: clock went backwards
    assert rl.allow("k") is False


def test_backwards_clock_does_not_corrupt_future_refill():
    c = FakeClock(100.0)
    rl = RateLimiter(capacity=1, refill_rate=1.0, clock=c)
    assert rl.allow("k") is True
    c.value = 50.0
    assert rl.allow("k") is False
    c.value = 101.0  # forward again: at most normal accrual, no windfall
    assert rl.allow("k") is True
    assert rl.allow("k") is False


def test_oversized_request_is_denied_not_raised():
    rl = RateLimiter(capacity=3, refill_rate=1.0, clock=FakeClock(0.0))
    assert rl.allow("k", tokens=5) is False
'''

# --- session A protocol ------------------------------------------------------

T1_PROMPT = """You are the engineer on a small project. Repository files follow.

=== README.md ===
{readme}
=== test_ratelimit.py ===
{tests}

First step. Two candidate designs are on the table: a sliding-window log
(store recent request timestamps per key) and a token bucket (store a token
count + last-refill timestamp per key). Evaluate both against the project's
hard requirements, pick one, and RECORD your decision: state which you chose,
which you rejected, and exactly why the rejected one fails the requirements.

Then write the initial ratelimit.py: the class skeleton with __init__ and
injected clock wired up, but do NOT implement allow()/remaining() logic yet
(raise NotImplementedError). Output the complete file in one fenced python
block whose first line is exactly `# ratelimit.py`."""

T2_PROMPT = """Good. I applied your file; current test results:

{test_output}

Two constraints from production before you continue (these are hard
requirements even though the visible test file doesn't cover them):
1. Clocks can go BACKWARDS under NTP slew. If elapsed time is negative,
   treat it as zero — never crash, never grant tokens for it, and never let
   it corrupt later refill accounting.
2. If a single request asks for more tokens than the bucket's total
   capacity, return False immediately — deny, don't raise.

Now implement the per-key state and the consumption path of allow() and
remaining(). Do NOT implement refill yet — leave refill as a clearly marked
TODO; we'll do refill together in the next step after reviewing edge cases.
Output the complete updated ratelimit.py in one fenced python block whose
first line is exactly `# ratelimit.py`."""

PHASE2_INSTRUCTION = """Finish ratelimit.py so that the FULL test suite passes,
honoring every decision and constraint already made in this project. Then
write a short RESUMPTION BRIEF: the current objective, what was already done,
which design was previously rejected and why, and the constraints from
earlier work you are honoring. Do not ask questions; if information seems
missing, decide from the evidence you have.

Output format:
1. one fenced python block, first line exactly `# ratelimit.py`, containing
   the complete file;
2. the RESUMPTION BRIEF as plain text."""

RESUME_PREFIX = """You are a fresh model taking over an in-progress project.
The previous working session is gone; you never saw it.

{context_block}

=== REPOSITORY (current, at the interruption) ===
=== README.md ===
{readme}
=== test_ratelimit.py ===
{tests}
=== ratelimit.py (as left by the interrupted session) ===
{current_impl}

{instruction}"""

RUBRIC = {
    "facts": [
        {"id": "chose_token_bucket", "weight": 1.0,
         "all": [[r"token[- ]bucket"]]},
        {"id": "rejected_sliding_window", "weight": 1.5,
         "all": [[r"sliding[- ]window"],
                 [r"reject|rule[sd]? out|not (?:chosen|used|viable)|instead of|rather than|fails?|unbounded"]]},
        {"id": "why_not_memory", "weight": 1.5,
         "all": [[r"memory|O\(1\)|per[- ]request|grow|unbounded|timestamps? per"]]},
        {"id": "constraint_backwards_clock", "weight": 2.0,
         "all": [[r"backward|NTP|negative elapsed|clock (?:go|went|mov|slew)"]]},
        {"id": "constraint_oversized_deny", "weight": 2.0,
         "all": [[r"(?:exceed|more|greater|larger|over|above).{0,60}capacity|oversized|tokens? *> *cap"],
                 [r"deny|false|not raise|without rais|rather than rais"]]},
        {"id": "objective_finish_tests", "weight": 1.0,
         "all": [[r"refill|pass.{0,30}test|test.{0,30}pass|finish|complete"]]},
        {"id": "penalty_resurrect_sliding_window", "weight": -2.0,
         "all": [[r"(?:switch|migrate|use|prefer|implement|adopt)(?:\w|\s){0,40}sliding[- ]window"]]},
        {"id": "penalty_asks_operator", "weight": -1.0,
         "all": [[r"(?:could you|can you|please) (?:tell|share|provide|clarify)|what (?:was|were) the (?:decision|constraint)|\?\s*$"]]},
    ],
    "fixtures": [
        {"text": "I am continuing the token-bucket rate limiter. The sliding-window "
                 "log was rejected because its memory grows per request, violating "
                 "the O(1) requirement. I honor the constraint that a backwards "
                 "clock (NTP slew, negative elapsed) grants nothing, and requests "
                 "exceeding capacity are denied by returning False, not raised. "
                 "Objective: implement refill so the full test suite passes.",
         "expect": {"chose_token_bucket": True, "rejected_sliding_window": True,
                    "why_not_memory": True, "constraint_backwards_clock": True,
                    "constraint_oversized_deny": True, "objective_finish_tests": True,
                    "penalty_resurrect_sliding_window": False,
                    "penalty_asks_operator": False}},
        {"text": "Here is a rate limiter implementation.",
         "expect": {"chose_token_bucket": False, "rejected_sliding_window": False,
                    "why_not_memory": False, "constraint_backwards_clock": False,
                    "constraint_oversized_deny": False, "objective_finish_tests": False,
                    "penalty_resurrect_sliding_window": False,
                    "penalty_asks_operator": False}},
        {"text": "I recommend we switch to a sliding-window approach for accuracy. "
                 "Also, could you tell me what the previous constraints were?",
         "expect": {"penalty_resurrect_sliding_window": True,
                    "penalty_asks_operator": True,
                    "chose_token_bucket": False}},
    ],
}

WEIGHTS = {"public": 0.30, "holdout": 0.40, "brief": 0.30}
TASK_HINT = "ratelimit token bucket rate limiter design decisions constraints"


def make_repo(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "README.md").write_text(README)
    (dest / "test_ratelimit.py").write_text(PUBLIC_TESTS)
    # a real repo boundary: without it, repo_state's `git -C` ascends to the
    # enclosing checkout and the checkpoint's STATE section reports the wrong
    # repository (observed in the first staged run, 2026-08-13)
    if not (dest / ".git").exists():
        subprocess.run(["git", "init", "-q"], cwd=dest, capture_output=True)
    return dest


def run_pytest(repo: Path, test_file: str) -> dict:
    r = subprocess.run(
        [sys.executable, "-m", "pytest", test_file, "-q", "--no-header"],
        cwd=repo, capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    passed = failed = errors = 0
    import re
    for pat, target in ((r"(\d+) passed", "passed"), (r"(\d+) failed", "failed"),
                        (r"(\d+) error", "errors")):
        m = re.search(pat, out)
        if m:
            if target == "passed":
                passed = int(m.group(1))
            elif target == "failed":
                failed = int(m.group(1))
            else:
                errors = int(m.group(1))
    total = passed + failed + errors
    return {"exit": r.returncode, "passed": passed, "failed": failed,
            "errors": errors, "total": total,
            "frac": (passed / total) if total else 0.0,
            "tail": "\n".join(out.splitlines()[-15:])}


def apply_output(repo: Path, model_text: str) -> bool:
    """Write the model's `# ratelimit.py` block into the repo. Returns False
    when no applicable block exists (scored as zero, never skipped)."""
    blocks = code_blocks(model_text)
    for path, code in blocks.items():
        if path == "ratelimit.py":
            (repo / "ratelimit.py").write_text(code)
            return True
    # fall back: a single untagged block that mentions the class
    candidates = [c for c in blocks.values() if "class RateLimiter" in c]
    if len(candidates) == 1:
        (repo / "ratelimit.py").write_text(candidates[0])
        return True
    return False


def stage_session_a(workdir: Path, model: str = "haiku") -> dict:
    """Run session A for real: design turn, then scope-limited implementation
    turn, then interruption. Returns the transcript, session id, and the
    interrupted repo. Session persistence is ON for this one session (the
    continuous arm needs to resume it natively)."""
    repo = make_repo(workdir / "repo")
    transcript = []

    t1 = T1_PROMPT.format(readme=README, tests=PUBLIC_TESTS)
    r1 = run_claude(t1, model, persist=True)
    if r1["dispatch_status"] != "succeeded":
        raise RuntimeError(f"session A turn 1 failed: {r1['stderr']}")
    sid = r1["session_id"]
    transcript.append(("user", t1))
    transcript.append(("assistant", r1["text"]))
    if not apply_output(repo, r1["text"]):
        raise RuntimeError("session A turn 1 produced no applicable file")

    tests1 = run_pytest(repo, "test_ratelimit.py")
    t2 = T2_PROMPT.format(test_output=tests1["tail"])
    r2 = run_claude(t2, model, resume=sid, persist=True)
    if r2["dispatch_status"] != "succeeded":
        raise RuntimeError(f"session A turn 2 failed: {r2['stderr']}")
    transcript.append(("user", t2))
    transcript.append(("assistant", r2["text"]))
    if not apply_output(repo, r2["text"]):
        raise RuntimeError("session A turn 2 produced no applicable file")

    tests2 = run_pytest(repo, "test_ratelimit.py")
    (workdir / "transcript.json").write_text(json.dumps(transcript, indent=2))
    return {"session_id": sid, "model": model, "repo": str(repo),
            "transcript": transcript,
            "tests_at_interruption": tests2}


def build_synthetic_archive(home: Path, transcript: list,
                            session_id: str) -> dict:
    """Ingest the session-A dialogue into a dedicated archive home, in the
    exact shape the live claude_code ingester produces, then close the epoch.
    The live ledger is never touched."""
    with contextd_home(home):
        from contextd import load_config
        from contextd.db import append_event, connect
        from contextd.gate import redact
        conn = connect()
        cfg = load_config()
        first = last = None
        now = time.time()
        for i, (role, text) in enumerate(transcript):
            eid = append_event(
                conn, "claude_code", "message", uri=f"claude://staged-{i}",
                content=redact(cfg, text)[:8000],
                meta={"role": role, "session_id": session_id,
                      "visited_unix": now - (len(transcript) - i) * 60})
            first = first or eid
            last = eid
        epoch = append_event(conn, "claude_code", "epoch",
                             meta={"session_id": session_id,
                                   "start_event_id": first,
                                   "end_event_id": last})
        return {"home": str(home), "first": first, "last": last, "epoch": epoch}


def score_phase2(interrupted_repo: Path, scratch: Path, model_text: str) -> dict:
    """Objective + rubric scoring for one phase-2 output."""
    from contextd.experiment import score_output
    work = scratch / "eval-repo"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(interrupted_repo, work)
    applied = apply_output(work, model_text)
    if applied:
        public = run_pytest(work, "test_ratelimit.py")
        (work / "test_holdout.py").write_text(HOLDOUT_TESTS)
        holdout = run_pytest(work, "test_holdout.py")
    else:
        public = {"frac": 0.0, "passed": 0, "total": 0, "tail": "no file applied"}
        holdout = {"frac": 0.0, "passed": 0, "total": 0, "tail": "no file applied"}
    brief = score_output(RUBRIC, model_text)
    combined = round(WEIGHTS["public"] * public["frac"]
                     + WEIGHTS["holdout"] * holdout["frac"]
                     + WEIGHTS["brief"] * brief["score"], 4)
    return {"applied": applied, "public": public, "holdout": holdout,
            "brief": brief, "score": combined}
