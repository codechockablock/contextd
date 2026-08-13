"""Synthetic worlds: isolated CONTEXTD_HOME archives built from the frozen
fixtures through public append paths only. Ground truth is the fixture's
plant labels — known by construction, never inferred.

Use-world construction (crossed, no per-arm curation):
- both arms share byte-identical dialogue, filler, and noise content;
- the with-arm adds exactly one operator act — `ctx loop add` of the
  acknowledgment utterance, verbatim (the opnote convention: the designer
  contributes no wording; choosing to externalize IS the simulated act);
- deterministic filler pushes the acknowledgment out of the raw tail so the
  without-arm reproduces the measured loss; mechanical preconditions verify
  the intended contrast before any model run.
"""

import random
from pathlib import Path

from experiments.handoff.common import contextd_home
from experiments.open_loops.fixtures import PROJECTS
from experiments.open_loops.scoring import normalize

FILLER_MESSAGES = 90
NOISE_NOTES = 30
TASK_HINT = "milestone status and refactor progress"  # never loop wording

FILLER_TOPICS = [
    "renaming the internal config keys for consistency",
    "tightening type hints across the helper modules",
    "reworking the logging format to structured lines",
    "profiling the hot path and caching the parse table",
    "cleaning up the CLI help texts and examples",
    "migrating the test fixtures to the builder helpers",
    "documenting the release steps in the runbook",
    "refactoring the error hierarchy into one module",
]


def _connect_here():
    from contextd.db import connect
    return connect()


def _msg(conn, role, text, session):
    from contextd.db import append_event
    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return append_event(conn, "claude_code", "message",
                        uri=f"claude://{session}-{n}", content=text,
                        meta={"role": role, "session_id": session})


def ack_message(fixture: dict, plant: dict) -> int:
    """Index of the acknowledgment: the last user message containing every
    match term. Mechanical; raises if the fixture cannot support it."""
    for i in range(len(fixture["messages"]) - 1, -1, -1):
        m = fixture["messages"][i]
        if m["role"] != "user":
            continue
        body = normalize(m["text"])
        if all(normalize(t) in body for t in plant["match"]):
            return i
    raise ValueError(f"{fixture['fid']}: no user message carries "
                     f"{plant['pid']}'s match terms")


def filler_lines(fid: str, project: str, n: int = FILLER_MESSAGES) -> list:
    rng = random.Random(f"{fid}:{project}")
    lines = []
    for i in range(n):
        topic = FILLER_TOPICS[rng.randrange(len(FILLER_TOPICS))]
        if i % 2 == 0:
            lines.append(("user", f"next chunk of {topic} — step {i}: "
                                  f"review the diff and keep it moving"))
        else:
            lines.append(("assistant",
                          f"step {i} of {topic} done: changes applied, "
                          f"tests still green, nothing else touched; "
                          f"continuing with the next slice of the work"))
    return lines


def noise_note_lines(fid: str, n: int = NOISE_NOTES) -> list:
    rng = random.Random(f"notes:{fid}")
    return [f"decision {i}: {FILLER_TOPICS[rng.randrange(len(FILLER_TOPICS))]}"
            f" — approach {i} accepted after review" for i in range(n)]


def build_dialogue_world(home: Path, fixture: dict) -> dict:
    """A capture-endpoint world: just the fixture dialogue, appended through
    the public path in an isolated archive. Returns message event ids."""
    home = Path(home)
    with contextd_home(home):
        conn = _connect_here()
        ids = [_msg(conn, m["role"], m["text"], fixture["fid"])
               for m in fixture["messages"]]
        conn.close()
    return {"home": str(home), "message_ids": ids}


def build_use_world(home: Path, fixture: dict, with_loop: bool) -> dict:
    """A use-endpoint world (one arm). See module docstring for the crossed
    construction; ground truth returned, never stored in the world."""
    home = Path(home)
    plant = next(p for p in fixture["planted"]
                 if p["label"] == "must_capture")
    ack_idx = ack_message(fixture, plant)
    ack_text = fixture["messages"][ack_idx]["text"]
    repo = PROJECTS[fixture["project"]]["repo"]
    loop_id = None
    with contextd_home(home):
        from contextd.db import append_event
        from contextd.loops import add_loop, make_scope
        conn = _connect_here()
        pre = [_msg(conn, m["role"], m["text"], fixture["fid"])
               for m in fixture["messages"][:ack_idx + 1]]
        if with_loop:
            loop_id = add_loop(conn, ack_text, make_scope(repo),
                               client="use-world",
                               source_events=[pre[-1]])["loop"]["id"]
        for m in fixture["messages"][ack_idx + 1:]:
            _msg(conn, m["role"], m["text"], fixture["fid"])
        for role, text in filler_lines(fixture["fid"], fixture["project"]):
            _msg(conn, role, text, fixture["fid"] + "-filler")
        for line in noise_note_lines(fixture["fid"]):
            append_event(conn, "note", "note", content=line,
                         meta={"actor": "human"})
        tip = conn.execute("SELECT MAX(id) FROM events").fetchone()[0]
        conn.close()
    return {"home": str(home), "repo": repo, "loop_id": loop_id,
            "ack_text": ack_text, "plant": plant, "tip": tip,
            "task_hint": TASK_HINT}


def compile_use_package(world: dict, budget: int = 4000) -> dict:
    """Compile the checkpoint for a use-world through the real pipeline
    (gated inside the world's own archive)."""
    with contextd_home(world["home"]):
        from contextd import load_config
        from contextd.handoff import compile_checkpoint
        conn = _connect_here()
        out = compile_checkpoint(
            conn, load_config(), budget=budget, task_hint=world["task_hint"],
            repo={"path": world["repo"], "branch": "main", "commit": "sim",
                  "log": "(synthetic project; no git history)"},
            client="open-loops-bench")
        conn.close()
    return out


def verify_use_contrast(world: dict, package: str, with_loop: bool) -> list:
    """Mechanical preconditions before any model run (abort-invalid rule):
    the with-arm package carries the loop verbatim in its dedicated section;
    the without-arm package contains the acknowledgment nowhere (neither
    tail nor recall resurrected it)."""
    problems = []
    norm_pkg = normalize(package)
    norm_ack = normalize(world["ack_text"])
    if with_loop:
        if "== ACTIVE OPEN LOOPS" not in package:
            problems.append("loops section missing in with-arm")
        if norm_ack not in norm_pkg:
            problems.append("loop text not carried in with-arm")
    else:
        if "== ACTIVE OPEN LOOPS" in package:
            problems.append("loops section present in without-arm")
        if norm_ack in norm_pkg:
            problems.append("acknowledgment leaked into without-arm context")
    return problems


def reduce_world_loops(home: Path) -> list:
    """Reduced loop records of a world, shaped for scoring.score_false_promotion."""
    with contextd_home(home):
        from contextd.loops import reduce_loops
        conn = _connect_here()
        reduced = reduce_loops(conn)["loops"]
        conn.close()
    return [{"id": lp["id"], "state": lp["state"], "text": lp["text"],
             "created_authority": lp["created_authority"],
             "created_state": lp["created_state"],
             "promoted_authority": lp["promoted_authority"]}
            for lp in reduced.values()]
