"""Cognitive checkpoint/restore: compile the active state of a project from
the archive so a fresh model — with zero access to the dead session — can
resume the actual work.

Two kernel jobs live here, both model-free:

1. **Frozen views** (:func:`freeze_view`): a truncated copy of the archive at
   an exact event id, in its own CONTEXTD_HOME. The hash chain is prefix-
   closed, so the copy is a *valid* archive whose tip is the interruption
   point. A resumed agent (or an experiment arm) pointed at a frozen view
   mechanically cannot see events from the future — the rows do not exist —
   which is what makes checkpoint experiments honest. Views are working
   copies for resumption and evaluation; the live archive stays canonical.

2. **Checkpoint compilation** (:func:`select_checkpoint_context`,
   :func:`compile_checkpoint`): a context compiler, not a search box. Given a
   token budget it allocates across evidence strata the archive already
   distinguishes:

     - the raw dialogue tail (the freshest working state, verbatim);
     - reconciled episode notes (model-written, derivation-anchored — the
       archive's own compressed history);
     - deliberate human notes (decisions the operator chose to record);
     - task-hint recall (the same gated selection walk recall uses).

   Every item keeps its ``[event-id]`` header, so each line of the package
   stays resolvable with ``ctx why`` / recall — the property the ablation
   experiments found survives aggressive compression (#41325..#41485).

The package is a *view produced for resumption*, never re-ingested as truth:
compilation discloses through the real gate (redacted, budgeted, receipted)
and the checkpoint's authority is exactly the archive events it cites.

Repository state is the caller's business: :func:`repo_state` gathers git
facts locally (subprocess, no network, nothing written to the ledger) and the
package renders them, because a checkpoint that cannot say what the working
tree looks like NOW strands the resumed agent in the archive's past.

The kernel never calls models. A distilled (model-compressed) checkpoint is
the harness's job — hooks/checkpoint_compile.py — same rule as synthesis
recall.
"""

import json
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

from .db import SCHEMA_VERSION, SCHEMA, _atomic_json, _db_tip, chain_state_paths, now_iso
from .gate import disclose, est_tokens, redact, select_items
from .liveness import capture_liveness, stale_line

VIEW_MARKER = "# frozen contextd view — a truncated working copy for resumption/evaluation."


def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return json.dumps(v)  # TOML basic strings share JSON's escape rules


def _view_config(src_home: Path) -> str:
    """The view keeps the source archive's gate discipline — redaction
    patterns, never-leave rules, budgets — and turns every ingester off:
    nothing new lands in a view except what its user deliberately appends."""
    import tomllib
    user = {}
    src_cfg = src_home / "config.toml"
    if src_cfg.exists():
        user = tomllib.loads(src_cfg.read_text())
    user.setdefault("ingest", {})["watch_dirs"] = []
    user.setdefault("browser", {}).update(chrome=False, safari=False)
    user.setdefault("claude", {})["enabled"] = False
    lines = [VIEW_MARKER]
    for section, values in user.items():
        if not isinstance(values, dict):
            lines.append(f"{section} = {_toml_value(values)}")
            continue
        subtables = {k: v for k, v in values.items() if isinstance(v, dict)}
        plain = {k: v for k, v in values.items() if not isinstance(v, dict)}
        lines.append(f"[{section}]")
        lines += [f"{k} = {_toml_value(v)}" for k, v in plain.items()]
        for name, sub in subtables.items():
            lines.append(f"[{section}.{name}]")
            lines += [f"{k} = {_toml_value(v)}" for k, v in sub.items()]
    return "\n".join(lines) + "\n"


class HandoffError(RuntimeError):
    pass


def freeze_view(src_db: Path, dest_home: Path, until_id: int) -> dict:
    """Copy events 1..until_id into a fresh archive home at dest_home.

    The chain is prefix-closed, so the copied rows verify as-is; the witness
    is written to match the new tip. FTS is rebuilt by the schema triggers on
    insert. Cursors and blobs are deliberately not copied: a view ingests
    nothing, and blob events (content NULL) never enter selection anyway.
    """
    dest_home = Path(dest_home)
    if dest_home.exists() and any(dest_home.iterdir()):
        raise HandoffError(f"destination {dest_home} is not empty")
    src = sqlite3.connect(f"file:{src_db}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    tip = src.execute(
        "SELECT id, chain_hash FROM events WHERE id <= ? "
        "ORDER BY id DESC LIMIT 1", (until_id,)).fetchone()
    if tip is None:
        src.close()
        raise HandoffError(f"no events at or before #{until_id}")
    real_tip = src.execute("SELECT MAX(id) AS m FROM events").fetchone()["m"]

    dest_home.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_home, 0o700)
    dst = sqlite3.connect(dest_home / "contextd.db")
    dst.row_factory = sqlite3.Row
    dst.executescript(SCHEMA)
    # A frozen view is built from the current schema by construction, so it is
    # current-version by definition. Without this stamp it reads as version 0
    # and the migration guard refuses to open it — a fresh database would be
    # mistaken for a pre-hardening archive awaiting migration.
    dst.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    rows = src.execute(
        "SELECT id, ts, source, kind, uri, content, content_hash, meta, "
        "prev_hash, chain_hash FROM events WHERE id <= ? ORDER BY id",
        (until_id,))
    n = 0
    dst.execute("BEGIN")
    for r in rows:
        dst.execute(
            "INSERT INTO events (id, ts, source, kind, uri, content, "
            "content_hash, meta, prev_hash, chain_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            tuple(r))
        n += 1
    dst.execute("INSERT INTO chain_state(singleton, witness_initialized) VALUES (1, 1)")
    dst.commit()
    src.close()
    witness_tip = _db_tip(dst)
    dst.close()
    _atomic_json(chain_state_paths(dest_home)["witness"],
                 {"version": 1, **witness_tip})
    (dest_home / "config.toml").write_text(_view_config(Path(src_db).parent))
    os.chmod(dest_home / "config.toml", 0o600)
    return {"home": str(dest_home), "events": n, "tip": witness_tip["id"],
            "source_tip": real_tip, "frozen": now_iso()}


def drop_view(dest_home: Path) -> None:
    """Remove a frozen view (a working copy, never the canonical archive)."""
    dest_home = Path(dest_home)
    if not (dest_home / "config.toml").exists() or \
            VIEW_MARKER not in (dest_home / "config.toml").read_text():
        raise HandoffError(f"{dest_home} is not a frozen view; refusing to remove")
    shutil.rmtree(dest_home)


# --- selection: the context compiler ----------------------------------------

def _actor(meta: dict) -> str:
    return meta.get("actor") or ""


def _render(cfg, row, extra: str = "") -> dict:
    text = redact(cfg, (row["content"] or "").strip())
    header = redact(cfg, f"--- [{row['id']}] {row['ts']} "
                         f"{row['source']}/{row['kind']}{extra} ---")
    return {"id": row["id"], "header": header, "text": text,
            "est_tokens": est_tokens(header + "\n" + text)}


def _pack(items_iter, budget: int, taken: set) -> list:
    out, used = [], 0
    for it in items_iter:
        if it["id"] in taken or not it["text"]:
            continue
        if used + it["est_tokens"] > budget:
            continue
        out.append(it)
        taken.add(it["id"])
        used += it["est_tokens"]
    return out


def select_checkpoint_context(conn, cfg, budget: int = 4000,
                              task_hint: str = "",
                              repo_path: str | None = None) -> dict:
    """Allocate the budget across the archive's evidence strata.

    Fractions are a policy under test, not a truth: tail 45%, reconciled
    episode notes 20%, human notes 15%, task-hint recall 20% (redistributed
    to the tail when no hint is given). Selection always runs against
    whatever archive the connection holds — compile from a frozen view and
    the future is unreachable by construction, no filtering required.

    Active open loops (docs/OPEN_LOOPS.md) are selected FIRST, by lifecycle
    state and scope only — never by recency or lexical match — into a
    reserved slice; an under-filled slice overflows back to the tail. If the
    slice cannot carry every active loop, the section names the omitted ids
    and count: silent loss is forbidden by contract.
    """
    from .decisions import reduce_supersessions
    from .loops import select_loop_section
    loop_sec = select_loop_section(conn, budget, repo_path)
    # supersession handling is two-pass (docs/DECISIONS.md r2): selection
    # runs reserve-free first; only when a carried chain's current version
    # is owed does it re-run with the reserve, so compiles that owe nothing
    # pay nothing. _select_strata is the shared single pass.
    sup = reduce_supersessions(conn)
    picked = _select_strata(conn, cfg, budget, task_hint, loop_sec, 0)
    sup_items: list = []
    sup_omitted: list = []
    reserve_engaged = False
    if sup["edges"]:
        if _owed_work(sup, picked):
            from .decisions import (SUPERSEDE_RESERVE_MIN,
                                    SUPERSEDE_RESERVE_SHARE)
            reserve = max(int(budget * SUPERSEDE_RESERVE_SHARE),
                          SUPERSEDE_RESERVE_MIN)
            picked = _select_strata(conn, cfg, budget, task_hint, loop_sec,
                                    reserve)
            reserve_engaged = True
        else:
            reserve = 0
        sup_items, sup_omitted = _apply_supersessions(
            conn, cfg, sup, reserve, picked["taken"], picked["sections"])
    return {"loops": loop_sec["items"], "loops_omitted": loop_sec["omitted"],
            "tail": picked["tail"], "episodes": picked["episodes"],
            "notes": picked["notes"], "recall": picked["recall"],
            "supersessions": sup_items, "supersessions_omitted": sup_omitted,
            "supersession_reserve_engaged": reserve_engaged,
            "budget": budget, "task_hint": task_hint}


def _owed_work(sup: dict, selected: dict) -> bool:
    """True iff a carried item's chain has a current version that is not
    itself carried (the condition that engages the reserve pass)."""
    from .decisions import current_version
    carried = set()
    for items in selected["sections"].values():
        carried.update(it["id"] for it in items if it["id"] is not None)
    for cid in carried:
        if cid in sup["edges"]:
            walk = current_version(sup["edges"], cid)
            if (not walk["cyclic"] and walk["current"] is not None
                    and walk["current"] not in carried):
                return True
    return False


def _select_strata(conn, cfg, budget: int, task_hint: str, loop_sec: dict,
                   sup_reserve: int) -> dict:
    remaining = budget - loop_sec["slice"] - sup_reserve
    shares = {"tail": 0.45, "episodes": 0.20, "notes": 0.15, "recall": 0.20}
    if not task_hint:
        shares["tail"] += shares.pop("recall")
    budgets = {k: int(remaining * v) for k, v in shares.items()}
    # loop under-fill overflows to the freshest stratum, per contract
    budgets["tail"] += max(loop_sec["slice"] - loop_sec["used"], 0)
    taken: set = set(loop_sec["ids"])

    # task recall first: these items earn their place by matching the task,
    # and the tail would otherwise swallow recent duplicates of them
    recall_items = []
    if task_hint:
        for it in select_items(conn, cfg, task_hint, budgets["recall"]):
            if it["id"] not in taken:
                recall_items.append({"id": it["id"], "header": it["header"],
                                     "text": it["text"],
                                     "est_tokens": it["est_tokens"]})
                taken.add(it["id"])

    def rows(sql, args=()):
        return conn.execute(sql, args).fetchall()

    notes = _pack(
        (_render(cfg, r) for r in rows(
            "SELECT * FROM events WHERE kind='note' "
            "AND json_extract(meta,'$.actor')='human' ORDER BY id DESC")),
        budgets["notes"], taken)

    episodes = _pack(
        (_render(cfg, r) for r in rows(
            "SELECT * FROM events WHERE kind='note' "
            "AND json_extract(meta,'$.actor')!='human' "
            "AND json_extract(meta,'$.derivation') IS NOT NULL "
            "ORDER BY id DESC")),
        budgets["episodes"], taken)

    tail_rows = rows(
        "SELECT * FROM events WHERE source='claude_code' AND kind='message' "
        "ORDER BY id DESC LIMIT 400")
    tail = _pack(
        (_render(cfg, r, extra=f" role={json.loads(r['meta'] or '{}').get('role', '?')}")
         for r in tail_rows),
        budgets["tail"], taken)

    # everything renders oldest-first inside its section; the tail is the
    # freshest evidence and the package places it last on purpose
    for section in (notes, episodes, tail):
        section.reverse()
    sections = {"tail": tail, "episodes": episodes, "notes": notes,
                "recall": recall_items}
    return {"tail": tail, "episodes": episodes, "notes": notes,
            "recall": recall_items, "taken": taken, "sections": sections,
            "reserve": sup_reserve}


def _apply_supersessions(conn, cfg, sup: dict, reserve: int, taken: set,
                         sections: dict) -> tuple[list, list]:
    """The compile contract (docs/DECISIONS.md): mark every carried
    superseded item, then carry each carried chain's current version from
    the reserve or name it loudly. Deterministic, model-free."""
    from .decisions import current_version, supersession_marker
    if not sup["edges"]:
        return [], []
    edges = sup["edges"]
    used = 0
    carried = set()
    for items in sections.values():
        carried.update(it["id"] for it in items if it["id"] is not None)
    for items in sections.values():
        for it in items:
            if it["id"] in edges:
                marker = redact(cfg, supersession_marker(edges, it["id"]))
                it["text"] = (it["text"] + "\n" + marker) if it["text"] \
                    else marker
                extra = est_tokens(marker)
                it["est_tokens"] += extra
                used += extra
    owed, seen_current = [], set()
    for cid in sorted(carried):
        if cid not in edges:
            continue
        walk = current_version(edges, cid)
        cur = walk["current"]
        if walk["cyclic"] or cur is None:
            continue  # the marker already says the chain is unresolvable
        if cur in carried or cur in taken or cur in seen_current:
            continue
        seen_current.add(cur)
        owed.append((cid, cur))
    sup_items, sup_omitted = [], []
    packing = reserve - 48  # held back so omission is always loud
    for cid, cur in owed:
        row = conn.execute(
            "SELECT * FROM events WHERE id = ?", (cur,)).fetchone()
        it = _render(cfg, row) if row is not None else None
        if it is None or not it["text"] or used + it["est_tokens"] > packing:
            sup_omitted.append({"carried": cid, "current": cur})
            continue
        sup_items.append(it)
        taken.add(cur)
        used += it["est_tokens"]
    for miss in sup_omitted:
        sup_items.append({
            "id": None, "header": "",
            "text": f"SUPERSESSION OMITTED: current version "
                    f"ev {miss['current']} of carried ev {miss['carried']} "
                    f"— run 'ctx recall'"})
    return sup_items, sup_omitted


# --- repository state --------------------------------------------------------

def _git(repo: Path, *args) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, timeout=30)
    return r.stdout.strip() if r.returncode == 0 else ""


def repo_state(repo: Path, test_cmd: list | None = None) -> dict:
    """Local git facts for the package's repository section. Read-only,
    no network, never written to the ledger — the resumed agent gets the
    repository normally; this only says what in it is current."""
    repo = Path(repo)
    state = {
        "path": str(repo),
        "branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        "commit": _git(repo, "rev-parse", "--short", "HEAD"),
        "log": _git(repo, "log", "--oneline", "-8"),
        "status": _git(repo, "status", "--short"),
        "diffstat": _git(repo, "diff", "--stat"),
    }
    if test_cmd:
        try:
            r = subprocess.run(test_cmd, cwd=repo, capture_output=True,
                               text=True, timeout=300)
            out = (r.stdout + r.stderr).strip()
            state["tests"] = {"cmd": " ".join(test_cmd), "exit": r.returncode,
                              "last_lines": "\n".join(out.splitlines()[-12:])}
        except (OSError, subprocess.TimeoutExpired) as e:
            state["tests"] = {"cmd": " ".join(test_cmd), "exit": None,
                              "last_lines": f"(could not run: {e})"}
    return state


# --- assembly ---------------------------------------------------------------

PREAMBLE = """=== CONTEXTD CHECKPOINT (compiled {compiled}, archive tip #{tip}) ===
The previous working session is gone. This package was compiled automatically
from the project archive so you can CONTINUE the work, not summarize it.
Bracketed [id]s are archive event ids; when you rely on an item, cite its id.
The sections run oldest-context-first; the raw dialogue tail at the end is
the freshest record of what was actually happening at the interruption."""

SECTION_TITLES = (
    ("loops", "ACTIVE OPEN LOOPS (operator-confirmed, lifecycle-selected)"),
    ("notes", "OPERATOR NOTES (deliberate, human-written)"),
    ("episodes", "RECONCILED EPISODE NOTES (model-written, anchor-verified)"),
    ("recall", "TASK-RELEVANT RECALL"),
    ("supersessions",
     "CURRENT DECISION VERSIONS (supersede items carried above)"),
    ("tail", "RAW DIALOGUE TAIL (the interrupted session, verbatim excerpts)"),
)


def render_package(selection: dict, repo: dict | None = None,
                   tip: int | None = None) -> str:
    parts = [PREAMBLE.format(compiled=now_iso(), tip=tip if tip is not None else "?")]
    if repo:
        lines = [f"branch {repo.get('branch')} @ {repo.get('commit')}",
                 "recent commits:", repo.get("log", "")]
        if repo.get("status"):
            lines += ["working tree (git status --short):", repo["status"]]
        else:
            lines.append("working tree clean")
        if repo.get("diffstat"):
            lines += ["uncommitted diffstat:", repo["diffstat"]]
        if repo.get("tests"):
            t = repo["tests"]
            lines.append(f"tests ({t['cmd']}): exit {t['exit']}")
            if t["last_lines"]:
                lines.append(t["last_lines"])
        parts.append("== REPOSITORY STATE (live, at compile time) ==\n"
                     + "\n".join(lines))
    for key, title in SECTION_TITLES:
        items = selection.get(key) or []
        if items:
            body = "\n\n".join(
                (it["header"] + "\n" + it["text"]) if it.get("header")
                else it["text"] for it in items)
            parts.append(f"== {title} ==\n{body}")
    return "\n\n".join(parts)


def compile_checkpoint(conn, cfg, budget: int = 4000, task_hint: str = "",
                       repo: dict | None = None, client: str = "checkpoint",
                       purpose: str = "") -> dict:
    """Compile, then disclose through the real gate. Returns the exact
    redacted package a resumed model may receive, with its egress receipt.
    Loop scope follows the repo argument: a repo checkpoint carries that
    repository's active loops, a repo-less checkpoint carries global ones."""
    repo_path = repo.get("path") if repo else None
    selection = select_checkpoint_context(conn, cfg, budget, task_hint,
                                          repo_path=repo_path)
    tip = _db_tip(conn)["id"]
    package = render_package(selection, repo=repo, tip=tip)
    # stale capture follows the loops-omission contract: named in-package
    # (first, so the resuming model sees it before any section) AND in the
    # egress meta; a fresh archive gets neither the line nor the key
    stale = [r for r in capture_liveness(conn, cfg) if r["stale"]]
    if stale:
        package = ("CAPTURE STALENESS: "
                   + "; ".join(stale_line(r) for r in stale)
                   + "\n\n" + package)
    # standing delegations are loud in every covering checkpoint
    # (docs/GRANTS.md): the operator and any resuming model cannot not
    # know what is currently delegated. A repo checkpoint shows global
    # grants plus its repo's; a global checkpoint shows everything active.
    from .grants import active_grants, grant_line
    from .loops import make_scope, scope_str
    grants = active_grants(conn)
    if repo_path:
        want = scope_str(make_scope(repo_path))
        grants = [g for g in grants
                  if g["scope"].get("global")
                  or scope_str(g["scope"]) == want]
    if grants:
        package = ("STANDING DELEGATIONS: "
                   + "; ".join(grant_line(g) for g in grants)
                   + "\n\n" + package)
    ids = sorted({it["id"]
                  for k in ("loops", "tail", "episodes", "notes", "recall",
                            "supersessions")
                  for it in selection[k] if it["id"] is not None})
    meta = {"type": "checkpoint", "tip": tip, "task_hint": task_hint,
            "purpose": purpose, "items": ids, "client": client,
            "loop_scope": repo_path or "global",
            "loops_omitted": selection.get("loops_omitted") or [],
            "supersessions_omitted":
                selection.get("supersessions_omitted") or []}
    if stale:
        meta["staleness"] = [{"source": r["source"],
                              "age_hours": r["age_hours"]} for r in stale]
    if grants:
        meta["delegations"] = [{"class": g["class"], "grant": g["id"],
                                "scope": scope_str(g["scope"]),
                                "expires": g["expires"]} for g in grants]
    disclosure = disclose(conn, cfg, package, meta)
    return {"package": disclosure["content"], "items": ids, "tip": tip,
            "egress_id": disclosure["egress_id"],
            "est_tokens": disclosure["est_tokens"], "selection": selection}
