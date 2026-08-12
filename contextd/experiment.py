"""Context ablation experiments: freeze one retrieval, intervene on it, and
account for every disclosure, run, and score as ledger events.

The question this module exists to answer is harder than "where did this come
from?" — it is "which recorded context actually mattered to the outcome?" The
kernel side stays model-free on principle: it freezes what recall would have
disclosed, applies interventions (drop an event, drop a provenance class,
substitute a distillation), scores outputs against a preregistered rubric, and
does the arithmetic. A harness (experiments/) invokes models and reports back;
models call the kernel, the kernel never calls models.

Honesty constraints, enforced here rather than promised:
- Every bundle an arm sends to a model passes the real gate (budget, redaction)
  and lands as an egress event. Experiments cannot disclose off the books.
- Experiment records are events with content=NULL, so they never enter FTS —
  an experiment's outputs can never leak into a later recall and contaminate
  the next experiment.
- Rubrics must pass their own known-answer fixtures before registration; a
  scorer that cannot tell a perfect answer from an empty one never runs.
- The null is measured, not assumed: an exact permutation test over the
  observed runs, and the report states the smallest p the design can produce.
- A changed score is not a causal proof. Reports label effects as
  "distinguishable" / "suggestive" / "within noise" and say what the result
  does not license.
"""

import hashlib
import json
import random
from itertools import combinations

from .db import append_event
from .gate import check_budget, est_tokens, log_egress, redact, select_items
from .search import search

PROVENANCE_CLASSES = ("human", "model", "activity", "other")


def provenance_class(source, kind, meta: dict) -> str:
    """Derive who a stored event speaks for. 'human': the operator's own words
    (CLI notes, watched files, user dialogue turns). 'model': model-written
    text (mcp/client notes, assistant/delegation/subagent turns). 'activity':
    behavioral traces (browser visits). 'other': anything unclassified."""
    if kind == "note":
        return "human" if meta.get("actor") == "human" else "model"
    if source == "claude_code" and kind == "message":
        return "human" if meta.get("role") == "user" else "model"
    if kind == "page_visit":
        return "activity"
    if source == "fs":
        return "human"
    return "other"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def freeze(conn, cfg, query: str, budget: int, since: str = "", until: str = "") -> dict:
    """Run the selection walk once and freeze its result. Every arm of an
    experiment is a subset of this one frozen set — never a re-retrieval, so
    intervention effects are not confounded with retrieval variance. Items
    carry their rendered bytes; render-time drift is a refusal, not a warning."""
    items = []
    for it in select_items(conn, cfg, query, budget, since, until):
        meta = json.loads(it["meta"]) if it["meta"] else {}
        items.append({
            "id": it["id"], "ts": it["ts"], "source": it["source"],
            "kind": it["kind"], "uri": it["uri"],
            "provenance": provenance_class(it["source"], it["kind"], meta),
            "est_tokens": it["est_tokens"],
            "header": it["header"], "text": it["text"],
            "sha": _sha(it["header"] + "\n" + it["text"]),
        })
    matched = [h["id"] for h in search(conn, query, limit=40, highlight=False,
                                      since=since or None, until=until or None)]
    included = {it["id"] for it in items}
    return {"query": query, "budget": budget, "since": since, "until": until,
            "items": items,
            "matched_not_included": [i for i in matched if i not in included]}


def apply_arm(frozen_items: list, arm: dict) -> list:
    """Intervene on the frozen set. Arms compose drop_ids and drop_classes;
    'no_context' yields nothing; 'replace' substitutes a single synthetic item
    (e.g. a distilled summary) whose provenance is declared, not inferred."""
    if arm.get("no_context"):
        return []
    if arm.get("replace") is not None:
        rep = arm["replace"]
        text = rep["text"]
        header = (f"--- [substitute] {rep.get('provenance', 'model')}-derived "
                  f"{rep.get('origin', 'substitute context')} ---")
        return [{"id": None, "provenance": rep.get("provenance", "model"),
                 "header": header, "text": text,
                 "est_tokens": est_tokens(header + text),
                 "sha": _sha(header + "\n" + text)}]
    drop_ids = set(arm.get("drop_ids", []))
    drop_classes = set(arm.get("drop_classes", []))
    return [it for it in frozen_items
            if it["id"] not in drop_ids and it["provenance"] not in drop_classes]


def render_bundle(items: list) -> str:
    return "\n\n".join(it["header"] + "\n" + it["text"] for it in items)


def disclose_for_run(conn, cfg, exp_id: int, arm: dict, run_idx: int,
                     frozen_items: list, client: str = "experiment") -> dict:
    """Render an arm's bundle and log it through the real gate before anything
    reaches a model. Returns {bundle, egress_id, items, sha}; a no-context arm
    discloses nothing and logs nothing. Frozen shas are re-verified so a bundle
    can never silently drift from what was registered."""
    kept = apply_arm(frozen_items, arm)
    if not kept:
        return {"bundle": None, "egress_id": None, "items": [], "sha": None}
    for it in kept:
        if _sha(it["header"] + "\n" + it["text"]) != it["sha"]:
            raise ValueError(f"frozen item {it['id']} drifted since registration")
    bundle = render_bundle(kept)
    check_budget(conn, cfg, upcoming=est_tokens(bundle))
    egress_id = log_egress(conn, cfg, bundle, {
        "type": "experiment", "exp_id": exp_id, "arm": arm["name"],
        "run": run_idx, "items": [it["id"] for it in kept], "client": client})
    return {"bundle": bundle, "egress_id": egress_id,
            "items": [it["id"] for it in kept], "sha": _sha(bundle)}


# --- scoring: deterministic, preregistered, self-testing ---------------------

def _fact_hit(fact: dict, text: str) -> bool:
    import re
    return all(any(re.search(alt, text, re.I | re.S) for alt in group)
               for group in fact["all"])


def score_output(rubric: dict, text: str) -> dict:
    hits = {f["id"]: _fact_hit(f, text) for f in rubric["facts"]}
    total = sum(f.get("weight", 1.0) for f in rubric["facts"])
    got = sum(f.get("weight", 1.0) for f in rubric["facts"] if hits[f["id"]])
    return {"score": round(got / total, 4) if total else 0.0, "hits": hits}


def validate_rubric(rubric: dict) -> list:
    """A scorer earns the right to run by passing known-answer fixtures:
    at least one where every fact should hit and one where none should.
    Returns a list of problems; empty means valid."""
    import re
    problems = []
    facts = rubric.get("facts", [])
    if not facts:
        problems.append("rubric has no facts")
    for f in facts:
        if not f.get("all"):
            problems.append(f"fact {f.get('id')}: no pattern groups")
        for group in f.get("all", []):
            for alt in group:
                try:
                    re.compile(alt, re.I | re.S)
                except re.error as e:
                    problems.append(f"fact {f.get('id')}: bad pattern {alt!r}: {e}")
    fixtures = rubric.get("fixtures", [])
    saw_all_hit = saw_all_miss = False
    for i, fx in enumerate(fixtures):
        got = score_output({"facts": facts}, fx["text"])["hits"]
        for fid, want in fx["expect"].items():
            if got.get(fid) != want:
                problems.append(f"fixture {i}: fact {fid} expected {want}, got {got.get(fid)}")
        if fx["expect"] and all(fx["expect"].values()):
            saw_all_hit = True
        if fx["expect"] and not any(fx["expect"].values()):
            saw_all_miss = True
    if not saw_all_hit:
        problems.append("no fixture where every fact hits (perfect answer)")
    if not saw_all_miss:
        problems.append("no fixture where no fact hits (empty/evasive answer)")
    return problems


def attribute_facts(frozen_items: list, rubric: dict) -> dict:
    """Which frozen items carry which rubric facts — the 'retrieved vs used'
    bridge. A fact matched in an item's text names that item as a candidate
    source; a fact with no source in the frozen set can only come from the
    model itself (or from an arm's substitute)."""
    return {f["id"]: [it["id"] for it in frozen_items
                      if _fact_hit(f, it["header"] + "\n" + it["text"])]
            for f in rubric["facts"]}


# --- statistics: the null is the observed runs, relabeled --------------------

def _mean(xs):
    return sum(xs) / len(xs)


def _sd(xs):
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return (sum((x - m) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5


def _n_choose_k(n, k):
    out = 1
    for i in range(k):
        out = out * (n - i) // (i + 1)
    return out


def perm_test(a: list, b: list) -> float:
    """Exact two-sided permutation test on the difference of means: how often
    a relabeling of these very runs produces a gap at least this large. Exact
    when the split count is small; deterministic Monte Carlo (seed 0) above
    100k splits."""
    obs = abs(_mean(a) - _mean(b))
    pool = list(a) + list(b)
    n = len(a)
    total = _n_choose_k(len(pool), n)
    extreme = trials = 0
    if total <= 100_000:
        for idx in combinations(range(len(pool)), n):
            chosen = set(idx)
            ga = [pool[i] for i in idx]
            gb = [pool[i] for i in range(len(pool)) if i not in chosen]
            trials += 1
            if abs(_mean(ga) - _mean(gb)) >= obs - 1e-12:
                extreme += 1
    else:
        rng = random.Random(0)
        for _ in range(20_000):
            shuffled = pool[:]
            rng.shuffle(shuffled)
            ga, gb = shuffled[:n], shuffled[n:]
            trials += 1
            if abs(_mean(ga) - _mean(gb)) >= obs - 1e-12:
                extreme += 1
    return round(extreme / trials, 4)


def p_floor(n_a: int, n_b: int) -> float:
    """The smallest two-sided p this design can produce (complete separation).
    Reported so 'no detection' is never mistaken for 'no effect' when the
    design could not have detected one."""
    return round(2 / _n_choose_k(n_a + n_b, n_a), 4)


def verdict(p: float) -> str:
    # conventional tiers, stated with the raw p so readers can apply their own
    if p <= 0.05:
        return "distinguishable"
    if p <= 0.15:
        return "suggestive"
    return "within noise"


# --- ledger records ----------------------------------------------------------

def register_experiment(conn, spec: dict) -> int:
    """Preregister the whole design — task, prompt, frozen items, arms, rubric,
    model, planned n — as one ledger event before any run happens. Refuses a
    rubric that fails its fixtures. The spec_sha names the design; reruns of
    the same sha are replications."""
    problems = validate_rubric(spec["rubric"])
    if problems:
        raise ValueError("rubric failed validation: " + "; ".join(problems))
    canonical = json.dumps({
        "task_id": spec["task_id"], "prompt_template": spec["prompt_template"],
        "query": spec["query"], "budget": spec["budget"],
        "arms": spec["arms"], "rubric": spec["rubric"],
        "frozen_shas": [it["sha"] for it in spec["frozen"]["items"]],
        "model": spec["model"], "n_per_arm": spec["n_per_arm"],
    }, sort_keys=True)
    spec = {**spec, "spec_sha": _sha(canonical)}
    return append_event(conn, "eval", "experiment", meta=spec)


def get_experiment(conn, exp_id: int) -> dict:
    row = conn.execute(
        "SELECT meta FROM events WHERE id = ? AND kind = 'experiment'",
        (exp_id,)).fetchone()
    if not row:
        raise ValueError(f"no experiment event #{exp_id}")
    return json.loads(row["meta"])


def record_run(conn, exp_id: int, run: dict) -> int:
    return append_event(conn, "eval", "exp_run", meta={"exp_id": exp_id, **run})


def runs_for(conn, exp_id: int) -> list:
    rows = conn.execute(
        "SELECT id, meta FROM events WHERE kind = 'exp_run' ORDER BY id").fetchall()
    out = []
    for r in rows:
        m = json.loads(r["meta"])
        if m.get("exp_id") == exp_id:
            out.append({"event_id": r["id"], **m})
    return out


def record_report(conn, exp_id: int, report: dict) -> int:
    return append_event(conn, "eval", "exp_report", meta={"exp_id": exp_id, **report})


def build_report(conn, exp_id: int) -> dict:
    """Recompute the full report from ledger events alone — anyone holding the
    archive can rebuild it and get the same numbers."""
    spec = get_experiment(conn, exp_id)
    runs = runs_for(conn, exp_id)
    by_arm = {}
    for r in runs:
        by_arm.setdefault(r["arm"], []).append(r)
    arms = {}
    for name, rs in by_arm.items():
        scores = [r["score"] for r in rs]
        arms[name] = {
            "n": len(rs), "mean": round(_mean(scores), 4),
            "sd": round(_sd(scores), 4),
            "min": min(scores), "max": max(scores),
            "scores": scores,
            "run_event_ids": [r["event_id"] for r in rs],
            "egress_ids": [r.get("egress_id") for r in rs],
        }
    baseline = arms.get("full")
    comparisons = []
    for arm_spec in spec["arms"]:
        name = arm_spec["name"]
        if baseline is None or name == "full" or name not in arms:
            continue
        a, b = baseline["scores"], arms[name]["scores"]
        p = perm_test(a, b)
        comparisons.append({
            "arm": name,
            "delta_vs_full": round(arms[name]["mean"] - baseline["mean"], 4),
            "estimated_contribution": round(baseline["mean"] - arms[name]["mean"], 4),
            "p": p, "p_floor": p_floor(len(a), len(b)),
            "verdict": verdict(p),
            "removed": _describe_removal(arm_spec, spec),
        })
    fact_rates = _fact_table(spec, by_arm)
    return {
        "generated": None,  # stamped by record_report's event timestamp
        "task_id": spec["task_id"], "model": spec["model"],
        "spec_sha": spec.get("spec_sha"),
        "n_runs": len(runs), "arms": arms, "comparisons": comparisons,
        "fact_rates": fact_rates,
        "interpretation": _interpret(spec, arms, comparisons, fact_rates),
        "not_licensed": [
            "a single task on a single model; nothing here generalizes beyond it",
            "decoding is stochastic and temperature is not controllable via "
            "claude -p; per-run variance is measured, not eliminated",
            "rubric facts are lexical matches; a correct paraphrase the "
            "patterns miss scores as absent",
            "verdict tiers (0.05/0.15) are conventions — the raw p and the "
            "design's p-floor are reported so readers can apply their own",
            "'within noise' means not detected at this n, not 'no effect'",
        ],
    }


def _describe_removal(arm_spec: dict, spec: dict) -> str:
    if arm_spec.get("no_context"):
        return "all contextd context"
    if arm_spec.get("replace") is not None:
        rep = arm_spec["replace"]
        return (f"all detailed items, replaced by {rep.get('provenance', 'model')}"
                f"-derived {rep.get('origin', 'substitute')}")
    parts = []
    if arm_spec.get("drop_classes"):
        parts.append(f"provenance class(es): {', '.join(arm_spec['drop_classes'])}")
    if arm_spec.get("drop_ids"):
        by_id = {it["id"]: it for it in spec["frozen"]["items"]}
        names = [f"#{i} ({by_id[i]['provenance']} {by_id[i]['source']}/{by_id[i]['kind']})"
                 if i in by_id else f"#{i}" for i in arm_spec["drop_ids"]]
        parts.append("event(s) " + ", ".join(names))
    return "; ".join(parts) or "nothing"


def _fact_table(spec: dict, by_arm: dict) -> dict:
    """Per-fact hit rate per arm. The 'used' evidence lives here: a fact whose
    no-context rate is already high is model-knowable, and its presence in the
    archive proves little; a fact that appears only when its source event is in
    the bundle is being read, not remembered."""
    table = {}
    for f in spec["rubric"]["facts"]:
        fid = f["id"]
        table[fid] = {
            "sources": spec.get("attribution", {}).get(fid, []),
            "rates": {arm: round(sum(1 for r in rs if r["hits"].get(fid)) / len(rs), 3)
                      for arm, rs in by_arm.items()},
        }
    return table


def _interpret(spec, arms, comparisons, fact_rates) -> list:
    lines = []
    if "full" in arms and "no_context" in arms:
        full, none = arms["full"], arms["no_context"]
        comp = next((c for c in comparisons if c["arm"] == "no_context"), None)
        if comp:
            lines.append(
                f"Full context scored {full['mean']:.2f} vs {none['mean']:.2f} "
                f"without contextd (Δ {comp['estimated_contribution']:+.2f}, "
                f"p={comp['p']}, {comp['verdict']}).")
    for c in comparisons:
        if c["arm"] == "no_context":
            continue
        if c["verdict"] == "within noise":
            lines.append(
                f"Removing {c['removed']} moved the mean by "
                f"{c['delta_vs_full']:+.2f} — indistinguishable from run-to-run "
                f"noise at this n (p={c['p']}); no causal claim licensed.")
        elif c["estimated_contribution"] > 0:
            lines.append(
                f"Removing {c['removed']} cost {c['estimated_contribution']:+.2f} "
                f"(p={c['p']}, {c['verdict']}): this material appears causally "
                f"relevant to this task.")
        else:
            lines.append(
                f"Removing {c['removed']} improved the score by "
                f"{-c['estimated_contribution']:+.2f} (p={c['p']}, {c['verdict']}): "
                f"this material appears harmful to this task.")
    knowable = [fid for fid, row in fact_rates.items()
                if row["rates"].get("no_context", 0) >= 0.5]
    if knowable:
        lines.append(
            "Facts already knowable without context (no-context hit rate ≥ 50%): "
            + ", ".join(knowable)
            + " — their presence in the archive is not evidence the archive mattered.")
    sole_source = [fid for fid, row in fact_rates.items()
                   if row["rates"].get("no_context", 1) == 0
                   and row["rates"].get("full", 0) >= 0.75 and row["sources"]]
    if sole_source:
        lines.append(
            "Facts stated only when their source events were supplied: "
            + ", ".join(sole_source)
            + " — consistent with the archive being the sole source.")
    return lines


def format_report(report: dict) -> str:
    out = [f"EXPERIMENT {report['task_id']}  model={report['model']}  "
           f"runs={report['n_runs']}  spec={str(report.get('spec_sha'))[:12]}"]
    out.append("")
    width = max(len(a) for a in report["arms"])
    for name, a in sorted(report["arms"].items(),
                          key=lambda kv: -kv[1]["mean"]):
        out.append(f"  {name:<{width}}  score {a['mean']:.2f} ± {a['sd']:.2f}  "
                   f"(n={a['n']}, range {a['min']:.2f}–{a['max']:.2f})")
    out.append("")
    for c in report["comparisons"]:
        out.append(f"  {c['arm']:<{width}}  Δ {c['delta_vs_full']:+.2f}  "
                   f"contribution {c['estimated_contribution']:+.2f}  "
                   f"p={c['p']} (floor {c['p_floor']})  {c['verdict']}")
    out.append("")
    out.append("  fact                     " + "  ".join(
        f"{a[:10]:>10}" for a in sorted(report["arms"])))
    for fid, row in report["fact_rates"].items():
        rates = "  ".join(f"{row['rates'].get(a, 0):>10.2f}"
                          for a in sorted(report["arms"]))
        src = ",".join(str(s) for s in row["sources"]) or "none"
        out.append(f"  {fid:<24} {rates}   src: {src}")
    out.append("")
    out.append("Interpretation:")
    for line in report["interpretation"]:
        out.append(f"  - {line}")
    out.append("")
    out.append("This result does not license:")
    for line in report["not_licensed"]:
        out.append(f"  - {line}")
    return "\n".join(out)
