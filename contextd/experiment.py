"""Context ablation experiments: freeze retrievals, intervene on them, and
account for every disclosure, run, and score as ledger events.

The question this module exists to answer is harder than "where did this come
from?" — it is "which recorded context actually mattered to the outcome?" The
kernel side stays model-free on principle: it freezes what recall would have
disclosed, applies interventions (drop an event, drop a provenance class or
origin, substitute a distillation, swap in an irrelevant token-matched set),
scores outputs against a preregistered rubric, and does the arithmetic. A
harness (experiments/) invokes models and reports back; models call the
kernel, the kernel never calls models.

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
- Provenance is two-layered: what the transport recorded (mechanical) and
  what the designer assessed the origin to be (recorded with its reason).
  Class claims are labeled with which layer they rest on; an item whose
  origin is 'mixed' or 'uncertain' blocks clean human-vs-model claims.
- A changed score is not a causal proof. Reports label effects as
  "distinguishable" / "suggestive" / "within noise" and say what the result
  does not license.
"""

import hashlib
import json
import random
from itertools import combinations

from .assurance import known_event_assurance
from .db import append_event
from .gate import disclose, est_tokens, select_items
# epistemic_type now lives in contextd/provenance.py — it is a pure classifier
# over recorded facts, not experiment machinery. Re-exported for the callers
# that have always imported it from here.
from .provenance import epistemic_type  # noqa: F401
from .search import search

PROVENANCE_CLASSES = ("human", "model", "activity", "other")


def provenance_class(source, kind, meta: dict) -> str:
    """Transport-derived class: who the *channel* says an event speaks for.
    'human': the operator's own words as recorded (CLI notes, watched files,
    user dialogue turns). 'model': model-written text (mcp/client notes,
    assistant/delegation/subagent turns). 'activity': behavioral traces.
    This is mechanical and can be wrong in substance — e.g. a harness prompt
    ingested as role=user — which is why frozen items also carry an assessed
    `origin` with its basis stated."""
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


def freeze(conn, cfg, query: str, budget: int, since: str = "", until: str = "",
           origin_overrides: dict | None = None, ranked_ids=None) -> dict:
    """Run the selection walk once and freeze its result. Every arm of an
    experiment is a subset of a frozen set — never a re-retrieval, so
    intervention effects are not confounded with retrieval variance. Items
    carry their rendered bytes; render-time drift is a refusal, not a warning.

    origin_overrides maps event id -> {"origin": ..., "reason": ...} for items
    whose transport class misstates their substantive origin (the reconciler-
    prompt-as-role=user case). Overrides are recorded, never silent."""
    origin_overrides = origin_overrides or {}
    items = []
    for it in select_items(conn, cfg, query, budget, since, until,
                           ranked_ids=ranked_ids):
        meta = json.loads(it["meta"]) if it["meta"] else {}
        prov = provenance_class(it["source"], it["kind"], meta)
        ov = origin_overrides.get(str(it["id"])) or origin_overrides.get(it["id"])
        items.append({
            "id": it["id"], "ts": it["ts"], "source": it["source"],
            "kind": it["kind"], "uri": it["uri"],
            "provenance": prov,
            "transport_role": meta.get("role") or meta.get("actor") or it["source"],
            "origin": ov["origin"] if ov else prov,
            "origin_basis": f"assessed: {ov['reason']}" if ov else "recorded",
            "epistemic_type": epistemic_type(
                it["source"],
                it["kind"],
                meta,
                known_event_assurance(conn, it),
            ),
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
    """Intervene on a frozen set. Arms compose drop_ids, drop_classes
    (transport-derived provenance), and drop_origins (assessed origin);
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
                 "origin": rep.get("provenance", "model"),
                 "origin_basis": "declared", "epistemic_type": "model_inference",
                 "header": header, "text": text,
                 "est_tokens": est_tokens(header + text),
                 "sha": _sha(header + "\n" + text)}]
    drop_ids = set(arm.get("drop_ids", []))
    drop_classes = set(arm.get("drop_classes", []))
    drop_origins = set(arm.get("drop_origins", []))
    return [it for it in frozen_items
            if it["id"] not in drop_ids
            and it["provenance"] not in drop_classes
            and it.get("origin", it["provenance"]) not in drop_origins]


def render_bundle(items: list) -> str:
    return "\n\n".join(it["header"] + "\n" + it["text"] for it in items)


def disclose_for_run(conn, cfg, exp_id: int, arm: dict, run_idx: int,
                     frozen_items: list, client: str = "experiment",
                     payload_factory=None) -> dict:
    """Render an arm's bundle and log it through the real gate before anything
    reaches a model. Returns {bundle, egress_id, items, sha, est_tokens}; a
    no-context arm discloses nothing and logs nothing. Frozen shas are
    re-verified so a bundle can never silently drift from what was registered."""
    kept = apply_arm(frozen_items, arm)
    if not kept:
        return {"bundle": None, "egress_id": None, "items": [], "sha": None,
                "est_tokens": 0}
    for it in kept:
        if _sha(it["header"] + "\n" + it["text"]) != it["sha"]:
            raise ValueError(f"frozen item {it['id']} drifted since registration")
    bundle = render_bundle(kept)
    payload = payload_factory(bundle) if payload_factory is not None else bundle
    disclosure = disclose(conn, cfg, payload, {
        "type": "experiment", "exp_id": exp_id, "arm": arm["name"],
        "run": run_idx, "items": [it["id"] for it in kept], "client": client})
    return {"bundle": bundle, "payload": disclosure["content"],
            "egress_id": disclosure["egress_id"],
            "items": [it["id"] for it in kept],
            "sha": _sha(bundle), "payload_sha": _sha(disclosure["content"]),
            "est_tokens": est_tokens(bundle),
            "dispatch_est_tokens": disclosure["est_tokens"]}


# --- scoring: deterministic, preregistered, self-testing ---------------------

def _fact_hit(fact: dict, text: str) -> bool:
    import re
    return all(any(re.search(alt, text, re.I | re.S) for alt in group)
               for group in fact["all"])


def score_output(rubric: dict, text: str) -> dict:
    """Weighted fraction of rubric facts matched. Negative-weight facts are
    penalties (e.g. recommending a recorded settled-negative, or flagging a
    decoy as a violation): they subtract from the score, which is clamped to
    [0, 1]. The denominator is the sum of positive weights only, so a perfect
    answer that trips no penalty scores 1.0."""
    hits = {f["id"]: _fact_hit(f, text) for f in rubric["facts"]}
    pos_total = sum(f.get("weight", 1.0) for f in rubric["facts"]
                    if f.get("weight", 1.0) > 0)
    got = sum(f.get("weight", 1.0) for f in rubric["facts"] if hits[f["id"]])
    score = got / pos_total if pos_total else 0.0
    return {"score": round(min(1.0, max(0.0, score)), 4), "hits": hits}


def validate_rubric(rubric: dict) -> list:
    """A scorer earns the right to run by passing known-answer fixtures: at
    least one where every positive-weight fact hits (a perfect answer) and one
    where none do (an empty/evasive answer). Rubrics with penalty facts should
    also include a plausible-bullshit fixture that trips them — enforced as a
    warning-level check: a penalty fact never exercised by any fixture is an
    error. Returns a list of problems; empty means valid."""
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
    pos = [f["id"] for f in facts if f.get("weight", 1.0) > 0]
    neg = [f["id"] for f in facts if f.get("weight", 1.0) < 0]
    fixtures = rubric.get("fixtures", [])
    saw_all_hit = saw_all_miss = False
    neg_exercised = set()
    for i, fx in enumerate(fixtures):
        got = score_output({"facts": facts}, fx["text"])["hits"]
        for fid, want in fx["expect"].items():
            if got.get(fid) != want:
                problems.append(f"fixture {i}: fact {fid} expected {want}, got {got.get(fid)}")
        pos_expect = {k: v for k, v in fx["expect"].items() if k in pos}
        if pos_expect and all(pos_expect.values()):
            saw_all_hit = True
        if pos_expect and not any(pos_expect.values()):
            saw_all_miss = True
        neg_exercised |= {k for k, v in fx["expect"].items() if k in neg and v}
    if not saw_all_hit:
        problems.append("no fixture where every positive fact hits (perfect answer)")
    if not saw_all_miss:
        problems.append("no fixture where no positive fact hits (empty/evasive answer)")
    for fid in neg:
        if fid not in neg_exercised:
            problems.append(f"penalty fact {fid} never exercised by any fixture "
                            "(add a plausible-bullshit fixture that trips it)")
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

def _spec_sets(spec: dict) -> dict:
    """Frozen sets by name; legacy single-freeze specs appear as {'default': ...}."""
    if "frozen_sets" in spec:
        return spec["frozen_sets"]
    return {"default": spec["frozen"]}


def register_experiment(conn, spec: dict) -> int:
    """Preregister the whole design — task, prompt, frozen sets, arms, rubric,
    model, planned n — as one ledger event before any run happens. Refuses a
    rubric that fails its fixtures. The spec_sha names the design; reruns of
    the same sha are replications."""
    problems = validate_rubric(spec["rubric"])
    if problems:
        raise ValueError("rubric failed validation: " + "; ".join(problems))
    sets = _spec_sets(spec)
    canonical = json.dumps({
        "task_id": spec["task_id"], "prompt_template": spec["prompt_template"],
        "arms": spec["arms"], "rubric": spec["rubric"],
        "frozen_shas": {name: [it["sha"] for it in fz["items"]]
                        for name, fz in sets.items()},
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
    """Record one run. The dispatched process's stderr is dropped here rather
    than archived: it is unbounded text produced by whatever the harness
    invoked, and an append-only log keeps it forever. The exit code carries
    the failure signal; the model's own output is retained (bounded and
    floor-redacted by the schema) because it is the measurement."""
    run = {k: v for k, v in run.items() if k != "stderr"}
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
        ctx = [r.get("context_est_tokens", 0) for r in rs]
        cited = [len(r.get("citations", {}).get("cited", [])) for r in rs]
        valid = [len(r.get("citations", {}).get("valid", [])) for r in rs]
        arms[name] = {
            "n": len(rs), "mean": round(_mean(scores), 4),
            "sd": round(_sd(scores), 4),
            "min": min(scores), "max": max(scores),
            "scores": scores,
            "context_tokens": round(_mean(ctx)) if ctx else 0,
            "score_per_1k_ctx": (round(_mean(scores) / (_mean(ctx) / 1000), 3)
                                 if ctx and _mean(ctx) > 0 else None),
            "citations_mean": round(_mean(cited), 1) if any(cited) else 0,
            "hallucinated_citations": sum(c - v for c, v in zip(cited, valid)),
            "run_event_ids": [r["event_id"] for r in rs],
            "egress_ids": [r.get("egress_id") for r in rs],
        }
    baseline_name = spec.get("baseline_arm", "full")
    baseline = arms.get(baseline_name)
    comparisons = []
    for arm_spec in spec["arms"]:
        name = arm_spec["name"]
        if baseline is None or name == baseline_name or name not in arms:
            continue
        a, b = baseline["scores"], arms[name]["scores"]
        p = perm_test(a, b)
        is_removal = bool(arm_spec.get("no_context") or arm_spec.get("drop_ids")
                          or arm_spec.get("drop_classes") or arm_spec.get("drop_origins"))
        comparisons.append({
            "arm": name, "baseline": baseline_name,
            "kind": "removal" if is_removal else "substitute",
            "delta_vs_baseline": round(arms[name]["mean"] - baseline["mean"], 4),
            "estimated_contribution": round(baseline["mean"] - arms[name]["mean"], 4),
            "p": p, "p_floor": p_floor(len(a), len(b)),
            "verdict": verdict(p),
            "removed": _describe_removal(arm_spec, spec),
        })
    ladder = _ladder_analysis(spec, arms)
    fact_rates = _fact_table(spec, by_arm)
    compression = _compression_loss(spec, arms, fact_rates)
    report = {
        "task_id": spec["task_id"], "model": spec["model"],
        "spec_sha": spec.get("spec_sha"),
        "n_runs": len(runs), "arms": arms, "comparisons": comparisons,
        "ladder": ladder, "fact_rates": fact_rates,
        "compression_loss": compression,
        "origin_caveats": _origin_caveats(spec),
        "interpretation": _interpret(spec, arms, comparisons, fact_rates, ladder,
                                     compression),
        "not_licensed": [
            "a single task on a single model; nothing here generalizes beyond it",
            "decoding is stochastic and temperature is not controllable via "
            "claude -p; per-run variance is measured, not eliminated",
            "rubric facts are lexical proxies for judgment quality; a correct "
            "paraphrase the patterns miss scores as absent, and a lexical hit "
            "is not proof of understanding",
            "verdict tiers (0.05/0.15) are conventions — the raw p and the "
            "design's p-floor are reported so readers can apply their own",
            "'within noise' means not detected at this n, not 'no effect'",
        ],
    }
    return report


def _origin_caveats(spec: dict) -> list:
    out = []
    for name, fz in _spec_sets(spec).items():
        for it in fz["items"]:
            if it.get("origin_basis", "recorded") != "recorded":
                out.append(f"item {it['id']} in set '{name}': transport says "
                           f"{it['provenance']}, origin {it['origin']} "
                           f"({it['origin_basis']})")
            elif it.get("origin") in ("mixed", "uncertain"):
                out.append(f"item {it['id']} in set '{name}': origin {it['origin']}")
    return out


def _ladder_analysis(spec: dict, arms: dict) -> list:
    """Consecutive contrasts along the declared context ladder (e.g. none ->
    distilled -> retrieved -> full): delta, p, and marginal score per extra
    1k context tokens. This is where 'more context stopped helping' shows up."""
    ladder = spec.get("ladder", [])
    out = []
    for lo, hi in zip(ladder, ladder[1:]):
        if lo not in arms or hi not in arms:
            continue
        a, b = arms[lo], arms[hi]
        p = perm_test(a["scores"], b["scores"])
        dtok = b["context_tokens"] - a["context_tokens"]
        delta = round(b["mean"] - a["mean"], 4)
        out.append({
            "from": lo, "to": hi, "delta": delta, "p": p,
            "verdict": verdict(p),
            "added_ctx_tokens": dtok,
            "marginal_per_1k": round(delta / (dtok / 1000), 3) if dtok else None,
        })
    return out


def _compression_loss(spec: dict, arms: dict, fact_rates: dict) -> dict | None:
    """When a distilled arm exists: which positive facts' evidence survived
    distillation, which were destroyed, and — via the preregistered loss_class
    on each fact — what *kind* of information the compression lost. Mechanical:
    a fact is 'lost in distillation' when its patterns no longer match the
    distillation text; the per-arm hit rates then show whether that loss cost
    anything downstream."""
    distilled = next((a for a in spec["arms"] if a.get("replace")), None)
    if not distilled or distilled["name"] not in arms:
        return None
    dtext = distilled["replace"]["text"]
    detail_arm = spec.get("detail_arm") or spec.get("baseline_arm", "full")
    lost, kept = [], []
    for f in spec["rubric"]["facts"]:
        if f.get("weight", 1.0) <= 0:
            continue
        entry = {
            "fact": f["id"], "loss_class": f.get("loss_class", "unclassified"),
            "rate_detail": fact_rates.get(f["id"], {}).get("rates", {}).get(detail_arm),
            "rate_distilled": fact_rates.get(f["id"], {}).get("rates", {}).get(distilled["name"]),
        }
        (kept if _fact_hit(f, dtext) else lost).append(entry)
    by_class = {}
    for e in lost:
        by_class.setdefault(e["loss_class"], []).append(e["fact"])
    return {"distilled_arm": distilled["name"], "detail_arm": detail_arm,
            "kept_in_distillation": kept, "lost_in_distillation": lost,
            "lost_by_class": by_class}


def _describe_removal(arm_spec: dict, spec: dict) -> str:
    if arm_spec.get("no_context"):
        return "all contextd context"
    if arm_spec.get("replace") is not None:
        rep = arm_spec["replace"]
        return (f"all detailed items, replaced by {rep.get('provenance', 'model')}"
                f"-derived {rep.get('origin', 'substitute')}")
    parts = []
    if arm_spec.get("context_set") and arm_spec["context_set"] != spec.get(
            "baseline_set", next(iter(_spec_sets(spec)))):
        parts.append(f"baseline set, using set '{arm_spec['context_set']}' instead")
    if arm_spec.get("drop_classes"):
        parts.append("transport class(es): " + ", ".join(arm_spec["drop_classes"]))
    if arm_spec.get("drop_origins"):
        parts.append("assessed origin(s): " + ", ".join(arm_spec["drop_origins"]))
    if arm_spec.get("drop_ids"):
        by_id = {it["id"]: it for fz in _spec_sets(spec).values()
                 for it in fz["items"]}
        names = [f"#{i} ({by_id[i]['provenance']} {by_id[i]['source']}/{by_id[i]['kind']})"
                 if i in by_id else f"#{i}" for i in arm_spec["drop_ids"]]
        parts.append("event(s) " + ", ".join(names))
    return "; ".join(parts) or "nothing"


def _fact_table(spec: dict, by_arm: dict) -> dict:
    """Per-fact hit rate per arm. The 'used' evidence lives here: a fact whose
    no-context rate is already high is model-knowable, and its presence in the
    archive proves little; a fact that appears only when its source event is in
    the bundle is being read, not remembered."""
    att = spec.get("attribution", {})
    if att and isinstance(next(iter(att.values()), None), dict):
        merged = {}
        for per_set in att.values():
            for fid, ids in per_set.items():
                merged.setdefault(fid, [])
                merged[fid] += [i for i in ids if i not in merged[fid]]
        att = merged
    table = {}
    for f in spec["rubric"]["facts"]:
        fid = f["id"]
        table[fid] = {
            "weight": f.get("weight", 1.0),
            "sources": att.get(fid, []),
            "rates": {arm: round(sum(1 for r in rs if r["hits"].get(fid)) / len(rs), 3)
                      for arm, rs in by_arm.items()},
        }
    return table


def _none_arm(spec: dict):
    return next((a["name"] for a in spec["arms"] if a.get("no_context")), None)


def _interpret(spec, arms, comparisons, fact_rates, ladder, compression) -> list:
    lines = []
    none_name = _none_arm(spec)
    base_name = spec.get("baseline_arm", "full")
    if base_name in arms and none_name in arms:
        full, none = arms[base_name], arms[none_name]
        comp = next((c for c in comparisons if c["arm"] == none_name), None)
        if comp:
            lines.append(
                f"{base_name} scored {full['mean']:.2f} vs {none['mean']:.2f} "
                f"with no context (Δ {comp['estimated_contribution']:+.2f}, "
                f"p={comp['p']}, {comp['verdict']}).")
    for step in ladder:
        if step["verdict"] == "within noise":
            lines.append(
                f"Ladder {step['from']} -> {step['to']}: Δ {step['delta']:+.2f} "
                f"for {step['added_ctx_tokens']:+d} context tokens — within "
                f"run-to-run noise (p={step['p']}); the extra context bought "
                f"nothing detectable at this n.")
        else:
            lines.append(
                f"Ladder {step['from']} -> {step['to']}: Δ {step['delta']:+.2f} "
                f"for {step['added_ctx_tokens']:+d} context tokens "
                f"({step['marginal_per_1k']} per 1k, p={step['p']}, "
                f"{step['verdict']}).")
    for c in comparisons:
        if c["arm"] == none_name or any(
                s["to"] == c["arm"] or s["from"] == c["arm"] for s in ladder):
            continue
        if c.get("kind") == "substitute":
            # a swapped bundle is a comparison, not a removal — "harmful
            # material" framing would be wrong in both directions
            lines.append(
                f"Arm {c['arm']} scored {c['delta_vs_baseline']:+.2f} vs "
                f"{c['baseline']} (p={c['p']}, {c['verdict']}).")
        elif c["verdict"] == "within noise":
            lines.append(
                f"Removing {c['removed']} moved the mean by "
                f"{c['delta_vs_baseline']:+.2f} — indistinguishable from "
                f"run-to-run noise at this n (p={c['p']}); no causal claim licensed.")
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
    if compression and compression["lost_by_class"]:
        classes = ", ".join(f"{k} ({', '.join(v)})"
                            for k, v in compression["lost_by_class"].items())
        lines.append(f"Distillation destroyed evidence for: {classes}.")
    if none_name:
        knowable = [fid for fid, row in fact_rates.items()
                    if row["weight"] > 0 and row["rates"].get(none_name, 0) >= 0.5]
        if knowable:
            lines.append(
                "Facts already knowable without context (no-context hit rate ≥ 50%): "
                + ", ".join(knowable)
                + " — their presence in the archive is not evidence the archive mattered.")
        sole_source = [fid for fid, row in fact_rates.items()
                       if row["weight"] > 0 and row["rates"].get(none_name, 1) == 0
                       and row["rates"].get(base_name, 0) >= 0.75 and row["sources"]]
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
    for name, a in sorted(report["arms"].items(), key=lambda kv: -kv[1]["mean"]):
        eff = (f"  {a['score_per_1k_ctx']}/1k" if a.get("score_per_1k_ctx")
               else "")
        out.append(f"  {name:<{width}}  score {a['mean']:.2f} ± {a['sd']:.2f}  "
                   f"(n={a['n']}, range {a['min']:.2f}–{a['max']:.2f})  "
                   f"ctx ~{a.get('context_tokens', 0)}tok{eff}")
    if report.get("ladder"):
        out.append("")
        out.append("  context ladder:")
        for s in report["ladder"]:
            marg = (f"  marginal {s['marginal_per_1k']}/1k"
                    if s.get("marginal_per_1k") is not None else "")
            out.append(f"    {s['from']} -> {s['to']}: Δ {s['delta']:+.2f} "
                       f"({s['added_ctx_tokens']:+d} ctx tok){marg}  "
                       f"p={s['p']}  {s['verdict']}")
    out.append("")
    for c in report["comparisons"]:
        out.append(f"  {c['arm']:<{width}}  Δ {c['delta_vs_baseline']:+.2f}  "
                   f"contribution {c['estimated_contribution']:+.2f}  "
                   f"p={c['p']} (floor {c['p_floor']})  {c['verdict']}")
    out.append("")
    arm_names = sorted(report["arms"])
    out.append("  fact                     " + "  ".join(
        f"{a[:10]:>10}" for a in arm_names))
    for fid, row in report["fact_rates"].items():
        rates = "  ".join(f"{row['rates'].get(a, 0):>10.2f}" for a in arm_names)
        src = ",".join(str(s) for s in row["sources"]) or "none"
        w = "" if row["weight"] > 0 else "  [penalty]"
        out.append(f"  {fid:<24} {rates}   src: {src}{w}")
    if report.get("compression_loss"):
        cl = report["compression_loss"]
        out.append("")
        out.append("  distillation kept: "
                   + (", ".join(e['fact'] for e in cl['kept_in_distillation']) or "nothing"))
        out.append("  distillation lost: "
                   + (", ".join(f"{e['fact']} [{e['loss_class']}]"
                                for e in cl['lost_in_distillation']) or "nothing"))
    if report.get("origin_caveats"):
        out.append("")
        out.append("  origin caveats:")
        for c in report["origin_caveats"]:
            out.append(f"    - {c}")
    out.append("")
    out.append("Interpretation:")
    for line in report["interpretation"]:
        out.append(f"  - {line}")
    out.append("")
    out.append("This result does not license:")
    for line in report["not_licensed"]:
        out.append(f"  - {line}")
    return "\n".join(out)
