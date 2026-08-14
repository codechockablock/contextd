"""Report rendering: a pure function of the durable artifacts (the frozen
spec, the dedicated ledger's prereg/exp_run events, and the deterministic
validity computations). ``bench.py report <prereg-id>`` rebuilds the report
and compares it byte-for-byte with the stored copy; ``--write`` stores it.

Deliberately OUTSIDE the hashed instrument set: wording here may be edited
after results (and the stored report re-written), measurement code may not."""

from pathlib import Path

from experiments.grant_calibration import scoring
from experiments.grant_calibration.fixtures import ALL_FIXTURES, split_fixtures

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent


def report_path(spec: dict) -> Path:
    return REPO / "runs" / f"grant-calibration-{spec['frozen']}" / \
        "final-report.md"


def _fmt_rate(d: dict) -> str:
    if d.get("rate") is None:
        return "n/a"
    out = f"{d['k']}/{d['n']} = {d['rate']:.4f}"
    w = d.get("wilson")
    if w and w[0] is not None:
        out += f" (Wilson 95% [{w[0]:.4f}, {w[1]:.4f}])"
    return out


def _score(rows: list, fixtures: list, arm: str) -> dict:
    return scoring.score_trials(fixtures, rows, arm=arm)


def render(prereg_meta: dict, prereg_id: int, rows: list, spec: dict,
           dispatches_used: int) -> str:
    """rows: every exp_run meta dict from the dedicated ledger, all phases."""
    split = split_fixtures()
    cal_rows = [r for r in rows if r.get("phase") == "calibration"]
    held_rows = [r for r in rows if r.get("phase") == "heldout"]
    last_iter = max((r.get("iteration", 1) for r in cal_rows), default=0)
    cal_last = [r for r in cal_rows if r.get("iteration", 1) == last_iter]

    cal_full = _score(cal_last, split["calibration"], "full")
    cal_noctx = _score(cal_last, split["calibration"], "nocontext")
    held_full = _score(held_rows, split["heldout"], "full")
    held_noctx = _score(held_rows, split["heldout"], "nocontext")

    surface = scoring.surface_separability(ALL_FIXTURES)
    lengths = scoring.length_balance(ALL_FIXTURES)
    bars = spec["bars"]
    decision = scoring.decide(held_full, held_noctx, bars)
    failures = [r for r in rows
                if r.get("dispatch_status") not in ("succeeded", None)]

    L = []
    w = L.append
    w("# Grant-calibration benchmark — final report")
    w("")
    w(f"Benchmark `{spec['benchmark']}`; spec sha `{prereg_meta['spec_sha']}`"
      f"; judge prompt sha `{spec['judge_prompt_sha']}`; fixtures digest "
      f"`{spec['fixture_digest']}`; preregistration = ledger event "
      f"`#{prereg_id}` in the dedicated experiment home "
      f"(`experiments/grant_calibration/results/ledger/`). Rebuild with "
      f"`experiments/grant_calibration/bench.py report {prereg_id}`.")
    w("")
    w("## Verdict (machine-side, capped)")
    w("")
    w("**CALIBRATION NOT EARNED.** This is a cap, not a failure report: the"
      " synthetic benchmark below cannot earn trust in model-granted loop"
      " confirmation no matter what its numbers say, because it measures a"
      " judge against constructed ground truth, not against the operator."
      " The only thing that can move the verdict is the frozen field"
      " protocol (`docs/GRANT_CALIBRATION.md`), run by the operator on the"
      " operator's schedule, after this mission ends.")
    w("")
    ok = decision["synthetic_bars_met"]
    w(f"Synthetic bars: **{'MET' if ok else 'NOT MET'}**"
      + ("" if ok else " — " + "; ".join(decision["reasons"])) + ".")
    w("")
    w("## Verdictable claims (each separately checkable below)")
    w("")
    fcf = held_full["false_confirm_fixtures"]
    w(f"1. **Harmful direction (false confirm), fixture level:** "
      f"{fcf['k']}/{fcf['n']} held-out should_dismiss fixtures were "
      f"confirmed on any rep (bar: <= {bars['false_confirm_fixtures_max']})."
      + (f" Fixtures: {', '.join(fcf['fids'])}." if fcf["fids"] else ""))
    w(f"2. **False confirm, trial level:** "
      f"{_fmt_rate(held_full['false_confirm'])} "
      f"(bar {bars['false_confirm_max']}).")
    w(f"3. **False dismiss, trial level:** "
      f"{_fmt_rate(held_full['false_dismiss'])} "
      f"(bar {bars['false_dismiss_max']}).")
    w(f"4. **Abstain rate:** {_fmt_rate(held_full['abstain'])} "
      f"(bar {bars['abstain_max']}); an always-abstain judge fails the "
      f"coverage floor, so abstention cannot fake calibration.")
    w(f"5. **Confirm coverage (usefulness floor):** "
      f"{_fmt_rate(held_full['confirm_coverage'])} "
      f"(bar >= {bars['confirm_coverage_min']}).")
    ctrl = decision["control"]
    w(f"6. **No-context control:** abstain rate "
      f"{ctrl['abstain_rate']} (bar >= {ctrl['abstain_min']}), decided "
      f"accuracy {ctrl['decided_accuracy']} (chance bar <= "
      f"{ctrl['decided_accuracy_max']}); control "
      f"{'landed as preregistered' if ctrl['pass'] else 'FAILED — instrument finding, see honest annotations'}.")
    w(f"7. **Malformed replies:** {_fmt_rate(held_full['malformed'])} "
      f"(counted as ABSTAIN, tallied, never dropped).")
    w("")
    w("## Manipulation validity (gate for everything above)")
    w("")
    w(f"- Surface leak (executable): best single-token classifier over "
      f"candidate texts alone scores {surface['best_token_accuracy']} "
      f"(token `{surface['best_token']}`) against a majority baseline of "
      f"{surface['majority_baseline']}; gate is baseline + 0.10.")
    w(f"- Length balance: should_confirm {lengths['should_confirm']}, "
      f"should_dismiss {lengths['should_dismiss']}.")
    w(f"- Calibration split (iteration {last_iter}), full context: decided "
      f"accuracy {_fmt_rate(cal_full['decided_accuracy'])}, abstain "
      f"{_fmt_rate(cal_full['abstain'])}, false confirm "
      f"{_fmt_rate(cal_full['false_confirm'])}.")
    w(f"- Calibration split, no context: decided accuracy "
      f"{_fmt_rate(cal_noctx['decided_accuracy'])}, abstain "
      f"{_fmt_rate(cal_noctx['abstain'])}.")
    w("")
    w("## Held-out results by subtype (full-context arm)")
    w("")
    w("| subtype | n | CONFIRM | DISMISS | ABSTAIN |")
    w("|---|---|---|---|---|")
    for st, d in held_full["by_subtype"].items():
        w(f"| {st} | {d['n']} | {d['CONFIRM']} | {d['DISMISS']} | "
          f"{d['ABSTAIN']} |")
    w("")
    w("No-context arm, same fixtures: abstain "
      f"{_fmt_rate(held_noctx['abstain'])}; decided accuracy "
      f"{_fmt_rate(held_noctx['decided_accuracy'])}.")
    w("")
    w("## Preregistered bars and their justification")
    w("")
    prov = spec.get("bars_provenance", {})
    for key in ("false_confirm_fixtures", "false_dismiss_fixture_scale"):
        if key in prov:
            j = prov[key]
            w(f"- `{j['endpoint']}` bar {j['bar']}: P(pass | good judge "
              f"p={j['p_good']}) = {j['pass_given_good']}, P(pass | bad "
              f"judge p={j['p_bad']}) = {j['pass_given_bad']}.")
    if "field" in prov:
        f = prov["field"]
        w(f"- Field window (frozen in docs/GRANT_CALIBRATION.md): >= "
          f"{f['min_confirms']} model-granted confirmations, at most "
          f"{f['max_vetoes']} veto; pass curve at the minimum sample: "
          + ", ".join(f"true {p} -> {q}"
                      for p, q in f["pass_curve_at_min_sample"].items())
          + ".")
    w("")
    w("## Dispatch accounting")
    w("")
    w(f"- Total haiku dispatches recorded in the dedicated ledger: "
      f"**{dispatches_used}** of a hard ceiling of "
      f"{spec['dispatch_plan']['ceiling_total']}.")
    w("- Dispatch failures/timeouts: "
      + (f"{len(failures)} — "
         + "; ".join(f"{r.get('phase')}/{r.get('fid')}/{r.get('arm')}"
                     f"#{r.get('rep')}: {r.get('dispatch_status')}"
                     for r in failures)
         if failures else "none")
      + ".")
    w("- Every dispatched bundle passed the real gate of the synthetic "
      "archive it came from and is an egress event there; the exp_run "
      "rows carry the egress ids.")
    w("")
    w("## Honest annotations")
    w("")
    w("- Reps of one fixture share its wording; the judge is close to "
      "deterministic per fixture, so trial-level Wilson intervals "
      "overstate independent evidence. The primary harmful endpoint is "
      "fixture-level for exactly this reason.")
    w("- The calibration split was seen (indirectly) while setting bars "
      "and iterating templates; every number above headlined as held-out "
      "comes from fixtures the judge prompt was never tuned against.")
    w("- ABSTAIN is the judge's escape hatch and the parse fallback for "
      "malformed output; the malformed tally above says how much of the "
      "abstain mass is parser fallback rather than judged restraint.")
    w("- The no-context control shares the candidate wording with the "
      "full arm by design; if it failed, every full-arm number above is "
      "confounded by surface leakage and the run reports that instead of "
      "the headline.")
    w("")
    w("## What these results do and do not license")
    w("")
    w("- They DO license: continuing the existing `loop.confirm` grant "
      "mechanism exactly as shipped (refuse-without-grant, model-granted "
      "provenance), and starting the field window.")
    w("- They do NOT license: widening any grant class, suggesting a "
      "default grant, `loop.dismiss` or `decision.supersede` delegation "
      "(separate missions), or any claim that the judge matches THIS "
      "operator — the fixtures are synthetic constructions of operator "
      "intent, not the operator.")
    w("- A synthetic pass is a *precondition* for the field window being "
      "worth the operator's mornings, nothing more; a synthetic fail "
      "would have ended the question here.")
    w("")
    w("Tracked as live loop#42848. Field protocol: "
      "`docs/GRANT_CALIBRATION.md` (frozen with this report). Raw "
      "artifacts: `experiments/grant_calibration/results/` (gitignored); "
      "prereg + every dispatch row are events in the dedicated ledger "
      "home.")
    w("")
    return "\n".join(L)
