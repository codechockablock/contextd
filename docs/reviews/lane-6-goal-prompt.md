# GOAL PROMPT — Lane 6: Advisory trajectory evidence

**Lane:** `gate-v1-lane-6` · **Depends on Lane 1 (landed).** Parallel with Lanes 2, 3, 4.
**Repo:** `~/contextd`. Detector source: `~/unified-stack` (vendored core `frontier_ops`).
If either is not there, halt and report — do not search or infer a path.
You are working in an **isolated git worktree** of contextd branched from `07f8998`. Do not commit.

## Objective

The gate proves an act was authorized and spent its authorization exactly once. It cannot prove
the act was *wanted*. A correctly-identified, correctly-authorized agent steered by injection into
an in-scope purchase produces a perfect record of a bad act — every identity control passes, the
mandate is valid, the chain verifies. No authorization primitive closes that gap.

What closes part of it is evidence about the trajectory that produced the act. This lane attaches
that as **signed advisory evidence** and does nothing else.

The claim this enables is **not** "we detect manipulation." It is: *when a dispute arises, the
record states what the trajectory looked like, what the detector was calibrated on, and what it
said — so an adjudicator can weigh it.*

## THE CONSTRAINT THAT DEFINES THIS LANE

**The score never blocks. Not in gate mode, not at any threshold, not behind a flag.**

The numbers are the reason. Verified byte-for-byte against `eval/CANONICAL_RESULTS.md`:

| Dataset | Traces | TPR | FPR |
|---|---|---|---|
| Internal | 518 | 94.5% | 10.9% |
| ATBench | 500 | 100.0% | 12.0% |
| AgentDojo | 357 | 93.2% | 0.8% |

**Two footnotes must travel with these numbers wherever they appear.** AgentDojo's 93.2% is
marked a **structural ceiling** — all 16 false negatives are dataset artifacts (9 banking traces
byte-identical to a benign peer, 7 slack traces truncated prefixes of benign peers). ATBench's
100% is post-harness-wiring, and its 12.0% FPR is explicitly accepted as a dual-use cost.

At 12% FPR roughly one in eight legitimate acts would be refused and the sidecar is uninstalled
inside a week. Note also: the spread from 0.8% to 12% is **fifteenfold, not the "fivefold" the
program text claims** — the canonical file wins, and the correction strengthens the argument.
Behavioral probes are additionally **frame-specific**: a signal calibrated in one framing does not
transfer cleanly to another, and a deployed marketplace is a different frame from any benchmark.
The score is always an observation made under stated conditions, never a fact about the act.

**Any API surface, field name, log line, or document produced by this lane that implies a verdict
is a defect.** `advisory_score`, not `is_malicious`. `trajectory_observation`, not
`threat_detected`.

## Scout findings — these change the design, read before building

### 1. There is no trajectory-level scoring seam. You must build the harness.

`Pipeline.evaluate(tool, content, result, result_signals) -> Observation` is **per-step**. The only
trajectory driver is `eval/run_evaluation.py::run_trace` (~131), a research script, and it reaches
into a private attribute (`pipe._current_reasoning = step['thinking']`, ~171) because no public
setter exists. You will drive the step loop and own session lifecycle yourself.

**Honest framing required in your report:** this lane pins to research-code internals at a specific
commit, not a supported API. `frontier_ops/__init__.py` exports only
`['ConstitutionSpec','ConstitutionalMetric','Pipeline']` — the integrity layer is not in `__all__`
at all. There is no changelog and no API-stability statement. Upstream refactors are silent
breakage.

### 2. Attach L2 first. L0 cannot be a light optional extra.

- **L2** — `from frontier_ops.integrity.layer import CognitiveIntegrityLayer`, with a real
  signature (`.set_user_task()`, `.evaluate(...) -> IntegrityVerdict`, `.reset()`), reaching only
  ~12 modules and importable with numpy alone. **This is the clean seam.**
- **L0** — `import frontier_ops.pipeline` reaches 57 modules and unconditionally imports **torch
  and transformers** at import time. It cannot be a light extra.

`GovernedAgent` is *not* usable here: it returns `GovernanceDecision(verdict, reason)` and by
design "exposes NO scores, thresholds, or signal breakdown," so it cannot source an evidence block.

### 3. Determinism: achievable, but only against four specific hazards.

Byte-identical evidence is a **stop condition** for this lane, and the pure-Python signal layer is
cleaner than expected — zero unseeded `random`/`np.random`, zero builtin `hash()` in any scoring
path, seeded RNG where it exists. The four real hazards:

1. **The natural return value can never be byte-identical.** `Observation` carries a `uuid4` id and
   a `datetime.now` timestamp, so `to_jsonl()` differs every call. **Build the block from an
   explicitly enumerated allow-list of scalar fields — never by serializing the object.**
2. **Device-dependent floating point.** Four modules select `mps` if available else `cpu`
   (`encoder.py` ~574, `semantic_track.py` ~218, `coherence.py` ~109–114,
   `result_action_tracker.py` ~77–81). Same input scores differently on Apple Silicon vs Linux.
   **Pin CPU on the deterministic path** and record the device in the block.
3. **Process-global mutable state.** `pipeline/core.py` ~141 holds a module-level
   `_session_suspicion_registry` keyed by session id, decayed 0.9× at every `Pipeline`
   construction and incremented +0.3 during scoring. There is **no `reset()`**. Re-scoring the
   same trajectory in the same process yields a different answer. Isolate per-process or reset the
   registry explicitly.
4. **Wall-clock decay.** `AuthorizationContext.suppression_factor()` uses
   `time.time() - self.timestamp` with a 30-minute half-life, multiplying a content score. Benign
   by default (a fresh context is synthesized per step), but a real hazard if
   `set_authorization_context()` is called once and steps replayed. **Forbid it on the
   deterministic path or require a frozen timestamp.**

### 4. An installed wheel silently runs a DIFFERENT, uncalibrated detector.

`unified-stack/pyproject.toml` ships `packages = ['frontier_ops']` only, but every model and
calibration path resolves to **repo-root/`models`** (~2.1 GB, not in the wheel). When absent,
`encoder.py` ~580 falls back to **downloading `all-MiniLM-L6-v2` from HuggingFace**, or degrades to
regex-only with a `logger.warning`, and conformal thresholds warn-and-continue **uncalibrated**.

**Therefore: the evidence block must assert model and calibration presence — digest the artifact
directories — and hard-fail if absent.** A silent regex-only degradation would emit a block that
looks valid and carries an uncalibrated number. That is the worst failure available to this lane.

### 5. Calibration pin: `4034b1a`, and the canonical file misattributes itself.

`4034b1a` (2026-04-10, *"fix(semantic_track): gate step_13 lightweight on content-only score"*) is
the commit the canonical file calls "this refresh". The file's own header names `573a7c5` because
**the file was written in `4034b1a`**. Pin `detector_version = 4034b1a`; the `frontier_ops` tree is
unchanged from there to current HEAD, so you may run current code and honestly attach these
numbers **without re-running any eval**. Also note `paper/main.tex` ~48 still carries stale
headline figures that `CANONICAL_RESULTS.md` explicitly overrides — do not source from it.

### 6. contextd already has an advisory-judge precedent. Use it.

Two registered schemas already implement exactly this shape — a calibrated external judge whose
verdicts are advisory instrument readings, logged as chained events, never acted on by the kernel:
`('eval','lineage_audit')` carrying `{egress_id, evidence_ids, judge_sha, verdict, ...}` and
`('eval','lineage_judge')` carrying `{calibration, corpus_digest, judge_sha, model, prereg_id,
prompt_version}`. That maps one-to-one onto an L0/L2 evidence block.

**Lead with this**: register `('eval','trajectory_score')` mirroring `lineage_audit`, plus a
one-time `('eval','trajectory_judge')` carrying the calibration snapshot. It reuses an established,
already-argued pattern instead of inventing one. The Lane 1 commerce path (`tx/execute` outcomes,
`redemptions`) is a legitimate **second** attach point, but state its semantics honestly: a block
riding a redemption outcome documents what the detector said about an act **that already
executed**.

### 7. Two hard contextd constraints the block must satisfy.

- **Closed registry.** `_validate` refuses undeclared fields and `validate_event_meta` refuses
  metadata entirely for unregistered types. The block cannot be smuggled onto an existing event.
- **No floats.** `canonical.py` refuses floats unconditionally — "IEEE-754 round-tripping is not
  reproducible across languages." **Scores must be quantized to integers on a fixed scale (e.g.
  basis points) with keys emitted in a fixed order.** This is the determinism gate's real teeth,
  and it forces the right design.

Also: `contextd/schemas.py` is being edited concurrently by Lane 2 (instruction-position pinning).
Coordinate; do not restructure what other lanes registered.

### 8. Environment mismatch — prefer a sidecar over a pip extra.

contextd's venv is **Python 3.14.3** with one runtime dependency (`mcp>=2`). unified-stack's venv is
**Python 3.13.11** with torch 2.11, transformers, sentence-transformers. cp314 wheel availability
for torch was not verified. **Gate zero:** check it. If cp314 wheels do not exist, an
out-of-process sidecar against the unified-stack checkout is the design — which also sidesteps the
Python-version question entirely and keeps contextd's dependency surface at one package.

## Definition of done

- [ ] contextd works **fully without the detector installed**. Base install pulls no detector
      dependency; absence produces acts with no advisory field — not errors, not a default score.
- [ ] When present, each act carries an advisory evidence block with, at minimum: the L2 (and/or
      L0) signal output; detector version and commit; the calibration snapshot identifier and the
      dataset it came from; the operating point and its TPR/FPR per `CANONICAL_RESULTS.md`; and an
      explicit statement that the observation is calibration-relative.
- [ ] The block is **inside the signed record**, covered by the chain, appended in the same
      transaction as the act. Advisory in meaning, not in durability.
- [ ] **Reproducibility test**: same trajectory, same detector version, same calibration snapshot
      produces a byte-identical block. A score that is not reproducible is not evidence.
- [ ] **Construct-validity test**: the score separates injected from clean trajectories on a
      held-out slice, and does **not** separate benign-but-unusual from benign-typical. A score
      that mostly detects "weird" rather than "steered" must be renamed to what it measures.
- [ ] **Latency budget** measured and published, including cold start (the only committed figure is
      13.7 ms/step warm; cold start — an 87 MB MiniLM load — is unmeasured, and CPU-pinning for
      determinism will make it slower). If it exceeds the operator's budget, the detector runs
      out-of-band and the block is attached by a later linked event — never by delaying the act.
- [ ] **Absence is recorded.** If the detector was configured but unavailable, the record says so.
      A missing advisory field must never be readable as a clean one.
- [ ] Integration test: an act with a **high** advisory score **completes normally**. Assert the
      act succeeded. This test exists to fail loudly if anyone ever wires the score into the
      decision path.
- [ ] Docs state the signal, its calibration, the FPR spread with both footnotes, the
      frame-specificity limit, and that it is not a verdict.

## Stop conditions — halt and report

- **Any nondeterminism in the evidence block** that you cannot eliminate. This invalidates the
  evidentiary framing entirely.
- **The construct-validity test fails** — the score separates unusual from typical rather than
  steered from clean. Report it, rename the field to what it measures, and stop. **This is a
  valuable negative result, not a failure of the mission.**
- The detector cannot be made optional without the base install pulling its dependencies.
- Integration requires changing `unified-stack` or `frontier_ops` beyond a bugfix.
- **Any impulse to gate, threshold, block, or warn-and-halt on the score.**
- **Any impulse to run a new experiment, sweep, ablation, retraining, or threshold tuning** on the
  detector. Those repos are inputs to this lane, not subjects of it. Write it down and stop.
- A number in `CANONICAL_RESULTS.md` disagrees with one in this brief — the canonical file wins.

## What Lane 5 may later claim from this

Only this, and only with the canonical numbers and both footnotes attached:

> The record states what the trajectory looked like, what the detector was calibrated on, and what
> it observed — attached to the act, inside the signed chain. It is advisory evidence for an
> adjudicator, not a verdict, and its operating characteristics vary by distribution (0.8%–12% FPR
> across the three checked-in datasets).

**Forbidden:** any detection rate without its FPR and dataset; any claim of manipulation detection
in deployment (no deployment data exists); any comparison asserting better detection than a
competitor (none publish comparable numbers on these benchmarks, and an unmatched comparison is
not a comparison).

## Verification gates

```bash
cd <your worktree>
pip install -e "." && python -m pytest -q          # base install carries no detector dep; baseline 685
python -c "from contextd.db import connect; connect()"   # works with no detector present
python -m pytest tests/ -q -k "advisory or detector or reproducib or construct or high_score"
python examples/gate_proof/concurrent_redemption.py      # frozen demo, EXPECT exit 0
git status --porcelain examples/gate_proof/ COMPARISON.md docs/reviews/   # EXPECT empty
```

Note: the program's stated gate `contextd.ledger_open()` **does not exist** — `contextd` exports
`home`, `load_config`, `DEFAULTS`, and the archive opens via `contextd.db.connect()`. The gate
above is corrected.

## Report format

Raw tool output, never a summary of state you did not observe. Include: each gate's output; the
reproducibility test run twice with the two blocks diffed; the construct-validity result **with its
held-out slice described**; measured warm and cold latency; and one honest paragraph on what the
score does **not** establish about an act.
