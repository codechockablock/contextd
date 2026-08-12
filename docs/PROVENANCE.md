# Derivation closure: what contextd can and cannot prove about model-derived context

*Written 2026-08-12, alongside the provenance hardening. This document is the
authority on what the provenance machinery claims; if code and this document
disagree, the code is overclaiming.*

## The problem this closes (and the one it cannot)

`gate.verify_anchors()` established: *"event #X was among the inputs supplied
to the model."* It never established: *"the claim carrying [X] is supported by
event #X."* A model (or a source that manipulates one) could attach a
perfectly valid anchor to a false claim and inherit the archive's authority —
provenance laundering with a valid receipt.

The machinery documented here closes the **structural** half of that gap
completely and makes the **semantic** half legible instead of pretending to
close it. That boundary is measured, pinned in tests, and stated below.

## The representation

A derived event (a reconciler note, a served synthesis distillate) carries a
derivation record binding it to the exact bytes its model saw:

```
meta.derivation = {
  "source_egress": <egress event id>,     # the disclosure the model received
  "anchors": [<event ids>],               # kernel-verified, never model-asserted
  "support": [{"event": id, "quote": "…", # optional verbatim spans
               "relation": "supports"|"contradicts"}]
}
```

- The **egress event** is the binding point on purpose: its content is the
  post-redaction, post-truncation payload, so provenance binds to what was
  disclosed — never silently to a rawer version of the underlying events.
  Quotes verify against the cited event's *segment of the disclosed bytes*
  (`provenance.disclosure_segments`), which is why a quote of a redacted
  secret fails and a quote of `[REDACTED:…]` succeeds.
- Synthesis egresses need no new fields: their existing
  `mode=synthesis` / `source_egress` / `anchors` meta *is* a derivation
  record, and the verifier consumes it directly.
- **Monotonicity** is required: `cited < source_egress < derived`. An honest
  archive cannot violate it (nothing is disclosed before it exists), and a
  true citation cycle turns out to *require* forging a future-item egress —
  so cycles are structurally impossible without leaving mechanical evidence.
- **Supersession** is an append-only annotation (`meta.supersedes: id`);
  history is never deleted, only outranked, and the closure walker surfaces it.
- **Contradictory or multiple parents** are representable via multiple
  anchors and `relation` labels. The labels are *recorded judgments*; the
  kernel verifies their structure, never their truth.

The reconciler binding: `hooks/reconcile.py` renders each dialogue message
with its event id, asks the model to cite per claim, and exports
`CONTEXTD_DERIVATION_SOURCE=<egress>` into the subprocess. The `note` tool
verifies proposed anchors against that egress's item list itself and stamps
`meta.derivation` — the model proposes text; the kernel writes lineage. Notes
citing undisclosed events are refused (retryable), because an anchor pointing
at an event never supplied launders authority and is worse than no note.
Like `CONTEXTD_CLIENT`, the binding is same-owner attribution, not
authentication.

## The verifier

`contextd/provenance.py` is deterministic and model-free. `ctx why <id>`
walks the full closure — claim → source disclosure → cited events →
recursively → leaf archive events — and reports, per claim, exactly one of
three **mechanical** levels:

| level | established mechanically |
|---|---|
| `unanchored` | the claim cites nothing |
| `anchored` | every cited id resolves, was in the source disclosure, predates it |
| `structurally_grounded` | anchored + every cited id carries a verbatim quote found in that event's disclosed segment |

and refuses malformed provenance outright: fabricated ids, citations outside
the disclosure, missing/wrong/undisclosed source egresses, non-monotonic
records, forged cycles, content-hash mismatches, quotes absent from the
disclosed bytes, support entries for events the text never cites, failed
dispatches, and chains terminating only in ungrounded model claims.

Closure verdicts: `grounded` (every terminal is an observation or human
assertion), `mixed` (some paths ground, some don't — including any uncited
claim text riding inside a cited note), `ungrounded` (no path reaches
grounded evidence), `malformed` (structural error anywhere).

`semantically_supported` and `contradicted` are **deliberately absent from
the kernel's vocabulary**. No kernel code path may emit them; a test pins
this (`test_verifier_never_emits_semantic_levels`), alongside the canonical
laundering case passing structural verification — so any future change that
claims to close the semantic gap mechanically must argue with a failing test.

## The measured boundary (deterministic adversarial suite)

Nineteen ground-truth-by-construction cases
(`experiments/provenance/cases.py`), each evaluated under three crossed
layers; matrix pinned in `tests/test_adversarial_matrix.py`:

| family | anchor baseline | closure | closure+quotes |
|---|---|---|---|
| fabrication (forged ids, wrong egress, forged cycle, tampered evidence, fabricated quote) | 2/6 | 5/6 | **6/6 rejected** |
| visibility (superseded-as-current, model-citing-model, uncited invention, model-claim-as-human, ungrounded recursion) | 0/5 | **5/5 flagged** | 5/5 flagged |
| semantic (false claim on valid anchor, true quote under overgeneralization, contradictory parents, human-to-human misattribution, injected instruction inside a grounded observation) | 0/5 | 0/5 | **0/5 — the boundary** |
| positive controls | 0 rejected | 0 rejected | 0 rejected |

## What this does NOT prove

- **A passing verification is not truth.** `structurally_grounded` means the
  evidence bytes sit verified next to the claim — a false paraphrase of true
  evidence still passes. Natural-language entailment is a semantic judgment
  and stays outside the kernel.
- **`observation` is not endorsement.** A hostile web page ingests as an
  observation *that this text appeared at this URI*. A grounded closure
  terminating in a page_visit proves the trail, not the content.
- **The binding is attribution, not authentication.** Same-owner processes
  remain trusted; an owner-level forger can still write a well-formed
  derivation record, exactly as the trust model has always said. The chain
  witness detects after-the-fact tampering, not a dishonest owner.
- **A claim bound to a different (but real and dispatched) disclosure that
  also contained the same events** is indistinguishable from an honest
  binding; the record *is* the binding.
- **Relation labels (`supports`/`contradicts`) are recorded, not verified.**
- **The trial results below are one task family on one model** (haiku via
  `claude -p`), with all the standard limits stated in every experiment
  report in this repository.

## Model trials

Preregistered in the live ledger before any run (events #41640, #41641,
#41642), with thresholds fixed in the registration meta; results reconstruct
from ledger events alone via
`experiments/provenance/model_trials.py report <exp_id>`.

### P1 — reconciler anchor compliance (exp #41640, report #41658): **earned**

The same six planted epochs reconciled under the old prompt vs the anchoring
prompt + kernel binding, identical dispatch machinery, haiku, crossed.

- **88.9%** of anchored-arm notes (16/18) carried ≥1 kernel-verified anchor
  (preregistered bar: 75%). The binding env demonstrably reaches the spawned
  MCP server (read-only wiring probe, run before the trial).
- Fact coverage **1.0 in both arms** — the rubrics saturated, so the
  no-harm criterion had full room to detect any drop and detected none;
  it also means this trial cannot claim anchoring *improves* coverage.
- Closure verdicts of the model's own notes: 3 grounded, 7 mixed,
  8 ungrounded — which is the epistemics working, not failing: notes citing
  only assistant messages honestly resolve to model-inference terminals
  instead of laundering into human assertions.

Consequence, per the preregistered decision rule: the production anchoring
prompt + binding (already the smallest possible integration) stays.

*(P2 and P3 results recorded below as they land)*
