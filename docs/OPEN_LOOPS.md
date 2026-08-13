# Open loops: operator-confirmed prospective state

*Contract frozen 2026-08-13, before implementation and before any model run
(mission discipline: design first, instrument second, model calls last).
Measured results are appended in the final section; if code and this document
disagree, the code is overclaiming.*

## The problem

The checkpoint/restore series established that compiled checkpoints beat
no-history resumption at every tested interruption point — and left one
measured gap. An older, conditional next action that the archive contained
was **not reliably recovered** by any automatic representation.

The raw record, stated precisely (correcting our own later prose): in exp
#41905 the `next_check` fact was recovered at rate **0.25 by the raw-tail and
recall arms** and 0.0 by the other six
(`experiments/results/handoff-r2-ranker-verdict-exp41905/report.json`,
`facts.next_check.rates`). The run log's summary sentence "stayed 0.00 across
all 8 arms" (`runs/handoff-20260812/final-report.md:46`) is an overstatement
and this document supersedes it. "Not reliably recovered" is the accurate
baseline; literal zero across every arm is not.

Four inference mechanisms then failed to close the gap (lexical markers
#42011, retro structural extraction #42067, live open/discharge tracking
#42123, model-maintained board #42127/#42163/#42168/#42240). Their shared
missing datum was the operator's prioritization — "that check is on the
board" — which was never externalized before the cutoff and cannot be
inferred from the tested dialogue view with both precision and recall.

One simulated explicit operator note, carried by the unchanged checkpoint
pipeline, moved the lost target from 0/5 to 5/5 (exp #42203, p=0.0079;
wrong-note control 0/5; total score +0.30, p=0.0317). That licenses exactly
one thing: **an explicit/confirmed state channel** — not transcript
mind-reading, not guaranteed capture.

This mechanism is that channel: a first-class, event-sourced **loop** entity
whose authority is always an operator act, whose lifecycle survives session
death by construction, and whose carriage into checkpoints is selected by
lifecycle state and scope — never by recency or lexical luck.

## The authority boundary

Valid loop state comes from operator acts. A model may **propose**; it may
never silently turn a guess into operator intent.

| authority label | meaning | who can produce it |
|---|---|---|
| `operator` | a direct human act through the CLI | `ctx loop ...` only |
| `model` | a model/harness proposal — non-authoritative | MCP `loop_candidate`, harness hooks |

All labels are **attribution, not authentication** — the same trust model
as `CONTEXTD_CLIENT` and `CONTEXTD_DERIVATION_SOURCE`
(`docs/PROVENANCE.md`): same-owner processes are trusted; labels make
honest wiring inspectable, they do not defeat a dishonest owner-level
process.

### Model-mediated confirmation: built, found unsound, retired

An `operator_via_model` relay (`loop_confirm(candidate_id, operator_quote)`)
was designed and implemented under this contract's first freeze: the kernel
verified that the quoted words occur verbatim in an ingested `role=user`
message appended *after* the candidate. Operator review identified the
defect before any field use, and it is disqualifying: the check proves
**utterance-occurrence, not assent**. Any post-candidate operator message
satisfies it — including an unrelated one, or a *rejecting* one ("no, drop
the dead-letter idea") — so a model could promote any candidate by quoting
arbitrary operator bytes, laundering them into operator authority. No
mechanical strengthening available to this record closes the gap:
content-overlap rules stay negation-blind, and assent-vs-rejection is
exactly the semantic judgment the kernel refuses everywhere else
(`docs/PROVENANCE.md`).

Per the mission rule — *if the installed client cannot provide the binding,
model-mediated confirmation is absent rather than behaviorally promised* —
the relay tools were **removed**, the `operator_via_model` label retired
unused, and a test pins the absence
(`tests/test_loops.py::test_no_model_facing_promotion_path_exists`).
Confirmation and dismissal are human CLI acts. A model that hears "yes,
board it" says so and hands the operator the one-line command; it cannot
act on it. This costs one command of friction and buys an authority
boundary that is sound by construction instead of plausible by wording.

## The lifecycle

Loops are event-sourced. Every lifecycle act is one append-only event of
kind `loop`; current state is rebuilt by a deterministic, model-free reducer
(`contextd/loops.py`) over those events in id order. No `UPDATE` or `DELETE`
is part of loop semantics (the events table forbids both by trigger).

A loop's **identity is the event id of the event that introduced it** (an
`add` or `candidate` event), written `loop#<id>`. Identity never changes
across transitions; `ctx why` and recall resolve it like any event.

### States

- `candidate` — model-suggested, non-authoritative. Never enters checkpoints.
- `open` — directly declared (`add`) or explicitly confirmed by the operator.
- `closed` — completed or deliberately retired, with optional reason.
- `dismissed` — a candidate the operator rejected; suppressed from
  re-proposal.
- reopened — externally observable as `open` with a nonzero reopen count and
  the reopening event in its history; selection treats it exactly as open.

### Transition table (op x current state)

| op | no loop | candidate | open | closed | dismissed |
|---|---|---|---|---|---|
| `add` | **create open** | **confirm it** (operator said it directly; the pending candidate with the same dedupe key becomes open) | idempotent: return existing | **create new loop** (fresh id; old stays closed) | **create new loop** (a direct operator add overrides suppression) |
| `candidate` | **create candidate** | idempotent: return existing | suppressed: return existing open loop, append nothing | **suppressed** (stale-resurrection defense; points at the closed loop) | **suppressed** (dismissal is a promise not to re-propose) |
| `confirm` | error | **-> open** | idempotent no-op | refuse: "closed; reopen instead" | refuse: "dismissed; re-add directly if it is a real priority" |
| `close` | error | refuse: "candidates are confirmed or dismissed" | **-> closed** | idempotent no-op | refuse |
| `reopen` | error | refuse | idempotent no-op ("already open") | **-> open** (reopen count +1) | refuse: "dismissed loops are re-added, not reopened" |
| `dismiss` | error | **-> dismissed** | refuse: "open loops are closed" | refuse | idempotent no-op |

Rules the table encodes:

- **Idempotency under retry.** Re-applying an op that already holds appends
  *nothing* and succeeds (exit 0), printing the current state. A crashed
  caller can always retry blindly. Creation retries are deduplicated by a
  **dedupe key**: `sha256(scope || normalized text)` where normalization is
  lowercase + whitespace collapse + trailing-period strip. `add`/`candidate`
  with a key matching a live (candidate/open) loop in the same scope returns
  that loop instead of forking a duplicate.
- **Invalid transitions refuse** — nonzero exit, explicit message, nothing
  appended. The write path never guesses; the read path (reducer) skips any
  historically invalid stored transition and surfaces it under `anomalies`
  rather than corrupting state.
- **Dedupe is normalized-exact only.** A reworded duplicate is a different
  loop; we refuse to claim semantic identity (that is a model judgment, and
  four experiments showed where model judgments of loop identity end up).

## Scope

Every loop is created with an explicit scope: `{"repo": "<resolved absolute
path>"}` or `{"global": true}`.

- CLI default: the git toplevel of the working directory if inside a
  repository, else global; `--repo PATH` and `--global` override.
- Scope is fixed at creation and inherited by every transition.
- **Historical dialogue is never retro-scoped.** Audited ground truth:
  `claude_code/message` events carry `role`/`session_id`/`visited_unix` and
  no repository identity; the transcript-path convention lives in a mutable
  cursor table outside the event chain. A loop's scope authority is the
  declaring act; `source_events` anchors are provenance, not scope.

## Checkpoint carriage

`ctx checkpoint --repo PATH` renders a dedicated section:

```
== ACTIVE OPEN LOOPS (operator-confirmed, lifecycle-selected) ==
```

- **Selection is lifecycle + scope only**: loops whose reduced state is
  `open` (including reopened) and whose scope matches the requested repo
  (resolved path equality); with no `--repo`, global-scoped loops. No FTS,
  no recency ranking, no competition with the human-notes stratum.
- Placement: first archive section, immediately after REPOSITORY STATE —
  ahead of notes, episodes, recall, and tail.
- Ordering: oldest-open first. The measured crowd-out victims are old loops;
  newest-first would rebuild the failure.
- Budget: a reserved slice (15% of the package budget, minimum 200 est.
  tokens — policy constants under test, chosen not measured) taken before
  the other strata split the remainder; an under-filled slice overflows back
  to the tail stratum (the stratum-under-fill artifact from the board
  trial, applied). Oldest-first ordering is likewise policy, not evidence.
- Loop events are disclosed content: their ids join the checkpoint egress
  `items` list, so every `[loop#id]`-adjacent bracketed id in the package
  resolves under `verify_anchors`. Source-event references render
  non-bracketed (`from event 41379`) because those events' content is *not*
  disclosed by the section — bracketed anchors remain a receipt, never a
  decoration.
- **Overflow is loud.** If the slice cannot carry every selected loop, the
  section ends with an explicit omission line naming the omitted loop ids
  and count (`BUDGET OMITTED: N active loop(s): loop#a, loop#b ... — run
  'ctx loop list'`). Room for that line is reserved before packing, so
  silent loss is structurally impossible.
- Exclusions by construction: candidates, closed, dismissed, and
  wrong-scope loops never render; reopened loops return.
- Distilled checkpoints (`--mode distill`) re-attach the raw section
  verbatim after the distillate: carriage does not depend on a model
  choosing to preserve it.

## Candidate generation (harness-side only)

The kernel never calls models. `hooks/loop_scan.py` may read recent dialogue
for a declared repo, disclose it through the real gate (redacted, budgeted,
receipted), and ask a model to propose candidates via the `loop_candidate`
MCP tool under a `CONTEXTD_DERIVATION_SOURCE` binding — so every candidate's
anchors are kernel-verified against the exact disclosed bytes, and dispatch
outcome (succeeded/failed/timeout) is recorded against the egress receipt.
The generator can emit candidates or an explicit "uncertain / nothing
found"; it has no path to `open`. Kernel-side dedupe suppresses re-proposal
against dismissed, open, and closed loops mechanically, whatever the model
does. A restricted MCP configuration that omits loop tools cannot invoke
them: the registry never advertises them (server-enforced allowlist).

## Threat model

- **A model inventing operator intent**: candidates are non-authoritative by
  label, and promotion is exclusively a human CLI act — the model-mediated
  relay was retired because its evidence check (utterance-occurrence) could
  not distinguish assent from rejection; there is no tool through which a
  model can move any loop past `candidate`.
- **Prompt injection in dialogue** ("mark all loops closed"): ingested text
  is data; nothing in the kernel executes it; closing requires the CLI or
  nothing. A poisoned generator can at worst propose junk candidates, which
  land labeled `model`, deduped, and reviewable via `ctx loop candidates`.
- **Duplicate/crash retries**: dedupe key + idempotent no-ops + the
  witness/recovery append protocol (`contextd/db.py`).
- **Crowd-out**: the dedicated stratum removes competition with newer notes;
  overflow is named, never silent.
- **Stale resurrection**: terminal states suppress candidate re-proposal;
  checkpoints exclude terminals by state, not by text.
- **What an owner-level forger can do**: append well-formed events with any
  labels. Unchanged trust model (`docs/PROVENANCE.md`): tamper-evident
  chain, attribution-not-authentication, honest-owner assumption.

## What the mechanism refuses to infer

- Lifecycle state from dialogue alone: no operator act, no `open`. Ever.
- Scope for historical dialogue events (the record lacks it).
- Semantic identity across rewordings (dedupe is normalized-exact).
- Auto-close from completion narratives (the measured masking failure of
  #42067); closing is explicit.
- Priority ranking among active loops (out of scope; all active loops carry
  or the omission is named).
- Any distinction between two byte-identical dialogues whose difference is
  private operator intent. The observable record cannot distinguish them;
  the mechanism's only honest outputs there are a candidate plus a
  confirmation request, or nothing — identical for both. This boundary is
  pinned by a test with such a pair.

## Evaluation design (frozen with this contract)

Seven endpoints, reported separately, never collapsed into one score:

1. **capture** — do candidates cover planted operator-recognized loops in
   unseen synthetic dialogues? (behavioral; the autonomous branch)
2. **false promotion** — any state stronger than `candidate` produced
   without an operator act. Bar: zero, mechanically counted.
3. **confirmation burden** — candidates proposed per true loop (precision
   side of capture; each false candidate costs one operator dismissal).
4. **lifecycle correctness** — deterministic: the full transition table,
   idempotency, refusal, crash-retry, backup/restore, replay.
5. **carriage** — deterministic: active/reopened present, terminal and
   wrong-scope absent, crowd-out resistance under many newer notes, loud
   overflow, distill re-attachment.
6. **fresh-model use** — behavioral: does a resumed model act on a carried
   loop it would otherwise miss? (with-section vs without-section arms)
7. **stale resurrection** — closed/dismissed loops absent from checkpoints
   and suppressed from re-proposal.

Instrument discipline (before any model run): synthetic **positive** and
**null** worlds with ground truth by construction; the scorer must recover
the positive world's plant and must return "nothing works" on the null;
thresholds and sample sizes derive from measured null/positive calibration,
not from prior studies' n or from observed results; the real evaluation is
preregistered in the live ledger before the first arm run. Held-out loop
wordings and more than one interruption shape and project. The
byte-identical pair with opposite private labels is part of the fixture set;
the only passing behaviors are uncertainty or confirmation-request on both.

Capture verdicts (`AUTONOMOUS CAPTURE EARNED` / `ASSISTED CAPTURE EARNED`)
additionally require a preregistered interaction with the **real operator**
using previously unseen wording and timing. Simulated operators calibrate
instruments; they cannot earn capture. If the operator trial has not run,
the verdict is `NOT EARNED` regardless of machine-side results, and
deterministic lifecycle results are reported separately without
generalizing capture.

## The operator trial (the only gate that can earn a capture verdict)

Machine-side results cannot earn `ASSISTED CAPTURE EARNED` or `AUTONOMOUS
CAPTURE EARNED`: those require the real operator, previously unseen loop
wording, and real timing. The protocol is fixed here before being offered;
running it is the operator's call. Simulated operators calibrate
instruments; they cannot stand in at this gate.

**Protocol v2 — frozen 2026-08-13.** (v1, frozen earlier the same day,
never ran. Operator review found its pass condition scored only the
survival of *externalized* loops: the recognized-but-never-externalized
list was collected but did not participate in scoring, so v1 could have
earned "assisted capture" while missing most recognized loops — it earned
assisted *carriage* at best. v2 puts the honest denominator in the pass
condition and stratifies by capture path. The defect was in the gate
definition, not in any result: no trial ran under v1.)

1. Window: the operator's next ~5 real working sessions (any repos), no
   scripted content, no reminders from the assistant mid-window; the window
   extends until at least 5 recognized loops exist (denominator floor).
2. Whenever the operator recognizes a real "that's on the board" moment,
   they externalize it in one short act of their choice: either
   `ctx loop add "<their own words>"` (path A), or saying it to a connected
   model, letting `loop_candidate` propose, and confirming with
   `ctx loop confirm <id>` (path B — confirmation is always the operator's
   CLI act; the model cannot do it).
3. Work and end sessions normally. On each later resumption in that repo,
   compile the normal checkpoint and note whether every still-relevant loop
   appears under ACTIVE OPEN LOOPS. Close/dismiss as reality dictates.
4. At window end, the operator lists every priority they recognized during
   the window but never externalized — including ones that died. This list
   is the rest of the denominator, on the operator's honor; the mechanism
   cannot see it, which is the point.

Endpoints, scored mechanically from the ledger plus the operator's list,
**stratified by capture path (A: direct add; B: candidate + CLI confirm)**
so neither path's success hides the other's failure:

- **assisted capture** = externalized loops / all recognized loops
  (externalized + the window-end list). Bar: >= 0.8 with denominator >= 5.
  This is the endpoint v1 lacked; without it the trial can only claim
  carriage.
- **carriage** = every still-relevant externalized loop present in every
  compiled resumption checkpoint for its repo. Bar: 100%.
- **burden** = false candidates the operator had to dismiss, per session.
  Bar: <= 1.0. (Path B only; path A has no burden by construction.)
- **false promotion** = any loop past `candidate` without an operator CLI
  act. Bar: 0.
- the operator's explicit yes/no on whether the workflow cost was
  acceptable.

`ASSISTED CAPTURE EARNED` requires every bar plus the operator's yes, with
per-path results reported separately (a pass carried entirely by path A is
reported as such — it says the CLI habit works, not that candidate
proposal helps). Autonomous capture would additionally require the scanner
proposing the operator's *unexternalized* priorities at the preregistered
bars on live dialogue — nothing below re-tests that branch on fixtures.

## CLI surface

```text
ctx loop add <text> [--repo PATH | --global] [--source-event ID ...]
ctx loop list [--repo PATH | --global] [--all]
ctx loop show <loop-id>
ctx loop close <loop-id> [--reason TEXT]
ctx loop reopen <loop-id> [--reason TEXT]
ctx loop candidates [--repo PATH | --global]
ctx loop confirm <candidate-id>
ctx loop dismiss <candidate-id> [--reason TEXT]
```

MCP tools (server-enforced allowlist; absent unless granted):
`loop_candidate` and `loop_list` only. There is no model-facing `add`,
`close`, `reopen`, `confirm`, or `dismiss` — promotion and dismissal are
human CLI acts (see "built, found unsound, retired" above).

## Measured results

Preregistration: live ledger event **#42331** (2026-08-13; spec sha
`5b95ed44…`, generator-prompt sha `5fbc7eef…`, fixture digest `f6813f45…`),
recorded after the wiring probe and a calibration-split pilot, before any
held-out run. Report: ledger event #42390; rebuild with
`.venv/bin/python experiments/open_loops/bench.py report 42331` (the rebuild
is verified to match the stored report). Raw artifacts:
`experiments/open_loops/results/open-loops-exp42331/`. All 52 model
dispatches succeeded; generator and resumption model: haiku.

Endpoints, separately, against the preregistered bars:

- **Capture (held-out, unseen wording): 11/12 = 0.917** (bar 10/12) — the
  machine-side capture decision passed. The one scored miss is a
  matching-rule artifact worth naming: the scanner *did* propose the item,
  quoting the operator's acknowledgment verbatim ("the property test is on
  the board — after the fixtures stabilize"), but the frozen match terms
  included a word from the assistant's proposal ("correction") that the
  operator's wording lacked. Preregistered scoring stands: it counts as a
  miss and as burden.
- **False promotion: 0** (bar 0). Every model-created loop in every world
  was born and stayed a `candidate` absent an operator act.
- **Confirmation burden: 0.167 false candidates per dialogue** (bar 1.0);
  0 distractor hits — no musing, completed action, or null dialogue drew a
  proposal. The three burden items were two end-of-session imperatives
  ("ship the pagination fix") whose execution the dialogue leaves
  unrecorded, plus the artifact miss above.
- **Identical pair: pass.** On byte-identical dialogues with opposite
  private labels the scanner proposed nothing on either — consistent
  behavior, no certainty asserted anywhere.
- **Lifecycle correctness / carriage / stale resurrection: deterministic
  gates**, all green — append-only replay, idempotent retry (including
  crash-retry on both sides of durability and a locked dedupe against
  racing writers), refusal of invalid transitions, scope separation,
  crowd-out resistance under 100 newer events, loud budget overflow naming
  omitted ids, closed/dismissed/candidate/wrong-project exclusion, reopen
  return, distill re-attachment, backup/restore state identity.
- **Fresh-model use: with-loop 0.75 vs without-loop 0.00, stratified
  permutation p = 0.0001** (bar 0.05) across 4 worlds x 2 crossed arms x 4
  runs. Per world (with-arm hits of 4): cf-amber-1 4, cm-gauge-2 4,
  cm-amber-1 3, cf-gauge-2 1. Exploratory annotation with receipts, never
  replacing the endpoint: in cf-gauge-2 all four with-arm outputs discussed
  the loop (one leads STILL OPEN with "loop#6, urgent") but three
  paraphrased ("cache never clears") past the strict substring indicator —
  the 0.75 is conservative. Without-arm runs never mentioned any target.

**Verdict: `NOT EARNED`.** The preregistered rule caps any capture verdict
until the real-operator trial (above) runs; machine-side results cannot
substitute for the operator. The deterministic lifecycle and carriage ship
on their own gates (the explicit-channel license from exp #42203 plus the
green deterministic and behavioral results here); the capture numbers above
are reported separately and license nothing beyond themselves.

## Limitations

- Everything behavioral above is a **haiku-tier property of synthetic
  fixture worlds** written by one designer. Held-out means unseen by the
  generator prompt and untouched during tuning (zero tuning iterations were
  in fact taken); it does not mean adversarial or ecologically sampled.
- The capture instrument's matching rule is normalized-substring on frozen
  terms; it under-credits paraphrase in both directions (one capture miss
  and roughly three use-arm hits were lost to it, all with receipts above).
  The conservative direction is deliberate.
- At n=12 held-out plants the capture design separates the coin-flip regime
  from >= 0.95 with both flip risks under 5%; a true 0.85-0.9 mechanism
  under-credits with p ~ 0.11 (calibration-frozen.json). n=13+ would be
  needed to separate 0.5 from 0.9.
- The retired utterance binding is a demonstrated negative, not a shipped
  caveat: proving an operator typed quoted words after a candidate existed
  cannot distinguish assent from rejection, so it could promote a candidate
  on rejecting words. Model-mediated confirmation is therefore absent; the
  whole authority surface remains same-owner attribution, not
  authentication (docs/PROVENANCE.md).
- No claim is made about other models, real archives, real operator
  wording/timing, cross-session ecology, or anything the operator trial
  alone can test.
