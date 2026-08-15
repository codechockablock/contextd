# Delegation grants r2 — PROPOSAL

Status: **not in force.** r1 (docs/GRANTS.md, frozen 2026-08-14) remains the
contract until the operator freezes a revision. This document exists so the
revision is deliberate — drafted while nothing is urgent, adopted act by act,
each section carrying its own earn condition. Drafted 2026-08-15 from the
post-hardening state of the archive.

## What changed since r1 froze

Three facts, all verified against the ledger and the working tree:

1. **The synthetic half of grant calibration is done.** Mission D ran to
   completion (prereg #56; held-out bars met; dispatches under ceiling).
   Its verdict is capped at `CALIBRATION NOT EARNED` by design — only the
   operator field window (docs/GRANT_CALIBRATION.md, frozen bars: ≥20
   model-granted confirmations, ≥10 grant-active days, ≤1 veto, 0
   `VETO-HARMFUL`) can earn the rest. The window has not started:
   `field_tally.py` reads 0 confirmations, 0 grant-active days.

2. **The authority plane landed (2026-08-15) and re-prices human acts.**
   Every operator speech act — note, loop add/close/confirm, grant
   add/revoke, decision supersede — now requires a presence-bound Secure
   Enclave signature. Until a signer is enrolled (`native/build.sh`,
   `contextd-signer enroll`, `ctx security key register`), these acts
   refuse on the live archive. Two consequences worth stating plainly:
   the field trial cannot start until enrollment; and once it does, r1's
   thesis becomes structural — every retained per-item human act costs a
   biometric approval, so authority moves up the altitude ladder or the
   operator drowns in prompts. A grant is now the *only* sound mechanism
   for reducing per-item human acts.

3. **Pre-cutover grants are anomalies now.** Events #42847 (grant,
   "tonight"), #42878 (revoke), #42908 (grant, "field window night 2")
   carry operator authority the cutover cannot verify; the reduction
   refuses them as `legacy_unverified` and `ctx grant list` reports each
   as "the model cannot grant to itself". This is the migration contract
   working — history keeps its bytes, assurance is not retroactive — but
   the message is wrong about what happened, and the noise will recur on
   every listing forever.

## Proposed changes

### R2.1 — loop.confirm window ladder (gated on the field verdict)

No mechanism change; `--for`/`--until` already support any window. The
revision is contract guidance for how long a window may reasonably be:

| tier | window | precondition |
|---|---|---|
| exploratory | hours (`--for 8h`..`--for 24h`) | none — this is how the field trial itself runs |
| earned | up to 7 days, repo-scoped | field verdict `CALIBRATION EARNED — loop.confirm` |
| standing | up to 30 days, global permitted | a *second* window at the 7-day tier meeting the same frozen bars |
| never | no expiry | — (`--for`/`--until` stay mandatory forever) |

The morning-review ritual continues at every tier; the tally keeps
counting; a `VETO-HARMFUL` at any tier drops the class back to
exploratory until a fresh window re-earns it. Nothing renews on its own.

### R2.2 — loop.dismiss and decision.supersede stay registered, stay cold

Both remain in the registry (r1 decision, unchanged) and remain
ungrantable-in-practice until each earns its own field mission:

- `loop.dismiss` ground truth is harder than confirm — a wrong dismissal
  is silent by nature. A future mission must define the observable (the
  operator re-proposing or manually adding something the model dismissed)
  before any bars can be set. Sketch deliberately not designed here.
- `decision.supersede` was explicitly left unlicensed by the
  decisions-lifecycle mission ("model-proposed edges" in its not-licensed
  list). Global scope, archive-wide blast radius; its mission needs its
  own contract first.

### R2.3 — classes considered and refused

Recorded so they join the settled-negatives registry rather than
returning as fresh ideas:

- **`outcome.record`** — letting the model file hit/partial/miss verdicts
  on its own recalls corrupts the outcome tally, which is the repo's own
  "only evaluation that matters." A model grading its own homework is not
  a calibration question; it is an instrument-destruction question.
  Refused structurally, not deferred.
- **`grant.renew` / any auto-renew** — r1 said silence is never consent;
  the authority plane now enforces presence per grant. Stays refused.
- **`loop.close`** — superficially attractive (the model verifiably
  finishes work), but `close` is also the *veto channel*: the field
  protocol's `VETO:` convention rides on close-with-reason. A model
  holding `loop.close` could close loops in ways that collide with — or
  in the worst case impersonate the absence of — operator vetoes.
  Refused until close-as-completion and close-as-veto are mechanically
  distinct acts, which is a kernel design question, not a grant question.

### R2.4 — anomaly messages must distinguish history from attack

`ctx grant list` currently prints the same anomaly line for a
pre-cutover operator grant (history, expected, permanent) and for a
post-cutover unauthorized grant event (an alarm that should never
happen). Proposal: the reduction reports pre-cutover-unverifiable events
as `legacy pre-cutover grant (inert; see migration contract)` and
reserves the "model cannot grant to itself" line for events *after* the
cutover tip. Kernel change, small, needs its own tests; until it lands,
operators should read the three existing anomalies (#42847, #42878,
#42908) as migration artifacts, not incidents.

### R2.5 — the harness invariant, pinned as contract text

Earned by implementation today (repo `.claude/settings.json`) and worth
pinning so future harness configurations cannot drift:

> A model-session harness must never auto-approve CLI mutations that
> carry operator provenance (`ctx note`, `ctx loop
> add/close/reopen/confirm/dismiss`, `ctx grant`, `ctx decision`,
> `ctx outcome`). Those commands sit behind an explicit per-use human
> approval in the harness (`ask`), or behind the authority plane's
> presence-bound signature, or both. The model's only unattended write
> path is MCP, where grants are checked at act time and provenance is
> recorded `model-granted`. An allowlist that lets a model session mint
> operator-provenance events is authority laundering through the
> harness, exactly as utterance-binding was through the transcript.

## What r2 refuses to change

Everything in r1's refusal list, verbatim and unweakened: no
model-mediated granting, no wildcard classes, no meta-grants, no default
grants, no auto-renew, no retroactive authority, no laundering —
`model-granted` never upgrades to `operator`.

## Bringing any of this into force

1. Operator enrolls the production signer (one-time; unblocks every
   operator act, not just grants):

       native/build.sh
       native/contextd-signer enroll --key-id default > operator-key.der
       ctx security key register operator-key.der

2. Operator starts the field window (the trial r1 was built for):

       ctx grant add loop.confirm --repo "$(pwd)" --for 12h -m "field window night 3"

3. Mornings: the ritual in docs/GRANT_CALIBRATION.md;
   `experiments/grant_calibration/field_tally.py` shows running state.

4. On `CALIBRATION EARNED`: move R2.1 (and any other accepted section)
   into docs/GRANTS.md with a dated freeze line; delete this file.
