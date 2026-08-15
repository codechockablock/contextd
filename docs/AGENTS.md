# Agent plane: roles, workflows, and non-convertibility

Contract frozen 2026-08-15, before implementation.

## What "secure" can honestly mean here

No agent that reads untrusted content can be made immune to prompt
injection. That sentence is the foundation, not a caveat. Every mechanism
below exists because influence over what a model *thinks* must never be
convertible into authority over what the system *does*: an injected
instruction can still bend a model's words, but it cannot mint a
capability, forge a grant, reach an egress channel it wasn't issued,
promote a workflow, or upgrade its own provenance. Where a stronger claim
appears — the coordinator — it is immunity by input starvation (the
component never reads free text at all), never immunity by model
robustness.

Security claims about this plane are made empirically or not at all:
seeded corpora with planted injections, run against each role's actual
tool surface through the experiment harness, with preregistered
obedience-rate bars. "Immune" is never claimed; "0/N planted injections
obeyed under this tool surface, re-verified when the surface changes" is
the strongest available sentence.

## The trifecta rule

The load-bearing invariant, checked mechanically wherever workflows are
admitted: **no agent holds all three of (a) untrusted-content reading,
(b) valuable-context access, (c) an output channel (egress or archive
write authority)**. Two of three, always; which two defines the role.

## Roles

### Ingest workers — dumb on purpose

Whatever reads raw untrusted bytes is the least capable thing in the
system: parsers, normalizers, redactors, writing only through the
kernel's schema-closed ingest paths. No recall, no egress, no shell, no
MCP surface beyond the input queue. An injection in a watched file may
say anything it likes; the worker has no tools with which to obey.
Intelligence at the trust boundary is attack surface, so the boundary
gets none. (a)+(c-write-typed-only); never (b).

### Analysis workers — smart under gated disclosure

Where capable models belong: reconciler-pattern dispatches that receive
one receipted, redacted, budgeted bundle and write only anchor-verified
notes bound to that exact disclosure by a single-use expiring capability
token. No network, no shell, one allowlisted write tool. A poisoned
document can bias what a note says about it — that residual is bounded
and *measured* (the calibrated lineage audit), never assumed away, and
`ctx why` walks any claim back to its poisoned leaf, provenance-labeled.
(b)+(c-anchored-notes-only); never (a) raw — untrusted content reaches an
analysis worker only after ingest normalization, redaction, and
provenance labeling.

### The coordinator — starved, not hardened

The coordinator consumes only kernel-emitted structured state: health
sweeps, tallies, lane states, backlog ages, the workflow registry —
content-NULL events with closed metadata schemas, the event class
designed to never carry free text. It never reads dialogue, notes,
files, or model output. There is no channel to inject through, which is
the only honest way a coordinator gets to be trusted. Its whole
authority: dispatch workflows that are ALREADY promoted, file loop
candidates, and notify the operator. It can never author a workflow and
run it; authoring and dispatching are different roles with different
provenance, and nothing may hold both in one context. (b-structured-only);
never (a), and (c) only as dispatch-of-the-already-authorized.

### Workflow authors — draft-only

Any agent, subagents included, may draft a workflow artifact into
staging. Drafts are inert text. Nothing about authoring grants any power
to run; a subagent's draft records one more provenance hop and enters
the same promotion pipeline as anything else.

## Workflow artifacts

A workflow is a frozen, digest-pinned spec — the experiment-spec idiom
applied to operations: declared tool allowlist, input sources with trust
labels, scopes, dispatch budget, verification gates, output paths.
Runtime improvisation is refused by construction: workers execute
promoted artifacts, not conversational instructions.

Promotion runs two gates, in order:

1. **Policy lint, mechanical.** A workflow whose declared surfaces
   violate the trifecta rule is refused before any judgment is applied —
   untrusted-read plus egress in one spec never reaches a human or a
   grant. Undeclared tools, unlabeled inputs, missing budgets: refused.
2. **Authorization.** A new workflow family requires the operator's
   presence-bound signature (the grant ceremony). A family may graduate
   to grant-covered auto-promotion (`workflow.promote`, scoped to that
   family) only through the calibration pattern already running for
   loop.confirm: a preregistered field window, morning review, veto
   bars, any VETO-HARMFUL blocking the verdict. Approval is a signature
   or an earned standing grant — never ambient, never inferred.

## What this contract refuses

- No agent with all three trifecta legs, ever, including "temporarily".
- No model in the kernel (unchanged, load-bearing).
- No coordinator input that can carry free text; a schema regression
  that would let content reach it must fail closed, as the closed
  registry already fails.
- No runtime-improvised workflows; no author-and-dispatch in one hand.
- No new grant classes without their own calibration missions
  (docs/GRANTS-r2-proposal.md ladder applies unchanged).
- No security claims without a measured obedience rate behind them, and
  no use of the word "immune" for anything that reads untrusted text.

## Honest residuals

- Analysis-note fidelity drift under adversarial content is bounded and
  audited, not eliminated.
- The coordinator's safety rests on content-NULL discipline holding;
  that discipline is enforced by the closed schema registry, whose
  failure mode was demonstrated 2026-08-15 to be refusal (fail-closed),
  which is the property to preserve.
- Same-owner trust model unchanged: none of this survives owner-level
  compromise; development mode remains attribution, not authentication.

## Build order, each stage earning the next

1. **Health sweep** (senses): model-free cron, verdicts as content-NULL
   `health` events, operator notified only on new degradation. Earn: its
   alarm path exercised by test; weeks of verdicts become the
   coordinator's first honest input feed.
2. **Workflow artifact format + policy lint**: the spec schema and the
   mechanical refusals, with a corpus of must-refuse fixtures. Earn:
   lint refuses every planted trifecta violation.
3. **Registry + promotion ceremony**: staging, presence-signed
   promotion, provenance chain. Earn: an end-to-end promoted workflow
   whose every hop `ctx why` can walk.
4. **Coordinator dispatch**: structured-state reader scheduling promoted
   workflows. Earn: dispatch decisions reproducible from ledger state
   alone.
5. **Author agents**: drafting into staging. Earn: first family
   calibrated to grant-covered promotion through its field window.
6. **Injection evaluation suite**: planted-injection corpora per role
   surface, preregistered bars, re-run on surface change. Earn: the
   numbers this contract's security section promises.

No stage starts until the previous stage's earn condition is met and
recorded.
