# Delegation grants: recorded, scoped, revocable model authority

Contract frozen 2026-08-14, before implementation.

## The problem this solves

The authority model to date has exactly one path for authoritative state:
a human CLI act per item. That design silently assumes the operator can
hold and act on working context the way a model can — and the operator
cannot, by their own report, past a few hours of parallel sessions. The
failure shape at the exhaustion point is the worst one available: the
operator starts confirming without judging ("just do what you think
best"), and every rubber-stamped act still carries operator provenance.
Exhausted assent laundered as deliberate confirmation is authority
laundering flowing *through* the human instead of around them.

A grant makes that moment a designed act instead of an ambient collapse.
The operator records — once, deliberately, while still holding judgment —
that the model holds provisional authority over a *named class* of acts,
in a *named scope*, for a *bounded window*, revocable in one command, and
loudly visible in every checkpoint until it ends. Human acts move up the
altitude ladder: from per-item confirmation (which requires context the
human doesn't have) to per-class delegation (which requires judgment only
the human has).

This is the same object from two directions: the kernel's answer to
"fewer, realer human acts", and the durable-authorization artifact that
harness-side confirmation rules can honor.

## The mechanism

### Grant events

    ctx grant add <class> [--repo PATH | --global] [--for 8h | --until ISO]
                  [-m reason]
    ctx grant revoke <grant_id> [-m reason]
    ctx grant list [--all]

A grant is one append-only event (source `grant`, kind `grant`, meta
`{op: "grant", class, scope, expires?, authority: "operator", client}`,
content = the operator's stated reason — carried wherever the grant is
displayed, because *why* you delegated is part of the record). A revoke is
another (`{op: "revoke", grant: <id>}`). Current state is the reduction of
grant events in id order; no UPDATE, no DELETE.

Granting and revoking are human CLI acts. A grant event whose meta does
not carry operator authority is ignored by the reduction and surfaced as
an anomaly — the model cannot grant to itself. (Attribution, not
authentication: same-owner trust model as everything else in the ledger.)

### Authority classes (closed registry)

| class | allows the model to | scopes |
|---|---|---|
| `loop.confirm` | confirm its own loop candidates | repo, global |
| `loop.dismiss` | dismiss loop candidates | repo, global |
| `decision.supersede` | record supersession edges | global only |

Unknown classes are refused at grant time. There is deliberately no
wildcard and no `grant.grant` — a grant can never confer the power to
grant. The registry grows only by contract revision.

### Scope and expiry

A repo-scoped grant covers acts whose target has that repo's scope; a
global grant covers everything in its class. `decision.supersede` is
global-only because edges are archive-global objects. Expiry is stored as
an absolute timestamp (computed from `--for` at grant time) and evaluated
at act time; an expired grant refuses exactly like an absent one. No
auto-renew: silence is never consent.

### Enforcement

The model-side write paths (MCP tools `loop_confirm`, `loop_dismiss`,
`decision_supersede`) check for an active covering grant at act time.
Without one they refuse with the grant that would be needed. With one,
the act is recorded with authority **`model-granted`** — never
`operator` — and the acting event's meta carries the grant's event id.
Nothing a grant enables is ever indistinguishable from a human act: the
provenance says the model did it, under which delegation, recorded when
and why. `ctx why` and the audit trail resolve act → grant → operator
reason.

Operator CLI paths are unchanged and never require a grant.

### Loudness

Every checkpoint compiled while grants are active in its scope carries a
standing-delegations line ahead of its sections:

    STANDING DELEGATIONS: model holds loop.confirm (grant ev 812, expires
    2026-08-15T02:00) — revoke: ctx grant revoke 812

and the checkpoint's egress meta lists the active grants. A resuming
model — and the operator reading any package — cannot not know what is
currently delegated. Revocation takes effect at the next act check;
there is no cache.

## What the mechanism refuses to do

- No model-mediated granting, ever (the reduction ignores it).
- No wildcard classes, no meta-grants, no default grants, no auto-renew.
- No retroactive authority: acts before a grant's event id are not
  covered by it, and revocation does not rewrite the provenance of acts
  taken while it was active (they remain valid-under-grant, visibly so).
- No laundering: `model-granted` never upgrades to `operator`. A
  granted confirmation is permanently distinguishable from a human one.
- Loop confirmation via grants is a *different mechanism* from the
  retired utterance-binding path (docs/OPEN_LOOPS.md): that path tried to
  infer per-item assent from operator text and was unsound. A grant is
  explicit class-level assent recorded as its own operator act; nothing
  is inferred.

## Evaluation

This mission ships a mechanism, not a fix claim: no behavioral surface is
asserted to have moved, so no model dispatches are spent. The deterministic
bars, all enforced by `tests/test_grants.py`:

1. Reduction correctness: grant/revoke/expiry/idempotence; non-operator
   grant events are anomalies; unknown classes refused.
2. Refusal without grant: every model-path tool refuses when no active
   covering grant exists (absent, revoked, expired, wrong scope, wrong
   class).
3. Provenance under grant: acts record `model-granted` + grant id;
   the loop/edge reductions carry it; operator paths are unchanged.
4. Loudness: active grant ⇒ standing-delegations line in every compiled
   checkpoint for the covering scope and grants listed in egress meta;
   no active grant ⇒ neither.
5. Revocation is immediate: act succeeds, revoke, identical act refuses.

Whether granted autonomy is *well-calibrated* (should the reconciler's
confirmations be trusted?) is a measurement question for a later
preregistered mission — this contract only makes such delegation
recordable, bounded, loud, and attributable, which is the precondition
for measuring it.
