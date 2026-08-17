# How contextd's authorization plane compares to existing alternatives

This document situates one property — authorization consumed atomically with
the act it authorizes — against four systems that solve neighboring problems.
The property is demonstrated, not asserted: `examples/gate_proof/
concurrent_redemption.py` races 8 OS processes on one single-use
authorization and `examples/gate_proof/RESULTS.md` records 21/21 runs of
exactly one success, with every refusal a durable ledger row.

Citations into this repo are stated as `file` / function (approximate lines,
at commit `a34ac8a`). Citations into Microsoft's toolkit are at commit
`7d0cef5` of `microsoft/agent-governance-toolkit`, under
`agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/`.
Line numbers are approximate ranges with the enclosing function named, so
they survive upstream edits.

## 1. Alternatives, described fairly

### Microsoft `agent-governance-toolkit`

An open-source control plane for agent governance: policy interception before
tool execution, audit logging, compliance checking, agent-to-agent messaging.
Its `AgentKernel.intercept_tool_execution` (agent_kernel.py, ~lines 160–220)
is a genuine choke point — "No tool executes without passing this gate" — with
argument-level policy checks, a shadow mode for dry-running agents, and a
"mute" protocol that returns actionable errors to blocked agents. Its audit
component is named exactly what it is: `FlightRecorder`, "Black Box Audit
Logger" (flight_recorder.py, module docstring), with WAL-mode SQLite, a
hash-chained `entry_hash` column, batched asynchronous writes for throughput,
and query/verification APIs. A `ComplianceEngine` (compliance.py, ~line 108)
does multi-framework compliance checking, reporting, and EU AI Act risk
assessment. It is free, broad, multi-language, and carries Microsoft's name.

Three properties of the flight recorder matter for the comparison below, and
none of them is a defect for its stated purpose:

1. **Recording is decoupled from deciding.** In `intercept_tool_execution`
   (agent_kernel.py, ~lines 177–205) the sequence is three independent steps
   with no transaction boundary: `audit_logger.start_trace()` writes a
   `'pending'` row, `policy_engine.check_violation()` runs as a separate
   call, then `audit_logger.log_violation()` updates that row. (A note on
   naming: an earlier read of this code referred to this as the
   "`check_and_log` path"; no function of that name exists — the enclosing
   method is `intercept_tool_execution`, in both its sync and async variants.)
2. **Records are buffered, not durable at act time.** `_queue_write`
   (flight_recorder.py, ~lines 241–245) appends to an in-memory
   `deque` (`_write_buffer`, ~line 117); the flush happens when `batch_size`
   (default 100, ~line 84) fills or `flush_interval_seconds` (default 5.0,
   ~line 85) elapses (`_maybe_flush`, ~lines 228–240). The connection also
   sets `PRAGMA synchronous=NORMAL` (~lines 139 and 264), so committed writes
   are not individually fsync'd.
3. **The model is INSERT-pending-then-UPDATE.** `start_trace`
   (flight_recorder.py, ~lines 332–400) computes `entry_hash` over the
   `:pending` state and inserts the row with verdict `'pending'`;
   `log_violation` (~lines 402–428) later UPDATEs the same row to
   `'blocked'`. There are no database triggers enforcing immutability.

This is a flight recorder, and it behaves like one. Enforcement deliberately
lives in a separate `policy_engine`. The distinction drawn in this document
is one of design goal, not correctness.

### TraceAgent

"Audit Logging for AI Agents — the immutable audit trail for AI agent
actions. Not what they thought — what they did." Its framing is exactly
right about the gap it targets: LLM observability tools trace prompts and
completions, while TraceAgent receipts the actions — API calls, file writes,
emails — as hash-chained, append-only, tamper-evident records with authority
chains back to the approving human, and one-click compliance exports mapped
to the EU AI Act, Colorado AI Act, ISO 42001, and NIST AI RMF. Its five-layer
audit model (identity, input, context, action, outcome) is a better integrity
story than the mutable rows of typical observability stacks. It is explicit
about being "the evidence layer": policy enforcement is something you plug in
on top. Logging is an out-of-band SDK call (or pass-through MCP middleware)
around the act. As of August 2026 it is pre-launch (waitlist), and its
signing scheme and key custody are not yet publicly specified.

### Temporal

A durable execution platform, MIT-licensed and self-hostable with a managed
cloud. Workflow state is persisted at every step; deterministic replay
against the stored Event History reconstructs exact program state after any
worker or process crash — no lost progress, with configurable retries,
timeouts, and heartbeats as platform primitives rather than application code.
This is the product's core competency, mature and battle-tested at scale,
with SDKs in seven languages, a serious compliance posture for Temporal Cloud
(SOC 2 Type II, HIPAA BAA, GDPR DPA, client-side payload encryption), and
hourly export of closed workflow histories explicitly marketed for compliance
and audit. Authorization is a gate in front of the API — a ClaimMapper plus
Authorizer evaluated per call, or Cloud RBAC — producing allow/deny from
reusable bearer credentials; the decision is not consumed and is not written
into the Event History. The history itself is an operational replay log:
append-only and durable while the workflow lives, unsigned, and
retention-bounded after close unless exported.

### Okta for AI Agents (with Auth0 for AI Agents)

Enterprise identity for agents as first-class non-human identities: discovery
and registration in a directory, least-privilege authorization via Cross App
Access (the IETF OAuth WG's Identity Assertion Authorization Grant), a Token
Vault built on RFC 8693 token exchange so agents hold short-lived scoped
tokens instead of long-lived secrets, and CIBA + Rich Authorization Requests
for push-to-phone human approval of a described transaction. Centralized,
immediate revocation across a large SaaS estate is the strongest version of
that capability on the market, and the standards-first approach (with named
ISV adoption) is a serious attempt at an industry protocol rather than a
proprietary silo. Structurally, the IdP mints a time-windowed bearer token
and the act executes later at a third-party resource server Okta never
observes: the authorization record and the act are separate events in
separate systems, and single-use enforcement is left to the downstream API.

## 2. Capability matrix

Ratings are for the shipped product as described in each vendor's own
documentation (TraceAgent: as advertised pre-launch). "Partial" is a real
rating, not a softened no — the justification is one line each.

| Capability | Microsoft toolkit | TraceAgent | Temporal | Okta for AI Agents | contextd |
|---|---|---|---|---|---|
| Signed append-only ledger | Partial — hash-chained `entry_hash` in SQLite, but rows are UPDATEd in place (pending → verdict), unsigned, no triggers enforcing immutability | Partial — hash-chained append-only receipts are the core claim; signing scheme and key custody not yet public | Partial — Event History is append-only and durable but unsigned, an operational replay log, retention-bounded after close | No — System Log / tenant logs are conventional event logs with SIEM streaming | Yes — hash-chained events with an fsync'd external witness, service signature coverage (`ledger_sig.py`), operator signatures on authorized acts, `verify_chain` (db.py, ~lines 628–645) |
| Compliance export | Yes — `ComplianceEngine`: multi-framework checking, reporting, EU AI Act risk assessment (compliance.py) | Yes (claimed) — one-click exports mapped to EU AI Act, Colorado AI Act, ISO 42001, NIST AI RMF; unshipped as of Aug 2026 | Yes — hourly export of closed histories to S3/GCS plus control-plane audit-log streaming, on a SOC 2/HIPAA/GDPR-audited cloud | Yes — System Log export and native streaming to SIEMs, on a heavily audited platform (SOC 2, ISO 27001, FedRAMP) | Partial — sealed, deterministic export bundles (`export.py`, `create_sealed_export`, ~lines 126–175); nothing regulator-mapped |
| Durable replay after crash | No — an audit log, not an execution layer; a crash can also lose up to `batch_size` buffered records | No — receipts reconstruct incidents; an act that crashes before its logging call leaves no receipt | **Yes — this is the product.** Deterministic replay against persisted Event History resumes exact program state | No — an identity plane; vaulted refresh tokens let a restarted agent re-mint, but there is no execution state | No — witness-first crash recovery completes or refuses the one in-flight append exactly once (db.py, `append_event_checked` / `recover_chain_state`); it does not replay application workflows |
| Scoped delegation tokens | No — per-agent policy configuration and A2A task-delegation messages, not issued consumable authority | No — authority chains are recorded metadata, not issued or validated tokens | Partial — namespace-scoped claims and API keys are reusable stateless bearer credentials, not attenuable per-act delegations | **Yes — this is the product.** RFC 8693 short-lived scope-narrowed tokens, cross-app access, centralized revocation across a SaaS estate | Yes, single-host — class- and scope-bound, expiring, revocable grants (`grants.py`) plus single-use dispatch capabilities (`capability.py`); nothing cross-app |
| Authorization consumed atomically with the act | No — check and record are three independent steps with no transaction (agent_kernel.py, `intercept_tool_execution`, ~lines 177–205) | No — logging wraps the act out-of-band; enforcement is explicitly deferred to tools plugged in on top | No — allow/deny is evaluated per API call, never consumed, not recorded in the history | Partial — CIBA+RAR binds a human approval to one described transaction, which is unusually good, but yields a time-windowed bearer token spent later at an API the IdP never observes | Yes — the nonce is consumed by a conditional UPDATE inside the same `BEGIN IMMEDIATE` transaction as the event INSERT (attest.py, `authorized_append` ~919–957 and `consume_nonce` ~828–856; db.py, `append_event_checked` ~680–864); demonstrated under process concurrency in `examples/gate_proof/` |
| Instruction-position (skill/tool-definition) digest pinning | **Yes — and they are ahead of us here.** MCP tool definitions are fingerprinted at registration (`agentmesh-mcp/src/mcp/security.rs` ~124–130: `description_hash`/`schema_hash`) and `check_rug_pull` (~153–181) reports a changed description or schema; `agent_control_plane/tool_registry.py` `verify_tool_integrity` (~361–375) compares the SHA-256 of a handler's source against its registration-time hash and is called *before execution* (~265). Plugin manifests are Ed25519-signed with the artifact SHA-256 bound into the signed bytes (`agent_marketplace/signing.py`, `manifest.py`), and the installer fails closed on a missing or untrusted signature (`installer.py` ~139–153) | No — the context layer records prompts; nothing pins tool/skill definitions | No — worker build-ID pinning versions code for replay, not authorization | No — RAR `authorization_details` could carry such a field in principle; the product neither computes nor verifies one | No — not implemented. The nearest existing analogue is the dispatch capability binding the exact disclosure digest it may derive from (`capability.py`, `egress_digest`); pinning the skill/tool-definition surface is known follow-on work |

Alternatives win real rows here: Temporal owns durable replay, Okta owns
cross-app delegation, and Microsoft's toolkit and TraceAgent both have a
compliance-reporting story contextd does not — and Microsoft's toolkit wins
the instruction-pinning row outright, which contextd does not implement at
all. The compliance row's bar is a compliance-facing export or reporting
surface — regulator-mapped reports, or audit-log export/streaming a
compliance team can consume — which is why contextd's generic sealed export
bundle rates only partial against four systems that ship exactly that.

## 3. The distinction

These systems record what happened, authorize a class of actions for a
window, or replay a workflow after a crash. None of them makes the
authorization and the act a single transaction: Microsoft's kernel checks in
one step and logs in another, TraceAgent receipts an act that already
happened, Temporal's authorizer evaluates the call before the history
records it — its decision is neither consumed nor written into that history —
and Okta's token authorizes a window that some later API call spends from.
The consequence is concrete: after a crash, none of them can tell from the
authorization record whether a new act is the mandated act honestly retried
or a second act redeemed against a spent mandate. Temporal comes closest —
its event history does distinguish a completed activity from an unfinished
one within a single workflow execution — but the approval itself is never
spent, so the same standing credential authorizes a fresh submission of the
same act with nothing to refuse it. The record says "this was authorized,"
not "this authorization was consumed by exactly this act and no other."
contextd makes that distinction mechanical: the
single-use nonce is spent by a conditional UPDATE inside the same
transaction that appends the event, so the retry refuses, the refusal lands
as a durable chained row in the same ledger (appended by the refused caller
— see Known Gaps), and the ledger can prove which of the two acts the
operator actually mandated. That is what makes a record adjudication-grade
rather than observability exhaust.

## 4. Use theirs instead if…

- **Your problem is internal workflow durability — use Temporal.** If you
  need long-running processes that survive crashes, retry flaky APIs, and
  resume exactly where they stopped, that is Temporal's core competency,
  proven at scale in a way a single-host SQLite ledger will never be. Build
  authorization semantics on top of it if you need them.
- **Your problem is enterprise identity across many tools — use Okta.** If
  agents must act across a SaaS estate under corporate governance, with
  vaulted credentials, standards-based delegation the ecosystem is actually
  adopting, push-to-phone approval, and one-switch revocation, nothing local
  competes with an IdP that the resource servers already trust.
- **You want an audit log and nothing more — use Microsoft's toolkit.** It
  is free, it carries their name, its interception point is real, its
  compliance engine maps to the frameworks auditors ask about, and a flight
  recorder is exactly the right tool when what you need is a black box, not
  a gate. TraceAgent, once launched, targets the same evidence layer with a
  stronger receipt-integrity story and regulator-mapped exports.

## 5. Use this if…

- You are **in the transaction path**: the authorization must be spent by
  the act it authorizes, exactly once, with the double-spend structurally
  unrepresentable rather than policed after the fact.
- You need **the refusal on the record**: a denied or replayed redemption
  must itself be a durable, chained, queryable ledger row — evidence, not a
  log line that may never have flushed.
- You want **one local binary rather than three hosted platforms**: a
  single-operator, single-host ledger with hardware-backed operator
  signatures, delegation grants, and integrity verification, with no network
  dependency in the trust path.

## 6. Known gaps

Stated in the first person, because a comparison that lists no gaps should
not be believed.

- **I am single-host.** The chain lock is `fcntl.flock` on a local lock file
  (db.py, `_chain_lock`, ~lines 359–366) over local SQLite. Two application
  servers pointed at shared storage do not serialize through it. There is no
  clustered mode; scaling past one host means putting the authority plane
  behind one process, and that process is the ceiling.
- **I have a single-operator authority plane.** One human, one key registry,
  one authority. There are no roles, no quorums, no separation between the
  person who grants and the person who audits. Okta-scale organizations
  should read that sentence as disqualifying, because for them it is.
- **I cannot make your counterparty idempotent.** The ledger prevents
  double-*recording*; if the authorized act has an external effect — an
  email, a payment, an API call — a crash between the commit and the effect
  (or the effect and its confirmation) is the classic dual-write problem,
  and it is not solved here. Exactly-once *effects* require an idempotent
  receiver or a reconciliation loop, and the ledger supplies neither.
- **Refusal rows are the caller's act.** `authorized_append` refuses by
  raising; the refusal becomes a durable ledger row because the calling
  harness appends one (as the gate-proof demo does), not because the core
  writes it automatically. A caller that dies before recording its refusal
  leaves the nonce state as the only trace.
- **I have no commerce event schemas.** The closed schema registry
  (schemas.py, `EVENT_SCHEMAS`, six event types) covers notes, loops,
  grants, decisions, evaluations, and disclosures. Orders, payments,
  refunds, settlement — none of that exists, and a `note` event is not an
  order record.
- **I do not pin the instruction surface.** An authorization binds the act's
  class, scope, arguments, content, and reason digests (attest.py,
  `prepare_action`), but not a digest of the skill and tool definitions the
  agent was operating under when the operator approved. Microsoft's toolkit
  already does this and contextd does not: it fingerprints MCP tool
  descriptions and schemas at registration and detects a changed definition
  (`agentmesh-mcp/src/mcp/security.rs`, `check_rug_pull`), and re-hashes a
  tool handler's source before execution
  (`agent_control_plane/tool_registry.py`, `verify_tool_integrity`). An
  earlier revision of this document claimed that row was "no" for everyone;
  that was wrong, produced by a search too narrow to reach either file, and
  is corrected here. For contextd it remains known follow-on work.
