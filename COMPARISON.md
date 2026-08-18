# How contextd's authorization plane compares to existing alternatives

This document situates one property — authorization consumed atomically with
the act it authorizes — against four systems that solve neighboring problems.
The property is demonstrated, not asserted: `examples/gate_proof/
concurrent_redemption.py` races 8 OS processes on one single-use
authorization and `examples/gate_proof/RESULTS.md` records 21/21 runs of
exactly one success, with every refusal a durable ledger row.
`examples/gate_proof/multihost_redemption.py` moves the same claim across a
machine boundary: 20/20 runs, two hosts with separate archive roots sharing
one database.

Citations into this repo are stated as `file` / function (approximate lines,
at commit `77e761c`). Citations into Microsoft's toolkit are at commit
`7d0cef5` of `microsoft/agent-governance-toolkit`, under
`agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/`
unless another path is given. Line numbers are approximate ranges with the
enclosing function named, so they survive upstream edits.

**The standing rule for this document: no competitive claim without a passing
test id behind it, and a file:line in the alternative for any contrast. A
claim that cannot be traced that way is deleted, not softened.** Section 6 is
the asset — it lists this project's gaps first-person and recommends
competitors for what they win.

## 1. Alternatives, described fairly

### Microsoft `agent-governance-toolkit`

An open-source control plane for agent governance: policy interception before
tool execution, audit logging, compliance checking, agent-to-agent messaging.
Its `AgentKernel.intercept_tool_execution` (`agent_kernel.py`, lines 155–224)
is a genuine choke point — "No tool executes without passing this gate" — with
argument-level policy checks, a shadow mode for dry-running agents, and a
"mute" protocol that returns actionable errors to blocked agents. Its audit
component is named exactly what it is: `FlightRecorder`, "Black Box Audit
Logger" (`flight_recorder.py`, module docstring), with WAL-mode SQLite, a
hash-chained `entry_hash` column, batched asynchronous writes for throughput,
and query/verification APIs. A `ComplianceEngine` (`compliance.py`, ~line 108)
does multi-framework compliance checking, reporting, and EU AI Act risk
assessment.

**They beat this project permanently on breadth**, and the gap is not close:
**five language SDKs** — Python, TypeScript, .NET, Rust, Go (`README.md:274`,
"All five language SDKs implement core governance") — plus a VS Code extension
(`agent-governance-typescript/agent-os-vscode/`), MCP servers, shadow mode
(`shadow_mode.py`), a time-travel debugger (`time_travel_debugger.py`),
constraint graphs (`constraint_graphs.py`), process isolation
(`process_isolation.py`), Microsoft's name, and actual distribution. contextd
is one person's single-language local daemon.

Three properties of the flight recorder matter for the comparison below, and
none of them is a defect for its stated purpose:

1. **Recording is decoupled from deciding.** In `intercept_tool_execution`
   (`agent_kernel.py`, 155–224) the sequence is three independent steps with
   no transaction boundary: `audit_logger.start_trace()` at line 180 writes a
   `'pending'` row, `policy_engine.check_violation()` runs as a separate call
   at line 186, then `audit_logger.log_violation()` updates that row at line
   190. (the enclosing method is `intercept_tool_execution`, in both its
   sync and async variants)
2. **Records are buffered, not durable at act time.** `_queue_write`
   (`flight_recorder.py`, line 241) appends under a lock to an in-memory
   `deque` (`_write_buffer`, line 117); the flush happens when `batch_size`
   (default 100, line 84) fills or `flush_interval_seconds` (default 5.0,
   line 85) elapses (elapsed check at line 236). The connection also sets
   `PRAGMA synchronous=NORMAL` (lines 139 and 264), so committed writes are
   not individually fsync'd.
3. **The model is INSERT-pending-then-UPDATE.** `start_trace` computes
   `entry_hash` over a string ending in `:pending` (line 372, hashed at 373)
   and inserts the row with verdict `'pending'` (INSERT at 393, `VALUES`
   at 395); `log_violation` (417–426) later UPDATEs the same row to
   `'blocked'` (line 420), and `entry_hash` is never recomputed. There are no
   database triggers enforcing immutability — `CREATE TRIGGER` appears **zero**
   times in the repository.

Point 3 is not an outside reading of their design; **their own EU AI Act
checklist states it**: "FlightRecorder hash covers INSERT, not final state …
Tampering of the verdict field is not detectable by integrity verification"
(`docs/compliance/eu-ai-act-checklist.md:194`).

This is a flight recorder, and it behaves like one. Enforcement deliberately
lives in a separate `policy_engine`. They never claimed atomicity. The
distinction drawn in this document is one of design goal, not correctness.

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
Access, a Token Vault so agents hold short-lived scoped tokens instead of
long-lived secrets, and CIBA + Rich Authorization Requests for push-to-phone
human approval of a described transaction. Centralized, immediate revocation
across a large SaaS estate is the strongest version of that capability on the
market, and the standards-first approach is a serious attempt at an industry
protocol rather than a proprietary silo.

**Stated precisely:** Okta's standards work here is the **Cross App Access / Identity
Assertion JWT Authorization Grant** draft, whose lead author is Aaron Parecki
of Okta. That draft *profiles* two pre-existing OAuth foundations — **RFC 8693**
(Token Exchange, January 2020) and **RFC 8707** (Resource Indicators, February
2020). **Neither Okta nor Anthropic appears on either RFC, and this document
does not describe them as "co-developed."** The verified Okta–Anthropic
collaboration is on MCP Enterprise-Managed Authorization (June 2026).

Structurally, the IdP mints a time-windowed bearer token and the act executes
later at a third-party resource server Okta never observes: the authorization
record and the act are separate events in separate systems, and single-use
enforcement is left to the downstream API. What a validity window cannot do —
and this is the whole distinction — is **distinguish a crashed agent's honest
retry from a second act redeemed against a spent mandate**. Both are inside
the window.

## 2. Capability matrix

Ratings are for the shipped product as described in each vendor's own
documentation (TraceAgent: as advertised pre-launch). "Partial" is a real
rating, not a softened no — the justification is one line each.

| Capability | Microsoft toolkit | TraceAgent | Temporal | Okta for AI Agents | contextd |
|---|---|---|---|---|---|
| Signed append-only ledger | Partial — hash-chained `entry_hash` in SQLite, but rows are UPDATEd in place (pending → verdict), the hash is not recomputed, unsigned, no triggers enforcing immutability (zero `CREATE TRIGGER` in the repo) | Partial — hash-chained append-only receipts are the core claim; signing scheme and key custody not yet public | Partial — Event History is append-only and durable but unsigned, an operational replay log, retention-bounded after close | No — System Log / tenant logs are conventional event logs with SIEM streaming | Yes — hash-chained events with an fsync'd external witness, service signature coverage (`ledger_sig.py`), operator signatures on authorized acts, `verify_chain` (db.py, ~794–810). DB-level `UPDATE`/`DELETE` triggers on SQLite; on PostgreSQL, triggers **plus** privilege revocation (`postgres.py`, `harden_roles` ~581) |
| Compliance export | Yes — `ComplianceEngine`: multi-framework checking, reporting, EU AI Act risk assessment (compliance.py) | Yes (claimed) — one-click exports mapped to EU AI Act, Colorado AI Act, ISO 42001, NIST AI RMF; unshipped as of Aug 2026 | Yes — hourly export of closed histories to S3/GCS plus control-plane audit-log streaming, on a SOC 2/HIPAA/GDPR-audited cloud | Yes — System Log export and native streaming to SIEMs, on a heavily audited platform (SOC 2, ISO 27001, FedRAMP) | Partial — sealed, deterministic export bundles (`export.py`, `create_sealed_export` ~126) plus a deterministic EU AI Act logging-evidence artifact (`compliance.py`, `ctx compliance`; `tests/test_compliance_export.py`, 22 tests). One regulation, no risk assessment, no multi-framework mapping, and deliberately **no verdict** |
| Durable replay after crash | No — an audit log, not an execution layer; a crash can also lose up to `batch_size` buffered records | No — receipts reconstruct incidents; an act that crashes before its logging call leaves no receipt | **Yes — this is the product.** Deterministic replay against persisted Event History resumes exact program state | No — an identity plane; vaulted refresh tokens let a restarted agent re-mint, but there is no execution state | No — witness-first crash recovery completes or refuses the one in-flight append exactly once (db.py, `append_event_checked` ~925 / `recover_chain_state`); it does not replay application workflows |
| Scoped delegation tokens | No — per-agent policy configuration and A2A task-delegation messages, not issued consumable authority | No — authority chains are recorded metadata, not issued or validated tokens | Partial — namespace-scoped claims and API keys are reusable stateless bearer credentials, not attenuable per-act delegations | **Yes — this is the product.** RFC 8693 short-lived scope-narrowed tokens, cross-app access, centralized revocation across a SaaS estate | Yes, locally — class- and scope-bound, expiring, revocable grants (`grants.py`) plus single-use dispatch capabilities (`capability.py`); nothing cross-app, no SaaS estate |
| Authorization consumed atomically with the act | No — check and record are three independent steps with no transaction (`agent_kernel.py`, `intercept_tool_execution`, lines 180/186/190) | No — logging wraps the act out-of-band; enforcement is explicitly deferred to tools plugged in on top | No — allow/deny is evaluated per API call, never consumed, not recorded in the history | Partial — CIBA+RAR binds a human approval to one described transaction, which is unusually good, but yields a time-windowed bearer token spent later at an API the IdP never observes | Yes — the nonce is consumed by a conditional UPDATE inside the same `BEGIN IMMEDIATE` transaction as the event INSERT (attest.py, `authorized_append` ~1103, `reverify_for_use` ~926, `consume_nonce` ~950; db.py, `append_event_checked` ~925). Test: `tests/test_commerce_redemption.py::test_sixteen_racing_redeemers_perform_the_act_exactly_once` |
| Same guarantee across hosts | No | No | Yes — but the guarantee is workflow durability, not authorization consumption | Yes — centralized by construction; that is what an IdP is | Yes, with PostgreSQL — separate archive roots, no shared filesystem, no advisory lock, no consensus service. Test: `tests/test_postgres_backend.py::test_multihost_single_use_authorization_is_redeemed_exactly_once`; demo 20/20 |
| Three-state redemption (executed / replayed / refused) with the refusal recorded by the core | No — a blocked call is an UPDATE to a pending row by the same process | No — an act that never reached the SDK leaves nothing | Partial — the history distinguishes a completed activity from an unfinished one, but the approval is never spent | No — token state is at the IdP; the resource server's refusal is not in it | Yes — `mandate.bind` / `tx.execute` / `tx.refuse` / `tx.inflight`, with the refusal written **by the core inside the detecting transaction**, not by the refused caller. Tests: `::test_the_core_records_a_refusal_the_caller_never_appended`, `::test_replay_returns_the_stored_outcome_and_never_re_executes`, `::test_a_refusal_row_never_carries_the_attestation_block`, `::test_exactly_one_of_the_act_and_the_refusal_is_durable` |
| Algorithm-tagged signatures and post-quantum checkpoints | No — records are unsigned, so there is no scheme to name | Not specified publicly | No — the history is unsigned | N/A — JWT `alg` is per-token, not a property of a retained record store | Yes — every signature record carries `alg`; verification dispatches on it and refuses a mismatch; ML-DSA (FIPS 204) hybrid checkpoints native via `cryptography` ≥ 47, no third-party PQC library. Tests: `tests/test_crypto_agility.py` (21), incl. `::test_verification_dispatches_on_the_recorded_algorithm`, `::test_hybrid_checkpoint_carries_both_schemes`, `::test_an_unavailable_algorithm_is_a_refusal_not_a_silent_downgrade` |
| Instruction-position (skill/tool-definition) digest pinning | **Yes — and this mechanism is theirs, not ours.** MCP tool definitions are fingerprinted at registration (`agent-governance-rust/agentmesh-mcp/src/mcp/security.rs` ~124–130: `description_hash`/`schema_hash`) and `check_rug_pull` (153–182) reports a changed description or schema; `agent_control_plane/tool_registry.py` `verify_tool_integrity` (361–402) compares the SHA-256 of a handler's source against its registration-time hash, and `execute_tool` **blocks before execution** on it (call at 266, guard at 267, early return 279–284, handler not reached until 295). Plugin manifests are Ed25519-signed with the artifact SHA-256 bound into the signed bytes (`agent_marketplace/signing.py`, `manifest.py`), and the installer fails closed on a missing or untrusted signature (`installer.py` ~139–153) | No — the context layer records prompts; nothing pins tool/skill definitions | No — worker build-ID pinning versions code for replay, not authorization | No — RAR `authorization_details` could carry such a field in principle; the product neither computes nor verifies one | Yes, with a different durability property — a pin is a chained, witnessed ledger event folded in id order with no in-process cache, so it outlives the process that took it. Test: `tests/test_instruction_pinning.py::test_pin_survives_process_restart` (three real OS processes, with a negative control so it cannot pass vacuously) |

Alternatives win real rows here: Temporal owns durable replay, Okta owns
cross-app delegation, Microsoft's toolkit and TraceAgent both have a
compliance-reporting story far broader than contextd's single-regulation
artifact — and Microsoft's toolkit is the **prior art for instruction-position
pinning**, which contextd adopted rather than invented.

### On the pinning row, precisely

This row
is worth being exact about what is and is not claimed.

**Conceded as prior art:** Microsoft pins tool definitions and blocks before
execution. That is verified in their source at the lines above, not inferred.
The mechanism — digest an instruction-position artifact at registration,
compare it later, refuse on mismatch — is theirs, and `contextd/schemas.py`
says so in the code itself.

**The contrast, and it is narrow:** their pin lives in a per-process
`Mutex<HashMap>` (Rust) or an in-process registry (Python). That is entirely
reasonable for a per-session MCP scanner and is not a defect in that scope.
contextd's pin is a ledger event, so a divergence is evidence rather than a
log line, and it survives the process. The claim is **durability and
evidentiary weight, not correctness, and not novelty.**

**Two further honesties**, both of which cut against contextd's framing:
what Microsoft's Python path pins is the **handler's source code**, not the
tool description or JSON schema (their Rust path pins description and schema);
and their `check_rug_pull` is **scan-time**, with their own OWASP mapping
recording runtime rug-pull detection as "No"
(`docs/compliance/owasp-llm-top10-mapping.md:339`). contextd's check runs at
act time. That is a genuine difference, and it is smaller than "they only
warn" — they block.

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

contextd makes that distinction mechanical: the single-use nonce is spent by
a conditional UPDATE inside the same transaction that appends the event, so
the retry refuses, **the refusal lands as a durable chained row written by the
core itself**, and the ledger can prove which of the two acts the operator
actually mandated. The intent digest (`attest.py`, `intent_digest`) is what
makes the two cases separable at all: it covers what is being done and
excludes which authorization is doing it, so two honest retries of the same
act share a value while a different act does not.

That is what makes a record adjudication-grade rather than observability
exhaust.

## 4. Use theirs instead if…

- **Your problem is internal workflow durability — use Temporal.** If you
  need long-running processes that survive crashes, retry flaky APIs, and
  resume exactly where they stopped, that is Temporal's core competency,
  proven at scale in a way a single-operator ledger will never be. Build
  authorization semantics on top of it if you need them.
- **Your problem is enterprise identity across many tools — use Okta.** If
  agents must act across a SaaS estate under corporate governance, with
  vaulted credentials, standards-based delegation the ecosystem is actually
  adopting, push-to-phone approval, and one-switch revocation, nothing local
  competes with an IdP that the resource servers already trust. contextd does
  not compete here and should not be evaluated as if it did; the honest
  relationship is **adjacency** — verify their token, bind it into the chain,
  consume it once.
- **You want an audit log, breadth, or more than one language — use
  Microsoft's toolkit.** It is free, it carries their name, its interception
  point is real, its compliance engine maps to the frameworks auditors ask
  about, and a flight recorder is exactly the right tool when what you need is
  a black box, not a gate. If your team is not writing Python, this is not a
  close call: they have five SDKs and contextd has one language and no
  distribution. TraceAgent, once launched, targets the same evidence layer
  with a stronger receipt-integrity story and regulator-mapped exports.

## 5. Use this if…

- You are **in the transaction path**: the authorization must be spent by
  the act it authorizes, exactly once, with the double-spend structurally
  unrepresentable rather than policed after the fact.
- You need **the refusal on the record**: a denied or replayed redemption
  must itself be a durable, chained, queryable ledger row — evidence, not a
  log line that may never have flushed. The core now writes that row itself,
  inside the transaction that detected the problem, rather than depending on
  the refused caller to cooperate.
- You need **the record to outlive the code**: the byte format, chain hash,
  canonical encoding, signing domains, and closed vocabulary are specified
  independently in `docs/FORMAT.md` (`contextd-record-format v1`), so an
  adjudicator can parse an archive with SHA-256 and a signature verifier and
  nothing else.
- You want **one local binary rather than three hosted platforms**: a
  single-operator ledger with hardware-backed operator signatures, delegation
  grants, and integrity verification, with no network dependency in the trust
  path. That last clause is true of the **default SQLite backend only**. A
  PostgreSQL archive puts a database — and, if it is not on loopback, a
  network — inside the trust path, and moves the tip into the same system
  being attested. Choose the backend accordingly.

## 6. Known gaps

Stated in the first person, because a comparison that lists no gaps should
not be believed. This section only ever grows: new capability creates new
gaps, and a gaps list that shrinks while the feature list grows is a tell.

### Structural, and not going away

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
- **I am one person's project in one language**, with no distribution, no
  SDKs, no editor integration, and no organization behind it. Every
  alternative in this document beats me on all five.

### Narrowed, but still real

These four replace earlier, broader concessions. The earlier wording is kept
alongside so the record shows what changed and why.

- **I am no longer single-host — but multi-host costs you the external
  witness.** *(Was: "I am single-host. The chain lock is `fcntl.flock` on a
  local lock file over local SQLite. There is no clustered mode.")* A
  PostgreSQL archive serializes appenders on a `FOR UPDATE` row lock inside
  the append transaction and is proven across two hosts 20/20. What you give
  up is stated in `docs/SECURITY.md` §10: **a Postgres superuser, the table
  owner, or root on the database host can disable the triggers, rewrite
  `events`, and set the tip to match in one internally consistent
  transaction**, and there is no external witness there to contradict them.
  Against that actor SQLite was strictly better. The fix — a signed checkpoint
  exported off the database host — **is not built**.
- **Postgres archives cannot be backed up or handed off.** `ctx backup` uses
  SQLite's online backup API (`backup.py:834–839`), which has no PostgreSQL
  counterpart; `handoff.py` opens the archive as SQLite directly. Ingest and
  live schema migration are likewise SQLite-only, and the weekly restore drill
  does not cover a Postgres archive at all. Multi-host is therefore a real
  capability with a real hole in its operational story.
- **Refusals are recorded by the core — for redemption, and not everywhere.** The
  three-state redemption path now writes its own refusal inside the detecting
  transaction. But **a mandate can still get stuck in flight**: if the act's
  callback raises an unknown exception or returns an oversized outcome, the
  mandate is consumed with no recorded outcome and **there is no
  operator-facing way to resolve it**. Refusing to guess an outcome is
  deliberate; having no resolve path is a dead end. Two further limits on that
  evidence: the concurrency proof for `redeem` is threads, not processes, and
  the crash coverage uses an injected fault hook rather than a killed process.
  The in-flight state was never reached in 160 observed worker outcomes under
  natural contention — it is exercised only by a test built to force it.
- **I pin the instruction surface, and the pin binds the caller's claim, not
  the file.** contextd never opens the artifact; it pins the bytes the caller
  said it read. Four attacks survive by construction — TOCTOU, incomplete
  labels, poisoned-at-first-sight, position renaming — each named and pinned
  by test in `contextd/pinning.py`, the authoritative enumeration. None is
  unique to contextd; all four hold for every registration-time digest
  scheme, prior art included. A claim that pins bind the model's actual
  context window is **not** earned and is not made.
- **The commerce vocabulary exists, and it is a vocabulary, not a domain
  model.** `mandate.bind`, `tx.execute`,
  `tx.refuse`, and `tx.inflight` are registered and tested. Orders, payments,
  refunds, and settlement still do not exist. Four words for *authorization
  lifecycle* is not a commerce system, and a `note` event is still not an
  order record.

### New gaps this work created

- **The no-network gate cannot see the thing that added network capability.**
  `scripts/gates.sh` greps `contextd/` for network vocabulary and diffs against
  a pinned manifest. The grep is **lexical**, and `psycopg` is not in its
  vocabulary — so the PostgreSQL backend, the one change that genuinely gives
  contextd network capability, was invisible to it. The gate's only match in
  that file was the word "socket" in a comment. Recorded here rather than
  papered over.
- **A default test run does not exercise the multi-host backend.** All 18
  PostgreSQL tests skip unless a server is configured, so the baseline suite
  is green whether or not that backend works. Any multi-host claim in this
  document rests on tests that must be deliberately switched on.
- **Post-quantum checkpointing is verified on one interpreter.** ML-DSA
  requires `cryptography` ≥ 47 and was verified on Python 3.14.3; CI runs 3.11
  and 3.13, where a misconfiguration would surface as a **skip rather than a
  failure**. The property is real; the CI evidence for it is weaker than the
  local evidence.
- **`ctx compliance` reports measurements, not compliance.** It covers one
  regulation's logging and retention articles, returns no verdict, and cannot
  observe whether the system is high-risk or whether the operator is a
  provider or a deployer. Microsoft's `ComplianceEngine` and TraceAgent's
  regulator-mapped exports are broader products, and this is not one.

  In fairness on the same axis: Microsoft's own EU AI Act checklist records
  that their toolkit has **"No retention enforcement"**
  (`docs/compliance/eu-ai-act-checklist.md:191`) and that, even where
  `retention_days` is configurable, "no code actually preserves or deletes logs
  based on this value" (line 334), which they mark a must-fix (line 333). That
  is a candid self-assessment in a document they published, and it is cited
  here the way this document cites everything else — as prior art read
  accurately, not as a dunk.

### Standing limits on all of the above

- **Tamper-evident, not tamper-proof.** An owner-level process that rewrites a
  row and recomputes every downstream hash — including the witness — defeats
  layers 1 and 2. The service signature is the layer that does not fall to
  that, and only once the key is owned by a service account it does not
  control. **This tree is `development`, not `hardened`**, so on a fresh clone
  that key sits beside the archive under the same uid.
- **Nothing here adjudicates truth.** A signature binds bytes; a chain binds
  order. Whether a record's content is *true* is outside every claim in this
  document, and `provenance.py` deliberately refuses to assert it.
