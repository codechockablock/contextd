# Gate v1.0 program — pre-flight verification

**Date:** 2026-08-17 · **Repo:** `~/contextd` @ `a34ac8a` (master) · **Baseline:** 646 passed
**Scope:** verify the mission program's own stated facts before any lane is dispatched, per its
stop condition *"A stated fact about an alternative does not check out, including any stated in
this document. Every one was verified once by one reader; that is a single point of failure."*

**Verdict: HALT. Do not dispatch as written.** Four stated facts are refuted, three are
imprecise, two verification gates cannot execute, and one licensing conflict needs an operator
decision. None of this invalidates the program's core thesis — the atomicity claim and the
gate-proof evidence are untouched — but six of six lanes need an edit before they are handed out.

Reference checkouts used: `microsoft/agent-governance-toolkit` @ `7d0cef5` (read-only clone),
`~/unified-stack` @ `1f197b6`, `~/frontier-ops`.

---

## A. Refuted — these are stop conditions

### A1. Lane 2's premise is false. The position is occupied.

The program states: *"Verified precedent: nothing in the Microsoft toolkit's plugin registry does
digest verification or signing. This position is unoccupied."*

It is occupied, including on exactly Lane 2's turf — instruction-position (tool-definition)
digest pinning. Verified firsthand:

- `agent-governance-rust/agentmesh-mcp/src/mcp/security.rs` (~124–130): on tool registration it
  computes `description_hash = sha256_hex(&tool.description)` and
  `schema_hash = sha256_hex(&serde_json::to_string(&tool.input_schema)?)`. `check_rug_pull`
  (~153–181) compares both and reports which of `description` / `schema` changed.
- `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/tool_registry.py`:
  `verify_tool_integrity` (~361–375) — *"Verify that a tool's handler has not been modified since
  registration. Compares the current SHA-256 hash of the handler's source code against the hash
  recorded at registration time"* — and it is invoked **before execution** (~265,
  `# Verify tool integrity before execution`).
- `agent-governance-python/agent-marketplace/src/agent_marketplace/`: `signing.py` (~22–56)
  Ed25519 `PluginSigner.sign` / `verify_signature`; `manifest.py` (~87–91) `artifact_sha256`
  documented as *"included in signable_bytes() so the Ed25519 signature binds both the manifest
  and the artifact"*; `installer.py` (~139–153) fails closed on a missing signature or an
  untrusted author. Enforcement is tested (`test_installer_atomic_and_verify.py`:
  tampered manifest, stripped signature, swapped author, signature bitflip).
- `agent-mesh` additionally carries Sigstore/SLSA provenance (`marketplace/sigstore_provenance.py`).

**What is still defensibly unoccupied** (much narrower — state it this way or not at all):
no key distribution or revocation infrastructure (trusted keys are an in-process dict);
`agent_marketplace/registry.py` itself contains no signature or digest logic; and
`agent-os/modules/nexus/registry.py` `_sign_registration` (~398–403) returns
`f"nexus_sig_{sha256(...)[:32]}"` — a truncated unkeyed hash, not a signature.

**Consequence:** Lane 2's "unoccupied position" framing is deleted. **Operator ruling 2026-08-17:**
*"it doesn't have to be different from what microsoft. if tool-definition digest pinning and fires
it before execution is the correct path then thats what we'll do too alongside our
differentiators."* Lane 2 **proceeds and builds the same mechanism**, openly convergent, with the
prior art cited rather than worked around. Convergence is evidence the mechanism is right; the
error would have been contorting the design to look different.

Two further facts, verified after the ruling, that set what Lane 2 must *earn* rather than assume:

- **Their check blocks, it does not merely warn.** `tool_registry.py` (~265–284) returns
  `{"success": False, "error": "Tool integrity verification failed: …"}` before execution and
  appends to `self._integrity_violations`. Characterize it that way; "warns" would be wrong.
- **Their pin state is in-process and non-durable.** `security.rs` builds its fingerprint registry
  as `registry: Mutex::new(HashMap::new())` (~114) — per-process memory. `_integrity_violations`
  is likewise an in-memory Python list. A process restart re-TOFUs from scratch, so a definition
  mutated across a restart presents as first sight rather than as divergence. That is a reasonable
  design for a per-session MCP scanner and is **not** a defect in their scope.

That second fact is the only honest differentiator, and it is a **claim, not yet a capability**:
contextd's pin and its divergence would be ledger events — durable, chained, witnessed, and bound
into the same transaction as the act. Under the program's one rule it may not enter `COMPARISON.md`
until a test substantiates it (see the Lane 2 brief for the specific restart test). `COMPARISON.md`
therefore continues to concede the row outright until that test exists.

### A2. The delivered `COMPARISON.md` contained a false row. Corrected.

The shipped matrix said Microsoft's toolkit does **no** instruction-position digest pinning
("HMACs protect hibernation snapshots and IPC payloads"). That row was produced by a search
scoped to `agent_control_plane/*.py` and truncated with `head -5`, which missed
`tool_registry.py` in that very directory. This is precisely the resolvable-but-unsupporting
failure `citation-guard` exists to catch, and it shipped.

Corrected in place at `COMPARISON.md`: the matrix row now reads **"Yes — and they are ahead of us
here"** with the citations above; the summary sentence "the last row no shipped system has" is
replaced with an explicit concession that Microsoft wins that row outright; and the §6 gap now
names the correction and the reason it was wrong. Done outside lane ownership deliberately —
leaving a known-false competitive claim in a delivered document while merely reporting it was
the worse option. Lane 5 inherits a corrected baseline.

### A3. Okta / RFC co-development attribution is false.

The program states: *"the standards work is real (RFC 8693/8707, co-developed with Anthropic and
Microsoft)."*

- RFC 8693 (Jan 2020) authors: Jones (Microsoft), Nadalin (Microsoft), Campbell/Ed. (Ping
  Identity), Bradley (Yubico), Mortimore (Visa). RFC 8707 (Feb 2020): Campbell (Ping), Bradley
  (Yubico), Tschofenig (Arm). **Okta appears on neither. Anthropic appears on neither** — and was
  founded January 2021, after both were published.
- The Okta–Anthropic collaboration is real but attaches elsewhere: Okta as a featured identity
  provider for Claude, and MCP Enterprise-Managed Authorization (press release 18 June 2026).
- Okta's genuine standards work is the **Cross App Access / Identity Assertion JWT Authorization
  Grant** draft (Aaron Parecki, Okta, lead author), which *profiles* RFC 8693/8707.
- Microsoft as co-developer of XAA/ID-JAG: **unverifiable** — the draft's acknowledgments list
  names only individuals, no Anthropic or Microsoft entity. Drop it.

**Correct framing for Lane 5:** cite ID-JAG/XAA and its MCP EMA adoption as the recent work, and
RFC 8693/8707 as the pre-existing OAuth foundations it builds on. Note the continuity thread
across all three is Brian Campbell of Ping Identity, not Okta.

### A4. "Four language SDKs" undercounts a competitor.

There are **five**, and the toolkit says so itself — `README.md:274`: *"All five language SDKs
implement core governance (policy, identity, trust, audit). Python has the full stack."* Under
the program's own rule (concede what alternatives win), this must be corrected upward.

Everything else in the breadth list **verified**: editor extensions, MCP server, shadow mode,
time-travel debugger, constraint graphs, process isolation all exist.

---

## B. Imprecise — will not survive a hostile reader

### B1. EU AI Act citations are pointed at the wrong article.

- **Article 12 (Record-keeping) contains no six-month requirement.** The six-month floor lives in
  **Art. 19(1)** (providers) and **Art. 26(6)** (deployers). Any "Art. 12 requires six-month
  retention" phrasing must be struck.
- It is a **floor, not a target**: *"for a period appropriate to the intended purpose of the
  high-risk AI system, of at least six months"*, limited to logs *"under their control"*, and
  displaceable by other Union or national law (notably data protection). A product that deletes
  at exactly six months may be non-compliant where the purpose demands longer.
- **The Regulation nowhere requires append-only, immutable, or tamper-evident logs.** Searches for
  "tamper", "immutab", "append-only", "unalterab" return zero matches across recitals, enacting
  terms, and annexes. An append-only ledger is a way to satisfy Arts. 12/19/26(6) and an
  evidentiary advantage — it is **not** a legal mandate, and Lane 5 must not imply it is.
- Applicability splits: 2 Aug 2026 for Annex III high-risk (Art. 6(2)); **2 Aug 2027** for
  product-embedded high-risk (Art. 6(1)).

The program's claim about Microsoft's own checklist — that it admits no retention enforcement
despite the six-month requirement — **verified** on all three parts.

### B2. liboqs carries an upstream production disclaimer.

Maintained (liboqs 0.16.0, Jul 2026; liboqs-python 0.16.0, pushed Aug 2026), ML-DSA-44 present,
Python bindings real. But upstream does not recommend it for production or sensitive data. Lane 3
must carry that disclaimer verbatim, keep the ML-DSA path opt-in and off by default, and keep
Ed25519 as the authoritative ledger signature in hybrid mode.

**Verified without change:** ML-DSA-44 = 2,420-byte signatures / 1,312-byte public keys;
Ed25519 = 64 / 32; the ~38× per-event ratio; ML-DSA is NIST-standardized as FIPS 204.

### B3. Lane 6's "fivefold spread" understates its own evidence.

The three canonical FPRs **verify exactly** against `eval/CANONICAL_RESULTS.md`: Internal 10.9%
(94.5% TPR), ATBench 12.0% (100% TPR), AgentDojo 0.8% (93.2% TPR). But 0.8% → 12.0% is a
**fifteenfold** spread, not fivefold. The canonical file wins; the correction strengthens Lane 6's
argument for why the score must never gate. Note also a supplemental thinking-augmented internal
slice at 13.0% FPR, which is outside the three headline datasets and should not be folded into
the range without saying so.

---

## C. Gates that cannot execute as written

| Gate | Problem |
|---|---|
| Lane 6: `python -c "import contextd; contextd.ledger_open()"` | **No such symbol.** `contextd` exports `home`, `load_config`, `DEFAULTS`. The archive is opened via `contextd.db.connect()`. Rewrite the gate or add the alias deliberately. |
| Lane 4: `concurrent_redemption.py --backend=postgres --hosts=2` | **Flags do not exist**; the demo takes only `--workers` and `--baseline-only`. Adding them modifies a file the program freezes as a fixed reference point, and "the gate-proof demo … requires modification to pass" is a global stop condition. **Needs an operator ruling** (see D1). |
| Lane 4: `pytest --backend=postgres` | Requires a new conftest option; fine under Lane 4's `tests/` ownership, but it does not exist today. |
| Lane 1: `migrations/` in may-modify | No such directory exists. Harmless (it would be created), but say so. |

---

## D. Decisions only the operator can make — **ALL THREE RULED 2026-08-17**

> **Operator rulings, verbatim:** *"separate multihost script, keep lane 6 and drop the
> conflicting license – its my call, widen lane 1 scope"*
>
> - **D1 → separate multihost script.** Lane 4 creates a NEW
>   `examples/gate_proof/multihost_redemption.py`. `concurrent_redemption.py` stays frozen and
>   byte-identical; the global stop condition on it is unamended and still binding.
> - **D2 → Lane 6 kept; AGPL dropped.** `~/unified-stack` relicensed **AGPLv3 → Apache-2.0**,
>   matching contextd. Authorship verified sole-holder first (418 + 264 commits, all
>   `codechockablock`; `frontier-ops` is an own repo, not an upstream fork). A pre-existing
>   internal contradiction was found and fixed in the same pass: `pyproject.toml` declared
>   `license = "MIT"` while `LICENSE` was AGPLv3 — both now read Apache-2.0. Changes are
>   uncommitted, for the operator's own commit. **Apache-2.0 was chosen over reverting to MIT**
>   because it matches contextd exactly and carries the patent grant the program calls "the
>   point"; flipping to MIT is a one-line change while there are no adopters.
>   **Still open (related, not ruled):** the standalone `~/frontier-ops` repo has **no LICENSE at
>   all** — all-rights-reserved by default. Harmless while Lane 6 consumes the vendored
>   `unified-stack/frontier_ops` copy, which the new Apache-2.0 grant now covers. Needs a license
>   if that repo is ever published or consumed directly.
> - **D3 → Lane 1 scope widened.** Lane 1 may now change the witness/recovery protocol,
>   including a `WITNESS_VERSION` bump. Its `db.py` restriction to "migration only — additive"
>   is lifted. See E2 for the required shape.

### Original decision text (retained for context)

### D1. Lane 4 needs a carve-out from the frozen-demo rule.

Lane 4 cannot prove a multi-host guarantee without a multi-host runner. Options: (a) a **separate**
`examples/gate_proof/multihost_redemption.py`, leaving the frozen demo untouched — recommended,
preserves the reference point exactly; (b) additive flags with a byte-identical default path, plus
an explicit amendment to the stop condition. Pick one before dispatch.

### D2. Lane 6 has a license conflict — this is the biggest finding after A1.

`~/unified-stack` is **AGPLv3** (added 2026-08-08, commit `1f197b6`). `contextd` is **Apache-2.0**.
Lane 6 proposes `pip install contextd[detector]`, which would pull AGPL code into an Apache-2.0
product whose entire Lane 5 licensing rationale is *"infrastructure meant to be absorbed into
standards and enterprise stacks; the patent grant is the point."* AGPL is a routine hard blocker
in exactly that procurement path, and its network clause is live for a sidecar. Note that
`b01404b` deliberately extracted part of the stack as an *Apache-2* MCP server, so a compatible
subset may already exist. Resolve before Lane 6 writes an extra: relicense the consumed subset,
consume it out-of-process across a boundary that does not create a combined work, or drop the
integration. Also note Lane 5's "license decision" item is already settled in-tree — `LICENSE` is
Apache-2.0 today, and `README.md` and `docs/SECURITY.md` already exist, so that lane extends
rather than creates.

### D3. Lane 1's refusal requirement exceeds its stated scope. (See E2.)

---

## E. Design findings that change Lane 1's brief

Lane 1 is otherwise clean — nothing in its scope is refuted — but two items will send a delegate
down a wrong path if not stated up front.

### E1. The replay digest cannot be `prepare_action`'s digest.

Lane 1 requires that *"two honest retries of the same act produce identical digests"* and cites
"`prepare_action`'s existing binding". That binding is **nonce-bound**: the signed action map
includes `nonce`, `sequence`, `issued_at`, `expires_at`, `archive_uuid`, and `key_id`, so
`Authorization.digest` differs on every retry **by construction** — which is exactly what makes it
single-use. The intent-only comparison exists only as a boolean in `Authorization.matches`
(attest.py ~663–678: action, scope, arguments, content_digest, reason_digest). **Lane 1 must
introduce a new intent-only digest** over those five fields. Conflating the two breaks replay
detection or breaks single-use; there is no version that does both.

### E2. Core-recorded refusal collides with the witness-first crash-recovery protocol.

Today a refusal raises inside `BEGIN IMMEDIATE` and `append_event_checked` rolls the whole
transaction back — which is why the durable refusal row is currently the caller's second append.
Making the core record it is not a local change:

- The recovery journal is written **before** `BEGIN`, naming a single `target` = `{id, chain_hash}`
  computed for *the act's* bytes (db.py ~794–801).
- `_recover_locked` (db.py ~488–499) accepts a committed tip only if it equals `previous`
  (rolled back) or `target` (committed), and otherwise raises **"database tip matches neither side
  of recovery journal"** — the tamper alarm.
- A refusal event has different bytes, therefore a different chain hash. Committing it under the
  act's journal turns a benign crash between commit and witness-finalize into a **false
  tamper alarm on the entire ledger**.

The workable shape is a journal that enumerates both permissible outcomes
(`{previous, target_act, target_refuse}`) with recovery accepting either — which is a **versioned
change to the witness protocol** (`WITNESS_VERSION` 1 → 2) and touches restore-drill and backup
machinery. That exceeds Lane 1's stated `db.py` scope of *"migration only — additive"*. Widen the
scope explicitly, or drop core-recorded refusal from Lane 1 and give it its own lane. Existing
coverage that must stay green: `tests/test_crash_recovery.py`, `tests/test_chain_witness.py`,
`tests/test_backup_restore.py`.

---

## F. Confirmed good — no action

- Repo at `~/contextd` @ `a34ac8a`, master, as the program states. No inferred path.
- Baseline suite **646 passed** before any change; no pre-existing failure.
- The gate-proof demo and its evidence are untouched and still passing.
- Lane 6's three FPR figures match the canonical file exactly.
- **Lane 6's calibration snapshot id is resolvable and clean.** The canonical header names
  `573a7c5` *"+ content-only semantic gate (this refresh)"*, which is not a commit. The refresh
  actually landed as **`4034b1a`** (2026-04-10, *"fix(semantic_track): gate step_13 lightweight on
  content-only score"*). Of the 13 commits from `573a7c5` to HEAD `1f197b6`, the **only** change
  under `frontier_ops/sensing/` is that commit — the signal path is unchanged from the calibration
  point to HEAD. So Lane 6 can pin `4034b1a` as the snapshot identifier and honestly attach the
  canonical numbers to current detector code **without re-running any eval**, which keeps it clear
  of its own "no new experiments" stop condition.

---

## G. Recommended dispatch order after edits

1. **Operator rulings first:** D1 (Lane 4 carve-out), D2 (Lane 6 licensing), D3/E2 (Lane 1 scope).
2. **Lane 1** with E1 and E2 written into its brief — still blocking.
3. **Lanes 3, 4, 6** in parallel once ruled on; **Lane 2 re-scoped or cut** per A1.
4. **Lane 5** last, inheriting the A2 correction and the A3/B1 rewrites.

Every competitive claim that survives this pass still owes a test id under the program's one rule.
Nothing here has been tested yet — this pass verified *facts*, not *claims*.
