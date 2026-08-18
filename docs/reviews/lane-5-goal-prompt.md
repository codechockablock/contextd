# GOAL PROMPT — Lane 5: Release surface and positioning

**Lane:** `gate-v1-lane-5` · **Runs last. Lanes 1–4 are MERGED to master** (`1c5b1c8`, map at
`ff40a6d`). **Lane 6 is HELD unmerged** — see the exclusion rule below.
**Repo:** `~/contextd`. If it is not there, halt and report — do not search or infer a path.
You are in an isolated git worktree branched from current master. **Do not commit** — the
orchestrator commits and merges. This lane owns every user-facing word.

## The one rule that overrides everything

**No competitive claim ships without a test id behind it.** Every superiority statement must name
a specific test that passes and, where it contrasts an alternative, a file:line in that
alternative. A claim that cannot be traced that way gets deleted, not softened. Run every test id
you cite and paste the pass in your report — a test id you did not run is a citation you did not
check. If a claim needs a test that does not exist, either write the test or drop the claim.

The concession sections are the asset. `COMPARISON.md` is credible because it recommends
competitors for what they win and lists its own gaps first-person. Expand concessions, never trim
them: new capability creates new gaps, and a gaps section that shrinks while the feature list
grows is a tell.

## The README line — operator ruling, 2026-08-17

The one-sentence pitch is ruled, not yours to invent. The operator's own description, sharpened:

> **contextd is a detailed ledger of what humans and AIs do on a computer — one that can't be
> quietly rewritten, and that an AI's authorization is spent inside, in the same transaction as
> the act, so nothing happens off the books.**

You may tighten rhythm and trim words. You may NOT lose any of its three load-bearing parts:
(a) a ledger of what humans and AIs do, (b) can't be quietly rewritten, (c) authorization is
*spent inside it*, transactionally with the act. The program's earlier working draft ("one gate,
one ledger…") is superseded. Aimed at an engineer, not a buyer. Sharpen, don't inflate.

## Definition of done

- [ ] **README.md** rebuilt around that line. Engineer-facing: what it is, the one demonstrated
      property (with the gate-proof and multi-host numbers and where to re-run them), quickstart,
      backends, extras, what it deliberately is not. The current README predates the entire
      program — expect a rewrite, not a patch.
- [ ] **Quickstart that works from a clean clone in under five minutes, tested in a fresh
      container.** Docker Desktop is running on this host. The gate:
      `docker run --rm -v "$PWD:/src" python:3.12 bash -c "cd /src && pip install -e . -q && python -c 'import contextd; print(...)'"`
      then follow your own README quickstart VERBATIM inside that container. If a step fails or
      needs local knowledge, the quickstart is wrong — fix the quickstart, not the transcript.
      Two known traps: the frozen demo needs `CONTEXTD_INSECURE_TEST_SIGNER=1` + a temp
      `CONTEXTD_HOME` (it sets these itself — verify it truly runs from a clean clone), and
      nothing in the quickstart may assume the operator's machine (no keg-only paths, no venv
      assumptions beyond `pip`).
- [ ] **SECURITY.md coverage.** `docs/SECURITY.md` exists and is load-bearing — extend, do not
      rewrite its threat model. Ensure it now covers: the injection surface, the hostile
      same-UID-agent model and adjudication-between-distrusting-parties model, **the uncovered
      checkpoint window** (events since the last checkpoint are protected only by local state —
      Lane 3's docs state this; link or lift), the **PostgreSQL trust trade** (a DB
      superuser can rewrite chain and tip together; the external witness does not exist there —
      cite `docs/reviews/lane-4-goal-prompt.md` and the merge commit), and a **disclosure
      process** (root `SECURITY.md` per GitHub convention pointing at it; private disclosure to
      the operator's email, no bug-bounty theater).
- [ ] **Format specification, versioned, its own document** (`docs/FORMAT.md` or similar,
      `contextd-record-format v1`). THE durable artifact: an adjudicator in 2035 must be able to
      parse a record written today without this codebase. From the code, precisely: the `events`
      table row shape; the chain-hash computation (`db._chain_hash` — fields, order, encoding);
      canonical encoding rules (`canonical.py` — including WHY floats are refused); the
      attestation block and `OperatorActionV1` (fields, domain separators, TTLs, nonce
      single-use); service signatures + algorithm identifiers + checkpoint records (Lane 3's
      three domains); the witness/recovery files (v2 outcomes journal); schema version 3 and the
      registered event vocabulary incl. Lane 1 commerce and Lane 2 pin/act types. Every field
      documented from the code with file references, not from memory. State plainly what is NOT
      specified (Postgres wire details, egress schemas if out of scope) rather than going quiet.
- [ ] **COMPARISON.md updated to the merged reality.** It was corrected mid-program and is now
      stale the OTHER way — it concedes instruction pinning outright, but Lane 2 merged with the
      restart test. Update honestly: contextd's pinning row cites
      `tests/test_instruction_pinning.py::test_pin_survives_process_restart` and still concedes
      Microsoft blocks-before-execution as prior art (`agent-governance-toolkit` @ `7d0cef5`,
      `tool_registry.py` `verify_tool_integrity` ~361–375, called ~265;
      `agentmesh-mcp/src/mcp/security.rs` `check_rug_pull` ~153–181). Add rows/claims for:
      three-state redemption + core-recorded refusal (cite `tests/test_commerce_redemption.py`
      ids and `tests/test_authenticated_provenance.py` refusal assertions), algorithm-tagged
      signatures + hybrid checkpoints (`tests/test_crypto_agility.py`), multi-host single-use
      (`examples/gate_proof/multihost_redemption.py`, 20/20). Extend the gaps section with what
      the program learned: Postgres archives cannot yet be backed up or handed off; the DB-owner
      trust trade; the stuck in-flight mandate with no resolve path; pinning binds the caller's
      claim, not the file (the four surviving attacks); the lexical network gate cannot see
      psycopg. Preserve every existing concession.
- [ ] **EU AI Act export.** A small deterministic generator (new module, e.g.
      `contextd/compliance.py`, plus a `ctx` subcommand) producing a compliance artifact from the
      existing ledger: retention coverage (earliest/latest event, count, chain verification
      result, checkpoint coverage), keyed to the CORRECT articles. **The program text was wrong
      and pre-flight corrected it — use these:** Article 12 is the *logging-capability* design
      requirement on high-risk systems; the six-month figure is a retention **floor** in
      **Art. 19(1)** (providers) and **Art. 26(6)** (deployers), "for a period appropriate to the
      intended purpose… at least six months," limited to logs under their control, displaceable
      by other Union/national law. **The Regulation nowhere requires append-only or
      tamper-evident storage** — position the ledger as one way to satisfy Arts. 12/19/26(6) and
      an evidentiary advantage, never as legally mandated. Applicability split: 2 Aug 2026 for
      Annex III (Art. 6(2)); 2 Aug 2027 for Art. 6(1) product-embedded. It is honest and good to
      note Microsoft's own compliance checklist admits no retention enforcement (verified in
      their repo's EU-AI-Act checklist) — with the same fair-purpose framing COMPARISON.md uses.
      No LLM anywhere in it. Deterministic output; a test runs it twice and diffs.
- [ ] **Packaging.** `pip install contextd` shape sanity from a clean env: base deps are exactly
      `mcp`,`cryptography`; extras `pqc`, `postgres`, `dev` documented in README. Verify the
      wheel actually contains `contextd.backends` (a Lane 4 fix — confirm, don't trust).
      `version = "0.0.1"` is visibly wrong for what this now is: recommend a version in your
      report (suggest `0.6.0` or similar) but DO NOT change it — the operator sets versions.
- [ ] **License**: settled — Apache-2.0 is in-tree and deliberate. Record as settled; do not
      re-open.

## Positioning sections — corrected inputs, use these not the program's originals

**Microsoft `agent-governance-toolkit`** (checkout at
`/private/tmp/claude-501/-Users-joseph/c5817bf3-6ce3-4231-aaf3-499777a6f280/scratchpad/agent-governance-toolkit`,
commit `7d0cef5` — verify it still exists; if gone, re-clone read-only to scratchpad, never into
the repo). The distinction: a flight recorder records the verdict; a gate IS the verdict.
Verified cites: `intercept_tool_execution` (~155–224) runs `start_trace()` →
`check_violation()` → `log_violation()` as three steps with no transaction; `_queue_write`
buffers to an in-memory deque flushed at `batch_size=100`/`flush_interval=5.0s`;
`PRAGMA synchronous=NORMAL`; INSERT-pending-then-UPDATE with `entry_hash` over the `:pending`
state; no `CREATE TRIGGER`. Fair reading in the same paragraph: it is named a flight recorder
and behaves like one; enforcement lives in a separate policy engine by design; they never
claimed atomicity. They beat this project permanently on breadth — **five language SDKs, not
four** (their README:274 says five) — editor extensions, MCP server, shadow mode, time-travel
debugger, constraint graphs, process isolation, and distribution. And they DO pin tool
definitions and block before execution — concede it as prior art for Lane 2's mechanism.

**Okta for AI Agents** — the program's sentence was refuted; use this framing: the distinction is
a token authorizes a class of actions for a window; contextd consumes an authorization for one
act. Okta's real standards work is the **Cross App Access / Identity Assertion JWT Authorization
Grant draft (Aaron Parecki, Okta, lead author)**, which *profiles* the pre-existing OAuth
foundations RFC 8693 (Token Exchange, Jan 2020) and RFC 8707 (Resource Indicators, Feb 2020) —
**Okta and Anthropic appear on neither RFC; do not say "co-developed."** The verified
Okta–Anthropic collaboration attaches to MCP Enterprise-Managed Authorization (June 2026 press
release). What a validity window cannot do: distinguish a crashed agent's honest retry from a
second act redeemed against a spent mandate — both are inside the window. Concede: on enterprise
identity across a SaaS estate, Okta wins and contextd does not compete; the honest claim is
adjacency — verify their token, bind it into the chain, consume it once.

**TraceAgent / Temporal**: keep COMPARISON.md's existing treatment; refresh only if you find it
contradicts a verified fact.

## The Lane 6 exclusion rule

Lane 6 (advisory trajectory evidence) is **held on `gate-v1-lane-6`, unmerged, deliberately**:
its detector's calibrated TPR does not transfer (100% dev corpus → 40% held-out slice). Nothing
user-facing may present trajectory scoring as a shipped capability. You may mention it once,
honestly, as unreleased work held back because the operator judged the honest version worth more
than the feature line — that sentence, if used, is itself positioning gold. Do not cite its
numbers as product claims.

## Repo constraints

**MAY create/modify:** `README.md`, root `SECURITY.md` (new), `docs/` (except `docs/reviews/`),
`COMPARISON.md` (this lane owns it), `contextd/compliance.py` (new), `contextd/cli.py` (wiring
the one subcommand only), `contextd/schemas.py` ONLY if the export needs a registered event type
(additive; keep the registry closed), `tests/`, `pyproject.toml` (extras documentation/metadata
only — not version, not dependencies).

**MUST NOT:** `examples/gate_proof/` (frozen, both demos must keep passing unmodified — note
`multihost_redemption.py` needs a Postgres URL and may be verified by running the SQLite demo
plus the multihost test suite if no server is up; PostgreSQL 18.6 is at
`/opt/homebrew/opt/postgresql@18/bin`, keg-only, needs `LC_ALL` set — recipe in
`docs/reviews/lane-4-goal-prompt.md`); the transaction path (`db.py`, `attest.py`,
`ledger_sig.py`, `backends/` — read, cite, never edit); `docs/reviews/`; git operations of any
kind. **Never run `pip install -e .` against the shared venv from your worktree** — it hijacks
the operator's live `ctx` (this happened once already); use the docker container or a throwaway
venv for install tests.

## Verification gates

```bash
cd <worktree>
python -m pytest -q                                     # baseline 755 passed + 18 skipped; no new failures
python examples/gate_proof/concurrent_redemption.py     # EXPECT exit 0, "1 success, 7 refused"
sh scripts/gates.sh                                     # EXPECT: GATES: ALL PASSED
docker run --rm -v "$PWD:/src" python:3.12 bash -c "cd /src && pip install -e . -q && python -c 'import contextd.db; print(\"import ok\")'"
# then: follow the README quickstart VERBATIM in that fresh container, and paste the transcript
python -m pytest tests/ -q -k "compliance or format_spec"   # your new tests
git status --porcelain examples/gate_proof/ docs/reviews/   # EXPECT empty
```

## Stop conditions — halt and report

- A claim intended for any user-facing doc cannot be traced to a passing test id and (for
  contrasts) a file:line.
- A stated fact about an alternative does not check out when you open the file.
- The quickstart cannot be made to work in the container without touching frozen or forbidden
  files.
- The suite was failing before your first change.
- Scope pressure toward: a hosted service, an LLM in any path this lane builds, marketing
  language the evidence does not carry, or re-opening the license.

## Completion report format

Raw tool output, never a summary of state you did not observe. (1) Every gate's output pasted,
including the FULL container quickstart transcript. (2) Every claim in README/COMPARISON.md with
its test id or file:line and a verified/unverified verdict — the citation-guard discipline:
resolvable-but-unsupporting is a fail. (3) The format spec's coverage list and what it
deliberately omits. (4) The version you recommend and why. (5) One honest paragraph: where is
the positioning still ahead of the evidence?
