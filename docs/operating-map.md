# contextd — operating map

Live coordination for parallel agent sessions. Read-first rule: any session
joining this project reads this file before starting work and records itself
as owning session if it takes a lane. Update on state change (start, block,
handoff, done), not as a journal.

**Canonical copy: master.** From any lane, read it with
`git show master:docs/operating-map.md`; never trust a lane checkout's copy
and never hand-mirror master content onto lanes — divergent copies drifted
and the 2026-08-15 flaw sweep retired that practice along with the stale
lane checkouts themselves.

## Operator queue

Everything the machinery cannot do for you, with the exact act.

1. **Grant Full Disk Access** for Safari history capture: System Settings →
   Privacy & Security → Full Disk Access, for your terminal and the watch
   daemon's python (`/opt/homebrew/Cellar/python@3.14/…/bin/python3.14`) —
   or set `[browser] safari=false`. The daemon was restarted onto the
   merged code 2026-08-15; a denied scan now records no-access in its
   cursor, `ctx status` warns from that state, and the first good scan
   self-clears it.
2. **Open a NEW grant-calibration field window when the post-gate-v1 code
   settles** (docs/GRANT_CALIBRATION.md): the r1 window is CLOSED as of
   2026-08-18 — see Decisions. Opening act: `ctx grant add loop.confirm
   --repo /Users/joseph/contextd --for <duration>`, then resume the morning
   review ritual for confirmations made under the new window.

Resolved 2026-08-15 (evening), by the operator: **production signer
enrolled** — key `0885eb01…` (secure_enclave, tag=default); first signed
act was grant ev 44232 (loop.confirm, repo-scoped, "field window night
3"). **Field window RUNNING**: 2/20 model-granted confirmations (loops
42848, 42914, both open awaiting review), 1/10 grant-active days, 0
vetoes. Grant events #42847/#42878/#42908 from the r1 era now reduce as
anomalies ("lacks a verified operator authorization") — expected after the
trust-model upgrade, not an incident: they were legitimate operator acts
under r1 metadata authority, are expired and inert, and the confirmations
they enabled still count in the field tally.

## Decisions

- 2026-08-18 — Operator: **grant-calibration field window r1 CLOSED at 2/20
  confirmations, 2 grant-active days, 0 vetoes — a regime break, not a
  calibration verdict.** gate-v1 landed mid-window (schema 3, new vocabulary,
  new operator acts), so accruing the remaining 18 samples into the same
  window would mix two systems under one measurement. Both seed loops
  (#42848, #42914) closed as OVERTAKEN, explicitly not vetoed: the model's
  confirmations were sound when made. Continuation grant ev 45893 revoked
  (revocation ev 45907). A fresh window opens post-settle; its tally starts
  at 0/20 and its numbers must never be pooled with r1's.

- 2026-08-18 — Operator rulings, batch: unified-stack Apache relicense merged
  and pushed (public master no longer AGPL); the frontier-ops/unified-stack
  name collision resolves by renaming unified-stack's package (agent
  dispatched); **Lane 6 DROPPED** — branch gate-v1-lane-6 deleted local and
  remote, README updated from "held" to "dropped"; the measurement (TPR 100%
  dev → 40% held-out) is the artifact worth keeping. frontier-ops fable-spec
  WIP retired to attic/fable-spec-wip. Rollback-copy deletion deferred.
  gate-v1.1 chartered: three lanes to close every recorded gap that is
  code-closable; explicitly excluded as not agent-closable on this machine:
  hardened-deployment distance (doctor --strict 6/7, needs root-owned signer
  and service uid) and true multi-machine network evidence.

- 2026-08-13 — Open-loops capture verdict is `NOT EARNED` pending the real
  operator trial (protocol v2, docs/OPEN_LOOPS.md); machine-side results
  cannot substitute.
- 2026-08-13 — Instruments branch (`instruments-liveness-tally`: capture
  liveness watermarks, checkpoint outcome tally + failure classes,
  `SCHEMA_VERSION` stamp) independently verified: ruff clean, 154 pytest,
  smoke green. Precondition for all three lanes below.
- 2026-08-13 — Three autonomous lanes chartered with exclusive territories;
  goal prompts pinned. Dispatch ceilings: selection-stress ≤ 300 haiku calls,
  lineage-drift ≤ 250. restore-firedrill makes zero model calls.
- 2026-08-13 — Liveness threshold policy: chrome/claude_code 48h, fs 72h
  (only once watch_dirs configured), safari and note deliberately
  unthresholded — thresholds flag pipeline death, not operator behavior.

- 2026-08-15 — Live archive migrated to schema 2 (cutover tip #44150, 44150
  events byte-identical). Reconciler revived: hardening had closed the meta
  registry without declaring `("claude_code","reconcile")` — every run
  dispatched, then crashed appending its marker (fix + regression test on
  master). Dev harness automated: repo `.claude/settings.json` (gate
  allowlist; operator speech acts kept behind `ask` — see
  docs/GRANTS-r2-proposal.md R2.5; live-verified ruff PostToolUse hook),
  `scripts/gates.sh` (CI-mirroring battery, network surface pinned by
  `tests/network_surface.txt`), restore-drill + lineage-audit launchd agents
  instantiated and loaded (calibration read AUDIT EARNED), first `.ctxbackup`
  bundle created and drill-verified PASS (#44177). Known operator-only items:
  Secure Enclave signer not enrolled (all operator CLI acts refuse since
  hardening — enrollment steps in GRANTS-r2-proposal.md), Safari FDA missing,
  grant-calibration field window not started (tally at 0/20, 0/10).

- 2026-08-15 — Agent-plane contract frozen before implementation
  (docs/AGENTS.md: trifecta rule, starved coordinator, workflows as
  promoted artifacts, injection claims empirical-only). Stage 1 built
  inline: health sweep (hooks/health_sweep.py, launchd every 30 min,
  content-NULL `health` events, notify on new degradation only). First
  live sweep found two instrument artifacts (kickstart's -15 read as
  failure; historical error streak read as current), both corrected and
  pinned by test — sweep now OK. Stage 2 (workflow artifact format +
  policy lint) not started; earn condition for stage 1 met.

## Lanes

### gate-v1.1-lane-p
- **Objective:** PostgreSQL parity — backup/handoff/ingest/migrate on the
  backend seam; CI service container so the 18 Postgres tests run. Brief:
  docs/reviews/lane-p-goal-prompt.md. Owns backup/handoff/ingest/ci.yml.
- **Owning session:** Claude Code / Fable 5 (orchestrator-dispatched worktree)
- **State:** RUNNING — dispatched 2026-08-18
- **Last update:** 2026-08-18 — chartered from the operator's fix-all-gaps ruling

### gate-v1.1-lane-q
- **Objective:** Authority follow-ups — exported signed checkpoint, in-flight
  mandate resolve act, refusal-row cap, migrate dry-run fix. Brief:
  docs/reviews/lane-q-goal-prompt.md. Owns attest/ledger_sig/schemas/migrate.
- **Owning session:** Claude Code / Fable 5 (orchestrator-dispatched worktree)
- **State:** RUNNING — dispatched 2026-08-18
- **Last update:** 2026-08-18 — chartered from the operator's fix-all-gaps ruling

### gate-v1.1-lane-r
- **Objective:** Verification hardening — independent-language format verifier,
  TOCTOU pinning test, import-level network gate. Brief:
  docs/reviews/lane-r-goal-prompt.md. Owns scripts/ and tests/ only.
- **Owning session:** Claude Code / Fable 5 (orchestrator-dispatched worktree)
- **State:** RUNNING — dispatched 2026-08-18
- **Last update:** 2026-08-18 — chartered from the operator's fix-all-gaps ruling

### operator-trial
- **Objective:** Protocol v2 field trial of open-loops assisted capture —
  ~5 real working sessions, honest window-end confession list, verdict earned
  or not by the frozen bars.
- **Owning session:** the operator (manual; no agent lane)
- **State:** RUNNING — window open since 2026-08-13 (archive marker #42453);
  this entry previously said "awaiting operator start" and was stale, caught
  by loop candidate #42915
- **Blockers:** —
- **Last update:** 2026-08-15 — map reconciled to the archive marker

## Done

- 2026-08-17 — **gate-v1-lane-5** (Claude Code / Fable 5, merged to master):
  the release surface, closing the Gate v1.0 program — all six lanes resolved
  (1–5 merged, 6 held by ruling). README rebuilt on the operator-ruled ledger
  line, quickstart proven verbatim in a fresh python:3.12 container,
  docs/FORMAT.md = contextd-record-format v1 (mutation-tested spec suite),
  root SECURITY.md disclosure process + checkpoint-window and Postgres-trust
  coverage, `ctx compliance` deterministic EU AI Act record-keeping artifact
  (corrected articles; renders no verdict), COMPARISON.md at merged reality
  with test ids. Two false old-README claims deleted (search-is-unlogged;
  campaign attribution). Suite 802+18 (820 with Postgres, zero skips), gates
  ALL PASSED. Version recommendation 0.6.0 — operator decision, not applied.

- 2026-08-17 — **gate-v1** (Claude Code / Fable 5, PR #1 merged to master as
  `1c5b1c8`): the Gate v1.0 program, lanes 1–4 of 6, orchestrator-verified —
  every lane's gates re-run independently, never taken from lane reports.
  Lane 1 three-state redemption + intent digest + core-recorded refusal
  (witness protocol v2); Lane 2 instruction-position pinning (openly
  convergent with Microsoft's toolkit, durability earned by a real
  restart test); Lane 3 algorithm-tagged signatures + ML-DSA checkpoint
  signing via native cryptography, **SCHEMA_VERSION 2→3**; Lane 4 backend
  seam + PostgreSQL path proven across two hosts 20/20 (protocol redesign —
  the "backend swap" premise was refuted). Cross-lane defects found by
  adversarial audit of the merged tree and fixed: PQ key silently disabling
  backups; concurrent-migration race (0/40 post-fix). **Live archive migrated
  to schema 3** (45,557 events, history byte-identical, chain green; rollback
  copy at `~/.contextd-prehmigration-schema2-20260817-185907`, forward-only —
  keep until the eval settles). Gate-proof demo frozen and byte-identical
  throughout. **Lane 6 (advisory trajectory evidence) HELD unmerged** on
  `gate-v1-lane-6`, deliberately: detector TPR does not transfer (100% dev
  → 40% held-out); the honest version is worth more unmerged. Lane 5
  (release surface) not started; COMPARISON.md corrected in place instead
  (instruction-pinning row conceded to Microsoft; no-network claim scoped to
  the SQLite backend). Reports: docs/reviews/gate-v1-preflight.md and the
  lane briefs beside it.
- 2026-08-15 — **flaw-sweep** (Claude Code / Fable 5, branch `flaw-sweep`,
  operator-chartered: "completely fix 1-6 end to end" from the repo-flaws
  review). Fixed: blob store quarantine-and-heal for a corrupt content
  address + dead-temp reaping (a torn blob no longer bricks ingest and the
  weekly backup); reconciler self-documentation now counts only notes whose
  kernel-stamped anchors cite into the epoch window (id-window co-location
  marked epochs self-documented under parallel sessions and silently never
  distilled them), and a size-capped disclosure's item list now names
  exactly the messages the payload carries (omission loud in payload and
  meta.omitted_messages, registered); `ctx status` surfaces the unenrolled
  signer with the enrollment remedy and browser no-access states recorded
  by the scanner; README + DECISIONS.md truth sweep (model-facing claim,
  zero-network claim vs authority socket, retired derivation env, schema 2,
  DECISIONS addendum for grant-gated supersession). Ops: stale worktrees
  ctx-b (lineage-drift-audit) and ctx-c (restore-firedrill) removed, ctx-a
  (delegation-grants) venv deleted — pre-hardening checkouts can no longer
  execute against the schema-2 live archive (their code predates the
  forward refusal); branches kept as history. Verified already fixed on
  master, no change needed: forward schema refusal in both directions
  (assert_supported_schema + tests), grants expiry as UTC instants,
  mandatory bounded expiry, attestation-gated grant registry.
- 2026-08-14 — **delegation-grants** (Claude Code / Fable 5, branch
  `delegation-grants` off decisions-lifecycle): operator-chartered from the
  authority-model conversation. `ctx grant add/revoke/list` — recorded,
  class-scoped (loop.confirm / loop.dismiss / decision.supersede), repo- or
  global-scoped, expiring, revocable delegations (docs/GRANTS.md, frozen
  before implementation). MCP loop_confirm/loop_dismiss/decision_supersede
  refuse without a covering grant; under one they record authority
  `model-granted` + grant id — never operator. Checkpoints carry a
  STANDING DELEGATIONS line + egress meta while grants are active. The
  retired utterance-binding stays retired (OPEN_LOOPS.md addendum); two
  registry guard tests evolved to pin the sharper invariant (tools exist,
  refuse ungated, never operator). Mechanism only — no calibration claim,
  zero dispatches. Gates: ruff clean, 230 pytest, smoke, selftest, network
  grep 2 (pre-existing parse-only).
- 2026-08-14 — **decisions-lifecycle** (Claude Code / Fable 5, branch
  `decisions-lifecycle`): **FIX DECLARED** against stale resurrection.
  Supersession edges (`ctx decision supersede`, docs/DECISIONS.md contract
  r2) + two-pass compile contract: superseded never served unmarked,
  current version carried or loudly named, owe-nothing compiles pay
  nothing. Round 1 (prereg #253) honestly failed bars 2 (scorer artifact)
  and 4 (reserve tax) — fix not declared, mechanism revised, re-frozen,
  re-preregistered (#255). Round 2: all 8 bars met — resurrection 0.269 →
  0.000 (0 silent, 0 unmarked, 0 unpaid losses), behavioral resurrects
  0.042 pooled (p=5e-5), v2-honors 0.958. Dispatches 273/300 cumulative.
  Report: runs/decisions-lifecycle-2026-08-14/ (rebuilds via `bench.py
  contrast-report 255`). Gates: ruff clean, 225 pytest, selftest, smoke.
  Not licensed: unrecorded supersessions, plain-recall marking,
  model-proposed edges (candidate follow-up discussed with operator).
- 2026-08-13 — **selection-stress** (Claude Code / Fable 5, branch
  `selection-stress` @ c6ff6e7): loss surface measured. Validity gate 1.0
  all pairs; 7,830-row grid; silent absence >20% already at t5k/recent/mid
  (0.556); stale resurrection 0.269; latency 21/63/248ms by tier;
  behavioral prereg #36 (249/300 dispatches — prereg #2 voided honestly at
  32 for a rubric token collision): restoring absent items moves honor
  rate by 0.833 (p=5e-5), stale carriage becomes stale behavior
  (0.625–0.875 v1-as-current). Positive control missed its bar (0.5 vs
  0.9) — instrument finding (placement salience). Report:
  runs/selection-stress-2026-08-13/ (rebuilds byte-identically via
  `bench.py report 36`). Gates: ruff clean, 164 pytest, selftest green.
- 2026-08-13 — **lineage-drift-audit** (Claude Code / Fable 5, branch
  `lineage-drift-audit` @ 7273da6): derivation-depth gauge (`ctx lineage`,
  depth>1 DEPTH ALERT) shipped; calibration verdict **AUDIT EARNED**
  (prereg #76, held-out 150/150 bars passed); live baseline measured (29
  notes, all depth 1, 38/38 anchors); first live audit ran (7 advisory
  verdicts); 183/250 dispatches used. Note: mission's `actor='mcp'` filter
  didn't match the live archive (notes carry client names); audit uses the
  provenance_class boundary instead, surfaced honestly in the final report.
  Report: runs/lineage-audit-2026-08-13/. Gates: ruff clean, 185 pytest,
  smoke, network grep 3.
- 2026-08-13 — **restore-firedrill** (Claude Code / Fable 5, branch
  `restore-firedrill` @ 1f6df05): weekly restore drill with tested alarm
  (PASS→forced FAIL→recovery exercised by pytest and smoke) shipped; 6/6
  scale cells PASS at full size (8 GiB included), temp ratio exactly 1.0;
  cross-machine rehearsal PASS; 9-case adversarial corpus, distinct
  refusals; 3 defects fixed with regression tests (incl. a bundle
  sequence-number reuse bug found by the new smoke alarm), 2 design
  questions stopped-and-reported. Report:
  runs/restore-firedrill-20260813/final-report.md. Gates: ruff clean, 178
  pytest, smoke ALL PASSED, network grep 3.
- 2026-08-13 — **merge**: all three lanes merged into master sequentially
  (`36ce893`→`9fd8550`), real conflicts in `contextd/__init__.py`,
  `contextd/cli.py`, `tests/smoke.py` between lineage-drift-audit and
  restore-firedrill (both inserted disjoint blocks at the same point —
  no logical overlap, both kept in full). Post-merge: 219 pytest, ruff
  clean, smoke ALL PASSED, network grep 3.
