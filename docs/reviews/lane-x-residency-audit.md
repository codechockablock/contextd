# Lane X — residency audit (Phase A, read-only)

Base: `origin/master` `97ee1da` (PR #2 lane-t-severance + PR #3
lane-nv-verifier-pqc; the earlier local base `c67effd` was a redundant
orphaned duplicate of PR #2 and this branch was rebased off it), branch
`lane-x-dissolution`, worktree `~/contextd-lane-x`. Baseline re-recorded
from scratch on this base:
`python -m pytest -q` → **904 passed, 35 skipped**;
`tests/test_core_boundary.py` → **3 passed**;
`examples/gate_proof/concurrent_redemption.py` → **exit 0**;
core→residency imports (`git grep` over `contextd/*.py`) → **zero**.

**Pre-existing red on this base, recorded, not chased:** the lexical
network-surface gate (`scripts/gates.sh` "network grep") fails because
`tests/network_surface.txt` lacks `contextd/authority_mode.py` — Lane T's
new core module mentions socket vocabulary in comments and the manifest was
never updated. Out of this lane's scope. **Interaction, stated explicitly:**
`rpc.py` and `authd.py` are pinned lines in that same manifest, so Phase B's
deletions must edit `tests/network_surface.txt` in the same commits (the
gate's own rule: surface changes and manifest move together). Those edits
will be listed per commit, distinct from the pre-existing
`authority_mode.py` omission, which this lane leaves as found.

Nothing was deleted or edited for this audit. This document is the only
change on the branch. **Phase A halts here for ratification.**

---

## 0. Where the brief's map and the repo disagree

The brief's DELETE set was written against a stale layout. Three corrections,
each verified in source:

1. **`service.py` is not the daemon.** It is the client-plane mux: every
   function is `if hardened(): RPC to the daemon; else: run the same
   operation in-process`. The daemon proper is `authd.py`'s
   `AuthorityService` (Unix-socket server, accept loop, per-connection
   threads), started only by `ctx security serve` (cli.py:506) or
   `launchd/com.contextd.authd.plist`.
2. **The "residency half of authd" the brief names — `hardened()` /
   `is_service_process()` — is no longer in authd.** Lane T ruling R6 moved
   both predicates (plus `service_context` and the `_SERVICE_PROCESS`
   marker) into `contextd/authority_mode.py`, which is **CORE**, with
   fail-closed daemon-absent defaults designed in (its module docstring
   derives them site by site). `authd.py:180` merely re-exports. The
   residency actually remaining in authd is the socket server and its
   tier/dispatch machinery — a clean split, so the brief's "authd will not
   split cleanly" halt condition does **not** fire.
3. **A second residency exists outside the brief's DELETE set**:
   `ctx watch` (cli.py `cmd_watch`, a `while True: run_all(); sleep()` loop)
   plus `launchd/com.contextd.watch.plist` (`KeepAlive`). It is the
   operator's live capture path. Recorded in §4; not deleted by this lane.

## 1. Symbol audit — who calls what, and its class

Classes: **(a)** dead once the daemon is gone · **(b)** replaceable by an
event-time path that already exists · **(c)** genuine continuous-runtime
need · **KEEP** not residency, stays.

### `rpc.py` (172 lines — the transport)

| Symbol | Callers | Class |
|---|---|---|
| `MAX_FRAME`, `PROTOCOL_VERSION`, `TIER_MODEL/OPERATOR/TIERS` | authd (OPERATIONS registry, `_tier_for`), service, tests | (a) |
| `peer_credentials`, `send_frame`, `read_frame`, `_load_libc` | authd sessions, tests | (a) |
| `RpcClient` | service.py `_client`, test_process_isolation, test_encrypted_export | (a) |
| `ServiceUnavailable` | service.py, tests | (a) — meaningless without a transport |
| `RpcError` | **both modes**: `_Refusal` (authd) subclasses it; cli.py:132 and mcp_server.py:16 catch it around calls that in development mode never touch a socket | **(b)** — re-home verbatim to the surviving operation layer in authd.py; it is the client-visible refusal type, not transport |

### `authd.py` (1373 lines — splits into server half and operation half)

**DELETE (residency — the always-on process):**

| Symbol | Callers | Class |
|---|---|---|
| `AuthorityService` (start/_serve/stop/_session/_principal/_dispatch, challenge rate state) | `main()`, service-mode tests | (a) |
| `_tier_for`, `allowed_operations`, `OPERATIONS`, `ATTESTED_ACTIONS`, `Operation` | `_dispatch`, `op_capabilities` | (a) — tier is a socket-peer concept |
| `_preflight_attestation` | `_dispatch` only | (a) |
| `op_ping`, `op_capabilities` | RPC clients only | (a) |
| `_error` | `_dispatch`/`_session` only | (a) |
| `socket_path`, `SOCKET_NAME` | service `_client`, doctor.py:27,343, tests | (a) — doctor loses its socket fact (§3) |
| `main` | cli.py:506 `ctx security serve` | (a) |
| `inspect_deployment`, `_service_account_exists` | doctor.py only | (a) — reports daemon-deployment facts (socket, installed code, service account) |

**KEEP (event-time operation layer — runs per-invocation in both modes today;
`service.py`'s development arms call these directly and exit):**
the 22 remaining `op_*` handlers, `_granted_transition`, `_archive`,
`_needs_attestation`, `_int`, `_text`, `_backup_action_arguments`,
`_export_action_arguments` (also imported by cli.py:1162 for dev-mode
export), `_restore_action_arguments`, `_Refusal`, and the
`authority_mode` re-export block (cli.py:594 and ~20 test sites import
through it).

### `service.py` (375 lines — the client mux)

| Piece | Class |
|---|---|
| `_client`, `_call`, the `RpcClient`/`ServiceUnavailable` imports, and every `if hardened(): return _call(...)` arm | (a) — the RPC half of the mux |
| `ClientRefused`, `_direct`'s hardened refusal, and each function's development arm | **KEEP** — this is the direct, event-time dispatch the CLI and MCP server use; the hardened arm becomes an explicit fail-closed refusal (§2 hazard) |

### Callers to rewire in Phase B (no deletions, import/text changes only)
- `cli.py`: drop the `security serve` subcommand; `RpcError` import moves.
- `mcp_server.py`: `from .authd import hardened` → `authority_mode` (or
  `service`); `RpcError` import moves.
- `doctor.py`: loses `inspect_deployment`/`socket_path`; its
  `protected_daemon` check and socket fact describe a deployment that no
  longer exists (§3, posture change for ratification). `_service_signatures`
  **stays** — signing is core (below), only remedy strings mention the
  service.
- `launchd/com.contextd.authd.plist`: delete. All other plists are
  `StartInterval` short-lived hooks — KEEP (watch is `KeepAlive`, §4).

## 2. The runtime-state map — what imports cannot show

| # | State | Set by | Read by | With the daemon gone |
|---|---|---|---|---|
| 1 | `_SERVICE_PROCESS` thread-local (authority_mode, CORE) | authd `_dispatch` (DELETE); service.py dev arms; cli bootstrap ceremony (cli.py:611); tests | `db._guard_direct_access` (db.py:264); `attest._assert_bootstrap_boundary` (attest.py:340) | Defaults False = the refusing side of both branches, by Lane T's design. The hardened first-key ceremony (`ctx security key bootstrap`, run as the service account) still sets it — that is a short-lived process, not residency, and survives. |
| 2 | `authd.sock` / `[security] socket` config | daemon `start()` (unlinked on `stop()`) | service `_client`, doctor's socket fact | Nothing in CORE or KEEP dials it once the RPC arms are gone. A stale socket file is inert. |
| 3 | `[security] mode` config | the operator, never the daemon | `authority_mode.hardened()` (CORE) | A hardened-configured archive **refuses everything** except the out-of-band bootstrap ceremony: `db._guard_direct_access` fails closed. Stricter, and already the SECURITY.md-specified no-service behavior. |
| 4 | `CONTEXTD_HOME` / `home()` | environment, per process | every entry point independently | No daemon involvement. The §4 virgin-home amputation exercises exactly this. |
| 5 | SQLite runtime (`journal_mode=WAL`, `busy_timeout`) | `db.connect` per connection (db.py:385,420) | every connection | The daemon holds no long-lived connection: `_archive` opens and closes per request. No pragma, lock, or WAL state depends on daemon lifetime. |
| 6 | Service signatures on accepted events / chain tips | **CORE append path** — `prepare_append_signing` / `sign_accepted_append` inside `db.py` (963, 1072), keys under `home()/keys` | `ledger_sig.verify_*`, doctor `_service_signatures` | Unchanged. Any appending process signs; new events remain signed post-dissolution. Doctor remedy strings saying "run the authority service" get a text fix only. |
| 7 | Daemon in-memory rate state (`_challenge_times`, outstanding-challenge cap) | `op_prepare_action` in the daemon process | nobody else | Dies with the process. The durable part — `operator_nonces` — is DB state owned by `attest` (CORE). The development direct path already runs without this limiter today. |
| 8 | Pidfile / lockfile / heartbeat | — | — | None exist (`liveness.py` is explicitly daemon-unaware). |

**The one hazard found (fail-open, must be handled in Phase B):** the
development arms in `service.py` wrap their in-process calls in
`with service_context():` (e.g. service.py:86). Today the hardened arm
short-circuits first, so those wrappers never run under hardened config. If
Phase B deleted the hardened arms and nothing else, a hardened-configured
archive would fall through to the dev arm, the wrapper would mark the thread
as the authority plane, and `db._guard_direct_access` would **open the
archive** — fail-open. Mitigation, per the lane's fail-closed rule: each
mux's hardened arm is replaced by an explicit `ClientRefused` (documented
inline: residency removed, hardened archives refuse until the operator
changes posture), so the wrapper stays unreachable under hardened config.

## 3. Product-posture changes surfaced for ratification

- **Hardened mode becomes refuse-everything.** Its meaning — "only the
  authority plane opens the archive" — is preserved by refusal: with no
  authority plane, nothing opens the archive (except the bootstrap
  ceremony). The operator's live deployment is development mode (map:
  doctor --strict at 6/7 is a recorded, excluded gap), so nothing running
  changes behavior.
- **`ctx security doctor` loses the daemon-deployment checks**
  (`protected_daemon`, socket fact). They test for a component that will not
  exist.
- **Docs sweep** (Phase B): DEPLOYMENT.md, SECURITY.md, OVERVIEW.md,
  OPERATOR_CEREMONY.md, GRANTS-r2-proposal.md, README.md, COMPARISON.md all
  describe the daemon. New statement of architecture: library + event-time
  hooks + timers; residency removed. The "continuous ambient capture is no
  longer part of the design" sentence is **only true if the watch loop's
  fate is ratified** (§4); otherwise the docs must say "except the capture
  polling loop, which is scheduled residency awaiting the socket-activated
  watcher."
- **Tests:** `test_process_isolation.py` (34 tests) is the daemon's own
  suite → deleted with it, except the marker/ceremony semantics that pin
  CORE behavior (e.g. `test_fresh_hardened_first_key_ceremony_*`'s
  bootstrap-refusal half) — those move to an authority_mode/attest-scoped
  test. `test_encrypted_export.py` (21 tests): the ~4 that drive export
  over `RpcClient`/`AuthorityService` are rewritten to the direct path or
  deleted as RPC-specific; export coverage itself is direct-path already in
  the rest. `test_dev_bootstrap.py` touches only authority_mode — unaffected.
- **Boundary literal:** CORE is untouched. DAEMON drops `rpc` (file
  deleted) — `service` and `authd` survive as files (client dispatch +
  operation layer), so they stay classified DAEMON. Per the brief, this
  DAEMON-side diff is explained here in advance: it is the deletion itself,
  not a reclassification.

## 4. Residency verdict per candidate

- **`authd.py` server half, `rpc.py`, `service.py` RPC arms, `ctx security
  serve`, authd plist: (a)/(b) throughout. No type-(c) found.** The daemon's
  entire value is privilege separation — a *deployment posture* enforced by
  file ownership, not a computation that must run continuously. Every
  operation is request-scoped: open, act, close. Nothing keeps state between
  requests that anything else reads (§2).
- **`ctx watch` + `com.contextd.watch.plist`: residency, outside this
  lane's DELETE set, in live use by the operator.** It is a `KeepAlive`
  polling wrapper around the same `run_all()` scan that `ctx ingest` runs
  once and exits — class (b): replaceable today by a `StartInterval` plist
  invoking `ctx ingest` (the pattern every other hook plist already uses),
  or later by the ~100-line socket-activated watcher (not this lane's to
  build). **Decision deferred to the operator**: default is untouched, since
  deleting capture the operator uses is an explicit stop condition.
- **`mcp_server.py`: not residency.** Its process lifetime is owned by the
  MCP client session that spawns it; it is idle-waiting on its client, not
  always-on for the archive.
- **hooks/ + StartInterval plists (`reconcile`, `health`, `backup`,
  `lineage-audit`, `restore-drill`) and `ingest`: KEEP** — short-lived,
  event-time, exactly the brief's KEEP set.

## 5. Byte-safety statement

No residency symbol produces a serialized byte. Canonical encodings, chain
hashes, and signatures are produced in CORE (`canonical`, `db`, `ledger_sig`,
`attest`); the daemon orchestrates and validates, then calls them. The three
signed-action argument builders (`_backup/_export/_restore_action_arguments`)
feed canonical signing and are KEEP — if any Phase B commit relocates them it
must move them verbatim. Historical bytes are not touched by any planned cut.

## 6. Proposed Phase B commit sequence (suite green at each)

1. `service.py`: hardened arms → explicit `ClientRefused` fail-closed
   refusal (documented inline, §2 hazard); drop `_client`/`_call`/rpc
   imports; re-home `RpcError` to authd.py; rewire cli/mcp imports.
2. `authd.py`: delete the server half (§1 DELETE table) + `ctx security
   serve` + `launchd/com.contextd.authd.plist`; doctor loses
   `inspect_deployment`/socket fact; remedy-string text fixes.
3. Delete `rpc.py`; `test_process_isolation.py` surgery (preserve the
   core-semantics pins); `test_encrypted_export.py` RPC-test rework;
   boundary DAEMON literal drops `rpc`.
4. Docs sweep (§3) + naming note: the `d` in `contextd` is now a fossil —
   recorded, nothing renamed (extraction-scope, operator's call).

Then the §4 real-amputation gate from the brief, on a virgin home, verbatim.

## Verdict

**The DELETE set is fully removable.** No genuine continuous-runtime need
exists in the authority daemon. One fail-open hazard is named with its
fail-closed mitigation (§2). One residency remains outside scope (`ctx
watch`, §4) awaiting an explicit operator decision. Ratification of Phase B —
including the doctor/hardened posture changes in §3 and the watch-loop
decision in §4 — is the operator's; this lane is halted until then.
