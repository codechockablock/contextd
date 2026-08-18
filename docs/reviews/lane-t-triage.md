# Lane T — boundary severance, Phase A triage

Read-only triage of every core→daemon import edge, with a verdict per site.
**Phase A ends here.** Nothing in `contextd/` was modified. The lane is blocked
on operator ratification, and the headline finding is that it is blocked much
harder than the brief anticipated — see [What is pre-authorized](#what-is-pre-authorized).

## Tree state this was measured against

| | |
|---|---|
| Worktree | `~/contextd-lane-t` (separate `git worktree`, see [Concurrency](#concurrency-with-lane-nv)) |
| Branch | `lane-t-severance` |
| Base | `9b8d678` — master tip at lane open |
| `git status --porcelain` | clean (empty) |
| Baseline suite | **877 passed, 35 skipped, exit 0**, 36.9s |
| Baseline `ruff check contextd/` | clean |
| `examples/gate_proof/concurrent_redemption.py` | passes; 20/20 in the repeat loop |

The 35 skips are the Postgres backend tests (no `--postgres-url`). No Node-22
FORMAT failures appeared: this worktree is at master tip and carries none of
Lane NV's in-flight edits, which is the whole reason the baseline is quotable.

## Concurrency with Lane NV

Lane NV holds `~/contextd` checked out on `lane-nv-verifier-pqc` with an
uncommitted edit to `scripts/verify_format_independent.mjs`. Switching that
checkout to a new branch would have pulled `HEAD` out from under a live session,
so this lane took a **separate git worktree** instead — same repository, same
`lane-t-severance` branch off master, its own directory and its own `HEAD`.
`~/contextd` was left untouched and still reads `lane-nv-verifier-pqc` with its
one dirty file. Worktrees are established practice in this repo (`ctx-a`/`ctx-b`/
`ctx-c`, retired by the 2026-08-15 flaw sweep).

File overlap with NV was verified, not assumed. `git diff master...lane-nv-verifier-pqc`
touches only `docs/operating-map.md` and 13 files under `scripts/vendor/`. Lane T's
diff is `tests/test_core_boundary.py` and this file. **Zero overlap.** Lane Q
(`attest.py`, `ledger_sig.py`) is not live — it closed with gate-v1.1, merged at
`ce27e55`.

One hazard for Phase B, recorded now: `~/contextd/.venv` holds the editable
install bound to `~/contextd`. Running `pip install -e .` from this worktree or
from the amputation rehearsal's tmpdir into that venv would rebind it and break
NV's `pytest`. The rehearsal must build its own throwaway venv. Test runs here
are already safe — `pythonpath = ["."]` puts the worktree first on `sys.path`,
and `tests/conftest.py` forces `CONTEXTD_HOME` to a temp directory, so the live
archive is never opened.

## AST re-measure vs the brief's §2 regex table

The AST checker (`tests/test_core_boundary.py`) parses every module under
`contextd/`, resolves relative and absolute in-package imports, and classifies
each edge as top-level / function-local / `TYPE_CHECKING` / dynamic.

**Delta: immaterial. The boundary's shape is exactly as briefed.**

| | §2 (regex) | AST | verdict |
|---|---|---|---|
| Daemon modules in core closure | 13 | **13** — identical set | no delta |
| Core modules with daemon edges | 9 | **9** — identical set | no delta |
| Per-module target sets | as tabled | **identical** | no delta |
| Direct edges | 21 | **24** | +3, not material |

The +3 is duplicate call sites inside edges §2 already names: `attest → redact`
is three separate `from .redact import sanitize_content` statements
(`attest.py:471`, `:499`, `:539`), which a regex collapses to one. No new source
module, no new target module, no new dependency.

Two small corrections to §2's prose:

- §2 places `loops` among the modules reached transitively via `authd`. It is
  reached **directly**, at `grants.py:42`. The genuinely transitive-only set is
  `decisions`, `ingest`, `rpc`.
- §2 anticipates the AST pass finding aliased, lazy, or `TYPE_CHECKING` imports
  the regex missed. It found none, because there are none: `contextd/` contains
  **zero** `TYPE_CHECKING` blocks and **zero** `importlib`/`__import__` call
  sites, package-wide. Every edge in the graph is a plain `import`. The boundary
  test still checks all four forms — that clause guards future drift, and it is
  honest to say it currently guards nothing.

Because the edge set is not materially different, the §7 stop condition
("report before cutting") is satisfied by this report rather than triggered by it.

## The triage table

24 sites. "What it does" is from reading the call, not from the module's name.

### attest.py

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `attest.py:48` top-level | `INSECURE_TEST_SIGNER`, `OPERATOR_AUTHORIZED`, `Attestation` | The assurance-level constants and the `Attestation` record that gets stamped onto events. `OPERATOR_AUTHORIZED` is the single level that grounds an authenticated-human claim. | **RECLASSIFY** `assurance` |
| `attest.py:340` fn-local | `authd.is_service_process` | First-key bootstrap boundary: refuse unless this process is the authority service. | **MOVE** |
| `attest.py:385` fn-local | `authd.hardened` | Refuse `--development` bootstrap when the archive is configured hardened. | **MOVE** |
| `attest.py:471` fn-local | `redact.sanitize_content` | `_normalized_content` — "the exact post-boundary text whose bytes are stored **and signed**". | **RECLASSIFY** `redact` — bit-critical |
| `attest.py:499` fn-local | `redact.sanitize_content` | `canonical_scope` — redacts the scope string before it enters the signed action, so an unredacted scope cannot walk past the closed schema. | **RECLASSIFY** `redact` — bit-critical |
| `attest.py:539` fn-local | `redact.sanitize_content` | `_normalize_arguments` — refuses any argument redaction would rewrite, before signing. | **RECLASSIFY** `redact` — bit-critical |

### db.py

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `db.py:21` top-level | `redact`, `sanitize_content`, `sanitize_label` | Sanitizers on the append path — every event's stored content and label pass through them. | **RECLASSIFY** `redact` — bit-critical |
| `db.py:264` fn-local | `authd.hardened`, `is_service_process` | The direct-access refusal: under hardened mode a client-plane process may not open the archive directly. | **MOVE** |
| `db.py:448` fn-local | `scratch.ScratchCleanupError`, `reap_stale` | Startup recovery: remove scratch directories a killed process left behind. Warns on stderr, never raises, never touches events. | **HOOK** (moot if `scratch` is reclassified) |

### export.py

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `export.py:35` top-level | `backup._atomic_private_write`, `create_backup` | `create_backup` produces the bundle — including its service-signed manifest — that the sealed export then encrypts. These *are* the sealed-export bytes. | **RECLASSIFY** `backup` — bit-critical |
| `export.py:37` top-level | `scratch.scratch_dir` | The 0700 workspace the plaintext bundle lives in before sealing. | **RECLASSIFY** `scratch` (alt: MOVE `scratch_dir`) |

### gate.py

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `gate.py:9` top-level | `domains.blocked`, `load_skip_domains` | Skip-domain blocklist on the egress path: refuses to disclose a URI the operator excluded. | **RECLASSIFY** `domains` — HOOK is unsafe here |
| `gate.py:10` top-level | `redact.redact` | Redacts the disclosed payload and its headers. What survives is what gets logged as the egress event's content. | **RECLASSIFY** `redact` — bit-critical |
| `gate.py:11` top-level | `search.search` | `assemble` gathers candidate events for a disclosure. | **MEMBERSHIP QUESTION** — see below |

### grants.py

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `grants.py:34` top-level | `MODEL_GRANTED`, `assurance_for_event`, `refuse_forged_authority` | The delegated-authority level, per-event assurance resolution, and the guard that refuses `authority="operator"` as a caller-supplied string. | **RECLASSIFY** `assurance` |
| `grants.py:42` top-level | `loops.scope_str` | A four-line pure formatter (`{"repo": p}` → `"repo:p"`), used at 8 sites — including `canonical = scope_str(scope)`, which lands in signed grant events. | **MOVE** |

### migrate.py

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `migrate.py:228` fn-local | `redact.sanitize_content` | Sanitizes legacy cursor sources and values as migration rewrites them. | **RECLASSIFY** `redact` — bit-critical |
| `migrate.py:466` fn-local | `assurance.assurance_of` | `legacy_label_report` — read-only tally of what each historical authority label now resolves to. Writes nothing. | **RECLASSIFY** `assurance` |

### pinning.py

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `pinning.py:97` top-level | `assurance.assurance_for_event` | Assurance resolution for a pin act. | **RECLASSIFY** `assurance` |
| `pinning.py:206` fn-local | `redact.sanitize_text` | Refuses an artifact name that redaction would rewrite — "a pin whose subject was silently renamed pins nothing". | **RECLASSIFY** `redact` |

### provenance.py

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `provenance.py:44` top-level | `experiment.epistemic_type` | A **pure classifier**: `(source, kind, meta, verified_assurance) → one of five epistemic levels`. No I/O, no daemon state, no other daemon calls in its body. | **MOVE** |
| `provenance.py:45` top-level | `assurance.known_event_assurance` | Per-event assurance for each node of the provenance report. | **RECLASSIFY** `assurance` |

### schemas.py

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `schemas.py:31` top-level | `correlate.keyed_id` | Derives the stable HMAC correlation id **stored in the event** for any field declared `stored_as`. | **RECLASSIFY** `correlate` — bit-critical |
| `schemas.py:32` top-level | `MAX_LABEL`, `MAX_TEXT`, `SanitizationError`, `sanitize_content`, `sanitize_label`, `sanitize_text` | The field bounds and sanitizers applied at the storage boundary — i.e. the validation layer's definition of what a stored field may contain. | **RECLASSIFY** `redact` — bit-critical |

### One daemon-side edge that must become a hook

Not a core→daemon edge, but the reason `decisions` is in the closure at all:

| Site | Names | What the call actually does | Verdict |
|---|---|---|---|
| `assurance.py:315`, `:319` fn-local | `loops.stored_loop_assurance`, `decisions.stored_decision_assurance` | `known_event_assurance` dispatches on `(source, kind)`; `loop` and `decision` are two registered types. A **read** path used by provenance and experiment displays. Falls through to `assurance_of(meta)` for unregistered types. | **HOOK** — a per-`(source, kind)` resolver registry; unregistered types already have a defined fallback |

### Verdict tally

| Verdict | Sites | Modules |
|---|---|---|
| RECLASSIFY | 18 | `assurance` (5), `redact` (8), `scratch` (2), `backup` (1), `domains` (1), `correlate` (1) |
| MOVE | 5 | `authd` predicates (3), `loops.scope_str` (1), `experiment.epistemic_type` (1) |
| Membership question | 1 | `search` (1) |
| HOOK | 1 | `assurance`'s resolver dispatch (daemon-side) |
| INLINE | **0** | — |

## The bit-stability constraint (§5) is what drives most of this

The brief expects HOOK to absorb the bulk of the boundary. It cannot, because
most of these calls sit **inside the bytes**. A hook whose default is a no-op is
only safe where "nothing registered" means "nothing changes"; at these sites it
would mean different stored bytes:

- **Signature coverage.** `attest._digest` documents the invariant directly:
  digesting pre-redaction text "would make the signature cover something the
  archive never holds". Redaction is on the signer's side of the signature by
  design. A no-op redactor changes what every `OperatorActionV1` covers.
- **Append path.** `db.py:21` sanitizes every event's content and label as it is
  written; `schemas.py:32` supplies the bounds that decide what a stored field
  may contain at all.
- **Egress events.** `gate.disclose` logs the redacted payload back into the
  archive. Redaction defines the egress event's content.
- **Migration.** `migrate.py:228` sanitizes cursor values it rewrites.
- **Stored correlation ids.** `correlate.keyed_id` derives the value `schemas`
  stores for any `stored_as` field.
- **Sealed exports.** `backup.create_backup` writes the bundle and its
  service-signed manifest; `export` encrypts exactly those bytes.

So these are RECLASSIFY, per §5's own instruction ("if any cut would alter what
gets written… that is a RECLASSIFY or a halt"). `redact` is precisely the case
§5 predicts: product functionality wearing a daemon name.

`domains` fails the hook test for a second, separate reason. A no-op default
does not merely change bytes — it **weakens a privacy control**: with nothing
registered, `blocked()` returns false and skip-domains stop being skipped. A
hook default must fail safe, and here the safe default is not "unregistered".

## Membership findings

**`redact` — RECLASSIFY, and the evidence is unambiguous.** 181 lines, and it
imports *nothing*: not one in-package import, not one third-party import. It
drags nothing into the core. It appears at 8 of the 24 sites, and at 6 of them
it decides stored or signed bytes.

**`assurance` — RECLASSIFY.** The typed provenance vocabulary: the assurance
levels stamped onto events and the rule that exactly one of them grounds a human
claim. Its module-level imports are `dataclasses` and nothing else. Its only
daemon reach is the two function-local calls in `known_event_assurance`, which
the HOOK verdict above covers. It accounts for 5 sites and is the sole reason
`decisions` is in the closure.

**`authd` — the split is far smaller than the brief anticipates.** §4 expects the
operator-signature verification half to move into core. That half is *already*
core: `attest.py` holds `prepare_action`, `verify_action`, `_verify_action`,
`verify_stored_authorization`, `redeem`, `consume_authorization`,
`sign_with_secure_enclave` — the entire `OperatorActionV1` surface. What core
actually reaches into `authd` for is two predicates totalling about six lines:

```python
def hardened() -> bool:
    return ((load_config().get("security") or {}).get("mode") or
            "development") == "hardened"

def is_service_process() -> bool:
    return getattr(_SERVICE_PROCESS, "value", False)
```

`hardened()` is a config read. `is_service_process()` reads a `threading.local`
marker that `authd` sets when the service is running. Both are authority-plane
concepts and both are core-shaped. Proposal: a small `contextd/authority_mode.py`
holding both plus the `threading.local`, with `authd` importing them and setting
the marker as it does today. No `operator_sig.py` is needed — that module would
be empty. Severing these three edges removes `authd`, `ingest`, and `rpc` from
the closure in one stroke, exactly as §4 predicts, just for a much smaller cut.

**`backup` — RECLASSIFY, with a caveat worth the operator's attention.** Its
imports are core-only (`backends`, `backends.transfer`, `canonical`, `db`,
`ledger_sig`), so it drags nothing. Its surface is the bundle *format*: manifest
construction and signing, the manifest trust store, bundle validation and
identity. That is product, not daemon. The caveat is size — 2020 lines — and one
function, `prune_bundles` (retention), that reads operational rather than
format-shaped. Moving only `create_backup` and `_atomic_private_write` instead
would split the bundle writer from the manifest signing that makes the bundle
trustworthy, which is worse. Recommend reclassifying the module and revisiting
`prune_bundles` separately.

**`scratch`, `correlate`, `domains` — RECLASSIFY, all small and all leaves.**
146 / 93 / 54 lines; imports are stdlib plus `contextd.home` (`domains`: stdlib
only). For `scratch`, splitting `scratch_dir` into core while `reap_stale` stays
daemon would put two creators on one scratch root and let the daemon's reaper
delete directories the core is actively using. Keep them together.

**`search` — genuinely open, and the only site where either answer works.**
`search.py` is 98 lines importing only `backends` (core), so admitting it costs
nothing structurally. The question is whether recall belongs to the product
surface. Both paths verify clean:
- **RECLASSIFY** if Terminus includes recall — `gate.assemble` keeps working
  untouched.
- **HOOK** if it does not — core defines a retrieval-provider registration point,
  the daemon registers `search.search` at its own import time, and daemon
  behaviour is bit-identical because the provider is always registered. Core
  alone would assemble nothing, which is coherent for a gate with no archive
  behind it. Unlike `domains`, an unregistered default here fails *safe*: it
  discloses less, not more.

This is a product call, not the session's. It is the one verdict Phase B cannot
proceed without.

**`lineage` — propose INTO the core list, per §1.** Its imports are exactly one
module: `provenance` (core). Zero daemon dependencies. It satisfies the §1
condition for admission. Note honestly that admitting it does **not** shrink the
closure — nothing in core imports `lineage`, so this widens the product surface
rather than closing a leak. It is a pure product judgement about whether recall
semantics ("every act a compromised skill touched") ship with Terminus.

## Does the proposed verdict set actually close the boundary?

Computed, not argued — the closure was recomputed under each hypothesis:

| Scenario | Daemon modules left in the closure |
|---|---|
| As-is today | assurance, authd, backup, correlate, decisions, domains, experiment, ingest, loops, redact, rpc, scratch, search |
| MOVEs only (authd predicates, `scope_str`, `epistemic_type`) | assurance, backup, correlate, decisions, domains, loops, redact, scratch, search |
| MOVEs + HOOK the assurance dispatch + RECLASSIFY the six | **search** |
| …and `search` reclassified core | **none — clean** |
| …or `search` hooked instead | **none — clean** |
| …and `lineage` admitted | **none — clean** |

## What is pre-authorized

**Almost nothing, and this is the finding the brief most needs to hear.**

§4 pre-authorizes INLINE and HOOK and holds MOVE and RECLASSIFY for
ratification, on the reasonable expectation that INLINE and HOOK would be the
bulk of the work. The measurement inverts that: **0 INLINE verdicts, 1 HOOK, and
23 of 24 sites needing ratification.** The boundary is not the core reaching
into the daemon for conveniences it could inline. It is six modules sitting on
the wrong side of a line that was drawn before them — and three of the six decide
bytes that are signed.

The single pre-authorized HOOK (`assurance`'s resolver dispatch) is not worth
executing alone: it only removes `decisions`, and it lives inside a module whose
own reclassification is unratified.

**Therefore Phase A's halt is the whole of Phase A.** No cut has been made.

## Ratification requested

1. **RECLASSIFY six modules into core**: `redact`, `assurance`, `correlate`,
   `domains`, `scratch`, `backup`. Strongest evidence for the first three; each
   decides stored or signed bytes.
2. **`search`** — reclassify into core, or hook it? Phase B is blocked on this.
3. **`lineage`** — admit to core? Proposed per §1; does not affect the closure.
4. **Release the MOVEs**: `authd.hardened` + `is_service_process` →
   `contextd/authority_mode.py`; `loops.scope_str` → core; `experiment.epistemic_type`
   → core.

Worth noting how cheap (1) is: **RECLASSIFY requires no code change at all.** It
edits the `CORE` literal in `tests/test_core_boundary.py` and moves nothing.
Zero risk to any serialized byte, by construction. All the code motion in this
lane lives in the four MOVEs, and those total roughly twenty lines.

## Proposed Phase B order (blast radius ascending)

Not started. Listed so ratification can approve or reorder it.

1. `loops.scope_str` → core. One edge, four pure lines.
2. `experiment.epistemic_type` → core. One edge, pure classifier.
3. `authd.hardened` + `is_service_process` → `contextd/authority_mode.py`. Three
   edges; removes `authd`, `ingest`, `rpc` at once — the largest single win.
4. HOOK the `assurance` resolver dispatch. Removes `decisions`.
5. RECLASSIFY the six (and `search`, per the ruling): edit the `CORE` literal.
6. Amputation rehearsal in a throwaway venv, then `git diff master --stat`.

Suite green at every commit, with `test_core_never_reaches_the_daemon` the one
known red until step 5 closes it.

## The honest paragraph

Two verdicts I would second-guess. **`backup`** is the weakest: 2020 lines is a
lot to admit on the strength of "its imports are already core-only", and I judged
it core from its function surface rather than from reading all of it — a reviewer
who knows what `prune_bundles` and the restore path are *for* operationally may
reasonably split it instead. **`search`** I deliberately refuse to decide;
I can show both directions verify clean, but which one is right depends on what
Terminus is for, which is not a fact in this repository. I am confident about
`redact` — the signature-coverage docstring in `attest._digest` settles it, and a
181-line module with no imports at all is not a daemon dependency by any reading.

What the boundary test cannot see: it is a static import checker, so it says
nothing about runtime coupling that does not travel through an import — shared
`CONTEXTD_HOME` state, the SQLite schema itself (core reading tables only daemon
code ever writes), config keys under `[ingest]`/`[browser]`/`[claude]` that core
would carry as dead defaults, or the `threading.local` marker in the `authd`
MOVE, which is import-clean but is still a value the daemon must set for the core
to behave correctly. It also cannot see whether a moved function *behaves*
identically — only that the edge is gone. And it proves nothing about bytes: only
the amputation rehearsal plus the frozen FORMAT vectors do that, and neither has
run against a severed tree yet, because no severance has happened.
