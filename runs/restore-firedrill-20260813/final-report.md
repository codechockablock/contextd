# Restore fire-drill — mission report (2026-08-13)

Mission: convert "backups exist" into "backups restore, verified weekly, and
the alarm itself is tested." Three layers: a recurring fire-drill hook with a
full verification battery and a ledger-derived status alarm; a multi-GB scale
trial that hunts cliffs before reality does; an expanded adversarial bundle
corpus where every hostile shape is refused loudly and distinctly. Zero model
calls, stdlib only, kernel-or-hook, no new authority. Branch:
`restore-firedrill` off master at `36ce893` (post
`instruments-liveness-tally`); baseline verified in-session at **154 passed**
before any change.

## What shipped

- **Fire-drill hook** (`hooks/restore_drill.py`): locates the newest
  `.ctxbackup`, preflights temp free space against a measured safety
  multiple, restores into a throwaway temp destination, then runs the
  battery — chain + witness on the restored copy, event count and tip vs the
  manifest's recorded snapshot, every manifest blob re-hashed, FTS probe
  equivalence, and behavioral equivalence (search / timeline / loop
  reduction / liveness / audit, byte-compared between the bundle's snapshot
  DB and the restored copy). Verdict appended to the live archive as a
  content-NULL `eval/restore_drill` event carrying bundle path, manifest
  hash, per-stage timings, peak temp bytes, and on FAIL the stage and
  reason. Temp destinations are deleted on every path, including failure
  (pinned by test). The hook calls no models and opens no sockets.
- **Status alarm** (`contextd/cli.py`, status only): `restore drill: PASS
  3.1d ago` derived from the last receipt; `WARNING:` when the last drill
  FAILED (with stage and reason) or when a drill has run before but none
  within `[backup].drill_stale_after_hours` (default 192,
  `contextd/__init__.py`). An archive that has never drilled prints
  `restore drill: never run` without warning — the drill is installed per
  machine, and warning every never-opted-in archive would train operators
  to ignore the line; staleness monitoring begins with the first receipt.
- **Schedule**: `launchd/com.contextd.restore-drill.plist`, weekly, Monday
  11:00 — two hours after the Monday 09:00 backup job, so the freshest
  bundle gets drilled the same morning.
- **Scale instrumentation** (`experiments/restore_scale/`): deterministic
  seeded inflator (real chain hashes via the kernel's `_chain_hash`, real
  FTS via the real triggers, content-addressed blobs, witness) and a trial
  driver measuring wall time per stage, sampled peak temp space, and child
  peak RSS via `os.wait4`. Results persisted in `results.json`; the
  subprocess use is classified in the model-egress inventory.
- **Adversarial corpus** (`tests/test_adversarial_bundles.py`): nine new
  hostile-bundle rows, each refused with a distinct reason, nonzero through
  the CLI, destination untouched, staging never leaked, plus a
  pairwise-distinctness meta-test. `contextd/backup.py`'s version refusal
  now names the found format/version vs the supported one, so a
  from-the-future bundle is identifiably "too new", never half-read.

## The alarm is tested

Verbatim fixture cycle (event metas from the live fixture ledger, via
`hooks/restore_drill.py --once --json`):

PASS receipt:

```json
{"bundle": ".../gate-fixture-home/backups/contextd-20260813-181515.ctxbackup", "bundle_bytes": 55944, "event_id": 7, "manifest_sha256": "89643c8651376e7b57b995783a5f8efb1fc78f44da3cbc81faf8163532bfb0f0", "peak_temp_bytes": 55084, "probes": 7, "stages": {"behavioral": 0.0, "blobs": 0.0, "chain_witness": 0.0, "fts_probe": 0.001, "locate": 0.001, "preflight": 0.0, "restore": 0.003, "snapshot_state": 0.0}, "total_seconds": 0.006, "verdict": "PASS"}
```

One flipped blob byte later (exit 2):

```json
{"bundle": ".../contextd-20260813-181515.ctxbackup", "bundle_bytes": 55944, "event_id": 8, "failed_stage": "restore", "manifest_sha256": "89643c8651376e7b57b995783a5f8efb1fc78f44da3cbc81faf8163532bfb0f0", "peak_temp_bytes": 0, "reason": "payload hash or size mismatch: store/72/72c39a6677e226b65b46f65a25c750adf2dd12cee8fc9dc172b2ccd6914fb95a", "stages": {"locate": 0.0, "preflight": 0.0, "restore": 0.001}, "total_seconds": 0.001, "verdict": "FAIL"}
```

```text
restore drill: FAIL 0.0h ago
WARNING: restore drill FAILED 0.0h ago at stage restore (payload hash or size
mismatch: store/72/72c39a…) — backups may not restore
```

Clean re-backup, drill again: `"verdict": "PASS"` (event #9), and status
returns to `restore drill: PASS 0.0h ago` with no warning. The same cycle —
plus truncated-DB, sabotaged-chain (caught at `chain_witness`), sabotaged
FTS shadow (caught at `fts_probe`), preflight refusal with required-vs-
available numbers, and the stale-drill warning — runs in
`tests/test_restore_drill.py` and in smoke §45 on every gate run. Drill
receipts are proven content-NULL, absent from the FTS index (docsize
shadow), and unreachable by search and recall (pinned by test).

## Scale trial: the 6-cell table

All cells run in-session on this machine (M-series, 10 cores, 24 GiB RAM,
APFS on NVMe), fixed drill code, seeded inflator. `trial.py report`:

```text
cell              archive   bundle   backup    drill  restore  peak tmp  ratio  drill RSS verdict
1g:event_heavy      1.04G    1.04G     14.2     17.4    11.18     1.04G    1.0        38M PASS
1g:blob_heavy       0.94G    0.94G      1.7      1.7    1.283     0.94G    1.0        34M PASS
4g:event_heavy      4.02G    4.02G     81.6    112.0   44.789     4.02G    1.0        34M PASS
4g:blob_heavy       3.94G    3.94G      8.1      8.6    6.693     3.94G    1.0        34M PASS
8g:event_heavy      8.02G    8.02G    574.6    675.3  368.297     8.02G    1.0        29M PASS
8g:blob_heavy       7.94G    7.94G     17.0     18.6   14.676     7.94G    1.0        34M PASS
```

Event-heavy cells: 400k / 1.56M / 3.12M events. Per-stage seconds live in
`experiments/restore_scale/results.json`.

**Preflight safety multiple:** measured peak temp space during
restore + battery was exactly **1.00×** the bundle size in all six cells
(the restore stage directory is renamed into place, never double-copied),
and backup's destination peak was likewise 1.00× the final bundle.
`DRILL_TEMP_MULTIPLE` is pinned at **1.5** (ceil of the measurement + 50%
margin), and the preflight refusal prints required vs available bytes
(pinned by test).

**Scaling curves.** Blob-heavy is linear in every stage (drill 1.7 / 8.6 /
18.6 s across 1 / 4 / 8 GiB; RSS flat ~34 MB). Event-heavy is linear from
1 → 4 GiB in every stage (restore 11.2 → 44.8 s for 3.9× events), then
super-linear from 4 → 8 GiB (restore 44.8 → 368 s, chain_witness 19.2 →
147 s for 2× data). Isolated hot-cache profiling of the primitives
(integrity_check, chain recompute, sha256, FTS query, blob scan) at 0.5 and
2 GiB showed each ~linear, so the 8 GiB inflation is attributed —
**as hypothesis, not proven root cause** — to the working set (two full
copies of an 8.6 GB archive read across ~6 validation passes) outgrowing
page-cache residency on a 24 GiB machine, raising per-pass I/O cost rather
than any stage's algorithmic complexity. Practical boundary, stated plainly:
on this class of machine a weekly drill costs ~18 s at 1 GiB, ~2 min at
4 GiB, ~11 min at 8 GiB event-heavy; blob-heavy stays under 20 s throughout.

## Defects found: fixed vs stopped

Fixed, each with a regression test:

1. **Retention/ordering defect in `contextd/backup.py` (kernel).**
   `_new_bundle_path` reused a bare-stamp name freed by pruning, so
   `(stamp, sequence)` ordering — which retention's `creation_key` and the
   drill's newest-bundle pick both rely on — could disagree with creation
   order within one second: retention could prune the *newest* bundle and
   keep stale ones, and the drill could restore a stale bundle while
   reporting PASS. Found because the new smoke alarm cycle flaked
   (StopIteration on the missing blob of a stale "newest" bundle) — the
   alarm caught its first real bug before the branch even merged. Fix:
   sequence numbers within a stamp only rise, freed names are never
   reallocated (`tests/test_backup_restore.py::
   test_same_second_sequence_never_reuses_a_pruned_name`). No bundle format
   or restore semantics change.
2. **O(archive) memory in the drill's probe derivation (hook).** The first
   draft fetched every content row to derive probes: 809 MB RSS at 1 GiB,
   2.9 GB at 4 GiB event-heavy (old-code cells, preserved receipts), ~7 GB
   extrapolated at 8 GiB. Rewritten to id-spaced O(1) sampling; measured
   RSS is now flat 29–40 MB through 8 GiB
   (`tests/test_restore_drill.py::
   test_derived_probes_stay_memory_bounded_and_deduplicated`, tracemalloc).
3. **Degenerate duplicate probes (hook).** The same draft derived eight
   copies of one whole-corpus probe, multiplying `search()`'s snippet cost
   over every match (fts_probe 169.8 s at 4 GiB old code → 13.9 s fixed).
   Probes are now offset-varied and deduplicated (same regression test).

Stopped design questions (reported, not decided):

- **Multi-pass validation cost at scale.** Backup + drill together hash and
  chain-verify the archive ~6 times (create, bundle-validate, restore-
  validate, staged re-verify, battery). Each pass is intended
  defense-in-depth per `backup.py`'s contract; collapsing passes or tuning
  SQLite cache/mmap for validation connections would trade verified-bytes
  guarantees or add speculative knobs, and at 8 GiB the cost interacts with
  machine RAM. Left as measured curve + operator decision.
- **`search()` snippet cost over huge match sets** (`contextd/search.py`,
  outside this mission's allowed diff): snippet() is computed for every
  row feeding the bm25 sorter, so a probe matching the whole corpus pays
  O(matches × snippet). The drill now avoids degenerate probes; the kernel
  characteristic remains and is only noted.

## Adversarial corpus (case → refusal)

| case | refusal reason (fragment) |
|---|---|
| truncated blob, manifest laundered | `blob content digest mismatch` |
| truncated DB payload | `invalid SQLite snapshot` |
| zero-byte DB | `FTS index check failed` |
| manifest version 0 (skew, past) | `…version=0 (this contextd reads contextd-backup v1)` |
| manifest version 99 (future) | `…version=99 (this contextd reads contextd-backup v1)` |
| duplicate manifest entries | `duplicate manifest path` |
| manifest lists absent file | `bundle is missing files: store/aa/…` |
| smuggled unlisted file | `bundle has unexpected files: smuggled.bin` |
| symlinked blob directory | `bundle contains a symlink` |

Every case: `restore_backup` raises, the CLI exits nonzero without a
traceback, the destination does not exist afterward, no staging directory
leaks, and no publish rename happens. Reasons proven pairwise distinct by
test. No existing refusal was weakened.

## Cross-machine rehearsal

Tier-1 (1 GiB blob-heavy) bundle, drill run with a different `HOME`, and
spaces in every operative path (`bundle shelf with spaces`,
`re store temp`, `live archive with spaces`, `other machine home`):
**PASS**, full battery. No absolute-path leakage surfaced, so no path fix
was needed; the rehearsal is re-runnable via `trial.py rehearse`.

## Gates (verbatim tails, all run in-session at completion)

```text
=== ruff check . ===
All checks passed!
=== pytest -q (tail) ===
..................................                                       [100%]
178 passed in 2.91s
=== smoke (tail) ===
ALL SMOKE TESTS PASSED
=== network grep ===
contextd/domains.py:12:from urllib.parse import urlsplit
contextd/gate.py:30:    if uri.startswith(("http://", "https://")) and blocked(load_skip_domains(cfg), uri):
contextd/ingest.py:14:from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
=== drill --once (fixture) ===
restore drill PASS: …/gate-fixture-home/backups/contextd-20260813-181515.ctxbackup (55944 bytes) restored and verified in 0.007s (event #6)
exit=0
```

`trial.py report` output is quoted in full above (6/6 PASS, findings:
none under the fixed code). Smoke re-run 6× consecutively after the
retention fix: 6× `ALL SMOKE TESTS PASSED` (it was this loop that exposed
defect 1). Baseline before any change: `154 passed`.

## Diff

```text
 README.md                                |  17 ++
 contextd/__init__.py                     |  10 +
 contextd/backup.py                       |  30 ++-
 contextd/cli.py                          |  27 ++-
 docs/operating-map.md                    |  14 +-
 experiments/restore_scale/inflate.py     | 156 ++++++++++++++
 experiments/restore_scale/results.json   | 225 +++++++++++++++++++++
 experiments/restore_scale/trial.py       | 293 +++++++++++++++++++++++++++
 hooks/restore_drill.py                   | 335 +++++++++++++++++++++++++++++++
 launchd/com.contextd.restore-drill.plist |  27 +++
 tests/smoke.py                           |  61 ++++++
 tests/test_adversarial_bundles.py        | 178 ++++++++++++++++
 tests/test_backup_restore.py             |  24 +++
 tests/test_model_egress_inventory.py     |   3 ++
 tests/test_restore_drill.py              | 295 +++++++++++++++++++++++++++
 15 files changed, 1681 insertions(+), 14 deletions(-)
```

## The honest boundary — what the drill does NOT prove

- **Media failure and offsite integrity.** The drill restores from the same
  disk the archive lives on. It proves the bundle's bytes restore and
  behave; it says nothing about that disk dying, bit rot on a copy that
  lives elsewhere, or whether any offsite copy exists at all.
- **The live archive's own health.** The drill verifies the newest bundle,
  not the running database; `ctx verify` covers the live chain, and a
  corrupted live archive would produce corrupted *future* bundles the drill
  would only reject if validation catches the corruption class.
- **Point-in-time loss.** A weekly PASS bounds restore *capability*, not
  data loss: everything since the newest bundle is still exposed.
- **Behavioral equivalence is a fixed battery**, not all reads: probes and
  read surfaces are broad (search, timeline, loops, liveness, audit) but
  finite by construction.
- **Scale numbers are one machine.** The 4→8 GiB super-linearity is
  attributed to memory residency as a stated hypothesis; on machines with
  less RAM the knee will arrive earlier.
- The old-code cliff receipts (809 MB / 2.9 GB RSS cells) are preserved
  outside the repo in the session scratchpad only; `results.json` contains
  the fixed-code table that matches shipped behavior.

## Not done

- The launchd plist is written but not loaded on this machine (installing
  agents is the operator's act, same as the backup plist).
- The 8 GiB cells ran with full sizes (no environment-limited fallback was
  needed); no attempt was made beyond 8 GiB.
- No mitigation shipped for the two stopped design questions above.
- The drill has not yet run against the operator's real backups —
  prohibited for the scale trial, and for the weekly path it starts with
  the plist install.
