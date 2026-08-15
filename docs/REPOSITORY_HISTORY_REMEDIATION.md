# Repository history remediation — findings and options

**Status: NOT REMEDIATED. No history was rewritten. This document records what
is there and what removing it would cost, so the decision can be made
deliberately rather than by default.**

Git history rewriting was explicitly out of scope for the hardening pass that
produced this document. Nothing here has been acted on.

## How to reproduce

```bash
audit_output_dir="$(mktemp -d)"
.venv/bin/python scripts/audit_repository_privacy.py \
  --history --redact-output \
  --report "$audit_output_dir/history-report.json"
```

The scanner never prints or stores a matched value — only class, location, and
count. That rule is enforced in the code (`scan_text` discards the matches) and
tested (`tests/test_repository_privacy.py::test_scanner_output_contains_no_matched_values`).

## Current tree — clean

```
.venv/bin/python scripts/audit_repository_privacy.py \
  --tracked --fail-on-findings --redact-output
```

Exits **0**. Two findings are approved as `awaiting_operator` in
`scripts/repository_privacy_allow.json` and are reprinted under `OUTSTANDING`
on every run so they cannot silently become the baseline:

| Location | Class | Count | Why it is still there |
|---|---|---|---|
| `experiments/restore_scale/results.json` | `session_uuid` | 4 | One real archive UUID in a tracked benchmark **result**. `experiments/` was outside the pass's modify scope, and editing a recorded result is not path sanitization. |
| `runs/handoff-20260812/final-report.md` | `session_uuid` | 1 | One real session UUID in a tracked benchmark **conclusion**. Run artifacts were permitted only portable path sanitization; a session id is not a path. |

## History — 77 findings across 75 blobs

Exit code **0** (history mode does not fail the build). Report written to the
path above.

| Class | Occurrences |
|---|---|
| `credential` | 257 |
| `home_path` | 59 |
| `archive_dialogue` | 21 |
| `session_uuid` | 5 |

Concentration by path (top locations):

| Occurrences | Path |
|---|---|
| 225 | `tests/smoke.py` |
| 24 | `contextd/__init__.py` |
| 20 | `README.md` |
| 16 | `experiments/tasks/retrieval-contradiction-sets.json` |
| 8 | `experiments/tasks/retrieval-synthesis-sets.json` |
| 6 | `docs/operating-map.md` |
| 6 | `launchd/com.contextd.watch.plist` |
| 5 | `launchd/com.contextd.lineage-audit.plist` |
| 5 | `launchd/com.contextd.reconcile.plist` |
| 4 | `experiments/restore_scale/results.json` |
| 4 | `launchd/com.contextd.restore-drill.plist` |
| 4 | `tests/test_provenance_closure.py` |
| 3 | `clients/codex.toml` |
| 3 | `launchd/com.contextd.backup.plist` |

### Reading these numbers honestly

- **The `credential` count is dominated by two non-secret sources**, based on
  where the counts sit rather than on inspecting any value: `tests/smoke.py`
  carries planted redaction canaries (invented literals, asserted to be
  redacted), and `contextd/__init__.py` historically held the redaction
  **patterns themselves**, some of which match their own documentation
  examples. Both are allowlisted as `synthetic` in the current tree for exactly
  this reason.
- **No value was read, printed, copied, or classified individually.** The
  mission constraints forbid it. Consequently this document cannot assert that
  *zero* of the 257 are real. **Per-finding triage is an outstanding operator
  task**, and it is the one that must happen before deciding whether history
  rewriting is warranted at all.
- **`archive_dialogue` (21) and `session_uuid` (5) are the findings with no
  benign explanation.** They are the historical versions of the two retrieval
  fixtures (replaced with synthetic data in the current tree) plus the two
  tracked benchmark artifacts above. This is real private material, permanently
  present in published history.
- **`home_path` (59)** is the operator's absolute home directory in launchd
  plists, client configs, README, and docs. Low sensitivity, high volume; the
  current tree templates all of them.

## Options, with costs

### Option A — do nothing (current state)

Private material stays in history. Anyone who clones the repository gets it.
For a repository that is already published, note that removal does not
retroactively un-publish: existing clones, forks, and any archival mirror keep
the old objects.

**Cost: none. Risk: unchanged, and permanent.**

### Option B — triage first, then decide

Classify the 257 `credential` findings as synthetic vs. real. This requires
reading matched values, which the hardening pass was forbidden to do.

- If **all** are synthetic/pattern text, the remaining exposure is 26 findings
  (dialogue + session UUIDs) plus 59 home paths, and Option C becomes a
  proportionate response.
- If **any** is a real credential, **rotation comes first** and rewriting
  history is secondary — a secret in a published repository must be assumed
  compromised regardless of whether the commit is later removed.

**Recommended first step.** It is the only option that produces the information
the other two need.

### Option C — rewrite history

`git filter-repo` over the affected paths, then force-push.

Costs, all of which land on the operator:

- **Every commit hash after the earliest rewritten object changes.** Every
  reference to a commit — in `docs/`, in `runs/` benchmark receipts, in the
  archive's own notes, in `docs/operating-map.md` — becomes dangling.
- **The benchmark corpus loses its anchors.** Several recorded results cite the
  exact commit they were measured at (e.g. "baseline 230 verified at
  6dcf117"). Rewriting invalidates those citations without invalidating the
  results, which is the worst combination: the numbers stay, their provenance
  breaks.
- **Force-push and ref deletion are required.** Any existing clone must be
  re-cloned; a stale clone that pushes re-introduces the old objects.
- **It does not un-publish.** See Option A.

**Not authorized. Not performed. Requires an explicit operator decision.**

## What has to be true before anyone runs Option C

1. Triage (Option B) is complete and its result recorded.
2. Any real credential found is **rotated first**, independently of git.
3. The operator accepts that commit references in docs, run receipts, and the
   archive will break, and has decided how to handle them.
4. Every clone and fork is accounted for.
5. The operator runs it. This is not a step an agent should take: it is
   irreversible, it rewrites published state, and its blast radius is outside
   the repository.
