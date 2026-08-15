# Repository history remediation — findings and options

**Status: TRIAGED, NOT REMEDIATED. No history was rewritten.**

**Triage result: zero credentials require rotation.** All 314 credential-shaped
strings in history have a non-secret explanation (§ "Credential triage" below).
The remaining exposure is 21 `archive_dialogue` + 5 `session_uuid` findings —
real private material, and the only part of this document still awaiting a
decision.

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

## Credential triage — complete

Run it yourself:

```bash
.venv/bin/python scripts/triage_history_credentials.py --report /tmp/triage.json
```

Exit 0 means every finding is explained; exit 1 lists the ones that are not.
The tool reads matched values in-process and **never emits one** — not to
stdout, not to the report. `tests/test_repository_privacy.py` asserts that,
asserts the triage accounts for every finding, and includes a negative control
proving the classifier still returns UNCLASSIFIED for a realistic-looking key
(without which "explain everything" would be trivially passable).

| Count | Class | What it means |
|---|---|---|
| 214 | `planted_canary` | A test literal: a repeated-character run, a sequential run, an explicit marker word, or a base64 body that decodes to one. Concentrated in `tests/smoke.py` and the canary suite. |
| 80 | `reserved_domain` | Points at an RFC 2606 / RFC 6761 reserved domain (`example.com`, `.test`, `.invalid`). Cannot be a working credential for anything. |
| 31 | `documented_example` | Prose. Mostly the redaction table's own explanatory comment illustrating the shape the pattern beneath it detects. |
| 4 | `code_identifier` | The regex matched source code, not data — an assignment whose right-hand side is an expression, e.g. `capability_id, secret = raw.split(".", 1)`. |
| 1 | `pem_header_only` | A `-----BEGIN … KEY-----` delimiter with no base64 body. A header carries no key material. |
| 1 | `low_entropy` | Below the entropy a real key of that length would carry. |
| 1 | `pattern_definition` | Regex source matching itself. |
| **0** | **UNCLASSIFIED** | **Nothing requires rotation.** |

### Why the raw count was so misleading

The 314 findings collapse to a handful of causes, each counted once per
historical blob that contained it. `tests/smoke.py` alone accounts for 256 of
them across ~20 revisions of the same planted canaries. A scanner counting
blob-occurrences will always inflate this way; that is a property of scanning
history, not evidence of scale.

### What the triage does NOT establish

- It does not prove the redaction floor caught everything. A secret of an
  *unlisted* shape was never a finding to begin with (`docs/SECURITY.md` §6
  pins the covered classes).
- It classifies by structure and context, not by testing whether a credential
  works. A high-entropy string that happened to sit on a line with a regex tell
  would be filed as a pattern. The negative-control test bounds this, but the
  method is heuristic and is documented as such.

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

### Option B — triage first, then decide — **DONE**

Completed; see "Credential triage" above. **No credential requires rotation.**

That resolves the branch this decision was waiting on: the remaining exposure
is 21 `archive_dialogue` + 5 `session_uuid` findings (the two live-derived
retrieval fixtures, since replaced with synthetic data in the working tree, and
two tracked benchmark artifacts) plus 59 low-sensitivity `home_path` findings.

Option C is now a judgement about **private conversation content and session
identifiers**, not about leaked keys — a materially smaller and less urgent
problem than the raw 257 suggested.

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
