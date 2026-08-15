# History rewrite runbook — NOT EXECUTED

**Nothing in this document has been run.** It was written for the operator to
execute, deliberately, after reading it. Rewriting published history is
irreversible, its effects reach outside this repository, and it is not a step
an agent should take. `docs/REPOSITORY_HISTORY_REMEDIATION.md` §"What has to be
true" lists the preconditions; this document is what to do once they hold.

**This runbook has not been tested by its author.** Step 2 is a mandatory
rehearsal on a throwaway clone precisely because of that. Do not skip it.

---

## What is actually left

Everything else is already resolved. The tracked tree is clean, and the
credential triage found nothing requiring rotation
(`docs/REPOSITORY_HISTORY_REMEDIATION.md`).

What remains is **four blobs**, none of which is in `HEAD`:

| Blob | Path | Findings | Size |
|---|---|---|---|
| `a7573cb11114` | `experiments/tasks/retrieval-contradiction-sets.json` | 14 × `archive_dialogue` | 35 293 B |
| `61c454ac6b59` | `experiments/tasks/retrieval-synthesis-sets.json` | 7 × `archive_dialogue` | 33 222 B |
| `90ab58f7a501` | `experiments/restore_scale/results.json` | 4 × `session_uuid` | 6 030 B |
| `9ef8b4f85e0c` | `runs/handoff-20260812/final-report.md` | 1 × `session_uuid` | 3 845 B |

That is the whole problem: **21 `archive_dialogue` + 5 `session_uuid`**. The
first two are the pre-replacement retrieval fixtures carrying verbatim private
dialogue; the last two are pre-sanitization copies of artifacts already fixed
in the working tree.

Two properties make this far easier than a general history scrub:

1. **Every offending blob has a sanitized successor already in `HEAD`.** The
   rewrite substitutes content rather than deleting paths, so no file
   disappears from history and no commit becomes empty.
2. **Only two commits touch each fixture.** The blast radius is small.

Confirm the list is still current before running anything — new commits can add
new blobs:

```bash
.venv/bin/python scripts/audit_repository_privacy.py --history --redact-output
```

---

## Preconditions

Do not proceed until every line is true.

- [ ] Credential triage complete, nothing requiring rotation — **done**, see
      `scripts/triage_history_credentials.py` (exit 0).
- [ ] Working tree clean — **done**, `--worktree --fail-on-findings` exits 0.
- [ ] You accept that **removal does not un-publish.** These blobs have been on
      the remote for some time. Any existing clone, fork, or mirror keeps them,
      and GitHub may retain unreachable objects until it garbage-collects.
- [ ] You have accounted for every clone. A stale clone that pushes
      **re-introduces the old objects**.
- [ ] You accept a force-push over `origin/master` **and**
      `origin/instruments-liveness-tally`, both of which get new SHAs.
- [ ] All eight local branches will be rewritten; none holds work you have not
      already merged or copied.
- [ ] The repository is currently **private**. If that ever changes, do this
      first, not after.

---

## Step 0 — a real backup, outside this repository

`filter-repo` refuses to run on a repo with unpushed changes or a dirty tree,
but its own safety net is not a backup.

```bash
cd ~
tar czf contextd-prerewrite-$(date +%Y%m%d-%H%M).tar.gz contextd
# derived, not hardcoded: the runbook should not carry the remote URL, and
# this stays correct if the remote ever moves
git clone --mirror "$(git -C ~/contextd remote get-url origin)" \
    contextd-remote-mirror-$(date +%Y%m%d).git
```

Keep both until you are certain. The mirror is what lets you restore the remote
exactly as it was.

## Step 1 — record the "before" state

```bash
cd ~/contextd
git rev-parse master > /tmp/before-master.txt
git for-each-ref --format='%(refname) %(objectname)' > /tmp/before-refs.txt
.venv/bin/python scripts/audit_repository_privacy.py --history --redact-output \
    > /tmp/before-history.txt
.venv/bin/python -m pytest -q > /tmp/before-tests.txt 2>&1; echo $?
```

## Step 2 — REHEARSE on a throwaway clone (mandatory)

Never rehearse in the working repository. `filter-repo` is designed to run on a
fresh clone and will alter whatever it is pointed at.

```bash
cd /tmp
rm -rf rewrite-rehearsal
git clone --no-local ~/contextd rewrite-rehearsal
cd rewrite-rehearsal
```

Export the sanitized replacements **before** rewriting, because the rewrite
changes what `HEAD` resolves to:

```bash
mkdir -p /tmp/replacements
git show HEAD:experiments/tasks/retrieval-contradiction-sets.json \
    > /tmp/replacements/contradiction.json
git show HEAD:experiments/tasks/retrieval-synthesis-sets.json \
    > /tmp/replacements/synthesis.json
git show HEAD:experiments/restore_scale/results.json \
    > /tmp/replacements/results.json
git show HEAD:runs/handoff-20260812/final-report.md \
    > /tmp/replacements/final-report.md
```

Sanity-check the replacements are themselves clean before you bake them in:

```bash
for f in /tmp/replacements/*; do
  echo "$f"; grep -cE 'claude://[0-9a-f]{12,}' "$f" || true
done
# every count must be 0
```

## Step 3 — the invocation

Substitution, not deletion. `--blob-callback` receives every blob; the four
targets are replaced by their sanitized successors and everything else passes
through untouched.

```bash
cd /tmp/rewrite-rehearsal

git filter-repo --force --blob-callback '
import pathlib
REPLACEMENTS = {
    b"a7573cb11114":  "/tmp/replacements/contradiction.json",
    b"61c454ac6b59":  "/tmp/replacements/synthesis.json",
    b"90ab58f7a501":  "/tmp/replacements/results.json",
    b"9ef8b4f85e0c":  "/tmp/replacements/final-report.md",
}
for prefix, path in REPLACEMENTS.items():
    if blob.original_id.startswith(prefix):
        blob.data = pathlib.Path(path).read_bytes()
        break
'
```

Notes on why it is written this way:

- **Prefix match on `original_id`.** `filter-repo` supplies the full 40-char
  oid as bytes; matching on the abbreviated prefix keeps the callback readable
  and is unambiguous here (all four prefixes are distinct in this repository).
- **`blob.data` assignment, not path filtering.** `--path ... --invert-paths`
  would erase the files from all history, including the synthetic versions you
  want to keep, and would leave commits that only touched them empty.
- **No `--replace-text`.** That operates on literal strings, which would mean
  writing the private dialogue into a patterns file — reintroducing on disk
  exactly what you are removing from history.
- **Commit messages are handled for you.** `filter-repo` rewrites short SHAs
  mentioned in commit messages to their new values, so the
  "baseline 230 verified at `6dcf117`" style references in this repository's
  history stay correct. No tracked *file* cites a commit SHA — verified.

## Step 4 — verify the rehearsal

```bash
cd /tmp/rewrite-rehearsal
python3 -m venv .venv && .venv/bin/pip install -qe '.[dev]'

# 1. the offending blobs are gone
for b in a7573cb11114 61c454ac6b59 90ab58f7a501 9ef8b4f85e0c; do
  git cat-file -e "$b" 2>/dev/null && echo "STILL PRESENT: $b" || echo "gone: $b"
done

# 2. the findings are down to the synthetic remainder
.venv/bin/python scripts/audit_repository_privacy.py --history --redact-output | tail -1
```

**Expected after a successful rewrite:** `archive_dialogue=4`,
`session_uuid=6`. Those are the planted values in `tests/fixtures/legacy_archive.json`
and `tests/test_repository_privacy.py`, which are synthetic by construction and
must survive — the migration and scanner suites assert on them.

If you see `archive_dialogue=25, session_uuid=11`, the callback did not fire:
check that the blob ids still exist (Step 0's list may be stale).

```bash
# 3. the tree still works
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
.venv/bin/python tests/smoke.py
.venv/bin/python scripts/audit_repository_privacy.py --worktree --fail-on-findings --redact-output

# 4. HEAD content is byte-identical to before — a substitution rewrite must not
#    change the current tree at all
git diff --stat $(cat /tmp/before-master.txt) HEAD -- . || true
```

Step 4.4 is the one that catches a mis-specified callback. Because every
replacement is the content already in `HEAD`, **the working tree after the
rewrite must be identical to the working tree before it.** Any diff means the
callback replaced the wrong blob.

## Step 5 — apply for real

Only after the rehearsal passes every check.

```bash
cd /tmp
rm -rf contextd-rewritten
git clone --no-local ~/contextd contextd-rewritten
cd contextd-rewritten
# repeat Step 3 exactly, then Step 4 exactly
```

`filter-repo` removes the `origin` remote on purpose, so a rewritten clone
cannot push by accident. Re-add it deliberately:

```bash
git remote add origin "$(git -C ~/contextd remote get-url origin)"
git push --force origin master
git push --force origin instruments-liveness-tally
```

Then replace your working copy from the rewritten clone rather than trying to
reconcile the old one — a rebase across a rewrite is how old objects come back:

```bash
cd ~ && mv contextd contextd-old-$(date +%Y%m%d) && mv /tmp/contextd-rewritten contextd
```

Preserve the two untracked files the hardening pass never touched:

```bash
cp ~/contextd-old-*/.metadata_never_index ~/contextd/ 2>/dev/null
cp ~/contextd-old-*/mission-d-grant-calibration.md ~/contextd/ 2>/dev/null
```

## Step 6 — after

- Re-run the full gates in the new working copy.
- **Restart anything running from the old path.** Your `ctx serve` MCP servers
  and the `com.contextd.*` launchd jobs execute from `~/contextd`; they will
  hold the old inode until restarted.
- Ask GitHub Support to garbage-collect unreachable objects if you want the old
  blobs actually unreachable via the API — a force-push alone leaves them
  retrievable by SHA for a while.
- Delete the local `contextd-old-*` copy and the mirror once you are satisfied.

---

## Rollback

Before the force-push, rollback is free: delete the rewritten clone.

After the force-push:

```bash
cd ~/contextd-remote-mirror-*.git
git push --force origin 'refs/heads/*:refs/heads/*'
```

This is why Step 0's mirror matters. Without it there is no way back.

---

## What this does not fix

- **It does not un-publish.** Anything already cloned keeps the old blobs. If
  the material is sensitive enough to require rewriting, treat it as already
  disclosed and act accordingly.
- **It does not change the redaction floor's coverage.** A secret of an
  unlisted shape was never a finding (`docs/SECURITY.md` §6).
- **It does not affect the live archive** at `~/.contextd`, which is a separate
  store and is not touched by any of this.
- **It does not make production hardened.** That is a different list entirely —
  `ctx security doctor --strict`.

## The honest recommendation

The repository is private, the credential triage came back empty, and what is
left is your own conversation content in four unreachable-from-HEAD blobs.
Weigh that against a force-push over published history, eight rewritten
branches, and a permanent fork in every clone.

A defensible alternative is to do nothing, keep the repository private, and let
the material age out — the tracked tree is already clean, so nothing new is
accumulating. Rewriting is warranted if the repository will ever be made
public, or if the dialogue content is more sensitive than "project notes".
That judgement is yours; this runbook exists so that if you make it, the
execution is not improvised.
