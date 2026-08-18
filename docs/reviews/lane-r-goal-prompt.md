# GOAL PROMPT — Lane R: Verification hardening

**Program:** gate-v1.1 (gaps closure) · **Repo:** `~/contextd` worktree, branch from the commit
carrying this brief. Baseline: **802 passed + 18 skipped**. Confirm first; halt if it differs.
**Do not commit.** Parallel with Lanes P and Q — you own `scripts/` and may not touch
`contextd/` core, `ci.yml` (P), or `attest.py`/`ledger_sig.py`/`schemas.py`/`migrate.py` (Q).

## Three gaps

### 1. Independent format verification (the FORMAT.md external-validation gap)

`docs/FORMAT.md` promises a 2035 adjudicator can parse an archive without this codebase. The
only evidence is `tests/test_format_spec.py` — same repo, same language, same author's
understanding. Build a **second implementation in a different language**: a standalone verifier
that, given an archive file (SQLite path) and nothing from the `contextd` package, recomputes
and checks (a) the chain hash for every event, byte-for-byte per FORMAT.md §chain-hash, (b) the
canonical-encoding test vectors (`tests/vectors/`), and (c) at least one service signature via
its algorithm tag. Language: check what this machine has — `node`, `go`, `rustc` — and prefer
the first available; if none, POSIX shell + `sqlite3` CLI + `openssl` + `jq` counts (different
language, independent crypto). It lives in `scripts/verify_format_independent.*`, is wired into
a pytest test that builds a small archive and runs it, and — the entire point — **it may import
nothing from `contextd`**. Mutation-test it: corrupt one row's content in a copy, verifier must
scream. If the verifier finds a place where FORMAT.md and reality disagree, THAT is the
headline finding: report it, do not quietly fix the spec.

### 2. The TOCTOU pinning attack has no test

Three of pinning's four surviving attacks are pinned by tests; the mutate-between-digest-and-
read window is not. Write the test that DEMONSTRATES it: pin a skill body, mutate the file,
"read" the mutated content while presenting the pinned body to the API, show the act records
clean provenance — and assert the documented behavior (the label is a claim about what the
caller presented, `contextd/pinning.py` docstring) rather than pretending it is a fix. A test
that proves a limitation exists and pins its exact shape is the deliverable; closing the window
would require the core to open files, which is a design change you must NOT make.

### 3. The network-surface gate is lexical

`scripts/gates.sh`'s network grep matches vocabulary ("socket", "http") and structurally cannot
see that `psycopg` gives contextd network capability (recorded in three docs). Build the
import-level companion: a script (stdlib-only Python is fine) that walks every module under
`contextd/` via AST, resolves its imports (direct and package-internal-transitive), and flags
any that reach a socket-capable set (stdlib: `socket`, `http`, `urllib.request`, `ssl`,
`asyncio` streams, `smtplib`, …; third-party by name: `psycopg`, `httpx`, `requests`, …),
diffing against a pinned manifest (`tests/network_imports.txt`) exactly like the lexical gate —
a new match fails until the manifest is updated in the same commit. Wire it into
`scripts/gates.sh` beside the existing grep (keep the grep; the two catch different lies) and
into a pytest test. Seed the manifest honestly with today's true surface (`backends/pgdriver`
etc.) and have the report explain each entry.

## Constraints

MUST NOT touch: `examples/gate_proof/` (frozen), anything under `contextd/` except NOTHING —
this lane writes only `scripts/`, `tests/`, and `tests/vectors/` fixtures if needed (read
`contextd/` freely, cite it, never edit it). Not `ci.yml`, not `README.md`/`COMPARISON.md`/
`docs/` except a FORMAT.md **errata note only if finding 1 uncovers a spec/reality mismatch**
(flag loudly). Never `pip install -e .` into the shared venv.

## Gates

```bash
python -m pytest -q                                    # no regressions vs 802+18
python -m pytest tests/ -q -k "independent or toctou or network_imports"
sh scripts/gates.sh                                    # your own updated battery: ALL PASSED
python examples/gate_proof/concurrent_redemption.py    # exit 0, unmodified
git status --porcelain examples/gate_proof/ docs/reviews/ contextd/   # contextd/ EMPTY unless FORMAT errata ruled in
```

Stop conditions: the independent verifier finds a FORMAT.md/reality disagreement (halt AFTER
capturing it fully — that finding outranks the rest of the lane); no non-Python toolchain and
the shell fallback cannot verify signatures (report which schemes it covered); baseline already
failing. Report: raw gates, which language the verifier is in and why, the mutation-test
evidence, the seeded import manifest annotated line by line, one honest paragraph on what
independent verification still does not cover.
