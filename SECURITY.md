# Security policy

## Reporting a vulnerability

**Report privately. Do not open a public issue for a security defect.**

Use GitHub's private vulnerability reporting on this repository — the
**Security** tab → **Report a vulnerability**. That opens a private advisory
visible only to the maintainer. If that is unavailable to you, email the
repository owner directly at the address on their commits (`git log --format=%ae`).

This is a single-maintainer personal project. There is **no bug bounty, no
payout, no service-level agreement, and no coordinated-disclosure team** — an
honest statement of scale rather than a policy that would not be honored.
What you will get is an acknowledgement and a real answer.

Expect a first response within about a week. If a report is confirmed, the fix
and its regression test land together, and the advisory names the reporter
unless they ask otherwise.

## Before you report: is it already documented?

[`docs/SECURITY.md`](docs/SECURITY.md) is the security contract — the threat
model, the assurance vocabulary, the enumerated supported claims with the test
that enforces each, and, importantly, an **"Implementation status"** table
saying what is actually enforced on this tree versus designed but not in force.

Several properties a reader might expect are **openly not claimed**, and a
report that one of them fails is not a vulnerability report. The most commonly
assumed:

- **This tree is in `development`, not `hardened`.** There is no dedicated
  service UID and no enrolled hardware signer on a fresh clone.
  `ctx security doctor --strict` exits nonzero here, and that is correct.
- **The gate is an audit layer, not an isolation boundary.** Any local process
  running as the same user can read the SQLite file directly.
- **The chain and the witness are tamper-evident, not tamper-proof.** An
  owner-level process that rewrites a row and recomputes every downstream hash
  — including the witness file — defeats both. The service signature is the
  layer that does not fall to that, and only once the key is service-owned.
- **Events since the last checkpoint are covered by local state alone.** That
  window is `checkpoint_interval_events` (default 100) and is documented as an
  exposure window, not an oversight.
- **A PostgreSQL superuser, the table owner, or root on the database host is
  outside the trust model.** They can disable the triggers, rewrite `events`,
  and set the tip to match in one consistent transaction.
- **Regex redaction is a floor, not a completeness claim.** The guaranteed
  secret classes are pinned in `docs/SECURITY.md` §6; a secret of an unlisted
  shape will pass through.
- **Instruction pinning binds the caller's claim, not the file on disk.** Four
  attacks survive by construction and are documented in `contextd/pinning.py`.

## What is in scope

Anything that breaks a **supported claim** in `docs/SECURITY.md` §4 — those are
the numbered `S1`–`S18` rows, each bound to a named test. Concretely, reports
of any of the following are very much wanted:

- a caller-supplied string producing authenticated operator provenance;
- a single-use authorization redeemed twice, or a nonce consumed without an
  event (or an event appended without consuming its nonce);
- an append that leaves the chain, witness, and recovery journal in a state
  recovery resolves incorrectly;
- a metadata field that escapes the closed schema registry, or a pinned-class
  credential surviving in stored bytes;
- a signature verifying under a scheme other than the one its record names;
- a chain rewrite that a valid service signature or checkpoint fails to catch;
- anything in `examples/gate_proof/` that can be made to pass while the
  property it demonstrates is false.

A working proof-of-concept against a throwaway archive is the most useful
possible report. `CONTEXTD_HOME` pointed at a temp directory keeps it harmless.

## Supported versions

The `master` branch only. This project has no release train and no backports;
there is nothing else to patch.
