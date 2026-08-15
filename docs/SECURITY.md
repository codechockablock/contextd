# contextd security contract

This document is the frozen reference for *what contextd claims* and *what it
refuses to claim*. Every claim here is bound to a test in `tests/` (named
inline). A claim without a test is a bug in this document.

Status of the tree this describes: **development hardening, implemented but
not deployed**. Every mission in the hardening pass has landed; nothing has
been installed, enrolled, or migrated against a live archive. Production is not hardened. See
[Deployment states](#deployment-states) and
[Implementation status](#implementation-status) — the second table is the one
that says which claims below are actually enforced today.

---

## 1. Attacker

The threat model is a **hostile same-UID agent**: an untrusted model, MCP
client, or subprocess running as the normal desktop user.

### In scope — assumed capabilities

The attacker MAY:

- control every MCP tool argument, including nested structures and long strings;
- set, unset, or forge every environment variable in its own process and in
  processes it spawns (`CONTEXTD_CLIENT`, `CONTEXTD_DERIVATION_SOURCE`,
  `CONTEXTD_HOME`, `CONTEXTD_LOOP_SCOPE`, `PATH`, …);
- run arbitrary shell commands as the desktop UID;
- `import contextd` and call any Python function in the package directly,
  bypassing the CLI and the MCP surface;
- replay any value it has previously observed (signatures, capabilities,
  nonces, grant ids, egress ids);
- induce crashes, kills, timeouts, and `KeyboardInterrupt` at any point;
- read, write, rename, delete, or symlink **any file the desktop UID owns**,
  including this repository, hook scratch, and the client's own config;
- choose process name, `argv[0]`, executable path, working directory, TTY
  state, and parent process.

### Out of scope — assumed impossible

The attacker MAY NOT:

- gain root, or write to root-owned installed code;
- read or write files owned by a **dedicated service UID** it does not control;
- use a Secure Enclave or FIDO operator key **without fresh user presence**
  (the biometric/passcode gesture is assumed to require the human);
- break SHA-256, ECDSA P-256, or the platform CSPRNG;
- modify an **independently protected checkpoint** (an off-device or
  differently-owned monotonic tip record);
- defeat physical access, a compromised OS kernel, or a malicious operator.

Anything that requires those capabilities is **explicitly not defended
against** and must not be claimed as defended.

---

## 2. Trusted computing base

| Component | Trusted for | Owner in a hardened deployment |
|---|---|---|
| macOS kernel + Secure Enclave | key non-exportability, user presence, peer credentials on `AF_UNIX` | OS |
| Root-owned installed daemon code | correct enforcement of every RPC | `root:wheel`, mode `0755`, not writable by the desktop UID |
| Dedicated service UID (`_contextd`) | exclusive access to DB, blobs, witness, service key, key registry, nonce/sequence state, plaintext backup staging | service account |
| Operator hardware key | grounding *authenticated-human* provenance | Secure Enclave, non-exportable, presence-gated |
| Protected checkpoint destination | rollback/truncation detection | anything the desktop UID cannot rewrite |

**Everything else is untrusted.** The Python package as installed in the user's
virtualenv, the CLI, the MCP server, the hooks, and this repository are all
attacker-writable in the threat model and are therefore *clients*, never
authorities.

---

## 3. Assurance vocabulary

These five words are not synonyms. Conflating them is the original defect this
work exists to fix.

### `origin_claim`
A **self-asserted label supplied by the caller**. Carries **zero** assurance.
`claimed_client` is the only such field that survives, and only as a bounded,
redacted diagnostic string.

> Anything a caller can type is an `origin_claim`. `CONTEXTD_CLIENT=human`,
> `actor="human"`, `authority="operator"`, `role="user"` are `origin_claim`s
> and nothing more. Tests: `tests/test_authenticated_provenance.py`.

### `transport`
The **channel the bytes were observed to arrive on**, as recorded by the
component that received them — `mcp`, `cli`, `fs`, `chrome`, `safari`,
`claude_code`. Observed, not caller-settable, but *weak*: a hostile same-UID
agent can invoke the CLI, so `transport == "cli"` does not imply a human.

### `principal`
The **authenticated identity of the RPC peer**, established by the daemon from
OS-level peer credentials on the Unix socket (`LOCAL_PEERCRED` / `SO_PEERCRED`)
plus the socket's own ownership and mode. A principal identifies a **UID and
process**, never a human. `principal.uid == 501` means "the desktop user's
account made this call", which under this threat model is exactly as likely to
be the attacker as the operator.

### `attestation`
A **verified `OperatorActionV1` signature** over an exact canonical byte
string, by a key registered in the daemon's key registry, produced by a
non-exportable Secure Enclave P-256 key **with fresh user presence**, consumed
against a daemon-issued nonce and monotonic sequence.

This is the **only** mechanism in contextd that grounds
*authenticated-human/operator* provenance. There is no production file-key,
environment-key, HMAC, prompt-only, TTY, or parent-process fallback.
See [§5](#5-what-an-attestation-does-and-does-not-prove).

### `integrity`
Whether stored bytes are **unaltered since acceptance**. Three independent
layers, in increasing strength:

1. SQLite hash chain — detects naive edits; **defeated** by an attacker who
   recomputes the chain.
2. Local witness tip — detects loss of the final row; **defeated** by the same
   attacker, who can rewrite the witness file.
3. **Service signature** over accepted authoritative envelopes and chain tips,
   under a key held by the service UID — **not** defeated by chain
   recomputation, because the attacker cannot produce the signature.
   Test: `tests/test_service_attestation.py`.

Layer 3 plus a protected checkpoint is what makes integrity meaningful against
this attacker. Layers 1–2 alone are *tamper-evident against accident*, not
against the modeled adversary.

---

## 4. Supported claims

Each is enforced and tested.

Claims marked **PENDING** are designed and documented but **not yet enforced or
tested in this tree**. They are listed so the gap is explicit; do not cite one
as a property contextd has.

| # | Claim | Test | Status |
|---|---|---|---|
| S1 | No caller-controlled string produces authenticated human/operator provenance. | `test_authenticated_provenance.py` | enforced |
| S2 | An `operator_authorized` status requires a verified `OperatorActionV1` from a registered presence-bound key. | `test_authenticated_provenance.py` | enforced |
| S3 | Mutating any signed field, or using the wrong key/archive/action/scope/content, or an expired/future/revoked/replayed authorization, appends **nothing**. | `test_authenticated_provenance.py` | enforced |
| S4 | Domain mutators refuse free-form `actor="human"` / `authority="operator"`; they require a verified authorization object. | `test_authenticated_provenance.py` | enforced |
| S5 | Grant authorization is verified inside the same append lock as the delegated act; concurrent replay yields exactly one success. | `test_grant_atomicity.py` | enforced |
| S6 | Grants require finite expiry; naive timestamps are refused; equivalent UTC offsets decide identically. | `test_grant_atomicity.py` | enforced |
| S7 | Every disclosure/event type uses a **closed** metadata schema; unknown fields are refused. | `test_privacy_boundary.py` | enforced |
| S8 | The built-in redaction floor cannot be weakened by configuration. | `test_privacy_boundary.py` | enforced |
| S9 | Credential canaries of the **pinned classes** (§6) do not survive in event content, URI, serialized metadata, SQLite/WAL/SHM, blobs, logs, errors, audit output, backup manifests, or temp files. | `test_privacy_boundary.py` | enforced |
| S10 | Scratch dirs are `0700`, scratch files `0600`, cleanup runs in `finally` on success and ordinary failure, and cleanup failure is loud. | `test_scratch_cleanup.py` | enforced |
| S11 | A forged `CONTEXTD_DERIVATION_SOURCE` has no authority; wrong-session/principal/egress, expired, or replayed capabilities refuse. | `test_derivation_capability.py` | enforced |
| S12 | Recomputing the hash chain and witness after tampering does not make a forged authoritative signature verify. | `test_service_attestation.py` | enforced² |
| S13 | Migration preserves every historical byte; legacy authority labels resolve `legacy_unverified`. | `test_security_migration.py` | enforced |
| S14 | Unsupported future schema versions refuse **before** filesystem or DB mutation. | `test_security_migration.py` | enforced |
| S15 | A hostile same-UID process cannot open the daemon-owned DB, obtain raw content through a CLI fallback, invoke a production signer without presence, read key material from env/argv/config/logs/backups/temp, or widen its RPC capabilities. | `test_process_isolation.py` | enforced¹ |
| S16 | `ctx security doctor --strict --json` reports each invariant separately and exits nonzero unless every one holds. | `test_security_doctor.py` | enforced |
| S17 | Tracked repository files contain no personal home path, live session UUID, raw archive dialogue, or private repository name. | `test_repository_privacy.py` | enforced |

² **S12 holds against a chain-recomputing attacker, not against one that
re-signs.** The service key is 0600 but currently lives beside the archive, so
in a *development* deployment the same UID owns both. The tests perform the
full attack — rewrite a row, recompute every downstream chain hash, rewrite the
witness — and show the signature still catches it; they do not claim the key is
out of reach. It becomes out of reach when the service account owns it.
`ctx security doctor` reports which case applies.

¹ **S15 is enforced in code and tested, with one simulated clause.** The RPC
surface, tier assignment from kernel peer credentials, attestation requirement,
fail-closed behaviour, and key-material absence are all directly tested. The
clause "cannot open the daemon-owned DB" rests in a real deployment on *file
ownership by a service account*, which the test suite cannot create without
root; it is simulated with file permissions and marked `SIMULATED BOUNDARY` in
`tests/test_process_isolation.py`. Until the service account exists, that
clause is designed and exercised, not proven.

---

## 5. What an attestation does and does not prove

A verified `OperatorActionV1` proves, and only proves:

> At time *T*, a specific registered Secure Enclave key on this device signed
> **exactly these bytes**, and the platform required a fresh user-presence
> gesture to do so, and the daemon had not previously consumed that nonce.

### Excluded claims — never assert these

- **Not authorship.** A signature over a note does not mean the operator wrote
  the note's words. It means the operator authorized appending *that exact
  content digest*.
- **Not comprehension.** Presence proves a gesture, not that the human read or
  understood what they approved.
- **Not truth.** Signed content can be false. Signing is not fact-checking.
- **Not semantic entailment.** `provenance.py` verifies anchor resolution,
  disclosure membership, and quote-span membership. It never claims a claim's
  wording is supported by its evidence. That refusal is deliberate and stays.
- **Not human vs. model identity beyond the key.** The attestation identifies
  a *key*, not a person; and it cannot distinguish Claude from Codex from any
  other client — client identity remains an `origin_claim`.
- **Not remote delivery.** Nothing here proves a provider received, stored, or
  acted on disclosed bytes. An `egress` receipt records what *left the gate*.
- **Not protection against root or physical compromise**, a malicious
  operator, or a user who approves a presence prompt without looking.
- **Not complete PII protection.** §6 pins exactly which secret classes are
  guaranteed. Arbitrary semantic PII is out of scope.

---

## 6. Redaction floor — pinned classes only

The built-in floor in `contextd/redact.py` is **immutable**: user config may
add patterns, never remove or weaken one. Guaranteed classes, each with a
planted-positive and a negative test in `tests/test_privacy_boundary.py`:

`api_key` (sk-/pk- prefixed), `aws_key` (AKIA…), `github_token`
(ghp/gho/ghs/ghu_…), `slack_token` (xox[bpars]-…), `jwt`, `private_key` (PEM
blocks), `ssn`, `card` (major-issuer PANs), `url_param` (auth-shaped query
parameters, including %-encoded), `openai_key` (sk-proj-…), `anthropic_key`
(sk-ant-…), `google_api_key` (AIza…), `bearer_header`, `basic_auth_url`
(`scheme://user:pass@host`), `password_assignment` (`password=…` style).

> **This is a pinned list, not a promise of completeness.** Regex redaction is
> a floor, not a claim of complete privacy. A secret of an unlisted shape will
> pass through. Adding a class requires adding its tests in the same change.

---

## 7. Migration boundary

- Historical events are **byte-for-byte immutable**: id, ts, source, kind, uri,
  content, content_hash, meta, prev_hash, chain_hash. Migration never rewrites
  one.
- Every historical `actor`, `authority`, `role`, and client label is
  **legacy/unverified**. `authority="operator"` written before this work
  resolves as `legacy_unverified`, never as `operator_authorized`.
- Legacy events **cannot** authorize grants, ground authenticated-human
  claims, or be silently re-signed.
- A **signed cutover checkpoint** adopts a legacy tip. It attests *"the service
  observed this tip at this time"* — it does **not** retroactively authenticate
  anything before it. Test: `tests/test_security_migration.py`.
- Migration is append-only and crash-safe; an unsupported future
  `schema_version` refuses **before** any filesystem or DB mutation.

---

## 8. Recovery assumptions

- **Rollback/truncation** is detectable only against a checkpoint the attacker
  cannot rewrite. With no protected destination configured,
  `ctx security doctor --strict` reports `rollback_resistance: incomplete` and
  exits nonzero. The interface exists; **no destination is selected in this
  tree**.
- **Backup/export** manifests are service-signed. In hardened mode, export is
  encrypted to an explicitly configured recovery recipient; with no recovery
  policy configured, export **refuses** rather than emitting plaintext.
- **Key loss**: losing the Secure Enclave key (device loss, key deletion)
  makes new operator-authorized events impossible until a new key is enrolled.
  Enrollment of the first key is a bootstrap act performed by the operator
  out of band; contextd does not self-enroll.
- **Crash**: the witness/recovery journal reconciles exactly one interrupted
  append. Nonce and capability consumption are atomic with the append they
  authorize, so a crash cannot leave a consumed nonce with no event or an
  event with an unconsumed nonce.

---

## Deployment states

| State | Meaning | `doctor --strict` |
|---|---|---|
| **development** | No dedicated service UID, no hardware signer. Client plane opens the DB directly. Assurance is *attribution only* — the same-UID attacker can do anything the owner can. | exits nonzero |
| **hardened** | Root-owned installed daemon under a dedicated UID; production hardware signer enrolled; raw archive inaccessible from the client boundary; valid service signatures; current protected checkpoint; no plaintext scratch; no insecure fallback. | exits zero |

## Implementation status

| Area | State |
|---|---|
| Closed metadata schemas, immutable redaction floor, keyed correlation ids | implemented, tested |
| Scratch hardening (modes, `finally` cleanup, loud failure, stale reaping) | implemented, tested |
| Synthetic retrieval fixtures + repository privacy scanner | implemented, tested |
| Typed assurance vocabulary; `claimed_client`; `claimed_` vs `attested_` split | implemented, tested |
| `OperatorActionV1`: canonical encoding, frozen vectors, verification, nonce/sequence, key registry, atomic consumption | implemented, tested |
| macOS Secure Enclave signer helper (`native/`) | **written and compiles; never built into the tree, never enrolled, never exercised against real hardware** |
| Grants: operator-authorized, finite expiry, UTC instants, verified inside the append, replay/revocation-safe | implemented, tested |
| Dispatch capabilities replacing `CONTEXTD_DERIVATION_SOURCE` | implemented, tested — the old binding is now an explicit refusal, not a silent no-op |
| Authority/storage daemon, closed RPC surface, hardened mode, no SQLite fallback | implemented, tested (daemon runs as the desktop uid until installed — the *isolation* is simulated, the *surface* is real) |
| `ctx security doctor --strict --json` | implemented, tested (reports 6 of 7 invariants failing on this tree, which is correct) |
| Service-signed envelopes and chain tips, key rotation, protected checkpoint | implemented, tested (see ² — the key is not yet service-owned) |
| Signed backup manifests | implemented, tested |
| Encrypted export | **not implemented** — hardened export *refuses* without a configured recovery recipient rather than emitting plaintext, and no recipient has been selected |
| Migration (append-only, idempotent, crash-safe), frozen legacy fixture, crash/concurrency tests, future-schema refusal | implemented, tested |

**This repository is in `development`.** No service has been installed, no key
enrolled, no checkpoint destination selected, and no migration run against a
live archive. Production may be called hardened only after the operator
performs those steps separately and gets a clean
`ctx security doctor --strict --json`.

See `docs/adr/0001-two-plane-authority.md` for the architecture and the exact
signed bytes.
