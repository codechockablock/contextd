# ADR 0001 — Two-plane authority boundary and exact attestation formats

- **Status**: accepted (implemented in this tree; **not deployed**)
- **Date**: 2026-08-14
- **Supersedes**: the implicit "same-owner processes are trusted" model
  documented in `contextd/provenance.py` and `docs/OPEN_LOOPS.md`.

## Context

contextd's original trust model said: *same-owner processes are trusted;
attribution, not authentication.* Under that model, provenance was carried by
strings the caller chose — `CONTEXTD_CLIENT`, `meta.actor`, `meta.authority`,
`meta.role`. That is sound only if every same-UID process is friendly.

The threat model has changed (`docs/SECURITY.md` §1): an untrusted model or
agent runs *as the desktop UID*. Under that model every such string is
attacker-chosen, so `authority="operator"` is a claim by the attacker about the
attacker. Metadata cannot carry authority across a boundary the attacker sits
inside.

## Decision

Split the system into two planes, and let exactly one cryptographic mechanism
cross between them.

```
┌─ CLIENT PLANE (desktop UID — untrusted) ──────────────────────────────┐
│  ctx CLI · MCP server · hooks · the contextd Python package           │
│  Holds: no DB handle, no keys, no witness, no plaintext staging       │
│  Speaks: closed RPC over AF_UNIX                                      │
└───────────────────────────┬───────────────────────────────────────────┘
                            │  authd.sock (peer credentials checked)
┌───────────────────────────┴─ AUTHORITY PLANE (service UID) ───────────┐
│  contextd-authd, from root-owned installed code                       │
│  Owns: contextd.db · blobs · witness · service key · key registry     │
│        nonce+sequence state · capability state · backup staging       │
│  Enforces: schemas, redaction floor, budget, grants, attestations     │
└───────────────────────────┬───────────────────────────────────────────┘
                            │  presence-gated signature request
                   ┌────────┴─────────┐
                   │  Secure Enclave  │  non-exportable P-256, user presence
                   └──────────────────┘
```

### 1. Which attacker capabilities are in/out of scope?

Answered normatively in `docs/SECURITY.md` §1. Summary of the load-bearing
line: **the attacker owns the desktop UID and everything it can write, and owns
nothing else.** Specifically it does not own root, the service UID, the Secure
Enclave's presence gate, or the protected checkpoint destination.

Consequences accepted:

- The repository, the virtualenv, and the installed *client* package are
  attacker-controlled. No security property may depend on their integrity.
- Therefore enforcement cannot live in the client. A client-side check is a
  UX affordance; the daemon re-checks everything it relies on.
- Therefore `CONTEXTD_CLIENT` cannot name a principal. It survives only as
  `claimed_client`: bounded, redacted, explicitly labelled unverified.

### 2. Which exact bytes are signed, and which component does what?

#### `OperatorActionV1` — the only operator-authoritative object

**Canonical encoding.** Not JSON. JSON canonicalization varies across
languages in number handling, escaping, and key ordering; those are exactly the
places signature-substitution bugs live. The encoding is length-prefixed and
type-tagged, so no two distinct field sets can produce the same bytes.

```
canonical(action) := b"contextd.OperatorActionV1\n" || enc_map(action)

enc_map(m)   := b"m" || enc_u64(len(m)) || concat(
                    enc_str(k) || enc_val(m[k])
                    for k in sorted(m, key=utf8_bytes)   # byte order, not locale
                )
enc_val(v)   := b"s" || enc_str(v)              if v is str
              | b"i" || int64_be(v)             if v is int  (and not bool)
              | b"m" || …                       if v is a map
              | b"l" || enc_u64(n) || …         if v is a list
              | REFUSE                          otherwise
enc_str(s)   := enc_u64(len(utf8(s))) || utf8(s)   # s MUST already be NFC
enc_u64(n)   := 8-byte big-endian unsigned
int64_be(n)  := 8-byte big-endian two's complement
```

Refused, unconditionally, at encode time: `float`, `bool`, `None`, `bytes`,
non-NFC strings, ints outside int64, non-string map keys, and **any key not in
the schema below**. Floats are refused because IEEE-754 round-tripping is not
reproducible across languages; there is no field that needs one.

**Field schema — exactly these twelve keys, all required:**

| Key | Type | Meaning | Constructed by |
|---|---|---|---|
| `domain` | str | `"contextd.operator.action"` — domain separator | constant |
| `version` | int | protocol version, `1` | constant |
| `archive_uuid` | str | UUID of the target archive | daemon |
| `key_id` | str | operator key identifier (SHA-256 of SPKI, hex) | daemon |
| `nonce` | str | 32-byte daemon-issued random, hex | **daemon** |
| `sequence` | int | daemon-issued monotonic counter | **daemon** |
| `issued_at` | int | epoch seconds, UTC | daemon |
| `expires_at` | int | epoch seconds, UTC; `> issued_at`, finite | daemon |
| `action` | str | closed action class (`note.deliberate`, `grant.add`, …) | daemon, from request |
| `scope` | str | canonical scope: `global` or `repo:<resolved abs path>` | daemon |
| `arguments` | map | normalized arguments, str→(str\|int) | **daemon**, never the caller verbatim |
| `content_digest` | str | `sha256(content bytes)` hex; digest of `b""` when no content | daemon |
| `reason_digest` | str | `sha256(reason bytes)` hex | daemon |

> `nonce`, `sequence`, and `arguments` are daemon-constructed on purpose. The
> caller proposes an intent; the daemon decides the exact bytes that will be
> signed and shows them back. A caller that could choose the nonce could
> pre-collect signatures; a caller that could choose `arguments` verbatim could
> smuggle unnormalized scope or unbounded text past the schema.

**Responsibility split.** This is the part that is easy to get wrong, so it is
stated per-verb:

| Verb | Component | Notes |
|---|---|---|
| **constructs** | daemon (`contextd/attest.py` `build_action`) | from a validated request + fresh nonce/sequence |
| **displays** | client, from the daemon's returned `human_summary` **and** the canonical bytes' digest | the client shows what it is about to ask the human to approve; the human's real assurance is the presence gesture plus the summary, and the ADR does **not** claim the human verified the digest |
| **signs** | `native/contextd-signer` (Swift, Security.framework) | `kSecKeyAlgorithmECDSASignatureMessageX962SHA256` over the exact canonical bytes; `kSecAccessControlBiometryCurrentSet \| .userPresence`, `kSecAttrIsPermanent`, `kSecAttrTokenIDSecureEnclave` |
| **verifies** | daemon (`contextd/attest.py` `verify_action`) using **pyca/cryptography** (P-256 ECDSA, X9.62/DER) | no hand-rolled primitives |
| **consumes** | daemon, inside the same append critical section as the act | nonce marked used + sequence advanced atomically with the event insert |
| **stores** | daemon | the action map, the DER signature, and `key_id` in the event's `attestation` block |

**Signature algorithm**: ECDSA P-256 with SHA-256, DER (X9.62) encoding, over
the canonical bytes as the *message* (the platform hashes it). Secure Enclave
production signing is P-256. Ed25519 software keys are **not** an equivalent
substitute and are never accepted in production mode.

**Frozen test vectors** live in `tests/vectors/operator_action_v1.json`: input
map → canonical bytes (hex) → digest. Any change to the encoding breaks them,
which is the point. They exist so a second implementation in another language
can be checked byte-for-byte.

#### `DispatchCapabilityV1` — replaces `CONTEXTD_DERIVATION_SOURCE`

An enumerable integer in an environment variable is guessable and forgeable, so
it is retired as an authority. The daemon issues an **opaque, expiring,
single-use** capability bound to: archive UUID, principal, dispatcher/session
id, the exact egress receipt id **and its content digest**, the single write it
permits, the observed dispatch state, and a nonce. It is consumed atomically
with the derived write. The old anchor-membership and semantic-boundary checks
are preserved and still run.

#### Service attestation

The daemon signs (a) each accepted authoritative event envelope and (b) chain
tips, with a service key held by the service UID. This is the layer that
survives chain recomputation: an attacker who rewrites SQLite and the local
witness still cannot produce the service signature.

### 3. What is the strongest honest claim when a component is absent?

| Absent | Strongest honest claim | Enforced by |
|---|---|---|
| Dedicated service UID / installed daemon | **Attribution only.** The client plane opens the DB directly; a same-UID attacker can append, rewrite, and recompute at will. Tamper-evidence holds against accident and against an attacker who does *not* recompute — nothing more. | `doctor --strict` fails `protected_daemon` |
| User-presence hardware signer | **`operator_authorized` is unreachable.** No event in the archive grounds authenticated-human provenance. Every authority label is `unauthenticated` or `legacy_unverified`. There is no fallback — not a file key, not an HMAC, not a TTY check, not a confirmation prompt. | `doctor --strict` fails `production_signer`; test-only signers stamp `INSECURE_TEST_SIGNER` |
| Protected/off-device checkpoint | **Rollback resistance incomplete.** Truncation or wholesale replacement of the archive by a UID-owning attacker is not detectable from local state alone. | `doctor --strict` reports `rollback_resistance: incomplete` |
| Recovery recipient / export key policy | **Export refuses.** Hardened mode never emits plaintext outside service-owned storage. | `backup`/`export` refuse in hardened mode |

## Consequences

**Accepted costs.**

- Two processes and a socket where there was one library. Every archive read in
  hardened mode is an RPC round trip.
- Domain mutators lose their free-form `actor=`/`authority=` parameters. Callers
  pass a verified authorization object or get refused. This is a breaking API
  change, taken deliberately.
- Operator acts that used to be one CLI call now require a presence gesture.
  That is the feature.
- The repository's own history already contains private material. This ADR does
  not clean it; `docs/REPOSITORY_HISTORY_REMEDIATION.md` records what is there
  and what removing it would cost. History rewriting is **not** authorized here.

**Explicitly not solved.**

- A malicious operator. Presence proves a gesture by whoever is at the machine.
- A human who approves without reading. Presence is not comprehension.
- Semantic truth of signed content. Unchanged from `provenance.py`'s original
  refusal, which stays.
- Complete PII redaction. The floor covers pinned classes (`SECURITY.md` §6).

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Keep metadata authority, document the caveat | The caveat *is* the vulnerability. Documentation does not stop `authority="operator"` from being typed by the attacker. |
| Same-UID file key or HMAC secret | The attacker reads any file the UID owns. This is authority theatre; explicitly forbidden by the mission's stop conditions. |
| TTY / parent-process / `argv[0]` inspection | All attacker-controlled. A subprocess can allocate a PTY and rename itself. |
| Confirmation prompt in the client | The client is attacker-controlled; the prompt can be answered by the attacker or skipped entirely. |
| Ed25519 software key in the login Keychain | Exportable-in-practice under the modeled attacker, and not what the Secure Enclave provides. Substituting it and calling it equivalent is the specific dishonesty this ADR forbids. |
| Canonical JSON (JCS) for signed bytes | Cross-language number/escaping ambiguity in the one place a mismatch is a forgery. Length-prefixed TLV removes the ambiguity class. |
