# contextd record format, version 1

**Format identifier:** `contextd-record-format v1`
**Archive schema version:** 3 (`contextd/db.py`, `SCHEMA_VERSION`)
**Document revision:** 2
**Status:** frozen for v1. A change to any byte layout below bumps the format
identifier; a change to the archive's DDL bumps the schema version; anything
this document merely gains — a new closed-vocabulary entry, a new section for a
format that lives *outside* the archive — bumps only the document revision
above. Revision 2 adds §11 (the exported checkpoint log), the `mandate.resolve`
action class, and the `(mandate, resolve)` event type. No byte layout in §§1–6
changed, which is why the format identifier and the schema version did not
move: an archive written before revision 2 parses identically under it.

## Why this document exists

An archive kept as evidence outlives the program that wrote it. A record
appended in 2026 may be disputed in 2035, by which time this repository may be
unbuildable, its dependencies unavailable, and its author unreachable. This
document exists so that an adjudicator with the raw bytes and no working copy
of contextd can parse a record, recompute its hash chain, and check a
signature — using only a SHA-256 implementation, an ECDSA or ML-DSA verifier,
and the rules written here.

Everything below is transcribed from the code, with the file and line where it
lives. Where this document and the code disagree, **the code is correct and
this document has a bug**. The reader is invited to check: every claim here
names its source.

Section 9 states plainly what this format does *not* specify. That section is
load-bearing; read it before assuming coverage.

---

## 1. The `events` table

Source: `contextd/db.py:25–36` (DDL), `contextd/db.py:837` (`_prepare_row`).

One append-only table holds every record. Ten columns, in this order:

| Column | SQL type | Meaning |
|---|---|---|
| `id` | `INTEGER PRIMARY KEY` | Monotonic event id, from 1. Also the chain position. |
| `ts` | `TEXT NOT NULL` | Timezone-aware ISO-8601, normalized to UTC, e.g. `2026-08-18T00:26:52+00:00`. Lexicographic order equals chronological order. |
| `source` | `TEXT NOT NULL` | Producing plane: `note`, `fs`, `chrome`, `safari`, `claude_code`, `gate`, `eval`, `loop`, `grant`, `decision`, `mandate`, `tx`, `pin`, `act`. |
| `kind` | `TEXT NOT NULL` | Record type within the source. `(source, kind)` is the registry key. |
| `uri` | `TEXT` | Subject locator when one exists (file path, page URL). May be NULL. |
| `content` | `TEXT` | The record's text, post-redaction. NULL for content-free records (§8). |
| `content_hash` | `TEXT` | SHA-256 of the pre-storage content, or the blob address for oversized payloads. May be NULL. |
| `meta` | `TEXT` | JSON object validated against the closed registry (§7). May be NULL. |
| `prev_hash` | `TEXT` | `chain_hash` of event `id − 1`; the empty string for event 1. |
| `chain_hash` | `TEXT` | This row's chain hash (§2). |

**Immutability is enforced by the database, not by convention.** Two triggers
(`contextd/db.py:42–45`) raise `ABORT` on any `UPDATE` or `DELETE` against
`events`. On the PostgreSQL backend the same guarantee is a PL/pgSQL trigger
plus privilege revocation — the application role holds `INSERT` and `SELECT`
only (`contextd/backends/postgres.py:94–101`).

A parser that finds no such trigger is looking at an archive whose
append-only property was removed. `verify_chain` will still recompute the
chain, but the DDL guarantee is gone and should be reported as such.

---

## 2. The chain hash

Source: `contextd/db.py:673–690` (`_chain_hash`).

```
chain_hash(row) = SHA256(
      prev_hash            || 0x1F
   || decimal(id)          || 0x1F
   || ts                   || 0x1F
   || source               || 0x1F
   || kind                 || 0x1F
   || (uri          or "") || 0x1F
   || (content      or "") || 0x1F
   || (content_hash or "") || 0x1F
   || (meta         or "") || 0x1F
)
```

Exactly and only these rules:

- **Nine fields, in the order listed.** No length prefixes, no JSON, no
  canonical encoder — this predates `canonical.py` and is deliberately left
  alone, because changing it would invalidate every existing archive.
- **`0x1F`** (ASCII unit separator) terminates *every* field, including the
  last. It is a terminator, not a delimiter.
- **NULL becomes the empty string.** `uri`, `content`, `content_hash` and
  `meta` are `or ""` in the source.
- **`id` is its decimal string**, via Python `str(int)`: no padding, no sign
  for positive values.
- **Every part is UTF-8 encoded** (`part.encode()` with Python's default).
- **`prev_hash` for event 1 is the empty string**, so the chain has a defined
  root without a sentinel row.
- The output is **lowercase hex**, 64 characters (`hexdigest()`).

Verification recomputes the whole chain in `id` order and compares each row's
stored `prev_hash` and `chain_hash` (`contextd/db.py:750–791`, `_verify_rows`).
A mismatch reports the first bad id. This detects rewrites, deletions,
insertions and reordering.

**What it does not detect:** an actor who rewrites a row *and* recomputes
every subsequent hash. The chain is tamper-**evident**, not tamper-proof. The
answer to that actor is a signature they cannot produce (§5) — not the chain.

> **Timestamp inversions are not chain errors.** Concurrent writers can commit
> rows whose `ts` decreases while `id` increases. `_verify_rows` counts these
> as `ts_warnings` and still returns `ok`. A parser must not treat a `ts`
> inversion as tampering.

---

## 3. Canonical encoding (signed objects only)

Source: `contextd/canonical.py` (whole file, 122 lines).
Frozen test vectors: `tests/vectors/operator_action_v1.json`.

Everything *signed* — as opposed to chained — is encoded with a
type-tagged, length-prefixed encoding, so that no two distinct structures
share an encoding and a verifier never needs a decoder.

```
canonical(domain, value) := utf8(domain) || 0x0A || enc(value)

enc(str)  := 's' || u64_be(len(utf8_bytes)) || utf8_bytes      # NFC required
enc(int)  := 'i' || i64_be(value)
enc(list) := 'l' || u64_be(n) || enc(v_1) .. enc(v_n)
enc(map)  := 'm' || u64_be(n) || (enc(k_i) || enc(v_i)) for keys sorted
             by their UTF-8 bytes; keys use the string encoding above
```

`u64_be`/`i64_be` are big-endian 8-byte integers (`struct` `>Q` / `>q`,
`contextd/canonical.py:55,89`). The domain separator must be non-empty and
must contain no newline (`canonical.py:116–117`).

### Refused unconditionally, and why

These are not validation niceties; each closes a signature-substitution class
(`contextd/canonical.py:68–107`):

| Refused | Reason |
|---|---|
| **`float`** | **IEEE-754 round-tripping is not reproducible across languages.** Two implementations that agree the value is "the same number" can produce different bytes, and a signature over one would fail against the other — or, worse, verify against a different value. No field in `OperatorActionV1` needs a float, so the type is refused rather than pinned to a formatting rule that a second implementation might read differently. |
| `bool` | Would encode identically to `0`/`1`, making `True` and `1` substitutable under signature. |
| `None` | Absence must be expressed by omitting the key, never by a present null. |
| `bytes` | Every field is text or an integer by construction. |
| non-NFC strings | Two visually identical strings with different code points must not produce two different signatures. |
| `int` outside int64 | The encoding is fixed-width. |
| non-string map keys | Key ordering must be defined by UTF-8 bytes. |

Bounds: depth ≤ 8, ≤ 4096 items per container (`canonical.py:44–45`).

Map keys sort by **UTF-8 byte order**, not locale and not code point order
(`canonical.py:103`). A second implementation must sort raw bytes.

---

## 4. `OperatorActionV1` — the authorization

Source: `contextd/attest.py:51–96`.

**Domain separator:** `contextd.OperatorActionV1` (`attest.py:51`)
**Protocol version:** 1 (`attest.py:52`)

The signed object is a map with **exactly these thirteen keys, all required;
unknown keys are refused** (`attest.py:60–65`, `ACTION_FIELDS`):

| Field | Type | Meaning |
|---|---|---|
| `domain` | str | `contextd.OperatorActionV1` |
| `version` | int | `1` |
| `archive_uuid` | str | Binds the authorization to one archive |
| `key_id` | str | Which registered operator key signs |
| `nonce` | str | Single-use; consumed by exactly one append |
| `sequence` | int | Monotonic per-archive counter |
| `issued_at` | int | Unix seconds |
| `expires_at` | int | Unix seconds |
| `action` | str | Action class, from the closed registry below |
| `scope` | str | `global` or `repo:<path>` |
| `arguments` | map | Action-specific, canonically encoded |
| `content_digest` | str | SHA-256 of the exact content authorized |
| `reason_digest` | str | SHA-256 of the operator's stated reason |

> The comment above `ACTION_FIELDS` at `contextd/attest.py:59` says "exactly
> these twelve keys". The tuple holds **thirteen**. The tuple is authoritative;
> the comment's count is a documentation defect, recorded here rather than
> silently corrected, because `attest.py` is on the transaction path.

**Signature:** ECDSA P-256 with SHA-256 over `canonical_bytes(DOMAIN, action)`
(`attest.py:899`), by a key registered in `operator_keys`.

### TTLs

- Default 300 s, maximum 900 s (`attest.py:95–96`, `DEFAULT_TTL_SECONDS`,
  `MAX_TTL_SECONDS`). An action whose `expires_at − issued_at` exceeds the
  maximum is refused at verification (`attest.py:795`).
- Replayable outcomes: default 900 s, maximum 86 400 s
  (`attest.py:1174–1175`). This bounds the right to be *served a stored
  receipt*; the ledger rows it points at are permanent regardless.

### Single-use, and where it is enforced

The nonce lives in `operator_nonces` (`db.py:74–83`) **in the same database as
`events`**, because a nonce must be consumed inside the same transaction as
the append it authorizes and a transaction cannot span two SQLite files
(`db.py:61–66`). Consumption is a conditional `UPDATE` setting
`consumed_event`; the loser of a race sees zero rows affected and is refused
inside the transaction. One signature authorizes exactly one append.

### The intent digest

**Domain separator:** `contextd.OperatorActIntentV1` (`attest.py:57`) —
deliberately *not* the action domain, so the two digests can never be
substituted for one another (pinned by
`tests/test_commerce_redemption.py::test_the_two_digests_use_different_domain_separators`).

It covers only `INTENT_FIELDS` (`attest.py:71–73`): `action`, `scope`,
`arguments`, `content_digest`, `reason_digest` — what is being done, and
nothing about which authorization is doing it. Everything else in
`ACTION_FIELDS` is envelope and is excluded. This is what makes two honest
retries of the same act share a value, and therefore what makes replay
detection possible at all.

### Closed action-class registry

`attest.py`, `ACTION_CLASSES`. A class not listed cannot be authorized:

`note.deliberate`, `loop.add`, `loop.confirm`, `loop.close`, `loop.reopen`,
`loop.dismiss`, `grant.add`, `grant.revoke`, `decision.supersede`,
`mandate.resolve`, `archive.raw_read`, `archive.export`, `archive.backup`,
`archive.restore`, `security.key_register`, `security.key_revoke`,
`pin.adopt`, `pin.barrier`.

`mandate.resolve` (document revision 2) is the operator's attested outcome for
a mandate the core cannot resolve — see the `(mandate, resolve)` row in §7. Its
`arguments` are exactly `{nonce, status}`: the in-flight mandate's nonce, and
`succeeded` or `failed`. A parser should read the recorded status from the
**signed arguments**, not from the event's convenience copy, because the
signature is what makes it an attestation.

### The attestation block as stored

`ATTESTATION_FIELDS` (`attest.py:74–76`), stored in `meta.attestation`:
`action`, `signature`, `key_id`, `signer`, `verified_at`.

`signer` is an enrollment tag (`secure_enclave` in production, or the
test-only software signer). A record whose `signer` names the test signer was
**not** produced by a presence-bound hardware key and must never be read as an
operator act; see `docs/SECURITY.md` §3.

---

## 5. Service signatures, algorithms, and checkpoints

Source: `contextd/ledger_sig.py:45–79`.

Three domain separators, none substitutable for another:

| Domain | Covers |
|---|---|
| `contextd.ServiceEnvelopeV1` | One event's semantic fields |
| `contextd.ServiceTipV1` | A chain tip |
| `contextd.ProtectedCheckpointV1` | A checkpointed chain tip |

### Envelope payload

`ledger_sig.py:520–529`. The **semantic fields, not the raw row**: `id`,
`ts`, `source`, `kind`, `uri`, `content_hash`, `meta` (NULLs as `""`).
Deliberately excludes `chain_hash` — signing a value the attacker recomputes
anyway would buy nothing.

### Tip payload

`ledger_sig.py:688–690`: `{archive_uuid, tip_id, chain_hash}`.

### Checkpoint payload

`ledger_sig.py:969–984`. Four fields — `archive_uuid`, `tip_id`,
`chain_hash`, `key_id` — **plus `alg` if and only if the scheme is not the
classical one.**

This asymmetry is deliberate and a parser must reproduce it: the classical
signature's message is byte-identical to every checkpoint signed before
algorithm identifiers existed, so old records keep verifying. Because the
canonical encoding length-prefixes the field count, a four-field map and a
five-field map cannot collide (`ledger_sig.py:974–982`).

### Algorithm identifiers

`ledger_sig.py:64–79`. Lowercase, hyphenated, and **never re-pointed at a
different scheme**:

- `ecdsa-p256-sha256` — the per-append scheme, and the backfill value for any
  record written before the `alg` column existed. That backfill is a statement
  of fact, not a default: no other scheme existed to have produced them.
- `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` — ML-DSA (FIPS 204), checkpoints only.

Verification **dispatches on the recorded name**. A signature naming one
scheme while its key is registered under another is refused, never verified
under whichever scheme happened to load
(`tests/test_crypto_agility.py::test_verification_dispatches_on_the_recorded_algorithm`).

### Signature tables

Schema version 3 (`db.py:119–151`). Every one carries `alg`:

- `service_keys(key_id, public_pem, created, retired, alg)`
- `service_signatures(event_id, key_id, digest, signature, signed_at, alg)`
- `service_tips(tip_id, chain_hash, key_id, signature, signed_at, cutover, alg)`
- `service_checkpoints(tip_id, alg, chain_hash, key_id, signature, signed_at)`,
  primary key `(tip_id, alg)` — one row per scheme, which is what makes a
  hybrid checkpoint representable.

Signatures are hex-encoded strings. `cutover = 1` marks a tip adopted at
migration: it attests only that the service observed this tip at this time,
and **retroactively authenticates nothing before it**.

**All signatures present on a checkpoint must verify.** A hybrid checkpoint
whose ML-DSA half fails is a broken checkpoint, not a classical one.

---

## 6. Witness and recovery files

Source: `contextd/db.py:154–164`, `db.py:402–408`, `db.py:512–528`,
`db.py:583–616`.

SQLite archives only (§9). Three files beside the database:

| Path | Purpose |
|---|---|
| `chain-witness.json` | The externally recorded chain tip |
| `chain-recovery.json` | The in-flight append journal |
| `chain-witness.lock` | `fcntl.flock` exclusion; holds no data |

**Witness** — exactly three keys, no more and no fewer (`db.py:574`):

```json
{"version": 2, "id": 45557, "chain_hash": "a7389bd7…"}
```

**Recovery journal, version 2** (`db.py:603`):

```json
{"version": 2,
 "previous": {"id": 45556, "chain_hash": "…"},
 "outcomes": [{"id": 45557, "chain_hash": "…"}, …]}
```

**Recovery journal, version 1** (`db.py:600`) — still read, never written:
`{"version": 1, "previous": {…}, "target": {…}}`.

Version 2 exists because an append may commit either the act **or** a
pre-declared refusal in its place, and both sets of bytes are fixed before
`BEGIN`, so both chain hashes are computable then. Under v1, committing a
refusal under the act's journal left a tip matching neither side, and a benign
crash was reported as ledger tampering (`db.py:586–594`).

Constraints a parser must enforce:

- A tip object has **exactly** `{"id", "chain_hash"}` (`db.py:513`).
- `id` is a non-negative int; `chain_hash` is 64 lowercase hex characters,
  **except** that `id == 0` pairs with the empty string (`db.py:516–524`).
- Every outcome must be `previous.id + 1` — a journal describes exactly one
  append (`db.py:612`).
- Outcomes must be distinct (`db.py:614`) and number 1..16
  (`MAX_RECOVERY_OUTCOMES`, `db.py:164`).
- A committed tip outside `{previous} ∪ outcomes` is **still a tamper alarm**
  (`tests/test_commerce_redemption.py::test_a_tip_outside_the_enumerated_outcomes_is_still_a_tamper_alarm`).

Supported state versions on read: 1 and 2 (`db.py:161`).

---

## 7. The event vocabulary

Source: `contextd/schemas.py`. The registry is **closed**: an unregistered
`(source, kind)` cannot carry metadata at all, and undeclared fields inside a
registered type are refused rather than dropped.

### Core types (`schemas.py:286–445`, `EVENT_SCHEMAS`)

| `(source, kind)` | Purpose |
|---|---|
| `(gate, egress_outcome)` | Locally observable result of a dispatch |
| `(eval, outcome)` | Operator's hit/partial/miss verdict on a disclosure |
| `(note, note)` | A deliberate note |
| `(loop, loop)` | Open-loop lifecycle: add/candidate/confirm/close/reopen/dismiss |
| `(grant, grant)` | Delegation grant or revocation |
| `(decision, decision)` | Supersession edge |

### Commerce vocabulary (`schemas.py`, `EVENT_SCHEMAS`)

Five words a transaction path needs that notes and grants do not have:

| `(source, kind)` | Meaning |
|---|---|
| `(mandate, bind)` | The authorization is bound to an intent. Carries an attestation block — it is the event that consumes the nonce. |
| `(mandate, resolve)` | The operator's attested outcome for an in-flight mandate (document revision 2). Also carries an attestation block, for the same reason: it consumes an operator nonce of its own. |
| `(tx, inflight)` | Observed-unresolved: the binding process did not live to record an outcome. Written at most once per mandate, by the core, when something asks — never by guessing. |
| `(tx, execute)` | The act executed; carries `status` (`succeeded`/`failed`) and `outcome_digest`. |
| `(tx, refuse)` | The core refused. Carries digests and a bounded reason, **never** an attestation block — the signature was not honored, and a refusal reproducing a live signed action would put an unconsumed authorization into the permanent record. |

`(mandate, bind)` and `(mandate, resolve)` are the two that carry an
attestation block; the three `tx` types consume no nonce and carry none.

**`(mandate, resolve)` carries two distinct nonces and a reader must not
conflate them.** `nonce` is the authorization *this* event consumes — the
`mandate.resolve` signature — exactly as in every other event here.
`mandate_nonce` is the in-flight mandate being resolved, which is the nonce of
the *original* authorization, consumed long before by its `(mandate, bind)`.
The row also carries `mandate_event`, `status`, `outcome_digest` and
`replay_until`; the receipt itself is the event's `content`.

A resolution is an assertion about the world, not an observation by contextd.
Its receipt is a JSON object carrying `resolved_by: "operator"`, which is what
distinguishes it from a `(tx, execute)` receipt the core actually witnessed. A
reader treating the two as the same kind of evidence is reading it wrong.

**Refusal rows are capped, and the cap is not evidence loss.** One
authorization may durably record at most `[security] max_refusals_per_nonce`
`(tx, refuse)` rows *per distinct reason* (default 64;
`attest.DEFAULT_MAX_REFUSALS_PER_NONCE`). The refusal branch does not consume
the nonce — a refused act must not burn the operator's signature — so without a
cap one authorization could mint refusal rows without limit. Repetitions beyond
the cap are refused identically to the caller but append nothing; since a
refusal event's bytes are a pure function of (authorization, reason), those
repetitions carry no information the recorded ones do not. Each reason keeps
its own budget, so flooding one cannot suppress the first record of another. An
adjudicator should therefore read the *presence* of a refusal reason as
evidence, and its **count as a floor, not a total**.

Refusal reasons are closed (`schemas.py:249–255`): `act_mismatch`,
`already_consumed`, `unverifiable`, `intent_mismatch`, `replay_expired`. The
set is closed because a refusal's exact bytes must be computable *before* the
transaction opens, so the recovery journal can name its chain hash (§6). Free
text would make that impossible.

### Pinning and provenance (`schemas.py:388–445`)

| `(source, kind)` | Meaning |
|---|---|
| `(pin, pin)` | `op` ∈ `observe` (trust on first sight) / `diverge` (bytes changed under a live pin) / `adopt` (**operator-signed; the only op that moves a pin**) |
| `(pin, refuse)` | Gate mode's refusal; reason ∈ `pin_unknown`, `pin_diverged` |
| `(act, act)` | One act labeled with the instruction-position digests in the context that produced it |
| `(act, barrier)` | Operator-signed break in the transitive provenance chain |

Artifact kinds are closed: `skill`, `tool`, `prompt_fragment`
(`schemas.py:268`). Pin statuses: `pinned`, `matched`, `diverged`
(`schemas.py:277`).

### Ingest and harness types

`INGEST_SCHEMAS` (`schemas.py:449–466`): `(fs, file_write)`,
`(fs, file_delete)`, `(claude_code, message)`, `(claude_code, epoch)`,
`(chrome|safari, page_visit)`.

`HARNESS_SCHEMAS` (`schemas.py:470+`): reconciler markers, lineage audit and
calibration runs, and experiment bookkeeping.

### Disclosures

`kind = 'egress'` records what left the gate, typed by `meta.type` against
`EGRESS_TYPES` (`schemas.py:137–232`). Two properties a parser should know:

- Egress rows are **excluded from the FTS index** by the trigger condition
  `new.kind != 'egress'` (`db.py:50`), so disclosures never feed on themselves.
- A unique partial index enforces one outcome per disclosure:
  `idx_egress_outcome_once` on `json_extract(meta,'$.egress_id')` where
  `kind = 'egress_outcome'` (`db.py:40–41`).

### Field kinds

`schemas.py:47–75` defines the type vocabulary: `ident`, `text`, `keyed`
(raw value never written — only a keyed correlation id), `int`, `number`,
`bool`, `int_list`, `str_list`, `digest` (64 lowercase hex), `scope`,
`scope_obj`, `instant` (timezone-aware ISO-8601 normalized to UTC), `enum`,
`json`, `derivation`, `attestation`, `artifact`.

---

## 8. Reading a record correctly

Three rules that a naive parser gets wrong:

1. **`content IS NULL` is meaningful, not missing data.** Verdict and
   instrument records — `health`, `restore_drill`, `lineage_audit`,
   experiment rows — are content-free by construction so they can never enter
   FTS and be recalled back into a model's context.
2. **`claimed_client`, `actor`, `authority` and `role` carry zero assurance.**
   They are self-asserted caller labels. Only a verified `attestation` block
   (§4) grounds operator authority. `docs/SECURITY.md` §3 is the contract.
3. **An event's presence evidences that it was recorded and not removed.** It
   does not evidence that its content is true. Signing is not fact-checking.

---

## 9. What this format does NOT specify

Stated plainly, because silence here would be read as coverage.

- **PostgreSQL wire and storage details.** The PostgreSQL backend
  (`contextd/backends/postgres.py`) reproduces the *semantics* above — same
  columns, same chain hash, same closed vocabulary — but its physical layout,
  the `chain_tip` singleton row, the `SECURITY DEFINER` tip-advance function,
  the trigger bodies, and the role/privilege model are **not specified here**
  and may change. A Postgres archive additionally has **no witness or recovery
  files** (§6): the tip lives in the database. Read `postgres.py:85–115` for
  the trust consequences of that.
- **Egress payload schemas.** `EGRESS_TYPES` (`schemas.py:137–232`) is a live
  registry driven by what the gate and the harness disclose. It is versioned
  by the archive schema, not by this document, and additional types are
  expected. Only the *rule* is frozen: the registry is closed and undeclared
  fields are refused.
- **The blob store layout.** Oversized payloads are content-addressed outside
  the database; `content_hash` names them. The on-disk arrangement is not
  specified.
- **Backup bundle (`.ctxbackup`) and sealed export formats.** Both are
  manifest-hashed and service-signed, and both are **SQLite-only**
  (`contextd/backup.py:834–839` uses SQLite's online backup API, which has no
  PostgreSQL counterpart). Their internal layout is out of scope here.
- **Key enrollment, Secure Enclave handles, and the `.sekey` blob.** Device-
  bound and platform-specific; see `docs/OPERATOR_CEREMONY.md`.
- **The FTS5 index.** Derived, rebuildable, and not evidence. Nothing in the
  chain or any signature covers it.
- **Any semantic claim about content.** This format specifies bytes and their
  integrity. It says nothing about whether a record's assertions are true, and
  `provenance.py` deliberately refuses to.

---

## 10. Minimal verification recipe

For an adjudicator with the raw SQLite file and nothing else:

1. Read rows ordered by `id`. Confirm ids are contiguous from 1.
2. Recompute each `chain_hash` by §2. Confirm each row's `prev_hash` equals
   the previous row's `chain_hash` (empty string for `id = 1`).
3. If `chain-witness.json` is present, confirm it names the last row (§6).
4. For any row with a `service_signatures` entry: rebuild the envelope
   payload (§5), canonically encode it under `contextd.ServiceEnvelopeV1`
   (§3), and verify under the algorithm named in that row's `alg`, using the
   public key from `service_keys`.
5. For each `service_checkpoints` row: rebuild the checkpoint payload (§5) —
   including `alg` only for non-classical schemes — and verify. All rows for
   a `tip_id` must verify.
6. For any row whose `meta.attestation` is present: canonically encode
   `attestation.action` under `contextd.OperatorActionV1` (§3, §4) and verify
   the ECDSA P-256 signature against the `operator_keys` entry for `key_id`.

Steps 1–3 need only SHA-256. Steps 4–6 need a signature verifier and no part
of this codebase.

The frozen vectors in `tests/vectors/operator_action_v1.json` freeze
input → bytes → digest, so a second implementation in another language can be
checked against exact bytes before it is trusted against a real archive.

---

## 11. The exported checkpoint log (document revision 2)

Source: `contextd/ledger_sig.py`, `append_checkpoint_log` /
`read_checkpoint_log` / `verify_checkpoint_log`.
CLI: `ctx security checkpoint export <dest>` and
`ctx security checkpoint verify <dest>`.

This is the one format in this document that does **not** live inside the
archive, and that is its entire purpose.

### Why it exists

§5's `service_checkpoints` rows sit inside the archive they attest. Against an
attacker who owns the storage — the SQLite file, or a PostgreSQL superuser —
they establish nothing on their own: rewriting the chain and rewriting the
checkpoint rows require the same privilege, so the attacker produces an archive
that is internally consistent at whatever state they chose. Every local check
passes.

Moving the same signed records somewhere the archive's owner cannot rewrite
removes that freedom. The archive can then be made to say it ends at `#400`,
but a signature the attacker could not forge still says it once reached `#900`,
and the two no longer agree.

### The format

**JSON Lines.** One JSON object per line, UTF-8, `\n`-terminated, appended with
`O_APPEND` and fsynced. Nothing already written is ever modified — which is
what lets the destination be genuinely append-only storage, and what bounds an
interrupted write to the trailing line.

Each line is a §5 checkpoint record plus two envelope keys:

| Field | Meaning |
|---|---|
| `v` | Log record version, currently `1`. |
| `exported_at` | Unix seconds when the line was appended. **Unsigned — see below.** |
| `archive_uuid`, `tip_id`, `chain_hash`, `key_id`, `signature` | The §5 checkpoint record, unchanged. |
| `alg`, `hybrid` | Present only in hybrid mode, exactly as in §5. |

The signature covers the §5 **checkpoint payload only** —
`{archive_uuid, tip_id, chain_hash, key_id}`, plus `alg` for non-classical
schemes — canonically encoded under `contextd.ProtectedCheckpointV1` (§3).

`v` and `exported_at` are deliberately outside it. The checkpoint payload is
frozen so that every record signed before this section existed keeps verifying
byte-for-byte, and buying a signed timestamp would have cost that. So
**`exported_at` is unauthenticated**: it is for the operator's own ordering,
and it is not evidence of when anything happened.

### Verifying a log

For each line: parse it, check `v`, rebuild the payload and verify every
signature it carries (§5 — *all* of them must verify), confirm `archive_uuid`
matches, then compare against the archive:

- `tip_id` greater than the archive's last event id → **ROLLBACK**: the archive
  no longer reaches a tip a signature says it had.
- the archive's `chain_hash` at `tip_id` differs from the record's →
  **REWRITTEN**.
- a line that does not parse is reported, never skipped — an unparseable line
  is what truncation and corruption look like.

**Every record must be checked, not just the newest.** An attacker who rolls
the archive back and then exports a fresh checkpoint at the rolled-back tip
produces a log whose last line is perfectly valid. The earlier lines are the
evidence, and a verifier that stops at the newest record finds nothing.

### What this does NOT prove

Stated here because the mechanism is easy to over-read, and returned as data by
`ledger_sig.checkpoint_log_claim` so a caller cannot quietly upgrade it:

- **On one machine under one uid this is advisory.** The uid that can rewrite
  the archive can rewrite the log. It detects accident, bug, and partial
  compromise — not an attacker who owns the account. The mechanism becomes
  load-bearing only when the destination is somewhere the archive's owner
  cannot write: another host, an append-only bucket, a different uid, or
  immutable storage. Nothing in the code can verify that the destination has
  that property; `ctx security doctor` reports separately whether the
  configured checkpoint destination is writable by this uid.
- **Completeness is not proved.** A log can be truncated, and a truncated log
  verifies — it is a valid log of fewer checkpoints. Only the destination's own
  append-only guarantee can rule that out.
- **A rollback to a state older than the first exported checkpoint is not
  detected**, because no exported record covers it.
- **Nothing about content.** A checkpoint carries no archive data by design —
  the destination is by definition somewhere the operator does not fully
  control, so it must not carry any.
