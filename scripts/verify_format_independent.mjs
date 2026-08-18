#!/usr/bin/env node
//
// An independent implementation of docs/FORMAT.md.
//
// WHY THIS EXISTS
// ---------------
// docs/FORMAT.md promises that an adjudicator in 2035, holding the raw bytes
// and no working copy of contextd, can parse a record, recompute its hash
// chain, and check a signature. `tests/test_format_spec.py` is evidence for
// that promise only in the weakest sense: it is the same repository, the same
// language, the same author's understanding of their own document, and it
// imports the very constants it checks. A document can be word-perfect
// against code that is itself the only thing that ever reads it and still be
// unusable by a stranger.
//
// This file is the stranger. It is written in JavaScript against the prose of
// FORMAT.md, and it imports NOTHING from contextd -- not the package, not a
// helper, not a constant. Every rule below is transcribed from the document,
// with the section it came from, and the citations are to FORMAT.md rather
// than to the Python so that a wrong document produces a wrong verifier and
// the disagreement surfaces here instead of in 2035.
//
// WHAT "INDEPENDENT" BUYS AND WHAT IT DOES NOT
// --------------------------------------------
// Independent language, independent crypto (Node's OpenSSL rather than
// Python's `cryptography`), independent SQLite driver, independent encoder.
// It does NOT buy independent *specification*: this reads the same FORMAT.md
// the Python was checked against, so a rule that is wrong in the document and
// wrong in the code the same way is invisible to both. What it does catch is
// the far more common failure -- a document that is silent, ambiguous, or
// stale where the code has moved on.
//
// SPEC GAPS ARE A FIRST-CLASS RESULT
// ----------------------------------
// This verifier records, separately from pass/fail, every point at which it
// had to reach for knowledge that FORMAT.md does not contain. Those are
// `spec_gap` findings. They are the entire reason a second implementation is
// worth writing: the Python cannot report them, because the Python already
// knows.
//
// USAGE
//   node scripts/verify_format_independent.mjs <archive-dir-or-db> [options]
//
//   --vectors <path>       canonical-encoding vectors (default:
//                          <repo>/tests/vectors/operator_action_v1.json)
//   --json                 emit the full findings object as JSON
//   --quiet                suppress the human-readable report
//   --fail-on-spec-gap     exit non-zero when a spec gap is recorded
//
// EXIT CODES
//   0  every check that could be run, passed
//   1  a verification check failed (or a spec gap, under --fail-on-spec-gap)
//   2  the archive could not be opened / usage error

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { dirname, join, resolve } from 'node:path';
import { argv, exit, stdout } from 'node:process';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

const findings = {
  pass: [], fail: [], warn: [], spec_gap: [], spec_mismatch: [], info: {},
};

const pass = (check, detail) => findings.pass.push({ check, detail });
const fail = (check, detail) => findings.fail.push({ check, detail });
const warn = (check, detail) => findings.warn.push({ check, detail });

/**
 * Record a place where FORMAT.md says something the archive contradicts.
 *
 * This is the loudest thing this program can emit and it is deliberately kept
 * distinct from `fail`. A `fail` means the ARCHIVE is wrong -- a broken chain,
 * a forged signature. A `spec_mismatch` means the DOCUMENT is wrong: the bytes
 * are fine and the prose does not describe them. FORMAT.md's own preamble
 * says "Where this document and the code disagree, the code is correct and
 * this document has a bug", and this is the finding class that says so.
 */
const specMismatch = (section, claim, reality, consequence) =>
  findings.spec_mismatch.push({ section, claim, reality, consequence });

/**
 * Record a place where FORMAT.md does not say what a stranger needs to know.
 *
 * `needed` is what the verifier was trying to do; `absent` is what the
 * document does not contain; `workaround` is what this implementation did
 * instead, which by definition came from somewhere other than the document.
 */
const specGap = (section, needed, absent, workaround) =>
  findings.spec_gap.push({ section, needed, absent, workaround });

// ---------------------------------------------------------------------------
// FORMAT.md section 2 -- the chain hash
// ---------------------------------------------------------------------------
//
//   chain_hash(row) = SHA256(
//         prev_hash            || 0x1F
//      || decimal(id)          || 0x1F
//      || ts                   || 0x1F
//      || source               || 0x1F
//      || kind                 || 0x1F
//      || (uri          or "") || 0x1F
//      || (content      or "") || 0x1F
//      || (content_hash or "") || 0x1F
//      || (meta         or "") || 0x1F
//   )
//
// Nine fields; 0x1F terminates EVERY field including the last; NULL becomes
// the empty string; id is its decimal string; every part is UTF-8; prev_hash
// for event 1 is the empty string; the output is 64 lowercase hex characters.

const US = Buffer.from([0x1f]);

function chainHash(row) {
  const parts = [
    row.prev_hash ?? '',
    String(row.id),
    row.ts,
    row.source,
    row.kind,
    row.uri ?? '',
    row.content ?? '',
    row.content_hash ?? '',
    row.meta ?? '',
  ];
  const h = createHash('sha256');
  for (const part of parts) {
    h.update(Buffer.from(part, 'utf8'));
    h.update(US);
  }
  return h.digest('hex');
}

// ---------------------------------------------------------------------------
// FORMAT.md section 3 -- canonical encoding
// ---------------------------------------------------------------------------
//
//   canonical(domain, value) := utf8(domain) || 0x0A || enc(value)
//
//   enc(str)  := 's' || u64_be(len(utf8_bytes)) || utf8_bytes      # NFC
//   enc(int)  := 'i' || i64_be(value)
//   enc(list) := 'l' || u64_be(n) || enc(v_1) .. enc(v_n)
//   enc(map)  := 'm' || u64_be(n) || (enc(k_i) || enc(v_i)) for keys sorted
//                by their UTF-8 bytes
//
// Refused unconditionally: float, bool, null, bytes, non-NFC strings, ints
// outside int64, non-string map keys. Bounds: depth <= 8, <= 4096 items.

const MAX_DEPTH = 8;
const MAX_ITEMS = 4096;

class CanonicalError extends Error {}

function u64be(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

function i64be(n) {
  const b = Buffer.alloc(8);
  b.writeBigInt64BE(BigInt(n));
  return b;
}

function encStr(value) {
  // NFC is required: two visually identical strings must not produce two
  // different signatures (FORMAT.md section 3).
  if (value.normalize('NFC') !== value) {
    throw new CanonicalError('string is not NFC-normalized');
  }
  const raw = Buffer.from(value, 'utf8');
  return Buffer.concat([Buffer.from('s'), u64be(raw.length), raw]);
}

function enc(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new CanonicalError('depth bound exceeded');
  if (typeof value === 'boolean') {
    throw new CanonicalError('bool is refused: it would encode as 0/1');
  }
  if (value === null || value === undefined) {
    throw new CanonicalError('null is refused: omit the key instead');
  }
  if (typeof value === 'string') return encStr(value);
  if (typeof value === 'number' || typeof value === 'bigint') {
    // JSON gives no int/float distinction, so the refusal of floats is
    // enforced here rather than inherited from a type system.
    if (typeof value === 'number' && !Number.isInteger(value)) {
      throw new CanonicalError('float is refused: IEEE-754 is not portable');
    }
    if (typeof value === 'number' && !Number.isSafeInteger(value)) {
      throw new CanonicalError('integer exceeds exact JS range; refusing');
    }
    const big = BigInt(value);
    if (big < -(2n ** 63n) || big >= 2n ** 63n) {
      throw new CanonicalError('integer out of int64 range');
    }
    return Buffer.concat([Buffer.from('i'), i64be(big)]);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    throw new CanonicalError('bytes is refused');
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_ITEMS) throw new CanonicalError('list bound exceeded');
    return Buffer.concat([
      Buffer.from('l'),
      u64be(value.length),
      ...value.map((v) => enc(v, depth + 1)),
    ]);
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length > MAX_ITEMS) throw new CanonicalError('map bound exceeded');
    // "Map keys sort by UTF-8 byte order, not locale and not code point
    // order" (FORMAT.md section 3). JavaScript's default string comparison is
    // by UTF-16 code unit, which disagrees with UTF-8 byte order above the
    // BMP, so the raw bytes are compared here on purpose.
    entries.sort((a, b) =>
      Buffer.compare(Buffer.from(a[0], 'utf8'), Buffer.from(b[0], 'utf8')));
    const out = [Buffer.from('m'), u64be(entries.length)];
    for (const [k, v] of entries) {
      if (typeof k !== 'string') throw new CanonicalError('map keys must be strings');
      out.push(encStr(k), enc(v, depth + 1));
    }
    return Buffer.concat(out);
  }
  throw new CanonicalError(`unsupported type ${typeof value}`);
}

function canonicalBytes(domain, value) {
  if (!domain || domain.includes('\n')) {
    throw new CanonicalError('domain must be non-empty and newline-free');
  }
  return Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0x0a]), enc(value)]);
}

function canonicalDigest(domain, value) {
  return createHash('sha256').update(canonicalBytes(domain, value)).digest('hex');
}

// ---------------------------------------------------------------------------
// signature verification
// ---------------------------------------------------------------------------
//
// FORMAT.md section 5: verification DISPATCHES ON THE RECORDED NAME. A
// signature naming one scheme while its key is registered under another is
// refused, never verified under whichever scheme happened to load. That rule
// is reproduced literally below: the `alg` column decides, and a mismatch
// between the recorded name and the key's own algorithm is a failure rather
// than a fallback.

const ALG_ECDSA_P256 = 'ecdsa-p256-sha256';
const ML_DSA_ALGS = new Set(['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87']);

function keyAlgorithmName(publicKey) {
  // Node reports ML-DSA keys as asymmetricKeyType 'ml-dsa-44' etc., and EC
  // keys as 'ec' with a named curve in asymmetricKeyDetails.
  const type = publicKey.asymmetricKeyType;
  if (type === 'ec') {
    const curve = publicKey.asymmetricKeyDetails?.namedCurve;
    return curve === 'prime256v1' ? ALG_ECDSA_P256 : `ec:${curve}`;
  }
  return type;
}

/**
 * Verify `signature` over `message` under exactly `alg`.
 *
 * Returns {ok, why}. Never falls back to another scheme: that fallback is the
 * exact behaviour FORMAT.md section 5 forbids.
 */
function verifySignature(alg, publicKey, message, signature) {
  const keyAlg = keyAlgorithmName(publicKey);
  if (alg === ALG_ECDSA_P256) {
    if (keyAlg !== ALG_ECDSA_P256) {
      return { ok: false, why: `alg says ${alg} but the key is ${keyAlg}` };
    }
    // `cryptography`'s ec.ECDSA(SHA256) emits a DER-encoded (r,s), which is
    // Node's default dsaEncoding; it is named explicitly rather than assumed.
    const ok = cryptoVerify('sha256', message,
      { key: publicKey, dsaEncoding: 'der' }, signature);
    return { ok, why: ok ? null : 'ECDSA P-256 signature does not verify' };
  }
  if (ML_DSA_ALGS.has(alg)) {
    if (keyAlg !== alg) {
      return { ok: false, why: `alg says ${alg} but the key is ${keyAlg}` };
    }
    // ML-DSA is a pure signature scheme: no separate digest algorithm.
    const ok = cryptoVerify(null, message, publicKey, signature);
    return { ok, why: ok ? null : `${alg} signature does not verify` };
  }
  return { ok: false, why: `unknown algorithm ${JSON.stringify(alg)}` };
}

// ---------------------------------------------------------------------------
// archive access
// ---------------------------------------------------------------------------

function tableExists(db, name) {
  const row = db
    .prepare("SELECT 1 AS present FROM sqlite_master WHERE type='table' AND name=?")
    .get(name);
  return Boolean(row);
}

function allRows(db, sql, ...params) {
  return db.prepare(sql).all(...params);
}

/** Some drivers hand back TEXT-affinity NULLs as null and BLOBs as Uint8Array. */
function asBuffer(value) {
  if (value === null || value === undefined) return null;
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  return null;
}

// ---------------------------------------------------------------------------
// check 1 -- the events table shape and its append-only triggers (section 1)
// ---------------------------------------------------------------------------

const EXPECTED_COLUMNS = [
  'id', 'ts', 'source', 'kind', 'uri', 'content',
  'content_hash', 'meta', 'prev_hash', 'chain_hash',
];

function checkEventsTable(db) {
  if (!tableExists(db, 'events')) {
    fail('events-table', 'no `events` table: this is not a contextd archive');
    return false;
  }
  const cols = allRows(db, 'PRAGMA table_info(events)').map((r) => r.name);
  if (JSON.stringify(cols) !== JSON.stringify(EXPECTED_COLUMNS)) {
    fail('events-columns',
      `section 1 names ten columns in order ${EXPECTED_COLUMNS.join(', ')}; ` +
      `the archive has ${cols.join(', ')}`);
    return false;
  }
  pass('events-columns', 'ten columns, in the order section 1 gives');

  // Section 1: "A parser that finds no such trigger is looking at an archive
  // whose append-only property was removed ... the DDL guarantee is gone and
  // should be reported as such."
  const triggers = allRows(db,
    "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='events'")
    .map((r) => r.name);
  for (const required of ['events_no_update', 'events_no_delete']) {
    if (triggers.includes(required)) {
      pass('append-only-trigger', `${required} present`);
    } else {
      warn('append-only-trigger',
        `${required} is ABSENT. Section 1: the chain can still be recomputed, ` +
        `but the database-enforced append-only guarantee has been removed from ` +
        `this archive and must be reported as such.`);
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// check 1b -- the `source` vocabulary section 1 enumerates
// ---------------------------------------------------------------------------
//
// Section 1's column table enumerates the producing planes and states that
// the list is closed -- exactly the first elements of section 7's
// `(source, kind)` registry keys.
//
// This list is transcribed from that enumeration and from nowhere else. It is
// deliberately NOT derived from the archive it is checking, because a check
// that reads its expectations out of the data it is checking cannot fail.
//
// HISTORY: this check is the one that caught the document drifting. Section 1
// originally listed fourteen planes and omitted `health`, which is written to
// every running archive roughly 48 times a day by a launchd-scheduled hook,
// and which section 8 named while section 1 did not. That is recorded in
// FORMAT.md's Errata section and fixed in its body; the check stays, because
// the next omission will look exactly like the last one.

const DOCUMENTED_SOURCES = [
  'note', 'fs', 'chrome', 'safari', 'claude_code', 'gate', 'eval', 'loop',
  'grant', 'decision', 'mandate', 'tx', 'pin', 'act', 'health',
];

function checkSourceVocabulary(db) {
  const rows = allRows(db,
    'SELECT source, COUNT(*) AS n FROM events GROUP BY source ORDER BY source');
  const present = rows.map((r) => r.source);
  findings.info.sources = present;
  const documented = new Set(DOCUMENTED_SOURCES);
  const undocumented = rows.filter((r) => !documented.has(r.source));
  if (undocumented.length === 0) {
    pass('source-vocabulary',
      `every source in the archive (${present.join(', ')}) appears in ` +
      `section 1's enumeration`);
    return;
  }
  for (const row of undocumented) {
    specMismatch(
      'section 1 (the `events` table, `source` column)',
      `section 1 enumerates the producing planes as ${DOCUMENTED_SOURCES.join(', ')}`,
      `this archive contains ${row.n} row(s) with source=${JSON.stringify(row.source)}, ` +
      `which that enumeration does not include`,
      `a parser built from section 1 alone has no rule for these rows. Note ` +
      `that section 8 rule 1 names \`${row.source}\` records itself ("Verdict and ` +
      `instrument records - health, restore_drill, lineage_audit, experiment ` +
      `rows - are content-free by construction"), so the document is also ` +
      `internally inconsistent: section 8 discusses a producing plane that ` +
      `section 1 does not list.`,
    );
  }
}

// ---------------------------------------------------------------------------
// check 2 -- recompute the whole chain (section 2, section 10 steps 1-2)
// ---------------------------------------------------------------------------

function checkChain(db) {
  const rows = allRows(db,
    'SELECT id, ts, source, kind, uri, content, content_hash, meta, ' +
    'prev_hash, chain_hash FROM events ORDER BY id');
  findings.info.events = rows.length;
  if (rows.length === 0) {
    warn('chain', 'the archive holds no events; nothing to recompute');
    return { rows, tip: null };
  }

  // Section 10 step 1: confirm ids are contiguous from 1.
  let expectedId = 1;
  for (const row of rows) {
    if (Number(row.id) !== expectedId) {
      fail('chain-contiguity',
        `section 10 step 1: ids must be contiguous from 1; expected ` +
        `${expectedId}, found ${row.id}`);
      return { rows, tip: null };
    }
    expectedId += 1;
  }
  pass('chain-contiguity', `ids 1..${rows.length} are contiguous`);

  let prev = '';
  let tsWarnings = 0;
  let lastTs = '';
  for (const row of rows) {
    const expect = chainHash({ ...row, prev_hash: prev });
    if ((row.prev_hash ?? '') !== prev) {
      fail('chain-link',
        `event ${row.id}: stored prev_hash ${JSON.stringify(row.prev_hash)} ` +
        `is not the previous row's chain_hash ${JSON.stringify(prev)}`);
      return { rows, tip: null };
    }
    if (row.chain_hash !== expect) {
      fail('chain-hash',
        `event ${row.id}: recomputing section 2 gives ${expect}, ` +
        `the archive stores ${JSON.stringify(row.chain_hash)}`);
      return { rows, tip: null };
    }
    if (!/^[0-9a-f]{64}$/.test(row.chain_hash)) {
      fail('chain-hash-shape', `event ${row.id}: chain_hash is not 64 lowercase hex`);
      return { rows, tip: null };
    }
    // Section 2: "A parser must not treat a ts inversion as tampering."
    if (row.ts < lastTs) tsWarnings += 1;
    lastTs = row.ts;
    prev = row.chain_hash;
  }
  pass('chain-hash',
    `recomputed ${rows.length} chain hashes from section 2's recipe; ` +
    `every stored value matches`);
  findings.info.ts_warnings = tsWarnings;
  if (tsWarnings > 0) {
    warn('ts-inversion',
      `${tsWarnings} timestamp inversion(s); section 2 says concurrent writers ` +
      `produce these and they are NOT chain errors`);
  }
  const last = rows[rows.length - 1];
  return { rows, tip: { id: Number(last.id), chain_hash: last.chain_hash } };
}

// ---------------------------------------------------------------------------
// check 3 -- witness and recovery files (section 6, section 10 step 3)
// ---------------------------------------------------------------------------

function checkWitness(archiveDir, tip) {
  const path = join(archiveDir, 'chain-witness.json');
  if (!existsSync(path)) {
    findings.info.witness = 'absent';
    warn('witness', 'no chain-witness.json beside the database (section 6 ' +
      'makes it optional for a parser; section 9 excludes it for Postgres)');
    return;
  }
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    fail('witness-parse', `chain-witness.json is not JSON: ${err.message}`);
    return;
  }
  // Section 6: "exactly three keys, no more and no fewer".
  const keys = Object.keys(doc).sort();
  if (JSON.stringify(keys) !== JSON.stringify(['chain_hash', 'id', 'version'])) {
    fail('witness-shape',
      `section 6: the witness has exactly {version, id, chain_hash}; found ` +
      `{${keys.join(', ')}}`);
    return;
  }
  if (!Number.isInteger(doc.id) || doc.id < 0) {
    fail('witness-shape', 'section 6: id must be a non-negative int');
    return;
  }
  const hashOk = doc.id === 0
    ? doc.chain_hash === ''
    : /^[0-9a-f]{64}$/.test(doc.chain_hash);
  if (!hashOk) {
    fail('witness-shape',
      'section 6: chain_hash is 64 lowercase hex, except that id == 0 pairs ' +
      'with the empty string');
    return;
  }
  pass('witness-shape', `witness is well formed (version ${doc.version})`);

  if (tip === null) {
    warn('witness-tip', 'chain did not verify, so the witness was not compared');
    return;
  }
  if (doc.id !== tip.id || doc.chain_hash !== tip.chain_hash) {
    fail('witness-tip',
      `section 10 step 3: the witness names id ${doc.id} / ` +
      `${String(doc.chain_hash).slice(0, 16)}..., but the last row is ` +
      `id ${tip.id} / ${tip.chain_hash.slice(0, 16)}...`);
    return;
  }
  pass('witness-tip', `the witness names the last row (id ${tip.id})`);
}

function checkRecoveryJournal(archiveDir) {
  const path = join(archiveDir, 'chain-recovery.json');
  if (!existsSync(path)) {
    findings.info.recovery_journal = 'absent';
    return;
  }
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    fail('recovery-parse', `chain-recovery.json is not JSON: ${err.message}`);
    return;
  }
  findings.info.recovery_journal = `version ${doc.version}`;
  // Section 6: supported state versions on read are 1 and 2.
  if (![1, 2].includes(doc.version)) {
    fail('recovery-version',
      `section 6: supported state versions on read are 1 and 2; found ${doc.version}`);
    return;
  }
  const tipShapeOk = (t) =>
    t && typeof t === 'object' &&
    JSON.stringify(Object.keys(t).sort()) === JSON.stringify(['chain_hash', 'id']);
  if (!tipShapeOk(doc.previous)) {
    fail('recovery-shape', 'section 6: a tip object has exactly {id, chain_hash}');
    return;
  }
  if (doc.version === 2) {
    const outcomes = doc.outcomes;
    if (!Array.isArray(outcomes) || outcomes.length < 1 || outcomes.length > 16) {
      fail('recovery-outcomes',
        'section 6: outcomes must number 1..16 (MAX_RECOVERY_OUTCOMES)');
      return;
    }
    const seen = new Set();
    for (const o of outcomes) {
      if (!tipShapeOk(o)) {
        fail('recovery-shape', 'section 6: every outcome is exactly {id, chain_hash}');
        return;
      }
      if (o.id !== doc.previous.id + 1) {
        fail('recovery-outcomes',
          `section 6: every outcome must be previous.id + 1 ` +
          `(${doc.previous.id + 1}); found ${o.id}`);
        return;
      }
      if (seen.has(o.chain_hash)) {
        fail('recovery-outcomes', 'section 6: outcomes must be distinct');
        return;
      }
      seen.add(o.chain_hash);
    }
  }
  pass('recovery-journal', `journal version ${doc.version} satisfies section 6`);
}

// ---------------------------------------------------------------------------
// check 4 -- the frozen canonical vectors (section 3, section 10 closing note)
// ---------------------------------------------------------------------------

function checkVectors(vectorPath) {
  if (!existsSync(vectorPath)) {
    fail('vectors', `no vector file at ${vectorPath}`);
    return;
  }
  const doc = JSON.parse(readFileSync(vectorPath, 'utf8'));
  const domain = doc.domain;
  if (!domain) {
    fail('vectors', 'the vector file declares no domain separator');
    return;
  }
  let checked = 0;
  for (const vector of doc.vectors) {
    let bytes;
    try {
      bytes = canonicalBytes(domain, vector.action);
    } catch (err) {
      fail('vector-encode',
        `${vector.name}: this implementation of section 3 refused the input: ${err.message}`);
      continue;
    }
    const hex = bytes.toString('hex');
    if (hex !== vector.canonical_hex) {
      fail('vector-bytes',
        `${vector.name}: section 3 re-implemented in JavaScript produced ` +
        `different bytes than the frozen vector.\n` +
        `      expected ${vector.canonical_hex.length / 2} bytes: ` +
        `${vector.canonical_hex.slice(0, 96)}...\n` +
        `      produced ${bytes.length} bytes: ${hex.slice(0, 96)}...`);
      continue;
    }
    const digest = createHash('sha256').update(bytes).digest('hex');
    if (digest !== vector.digest) {
      fail('vector-digest',
        `${vector.name}: digest ${digest} != frozen ${vector.digest}`);
      continue;
    }
    checked += 1;
  }
  findings.info.vectors = { file: vectorPath, checked, total: doc.vectors.length };
  if (checked === doc.vectors.length) {
    pass('vectors',
      `${checked}/${doc.vectors.length} frozen vectors reproduce byte-for-byte ` +
      `from section 3's prose`);
  }

  // The refusals in section 3 are load-bearing: each closes a
  // signature-substitution class. A verifier that accepts them is not
  // implementing this encoding, so they are exercised here rather than
  // assumed.
  const refusals = [
    ['float', { x: 1.5 }],
    ['bool', { x: true }],
    ['null', { x: null }],
  ];
  for (const [name, value] of refusals) {
    let refused = false;
    try {
      canonicalBytes(domain, value);
    } catch (err) {
      refused = err instanceof CanonicalError;
    }
    if (refused) {
      pass('vector-refusal', `section 3's refusal of ${name} is implemented`);
    } else {
      fail('vector-refusal',
        `section 3 refuses ${name} unconditionally; this encoder accepted it`);
    }
  }
}

// ---------------------------------------------------------------------------
// check 5 -- service signatures (section 5, section 10 step 4)
// ---------------------------------------------------------------------------

function loadServiceKeys(db) {
  const keys = new Map();
  if (!tableExists(db, 'service_keys')) return keys;
  for (const row of allRows(db, 'SELECT key_id, public_pem, alg FROM service_keys')) {
    try {
      keys.set(row.key_id, {
        key: createPublicKey(row.public_pem),
        alg: row.alg,
      });
    } catch (err) {
      fail('service-key', `key ${row.key_id} has an unloadable public_pem: ${err.message}`);
    }
  }
  return keys;
}

function checkServiceSignatures(db, keys) {
  if (!tableExists(db, 'service_signatures')) {
    findings.info.service_signatures = 0;
    return;
  }
  const rows = allRows(db,
    'SELECT event_id, key_id, digest, signature, alg FROM service_signatures ' +
    'ORDER BY event_id');
  findings.info.service_signatures = rows.length;
  if (rows.length === 0) {
    warn('service-signature', 'the archive carries no service signatures');
    return;
  }
  let verified = 0;
  for (const sig of rows) {
    const row = db.prepare(
      'SELECT id, ts, source, kind, uri, content_hash, meta FROM events WHERE id = ?')
      .get(sig.event_id);
    if (!row) {
      fail('service-signature', `signature names event ${sig.event_id}, which is absent`);
      continue;
    }
    // Section 5, envelope payload: the SEMANTIC fields, not the raw row.
    // NULLs as "". chain_hash is deliberately excluded.
    const payload = {
      id: Number(row.id),
      ts: row.ts,
      source: row.source,
      kind: row.kind,
      uri: row.uri ?? '',
      content_hash: row.content_hash ?? '',
      meta: row.meta ?? '',
    };
    const message = canonicalBytes('contextd.ServiceEnvelopeV1', payload);

    const recomputed = createHash('sha256').update(message).digest('hex');
    if (sig.digest && sig.digest !== recomputed) {
      fail('service-signature-digest',
        `event ${sig.event_id}: the stored digest ${sig.digest} is not the ` +
        `canonical digest of the envelope this document describes (${recomputed})`);
      continue;
    }

    const key = keys.get(sig.key_id);
    if (!key) {
      fail('service-signature',
        `event ${sig.event_id}: no service_keys row for key_id ${sig.key_id}`);
      continue;
    }
    const result = verifySignature(sig.alg, key.key, message,
      Buffer.from(sig.signature, 'hex'));
    if (!result.ok) {
      fail('service-signature',
        `event ${sig.event_id}: ${result.why} (alg ${sig.alg}, key ${sig.key_id})`);
      continue;
    }
    verified += 1;
  }
  if (verified === rows.length) {
    pass('service-signature',
      `${verified}/${rows.length} event envelope signature(s) verify under the ` +
      `algorithm each row names`);
  }
  findings.info.service_signatures_verified = verified;
}

// ---------------------------------------------------------------------------
// check 6 -- tips and checkpoints (section 5, section 10 step 5)
// ---------------------------------------------------------------------------
//
// Both payloads begin with `archive_uuid`, and this is where FORMAT.md runs
// out. See `resolveArchiveUuid`.

function resolveArchiveUuid(db) {
  // Section 4, "Where archive_uuid comes from", and section 10 step 5: read it
  // as `SELECT uuid FROM archive_identity WHERE singleton = 1`.
  //
  // This query is transcribed from the document. It did not used to be: until
  // the errata, FORMAT.md named `archive_uuid` in three payloads and never
  // said where to read it, so this function found the table by inspecting the
  // SQLite schema and recorded a spec gap for having had to. The gap is closed
  // and the workaround is gone.
  if (!tableExists(db, 'archive_identity')) {
    specGap(
      'section 4 / section 10 step 5',
      'read archive_uuid, the first field of the tip and checkpoint payloads',
      'the document says it lives in archive_identity, but this archive has no ' +
      'such table',
      'none available; tip and checkpoint payloads cannot be rebuilt',
    );
    return null;
  }
  const row = db.prepare(
    'SELECT uuid FROM archive_identity WHERE singleton = 1').get();
  return row ? row.uuid : null;
}

function checkTips(db, keys, archiveUuid, tip) {
  if (!tableExists(db, 'service_tips')) return;
  const rows = allRows(db,
    'SELECT tip_id, chain_hash, key_id, signature, cutover, alg FROM service_tips ' +
    'ORDER BY tip_id');
  findings.info.service_tips = rows.length;
  if (rows.length === 0) return;
  if (archiveUuid === null) {
    fail('service-tip',
      'the archive has tip signatures but no archive uuid could be resolved, so ' +
      'the tip payload cannot be rebuilt');
    return;
  }
  let verified = 0;
  for (const row of rows) {
    // Section 5, tip payload: {archive_uuid, tip_id, chain_hash}.
    const payload = {
      archive_uuid: archiveUuid,
      tip_id: Number(row.tip_id),
      chain_hash: row.chain_hash,
    };
    const message = canonicalBytes('contextd.ServiceTipV1', payload);
    const key = keys.get(row.key_id);
    if (!key) {
      fail('service-tip', `tip ${row.tip_id}: no service_keys row for ${row.key_id}`);
      continue;
    }
    const result = verifySignature(row.alg, key.key, message,
      Buffer.from(row.signature, 'hex'));
    if (!result.ok) {
      fail('service-tip', `tip ${row.tip_id}: ${result.why}`);
      continue;
    }
    verified += 1;
  }
  if (verified === rows.length) {
    pass('service-tip', `${verified}/${rows.length} chain-tip signature(s) verify`);
  }
  findings.info.service_tips_verified = verified;

  // Section 5: "cutover = 1 marks a tip adopted at migration: it attests only
  // that the service observed this tip at this time, and retroactively
  // authenticates nothing before it."
  const cutovers = rows.filter((r) => Number(r.cutover) === 1).map((r) => Number(r.tip_id));
  if (cutovers.length > 0) {
    findings.info.cutover_tip = cutovers;
    warn('service-tip-cutover',
      `tip(s) ${cutovers.join(', ')} are cutover signatures: section 5 says they ` +
      `attest only that the service observed the tip at that time and ` +
      `retroactively authenticate NOTHING before them`);
  }
  if (tip && rows.every((r) => Number(r.tip_id) !== tip.id)) {
    warn('service-tip-coverage',
      `the last event (id ${tip.id}) carries no tip signature; events appended ` +
      `since the newest signed tip rest on local state alone`);
  }
}

function checkCheckpoints(db, keys, archiveUuid) {
  if (!tableExists(db, 'service_checkpoints')) return;
  const rows = allRows(db,
    'SELECT tip_id, alg, chain_hash, key_id, signature FROM service_checkpoints ' +
    'ORDER BY tip_id, alg');
  findings.info.service_checkpoints = rows.length;
  if (rows.length === 0) return;
  if (archiveUuid === null) {
    fail('checkpoint', 'checkpoints present but no archive uuid could be resolved');
    return;
  }
  let verified = 0;
  const algsSeen = new Set();
  for (const row of rows) {
    // Section 5, checkpoint payload: four fields -- archive_uuid, tip_id,
    // chain_hash, key_id -- PLUS `alg` if and only if the scheme is not the
    // classical one. "This asymmetry is deliberate and a parser must
    // reproduce it."
    const payload = {
      archive_uuid: archiveUuid,
      tip_id: Number(row.tip_id),
      chain_hash: row.chain_hash,
      key_id: row.key_id,
    };
    if (row.alg !== ALG_ECDSA_P256) payload.alg = row.alg;
    const message = canonicalBytes('contextd.ProtectedCheckpointV1', payload);
    const key = keys.get(row.key_id);
    if (!key) {
      fail('checkpoint',
        `checkpoint ${row.tip_id}/${row.alg}: no service_keys row for ${row.key_id}`);
      continue;
    }
    const result = verifySignature(row.alg, key.key, message,
      Buffer.from(row.signature, 'hex'));
    if (!result.ok) {
      // Section 5: "All signatures present on a checkpoint must verify. A
      // hybrid checkpoint whose ML-DSA half fails is a broken checkpoint, not
      // a classical one."
      fail('checkpoint', `checkpoint ${row.tip_id}/${row.alg}: ${result.why}`);
      continue;
    }
    algsSeen.add(row.alg);
    verified += 1;
  }
  if (verified === rows.length) {
    pass('checkpoint',
      `${verified}/${rows.length} checkpoint signature(s) verify ` +
      `(schemes: ${[...algsSeen].sort().join(', ')})`);
  }
  findings.info.service_checkpoints_verified = verified;
  findings.info.checkpoint_algs = [...algsSeen].sort();
}

// ---------------------------------------------------------------------------
// check 7 -- operator attestations (section 4, section 10 step 6)
// ---------------------------------------------------------------------------

const ACTION_FIELDS = [
  'domain', 'version', 'archive_uuid', 'key_id', 'nonce', 'sequence',
  'issued_at', 'expires_at', 'action', 'scope', 'arguments',
  'content_digest', 'reason_digest',
];

const ACTION_CLASSES = new Set([
  'note.deliberate', 'loop.add', 'loop.confirm', 'loop.close', 'loop.reopen',
  'loop.dismiss', 'grant.add', 'grant.revoke', 'decision.supersede',
  'archive.raw_read', 'archive.export', 'archive.backup', 'archive.restore',
  'security.key_register', 'security.key_revoke', 'pin.adopt', 'pin.barrier',
]);

const MAX_TTL_SECONDS = 900;

function loadOperatorKeys(db) {
  const keys = new Map();
  if (!tableExists(db, 'operator_keys')) return keys;
  // Section 4, "Where the operator key lives", and section 10 step 6:
  // `operator_keys.public_der` is a raw DER SubjectPublicKeyInfo blob -- NOT
  // PEM, unlike `service_keys.public_pem` in section 5. The document now
  // states that asymmetry in both directions; before the errata it stated
  // neither, and this function inferred the column and its encoding from the
  // schema while recording a spec gap.
  const cols = allRows(db, 'PRAGMA table_info(operator_keys)').map((r) => r.name);
  if (!cols.includes('public_der')) {
    fail('operator-key',
      `section 4 gives operator_keys a public_der column; this archive has ` +
      `${cols.join(', ')}`);
    return keys;
  }
  for (const row of allRows(db, 'SELECT key_id, public_der, signer, revoked FROM operator_keys')) {
    const der = asBuffer(row.public_der);
    if (der === null) {
      fail('operator-key', `key ${row.key_id}: public_der is not readable bytes`);
      continue;
    }
    try {
      keys.set(row.key_id, {
        key: createPublicKey({ key: der, format: 'der', type: 'spki' }),
        signer: row.signer,
        revoked: row.revoked,
      });
    } catch (err) {
      fail('operator-key', `key ${row.key_id}: ${err.message}`);
    }
  }
  return keys;
}

function checkAttestations(db, operatorKeys, archiveUuid) {
  const rows = allRows(db,
    "SELECT id, meta FROM events WHERE meta LIKE '%\"attestation\"%' ORDER BY id");
  const attested = [];
  for (const row of rows) {
    let meta;
    try {
      meta = JSON.parse(row.meta);
    } catch {
      continue;
    }
    if (meta && typeof meta === 'object' && meta.attestation) {
      attested.push({ id: Number(row.id), attestation: meta.attestation });
    }
  }
  findings.info.attestations = attested.length;
  if (attested.length === 0) {
    warn('attestation', 'the archive carries no operator attestation blocks');
    return;
  }
  let verified = 0;
  const signers = new Set();
  for (const { id, attestation } of attested) {
    const action = attestation.action;
    // Section 4: exactly thirteen keys, all required; unknown keys refused.
    const keys = Object.keys(action).sort();
    const expected = [...ACTION_FIELDS].sort();
    if (JSON.stringify(keys) !== JSON.stringify(expected)) {
      fail('attestation-fields',
        `event ${id}: section 4 requires exactly the thirteen ACTION_FIELDS; ` +
        `found ${keys.length} (${keys.join(', ')})`);
      continue;
    }
    if (action.domain !== 'contextd.OperatorActionV1' || action.version !== 1) {
      fail('attestation-fields',
        `event ${id}: domain/version must be contextd.OperatorActionV1 / 1`);
      continue;
    }
    if (!ACTION_CLASSES.has(action.action)) {
      fail('attestation-registry',
        `event ${id}: section 4's action-class registry is closed and does not ` +
        `contain ${JSON.stringify(action.action)}`);
      continue;
    }
    if (!(action.scope === 'global' || action.scope.startsWith('repo:'))) {
      fail('attestation-scope',
        `event ${id}: section 4 gives scope as 'global' or 'repo:<path>'; ` +
        `found ${JSON.stringify(action.scope)}`);
      continue;
    }
    // Section 4 TTLs: an action whose expires_at - issued_at exceeds the
    // maximum is refused at verification.
    const ttl = action.expires_at - action.issued_at;
    if (ttl > MAX_TTL_SECONDS || ttl <= 0) {
      fail('attestation-ttl',
        `event ${id}: expires_at - issued_at is ${ttl}s; section 4 caps it at ` +
        `${MAX_TTL_SECONDS}s`);
      continue;
    }
    if (archiveUuid !== null && action.archive_uuid !== archiveUuid) {
      fail('attestation-archive',
        `event ${id}: the action binds archive ${action.archive_uuid}, but this ` +
        `archive is ${archiveUuid}`);
      continue;
    }
    const key = operatorKeys.get(attestation.key_id);
    if (!key) {
      fail('attestation',
        `event ${id}: no operator_keys row for key_id ${attestation.key_id}`);
      continue;
    }
    if (attestation.key_id !== action.key_id) {
      fail('attestation',
        `event ${id}: the block names key ${attestation.key_id} while the signed ` +
        `action names ${action.key_id}`);
      continue;
    }
    // Section 4: ECDSA P-256 with SHA-256 over canonical_bytes(DOMAIN, action).
    const message = canonicalBytes('contextd.OperatorActionV1', action);
    const result = verifySignature(ALG_ECDSA_P256, key.key, message,
      Buffer.from(attestation.signature, 'hex'));
    if (!result.ok) {
      fail('attestation', `event ${id}: ${result.why}`);
      continue;
    }
    signers.add(attestation.signer);
    verified += 1;
  }
  if (verified === attested.length) {
    pass('attestation',
      `${verified}/${attested.length} operator attestation(s) verify as ECDSA ` +
      `P-256 over the canonical action bytes`);
  }
  findings.info.attestations_verified = verified;
  findings.info.attestation_signers = [...signers].sort();

  // Section 4: "A record whose `signer` names the test signer was NOT produced
  // by a presence-bound hardware key and must never be read as an operator
  // act." An independent verifier that verified the maths and stayed silent
  // about this would be handing an adjudicator a false positive.
  for (const signer of signers) {
    if (signer !== 'secure_enclave') {
      warn('attestation-assurance',
        `attestation(s) carry signer=${JSON.stringify(signer)}. Section 4: only ` +
        `secure_enclave is a presence-bound hardware key; anything else was NOT ` +
        `produced by one and MUST NOT be read as an operator act.`);
    }
  }
}

// ---------------------------------------------------------------------------
// driver
// ---------------------------------------------------------------------------

function parseArgs(args) {
  const opts = {
    archive: null,
    vectors: join(REPO_ROOT, 'tests', 'vectors', 'operator_action_v1.json'),
    json: false,
    quiet: false,
    failOnSpecGap: false,
  };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--vectors') { opts.vectors = args[i += 1]; continue; }
    if (arg === '--json') { opts.json = true; continue; }
    if (arg === '--quiet') { opts.quiet = true; continue; }
    if (arg === '--fail-on-spec-gap') { opts.failOnSpecGap = true; continue; }
    if (arg.startsWith('--')) throw new Error(`unknown option ${arg}`);
    if (opts.archive === null) { opts.archive = arg; continue; }
    throw new Error(`unexpected argument ${arg}`);
  }
  if (opts.archive === null) throw new Error('an archive path is required');
  return opts;
}

function resolveArchive(path) {
  const target = resolve(path);
  if (!existsSync(target)) throw new Error(`no such path: ${target}`);
  if (statSync(target).isDirectory()) {
    const db = join(target, 'contextd.db');
    if (!existsSync(db)) throw new Error(`no contextd.db in ${target}`);
    return { db, dir: target };
  }
  return { db: target, dir: dirname(target) };
}

function report(opts) {
  const lines = [];
  lines.push('independent verification of docs/FORMAT.md');
  lines.push(`  implementation: JavaScript (node ${process.version}), ` +
    `node:sqlite + node:crypto, zero contextd imports`);
  lines.push(`  archive: ${findings.info.archive}`);
  lines.push('');
  for (const p of findings.pass) lines.push(`  PASS  ${p.check}: ${p.detail}`);
  for (const w of findings.warn) lines.push(`  WARN  ${w.check}: ${w.detail}`);
  for (const f of findings.fail) lines.push(`  FAIL  ${f.check}: ${f.detail}`);
  if (findings.spec_mismatch.length > 0) {
    lines.push('');
    lines.push('  ' + '='.repeat(70));
    lines.push(`  SPEC/REALITY DISAGREEMENT (${findings.spec_mismatch.length}) ` +
      `-- the archive is fine; docs/FORMAT.md is wrong about it.`);
    lines.push('  ' + '='.repeat(70));
    for (const m of findings.spec_mismatch) {
      lines.push(`    * ${m.section}`);
      lines.push(`        the document claims: ${m.claim}`);
      lines.push(`        the archive holds:   ${m.reality}`);
      lines.push(`        consequence:         ${m.consequence}`);
    }
  }
  if (findings.spec_gap.length > 0) {
    lines.push('');
    lines.push(`  SPEC GAPS (${findings.spec_gap.length}) -- points at which this ` +
      `verifier had to look past docs/FORMAT.md:`);
    for (const g of findings.spec_gap) {
      lines.push(`    * ${g.section}`);
      lines.push(`        needed:     ${g.needed}`);
      lines.push(`        absent:     ${g.absent}`);
      lines.push(`        workaround: ${g.workaround}`);
    }
  }
  lines.push('');
  lines.push(`  ${findings.pass.length} passed, ${findings.fail.length} failed, ` +
    `${findings.warn.length} warning(s), ${findings.spec_gap.length} spec gap(s), ` +
    `${findings.spec_mismatch.length} spec/reality disagreement(s)`);
  if (!opts.quiet) stdout.write(lines.join('\n') + '\n');
}

function main() {
  let opts;
  try {
    opts = parseArgs(argv.slice(2));
  } catch (err) {
    stdout.write(`usage error: ${err.message}\n`);
    stdout.write('usage: verify_format_independent.mjs <archive-dir-or-db> ' +
      '[--vectors PATH] [--json] [--quiet] [--fail-on-spec-gap]\n');
    return 2;
  }

  let archive;
  try {
    archive = resolveArchive(opts.archive);
  } catch (err) {
    stdout.write(`cannot open archive: ${err.message}\n`);
    return 2;
  }
  findings.info.archive = archive.db;
  findings.info.node = process.version;

  // The canonical vectors need no archive at all -- they are the part a
  // second implementation should pass before it is trusted against real bytes
  // (FORMAT.md section 10, closing paragraph).
  checkVectors(opts.vectors);

  let db;
  try {
    db = new DatabaseSync(archive.db, { readOnly: true });
  } catch (err) {
    stdout.write(`cannot open ${archive.db}: ${err.message}\n`);
    return 2;
  }

  try {
    if (checkEventsTable(db)) {
      checkSourceVocabulary(db);
      const { tip } = checkChain(db);
      checkWitness(archive.dir, tip);
      checkRecoveryJournal(archive.dir);
      const serviceKeys = loadServiceKeys(db);
      checkServiceSignatures(db, serviceKeys);
      const archiveUuid = resolveArchiveUuid(db);
      findings.info.archive_uuid = archiveUuid;
      checkTips(db, serviceKeys, archiveUuid, tip);
      checkCheckpoints(db, serviceKeys, archiveUuid);
      checkAttestations(db, loadOperatorKeys(db), archiveUuid);
    }
  } finally {
    db.close();
  }

  report(opts);
  if (opts.json) stdout.write(JSON.stringify(findings, null, 2) + '\n');
  if (findings.fail.length > 0) return 1;
  // A disagreement between the document and the bytes is a non-zero exit on
  // purpose. The archive verified; the specification did not describe it, and
  // a verifier that returned success there would be certifying the document.
  if (findings.spec_mismatch.length > 0) return 1;
  if (opts.failOnSpecGap && findings.spec_gap.length > 0) return 1;
  return 0;
}

exit(main());
