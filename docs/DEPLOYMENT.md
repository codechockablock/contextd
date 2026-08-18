# Deployment and rollback — runbook (NOT EXECUTED)

**Nothing in this document has been run.** No service was installed, no key
enrolled, no launchd job loaded, no live archive migrated, and no live client
configuration changed. Every command below is for the operator to run
deliberately, and several need a password that an agent must not be given.

Read `docs/SECURITY.md` "Implementation status" first. Every step below is
implemented and tested; what has **not** happened is any of it being run
against a real deployment. Two things remain unimplemented by design decision
rather than by omission, and are marked where they appear: encrypted export
(no recovery recipient selected — export refuses instead) and a protected
checkpoint destination (none selected — rollback resistance reports
incomplete).

---

## 0. Before anything

```bash
cd /path/to/contextd
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
.venv/bin/python tests/smoke.py
```

All three must exit 0. Then confirm the tracked tree is clean:

```bash
.venv/bin/python scripts/audit_repository_privacy.py --tracked --fail-on-findings --redact-output
```

## 1. Render local deployment files

The tracked `launchd/` and `clients/` files carry placeholders, not paths.

```bash
.venv/bin/python scripts/render_deployment.py
```

Writes to `build/deploy/` (gitignored). Nothing is installed.

## 2. Build the Secure Enclave signer

```bash
native/build.sh
```

Compiles and ad-hoc code-signs `native/contextd-signer`. It does **not** create
a key.

## 3. Enroll an operator key — OPERATOR ACTION

Creates a non-exportable P-256 key in the Secure Enclave, gated on user
presence. This touches Keychain state and requires the human at the machine.

```bash
native/contextd-signer enroll --key-id default > /tmp/operator-key.der
```

Register the public key with the archive:

```bash
ctx security key register /tmp/operator-key.der
ctx security key list
```

Verify the key answers, and that cancelling produces nothing:

```bash
printf 'test' | native/contextd-signer sign --key-id default --summary "enrollment check" | xxd | head
# Cancel the prompt: expect a nonzero exit and no output on stdout.
```

Then delete the exported public key file — it is not secret, but it is clutter:

```bash
rm /tmp/operator-key.der
```

## 4. The authority daemon — REMOVED (lane X)

This section used to install a resident authority daemon under a dedicated
service account. The daemon was removed with the rest of residency (lane X,
residency dissolution): there is no `ctx security serve`, no
`com.contextd.authd.plist`, and no RPC surface. The architecture is a
library plus event-time hooks and launchd timers; nothing runs continuously.

What replaces the installed-daemon posture:

- **Development mode** (the default) is unchanged: the client plane opens
  the archive directly and assurance is attribution.
- **Hardened mode is a fail-closed refusal.** With no authority plane to
  serve reads, a `[security] mode = "hardened"` archive refuses every read
  and write from every boundary (docs/SECURITY.md, Deployment states). The
  out-of-band first-key bootstrap ceremony (§3) is the one hardened path
  that still runs.
- The service-account and file-ownership recipe that used to live here is
  extraction-scope for a future authority plane; nothing in this tree
  consumes it today.

## 5. Migrate the live archive — OPERATOR ACTION

**Back up first, and verify the backup restores, before migrating anything.**

```bash
ctx backup --keep 5
ctx restore <newest-bundle> /tmp/restore-check   # must succeed
```

The first backup also atomically creates `backup-trust.json` in the live
archive home. This is the independent public-key pin set used to authenticate
bundle manifests. It is deliberately **not included in the bundle** and a
restore never loads keys from the bundle's SQLite database. Preserve a copy of
this 0600 file through a separately protected channel before relying on the
backup for whole-machine recovery. A bundle and a trust file stored under the
same attacker-writable directory do not form two trust roots.

Every validation and restore requires a valid signature from a pinned key.
Missing pins, unknown keys, unsigned manifests, and stale signatures all fail
before publication. Key rotation is continuous: each backup append-merges the
live archive's current and retired public keys into the pin file, so old and
new bundles remain verifiable. Pin-file loading refuses symlinks, insecure
file/parent modes, hard links, duplicate/conflicting key IDs, and IDs that do
not match their public keys. Previously issued, pinned-key signed manifests
remain verifiable under signature scheme 1; new scheme-2 signatures bind each
payload path, size, and digest as well as the snapshot and blob inventory.

For a fresh-machine drill where `CONTEXTD_HOME` has no pin file, load the
offline pin explicitly through the recovery API:

```python
from pathlib import Path
from contextd.backup import ManifestTrustStore, bundle_identity, restore_backup

pins = ManifestTrustStore.load(Path("/offline/contextd-backup-trust.json"))
bundle = Path("/safe/contextd-….ctxbackup")
destination = Path("/new/empty/contextd-home")
authorized = bundle_identity(
    bundle, destination=destination, trust_store=pins
)
# After the operator authorizes this exact identity:
restore_backup(
    bundle,
    destination,
    trust_store=pins,
    expected_manifest_sha256=authorized["manifest_sha256"],
)
```

Do not copy a key registry out of `contextd.db` in the bundle and call it a
pin. `ManifestTrustStore.from_connection(...)` is only for an already-trusted
live archive. Operator authorization for restore must bind the canonical
identity returned by `bundle_identity(...)`: normalized bundle path,
normalized destination path, manifest SHA-256, signing key ID, and snapshot
tip. Pass the authorized digest back as `expected_manifest_sha256` when
executing the restore; otherwise a different valid signed bundle can be
substituted under the approved path between approval and execution. Binding
only the lexical paths permits the same substitution.

Backup authorization likewise binds `normalized_path(destination)`, retention,
archive UUID, and the exact current head id/hash. The authority plane passes
that pair to `create_backup(expected_head_id=..., expected_head_hash=...)`;
creation rechecks it inside the append lock immediately before the online
snapshot and keeps the lock through the snapshot. A concurrent append after
approval therefore refuses instead of silently producing a different backup.

Unsigned legacy recovery is a one-time, non-hardened exception. It requires an
explicit `LegacyBundlePolicy` containing the exact reviewed manifest digest;
it is never a fallback for a bad signature and cannot authorize a snapshot
with a service-signature cutover. Hardened RPC code must not expose this
policy.

Then:

```bash
ctx security migrate --dry-run --json     # reports what would change; changes nothing
ctx security migrate                      # append-only; preserves every historical byte
ctx verify                                # chain + witness must still be OK
```

The migration issues **no UPDATE or DELETE against `events`** — that is how the
byte-preservation guarantee is achieved rather than merely asserted, and it is
also why the migration is crash-safe and re-runnable: an interruption leaves
history byte-identical and running it again completes it. It fingerprints every
historical column before and after and refuses if anything moved.

It also refuses to migrate an archive whose chain does not already verify, so a
pre-existing break cannot be buried under a successful-looking migration.

The migration is append-only by contract: it preserves every old event id,
timestamp, content byte, metadata byte, content hash, chain hash, and witness
tip, and adopts the legacy tip with a signed cutover checkpoint that
**does not** retroactively authenticate anything before it.

## 6. Configure a protected checkpoint — OPERATOR ACTION

**Destination selected: `/var/db/contextd/checkpoint.json`**, owned by the
service account at mode 0600. It is the only candidate on this machine that
the desktop UID genuinely cannot rewrite, which is the whole property — a
checkpoint your own account can edit proves nothing, because the attacker in
this threat model *is* your account.

It becomes real when step 4 creates the service-owned directory. Until then
`ctx security doctor` reports `rollback_resistance: incomplete`, correctly.

Set it in the deployed archive's config (not `~/.contextd`):

```bash
sudo -u _contextd tee -a /var/db/contextd/config.toml >/dev/null <<'TOML'
[security]
mode = "hardened"
checkpoint_destination = "/var/db/contextd/checkpoint.json"
TOML
```

Write the first checkpoint, then verify it:

```bash
sudo -u _contextd env CONTEXTD_HOME=/var/db/contextd \
    /usr/local/libexec/contextd/ctx security checkpoint --write
sudo -u _contextd env CONTEXTD_HOME=/var/db/contextd \
    /usr/local/libexec/contextd/ctx security checkpoint     # exits 0 if it verifies
```

Confirm your own account cannot rewrite it — this is the check that matters,
and it must FAIL:

```bash
touch /var/db/contextd/checkpoint.json && echo "BAD: writable by you" \
    || echo "ok: not writable by this uid"
```

### What the checkpoint contains, and what it catches

Five fields only — archive UUID, tip id, chain hash, key id, signature. No
archive content leaves with it, deliberately: a checkpoint destination is by
definition somewhere you do not fully control.

The layering is worth being precise about, because it is easy to assume the
hash chain already covers this. It does not. Verified by rehearsal:

| Attack step | Detected by |
|---|---|
| Edit an event | hash chain (layer 1) |
| Edit + recompute the chain | local witness (layer 2) |
| Truncate the ledger | local witness |
| Truncate **and rewrite the witness to match** | **checkpoint only** |

That last row is the reason this step exists. A same-UID attacker owns both
the database and the witness file, so both are rewritable; the checkpoint is
the first record they cannot reach. In rehearsal, after truncating to tip #3
and rewriting the witness, `verify_chain` returned OK and the archive opened
without error — and the checkpoint still reported
`ROLLBACK: the archive ends at #3 but a protected checkpoint recorded #6`.

### Off-device survival is a separate problem

This destination protects against rollback, not against device loss. If you
want both, mirror the checkpoint to iCloud or another provider after writing
it. Be honest about what the mirror buys: the local copy there is writable by
your UID, so its value is the provider's version history, not permissions.

## 7. Configure export policy — OPERATOR ACTION

Export seals the archive to an X25519 recipient. With no recipient configured
it refuses; it never emits plaintext as a fallback.

### Generate the recipient somewhere else

This is the step that decides whether encrypted export is worth anything. The
attacker in this threat model runs as your desktop user. If the private key is
on this machine, they read it and decrypt the export, and the encryption was
decoration. **Generate the key on another machine and bring only the public
half here.**

On the *other* machine:

```bash
openssl genpkey -algorithm X25519 -out contextd-export.key
```

```bash
openssl pkey -in contextd-export.key -pubout -out contextd-export.pub
```

Keep `contextd-export.key` there — offline media, a hardware-backed store, a
password manager. It is the only thing that can ever open an export. Copy
`contextd-export.pub` to this host, then:

```bash
chmod 600 ~/.contextd/contextd-export.pub
```

The 0600 is an integrity requirement, not a secrecy one: a public key is not
secret, but a group-writable key file is one another local account can
substitute. Export refuses a group- or world-accessible recipient file.

Point config at it in `~/.contextd/config.toml`:

```toml
[security]
export_recipient = "/Users/you/.contextd/contextd-export.pub"
```

### What config does and does not decide

Config *names* the recipient. It does not authorize it. `config.toml` is
writable by the modeled attacker, so the recipient's sha256 is covered by the
operator's signed action. If the configured key is swapped between the moment
you approve and the moment the export runs, the export **refuses** — it does
not quietly re-address itself. `ctx security export` prints the digest it is
about to seal to, before the presence prompt, so what you approve is legible.

### Producing and opening an export

```bash
ctx security export --dest ~/exports
```

Opening is done on the recovery machine, where the private key lives:

```bash
ctx security export-open contextd-20260815-154446.ctxexport --identity contextd-export.key --dest ./recovered
```

Without `--identity` it prints the header only — recipient, manifest digest,
suite — and says plainly that none of it is authenticated until opened. That
is enough to work out *which* key you need without having the key present.

The recovered directory is an ordinary backup bundle, so `ctx restore` and the
manifest trust store apply to it unchanged.

## 8. Final verification

```bash
ctx security doctor --strict --json
```

On this tree it reports most of its five invariants failing, which is the
correct answer: no hardware key is enrolled, no protected checkpoint is
configured, and development mode permits direct archive access. (The two
daemon-deployment invariants were deleted with the daemon, lane X.)

Production may be called hardened **only** when this exits 0 with every
invariant reported separately and true:

- production hardware signer enrolled
- valid service signatures
- current protected checkpoint
- no plaintext scratch
- no insecure fallback

Until then the honest answer to "is production hardened?" is **no**.

---

## Rollback

Rollback is the reason step 5 begins with a verified backup.

The archive is append-only, so a migration cannot be "undone" by deletion —
recovery is a restore:

```bash
ctx restore <pre-migration-bundle> ~/.contextd-restored
# inspect, then swap only after `ctx verify` on the restored copy passes
```

That command uses the live archive's external `backup-trust.json`. If the live
archive is unavailable, use the separately protected pin and the explicit
fresh-home recovery API shown above. Losing both the live pin file and its
offline copy is intentionally unrecoverable through authenticated restore;
trusting a public key supplied by the bundle would make forged backups pass.

Revoking an enrolled key is an operator action and does not remove events it
already authorized; it stops new ones:

```bash
ctx security key revoke <key-id>
```

Deleting the Secure Enclave key itself is destructive and irreversible; do it
only after a replacement is enrolled and verified.
