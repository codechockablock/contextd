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

## 4. Install the authority daemon — OPERATOR ACTION, REQUIRES ROOT

The daemon exists (`contextd/authd.py`) and can be run in the foreground today:

```bash
CONTEXTD_HOME=/path/to/archive .venv/bin/ctx security serve --socket /tmp/authd.sock
```

That runs it as **you**, which is useful for testing the RPC surface but
provides no isolation — the archive is still yours. Real isolation needs the
service account below, and is a root action:

```bash
# create the dedicated service account
sudo dscl . -create /Users/_contextd UserShell /usr/bin/false
sudo dscl . -create /Users/_contextd UniqueID 499
sudo dscl . -create /Users/_contextd PrimaryGroupID 499

# root-owned installed code — NOT writable by the desktop UID
sudo install -d -o root -g wheel -m 0755 /usr/local/libexec/contextd
sudo install -o root -g wheel -m 0755 dist/contextd-authd /usr/local/libexec/contextd/

# service-owned archive
sudo install -d -o _contextd -g _contextd -m 0700 /var/db/contextd
sudo install -d -o _contextd -g staff  -m 0750 /var/run/contextd

sudo cp build/deploy/launchd/com.contextd.authd.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.contextd.authd.plist
sudo launchctl load -w /Library/LaunchDaemons/com.contextd.authd.plist
```

Verify ownership actually landed — the security property is the ownership, not
the copy:

```bash
ls -ln /usr/local/libexec/contextd /var/db/contextd /var/run/contextd/authd.sock
sudo -u nobody test -r /var/db/contextd/contextd.db && echo "FAIL: readable" || echo "ok: not readable"
```

## 5. Migrate the live archive — OPERATOR ACTION

**Back up first, and verify the backup restores, before migrating anything.**

```bash
ctx backup --keep 5
ctx restore <newest-bundle> /tmp/restore-check   # must succeed
```

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

The interface is implemented. **No destination has been selected**, and until
one is, `ctx security doctor` reports `rollback_resistance: incomplete`.

```bash
ctx security checkpoint                    # print the current record
ctx security checkpoint --write            # write it to the configured path
ctx security checkpoint                    # verify the written one (exit 1 on rollback)
```

Set `[security] checkpoint_destination` to somewhere **this uid cannot
rewrite** — another host, a service-owned path, append-only storage. The
doctor explicitly fails the invariant if the checkpoint file is writable by the
calling uid, because a checkpoint you can rewrite proves nothing.

The record contains only: archive UUID, tip id, chain hash, key id, signature.
No archive content leaves with it.

## 7. Configure export policy — DECISION REQUIRED

Hardened mode refuses plaintext export. Encrypted export needs an explicitly
configured recovery recipient; **none has been selected**, so export stays
refused rather than silently emitting plaintext.

## 8. Final verification

```bash
ctx security doctor --strict --json
```

On this tree it reports 6 of 7 invariants failing, which is the correct answer:
the service is not installed, no hardware key is enrolled, the archive is
readable by the desktop uid, service signatures are unimplemented, no protected
checkpoint is configured, and the test signer is available in development.

Production may be called hardened **only** when this exits 0 with every
invariant reported separately and true:

- protected daemon (root-owned code, dedicated service UID)
- production hardware signer enrolled
- raw archive inaccessible from the client boundary
- valid service signatures
- current protected checkpoint
- no plaintext scratch
- no insecure fallback

Until then the honest answer to "is production hardened?" is **no**.

---

## Rollback

Rollback is the reason step 5 begins with a verified backup.

```bash
sudo launchctl unload -w /Library/LaunchDaemons/com.contextd.authd.plist
sudo rm /Library/LaunchDaemons/com.contextd.authd.plist
```

The archive is append-only, so a migration cannot be "undone" by deletion —
recovery is a restore:

```bash
ctx restore <pre-migration-bundle> ~/.contextd-restored
# inspect, then swap only after `ctx verify` on the restored copy passes
```

Revoking an enrolled key is an operator action and does not remove events it
already authorized; it stops new ones:

```bash
ctx security key revoke <key-id>
```

Deleting the Secure Enclave key itself is destructive and irreversible; do it
only after a replacement is enrolled and verified.
