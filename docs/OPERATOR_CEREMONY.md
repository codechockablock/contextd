# Hardened operator-key ceremony

This ceremony crosses two different boundaries. The desktop operator owns the
presence-gated Secure Enclave key. The `_contextd` service account owns the
archive and key registry. No RPC can enroll the first key.

## Preconditions

- The CLI is installed from root-owned code under
  `/usr/local/libexec/contextd`.
- The archive database is owned by `_contextd`, mode `0600`; its parent is not
  group/world-writable.
- `[security] mode = "hardened"` and the desktop user can reach only the Unix
  socket, not the archive files.
- The first-key command is run by a service administrator who can become
  `_contextd`. A normal desktop client cannot satisfy this precondition.

## One-time first key

Run the build as the desktop operator, install the signer as root, and enroll
the private key as the desktop operator:

```sh
native/build.sh
sudo native/install.sh
/usr/local/libexec/contextd/contextd-signer enroll --key-id primary \
  > /tmp/contextd-operator-public.der
```

The DER file is public material. Install it where `_contextd` can read it, then
perform the only first-key bootstrap path out of band:

```sh
sudo install -o _contextd -g wheel -m 0400 \
  /tmp/contextd-operator-public.der /var/db/contextd/operator-public.der
sudo -u _contextd /usr/local/libexec/contextd/ctx security key bootstrap \
  /var/db/contextd/operator-public.der --signer-tag primary \
  --acknowledge-first-key-bootstrap
```

Bootstrap refuses unless all of these are true: the process is explicitly in
the service context, its effective UID is `_contextd`, archive ownership and
modes are private, the acknowledgement flag is present, and the registry has
never contained a key. A revoked key does not reopen bootstrap.

## Normal operation and rotation

An ordinary desktop client asks the attestation layer to prepare an action
(there is no resident daemon since lane X; preparation runs in-process
against the archive). The preparation mints its nonce, monotonic sequence,
normalized arguments, content/reason digests, and expiry; it returns both the
exact canonical bytes and a summary. The root-owned native signer decodes
those bytes and constructs its own trusted prompt before requesting fresh
user presence. The protected operation verifies and spends the action once,
inside the same transaction as the act.

Additional keys use the normal, already-attested path:

```sh
/usr/local/libexec/contextd/contextd-signer enroll --key-id replacement \
  > /tmp/contextd-replacement-public.der
/usr/local/libexec/contextd/ctx security key register \
  /tmp/contextd-replacement-public.der --signer-tag replacement
/usr/local/libexec/contextd/ctx security key revoke OLD_KEY_ID
```

The enrollment tag is registry metadata used to find the Secure Enclave key;
it is not the SHA-256 key id. Re-registering a revoked key is refused.

## Keeping a spare, and why it is not optional

Do this while the first key still works. Once every enrolled key is gone the
archive can never accept another operator act: bootstrap stays closed against
a non-empty registry, and registering a replacement is authorized by an active
key you no longer have. The full dead end is `docs/SECURITY.md` §8; the point
here is that the only remedy is taken *before* the loss.

Two active keys are the intended steady state, and the same already-attested
path enrolls one — register it, do **not** revoke the first:

```sh
/usr/local/libexec/contextd/contextd-signer enroll --key-id spare \
  > /tmp/contextd-spare-public.der
/usr/local/libexec/contextd/ctx security key register \
  /tmp/contextd-spare-public.der --signer-tag spare
```

What that buys depends on where the spare's handle lives, and the distinction
matters more than it looks:

- **Same machine.** Covers deletion or corruption of one `.sekey` handle. It
  does not survive losing the machine — both handles die with it.
- **Second device.** The only configuration that survives losing this one.
  Enroll on that device, carry back its public DER (public material, like the
  first key's), and register it here. Its signatures verify against this
  archive because verification needs nothing but the public key.

An Enclave handle is device-bound ciphertext. It cannot be copied to another
machine or restored from a backup, so "back up the key" is not available and a
second device is not a convenience.

Selection follows registration order: acts sign with the most recently
registered active key. After enrolling a spare on a *second* device, that key
is the newest and this machine cannot sign for it, so local acts must name a
key they can reach:

```sh
ctx --signer-key primary grant add loop.confirm --repo /path --for 8h
```

`ctx security key list` shows both columns the flag accepts, and a wrong tag
refuses by naming the keys that are actually registered rather than failing at
the signer.

## Honest limits

The automated suite exercises the complete ceremony with real P-256
signatures but a software-created private key and a simulated service UID. It
does not prove that a particular machine's Secure Enclave, biometric policy,
root installation, service-account ownership, or protected rollback checkpoint
was configured correctly. Those remain deployment checks.
