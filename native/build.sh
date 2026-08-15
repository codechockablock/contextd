#!/bin/sh
# Build the Secure Enclave signer helper.
#
# This ONLY compiles. It does not enroll a key, does not install anything, and
# does not touch the Keychain — all three are operator actions requiring
# explicit approval (docs/SECURITY.md, "Deployment states").
#
#   native/build.sh                 -> native/contextd-signer
#
# The local build is ad-hoc signed without restricted entitlements. Adding a
# keychain-access-group entitlement to an ad-hoc binary makes macOS kill it at
# launch because no provisioning profile grants that group. A release build
# may use a stable Developer ID/provisioned identifier, but must remain able to
# execute after signing. Verify the local artifact with `codesign --verify`.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/contextd-signer"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "the Secure Enclave signer is macOS-only; there is no software" >&2
    echo "fallback on other platforms (docs/SECURITY.md §3)." >&2
    exit 2
fi

if ! command -v swiftc >/dev/null 2>&1; then
    echo "swiftc not found. Install the Xcode command line tools:" >&2
    echo "  xcode-select --install" >&2
    exit 2
fi

echo "compiling $out"
swiftc -O \
    -framework Foundation \
    -framework Security \
    -framework LocalAuthentication \
    -o "$out" \
    "$here/contextd-signer.swift"

echo "code-signing (ad-hoc, no restricted entitlements)"
codesign --force --sign - "$out"
codesign --verify --strict "$out"

chmod 0755 "$out"
echo
echo "built: $out"
echo
echo "NOT DONE AUTOMATICALLY (each is an operator action):"
echo "  1. enroll a key:   $out enroll --key-id default > operator-key.der"
echo "  2. install helper: sudo native/install.sh"
echo "  3. first archive:  follow docs/OPERATOR_CEREMONY.md bootstrap steps"
echo "     later key:      ctx security key register operator-key.der --signer-tag default"
echo "  4. verify:         ctx security doctor --strict --json"
