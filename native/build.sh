#!/bin/sh
# Build the Secure Enclave signer helper.
#
# This ONLY compiles. It does not enroll a key, does not install anything, and
# does not touch the Keychain — all three are operator actions requiring
# explicit approval (docs/SECURITY.md, "Deployment states").
#
#   native/build.sh                 -> native/contextd-signer
#
# Signing with the Secure Enclave requires the binary to be code-signed with a
# keychain-access entitlement. For local operator use, ad-hoc signing is
# enough; for an installed deployment, sign with a Developer ID identity:
#
#   codesign --force --sign - --entitlements native/signer.entitlements \
#            native/contextd-signer
#
# The build below applies the ad-hoc form. Verify what you got with:
#   codesign -d --entitlements - native/contextd-signer
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

echo "code-signing (ad-hoc) with the keychain-access entitlement"
codesign --force --sign - \
    --entitlements "$here/signer.entitlements" \
    "$out"

chmod 0755 "$out"
echo
echo "built: $out"
echo
echo "NOT DONE AUTOMATICALLY (each is an operator action):"
echo "  1. enroll a key:   $out enroll --key-id default > operator-key.der"
echo "  2. register it:    ctx security key register operator-key.der"
echo "  3. verify:         ctx security doctor --strict --json"
