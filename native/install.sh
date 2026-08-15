#!/bin/sh
# Install the already-built signer at the only path hardened clients trust.
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "the production signer is macOS-only" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo; hardened signing requires a root-owned helper" >&2
    exit 2
fi

here="$(cd "$(dirname "$0")" && pwd)"
source_binary="$here/contextd-signer"
target_dir="/usr/local/libexec/contextd"
target_binary="$target_dir/contextd-signer"

if [ ! -f "$source_binary" ] || [ -L "$source_binary" ]; then
    echo "build native/contextd-signer before installing it" >&2
    exit 2
fi

install -d -o root -g wheel -m 0755 "$target_dir"
install -o root -g wheel -m 0755 "$source_binary" "$target_binary"

owner="$(stat -f %u "$target_binary")"
mode="$(stat -f %Lp "$target_binary")"
if [ "$owner" != "0" ] || [ "$mode" != "755" ]; then
    echo "installed signer ownership/mode verification failed" >&2
    exit 2
fi
codesign --verify --strict "$target_binary"
echo "installed: $target_binary (root:wheel 0755, signature verified)"
