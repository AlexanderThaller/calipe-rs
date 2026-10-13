#!/usr/bin/env bash
# Cross-compile calipers for FreeBSD on a Linux host with clang + lld, using
# the libraries from the official FreeBSD base.txz as sysroot.
#
#   cross-build.sh [cargo args...]     e.g. cross-build.sh build --release
#
# Prints nothing extra; the binary lands in target/x86_64-unknown-freebsd/.
set -euo pipefail

FREEBSD_VERSION="${FREEBSD_VERSION:-15.1}"
SYSROOT="${XDG_CACHE_HOME:-$HOME/.cache}/calipers-firecracker/sysroot-$FREEBSD_VERSION"
TARGET=x86_64-unknown-freebsd

if [[ ! -e "$SYSROOT/.complete" ]]; then
    echo "fetching FreeBSD $FREEBSD_VERSION sysroot" >&2
    mkdir -p "$SYSROOT"
    curl -fsSL "https://download.freebsd.org/releases/amd64/$FREEBSD_VERSION-RELEASE/base.txz" |
        tar -xJf - -C "$SYSROOT" ./lib ./usr/lib ./usr/include 2>/dev/null || true
    [[ -e "$SYSROOT/usr/lib/libc.so" ]] || { echo "sysroot extraction failed" >&2; exit 1; }
    touch "$SYSROOT/.complete"
fi

rustup target list --installed | grep -qx "$TARGET" || rustup target add "$TARGET"

export CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER=clang
export CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_RUSTFLAGS="-C link-arg=--target=$TARGET$FREEBSD_VERSION -C link-arg=--sysroot=$SYSROOT -C link-arg=-fuse-ld=lld"
cmd="${1:-build}"
[[ $# -gt 0 ]] && shift
exec cargo "$cmd" --target "$TARGET" "$@"
