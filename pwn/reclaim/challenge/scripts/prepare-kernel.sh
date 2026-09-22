#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=6.12.103
ARCHIVE_SHA256=f143aaade8877ba5616e788b4482576db28481bcf557ef537f4fcc3938fc3176
REFERENCE_BZIMAGE_SHA256=c71f589dc3e84c00006821cb60869e59c452e03300ae9dd045fd218fb525feb8
BUILD=${KERNEL_BUILD:-"$ROOT/build/kernel-$VERSION"}
SOURCE=${KERNEL_SOURCE:-"$ROOT/build/linux-$VERSION"}
ARCHIVE=${KERNEL_ARCHIVE:-"$ROOT/build/linux-$VERSION.tar.xz"}
JOBS=${JOBS:-$(nproc)}
URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$VERSION.tar.xz"

mkdir -p "$ROOT/build"
if [[ ! -f "$ARCHIVE" ]]; then
	curl -fL --retry 3 -C - -o "$ARCHIVE" "$URL"
fi
printf '%s  %s\n' "$ARCHIVE_SHA256" "$ARCHIVE" | sha256sum -c -
if [[ ! -d "$SOURCE" ]]; then
	tar --no-same-owner -xJf "$ARCHIVE" -C "$ROOT/build"
fi
mkdir -p "$BUILD"
cp "$ROOT/config/linux-$VERSION.config" "$BUILD/.config"
make -C "$SOURCE" O="$BUILD" olddefconfig

export KBUILD_BUILD_USER=pwn3
export KBUILD_BUILD_HOST=localhost
export KBUILD_BUILD_TIMESTAMP='Thu Aug 20 01:00:56 KST 2026'
export KBUILD_BUILD_VERSION=3
make -C "$SOURCE" O="$BUILD" -j"$JOBS" bzImage modules_prepare
if [[ -s "$BUILD/vmlinux.symvers" ]]; then
	cp "$BUILD/vmlinux.symvers" "$BUILD/Module.symvers"
fi
cp "$BUILD/arch/x86/boot/bzImage" "$ROOT/build/bzImage"
actual=$(sha256sum "$ROOT/build/bzImage" | awk '{print $1}')
printf 'built bzImage: %s\n' "$actual"
if [[ "$actual" != "$REFERENCE_BZIMAGE_SHA256" ]]; then
	printf 'note: canonical artifact hash is %s; compiler/package differences can change bytes\n' \
		"$REFERENCE_BZIMAGE_SHA256" >&2
fi
