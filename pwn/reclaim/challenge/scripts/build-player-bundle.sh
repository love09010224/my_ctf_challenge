#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
KERNEL=${KERNEL:-"$ROOT/build/bzImage"}
ROOTFS=${ROOTFS:-"$ROOT/build/rootfs.cpio.gz"}
OUTPUT=${OUTPUT:-"$ROOT/build/reclaim-box-000-player.tar.gz"}
for input in "$KERNEL" "$ROOTFS" "$ROOT/player/README.md" "$ROOT/player/run.sh"; do
	[[ -f "$input" && ! -L "$input" ]] || { echo "missing input: $input" >&2; exit 1; }
done
stage=$(mktemp -d "${TMPDIR:-/tmp}/reclaim-player.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
install -m 0444 "$ROOT/player/README.md" "$stage/README.md"
install -m 0444 "$KERNEL" "$stage/bzImage"
install -m 0444 "$ROOTFS" "$stage/rootfs.cpio.gz"
install -m 0555 "$ROOT/player/run.sh" "$stage/run.sh"
mkdir -p "$(dirname "$OUTPUT")"
(
	cd "$stage"
	tar --sort=name --mtime='UTC 2026-01-01' --owner=0 --group=0 --numeric-owner \
		-cf - README.md bzImage rootfs.cpio.gz run.sh | gzip -9n > "$OUTPUT"
)
sha256sum "$OUTPUT"
