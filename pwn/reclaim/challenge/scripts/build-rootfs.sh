#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUSYBOX=${BUSYBOX:-$(command -v busybox || true)}
MODULE=${MODULE:-"$ROOT/module/reclaim_v4_release.ko"}
GATE=${GATE:-"$ROOT/user/reclaim-approval"}
FLAG_FILE=${FLAG_FILE:-"$ROOT/fixtures/development_flag.txt"}
OUTPUT=${OUTPUT:-"$ROOT/build/rootfs.cpio.gz"}
MANIFEST=${MANIFEST:-"$ROOT/build/vault-private.json"}

for input in "$BUSYBOX" "$MODULE" "$GATE" "$FLAG_FILE"; do
	[[ -f "$input" && ! -L "$input" ]] || { echo "missing input: $input" >&2; exit 1; }
done
[[ -x "$BUSYBOX" && -x "$GATE" ]] || { echo 'BusyBox and approval gate must be executable' >&2; exit 1; }

stage=$(mktemp -d "${TMPDIR:-/tmp}/reclaim-rootfs.XXXXXX")
trap 'chmod -R u+rwX "$stage" 2>/dev/null || true; rm -rf -- "$stage"' EXIT
install -D -m 0755 "$BUSYBOX" "$stage/bin/busybox"
while IFS= read -r applet; do
	case "$applet" in bin/busybox|usr/bin/busybox) continue ;; esac
	mkdir -p "$stage/$(dirname "$applet")"
	ln -s /bin/busybox "$stage/$applet"
done < <("$BUSYBOX" --list-full)
install -D -m 0600 "$MODULE" "$stage/reclaim.ko"
strip --strip-unneeded "$stage/reclaim.ko"
install -D -m 4755 "$GATE" "$stage/usr/bin/reclaim-approval"
strip --strip-all "$stage/usr/bin/reclaim-approval"
install -D -m 0755 "$ROOT/rootfs/init" "$stage/init"
install -D -m 0644 "$ROOT/rootfs/etc/passwd" "$stage/etc/passwd"
install -D -m 0644 "$ROOT/rootfs/etc/group" "$stage/etc/group"
install -D -m 0400 "$ROOT/rootfs/etc/shadow" "$stage/etc/shadow"
cat > "$stage/etc/motd" <<'MOTD'
RE:CLAIM — BOX 000
The export gate accepts an original approval response.
MOTD
chmod 0644 "$stage/etc/motd"
mkdir -p "$stage/dev" "$stage/proc" "$stage/sys" "$stage/tmp" "$stage/run" "$stage/home/ctf" "$stage/root"
chmod 1777 "$stage/tmp"
chmod 0755 "$stage/home" "$stage/home/ctf"
chmod 0700 "$stage/root"
mkdir -p "$(dirname "$OUTPUT")" "$(dirname "$MANIFEST")"
python3 "$ROOT/scripts/populate_vault.py" \
	--root "$stage" --flag-file "$FLAG_FILE" --private-manifest "$MANIFEST" \
	--dummy-count 127 --without-approval-token
chmod 0600 "$MANIFEST"
(
	cd "$stage"
	find . -print0 | sort -z | cpio --null --quiet -o --format=newc --owner=0:0 | gzip -9n > "$OUTPUT"
)
echo "built $OUTPUT"
