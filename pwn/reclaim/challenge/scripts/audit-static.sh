#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
MODULE=${MODULE:-"$ROOT_DIR/module/reclaim_v4_release.ko"}
KCONFIG=${KCONFIG:-"$ROOT_DIR/build/kernel-6.12.103/.config"}

for forbidden in \
	commit_creds prepare_kernel_cred call_usermodehelper \
	modprobe_path core_pattern page_offset_base vmemmap_base phys_base; do
	if nm -u "$MODULE" | awk '{print $2}' | grep -Fxq "$forbidden"; then
		echo "forbidden module import: $forbidden" >&2
		exit 1
	fi
done

if strings -a "$MODULE" | grep -Fq '/dev/reclaim-archive'; then
	echo 'monolithic archive device survived' >&2
	exit 1
fi
if strings -a "$MODULE" | grep -Fq 'reclaim-work'; then
	echo 'removed writable work carrier survived' >&2
	exit 1
fi
if grep -Rq --include='*.c' --include='*.h' \
	'RECLAIM_ARCHIVE_IOC_DROP_FRAME' "$ROOT_DIR/module"; then
	echo 'dedicated catalog-frame free operation survived' >&2
	exit 1
fi
if grep -RqE --include='*.c' --include='*.h' \
	'RECLAIM_ARCHIVE_IOC_(SELECTOR|ISSUE|SELECT_ORDER|SELECT_LEASE|NEXT|RECOVER)' \
	"$ROOT_DIR/module"; then
	echo 'exploit-spine archive operation survived' >&2
	exit 1
fi

grep -q '^CONFIG_STATIC_USERMODEHELPER=y$' "$KCONFIG"
grep -q '^CONFIG_STATIC_USERMODEHELPER_PATH=""$' "$KCONFIG"
grep -q '^# CONFIG_KALLSYMS is not set$' "$KCONFIG"
grep -q '^# CONFIG_USER_NS is not set$' "$KCONFIG"
grep -q '^# CONFIG_BPF_SYSCALL is not set$' "$KCONFIG"
grep -q '^# CONFIG_IO_URING is not set$' "$KCONFIG"
grep -q '^CONFIG_RANDOMIZE_BASE=y$' "$KCONFIG"
grep -q '^CONFIG_SLAB_FREELIST_HARDENED=y$' "$KCONFIG"
grep -q '^CONFIG_SLAB_FREELIST_RANDOM=y$' "$KCONFIG"

echo '[V4-STATIC-SHORTCUT-AUDIT-PASS]'
