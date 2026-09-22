#!/usr/bin/env bash
set -euo pipefail

DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec qemu-system-x86_64 \
	-machine "accel=${ACCEL:-tcg}" \
	-m 512M \
	-smp 2 \
	-cpu qemu64,+smep,+smap \
	-kernel "$DIR/bzImage" \
	-initrd "$DIR/rootfs.cpio.gz" \
	-append 'console=ttyS0 quiet kaslr panic=1 oops=panic pti=on' \
	-nographic \
	-monitor none \
	-net none \
	-no-reboot
