ROOT := $(abspath .)
KERNEL_VERSION := 6.12.103
KERNEL_BUILD ?= $(ROOT)/build/kernel-$(KERNEL_VERSION)
BUSYBOX ?= $(shell command -v busybox 2>/dev/null)

.PHONY: all kernel module user rootfs bundle audit clean
all: module user
kernel:
	./scripts/prepare-kernel.sh
module:
	@test -d "$(KERNEL_BUILD)" || { echo 'run make kernel first' >&2; exit 1; }
	$(MAKE) -C module KDIR="$(KERNEL_BUILD)"
user:
	$(MAKE) -C user
rootfs: module user
	BUSYBOX="$(BUSYBOX)" ./scripts/build-rootfs.sh
bundle: rootfs
	./scripts/build-player-bundle.sh
audit: bundle
	python3 ./scripts/audit-player-candidate.py \
		--kernel build/bzImage --rootfs build/rootfs.cpio.gz
	python3 ./scripts/audit-sealed-candidate.py \
		--bundle build/reclaim-box-000-player.tar.gz \
		--extract-vmlinux build/linux-$(KERNEL_VERSION)/scripts/extract-vmlinux \
		--kernel-config build/kernel-$(KERNEL_VERSION)/.config
clean:
	$(MAKE) -C user clean
	@if [ -d "$(KERNEL_BUILD)" ]; then $(MAKE) -C module KDIR="$(KERNEL_BUILD)" clean; fi
	rm -rf build/rootfs.cpio.gz build/vault-private.json \
		build/reclaim-box-000-player.tar.gz
