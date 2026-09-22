#!/bin/sh
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VM_TIMEOUT_SECONDS=${VM_TIMEOUT_SECONDS:-900}

case "$VM_TIMEOUT_SECONDS" in
    ''|*[!0-9]*)
        echo 'VM_TIMEOUT_SECONDS must be an integer' >&2
        exit 64
        ;;
esac

if [ "$VM_TIMEOUT_SECONDS" -gt 86400 ]; then
    echo 'VM_TIMEOUT_SECONDS must be between 0 and 86400' >&2
    exit 64
fi

# Zero is an explicit organizer override. Normal deployments should let both
# their instancer and this outer timeout bound the lifetime of the VM.
if [ "$VM_TIMEOUT_SECONDS" -eq 0 ]; then
    exec "$DIR/run-qemu.sh"
fi

exec timeout --foreground --signal=TERM --kill-after=3 \
    "$VM_TIMEOUT_SECONDS" "$DIR/run-qemu.sh"
