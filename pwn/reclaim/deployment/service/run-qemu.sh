#!/bin/sh
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
QEMU_SYSTEM_X86_64=${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}
SERIAL_BIND_HOST=${SERIAL_BIND_HOST:-0.0.0.0}
SERIAL_PORT=${SERIAL_PORT:-31337}

for file in "$DIR/bzImage" "$DIR/rootfs.cpio.gz"; do
    [ -f "$file" ] || {
        echo "missing service artifact: $file" >&2
        exit 1
    }
done

case "$SERIAL_BIND_HOST" in
    ''|*[!a-zA-Z0-9_.:-]*)
        echo 'SERIAL_BIND_HOST contains invalid characters' >&2
        exit 64
        ;;
esac
case "$SERIAL_PORT" in
    ''|*[!0-9]*)
        echo 'SERIAL_PORT must be an integer' >&2
        exit 64
        ;;
esac
if [ "$SERIAL_PORT" -lt 1024 ] || [ "$SERIAL_PORT" -gt 65535 ]; then
    echo 'SERIAL_PORT must be between 1024 and 65535' >&2
    exit 64
fi

# The VM waits for the first TCP serial client before booting. There is no
# guest NIC and no monitor. Authentication and per-team lifecycle belong to
# the organizer's instancer, outside this image.  The console_noecho marker is
# consumed by player-init only on this TCP transport: ncat keeps the local tty
# echo, while disabling guest echo prevents BusyBox ash's cursor-position query
# from being rendered as "^[[<row>;<col>R" by the participant terminal.
exec "$QEMU_SYSTEM_X86_64" \
    -machine accel=tcg \
    -m 512M \
    -smp 2 \
    -cpu qemu64,+smep,+smap \
    -kernel "$DIR/bzImage" \
    -initrd "$DIR/rootfs.cpio.gz" \
    -append 'console=ttyS0 quiet kaslr panic=1 oops=panic pti=on reclaim.console_noecho=1' \
    -display none \
    -monitor none \
    -net none \
    -chardev "socket,id=console,host=${SERIAL_BIND_HOST},port=${SERIAL_PORT},server=on,wait=on,nodelay=on" \
    -serial chardev:console \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
    -no-reboot
