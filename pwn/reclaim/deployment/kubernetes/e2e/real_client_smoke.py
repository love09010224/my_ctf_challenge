#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import ssl
import sys
import time

from check_client import open_tls


FLAG_PATTERN = re.compile(rb"[A-Z][A-Z0-9_]{1,15}\{[^\r\n}]{1,256}\}")
TOKEN = b"integration-token-team42"


def failure_summary(transcript: bytes) -> str:
    """Return only fixed predicates; never expose guest or bearer bytes."""
    if FLAG_PATTERN.search(transcript):
        raise SystemExit("unexpected flag-shaped output during failed real-service smoke")
    predicates = {
        "authenticated": b"Authenticated." in transcript,
        "instance_ready": b" ready; " in transcript,
        "backend_unavailable": b"temporarily unavailable" in transcript.lower(),
        "busybox": b"BusyBox" in transcript,
        "shell_prompt": b"/ $" in transcript,
    }
    return " ".join(f"{key}={int(value)}" for key, value in predicates.items()) + (
        f" bytes={len(transcript)}"
    )


def receive_until(sock: ssl.SSLSocket, transcript: bytearray, predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    sock.settimeout(0.5)
    while time.monotonic() < deadline:
        if predicate(bytes(transcript)):
            return True
        try:
            chunk = sock.recv(65536)
        except TimeoutError:
            continue
        if not chunk:
            break
        transcript.extend(chunk)
    return predicate(bytes(transcript))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=23138)
    args = parser.parse_args()
    transcript = bytearray()
    with open_tls(args.port) as sock:
        if not receive_until(sock, transcript, lambda data: b"Token: " in data, 10):
            raise SystemExit("gateway token prompt did not appear")
        sock.sendall(TOKEN + b"\n")
        if not receive_until(
            sock,
            transcript,
            lambda data: b"BusyBox" in data and b"/ $" in data,
            120,
        ):
            raise SystemExit(
                "real uid-1000 guest shell did not boot; "
                + failure_summary(bytes(transcript))
            )
        sock.sendall(b"\nid\necho KUBERNETES_REAL_SERVICE_OK\n")
        if not receive_until(
            sock,
            transcript,
            lambda data: b"uid=1000" in data
            and b"KUBERNETES_REAL_SERVICE_OK" in data,
            15,
        ):
            raise SystemExit("real guest command round-trip failed")
    if TOKEN in transcript:
        raise SystemExit("gateway echoed or forwarded the participant token")
    if FLAG_PATTERN.search(transcript):
        raise SystemExit("unexpected flag-shaped output during real-service smoke")
    print("[KUBERNETES-REAL-SERVICE-SMOKE-PASS] uid1000=1 flag_output=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
