#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import socket
import ssl
import sys
import time


FLAG_PATTERN = re.compile(rb"[A-Z][A-Z0-9_:.-]{1,31}\{[^\r\n}]{1,256}\}")
MAX_TRANSCRIPT = 2 * 1024 * 1024


def receive_until(
    sock: ssl.SSLSocket,
    transcript: bytearray,
    predicate,
    timeout: float,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(bytes(transcript)):
            return True
        sock.settimeout(min(1.0, max(0.1, deadline - time.monotonic())))
        try:
            chunk = sock.recv(65536)
        except (TimeoutError, socket.timeout):
            continue
        if not chunk:
            break
        transcript.extend(chunk)
        if len(transcript) > MAX_TRANSCRIPT:
            raise RuntimeError("smoke transcript exceeded the safety limit")
    return predicate(bytes(transcript))


def fixed_failure(transcript: bytes) -> str:
    if FLAG_PATTERN.search(transcript):
        raise RuntimeError("unexpected flag-shaped output during failed smoke")
    checks = {
        "authenticated": b"Authenticated." in transcript,
        "allocated": b"Slot allocated." in transcript,
        "ready": b" ready; " in transcript,
        "busybox": b"BusyBox" in transcript,
        "shell": b"/ $" in transcript,
        "unavailable": b"temporarily unavailable" in transcript.lower(),
    }
    return " ".join(f"{name}={int(value)}" for name, value in checks.items())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authenticated RE:CLAIM uid-1000 smoke without flag access"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--ca-file")
    args = parser.parse_args()

    raw_token = sys.stdin.buffer.readline(1024)
    if not raw_token or len(raw_token) > 514 or not raw_token.endswith(b"\n"):
        raise SystemExit("expected one Access Token line on stdin")
    token = raw_token.rstrip(b"\r\n")
    if not token or any(byte < 0x21 or byte > 0x7E for byte in token):
        raise SystemExit("Access Token contains invalid bytes")
    raw_token = b""

    context = ssl.create_default_context(cafile=args.ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    transcript = bytearray()
    marker = f"RECLAIM_SMOKE_{__import__('secrets').token_hex(16)}".encode("ascii")
    try:
        with socket.create_connection((args.host, args.port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=args.server_name) as sock:
                if not receive_until(sock, transcript, lambda data: b"Token: " in data, 10):
                    raise RuntimeError("gateway token prompt did not appear")
                sock.sendall(token + b"\n")
                if not receive_until(
                    sock,
                    transcript,
                    lambda data: b"BusyBox" in data and b"/ $" in data,
                    150,
                ):
                    raise RuntimeError("guest did not boot: " + fixed_failure(bytes(transcript)))
                sock.sendall(b"\nid\nprintf '" + marker + b"\\n'\n")
                if not receive_until(
                    sock,
                    transcript,
                    lambda data: b"uid=1000" in data and marker in data,
                    15,
                ):
                    raise RuntimeError("uid-1000 command round trip failed")
    except (OSError, ssl.SSLError, RuntimeError) as error:
        raise SystemExit(f"smoke failed: {error}") from None

    if token in transcript:
        raise SystemExit("gateway echoed or forwarded the participant token")
    token = b""
    if FLAG_PATTERN.search(transcript):
        raise SystemExit("unexpected flag-shaped output during smoke")
    print("[RECLAIM-Q2-AUTHENTICATED-SMOKE-PASS] uid1000=1 flag_output=0 token_echo=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
