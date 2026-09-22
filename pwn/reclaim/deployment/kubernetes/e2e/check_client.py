#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time


def receive_until(sock: ssl.SSLSocket, marker: bytes, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    value = bytearray()
    while marker not in value:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"did not receive marker {marker!r}")
        sock.settimeout(min(remaining, 2))
        try:
            chunk = sock.recv(65536)
        except TimeoutError:
            continue
        if not chunk:
            break
        value.extend(chunk)
    return bytes(value)


def open_tls(port: int, timeout: float = 30) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    deadline = time.monotonic() + timeout
    last_error: OSError | ssl.SSLError | None = None
    while time.monotonic() < deadline:
        raw: socket.socket | None = None
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=2)
            return context.wrap_socket(raw, server_hostname="localhost")
        except (OSError, ssl.SSLError) as error:
            last_error = error
            if raw is not None:
                raw.close()
            time.sleep(0.2)
    raise TimeoutError("gateway TLS endpoint did not become ready") from last_error


def connect(port: int, token: str, command: bytes = b"ping\n") -> bytes:
    with open_tls(port) as sock:
        transcript = receive_until(sock, b"Token: ", 10)
        # Coalesce the bearer and first guest command to test buffered data flow.
        sock.sendall(token.encode("ascii") + b"\n" + command)
        expected = b"GUEST:" + command
        transcript += receive_until(sock, expected, 60)
        return transcript


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=23137)
    parser.add_argument("--token", required=True)
    parser.add_argument("--expect", default="GUEST:ping")
    parser.add_argument("--forbid", default="")
    args = parser.parse_args()
    transcript = connect(args.port, args.token)
    if args.expect.encode() not in transcript:
        raise SystemExit("expected marker was not returned")
    if args.forbid and args.forbid.encode() in transcript:
        raise SystemExit("forbidden bearer material reached the guest transcript")
    # Deliberately print only fixed markers, never the transcript or token.
    print("[KUBERNETES-E2E-CLIENT-PASS]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
