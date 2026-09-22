#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


TOKENS = {
    **{f"integration-token-team{number:02d}": number for number in range(1, 33)},
    # The real-QEMU smoke uses a separate token so it cannot accidentally
    # overlap with the thirty-two-team FIFO integration scenario.
    "integration-token-team42": 42,
}


class CTFdHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        authorization = self.headers.get("Authorization", "")
        # Match CTFd 3.x's token middleware: bearer authentication is only
        # evaluated for requests classified as JSON.
        if self.headers.get("Content-Type") != "application/json":
            self.send_response(401)
            self.end_headers()
            return
        prefix = "Token "
        token = authorization[len(prefix) :] if authorization.startswith(prefix) else ""
        team_id = TOKENS.get(token)
        if team_id is None:
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/api/v1/users/me":
            payload = {
                "success": True,
                "data": {
                    "id": team_id + 1000,
                    "team_id": team_id,
                    "banned": False,
                },
            }
        elif self.path == "/api/v1/challenges/1":
            payload = {"success": True, "data": {"id": 1}}
        else:
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # Access headers contain bearer credentials. Never emit request logs.
        pass


class GuestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        # Fixed diagnostic markers only: never log peer addresses or payloads.
        print("MOCK_GUEST_ACCEPT", flush=True)
        self.wfile.write(b"MOCK-GUEST-READY\n")
        self.wfile.flush()
        print("MOCK_GUEST_READY_SENT", flush=True)
        while True:
            line = self.rfile.readline(4096)
            if not line:
                return
            self.wfile.write(b"GUEST:" + line)
            self.wfile.flush()


class GuestServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    mode = os.getenv("MOCK_MODE", "guest")
    if mode == "ctfd":
        ThreadingHTTPServer(("0.0.0.0", 8081), CTFdHandler).serve_forever()
    elif mode == "guest":
        GuestServer(("0.0.0.0", 31337), GuestHandler).serve_forever()
    else:
        raise SystemExit("invalid MOCK_MODE")


if __name__ == "__main__":
    main()
