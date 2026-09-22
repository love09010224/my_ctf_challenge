from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from reclaim_gateway.config import Settings
from reclaim_gateway.ctfd import AuthenticationError, CTFdClient


class _Handler(BaseHTTPRequestHandler):
    expected_token = "participant-access-token"
    requests: list[tuple[str, str | None, str | None]] = []

    def do_GET(self) -> None:  # noqa: N802
        authorization = self.headers.get("Authorization")
        content_type = self.headers.get("Content-Type")
        self.__class__.requests.append((self.path, authorization, content_type))
        if (
            authorization != f"Token {self.expected_token}"
            or content_type != "application/json"
        ):
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/api/v1/users/me":
            payload = {
                "success": True,
                "data": {"id": 7, "team_id": 42, "banned": False},
            }
        elif self.path == "/api/v1/challenges/9":
            payload = {"success": True, "data": {"id": 9}}
        else:
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass


def settings(base_url: str, *, challenge_id: int | None = 9) -> Settings:
    return Settings(
        ctfd_base_url=base_url,
        ctfd_challenge_id=challenge_id,
        ctfd_require_team=True,
        ctfd_ca_file=None,
        ctfd_timeout_seconds=2,
        namespace="reclaim",
        challenge_image="private/reclaim@sha256:test",
        instance_name_secret=b"x" * 32,
        tls_mode="plaintext",
    )


class CTFdClientTests(unittest.TestCase):
    def setUp(self) -> None:
        _Handler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_participant_token_resolves_team_and_checks_challenge(self) -> None:
        base = f"http://127.0.0.1:{self.server.server_port}"
        identity = CTFdClient(settings(base)).validate(_Handler.expected_token)
        self.assertEqual(identity.subject, "team:42")
        self.assertEqual(
            _Handler.requests,
            [
                (
                    "/api/v1/users/me",
                    f"Token {_Handler.expected_token}",
                    "application/json",
                ),
                (
                    "/api/v1/challenges/9",
                    f"Token {_Handler.expected_token}",
                    "application/json",
                ),
            ],
        )

    def test_invalid_token_error_does_not_echo_bearer(self) -> None:
        base = f"http://127.0.0.1:{self.server.server_port}"
        secret = "definitely-not-the-token"
        with self.assertRaises(AuthenticationError) as caught:
            CTFdClient(settings(base, challenge_id=None)).validate(secret)
        self.assertNotIn(secret, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
