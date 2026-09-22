from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import Settings


class AuthenticationError(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class Identity:
    subject: str


class CTFdClient:
    """Validate a participant bearer token without retaining or logging it."""

    def __init__(self, settings: Settings):
        self.base_url = settings.ctfd_base_url
        self.challenge_id = settings.ctfd_challenge_id
        self.require_team = settings.ctfd_require_team
        self.timeout = settings.ctfd_timeout_seconds
        context = ssl.create_default_context(cafile=settings.ctfd_ca_file)
        self.opener = urllib.request.build_opener(
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPHandler(),
        )

    @staticmethod
    def _validate_token_syntax(token: str) -> None:
        if not 1 <= len(token) <= 512:
            raise AuthenticationError("invalid access token")
        if any(ord(character) < 0x21 or ord(character) > 0x7E for character in token):
            raise AuthenticationError("invalid access token")

    def _get(self, path: str, token: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            headers={
                "Accept": "application/json",
                # CTFd 3.x only evaluates Authorization tokens for requests
                # it classifies as JSON, including safe GET requests.
                "Content-Type": "application/json",
                "Authorization": f"Token {token}",
                "User-Agent": "reclaim-kubernetes-gateway/1.0",
            },
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            # HTTPError is also a file-like response. Explicitly close it so
            # repeated rejected participant tokens cannot leak sockets.
            error.close()
            raise AuthenticationError("CTFd rejected the access token") from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise AuthenticationError("CTFd rejected the access token") from error
        if len(raw) > 1024 * 1024:
            raise AuthenticationError("CTFd returned an oversized response")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuthenticationError("CTFd returned an invalid response") from error
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise AuthenticationError("CTFd rejected the access token")
        return payload

    @staticmethod
    def _positive_identifier(value: object) -> str | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int) and value > 0:
            return str(value)
        if isinstance(value, str) and value.isdigit() and int(value, 10) > 0:
            return str(int(value, 10))
        return None

    def validate(self, token: str) -> Identity:
        self._validate_token_syntax(token)
        payload = self._get("/api/v1/users/me", token)
        data = payload.get("data")
        if not isinstance(data, dict) or data.get("banned") is True:
            raise AuthenticationError("CTFd account is not eligible")

        team_id = self._positive_identifier(data.get("team_id"))
        user_id = self._positive_identifier(data.get("id"))
        if self.require_team:
            if team_id is None:
                raise AuthenticationError("the account is not assigned to a team")
            subject = f"team:{team_id}"
        else:
            if team_id is not None:
                subject = f"team:{team_id}"
            elif user_id is not None:
                subject = f"user:{user_id}"
            else:
                raise AuthenticationError("CTFd returned no usable identity")

        if self.challenge_id is not None:
            self._get(f"/api/v1/challenges/{self.challenge_id}", token)
        return Identity(subject=subject)
