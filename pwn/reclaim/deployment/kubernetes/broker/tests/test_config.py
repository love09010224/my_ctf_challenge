from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reclaim_gateway.config import ConfigError, Settings


class ConfigTests(unittest.TestCase):
    def environment(self, directory: str) -> dict[str, str]:
        secret = Path(directory) / "hmac"
        secret.write_bytes(b"x" * 48)
        redis_password = Path(directory) / "redis-password"
        redis_password.write_text("r" * 32, encoding="utf-8")
        return {
            "CTFD_BASE_URL": "https://ctf.example.org",
            "INSTANCE_NAMESPACE": "reclaim-instances",
            "CHALLENGE_IMAGE": "registry.invalid/reclaim@sha256:" + "a" * 64,
            "INSTANCE_NAME_SECRET_FILE": str(secret),
            "REDIS_URL": "redis://q2-redis:6379/0",
            "REDIS_PASSWORD_FILE": str(redis_password),
            "TLS_MODE": "plaintext",
        }

    def test_base_url_is_sufficient_without_admin_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, self.environment(directory), clear=True):
                settings = Settings.from_env()
        self.assertEqual(settings.ctfd_base_url, "https://ctf.example.org")
        self.assertEqual(settings.namespace, "reclaim-instances")
        self.assertEqual(settings.max_instances, 30)
        self.assertFalse(hasattr(settings, "ctfd_admin_token"))

    def test_capacity_is_fixed_at_thirty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self.environment(directory)
            environment["MAX_INSTANCES"] = "29"
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(ConfigError):
                    Settings.from_env()

    def test_redis_url_rejects_embedded_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self.environment(directory)
            environment["REDIS_URL"] = "redis://user:secret@q2-redis:6379/0"
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(ConfigError):
                    Settings.from_env()

    def test_plain_http_ctfd_requires_explicit_development_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self.environment(directory)
            environment["CTFD_BASE_URL"] = "http://ctfd.local"
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(ConfigError):
                    Settings.from_env()
            environment["CTFD_ALLOW_HTTP"] = "true"
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(Settings.from_env().ctfd_base_url, "http://ctfd.local")

    def test_direct_tls_requires_readable_certificate_and_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self.environment(directory)
            environment["TLS_MODE"] = "direct"
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(ConfigError):
                    Settings.from_env()


if __name__ == "__main__":
    unittest.main()
