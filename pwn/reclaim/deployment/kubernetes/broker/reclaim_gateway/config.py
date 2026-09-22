from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(ValueError):
    pass


DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?")


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _boolean(name: str, default: bool) -> bool:
    raw = os.getenv(name, "true" if default else "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean")


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise ConfigError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _number(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = float(raw)
    except ValueError as error:
        raise ConfigError(f"{name} must be a number") from error
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _optional_integer(name: str) -> int | None:
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise ConfigError(f"{name} must be an integer") from error
    if value <= 0:
        raise ConfigError(f"{name} must be positive")
    return value


def _json_object(name: str) -> dict[str, str]:
    raw = os.getenv(name, "{}").strip()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ConfigError(f"{name} must be valid JSON") from error
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise ConfigError(f"{name} must be a string-to-string JSON object")
    return value


def _json_array(name: str) -> list[dict[str, object]]:
    raw = os.getenv(name, "[]").strip()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ConfigError(f"{name} must be valid JSON") from error
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ConfigError(f"{name} must be a JSON array of objects")
    return value


def _namespace() -> str:
    value = os.getenv("INSTANCE_NAMESPACE", "").strip()
    if not value:
        path = Path(os.getenv(
            "POD_NAMESPACE_FILE",
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        ))
        if path.is_file():
            value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ConfigError("INSTANCE_NAMESPACE or POD_NAMESPACE_FILE is required")
    if len(value) > 63 or DNS_LABEL.fullmatch(value) is None:
        raise ConfigError("INSTANCE_NAMESPACE is not a valid DNS label")
    return value


def _secret_file() -> bytes:
    path = Path(_required("INSTANCE_NAME_SECRET_FILE"))
    try:
        value = path.read_bytes().strip()
    except OSError as error:
        raise ConfigError("cannot read INSTANCE_NAME_SECRET_FILE") from error
    if len(value) < 32:
        raise ConfigError("instance-name HMAC secret must contain at least 32 bytes")
    return value


def _text_secret_file(name: str, description: str) -> str:
    path = Path(_required(name))
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise ConfigError(f"cannot read {name}") from error
    if len(value) < 16 or len(value) > 512 or any(ord(char) < 0x21 for char in value):
        raise ConfigError(f"{description} must contain 16-512 printable characters")
    return value


def _validate_base_url(value: str, allow_http: bool) -> str:
    parsed = urlsplit(value)
    allowed_schemes = {"https"} | ({"http"} if allow_http else set())
    if (
        parsed.scheme not in allowed_schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigError("CTFD_BASE_URL must be an HTTPS origin or base path")
    return value.rstrip("/")


def _validate_redis_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"redis", "rediss"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (parsed.path not in {"", "/"} and not re.fullmatch(r"/[0-9]+", parsed.path))
    ):
        raise ConfigError(
            "REDIS_URL must be a redis:// or rediss:// URL without embedded credentials"
        )
    return value


def _redis_prefix() -> str:
    value = os.getenv("REDIS_PREFIX", "q2:reclaim").strip()
    if not re.fullmatch(r"[A-Za-z0-9:_-]{1,64}", value):
        raise ConfigError("REDIS_PREFIX contains invalid characters")
    return value


@dataclass(frozen=True)
class Settings:
    ctfd_base_url: str
    ctfd_challenge_id: int | None
    ctfd_require_team: bool
    ctfd_ca_file: str | None
    ctfd_timeout_seconds: int
    namespace: str
    challenge_image: str
    instance_name_secret: bytes = field(repr=False)
    redis_url: str = "redis://q2-redis:6379/0"
    redis_password: str = field(default="", repr=False)
    redis_ca_file: str | None = None
    redis_prefix: str = "q2:reclaim"
    instance_timeout_seconds: int = 900
    finished_job_ttl_seconds: int = 60
    max_instances: int = 30
    backend_startup_seconds: int = 90
    image_pull_policy: str = "IfNotPresent"
    image_pull_secrets: tuple[str, ...] = ()
    node_selector: dict[str, str] = field(default_factory=dict)
    tolerations: tuple[dict[str, object], ...] = ()
    runtime_class_name: str | None = None
    priority_class_name: str | None = None
    instance_cpu_request: str = "250m"
    instance_cpu_limit: str = "2"
    instance_memory: str = "640Mi"
    listen_host: str = "0.0.0.0"
    listen_port: int = 31337
    health_host: str = "0.0.0.0"
    health_port: int = 8080
    tls_mode: str = "direct"
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    token_timeout_seconds: int = 30
    queue_poll_seconds: float = 1.0
    queue_status_seconds: int = 5
    queue_wait_seconds: int = 3600
    queued_input_limit: int = 65536
    max_connections: int = 256
    auth_attempts_per_minute: int = 300
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        allow_http = _boolean("CTFD_ALLOW_HTTP", False)
        base_url = _validate_base_url(_required("CTFD_BASE_URL"), allow_http)

        tls_mode = os.getenv("TLS_MODE", "direct").strip().lower()
        if tls_mode not in {"direct", "upstream", "plaintext"}:
            raise ConfigError("TLS_MODE must be direct, upstream, or plaintext")
        cert_file = os.getenv("TLS_CERT_FILE", "").strip() or None
        key_file = os.getenv("TLS_KEY_FILE", "").strip() or None
        if tls_mode == "direct":
            if not cert_file or not key_file:
                raise ConfigError("direct TLS requires TLS_CERT_FILE and TLS_KEY_FILE")
            if not Path(cert_file).is_file() or not Path(key_file).is_file():
                raise ConfigError("direct TLS certificate or key is not readable")
        elif cert_file or key_file:
            raise ConfigError("TLS certificate paths are valid only in direct mode")

        pull_secrets = tuple(
            item.strip()
            for item in os.getenv("INSTANCE_IMAGE_PULL_SECRETS", "").split(",")
            if item.strip()
        )
        if any(len(item) > 253 for item in pull_secrets):
            raise ConfigError("INSTANCE_IMAGE_PULL_SECRETS contains an invalid name")

        image_pull_policy = os.getenv(
            "INSTANCE_IMAGE_PULL_POLICY", "IfNotPresent"
        ).strip()
        if image_pull_policy not in {"Always", "IfNotPresent", "Never"}:
            raise ConfigError("INSTANCE_IMAGE_PULL_POLICY is invalid")

        return cls(
            ctfd_base_url=base_url,
            ctfd_challenge_id=_optional_integer("CTFD_CHALLENGE_ID"),
            ctfd_require_team=_boolean("CTFD_REQUIRE_TEAM", True),
            ctfd_ca_file=os.getenv("CTFD_CA_FILE", "").strip() or None,
            ctfd_timeout_seconds=_integer("CTFD_TIMEOUT_SECONDS", 5, 1, 30),
            namespace=_namespace(),
            challenge_image=_required("CHALLENGE_IMAGE"),
            instance_name_secret=_secret_file(),
            redis_url=_validate_redis_url(_required("REDIS_URL")),
            redis_password=_text_secret_file(
                "REDIS_PASSWORD_FILE", "Redis password"
            ),
            redis_ca_file=os.getenv("REDIS_CA_FILE", "").strip() or None,
            redis_prefix=_redis_prefix(),
            instance_timeout_seconds=_integer(
                "INSTANCE_TIMEOUT_SECONDS", 900, 60, 86400
            ),
            finished_job_ttl_seconds=_integer(
                "FINISHED_JOB_TTL_SECONDS", 60, 0, 86400
            ),
            # The event capacity contract is deliberately fixed. Changing it is
            # an infrastructure decision, not a runtime tuning knob.
            max_instances=_integer("MAX_INSTANCES", 30, 30, 30),
            backend_startup_seconds=_integer(
                "BACKEND_STARTUP_SECONDS", 90, 5, 300
            ),
            image_pull_policy=image_pull_policy,
            image_pull_secrets=pull_secrets,
            node_selector=_json_object("INSTANCE_NODE_SELECTOR_JSON"),
            tolerations=tuple(_json_array("INSTANCE_TOLERATIONS_JSON")),
            runtime_class_name=os.getenv("INSTANCE_RUNTIME_CLASS", "").strip() or None,
            priority_class_name=os.getenv(
                "INSTANCE_PRIORITY_CLASS", ""
            ).strip() or None,
            instance_cpu_request=os.getenv(
                "INSTANCE_CPU_REQUEST", "250m"
            ).strip(),
            instance_cpu_limit=os.getenv("INSTANCE_CPU_LIMIT", "2").strip(),
            instance_memory=os.getenv("INSTANCE_MEMORY", "640Mi").strip(),
            listen_host=os.getenv("LISTEN_HOST", "0.0.0.0").strip(),
            listen_port=_integer("LISTEN_PORT", 31337, 1024, 65535),
            health_host=os.getenv("HEALTH_HOST", "0.0.0.0").strip(),
            health_port=_integer("HEALTH_PORT", 8080, 1024, 65535),
            tls_mode=tls_mode,
            tls_cert_file=cert_file,
            tls_key_file=key_file,
            token_timeout_seconds=_integer("TOKEN_TIMEOUT_SECONDS", 30, 5, 300),
            queue_poll_seconds=_number("QUEUE_POLL_SECONDS", 1.0, 0.1, 10.0),
            queue_status_seconds=_integer("QUEUE_STATUS_SECONDS", 5, 1, 60),
            queue_wait_seconds=_integer("QUEUE_WAIT_SECONDS", 3600, 60, 14400),
            queued_input_limit=_integer(
                "QUEUED_INPUT_LIMIT", 65536, 0, 1024 * 1024
            ),
            max_connections=_integer("MAX_CONNECTIONS", 256, 1, 10000),
            auth_attempts_per_minute=_integer(
                "AUTH_ATTEMPTS_PER_MINUTE", 300, 1, 1000
            ),
            log_level=os.getenv("LOG_LEVEL", "INFO").strip().upper(),
        )
