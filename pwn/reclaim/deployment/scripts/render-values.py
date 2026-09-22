#!/usr/bin/env python3
from __future__ import annotations

import json
import ipaddress
import os
import re
import sys
from urllib.parse import urlsplit


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def boolean(name: str) -> bool:
    value = required(name).lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise SystemExit(f"{name} must be true or false")


def dns_label(name: str) -> str:
    value = required(name)
    if len(value) > 63 or re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", value) is None:
        raise SystemExit(f"{name} is not a DNS label")
    return value


def exact_ipv4_cidrs(name: str) -> list[str]:
    raw = required(name)
    result: list[str] = []
    for value in raw.split(","):
        value = value.strip()
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise SystemExit(f"{name} contains an invalid CIDR: {value}") from error
        if network.version != 4 or network.prefixlen != 32:
            raise SystemExit(f"{name} entries must be exact IPv4 /32 networks")
        if network.network_address == ipaddress.ip_address("169.254.169.254"):
            raise SystemExit(f"{name} must not allow the metadata endpoint")
        canonical = str(network)
        if canonical not in result:
            result.append(canonical)
    return result


def port(name: str) -> int:
    value = required(name)
    try:
        number = int(value, 10)
    except ValueError as error:
        raise SystemExit(f"{name} must be an integer port") from error
    if not 1 <= number <= 65535:
        raise SystemExit(f"{name} must be between 1 and 65535")
    return number


base_url = required("CTFD_BASE_URL").rstrip("/")
parsed = urlsplit(base_url)
if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
    raise SystemExit("CTFD_BASE_URL must be an HTTPS origin or base path without credentials")
ctfd_port = parsed.port or 443

challenge_id = required("CTFD_CHALLENGE_ID")
if not challenge_id.isdigit() or int(challenge_id) <= 0:
    raise SystemExit("CTFD_CHALLENGE_ID must be a positive numeric ID")

service_type = required("PUBLIC_SERVICE_TYPE")
if service_type not in {"LoadBalancer", "NodePort"}:
    raise SystemExit("PUBLIC_SERVICE_TYPE must be LoadBalancer or NodePort")

node_port = int(required("PUBLIC_NODE_PORT"))
if service_type == "NodePort" and not 30000 <= node_port <= 32767:
    raise SystemExit("PUBLIC_NODE_PORT must be in the default Kubernetes NodePort range")

gateway_namespace = dns_label("GATEWAY_NAMESPACE")
instance_namespace = dns_label("INSTANCE_NAMESPACE")
if gateway_namespace == instance_namespace:
    raise SystemExit("gateway and instance namespaces must differ")
release_name = dns_label("RELEASE_NAME")
if len(f"{release_name}-reclaim-gateway") > 63:
    raise SystemExit("RELEASE_NAME is too long for deterministic resource names")

values: dict[str, object] = {
    "gateway": {
        "replicaCount": 1,
        "image": {
            "repository": required("GATEWAY_IMAGE_REPOSITORY"),
            "tag": required("GATEWAY_IMAGE_TAG"),
            "digest": "",
            "pullPolicy": "Never",
        },
        "maxConnections": 256,
        "queueWaitSeconds": 3600,
        "queuedInputLimit": 65536,
    },
    "ctfd": {
        "baseUrl": base_url,
        "challengeId": challenge_id,
        "requireTeam": boolean("CTFD_REQUIRE_TEAM"),
        "allowHttp": False,
    },
    "tls": {
        "mode": "direct",
        "existingSecret": "reclaim-gateway-tls",
    },
    "secrets": {"existingSecret": "reclaim-gateway-secrets"},
    "redis": {"enabled": True, "existingSecret": "reclaim-q2-redis-auth"},
    "service": {"type": service_type, "port": 31337},
    "challenge": {
        "namespace": instance_namespace,
        "image": {
            "repository": required("CHALLENGE_IMAGE_REPOSITORY"),
            "tag": required("CHALLENGE_IMAGE_TAG"),
            "digest": "",
            "pullPolicy": "Never",
        },
        "timeoutSeconds": 900,
        "finishedJobTtlSeconds": 60,
        "maxInstances": 30,
        "backendStartupSeconds": 90,
        "resources": {
            "requests": {"cpu": "250m", "memory": "640Mi"},
            "limits": {"cpu": "2", "memory": "640Mi"},
        },
        "nodeSelector": {
            "kubernetes.io/arch": "amd64",
            "workload": "untrusted-qemu",
        },
    },
    "networkPolicy": {
        "enabled": True,
        "kubernetesApiCidrs": exact_ipv4_cidrs("KUBERNETES_API_EGRESS_CIDRS"),
        "kubernetesApiPort": 443,
        "kubernetesApiEndpointCidrs": exact_ipv4_cidrs(
            "KUBERNETES_API_ENDPOINT_EGRESS_CIDRS"
        ),
        "kubernetesApiEndpointPort": port("KUBERNETES_API_ENDPOINT_EGRESS_PORT"),
        "ctfdCidrs": exact_ipv4_cidrs("CTFD_EGRESS_CIDRS"),
        "ctfdPort": ctfd_port,
        "ctfdPodSelector": {},
    },
    "quota": {
        "enabled": True,
        "hard": {
            "pods": "30",
            "count/jobs.batch": "30",
            "count/services": "30",
            "requests.cpu": "7500m",
            "requests.memory": "19200Mi",
            "limits.cpu": "60",
            "limits.memory": "19200Mi",
        },
    },
}

ca_file = os.environ.get("CTFD_CA_FILE", "").strip()
if ca_file:
    values["ctfd"]["caSecret"] = "reclaim-ctfd-ca"  # type: ignore[index]

service = values["service"]
assert isinstance(service, dict)
if service_type == "NodePort":
    service["nodePort"] = node_port
if value := os.environ.get("LOAD_BALANCER_IP", "").strip():
    service["loadBalancerIP"] = value
if raw := os.environ.get("LOAD_BALANCER_SOURCE_RANGES", "").strip():
    ranges = [item.strip() for item in raw.split(",") if item.strip()]
    service["loadBalancerSourceRanges"] = ranges

json.dump(values, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
sys.stdout.write("\n")
