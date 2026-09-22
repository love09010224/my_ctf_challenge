#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

import yaml


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def by_component(documents: list[dict], kind: str, component: str) -> dict:
    matches = [
        item
        for item in documents
        if item.get("kind") == kind
        and item.get("metadata", {}).get("labels", {}).get(
            "app.kubernetes.io/component"
        )
        == component
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one {component} {kind}, found {len(matches)}")
    return matches[0]


def gateway_object(documents: list[dict], kind: str) -> dict:
    matches = [
        item
        for item in documents
        if item.get("kind") == kind
        and item.get("metadata", {}).get("labels", {}).get(
            "app.kubernetes.io/component"
        )
        != "redis"
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one gateway {kind}, found {len(matches)}")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rendered", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--flag-file", type=Path)
    args = parser.parse_args()

    documents = [
        value
        for value in yaml.safe_load_all(args.rendered.read_text(encoding="utf-8"))
        if isinstance(value, dict)
    ]
    errors: list[str] = []
    kinds = [item.get("kind") for item in documents]
    require("Secret" not in kinds, "chart must not render secret material", errors)

    try:
        deployment = gateway_object(documents, "Deployment")
        service = gateway_object(documents, "Service")
        redis_deployment = by_component(documents, "Deployment", "redis")
        redis_service = by_component(documents, "Service", "redis")
        role = gateway_object(documents, "Role")
        service_account = gateway_object(documents, "ServiceAccount")
    except ValueError as error:
        errors.append(str(error))
        deployment = service = redis_deployment = redis_service = {}
        role = service_account = {}

    if deployment:
        spec = deployment.get("spec", {})
        pod = spec.get("template", {}).get("spec", {})
        containers = pod.get("containers", [])
        require(spec.get("replicas") == 1, "gateway must have one replica", errors)
        require(
            spec.get("strategy", {}).get("type") == "Recreate",
            "gateway rollout must avoid overlapping replicas",
            errors,
        )
        require(
            pod.get("automountServiceAccountToken") is True,
            "gateway needs its scoped service-account token",
            errors,
        )
        require(len(containers) == 1, "gateway Deployment must have one container", errors)
        if containers:
            container = containers[0]
            security = container.get("securityContext", {})
            require(
                security.get("readOnlyRootFilesystem") is True,
                "gateway root filesystem must be read-only",
                errors,
            )
            require(
                security.get("allowPrivilegeEscalation") is False,
                "gateway privilege escalation must be disabled",
                errors,
            )
            require(
                security.get("capabilities", {}).get("drop") == ["ALL"],
                "gateway must drop all capabilities",
                errors,
            )
            env = {
                item.get("name"): item.get("value")
                for item in container.get("env", [])
                if isinstance(item, dict)
            }
            require("CTFD_BASE_URL" in env, "CTFd URL is missing", errors)
            require("REDIS_URL" in env, "Redis URL is missing", errors)
            require(
                env.get("REDIS_PASSWORD_FILE")
                == "/var/run/secrets/reclaim-redis/password",
                "Redis password must be file-mounted",
                errors,
            )
            require(env.get("MAX_INSTANCES") == "30", "capacity must be exactly 30", errors)
            require(
                env.get("INSTANCE_CPU_REQUEST") == "250m",
                "instance CPU request must be exactly 250m",
                errors,
            )
            require(env.get("INSTANCE_CPU_LIMIT") == "2", "instance CPU limit must be exactly 2", errors)
            require(env.get("INSTANCE_MEMORY") == "640Mi", "instance memory must be exactly 640Mi", errors)
            require(
                not any(
                    isinstance(name, str)
                    and ("ADMIN" in name or name in {"CTFD_TOKEN", "CTFD_API_TOKEN"})
                    for name in env
                ),
                "gateway must not require a CTFd administrator token",
                errors,
            )

    if redis_deployment:
        spec = redis_deployment.get("spec", {})
        pod = spec.get("template", {}).get("spec", {})
        containers = pod.get("containers", [])
        require(spec.get("replicas") == 1, "Redis must have one replica", errors)
        require(
            pod.get("automountServiceAccountToken") is False,
            "Redis must not receive a service-account token",
            errors,
        )
        require(len(containers) == 1, "Redis Deployment must have one container", errors)
        if containers:
            security = containers[0].get("securityContext", {})
            require(
                security.get("readOnlyRootFilesystem") is True,
                "Redis root filesystem must be read-only",
                errors,
            )
            require(
                security.get("allowPrivilegeEscalation") is False,
                "Redis privilege escalation must be disabled",
                errors,
            )
            require(
                security.get("capabilities", {}).get("drop") == ["ALL"],
                "Redis must drop all capabilities",
                errors,
            )

    if service:
        ports = service.get("spec", {}).get("ports", [])
        require(len(ports) == 1, "public Service must expose one port", errors)
        if ports:
            require(ports[0].get("port") == 31337, "public port must be 31337", errors)
        require(
            service.get("spec", {}).get("selector", {}).get(
                "reclaim.hspace.io/workload"
            )
            == "gateway",
            "public Service must select only the gateway",
            errors,
        )

    if redis_service:
        redis_spec = redis_service.get("spec", {})
        require(redis_spec.get("type") == "ClusterIP", "Redis Service must be private", errors)
        redis_ports = redis_spec.get("ports", [])
        require(
            len(redis_ports) == 1 and redis_ports[0].get("port") == 6379,
            "Redis Service must expose only 6379",
            errors,
        )

    if role:
        rules = role.get("rules", [])
        resources = {
            resource
            for rule in rules
            for resource in rule.get("resources", [])
            if isinstance(resource, str)
        }
        verbs = {
            verb
            for rule in rules
            for verb in rule.get("verbs", [])
            if isinstance(verb, str)
        }
        require(
            resources == {"jobs", "services", "endpointslices"},
            "RBAC scope differs from jobs/services/EndpointSlice readiness",
            errors,
        )
        require(
            verbs <= {"get", "list", "create", "delete"},
            "RBAC contains mutation verbs that the broker does not need",
            errors,
        )
        require("secrets" not in resources, "gateway must not read Secrets via API", errors)
        endpoint_rules = [
            rule
            for rule in rules
            if rule.get("apiGroups") == ["discovery.k8s.io"]
            and rule.get("resources") == ["endpointslices"]
        ]
        require(
            len(endpoint_rules) == 1 and endpoint_rules[0].get("verbs") == ["list"],
            "EndpointSlice readiness access must be read-only list",
            errors,
        )

    if service_account:
        require(
            service_account.get("automountServiceAccountToken") is True,
            "gateway ServiceAccount token mount is unexpectedly disabled",
            errors,
        )

    policies = [item for item in documents if item.get("kind") == "NetworkPolicy"]
    gateway_policies = [
        item
        for item in policies
        if item.get("spec", {}).get("podSelector", {}).get("matchLabels", {}).get(
            "reclaim.hspace.io/workload"
        )
        == "gateway"
    ]
    require(len(gateway_policies) == 1, "gateway NetworkPolicy is missing", errors)
    if gateway_policies:
        policy = gateway_policies[0].get("spec", {})
        require(
            set(policy.get("policyTypes", [])) == {"Ingress", "Egress"},
            "gateway NetworkPolicy must isolate both directions",
            errors,
        )
        egress = policy.get("egress", [])
        require(len(egress) == 6, "gateway must have exactly six egress rules", errors)

        rules_by_ports: dict[frozenset[tuple[int, str]], list[dict]] = {}
        for rule in egress:
            ports = frozenset(
                (entry.get("port"), entry.get("protocol", "TCP"))
                for entry in rule.get("ports", [])
            )
            rules_by_ports.setdefault(ports, []).append(rule)
            require(bool(rule.get("to")), "gateway egress rule has an unrestricted peer", errors)

        dns_rules = rules_by_ports.get(frozenset({(53, "UDP"), (53, "TCP")}), [])
        require(len(dns_rules) == 1, "gateway DNS egress is not exact", errors)
        if dns_rules:
            peers = dns_rules[0].get("to", [])
            require(
                len(peers) == 1
                and peers[0].get("namespaceSelector", {}).get("matchLabels", {}).get(
                    "kubernetes.io/metadata.name"
                )
                == "kube-system"
                and peers[0].get("podSelector", {}).get("matchLabels", {}).get(
                    "k8s-app"
                )
                == "kube-dns",
                "gateway DNS egress must target only kube-system/kube-dns",
                errors,
            )

        redis_rules = rules_by_ports.get(frozenset({(6379, "TCP")}), [])
        require(len(redis_rules) == 1, "gateway Redis egress is not exact", errors)
        if redis_rules:
            peers = redis_rules[0].get("to", [])
            require(
                len(peers) == 1
                and peers[0].get("podSelector", {}).get("matchLabels", {}).get(
                    "app.kubernetes.io/component"
                )
                == "redis"
                and "namespaceSelector" not in peers[0]
                and "ipBlock" not in peers[0],
                "gateway Redis egress must target only the local Redis Pod",
                errors,
            )

        instance_rules = rules_by_ports.get(frozenset({(31337, "TCP")}), [])
        require(len(instance_rules) == 1, "gateway instance egress is not exact", errors)
        if instance_rules:
            peers = instance_rules[0].get("to", [])
            require(
                len(peers) == 1
                and peers[0].get("namespaceSelector", {}).get("matchLabels", {}).get(
                    "kubernetes.io/metadata.name"
                )
                == "reclaim-instances"
                and peers[0].get("podSelector", {}).get("matchLabels", {}).get(
                    "reclaim.hspace.io/managed"
                )
                == "true"
                and peers[0].get("podSelector", {}).get("matchLabels", {}).get(
                    "reclaim.hspace.io/workload"
                )
                == "instance",
                "gateway instance egress must target managed challenge Pods only",
                errors,
            )

        https_rules = rules_by_ports.get(frozenset({(443, "TCP")}), [])
        require(len(https_rules) == 2, "gateway must have exact API and CTFd HTTPS rules", errors)
        https_networks: list[ipaddress.IPv4Network] = []
        for rule in https_rules:
            for peer in rule.get("to", []):
                block = peer.get("ipBlock", {})
                cidr = block.get("cidr")
                try:
                    network = ipaddress.ip_network(cidr, strict=True)
                except (TypeError, ValueError):
                    errors.append("gateway HTTPS egress contains an invalid IP block")
                    continue
                require(
                    isinstance(network, ipaddress.IPv4Network) and network.prefixlen == 32,
                    "gateway HTTPS egress must use exact IPv4 /32 peers",
                    errors,
                )
                require(not block.get("except"), "gateway HTTPS egress must not use CIDR exceptions", errors)
                if isinstance(network, ipaddress.IPv4Network):
                    https_networks.append(network)
        metadata = ipaddress.ip_address("169.254.169.254")
        require(
            all(metadata not in network for network in https_networks),
            "gateway egress must not reach the metadata endpoint",
            errors,
        )

        api_backend_rules = rules_by_ports.get(frozenset({(6443, "TCP")}), [])
        require(len(api_backend_rules) == 1, "gateway API backend egress is not exact", errors)
        if api_backend_rules:
            peers = api_backend_rules[0].get("to", [])
            require(bool(peers), "gateway API backend egress has no peer", errors)
            for peer in peers:
                block = peer.get("ipBlock", {})
                try:
                    network = ipaddress.ip_network(block.get("cidr"), strict=True)
                except (TypeError, ValueError):
                    errors.append("gateway API backend egress contains an invalid IP block")
                    continue
                require(
                    isinstance(network, ipaddress.IPv4Network) and network.prefixlen == 32,
                    "gateway API backend egress must use exact IPv4 /32 peers",
                    errors,
                )
                require(
                    metadata not in network,
                    "gateway API backend egress must not reach metadata",
                    errors,
                )

        expected_port_sets = {
            frozenset({(53, "UDP"), (53, "TCP")}),
            frozenset({(6379, "TCP")}),
            frozenset({(31337, "TCP")}),
            frozenset({(443, "TCP")}),
            frozenset({(6443, "TCP")}),
        }
        require(
            set(rules_by_ports) == expected_port_sets,
            "gateway egress exposes an unexpected port or protocol",
            errors,
        )

    instance_policies = [
        item
        for item in policies
        if item.get("metadata", {}).get("namespace")
        != deployment.get("metadata", {}).get("namespace")
        and item.get("spec", {}).get("egress") == []
    ]
    require(len(instance_policies) == 1, "instance NetworkPolicy is missing", errors)
    if instance_policies:
        policy = instance_policies[0].get("spec", {})
        require(
            policy.get("podSelector") == {},
            "instance namespace policy must select every Pod",
            errors,
        )
        require(policy.get("egress") == [], "challenge pods must have deny-all egress", errors)
        require(
            set(policy.get("policyTypes", [])) == {"Ingress", "Egress"},
            "challenge NetworkPolicy must isolate both directions",
            errors,
        )

    redis_policies = [
        item
        for item in policies
        if item.get("spec", {}).get("podSelector", {}).get("matchLabels", {}).get(
            "app.kubernetes.io/component"
        )
        == "redis"
    ]
    require(len(redis_policies) == 1, "Redis NetworkPolicy is missing", errors)
    if redis_policies:
        policy = redis_policies[0].get("spec", {})
        require(policy.get("egress") == [], "Redis must have deny-all egress", errors)
        ingress = policy.get("ingress", [])
        require(
            len(ingress) == 1
            and ingress[0].get("ports", [{}])[0].get("port") == 6379,
            "Redis ingress must be gateway-only port 6379",
            errors,
        )

    role_bindings = [item for item in documents if item.get("kind") == "RoleBinding"]
    if len(role_bindings) == 1:
        binding = role_bindings[0]
        binding_namespace = binding.get("metadata", {}).get("namespace")
        subjects = binding.get("subjects", [])
        subject_namespace = subjects[0].get("namespace") if subjects else None
        require(
            isinstance(binding_namespace, str)
            and isinstance(subject_namespace, str)
            and binding_namespace != subject_namespace,
            "gateway and untrusted instance namespaces must be separate",
            errors,
        )
    else:
        errors.append("expected one RoleBinding")

    quotas = [item for item in documents if item.get("kind") == "ResourceQuota"]
    require(len(quotas) == 1, "instance ResourceQuota is required", errors)
    if quotas:
        hard = quotas[0].get("spec", {}).get("hard", {})
        require(hard.get("pods") == "30", "Pod quota must be exactly 30", errors)
        require(
            hard.get("count/jobs.batch") == "30",
            "Job quota must be exactly 30",
            errors,
        )
        require(
            hard.get("count/services") == "30",
            "Service quota must be exactly 30",
            errors,
        )
        require(hard.get("requests.cpu") == "7500m", "CPU request quota must be 7500m", errors)
        require(hard.get("requests.memory") == "19200Mi", "memory request quota must be 19200Mi", errors)
        require(hard.get("limits.cpu") == "60", "CPU limit quota must be 60", errors)
        require(hard.get("limits.memory") == "19200Mi", "memory limit quota must be 19200Mi", errors)

    source_files = [path for path in args.source_root.rglob("*") if path.is_file()]
    if args.flag_file and args.flag_file.is_file():
        secret = args.flag_file.read_bytes().strip()
        leaks = [path for path in source_files if secret and secret in path.read_bytes()]
        require(not leaks, "canonical flag bytes appear in Kubernetes sources", errors)

    broker_source = (args.source_root / "broker/reclaim_gateway/broker.py").read_text()
    ctfd_source = (args.source_root / "broker/reclaim_gateway/ctfd.py").read_text()
    state_source = (args.source_root / "broker/reclaim_gateway/state.py").read_text()
    require('token = ""' in broker_source, "broker does not drop its bearer reference", errors)
    require(
        "identity = None" in broker_source,
        "broker does not drop its raw team identity",
        errors,
    )
    require(
        '"/api/v1/users/me"' in ctfd_source,
        "CTFd participant identity endpoint is missing",
        errors,
    )
    require("RedisSessionState" in state_source, "Redis FIFO state is missing", errors)
    require("max_instances: int = 30" in (args.source_root / "broker/reclaim_gateway/config.py").read_text(), "source capacity default is not 30", errors)

    print(f"rendered_documents={len(documents)}")
    print(f"network_policies={len(policies)}")
    print("configured_capacity=30")
    if errors:
        print("[Q2-KUBERNETES-AUDIT-FAIL]")
        for error in errors:
            print(f"- {error}")
        return 1
    print("[Q2-KUBERNETES-AUDIT-PASS]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
