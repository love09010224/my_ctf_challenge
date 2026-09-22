#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


OPAQUE_ID = re.compile(r"[0-9a-f]{24}")


def items_of(data: dict, kind: str) -> list[dict]:
    return [item for item in data.get("items", []) if item.get("kind") == kind]


def instance_ids(items: list[dict], kind: str) -> set[str]:
    values = {
        item.get("metadata", {}).get("labels", {}).get(
            "reclaim.hspace.io/instance", ""
        )
        for item in items
    }
    if any(OPAQUE_ID.fullmatch(value) is None for value in values):
        raise SystemExit(f"{kind} contains a non-opaque instance identity")
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("json_file", type=Path)
    parser.add_argument("--expected-instances", type=int, choices=(0, 30), required=True)
    args = parser.parse_args()
    raw = args.json_file.read_bytes()
    for forbidden in (b"integration-token-", b"invalid-integration-token", b"team:"):
        if forbidden in raw:
            raise SystemExit("raw identity or bearer material appears in workload objects")

    data = json.loads(raw)
    jobs = items_of(data, "Job")
    pods = items_of(data, "Pod")
    services = items_of(data, "Service")
    quotas = items_of(data, "ResourceQuota")
    expected = args.expected_instances
    if not (len(jobs) == len(pods) == len(services) == expected):
        raise SystemExit(
            f"expected {expected} Jobs, Pods, and private Services; "
            f"found {len(jobs)}, {len(pods)}, {len(services)}"
        )
    if len(quotas) != 1:
        raise SystemExit("expected one instance-namespace ResourceQuota")
    hard = quotas[0].get("spec", {}).get("hard", {})
    for field in ("pods", "count/jobs.batch", "count/services"):
        if hard.get(field) != "30":
            raise SystemExit(f"ResourceQuota {field} is not fixed at thirty")
    expected_resources = {
        "requests.cpu": "7500m",
        "requests.memory": "19200Mi",
        "limits.cpu": "60",
        "limits.memory": "19200Mi",
    }
    for field, expected_value in expected_resources.items():
        if hard.get(field) != expected_value:
            raise SystemExit(
                f"ResourceQuota {field} is {hard.get(field)!r}, expected {expected_value}"
            )

    if expected:
        ids = instance_ids(jobs, "Job")
        if len(ids) != expected:
            raise SystemExit("active Jobs do not have unique opaque identities")
        if instance_ids(pods, "Pod") != ids or instance_ids(services, "Service") != ids:
            raise SystemExit("Job, Pod, and Service identity sets disagree")
        expected_names = {f"reclaim-{value}" for value in ids}
        if {item["metadata"]["name"] for item in jobs} != expected_names:
            raise SystemExit("Job names do not derive from opaque identities")
        if {item["metadata"]["name"] for item in services} != expected_names:
            raise SystemExit("Service names do not derive from opaque identities")

        jobs_by_name = {item["metadata"]["name"]: item for item in jobs}
        for job in jobs:
            spec = job.get("spec", {})
            deadline = spec.get("activeDeadlineSeconds")
            if not isinstance(deadline, int) or not 60 <= deadline <= 900:
                raise SystemExit("Job lifetime is outside the 60-900 second contract")
            if spec.get("backoffLimit") != 0:
                raise SystemExit("Job restart/backoff must be disabled")

        for pod in pods:
            pod_spec = pod["spec"]
            containers = pod_spec.get("containers", [])
            if len(containers) != 1:
                raise SystemExit("each instance Pod must contain exactly one container")
            security = containers[0].get("securityContext", {})
            if pod_spec.get("automountServiceAccountToken") is not False:
                raise SystemExit("instance Pod received a service-account token")
            if security.get("readOnlyRootFilesystem") is not True:
                raise SystemExit("instance root filesystem is writable")
            if security.get("allowPrivilegeEscalation") is not False:
                raise SystemExit("instance privilege escalation is enabled")
            if security.get("capabilities", {}).get("drop") != ["ALL"]:
                raise SystemExit("instance container did not drop all capabilities")
            if security.get("runAsUser") != 65534 or security.get("runAsGroup") != 65534:
                raise SystemExit("instance container is not pinned to the unprivileged UID/GID")
            readiness = containers[0].get("readinessProbe", {})
            if "exec" not in readiness or "tcpSocket" in readiness:
                raise SystemExit("instance readiness must not consume the one-shot TCP socket")
            probe = " ".join(readiness.get("exec", {}).get("command", []))
            if "/proc/net/tcp" not in probe:
                raise SystemExit("instance listener readiness probe is missing")
            environment = {
                item.get("name"): item.get("value")
                for item in containers[0].get("env", [])
                if isinstance(item, dict)
            }
            if set(environment) != {"VM_TIMEOUT_SECONDS"}:
                raise SystemExit("instance environment contains unexpected values")

        for service in services:
            if service.get("spec", {}).get("type") != "ClusterIP":
                raise SystemExit("an instance Service is publicly reachable")
            name = service["metadata"]["name"]
            references = service["metadata"].get("ownerReferences", [])
            if not any(
                reference.get("kind") == "Job"
                and reference.get("name") == name
                and reference.get("uid") == jobs_by_name[name]["metadata"]["uid"]
                for reference in references
                if isinstance(reference, dict)
            ):
                raise SystemExit("an instance Service is not owned by its matching Job")

    print(
        "[KUBERNETES-E2E-OBJECT-AUDIT-PASS] "
        f"active_instances={expected} opaque_identity_only=1"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
