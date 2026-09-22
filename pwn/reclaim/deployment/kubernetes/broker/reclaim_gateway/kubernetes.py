from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Settings


MANAGED_LABEL = "reclaim.hspace.io/managed"
INSTANCE_LABEL = "reclaim.hspace.io/instance"
WORKLOAD_LABEL = "reclaim.hspace.io/workload"
EXPIRES_ANNOTATION = "reclaim.hspace.io/expires-at"


class KubernetesError(RuntimeError):
    pass


class CapacityError(KubernetesError):
    pass


class ApiError(KubernetesError):
    def __init__(self, status: int, operation: str):
        super().__init__(f"Kubernetes API {operation} failed with status {status}")
        self.status = status


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    expires_at: int
    instance_id: str


class KubernetesApi:
    """Small in-cluster REST client with no dependency on kubectl or kubeconfig."""

    def __init__(self, namespace: str):
        host = __import__("os").environ.get("KUBERNETES_SERVICE_HOST", "")
        port = __import__("os").environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        if not host:
            raise KubernetesError("KUBERNETES_SERVICE_HOST is missing")
        self.base_url = f"https://{host}:{port}"
        self.namespace = urllib.parse.quote(namespace, safe="")
        self.token_file = Path(
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        )
        ca_file = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        self.context = ssl.create_default_context(cafile=ca_file)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.context)
        )

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        operation: str,
        missing_ok: bool = False,
    ) -> dict[str, Any] | None:
        try:
            token = self.token_file.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise KubernetesError("cannot read Kubernetes service-account token") from error
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "reclaim-kubernetes-gateway/1.0",
            },
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            status = error.code
            # HTTPError owns the failed HTTP response and its socket.
            error.close()
            if missing_ok and status == 404:
                return None
            raise ApiError(status, operation) from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise KubernetesError(f"Kubernetes API {operation} failed") from error
        if len(raw) > 2 * 1024 * 1024:
            raise KubernetesError("Kubernetes API response is oversized")
        if not raw:
            return {}
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise KubernetesError("Kubernetes API returned invalid JSON") from error
        if not isinstance(payload, dict):
            raise KubernetesError("Kubernetes API returned an invalid object")
        return payload

    @property
    def jobs_path(self) -> str:
        return f"/apis/batch/v1/namespaces/{self.namespace}/jobs"

    @property
    def services_path(self) -> str:
        return f"/api/v1/namespaces/{self.namespace}/services"

    @property
    def endpoint_slices_path(self) -> str:
        return (
            f"/apis/discovery.k8s.io/v1/namespaces/{self.namespace}"
            "/endpointslices"
        )

    def get_job(self, name: str) -> dict[str, Any] | None:
        return self._request(
            "GET", f"{self.jobs_path}/{name}", operation="get job", missing_ok=True
        )

    def list_jobs(self) -> list[dict[str, Any]]:
        selector = urllib.parse.quote(f"{MANAGED_LABEL}=true", safe="=,./")
        payload = self._request(
            "GET", f"{self.jobs_path}?labelSelector={selector}", operation="list jobs"
        )
        items = [] if payload is None else payload.get("items", [])
        if not isinstance(items, list):
            raise KubernetesError("Kubernetes API returned an invalid Job list")
        return [item for item in items if isinstance(item, dict)]

    def create_job(self, body: dict[str, Any]) -> dict[str, Any]:
        result = self._request("POST", self.jobs_path, body, operation="create job")
        assert result is not None
        return result

    def delete_job(self, name: str) -> None:
        self._request(
            "DELETE",
            f"{self.jobs_path}/{name}",
            {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "gracePeriodSeconds": 0,
                "propagationPolicy": "Foreground",
            },
            operation="delete job",
            missing_ok=True,
        )

    def get_service(self, name: str) -> dict[str, Any] | None:
        return self._request(
            "GET",
            f"{self.services_path}/{name}",
            operation="get service",
            missing_ok=True,
        )

    def list_services(self) -> list[dict[str, Any]]:
        selector = urllib.parse.quote(f"{MANAGED_LABEL}=true", safe="=,./")
        payload = self._request(
            "GET",
            f"{self.services_path}?labelSelector={selector}",
            operation="list services",
        )
        items = [] if payload is None else payload.get("items", [])
        if not isinstance(items, list):
            raise KubernetesError("Kubernetes API returned an invalid Service list")
        return [item for item in items if isinstance(item, dict)]

    def create_service(self, body: dict[str, Any]) -> dict[str, Any]:
        result = self._request(
            "POST", self.services_path, body, operation="create service"
        )
        assert result is not None
        return result

    def delete_service(self, name: str) -> None:
        self._request(
            "DELETE",
            f"{self.services_path}/{name}",
            {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "gracePeriodSeconds": 0,
                "propagationPolicy": "Background",
            },
            operation="delete service",
            missing_ok=True,
        )

    def service_has_ready_endpoint(self, name: str) -> bool:
        selector = urllib.parse.quote(
            f"kubernetes.io/service-name={name}", safe="=,./"
        )
        payload = self._request(
            "GET",
            f"{self.endpoint_slices_path}?labelSelector={selector}",
            operation="list endpoint slices",
        )
        items = [] if payload is None else payload.get("items", [])
        if not isinstance(items, list):
            raise KubernetesError("Kubernetes API returned an invalid EndpointSlice list")
        for item in items:
            if not isinstance(item, dict):
                continue
            endpoints = item.get("endpoints", [])
            if not isinstance(endpoints, list):
                continue
            for endpoint in endpoints:
                if not isinstance(endpoint, dict):
                    continue
                conditions = endpoint.get("conditions", {})
                addresses = endpoint.get("addresses", [])
                if (
                    isinstance(conditions, dict)
                    and conditions.get("ready") is True
                    and conditions.get("terminating") is not True
                    and isinstance(addresses, list)
                    and any(isinstance(address, str) and address for address in addresses)
                ):
                    return True
        return False


class InstanceController:
    def __init__(self, settings: Settings, api: KubernetesApi):
        self.settings = settings
        self.api = api
        # ensure() runs in worker threads. Serialize capacity checks and object
        # replacement so concurrent teams cannot oversubscribe the configured cap.
        self._allocation_lock = threading.RLock()

    def opaque_subject(self, subject: str) -> str:
        digest = hmac.new(
            self.settings.instance_name_secret,
            b"reclaim-instance-v1\0" + subject.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()[:24]
        return digest

    def _name(self, instance_id: str) -> str:
        return f"reclaim-{instance_id}"

    @staticmethod
    def _conditions_finished(job: dict[str, Any]) -> bool:
        status = job.get("status", {})
        if not isinstance(status, dict):
            return True
        conditions = status.get("conditions", [])
        if not isinstance(conditions, list):
            return True
        return any(
            isinstance(item, dict)
            and item.get("status") == "True"
            and item.get("type") in {"Complete", "Failed"}
            for item in conditions
        )

    @staticmethod
    def _expiry(job: dict[str, Any]) -> int:
        metadata = job.get("metadata", {})
        annotations = metadata.get("annotations", {}) if isinstance(metadata, dict) else {}
        raw = annotations.get(EXPIRES_ANNOTATION, "") if isinstance(annotations, dict) else ""
        try:
            return int(raw, 10)
        except (TypeError, ValueError):
            return 0

    def _usable(self, job: dict[str, Any], now: int) -> bool:
        metadata = job.get("metadata", {})
        return (
            isinstance(metadata, dict)
            and not metadata.get("deletionTimestamp")
            and self._expiry(job) > now
            and not self._conditions_finished(job)
        )

    def _labels(self, instance_id: str) -> dict[str, str]:
        return {
            MANAGED_LABEL: "true",
            INSTANCE_LABEL: instance_id,
            WORKLOAD_LABEL: "instance",
            "app.kubernetes.io/name": "reclaim-instance",
            "app.kubernetes.io/managed-by": "reclaim-gateway",
        }

    def _job_manifest(
        self, name: str, instance_id: str, expires_at: int
    ) -> dict[str, Any]:
        labels = self._labels(instance_id)
        pod_spec: dict[str, Any] = {
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 5,
            "securityContext": {
                "runAsNonRoot": True,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "qemu",
                    "image": self.settings.challenge_image,
                    "imagePullPolicy": self.settings.image_pull_policy,
                    "ports": [{"name": "serial", "containerPort": 31337, "protocol": "TCP"}],
                    # The real QEMU chardev accepts exactly one client. A
                    # tcpSocket probe would consume that connection and boot
                    # the guest without the participant, so gate Service
                    # endpoint publication by inspecting the listening socket
                    # without connecting to it.
                    "readinessProbe": {
                        "exec": {
                            "command": [
                                "/bin/sh",
                                "-ec",
                                "grep -qE '^[[:space:]]*[0-9]+: [0-9A-Fa-f]+:7A69 ' /proc/net/tcp /proc/net/tcp6",
                            ]
                        },
                        "periodSeconds": 1,
                        "timeoutSeconds": 1,
                        "failureThreshold": 90,
                    },
                    "env": [
                        {
                            "name": "VM_TIMEOUT_SECONDS",
                            "value": str(self.settings.instance_timeout_seconds),
                        }
                    ],
                    "resources": {
                        "requests": {
                            "cpu": self.settings.instance_cpu_request,
                            "memory": self.settings.instance_memory,
                        },
                        "limits": {
                            "cpu": self.settings.instance_cpu_limit,
                            "memory": self.settings.instance_memory,
                        },
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                        "privileged": False,
                        "readOnlyRootFilesystem": True,
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                        "runAsGroup": 65534,
                    },
                    "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                }
            ],
            "volumes": [
                {
                    "name": "tmp",
                    "emptyDir": {"medium": "Memory", "sizeLimit": "4Mi"},
                }
            ],
        }
        if self.settings.image_pull_secrets:
            pod_spec["imagePullSecrets"] = [
                {"name": item} for item in self.settings.image_pull_secrets
            ]
        if self.settings.node_selector:
            pod_spec["nodeSelector"] = self.settings.node_selector
        if self.settings.tolerations:
            pod_spec["tolerations"] = list(self.settings.tolerations)
        if self.settings.runtime_class_name:
            pod_spec["runtimeClassName"] = self.settings.runtime_class_name
        if self.settings.priority_class_name:
            pod_spec["priorityClassName"] = self.settings.priority_class_name

        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": name,
                "labels": labels,
                "annotations": {EXPIRES_ANNOTATION: str(expires_at)},
            },
            "spec": {
                "activeDeadlineSeconds": self.settings.instance_timeout_seconds,
                "backoffLimit": 0,
                "ttlSecondsAfterFinished": self.settings.finished_job_ttl_seconds,
                "template": {
                    "metadata": {"labels": labels},
                    "spec": pod_spec,
                },
            },
        }

    def _service_manifest(
        self, name: str, instance_id: str, job_uid: str
    ) -> dict[str, Any]:
        return {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": name,
                "labels": self._labels(instance_id),
                "ownerReferences": [
                    {
                        "apiVersion": "batch/v1",
                        "kind": "Job",
                        "name": name,
                        "uid": job_uid,
                        "controller": False,
                        "blockOwnerDeletion": False,
                    }
                ],
            },
            "spec": {
                "type": "ClusterIP",
                "selector": {INSTANCE_LABEL: instance_id},
                "ports": [
                    {
                        "name": "serial",
                        "port": 31337,
                        "targetPort": 31337,
                        "protocol": "TCP",
                    }
                ],
            },
        }

    def _active_count(self, now: int) -> int:
        return sum(self._usable(job, now) for job in self.api.list_jobs())

    def _delete_pair(self, name: str) -> None:
        self.api.delete_service(name)
        self.api.delete_job(name)

    def _wait_absent(self, name: str, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.api.get_job(name) is None and self.api.get_service(name) is None:
                return
            time.sleep(0.2)
        raise KubernetesError("expired instance resources did not terminate")

    def _ensure_service(
        self, name: str, instance_id: str, job: dict[str, Any]
    ) -> None:
        metadata = job.get("metadata", {})
        uid = metadata.get("uid") if isinstance(metadata, dict) else None
        if not isinstance(uid, str) or not uid:
            raise KubernetesError("Kubernetes Job has no UID")
        service = self.api.get_service(name)
        if service is not None:
            references = service.get("metadata", {}).get("ownerReferences", [])
            if isinstance(references, list) and any(
                isinstance(item, dict) and item.get("uid") == uid for item in references
            ):
                return
            self.api.delete_service(name)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.api.get_service(name) is None:
                    break
                time.sleep(0.2)
            else:
                raise KubernetesError("stale instance Service did not terminate")
        self.api.create_service(self._service_manifest(name, instance_id, uid))

    def _ensure_sync(self, instance_id: str) -> Endpoint:
        if len(instance_id) != 24 or any(char not in "0123456789abcdef" for char in instance_id):
            raise KubernetesError("invalid opaque instance identifier")
        name = self._name(instance_id)
        now = int(time.time())
        job = self.api.get_job(name)
        if job is not None and not self._usable(job, now):
            self._delete_pair(name)
            self._wait_absent(name)
            job = None

        if job is None:
            if self._active_count(now) >= self.settings.max_instances:
                raise CapacityError("the instance pool is full")
            expires_at = now + self.settings.instance_timeout_seconds
            job = self.api.create_job(
                self._job_manifest(name, instance_id, expires_at)
            )
            try:
                self._ensure_service(name, instance_id, job)
            except Exception:
                self.api.delete_job(name)
                raise
        else:
            expires_at = self._expiry(job)
            self._ensure_service(name, instance_id, job)

        return Endpoint(
            host=f"{name}.{self.settings.namespace}.svc",
            port=31337,
            expires_at=expires_at,
            instance_id=instance_id,
        )

    async def ensure(self, instance_id: str) -> Endpoint:
        def locked_ensure() -> Endpoint:
            with self._allocation_lock:
                return self._ensure_sync(instance_id)

        return await asyncio.to_thread(locked_ensure)

    async def wait_ready(self, instance_id: str, timeout: float) -> None:
        if len(instance_id) != 24 or any(
            char not in "0123456789abcdef" for char in instance_id
        ):
            raise KubernetesError("invalid opaque instance identifier")
        name = self._name(instance_id)
        deadline = time.monotonic() + timeout
        consecutive = 0
        while time.monotonic() < deadline:
            ready = await asyncio.to_thread(
                self.api.service_has_ready_endpoint, name
            )
            consecutive = consecutive + 1 if ready else 0
            # A second observation avoids connecting in the same instant the
            # EndpointSlice and NetworkPolicy dataplane are first published.
            if consecutive >= 2:
                return
            await asyncio.sleep(0.25)
        raise KubernetesError("instance endpoint did not become ready")

    def _destroy_sync(self, instance_id: str) -> None:
        if len(instance_id) != 24 or any(char not in "0123456789abcdef" for char in instance_id):
            raise KubernetesError("invalid opaque instance identifier")
        name = self._name(instance_id)
        self._delete_pair(name)
        self._wait_absent(name)

    async def destroy(self, instance_id: str) -> None:
        def locked_destroy() -> None:
            with self._allocation_lock:
                self._destroy_sync(instance_id)

        await asyncio.to_thread(locked_destroy)

    @staticmethod
    def _object_name(item: dict[str, Any]) -> str | None:
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            return None
        name = metadata.get("name")
        labels = metadata.get("labels", {})
        if (
            isinstance(name, str)
            and name.startswith("reclaim-")
            and isinstance(labels, dict)
            and labels.get(MANAGED_LABEL) == "true"
        ):
            return name
        return None

    def _destroy_all_sync(self) -> None:
        names = {
            name
            for item in [*self.api.list_jobs(), *self.api.list_services()]
            if (name := self._object_name(item)) is not None
        }
        for name in sorted(names):
            self._delete_pair(name)
        for name in sorted(names):
            self._wait_absent(name)

    async def destroy_all(self) -> None:
        """Remove orphaned sessions before a single-replica gateway starts."""

        def locked_destroy_all() -> None:
            with self._allocation_lock:
                self._destroy_all_sync()

        await asyncio.to_thread(locked_destroy_all)
