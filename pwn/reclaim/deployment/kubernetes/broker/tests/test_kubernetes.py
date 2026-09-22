from __future__ import annotations

import json
import unittest
from copy import deepcopy

from reclaim_gateway.config import Settings
from reclaim_gateway.kubernetes import CapacityError, InstanceController, KubernetesApi


class _UnusedApi:
    pass


class _FakeApi:
    def __init__(self) -> None:
        self.jobs: dict[str, dict] = {}
        self.services: dict[str, dict] = {}
        self.created_jobs = 0
        self.endpoint_results: list[bool] = [True, True]
        self.endpoint_checks = 0

    def get_job(self, name: str):
        return self.jobs.get(name)

    def list_jobs(self):
        return list(self.jobs.values())

    def list_services(self):
        return list(self.services.values())

    def create_job(self, body: dict):
        item = deepcopy(body)
        item["metadata"]["uid"] = f"uid-{self.created_jobs}"
        self.created_jobs += 1
        self.jobs[item["metadata"]["name"]] = item
        return item

    def delete_job(self, name: str) -> None:
        self.jobs.pop(name, None)

    def get_service(self, name: str):
        return self.services.get(name)

    def create_service(self, body: dict):
        item = deepcopy(body)
        self.services[item["metadata"]["name"]] = item
        return item

    def delete_service(self, name: str) -> None:
        self.services.pop(name, None)

    def service_has_ready_endpoint(self, name: str) -> bool:
        if name not in self.services:
            return False
        self.endpoint_checks += 1
        if self.endpoint_results:
            return self.endpoint_results.pop(0)
        return True


def settings() -> Settings:
    return Settings(
        ctfd_base_url="https://ctfd.invalid",
        ctfd_challenge_id=None,
        ctfd_require_team=True,
        ctfd_ca_file=None,
        ctfd_timeout_seconds=2,
        namespace="reclaim",
        challenge_image="registry.invalid/reclaim@sha256:" + "a" * 64,
        instance_name_secret=b"hmac-secret-material-32-bytes!!",
        tls_mode="plaintext",
        image_pull_secrets=("private-registry",),
        node_selector={"workload": "untrusted-qemu"},
    )


class ManifestTests(unittest.TestCase):
    def test_subject_is_hmaced_and_absent_from_workload_manifest(self) -> None:
        controller = InstanceController(settings(), _UnusedApi())  # type: ignore[arg-type]
        instance_id = controller.opaque_subject("team:42")
        self.assertEqual(len(instance_id), 24)
        self.assertNotEqual(instance_id, controller.opaque_subject("team:43"))
        name = controller._name(instance_id)
        job = controller._job_manifest(name, instance_id, 1234567890)
        encoded = json.dumps(job, sort_keys=True)
        self.assertNotIn("team:42", encoded)
        self.assertNotIn("participant", encoded)

        spec = job["spec"]
        pod_spec = spec["template"]["spec"]
        container = pod_spec["containers"][0]
        security = container["securityContext"]
        self.assertEqual(spec["activeDeadlineSeconds"], 900)
        self.assertEqual(spec["backoffLimit"], 0)
        self.assertFalse(pod_spec["automountServiceAccountToken"])
        self.assertFalse(security["allowPrivilegeEscalation"])
        self.assertTrue(security["readOnlyRootFilesystem"])
        self.assertEqual(security["capabilities"]["drop"], ["ALL"])
        self.assertEqual(container["resources"]["limits"]["memory"], "640Mi")
        self.assertEqual(pod_spec["nodeSelector"], {"workload": "untrusted-qemu"})
        readiness = container["readinessProbe"]
        self.assertIn("exec", readiness)
        self.assertNotIn("tcpSocket", readiness)
        probe = " ".join(readiness["exec"]["command"])
        self.assertIn("/proc/net/tcp", probe)
        self.assertNotIn("nc ", probe)
        self.assertNotIn("curl", probe)

    def test_service_is_private_and_owned_by_job(self) -> None:
        controller = InstanceController(settings(), _UnusedApi())  # type: ignore[arg-type]
        instance_id = controller.opaque_subject("team:42")
        name = controller._name(instance_id)
        service = controller._service_manifest(name, instance_id, "job-uid")
        self.assertEqual(service["spec"]["type"], "ClusterIP")
        self.assertEqual(service["spec"]["ports"][0]["port"], 31337)
        self.assertEqual(
            service["metadata"]["ownerReferences"][0]["uid"], "job-uid"
        )


class ApiResponseTests(unittest.TestCase):
    def test_endpoint_slice_requires_a_ready_nonterminating_address(self) -> None:
        api = KubernetesApi.__new__(KubernetesApi)
        api.namespace = "reclaim"
        responses = [
            {
                "items": [
                    {
                        "endpoints": [
                            {
                                "addresses": ["10.0.0.2"],
                                "conditions": {"ready": False},
                            }
                        ]
                    }
                ]
            },
            {
                "items": [
                    {
                        "endpoints": [
                            {
                                "addresses": ["10.0.0.2"],
                                "conditions": {"ready": True, "terminating": False},
                            }
                        ]
                    }
                ]
            },
        ]

        def request(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            return responses.pop(0)

        api._request = request  # type: ignore[method-assign]
        self.assertFalse(api.service_has_ready_endpoint("reclaim-a"))
        self.assertTrue(api.service_has_ready_endpoint("reclaim-a"))


class ControllerTests(unittest.IsolatedAsyncioTestCase):
    async def test_ensure_creates_and_reuses_one_private_team_endpoint(self) -> None:
        api = _FakeApi()
        controller = InstanceController(settings(), api)  # type: ignore[arg-type]
        instance_id = controller.opaque_subject("team:42")
        first = await controller.ensure(instance_id)
        second = await controller.ensure(instance_id)
        self.assertEqual(first, second)
        self.assertEqual(api.created_jobs, 1)
        self.assertEqual(len(api.jobs), 1)
        self.assertEqual(len(api.services), 1)
        self.assertEqual(
            first.host,
            f"reclaim-{first.instance_id}.reclaim.svc",
        )
        encoded = json.dumps({"jobs": api.jobs, "services": api.services})
        self.assertNotIn("team:42", encoded)

    async def test_disconnect_destroy_removes_job_and_service(self) -> None:
        api = _FakeApi()
        controller = InstanceController(settings(), api)  # type: ignore[arg-type]
        instance_id = controller.opaque_subject("team:42")
        await controller.ensure(instance_id)
        await controller.destroy(instance_id)
        self.assertEqual(api.jobs, {})
        self.assertEqual(api.services, {})

    async def test_readiness_requires_two_endpoint_slice_observations(self) -> None:
        api = _FakeApi()
        api.endpoint_results = [False, True, True]
        controller = InstanceController(settings(), api)  # type: ignore[arg-type]
        instance_id = controller.opaque_subject("team:42")
        await controller.ensure(instance_id)
        await controller.wait_ready(instance_id, timeout=2)
        self.assertEqual(api.endpoint_checks, 3)

    async def test_capacity_rejects_a_new_team(self) -> None:
        api = _FakeApi()
        controller = InstanceController(settings(), api)  # type: ignore[arg-type]
        for number in range(30):
            await controller.ensure(controller.opaque_subject(f"team:{number + 1}"))
        with self.assertRaises(CapacityError):
            await controller.ensure(controller.opaque_subject("team:31"))


if __name__ == "__main__":
    unittest.main()
