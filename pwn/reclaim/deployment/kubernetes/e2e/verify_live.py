#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from check_client import open_tls


TOKENS = tuple(f"integration-token-team{number:02d}" for number in range(1, 33))
INVALID_TOKEN = "invalid-integration-token"
INSTANCE = re.compile(rb"Instance ([0-9a-f]{24}) ready")
OPAQUE_ID = re.compile(r"[0-9a-f]{24}")
CONNECTION_ID = re.compile(r"[0-9a-f]{32}")


@dataclass
class GatewaySession:
    sock: ssl.SSLSocket
    transcript: bytearray = field(default_factory=bytearray)
    closed: bool = False

    def receive_until(self, marker: bytes, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        while marker not in self.transcript:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("gateway did not return the expected fixed marker")
            self.sock.settimeout(min(remaining, 1.0))
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError:
                continue
            if not chunk:
                raise ConnectionError("gateway closed before the expected fixed marker")
            self.transcript.extend(chunk)
        return bytes(self.transcript)

    def receive_for(self, seconds: float) -> bytes:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.sock.settimeout(min(0.25, deadline - time.monotonic()))
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError:
                continue
            if not chunk:
                break
            self.transcript.extend(chunk)
        return bytes(self.transcript)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.sock.close()


class Cluster:
    def __init__(
        self,
        kubectl: str,
        kubeconfig: Path,
        instance_namespace: str,
        gateway_namespace: str,
    ):
        self.command = [kubectl, "--kubeconfig", str(kubeconfig)]
        self.instance_namespace = instance_namespace
        self.gateway_namespace = gateway_namespace

    def run(
        self,
        *arguments: str,
        timeout: float = 30,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [*self.command, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode != 0:
            raise RuntimeError("kubectl integration command failed")
        return result

    def objects(self) -> tuple[bytes, dict]:
        raw = self.run(
            "-n",
            self.instance_namespace,
            "get",
            "jobs,pods,services,resourcequotas",
            "-o",
            "json",
        ).stdout
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("kubectl returned invalid object JSON") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise RuntimeError("kubectl returned an invalid object list")
        return raw, payload

    @staticmethod
    def counts(payload: dict) -> tuple[int, int, int]:
        items = payload["items"]
        return tuple(
            sum(item.get("kind") == kind for item in items)
            for kind in ("Job", "Pod", "Service")
        )

    def wait_for_count(self, expected: int, timeout: float = 90) -> tuple[bytes, dict]:
        deadline = time.monotonic() + timeout
        last: tuple[bytes, dict] | None = None
        while time.monotonic() < deadline:
            last = self.objects()
            if self.counts(last[1]) == (expected, expected, expected):
                return last
            time.sleep(0.25)
        if last is None:
            raise RuntimeError("no Kubernetes object snapshot was captured")
        raise TimeoutError("Kubernetes objects did not reach the expected count")

    def redis_pod(self) -> str:
        value = self.run(
            "-n",
            self.gateway_namespace,
            "get",
            "pod",
            "-l",
            "app.kubernetes.io/component=redis",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ).stdout.decode("ascii")
        if not value:
            raise RuntimeError("Redis Pod was not found")
        return value

    def redis_values(self, operation: str, key: str) -> list[str]:
        if operation not in {"LRANGE", "HGETALL"}:
            raise ValueError("unsupported Redis audit operation")
        arguments = [operation, key]
        if operation == "LRANGE":
            arguments.extend(["0", "-1"])
        result = self.run(
            "-n",
            self.gateway_namespace,
            "exec",
            self.redis_pod(),
            "--",
            "/bin/sh",
            "-ec",
            'export REDISCLI_AUTH="$(cat /var/run/secrets/reclaim-redis/password)"; '
            'exec redis-cli --raw "$@"',
            "redis-audit",
            *arguments,
        )
        decoded = result.stdout.decode("ascii")
        # redis-cli emits a lone newline for an empty array in this image.
        if not decoded.strip():
            return []
        return decoded.splitlines()

    def redis_state(self) -> dict[str, object]:
        queue = self.redis_values("LRANGE", "q2:reclaim:queue")
        queued_raw = self.redis_values("HGETALL", "q2:reclaim:queued")
        active_raw = self.redis_values("HGETALL", "q2:reclaim:active")
        if len(queued_raw) % 2 or len(active_raw) % 2:
            raise RuntimeError("Redis hashes returned an invalid field/value sequence")
        queued = dict(zip(queued_raw[::2], queued_raw[1::2], strict=True))
        active = dict(zip(active_raw[::2], active_raw[1::2], strict=True))
        return {"queue": queue, "queued": queued, "active": active}

    def assert_egress_denied(self, pod: str) -> None:
        target = self.run(
            "-n",
            self.gateway_namespace,
            "get",
            "service/ctfd-mock",
            "-o",
            "jsonpath={.spec.clusterIP}",
        ).stdout.decode("ascii")
        if not target:
            raise RuntimeError("CTFd mock ClusterIP was not found")
        result = self.run(
            "-n",
            self.instance_namespace,
            "exec",
            pod,
            "--",
            "python",
            "-c",
            (
                "import socket; "
                f"s=socket.create_connection(({target!r},8081),2); s.close()"
            ),
            timeout=15,
            check=False,
        )
        if result.returncode == 0:
            raise AssertionError("an instance Pod reached the CTFd control plane")


def assert_no_bearer(transcript: bytes) -> None:
    if b"integration-token-" in transcript or INVALID_TOKEN.encode() in transcript:
        raise AssertionError("gateway echoed a bearer token")


def open_session(port: int) -> GatewaySession:
    session = GatewaySession(open_tls(port))
    session.receive_until(b"Token: ", 10)
    return session


def open_active(port: int, number: int) -> tuple[GatewaySession, str]:
    session = open_session(port)
    command = f"active-{number:02d}\n".encode("ascii")
    session.sock.sendall(TOKENS[number - 1].encode("ascii") + b"\n" + command)
    transcript = session.receive_until(b"GUEST:" + command, 90)
    assert_no_bearer(transcript)
    matches = INSTANCE.findall(transcript)
    if len(matches) != 1:
        raise AssertionError("active session did not expose one opaque instance ID")
    return session, matches[0].decode("ascii")


def open_queued(port: int, number: int, position: int) -> GatewaySession:
    session = open_session(port)
    command = f"queued-{number:02d}\n".encode("ascii")
    session.sock.sendall(TOKENS[number - 1].encode("ascii") + b"\n" + command)
    transcript = session.receive_until(f"Queued: position {position};".encode(), 20)
    assert_no_bearer(transcript)
    if b"Slot allocated." in transcript or b"GUEST:" in transcript:
        raise AssertionError("a queued team received an instance before a slot was free")
    return session


def expect_rejected(port: int, token: str, marker: bytes) -> None:
    session = open_session(port)
    try:
        session.sock.sendall(token.encode("ascii") + b"\n")
        transcript = session.receive_until(marker, 15)
        assert_no_bearer(transcript)
    finally:
        session.close()


def by_kind(payload: dict, kind: str) -> list[dict]:
    return [item for item in payload["items"] if item.get("kind") == kind]


def instance_ids(payload: dict, kind: str) -> set[str]:
    values = {
        item.get("metadata", {}).get("labels", {}).get(
            "reclaim.hspace.io/instance", ""
        )
        for item in by_kind(payload, kind)
    }
    if any(OPAQUE_ID.fullmatch(value) is None for value in values):
        raise AssertionError(f"{kind} has an invalid opaque instance label")
    return values


def assert_object_identity(payload: dict, expected_ids: set[str]) -> None:
    for kind in ("Job", "Pod", "Service"):
        if instance_ids(payload, kind) != expected_ids:
            raise AssertionError(f"{kind} objects do not match active sessions")
    expected_names = {f"reclaim-{value}" for value in expected_ids}
    for kind in ("Job", "Service"):
        names = {item["metadata"]["name"] for item in by_kind(payload, kind)}
        if names != expected_names:
            raise AssertionError(f"{kind} names do not match opaque session IDs")


def assert_redis_shape(
    state: dict[str, object], *, expected_active: set[str], expected_queue_size: int
) -> None:
    queue = state["queue"]
    queued = state["queued"]
    active = state["active"]
    if not isinstance(queue, list) or not isinstance(queued, dict) or not isinstance(active, dict):
        raise AssertionError("Redis state has an invalid shape")
    if set(active) != expected_active or len(queue) != expected_queue_size:
        raise AssertionError("Redis active/queue state does not match live sessions")
    if set(queued) != set(queue):
        raise AssertionError("Redis FIFO and queued ownership disagree")
    if any(OPAQUE_ID.fullmatch(value) is None for value in [*queue, *queued, *active]):
        raise AssertionError("Redis contains a non-opaque identity")
    if any(
        CONNECTION_ID.fullmatch(value) is None
        for value in [*queued.values(), *active.values()]
    ):
        raise AssertionError("Redis contains an invalid connection owner")
    serialized = json.dumps(state, sort_keys=True).encode("ascii")
    if b"integration-token-" in serialized or b"team:" in serialized:
        raise AssertionError("Redis contains raw bearer or team identity material")


def write(path: Path | None, data: bytes | dict[str, object]) -> None:
    if path is None:
        return
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(
            json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="ascii"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=23137)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--kubeconfig", required=True, type=Path)
    parser.add_argument("--instance-namespace", default="reclaim-instances")
    parser.add_argument("--gateway-namespace", default="reclaim-gateway")
    parser.add_argument("--capacity-objects", type=Path)
    parser.add_argument("--promoted-objects", type=Path)
    parser.add_argument("--cleanup-objects", type=Path)
    parser.add_argument("--capacity-redis", type=Path)
    parser.add_argument("--promoted-redis", type=Path)
    args = parser.parse_args()

    cluster = Cluster(
        args.kubectl,
        args.kubeconfig,
        args.instance_namespace,
        args.gateway_namespace,
    )
    active: list[GatewaySession] = []
    thirty_first: GatewaySession | None = None
    thirty_second: GatewaySession | None = None
    try:
        active_ids: list[str] = []
        for number in range(1, 31):
            print(f"[KUBERNETES-E2E-ACTIVE-START] ordinal={number}", flush=True)
            session, instance_id = open_active(args.port, number)
            active.append(session)
            active_ids.append(instance_id)
            print(f"[KUBERNETES-E2E-ACTIVE-READY] ordinal={number}", flush=True)
        if len(set(active_ids)) != 30:
            raise AssertionError("thirty teams did not receive thirty unique instances")

        expect_rejected(
            args.port,
            TOKENS[0],
            b"already has an active or queued connection",
        )
        thirty_first = open_queued(args.port, 31, 1)
        thirty_second = open_queued(args.port, 32, 2)
        expect_rejected(
            args.port,
            TOKENS[30],
            b"already has an active or queued connection",
        )
        expect_rejected(args.port, INVALID_TOKEN, b"Authentication failed")
        print("[KUBERNETES-E2E-AUTH-AND-TEAM-LOCK-PASS]")

        raw, capacity_objects = cluster.wait_for_count(30)
        expected_active = set(active_ids)
        assert_object_identity(capacity_objects, expected_active)
        write(args.capacity_objects, raw)
        capacity_state = cluster.redis_state()
        assert_redis_shape(
            capacity_state,
            expected_active=expected_active,
            expected_queue_size=2,
        )
        initial_queue = list(capacity_state["queue"])
        write(args.capacity_redis, capacity_state)
        first_pod = by_kind(capacity_objects, "Pod")[0]["metadata"]["name"]
        cluster.assert_egress_denied(first_pod)
        print("[KUBERNETES-E2E-30-SLOT-QUEUE-AND-EGRESS-PASS]")

        victim = active.pop(0)
        victim.close()
        promoted_transcript = thirty_first.receive_until(b"GUEST:queued-31\n", 90)
        assert_no_bearer(promoted_transcript)
        matches = INSTANCE.findall(promoted_transcript)
        if len(matches) != 1:
            raise AssertionError("the thirty-first team did not receive one instance")
        thirty_first_id = matches[0].decode("ascii")
        if thirty_first_id != initial_queue[0]:
            raise AssertionError("the FIFO head was not the promoted team")
        active.append(thirty_first)
        thirty_first = None

        thirty_second_transcript = thirty_second.receive_for(3)
        if b"Slot allocated." in thirty_second_transcript or b"GUEST:" in thirty_second_transcript:
            raise AssertionError("more than one queued team was promoted for one free slot")

        raw, promoted_objects = cluster.wait_for_count(30)
        promoted_ids = set(active_ids[1:]) | {thirty_first_id}
        assert_object_identity(promoted_objects, promoted_ids)
        write(args.promoted_objects, raw)
        promoted_state = cluster.redis_state()
        assert_redis_shape(
            promoted_state,
            expected_active=promoted_ids,
            expected_queue_size=1,
        )
        if promoted_state["queue"] != [initial_queue[1]]:
            raise AssertionError("the thirty-second team did not remain at the FIFO head")
        write(args.promoted_redis, promoted_state)
        print("[KUBERNETES-E2E-FIFO-SINGLE-PROMOTION-PASS]")

        thirty_second.close()
        thirty_second = None
        for session in active:
            session.close()
        active.clear()
        # Instance deletion is deliberately serialized by the allocation lock
        # so a slot is never released before its Job and Service are absent.
        raw, _ = cluster.wait_for_count(0, timeout=300)
        write(args.cleanup_objects, raw)
        deadline = time.monotonic() + 30
        while True:
            final_state = cluster.redis_state()
            if final_state == {"queue": [], "queued": {}, "active": {}}:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Redis session state did not drain after disconnects")
            time.sleep(0.25)
        print("[KUBERNETES-E2E-DISCONNECT-CLEANUP-PASS]")
        print("[KUBERNETES-KIND-E2E-PASS]")
        return 0
    finally:
        if thirty_first is not None:
            thirty_first.close()
        if thirty_second is not None:
            thirty_second.close()
        for session in active:
            session.close()


if __name__ == "__main__":
    sys.exit(main())
