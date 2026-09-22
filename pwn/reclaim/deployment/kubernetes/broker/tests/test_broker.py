from __future__ import annotations

import asyncio
import time
import unittest

from reclaim_gateway.broker import Broker
from reclaim_gateway.config import Settings
from reclaim_gateway.ctfd import Identity
from reclaim_gateway.kubernetes import Endpoint
from reclaim_gateway.state import InMemorySessionState


TOKEN = "participant-access-token"
OPAQUE = "a" * 24


def settings() -> Settings:
    return Settings(
        ctfd_base_url="https://ctfd.invalid",
        ctfd_challenge_id=None,
        ctfd_require_team=True,
        ctfd_ca_file=None,
        ctfd_timeout_seconds=2,
        namespace="reclaim",
        challenge_image="private/reclaim@sha256:test",
        instance_name_secret=b"x" * 32,
        tls_mode="plaintext",
        backend_startup_seconds=2,
        token_timeout_seconds=2,
        queue_poll_seconds=0.05,
        queue_status_seconds=1,
    )


class _Validator:
    def __init__(self) -> None:
        self.seen: list[str] = []

    def validate(self, token: str) -> Identity:
        self.seen.append(token)
        if token != TOKEN:
            raise AssertionError("unexpected token")
        return Identity(subject="team:42")


class _Controller:
    def __init__(self, port: int) -> None:
        self.port = port
        self.instance_ids: list[str] = []
        self.destroyed: list[str] = []
        self.destroyed_event = asyncio.Event()
        self.ready_checks: list[str] = []

    def opaque_subject(self, subject: str) -> str:
        if subject != "team:42":
            raise AssertionError("raw identity mismatch")
        return OPAQUE

    async def ensure(self, instance_id: str) -> Endpoint:
        self.instance_ids.append(instance_id)
        return Endpoint(
            host="127.0.0.1",
            port=self.port,
            expires_at=int(time.time()) + 900,
            instance_id=instance_id,
        )

    async def wait_ready(self, instance_id: str, timeout: float) -> None:
        if timeout <= 0:
            raise AssertionError("backend readiness timeout was not positive")
        self.ready_checks.append(instance_id)

    async def destroy(self, instance_id: str) -> None:
        self.destroyed.append(instance_id)
        self.destroyed_event.set()


class BrokerTests(unittest.IsolatedAsyncioTestCase):
    async def test_backend_connection_retries_immediate_eof(self) -> None:
        connections = 0
        stable_connected = asyncio.Event()
        release_stable = asyncio.Event()
        stable_closed = asyncio.Event()

        async def backend(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            nonlocal connections
            connections += 1
            if connections == 1:
                writer.close()
                await writer.wait_closed()
                return
            writer.write(b"S")
            await writer.drain()
            stable_connected.set()
            await release_stable.wait()
            writer.close()
            await writer.wait_closed()
            stable_closed.set()

        server = await asyncio.start_server(backend, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        broker = Broker(
            settings(),
            _Validator(),
            _Controller(port),
            InMemorySessionState(8),
        )
        endpoint = Endpoint(
            host="127.0.0.1",
            port=port,
            expires_at=int(time.time()) + 900,
            instance_id=OPAQUE,
        )
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer, prefix = await broker._connect_backend(endpoint)
            await asyncio.wait_for(stable_connected.wait(), timeout=2)
            self.assertEqual(connections, 2)
            self.assertEqual(prefix, b"S")
            self.assertFalse(reader.at_eof())
            self.assertEqual(broker.controller.ready_checks, [OPAQUE])
        finally:
            release_stable.set()
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            await asyncio.wait_for(stable_closed.wait(), timeout=2)
            server.close()
            await server.wait_closed()

    async def test_token_is_consumed_early_input_preserved_and_job_destroyed(self) -> None:
        captured = bytearray()
        captured_event = asyncio.Event()

        async def backend(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.write(b"guest-ready\n")
            await writer.drain()
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                captured.extend(data)
                if b"whoami\n" in captured:
                    captured_event.set()
                    break
            writer.close()
            await writer.wait_closed()

        backend_server = await asyncio.start_server(backend, "127.0.0.1", 0)
        backend_port = backend_server.sockets[0].getsockname()[1]
        validator = _Validator()
        controller = _Controller(backend_port)
        state = InMemorySessionState(8)
        broker = Broker(settings(), validator, controller, state)
        gateway_done = asyncio.Event()

        async def gateway(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await broker.handle(reader, writer)
            finally:
                gateway_done.set()

        gateway_server = await asyncio.start_server(gateway, "127.0.0.1", 0)
        gateway_port = gateway_server.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", gateway_port)
            prompt = await asyncio.wait_for(reader.readuntil(b"Token: "), timeout=2)
            self.assertIn(b"Token: ", prompt)
            # Deliberately coalesce the token and first guest command.
            writer.write(TOKEN.encode() + b"\nwhoami\n")
            await writer.drain()
            transcript = await asyncio.wait_for(
                reader.readuntil(b"guest-ready\n"), timeout=3
            )
            self.assertIn(b"Authenticated", transcript)
            self.assertIn(b"Slot allocated", transcript)
            await asyncio.wait_for(captured_event.wait(), timeout=2)
            self.assertEqual(bytes(captured), b"whoami\n")
            self.assertNotIn(TOKEN.encode(), captured)
            self.assertEqual(validator.seen, [TOKEN])
            self.assertEqual(controller.instance_ids, [OPAQUE])
            self.assertEqual(controller.ready_checks, [OPAQUE])
            writer.close()
            await writer.wait_closed()
            await asyncio.wait_for(controller.destroyed_event.wait(), timeout=2)
            await asyncio.wait_for(gateway_done.wait(), timeout=2)
            self.assertEqual(controller.destroyed, [OPAQUE])
        finally:
            gateway_server.close()
            backend_server.close()
            await gateway_server.wait_closed()
            await backend_server.wait_closed()

    async def test_duplicate_team_is_rejected_while_queued(self) -> None:
        state = InMemorySessionState(8)
        first_connection = "1" * 32
        snapshot = await state.join(OPAQUE, first_connection)
        self.assertTrue(snapshot.accepted)

        async def unused_backend(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.close()
            await writer.wait_closed()

        backend_server = await asyncio.start_server(unused_backend, "127.0.0.1", 0)
        controller = _Controller(backend_server.sockets[0].getsockname()[1])
        broker = Broker(settings(), _Validator(), controller, state)
        gateway_done = asyncio.Event()

        async def gateway(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await broker.handle(reader, writer)
            finally:
                gateway_done.set()

        gateway_server = await asyncio.start_server(gateway, "127.0.0.1", 0)
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway_server.sockets[0].getsockname()[1]
            )
            await reader.readuntil(b"Token: ")
            writer.write(TOKEN.encode() + b"\n")
            await writer.drain()
            result = await asyncio.wait_for(reader.read(), timeout=2)
            self.assertIn(b"already has an active or queued", result)
            self.assertEqual(controller.instance_ids, [])
            writer.close()
            await writer.wait_closed()
            await asyncio.wait_for(gateway_done.wait(), timeout=2)
        finally:
            await state.leave(OPAQUE, first_connection)
            gateway_server.close()
            backend_server.close()
            await gateway_server.wait_closed()
            await backend_server.wait_closed()


if __name__ == "__main__":
    unittest.main()
