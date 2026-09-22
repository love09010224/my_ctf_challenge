from __future__ import annotations

import asyncio
import collections
import logging
import secrets
import time
from typing import Protocol

from .config import Settings
from .ctfd import AuthenticationError, Identity
from .kubernetes import CapacityError, Endpoint, KubernetesError
from .state import SessionState, StateError


LOGGER = logging.getLogger(__name__)


class ClientDisconnected(ConnectionError):
    pass


class QueueWaitExpired(TimeoutError):
    pass


class QueuedInputTooLarge(ValueError):
    pass


class IdentityValidator(Protocol):
    def validate(self, token: str) -> Identity: ...


class EndpointController(Protocol):
    def opaque_subject(self, subject: str) -> str: ...

    async def ensure(self, instance_id: str) -> Endpoint: ...

    async def wait_ready(self, instance_id: str, timeout: float) -> None: ...

    async def destroy(self, instance_id: str) -> None: ...


class AuthRateLimiter:
    def __init__(self, attempts: int, period: float = 60.0):
        self.attempts = attempts
        self.period = period
        self.events: dict[str, collections.deque[float]] = {}

    def allow(self, peer: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        queue = self.events.setdefault(peer, collections.deque())
        while queue and queue[0] <= current - self.period:
            queue.popleft()
        if len(queue) >= self.attempts:
            return False
        queue.append(current)
        if len(self.events) > 10000:
            cutoff = current - self.period
            compacted: dict[str, collections.deque[float]] = {}
            for key, values in self.events.items():
                while values and values[0] <= cutoff:
                    values.popleft()
                if values:
                    compacted[key] = values
            while len(compacted) > 10000:
                compacted.pop(next(iter(compacted)))
            self.events = compacted
        return True


class Broker:
    def __init__(
        self,
        settings: Settings,
        validator: IdentityValidator,
        controller: EndpointController,
        state: SessionState,
    ):
        self.settings = settings
        self.validator = validator
        self.controller = controller
        self.state = state
        self.connection_slots = asyncio.Semaphore(settings.max_connections)
        self.rate_limiter = AuthRateLimiter(settings.auth_attempts_per_minute)

    @staticmethod
    async def _write(writer: asyncio.StreamWriter, value: str) -> None:
        writer.write(value.encode("utf-8"))
        await writer.drain()

    @staticmethod
    def _peer(writer: asyncio.StreamWriter) -> str:
        value = writer.get_extra_info("peername")
        if isinstance(value, tuple) and value:
            return str(value[0])
        return "unknown"

    async def _read_token(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> str:
        await self._write(writer, "RE:CLAIM instance gateway\nToken: ")
        try:
            raw = await asyncio.wait_for(
                reader.readline(), timeout=self.settings.token_timeout_seconds
            )
        except (TimeoutError, ValueError) as error:
            raise AuthenticationError("token input timed out") from error
        if not raw or len(raw) > 514 or not raw.endswith(b"\n"):
            raise AuthenticationError("invalid access token")
        raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError as error:
            raise AuthenticationError("invalid access token") from error

    async def _connect_backend(
        self, endpoint: Endpoint
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bytes]:
        deadline = time.monotonic() + self.settings.backend_startup_seconds
        # Do not race a newly-created Service with EndpointSlice publication.
        # The real QEMU serial listener is one-client-sensitive, so probing or
        # reconnecting after an accepted socket is unsafe. Wait using the
        # Kubernetes readiness control plane, then make the single connection.
        await self.controller.wait_ready(
            endpoint.instance_id,
            max(0.1, deadline - time.monotonic()),
        )
        last_error: BaseException | None = None
        while time.monotonic() < deadline:
            backend_writer: asyncio.StreamWriter | None = None
            try:
                backend_reader, backend_writer = await asyncio.wait_for(
                    asyncio.open_connection(endpoint.host, endpoint.port), timeout=2
                )
            except (OSError, TimeoutError) as error:
                last_error = error
                await asyncio.sleep(0.25)
                continue

            # A Service can accept before QEMU is the real consumer. Only the
            # first guest serial byte proves readiness; preserve that byte.
            remaining = deadline - time.monotonic()
            try:
                first = await asyncio.wait_for(
                    backend_reader.read(1), timeout=max(0.1, remaining)
                )
            except asyncio.CancelledError:
                backend_writer.close()
                try:
                    await backend_writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
                raise
            except TimeoutError as error:
                last_error = error
                backend_writer.close()
                try:
                    await backend_writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
                break
            if not first:
                last_error = ConnectionResetError(
                    "backend closed before emitting guest output"
                )
                backend_writer.close()
                try:
                    await backend_writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
                await asyncio.sleep(0.25)
                continue
            return backend_reader, backend_writer, first
        raise KubernetesError("instance did not become ready") from last_error

    def _append_queued_input(self, buffered: bytearray, data: bytes) -> None:
        buffered.extend(data)
        if len(buffered) > self.settings.queued_input_limit:
            raise QueuedInputTooLarge("too much input was sent before instance readiness")

    async def _wait_for_slot(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        instance_id: str,
        connection_id: str,
    ) -> bytes:
        deadline = time.monotonic() + self.settings.queue_wait_seconds
        next_status = 0.0
        buffered = bytearray()
        while True:
            snapshot = await self.state.try_promote(instance_id, connection_id)
            if snapshot.duplicate or not snapshot.accepted:
                raise StateError("queue ownership was lost")
            if snapshot.promoted:
                return bytes(buffered)
            now = time.monotonic()
            if now >= deadline:
                raise QueueWaitExpired("queue wait expired")
            if now >= next_status:
                await self._write(
                    writer,
                    f"Queued: position {snapshot.position}; "
                    f"active {snapshot.active}/{self.settings.max_instances}.\n",
                )
                next_status = now + self.settings.queue_status_seconds
            timeout = min(self.settings.queue_poll_seconds, deadline - now)
            try:
                data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            except TimeoutError:
                continue
            if not data:
                raise ClientDisconnected("client disconnected while queued")
            self._append_queued_input(buffered, data)

    async def _prepare_backend(
        self,
        reader: asyncio.StreamReader,
        endpoint: Endpoint,
        queued_input: bytes,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bytes, bytes]:
        backend_task = asyncio.create_task(self._connect_backend(endpoint))
        buffered = bytearray(queued_input)
        try:
            while True:
                client_task = asyncio.create_task(reader.read(65536))
                done, _ = await asyncio.wait(
                    {backend_task, client_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if client_task in done:
                    data = client_task.result()
                    if not data:
                        backend_task.cancel()
                        await asyncio.gather(backend_task, return_exceptions=True)
                        raise ClientDisconnected(
                            "client disconnected while the instance was starting"
                        )
                    self._append_queued_input(buffered, data)
                if backend_task in done:
                    if client_task not in done:
                        client_task.cancel()
                        await asyncio.gather(client_task, return_exceptions=True)
                    backend_reader, backend_writer, backend_prefix = backend_task.result()
                    return (
                        backend_reader,
                        backend_writer,
                        backend_prefix,
                        bytes(buffered),
                    )
        except BaseException:
            if not backend_task.done():
                backend_task.cancel()
                await asyncio.gather(backend_task, return_exceptions=True)
            raise

    @staticmethod
    async def _pump(
        source: asyncio.StreamReader, destination: asyncio.StreamWriter
    ) -> None:
        while True:
            data = await source.read(65536)
            if not data:
                break
            destination.write(data)
            await destination.drain()

    async def _proxy(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        backend_reader: asyncio.StreamReader,
        backend_writer: asyncio.StreamWriter,
        backend_prefix: bytes = b"",
        client_prefix: bytes = b"",
    ) -> None:
        if backend_prefix:
            client_writer.write(backend_prefix)
            await client_writer.drain()
        if client_prefix:
            backend_writer.write(client_prefix)
            await backend_writer.drain()
        tasks = {
            asyncio.create_task(self._pump(client_reader, backend_writer)),
            asyncio.create_task(self._pump(backend_reader, client_writer)),
        }
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            try:
                task.result()
            except (ConnectionError, OSError):
                pass

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        acquired = False
        instance_id: str | None = None
        connection_id = secrets.token_hex(16)
        joined = False
        promoted = False
        allocation_started = False
        backend_writer: asyncio.StreamWriter | None = None
        cleanup_succeeded = False
        try:
            try:
                await asyncio.wait_for(self.connection_slots.acquire(), timeout=0.1)
                acquired = True
            except TimeoutError:
                await self._write(writer, "Gateway is busy. Try again later.\n")
                return

            peer = self._peer(writer)
            if not self.rate_limiter.allow(peer):
                await self._write(writer, "Too many authentication attempts.\n")
                return

            token = await self._read_token(reader, writer)
            identity = await asyncio.to_thread(self.validator.validate, token)
            token = ""  # Drop the participant bearer before queue or instance work.
            instance_id = self.controller.opaque_subject(identity.subject)
            identity = None  # Drop raw team identity before Redis/Kubernetes work.

            snapshot = await self.state.join(instance_id, connection_id)
            if snapshot.duplicate or not snapshot.accepted:
                await self._write(
                    writer,
                    "This team already has an active or queued connection.\n",
                )
                return
            joined = True
            await self._write(writer, "\nAuthenticated. Waiting for an instance slot.\n")
            queued_input = await self._wait_for_slot(
                reader, writer, instance_id, connection_id
            )
            promoted = True

            await self._write(writer, "Slot allocated. Starting the team instance...\n")
            allocation_started = True
            endpoint = await self.controller.ensure(instance_id)
            (
                backend_reader,
                backend_writer,
                backend_prefix,
                queued_input,
            ) = await self._prepare_backend(reader, endpoint, queued_input)
            remaining = max(0, endpoint.expires_at - int(time.time()))
            await self._write(
                writer,
                f"Instance {endpoint.instance_id} ready; {remaining}s remaining.\n\n",
            )
            await self._proxy(
                reader,
                writer,
                backend_reader,
                backend_writer,
                backend_prefix,
                queued_input,
            )
        except AuthenticationError:
            try:
                await self._write(writer, "\nAuthentication failed.\n")
            except (ConnectionError, OSError):
                pass
        except QueueWaitExpired:
            try:
                await self._write(writer, "\nQueue wait expired. Reconnect to try again.\n")
            except (ConnectionError, OSError):
                pass
        except QueuedInputTooLarge:
            try:
                await self._write(writer, "\nToo much input before instance readiness.\n")
            except (ConnectionError, OSError):
                pass
        except CapacityError:
            # Redis is authoritative; this means stale Kubernetes resources are
            # still terminating. Fail closed instead of exceeding thirty slots.
            LOGGER.exception("Kubernetes capacity disagrees with queue state")
            try:
                await self._write(writer, "\nInstance capacity is reconciling.\n")
            except (ConnectionError, OSError):
                pass
        except (KubernetesError, StateError):
            LOGGER.exception("instance allocation, cleanup, or state operation failed")
            try:
                await self._write(
                    writer, "\nInstance service is temporarily unavailable.\n"
                )
            except (ConnectionError, OSError):
                pass
        except ClientDisconnected:
            pass
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError):
            pass
        except Exception:
            LOGGER.exception("unexpected gateway connection failure")
        finally:
            if backend_writer is not None:
                backend_writer.close()
                try:
                    await backend_writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
            if allocation_started and instance_id is not None:
                try:
                    await asyncio.shield(self.controller.destroy(instance_id))
                    cleanup_succeeded = True
                except (KubernetesError, asyncio.CancelledError):
                    LOGGER.exception(
                        "instance cleanup failed; retaining the active slot fail-closed"
                    )
            if joined and instance_id is not None:
                # Queued connections can always leave. Promoted slots are
                # released only after Job and Service deletion is confirmed.
                if not promoted or cleanup_succeeded:
                    try:
                        await asyncio.shield(
                            self.state.leave(instance_id, connection_id)
                        )
                    except (StateError, asyncio.CancelledError):
                        LOGGER.exception("failed to release queue state")
            if acquired:
                self.connection_slots.release()
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
