from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Protocol

from .config import Settings


OPAQUE_ID = re.compile(r"[0-9a-f]{24}")
CONNECTION_ID = re.compile(r"[0-9a-f]{32}")


class StateError(RuntimeError):
    pass


@dataclass(frozen=True)
class QueueSnapshot:
    accepted: bool
    promoted: bool
    duplicate: bool
    position: int
    active: int


class SessionState(Protocol):
    async def ping(self) -> None: ...

    async def reset(self) -> None: ...

    async def join(self, instance_id: str, connection_id: str) -> QueueSnapshot: ...

    async def try_promote(
        self, instance_id: str, connection_id: str
    ) -> QueueSnapshot: ...

    async def leave(self, instance_id: str, connection_id: str) -> None: ...

    async def close(self) -> None: ...


def _validate(instance_id: str, connection_id: str) -> None:
    if OPAQUE_ID.fullmatch(instance_id) is None:
        raise StateError("invalid opaque instance identifier")
    if CONNECTION_ID.fullmatch(connection_id) is None:
        raise StateError("invalid connection identifier")


class InMemorySessionState:
    """Deterministic model used by unit tests; production uses Redis."""

    def __init__(self, max_instances: int):
        self.max_instances = max_instances
        self._queue: list[str] = []
        self._queued: dict[str, str] = {}
        self._active: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def ping(self) -> None:
        return None

    async def reset(self) -> None:
        async with self._lock:
            self._queue.clear()
            self._queued.clear()
            self._active.clear()

    def _snapshot(
        self,
        instance_id: str,
        *,
        accepted: bool,
        promoted: bool,
        duplicate: bool,
    ) -> QueueSnapshot:
        try:
            position = self._queue.index(instance_id) + 1
        except ValueError:
            position = 0
        return QueueSnapshot(
            accepted=accepted,
            promoted=promoted,
            duplicate=duplicate,
            position=position,
            active=len(self._active),
        )

    async def join(self, instance_id: str, connection_id: str) -> QueueSnapshot:
        _validate(instance_id, connection_id)
        async with self._lock:
            if instance_id in self._active or instance_id in self._queued:
                return self._snapshot(
                    instance_id,
                    accepted=False,
                    promoted=False,
                    duplicate=True,
                )
            self._queue.append(instance_id)
            self._queued[instance_id] = connection_id
            return self._snapshot(
                instance_id,
                accepted=True,
                promoted=False,
                duplicate=False,
            )

    async def try_promote(
        self, instance_id: str, connection_id: str
    ) -> QueueSnapshot:
        _validate(instance_id, connection_id)
        async with self._lock:
            if self._active.get(instance_id) == connection_id:
                return self._snapshot(
                    instance_id,
                    accepted=True,
                    promoted=True,
                    duplicate=False,
                )
            if self._queued.get(instance_id) != connection_id:
                return self._snapshot(
                    instance_id,
                    accepted=False,
                    promoted=False,
                    duplicate=True,
                )
            if len(self._active) >= self.max_instances or self._queue[0] != instance_id:
                return self._snapshot(
                    instance_id,
                    accepted=True,
                    promoted=False,
                    duplicate=False,
                )
            self._queue.pop(0)
            del self._queued[instance_id]
            self._active[instance_id] = connection_id
            return self._snapshot(
                instance_id,
                accepted=True,
                promoted=True,
                duplicate=False,
            )

    async def leave(self, instance_id: str, connection_id: str) -> None:
        _validate(instance_id, connection_id)
        async with self._lock:
            if self._active.get(instance_id) == connection_id:
                del self._active[instance_id]
            if self._queued.get(instance_id) == connection_id:
                del self._queued[instance_id]
                self._queue = [item for item in self._queue if item != instance_id]

    async def close(self) -> None:
        return None


class RedisSessionState:
    """FIFO and active-slot state for the single authoritative gateway replica.

    The Helm chart enforces one gateway replica. Operations are serialized in
    this process and persisted in Redis so queue metrics and state are explicit.
    A gateway restart drops every TCP connection; startup reconciliation first
    deletes managed Jobs and then resets only this key prefix.
    """

    def __init__(self, settings: Settings):
        try:
            import redis.asyncio as redis
        except ImportError as error:  # pragma: no cover - image/runtime guard
            raise StateError("redis package is not installed") from error

        options: dict[str, object] = {
            "password": settings.redis_password,
            "decode_responses": True,
            "socket_connect_timeout": 2,
            "socket_timeout": 2,
            "health_check_interval": 15,
        }
        if settings.redis_ca_file:
            options["ssl_ca_certs"] = settings.redis_ca_file
            options["ssl_cert_reqs"] = "required"
        self._client = redis.Redis.from_url(settings.redis_url, **options)
        self.max_instances = settings.max_instances
        self.queue_key = f"{settings.redis_prefix}:queue"
        self.queued_key = f"{settings.redis_prefix}:queued"
        self.active_key = f"{settings.redis_prefix}:active"
        self._lock = asyncio.Lock()

    async def _call(self, awaitable):  # noqa: ANN001, ANN202
        try:
            return await awaitable
        except Exception as error:
            raise StateError("Redis state operation failed") from error

    async def ping(self) -> None:
        result = await self._call(self._client.ping())
        if result is not True:
            raise StateError("Redis ping failed")

    async def reset(self) -> None:
        async with self._lock:
            await self._call(
                self._client.delete(self.queue_key, self.queued_key, self.active_key)
            )

    async def _snapshot(
        self,
        instance_id: str,
        *,
        accepted: bool,
        promoted: bool,
        duplicate: bool,
    ) -> QueueSnapshot:
        pipe = self._client.pipeline(transaction=False)
        pipe.lpos(self.queue_key, instance_id)
        pipe.hlen(self.active_key)
        position, active = await self._call(pipe.execute())
        return QueueSnapshot(
            accepted=accepted,
            promoted=promoted,
            duplicate=duplicate,
            position=0 if position is None else int(position) + 1,
            active=int(active),
        )

    async def join(self, instance_id: str, connection_id: str) -> QueueSnapshot:
        _validate(instance_id, connection_id)
        async with self._lock:
            pipe = self._client.pipeline(transaction=False)
            pipe.hexists(self.active_key, instance_id)
            pipe.hexists(self.queued_key, instance_id)
            active, queued = await self._call(pipe.execute())
            if active or queued:
                return await self._snapshot(
                    instance_id,
                    accepted=False,
                    promoted=False,
                    duplicate=True,
                )
            pipe = self._client.pipeline(transaction=True)
            pipe.rpush(self.queue_key, instance_id)
            pipe.hset(self.queued_key, instance_id, connection_id)
            await self._call(pipe.execute())
            return await self._snapshot(
                instance_id,
                accepted=True,
                promoted=False,
                duplicate=False,
            )

    async def try_promote(
        self, instance_id: str, connection_id: str
    ) -> QueueSnapshot:
        _validate(instance_id, connection_id)
        async with self._lock:
            pipe = self._client.pipeline(transaction=False)
            pipe.hget(self.active_key, instance_id)
            pipe.hget(self.queued_key, instance_id)
            pipe.hlen(self.active_key)
            pipe.lindex(self.queue_key, 0)
            active_owner, queued_owner, active_count, head = await self._call(
                pipe.execute()
            )
            if active_owner == connection_id:
                return await self._snapshot(
                    instance_id,
                    accepted=True,
                    promoted=True,
                    duplicate=False,
                )
            if queued_owner != connection_id:
                return await self._snapshot(
                    instance_id,
                    accepted=False,
                    promoted=False,
                    duplicate=True,
                )
            if int(active_count) >= self.max_instances or head != instance_id:
                return await self._snapshot(
                    instance_id,
                    accepted=True,
                    promoted=False,
                    duplicate=False,
                )
            pipe = self._client.pipeline(transaction=True)
            pipe.lpop(self.queue_key)
            pipe.hdel(self.queued_key, instance_id)
            pipe.hset(self.active_key, instance_id, connection_id)
            await self._call(pipe.execute())
            return await self._snapshot(
                instance_id,
                accepted=True,
                promoted=True,
                duplicate=False,
            )

    async def leave(self, instance_id: str, connection_id: str) -> None:
        _validate(instance_id, connection_id)
        async with self._lock:
            pipe = self._client.pipeline(transaction=False)
            pipe.hget(self.active_key, instance_id)
            pipe.hget(self.queued_key, instance_id)
            active_owner, queued_owner = await self._call(pipe.execute())
            pipe = self._client.pipeline(transaction=True)
            changed = False
            if active_owner == connection_id:
                pipe.hdel(self.active_key, instance_id)
                changed = True
            if queued_owner == connection_id:
                pipe.hdel(self.queued_key, instance_id)
                pipe.lrem(self.queue_key, 0, instance_id)
                changed = True
            if changed:
                await self._call(pipe.execute())

    async def close(self) -> None:
        await self._call(self._client.aclose())
