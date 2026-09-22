#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import os

from reclaim_gateway.config import Settings
from reclaim_gateway.state import RedisSessionState


def opaque(number: int) -> str:
    return f"{number:024x}"


def connection(number: int) -> str:
    return f"{number:032x}"


async def main() -> None:
    password = os.environ["REDIS_TEST_PASSWORD"]
    host = os.environ.get("REDIS_TEST_HOST", "redis")
    settings = Settings(
        ctfd_base_url="https://ctfd.invalid",
        ctfd_challenge_id=None,
        ctfd_require_team=True,
        ctfd_ca_file=None,
        ctfd_timeout_seconds=2,
        namespace="reclaim-instances",
        challenge_image="private.invalid/reclaim@sha256:" + "a" * 64,
        instance_name_secret=b"h" * 32,
        redis_url=f"redis://{host}:6379/0",
        redis_password=password,
        redis_prefix="q2:test",
        tls_mode="plaintext",
        max_instances=30,
    )
    state = RedisSessionState(settings)
    try:
        await state.ping()
        await state.reset()
        for number in range(1, 31):
            assert (await state.join(opaque(number), connection(number))).accepted
            snapshot = await state.try_promote(opaque(number), connection(number))
            assert snapshot.promoted
            assert snapshot.active == number

        thirty_first = await state.join(opaque(31), connection(31))
        thirty_second = await state.join(opaque(32), connection(32))
        assert thirty_first.position == 1
        assert thirty_second.position == 2
        assert not (await state.try_promote(opaque(31), connection(31))).promoted
        assert (await state.join(opaque(31), connection(99))).duplicate

        await state.leave(opaque(1), connection(1))
        assert (await state.try_promote(opaque(31), connection(31))).promoted
        thirty_second_waiting = await state.try_promote(opaque(32), connection(32))
        assert not thirty_second_waiting.promoted and thirty_second_waiting.position == 1

        await state.leave(opaque(2), connection(2))
        assert (await state.try_promote(opaque(32), connection(32))).promoted
        print("[Q2-REDIS-FIFO-30-SLOT-PASS]")
    finally:
        await state.reset()
        await state.close()


if __name__ == "__main__":
    asyncio.run(main())
