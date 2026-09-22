from __future__ import annotations

import unittest

from reclaim_gateway.state import InMemorySessionState


def opaque(number: int) -> str:
    return f"{number:024x}"


def connection(number: int) -> str:
    return f"{number:032x}"


class StateTests(unittest.IsolatedAsyncioTestCase):
    async def test_exactly_thirty_active_and_next_two_are_fifo(self) -> None:
        state = InMemorySessionState(30)
        for number in range(1, 31):
            joined = await state.join(opaque(number), connection(number))
            self.assertTrue(joined.accepted)
            promoted = await state.try_promote(opaque(number), connection(number))
            self.assertTrue(promoted.promoted)
            self.assertEqual(promoted.active, number)

        thirty_first = await state.join(opaque(31), connection(31))
        thirty_second = await state.join(opaque(32), connection(32))
        self.assertEqual(thirty_first.position, 1)
        self.assertEqual(thirty_second.position, 2)
        self.assertFalse(
            (await state.try_promote(opaque(31), connection(31))).promoted
        )

        await state.leave(opaque(1), connection(1))
        promoted_thirty_first = await state.try_promote(opaque(31), connection(31))
        self.assertTrue(promoted_thirty_first.promoted)
        waiting_thirty_second = await state.try_promote(opaque(32), connection(32))
        self.assertFalse(waiting_thirty_second.promoted)
        self.assertEqual(waiting_thirty_second.position, 1)

        await state.leave(opaque(2), connection(2))
        self.assertTrue(
            (await state.try_promote(opaque(32), connection(32))).promoted
        )

    async def test_one_active_or_queued_connection_per_team(self) -> None:
        state = InMemorySessionState(8)
        first = await state.join(opaque(1), connection(1))
        duplicate_queued = await state.join(opaque(1), connection(2))
        self.assertTrue(first.accepted)
        self.assertTrue(duplicate_queued.duplicate)
        self.assertTrue(
            (await state.try_promote(opaque(1), connection(1))).promoted
        )
        duplicate_active = await state.join(opaque(1), connection(3))
        self.assertTrue(duplicate_active.duplicate)


if __name__ == "__main__":
    unittest.main()
