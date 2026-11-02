"""Unit tests for services.async_utils.gather_all."""

import asyncio

import pytest

from services.async_utils import gather_all


async def test_returns_results_in_order():
    async def value(v):
        return v

    assert await gather_all(value(1), value(2)) == [1, 2]


async def test_waits_for_every_awaitable_before_raising():
    finished = []

    async def fail_fast():
        raise ValueError("boom")

    async def slow():
        await asyncio.sleep(0.05)
        finished.append("slow")

    with pytest.raises(ValueError, match="boom"):
        await gather_all(fail_fast(), slow())
    # Plain asyncio.gather would have raised before `slow` finished.
    assert finished == ["slow"]


async def test_raises_first_exception_in_argument_order():
    async def fail(exc, delay):
        await asyncio.sleep(delay)
        raise exc

    with pytest.raises(KeyError):
        await gather_all(fail(KeyError("first"), 0.05), fail(ValueError("second"), 0))
