"""Unit tests for services.async_utils.gather_all."""

import asyncio
import logging

import pytest
from fastapi import HTTPException

from services.async_utils import gather_all
from services.http_errors import ExpectedHTTPException
from services.logs_service import (
    LoggedException,
    LoggedMessage,
    RequestLog,
    _request_log,
)


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


@pytest.fixture
def request_log():
    """Stand in for the request in flight, as `log_requests` would set it up."""
    context = RequestLog()
    token = _request_log.set(context)
    yield context
    _request_log.reset(token)


async def fail(exc):
    raise exc


async def test_records_the_exceptions_it_does_not_raise(request_log):
    with pytest.raises(HTTPException) as raised:
        await gather_all(
            fail(HTTPException(500, "CoManage API error")),
            fail(HTTPException(400, "Identity API error: bad degree for a@b.com")),
        )
    assert raised.value.status_code == 500

    (entry,) = request_log.entries
    assert isinstance(entry, LoggedException)
    assert "only the first error (HTTPException) is returned" in entry.message
    assert "400: Identity API error: bad degree for *@b***m" in entry.summary
    assert "Traceback" in entry.traceback_text


async def test_logs_routine_exceptions_it_does_not_raise_without_reporting_them(
    request_log,
):
    with pytest.raises(ValueError):
        await gather_all(
            fail(ValueError("boom")),
            fail(ExpectedHTTPException(400, "already linked")),
        )

    assert not request_log.has_exception
    (entry,) = request_log.entries
    assert isinstance(entry, LoggedMessage)
    assert entry.levelno == logging.INFO
    assert "400: already linked" in entry.message
