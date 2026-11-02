from asyncio import gather
from collections.abc import Awaitable
from typing import Any


async def gather_all(*aws: Awaitable[Any]) -> list[Any]:
    """Run awaitables concurrently, waiting for all of them before raising.

    `asyncio.gather` raises the first exception as soon as it happens and leaves
    the remaining tasks running unobserved. For steps that create records, that
    means records can still be created after the caller has given up -- too late
    to be rolled back, and too late to show up in the request's log record.
    This waits for every awaitable to settle, then re-raises the first exception
    (in argument order), if any.
    """
    results = await gather(*aws, return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException):
            raise result
    return results
