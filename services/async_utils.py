import logging
from asyncio import gather
from collections.abc import Awaitable
from typing import Any

from services.http_errors import ExpectedHTTPException
from services.logs_service import record_exception

logger = logging.getLogger("access_account_api")


async def gather_all(*aws: Awaitable[Any]) -> list[Any]:
    """Run awaitables concurrently, waiting for all of them before raising.

    `asyncio.gather` raises the first exception as soon as it happens and leaves
    the remaining tasks running unobserved. For steps that create records, that
    means records can still be created after the caller has given up -- too late
    to be rolled back, and too late to show up in the request's log record.
    This waits for every awaitable to settle, then re-raises the first exception
    (in argument order), if any.

    Only one exception can be raised, so the others are recorded against the
    request in flight; otherwise their details would be lost.
    """
    results = await gather(*aws, return_exceptions=True)
    errors = [result for result in results if isinstance(result, BaseException)]
    if not errors:
        return results

    first, *others = errors
    for other in others:
        message = (
            f"A concurrent step also failed; only the first error "
            f"({type(first).__name__}) is returned"
        )
        if isinstance(other, ExpectedHTTPException):
            # A routine error shouldn't get the request reported to Slack, but
            # keep it in the log record.
            logger.info(f"{message}: {other}")
        else:
            record_exception(message, exc=other)
    raise first
