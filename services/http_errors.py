from fastapi import HTTPException, Request
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from services.logs_service import record_error_response


class ExpectedHTTPException(HTTPException):
    """An error response that's a routine part of using the app.

    Raise this instead of `HTTPException` for errors caused by what the user
    did rather than by something going wrong: a mistyped verification code, an
    expired session, a password that doesn't meet the policy. The response is
    the same; the difference is that it isn't reported to Slack.
    """

    @classmethod
    def from_exception(cls, exc: HTTPException) -> "ExpectedHTTPException":
        headers = dict(exc.headers) if exc.headers else None
        return cls(status_code=exc.status_code, detail=exc.detail, headers=headers)


# Validation errors are only worth reporting where the request comes from a
# form in the frontend, where a 422 means the frontend and API disagree.
# Elsewhere they're usually someone poking at the API.
REPORTED_VALIDATION_ROUTES = {
    ("POST", "/api/v1/account"),
    ("POST", "/api/v1/account/{username}"),
}


def _route_path(request: Request) -> str | None:
    return getattr(request.scope.get("route"), "path", None)


async def handle_http_exception(request: Request, exc: StarletteHTTPException):
    expected = (
        isinstance(exc, ExpectedHTTPException)
        # Paths and methods the API doesn't have: crawlers and scanners.
        or (exc.status_code == 404 and _route_path(request) is None)
        or exc.status_code == 405
    )
    record_error_response(str(exc.detail), expected)
    return await http_exception_handler(request, exc)


async def handle_validation_error(request: Request, exc: RequestValidationError):
    # Report where the problem is, not the values: they're user input.
    detail = "; ".join(
        f"{'.'.join(str(part) for part in error.get('loc', ()))}: {error.get('msg')}"
        for error in exc.errors()
    )
    expected = (request.method, _route_path(request)) not in REPORTED_VALIDATION_ROUTES
    record_error_response(detail, expected)
    return await request_validation_exception_handler(request, exc)


async def handle_rate_limit_exceeded(request: Request, exc: RateLimitExceeded):
    record_error_response(f"Rate limit exceeded: {exc.detail}", expected=True)
    return _rate_limit_exceeded_handler(request, exc)
