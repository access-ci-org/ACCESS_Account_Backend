import logging
import re
import time
import traceback
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from textwrap import indent

from starlette.requests import Request
from starlette.responses import Response

from config import DEBUG, LOG_FILE_PATH

# Config logging
logger = logging.getLogger("access_account_api")
logger.setLevel(logging.INFO)

# In debug mode, log to stderr so messages show up in the console. Otherwise,
# write directly to a file -- gunicorn does not capture worker stdout/stderr
# into its log files unless explicitly configured to.
handler = logging.StreamHandler() if DEBUG else logging.FileHandler(LOG_FILE_PATH)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)


def obfuscate_string(value: str, char: str = "*") -> str:
    """Mask the middle portion of a string, keeping its outer edges visible.

    The number of characters replaced is half the string's length (rounded up,
    at least 1), centered within the string.
    """
    length = len(value)
    replace = max(-(-length // 2), 1)
    start = (length - replace) // 2
    return value[:start] + char * replace + value[start + replace :]


def obfuscate_email(address: str | None) -> str | None:
    """Obfuscate the account and domain portions of an email address separately.

    Returns None if ``address`` is falsy or does not contain an "@".
    """
    if not address:
        return None
    account, sep, domain = address.partition("@")
    if not sep:
        return None
    return obfuscate_string(account) + "@" + obfuscate_string(domain)


# "%" is deliberately excluded from the account character class so that the
# separator alternation gets first claim on a percent-encoded "@".
_EMAIL_IN_TEXT = re.compile(
    r"([A-Za-z0-9._+\-]+)(@|%40)([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)",
    re.IGNORECASE,
)


def obfuscate_emails_in_text(text: str) -> str:
    """Obfuscate every email address appearing inside a larger string.

    Percent-encoded "@" is handled as well, so that emails embedded in URL query
    strings -- e.g. CoManage's `?search.mail=jdoe%40example.com` -- are masked
    when the URL is logged.
    """

    def mask(match: re.Match[str]) -> str:
        account, separator, domain = match.groups()
        return obfuscate_string(account) + separator + obfuscate_string(domain)

    return _EMAIL_IN_TEXT.sub(mask, text)


# --- Unified per-request logging -------------------------------------------
#
# Gunicorn's access and error logs record the IP, URL and status of a request
# but not the time; the application log records the time and the user but not
# the IP or URL, which makes the three hard to correlate. To get all of it in
# one place, `log_requests` accumulates a per-request context and emits a single
# record once the response is ready:
#
#   <time> - INFO - access_account_api.access - <ip> <user> <method> <url> <status> <elapsed>
#       -> GET  https://registry.access-ci.org/registry/co_people.json?coid=2 200 118.7ms
#       !! Unexpected SES error for email=j**e@ex******org: Throttling
#          Traceback (most recent call last):
#            ...
#
# The whole thing is one log record (one write), so records from concurrent
# requests and from sibling gunicorn workers can't interleave mid-record.

access_logger = logging.getLogger("access_account_api.access")


@dataclass
class BackendCall:
    """One outbound call to a backend API, as seen by `RestClient`."""

    method: str
    url: str
    status: int | str
    elapsed_ms: float

    def render(self) -> str:
        return (
            f"    -> {self.method:<6} {self.url} {self.status} {self.elapsed_ms:.1f}ms"
        )


@dataclass
class LoggedException:
    """An exception caught and handled mid-request, with its traceback.

    Handled exceptions are recoverable -- they become a 4xx rather than bubbling
    up -- so they never reach the middleware's own exception path. Folding them
    into the request record puts the traceback next to the IP, URL and backend
    calls that produced it, instead of in a bare record of its own.
    """

    message: str
    traceback_text: str

    def render(self) -> str:
        body = indent(self.traceback_text.rstrip(), " " * 7)
        return f"    !! {self.message}\n{body}"


@dataclass
class RequestLog:
    """Everything gathered about the request currently being served."""

    user: str | None = None
    # Backend calls and handled exceptions share one list so that the rendered
    # child lines stay in the order things actually happened.
    entries: list[BackendCall | LoggedException] = field(default_factory=list)

    @property
    def has_exception(self) -> bool:
        return any(isinstance(entry, LoggedException) for entry in self.entries)


# Holds the RequestLog for the request in flight, or None when there is no
# request -- e.g. the startup hooks and the cron jobs, which also make backend
# calls but have nothing to attribute them to.
#
# Starlette runs the downstream app in a child task, which inherits a *copy* of
# this context. Mutating the RequestLog object is therefore visible to the
# middleware once the response comes back, but rebinding the ContextVar
# downstream would not be -- so the helpers below only ever mutate.
_request_log: ContextVar[RequestLog | None] = ContextVar("request_log", default=None)


def set_request_user(username: str | None, email: str | None = None) -> None:
    """Attribute the request in flight to a user.

    The ACCESS username is logged as-is; an email is obfuscated. Called from the
    auth dependency for authenticated routes, and directly by the OTP routes,
    which identify their user from the request body rather than from a token.
    """
    context = _request_log.get()
    if context is None:
        return
    context.user = username or obfuscate_email(email) or context.user


def record_backend_call(
    method: str, url: str, status: int | str, elapsed_ms: float
) -> None:
    """Record one outbound backend call against the request in flight.

    A no-op outside a request, so `RestClient` can call it unconditionally.
    """
    context = _request_log.get()
    if context is None:
        return
    context.entries.append(
        BackendCall(method.upper(), obfuscate_emails_in_text(url), status, elapsed_ms)
    )


def record_exception(message: str, fallback: logging.Logger = logger) -> None:
    """Attach the exception being handled to the request in flight.

    A drop-in replacement for `logger.exception(message)` at call sites that
    catch and convert an error rather than letting it propagate. Must be called
    from inside an `except` block, same as `logger.exception`.

    Outside a request -- cron jobs, startup hooks -- there is nothing to attach
    to, so this falls back to logging a standalone record on `fallback`.
    """
    context = _request_log.get()
    if context is None:
        fallback.exception(message)
        return
    context.entries.append(
        LoggedException(message, obfuscate_emails_in_text(traceback.format_exc()))
    )


def _format_record(
    request: Request, context: RequestLog, status: int | str, elapsed_ms: float
) -> str:
    client = request.client.host if request.client else "-"
    url = request.url.path
    if request.url.query:
        url = f"{url}?{request.url.query}"

    lines = [
        (
            f"{client} {context.user or '-'} {request.method} "
            f"{obfuscate_emails_in_text(url)} {status} {elapsed_ms:.1f}ms"
        )
    ]
    lines += [entry.render() for entry in context.entries]
    return "\n".join(lines)


async def log_requests(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """HTTP middleware emitting one unified log record per request."""
    context = RequestLog()
    token = _request_log.set(context)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        # Responses built by an exception handler (HTTPException, rate limits)
        # come back through `call_next` normally; only genuinely unhandled
        # errors land here. Log the traceback against this request's record --
        # attaching it to the URL and user it came from -- then let Starlette
        # turn it into the 500 the client sees.
        elapsed_ms = (time.perf_counter() - started) * 1000
        access_logger.exception(_format_record(request, context, 500, elapsed_ms))
        raise
    else:
        elapsed_ms = (time.perf_counter() - started) * 1000
        # A request that handled an exception on its way to a 4xx still carries
        # a traceback, so the record has to keep the ERROR level those call
        # sites used to log at -- otherwise level-based alerting stops seeing
        # them the moment they are folded in here.
        level = logging.ERROR if context.has_exception else logging.INFO
        access_logger.log(
            level, _format_record(request, context, response.status_code, elapsed_ms)
        )
        return response
    finally:
        _request_log.reset(token)
