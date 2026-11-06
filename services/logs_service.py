import ipaddress
import logging
import re
import sys
import time
import traceback
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from textwrap import indent

from starlette.requests import Request
from starlette.responses import Response

from config import DEBUG, LOG_FILE_PATH
from services.slack_reporter import slack_reporter

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


def mask_ip(host: str | None) -> str:
    """Hide the middle of an IP address, keeping its first and last parts.

    Every IPv4 address comes out in the same shape (``144.*.*.87``), so
    repeats from one address still stand out without revealing it. IPv6 keeps
    its first and last groups (``2607:*:1a2b``). Anything that isn't an IP
    address is masked like any other string.
    """
    if not host:
        return "-"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return obfuscate_string(host)
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.version == 4:
        parts = str(address).split(".")
        return f"{parts[0]}.*.*.{parts[-1]}"
    groups = address.exploded.split(":")
    return f"{groups[0].lstrip('0') or '0'}:*:{groups[-1].lstrip('0') or '0'}"


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
#       -- WARNING access_account_api.otp - OTP mismatch for email=j**e@ex******org
#       !! Unexpected SES error for email=j**e@ex******org: Throttling
#          Traceback (most recent call last):
#            ...
#
# The whole thing is one log record (one write), so records from concurrent
# requests and from sibling gunicorn workers can't interleave mid-record.
# Messages the app logs while serving a request (the `--` lines) are folded in
# too, by `_fold_into_request`, so nothing about a request ends up in a record
# of its own that can only be tied back to it by time.

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
    # The exception's last line, e.g. "ReadTimeout: timed out".
    summary: str = ""

    def render(self) -> str:
        body = indent(self.traceback_text.rstrip(), " " * 7)
        return f"    !! {self.message}\n{body}"


@dataclass
class LoggedMessage:
    """A message logged by the app while serving a request."""

    levelno: int
    logger_name: str
    message: str

    def render(self) -> str:
        first, *rest = self.message.rstrip().splitlines() or [""]
        lines = [
            f"    -- {logging.getLevelName(self.levelno)} {self.logger_name} - {first}"
        ]
        lines += [" " * 7 + line for line in rest]
        return "\n".join(lines)


@dataclass
class RequestLog:
    """Everything gathered about the request currently being served."""

    user: str | None = None
    # Backend calls, handled exceptions and logged messages share one list so
    # that the rendered child lines stay in the order things actually happened.
    entries: list[BackendCall | LoggedException | LoggedMessage] = field(
        default_factory=list
    )
    # The detail of the error response, if the request ended in one, and
    # whether that error is a routine part of using the app (see
    # `record_error_response`).
    error_detail: str | None = None
    expected_error: bool = False
    # Set once the record is written; anything logged after that (e.g. while
    # the response body streams) has to go out as a record of its own.
    finished: bool = False

    @property
    def has_exception(self) -> bool:
        return any(isinstance(entry, LoggedException) for entry in self.entries)

    @property
    def levelno(self) -> int:
        """The level the record goes out at: the highest of its parts.

        A folded-in warning or error, or a handled exception's traceback, keeps
        the level it would have had as a record of its own -- otherwise
        level-based alerting stops seeing it the moment it is folded in here.
        """
        levels = [logging.INFO]
        levels += [e.levelno for e in self.entries if isinstance(e, LoggedMessage)]
        if self.has_exception:
            levels.append(logging.ERROR)
        return max(levels)


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
        LoggedException(
            message,
            obfuscate_emails_in_text(traceback.format_exc()),
            obfuscate_emails_in_text(_exception_summary(sys.exc_info()[1])),
        )
    )


def record_error_response(detail: str, expected: bool) -> None:
    """Note the error response the request in flight is about to return.

    Called by the exception handlers, which see the exception that produced
    the response; the middleware only sees the finished response. ``expected``
    marks errors that are a routine part of using the app (a mistyped code, an
    expired session), which aren't reported to Slack.
    """
    context = _request_log.get()
    if context is None:
        return
    context.error_detail = detail
    context.expected_error = expected


def _fold_into_request(record: logging.LogRecord) -> bool:
    """Handler filter: put a message logged mid-request into the request record.

    Returns False -- don't write the record on its own -- when it was folded in.
    Outside a request (cron jobs, startup hooks) records are written as usual.
    """
    context = _request_log.get()
    if context is None or context.finished or record.name == access_logger.name:
        return True
    # The call sites obfuscate the emails in their messages, but a traceback can
    # carry an address they never saw (same as `record_exception`).
    message = record.getMessage()
    if record.exc_info:
        message += "\n" + obfuscate_emails_in_text(
            "".join(traceback.format_exception(*record.exc_info))
        )
    context.entries.append(LoggedMessage(record.levelno, record.name, message))
    return False


handler.addFilter(_fold_into_request)


def _exception_summary(exc: BaseException | None) -> str:
    if exc is None:
        return ""
    lines = traceback.format_exception_only(exc)
    return lines[-1].strip() if lines else type(exc).__name__


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


# Error details are usually a sentence, but a backend's error body passed through
# can be a whole HTML page; the full text stays in the log.
_MAX_DETAIL_LENGTH = 500


def _truncate(text: str, limit: int = _MAX_DETAIL_LENGTH) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _should_report(context: RequestLog, status: int) -> bool:
    if status < 400:
        return False
    # A traceback is worth seeing even when the error it led to is routine.
    return context.has_exception or not context.expected_error


def _backend_call_failed(call: BackendCall) -> bool:
    return not isinstance(call.status, int) or call.status >= 400


def _format_slack_report(
    request: Request,
    context: RequestLog,
    status: int,
    elapsed_ms: float,
    exception: BaseException | None = None,
) -> str:
    """Summarize a failed request for Slack.

    Unlike the log record, this leaves out the messages below WARNING and the
    tracebacks, and masks the client IP. Backend calls that worked are left out
    too, unless one of the request's backend calls failed: then every call is
    listed, so the failure can be read alongside what else the request did.
    """
    url = request.url.path
    if request.url.query:
        url = f"{url}?{request.url.query}"
    client = request.client.host if request.client else None
    lines = [
        (
            f"{status} {request.method} {obfuscate_emails_in_text(url)} · "
            f"{mask_ip(client)} · {context.user or '-'} · {elapsed_ms:.1f}ms"
        )
    ]

    backend_calls = [e for e in context.entries if isinstance(e, BackendCall)]
    any_backend_failed = any(_backend_call_failed(c) for c in backend_calls)

    if exception is not None:
        lines.append(_truncate(obfuscate_emails_in_text(_exception_summary(exception))))
    elif context.error_detail:
        lines.append(_truncate(obfuscate_emails_in_text(context.error_detail)))

    for entry in context.entries:
        if isinstance(entry, LoggedException):
            lines.append(f"!! {_truncate(entry.message)}")
            if entry.summary:
                lines.append(f"   {_truncate(entry.summary)}")
        elif isinstance(entry, LoggedMessage):
            if entry.levelno >= logging.WARNING:
                level = logging.getLevelName(entry.levelno)
                first_line = entry.message.strip().partition("\n")[0]
                lines.append(f"-- {level} {_truncate(first_line)}")
        elif any_backend_failed:
            backend_url = entry.url.removeprefix("https://").removeprefix("http://")
            lines.append(
                f"-> {entry.method} {backend_url} {entry.status} "
                f"{entry.elapsed_ms:.1f}ms"
            )

    return "```\n" + "\n".join(lines) + "\n```"


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
        context.finished = True
        access_logger.exception(_format_record(request, context, 500, elapsed_ms))
        slack_reporter.report(
            _format_slack_report(
                request, context, 500, elapsed_ms, exception=sys.exc_info()[1]
            )
        )
        raise
    else:
        elapsed_ms = (time.perf_counter() - started) * 1000
        context.finished = True
        access_logger.log(
            context.levelno,
            _format_record(request, context, response.status_code, elapsed_ms),
        )
        if _should_report(context, response.status_code):
            slack_reporter.report(
                _format_slack_report(request, context, response.status_code, elapsed_ms)
            )
        return response
    finally:
        _request_log.reset(token)
