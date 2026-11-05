"""Search the application log for the records about one user.

A record starts with a line in the `logs_service` format:

    2026-11-05 14:03:12,345 - INFO - access_account_api.access - <message>

Every following line that doesn't start with a timestamp belongs to the same
record: the backend calls (`->`), handled exceptions (`!!`) and logged messages
(`--`) folded into a request record, and traceback lines.

A request record names its user (ACCESS ID or obfuscated email) in a field of
its first line, so it matches if that field is the user. Records without a
user -- requests made before anyone signed in, like the SES email callback,
and anything logged outside a request -- match if the user appears anywhere
in their text. Matching records are returned whole.
"""

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

from services.logs_service import access_logger, obfuscate_email

_RECORD_START = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} - (?P<level>[A-Z]+) - "
    r"(?P<name>\S+) - (?P<message>.*)$"
)
# The first line of a request record: "<ip> <user> <method> <url> ...".
_NO_USER = "-"
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# For records without a user field, the user is matched in the text.
# Characters that can be part of an ACCESS ID or an (obfuscated) email address.
# A match can't have one of these on either side, so "ada" doesn't match "adam"
# and "j" doesn't match the start of "j**e@ex******org". A "." after it is fine
# unless more of a name follows, so a match can end a sentence.
_WORD = r"[A-Za-z0-9._+*\-]"
_NOT_BEFORE = rf"(?<!{_WORD})"
_NOT_AFTER = r"(?![A-Za-z0-9_+*\-]|\.[A-Za-z0-9_+*\-])"


@dataclass
class LogRecord:
    timestamp: datetime | None
    level: str | None
    lines: list[str]
    # The user field of a request record; None for other records, and for
    # requests with no user.
    user: str | None = None

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def iter_records(lines: Iterable[str]) -> Iterator[LogRecord]:
    """Group log lines into records, a header line plus its subentries.

    Lines before the first header (e.g. the tail of a record cut off by log
    rotation) are returned as a record with no timestamp.
    """
    record = None
    for line in lines:
        line = line.rstrip("\n")
        start = _RECORD_START.match(line)
        if start:
            if record:
                yield record
            record = LogRecord(
                datetime.strptime(start["time"], _TIME_FORMAT),
                start["level"],
                [line],
                _request_user(start["name"], start["message"]),
            )
        elif record:
            record.lines.append(line)
        elif line:
            record = LogRecord(None, None, [line])
    if record:
        yield record


def _request_user(logger_name: str, message: str) -> str | None:
    if logger_name != access_logger.name:
        return None
    fields = message.split(maxsplit=2)
    if len(fields) < 2 or fields[1] == _NO_USER:
        return None
    return fields[1]


def search_term(user: str) -> str:
    """The text a user appears as in the log.

    Emails are logged obfuscated, so an email is obfuscated the same way.
    """
    user = user.strip()
    if "@" not in user:
        return user
    obfuscated = obfuscate_email(user)
    assert obfuscated is not None  # only None without an "@"
    return obfuscated


def search_pattern(user: str) -> re.Pattern[str]:
    """Match the user as a whole word in a record's text, ignoring case.

    An obfuscated email also matches with a percent-encoded "@", as it appears
    in logged URLs.
    """
    term = search_term(user)
    account, at, domain = term.partition("@")
    escaped = (
        re.escape(account) + "(?:@|%40)" + re.escape(domain) if at else re.escape(term)
    )
    return re.compile(_NOT_BEFORE + escaped + _NOT_AFTER, re.IGNORECASE)


def search_log(
    lines: Iterable[str],
    user: str,
    start: datetime | None = None,
    end: datetime | None = None,
) -> Iterator[LogRecord]:
    """Yield each record about `user`, logged from `start` to before `end`.

    Records with no timestamp are left out when a time range is given.
    """
    term = search_term(user).lower()
    pattern = search_pattern(user)
    for record in iter_records(lines):
        if start or end:
            if record.timestamp is None:
                continue
            if start and record.timestamp < start:
                continue
            if end and record.timestamp >= end:
                continue
        if record.user is not None:
            if record.user.lower() == term:
                yield record
        elif pattern.search(record.text):
            yield record
