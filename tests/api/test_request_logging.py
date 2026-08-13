"""Tests for the unified per-request log record.

Covers the three pieces that have to cooperate for a record to be complete: the
middleware that emits it, the `RestClient` hook that contributes the indented
backend-call lines, and the auth dependency that names the user. The backend
calls in particular are worth an end-to-end test -- they reach the middleware
by *mutating* a ContextVar's value across Starlette's child-task boundary, which
works only because nothing downstream rebinds the var.
"""

import asyncio
import logging

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from services.logs_service import (
    access_logger,
    log_requests,
    obfuscate_emails_in_text,
    record_exception,
)
from services.rest_client import RestClient

BASE = "/api/v1"


@pytest.fixture
def records(caplog):
    """Yield an accessor for the access-log records emitted during a test."""
    caplog.set_level(logging.INFO, logger=access_logger.name)

    def _records() -> list[logging.LogRecord]:
        return [r for r in caplog.records if r.name == access_logger.name]

    return _records


# ---------------------------------------------------------------------------
# URL scrubbing
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text,expected",
    [
        # Percent-encoded "@", as CoManage's ?search.mail= produces.
        (
            "https://x.org/co_people.json?coid=2&search.mail=jdoe%40example.com",
            "https://x.org/co_people.json?coid=2&search.mail=j**e%40ex******com",
        ),
        # Bare "@".
        ("mail=jdoe@example.com&x=1", "mail=j**e@ex******com&x=1"),
        # More than one address in the same string.
        ("a@b.com,cd@e.org", "*@b***m,*d@e***g"),
        # Nothing email-shaped is touched.
        ("https://x.org/registry/co_people/42.json", None),
        ("/api/v1/account/jdoe15/ssh-key", None),
    ],
)
def test_obfuscate_emails_in_text(text, expected):
    assert obfuscate_emails_in_text(text) == (text if expected is None else expected)


def test_obfuscate_emails_in_text_leaves_no_full_address():
    scrubbed = obfuscate_emails_in_text("?search.mail=jdoe%40example.com")
    assert "jdoe" not in scrubbed
    assert "example" not in scrubbed


# ---------------------------------------------------------------------------
# The parent line, against the real app
# ---------------------------------------------------------------------------
def test_request_line_reports_user_url_status_and_elapsed(
    client, mock_comanage, auth_header, records
):
    mock_comanage.get_user_info.return_value = {}

    response = client.get(
        f"{BASE}/account/user/ssh-key", headers=auth_header(username="user")
    )
    assert response.status_code == 200

    (record,) = records()
    line = record.getMessage()
    assert "testclient" in line  # TestClient's stand-in for the client IP
    assert " user " in line  # attributed by require_auth, via the real JWT
    assert f"GET {BASE}/account/user/ssh-key" in line
    assert " 200 " in line
    assert line.rstrip().endswith("ms")


def test_otp_token_without_username_is_attributed_by_obfuscated_email(
    client, auth_header, records
):
    """OTP tokens can predate the account, so there is no uid to log -- only the
    email in `sub`, which must never reach the log in the clear.

    The route rejects an OTP token, but `require_auth` names the user before
    `require_login` turns it away, so the 403 is still attributed.
    """
    client.get(
        f"{BASE}/account/user/ssh-key",
        headers=auth_header(token_type="otp", sub="jdoe@example.org", username=None),
    )

    line = records()[0].getMessage()
    assert "j**e@ex******org" in line
    assert "jdoe@example.org" not in line


def test_rejected_request_is_still_logged(client, records):
    """4xx responses are built by an exception handler that runs inside the
    middleware, so they show up in the log like any other response."""
    response = client.get(f"{BASE}/account/user/ssh-key")
    assert response.status_code == 403

    line = records()[0].getMessage()
    assert " 403 " in line
    assert " - " in line  # no user could be identified


def test_unhandled_error_logs_traceback_against_the_request(records):
    # Exercised against a throwaway app so the real app's routing table is left
    # alone; the middleware behaves the same either way.
    scratch = FastAPI()
    scratch.middleware("http")(log_requests)

    @scratch.get("/boom")
    async def _boom():
        raise RuntimeError("kaboom")

    with TestClient(scratch, raise_server_exceptions=False) as scratch_client:
        assert scratch_client.get("/boom").status_code == 500

    (record,) = records()
    assert record.levelno == logging.ERROR
    assert " 500 " in record.getMessage()
    assert record.exc_info is not None  # the traceback rides along on the record


# ---------------------------------------------------------------------------
# The indented backend-call lines
# ---------------------------------------------------------------------------
def _app_calling(*urls: str) -> FastAPI:
    """A minimal app whose one route makes real `RestClient` calls."""
    scratch = FastAPI()
    scratch.middleware("http")(log_requests)

    @scratch.get("/call")
    async def _call():
        rest = RestClient()
        for url in urls:
            await rest.request(url)
        return {"ok": True}

    return scratch


@pytest.fixture
def stub_httpx(monkeypatch):
    """Answer every outbound httpx request with a canned status."""

    def _stub(status_code: int = 200):
        async def fake_request(_self, method, url, **kwargs):
            request = httpx.Request(method, url, params=kwargs.get("params"))
            return httpx.Response(status_code, json={}, request=request)

        monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)

    return _stub


def test_backend_calls_are_attached_to_the_request_that_made_them(stub_httpx, records):
    stub_httpx()
    app = _app_calling(
        "https://registry.example.org/registry/co_people.json?coid=2",
        "https://registry.example.org/registry/identifiers.json?copersonid=7",
    )

    with TestClient(app) as scratch_client:
        assert scratch_client.get("/call").status_code == 200

    lines = records()[0].getMessage().splitlines()
    assert len(lines) == 3
    assert lines[0].startswith("testclient")
    assert "-> GET" in lines[1] and "co_people.json?coid=2 200 " in lines[1]
    assert "-> GET" in lines[2] and "identifiers.json?copersonid=7 200 " in lines[2]
    assert all(line.startswith("    ") for line in lines[1:])


def test_backend_call_url_is_scrubbed_of_emails(stub_httpx, records):
    stub_httpx()
    app = _app_calling(
        "https://registry.example.org/registry/co_people.json?search.mail=jdoe%40example.com"
    )

    with TestClient(app) as scratch_client:
        scratch_client.get("/call")

    message = records()[0].getMessage()
    assert "jdoe%40example.com" not in message
    assert "j**e%40ex******com" in message


def test_failed_backend_call_records_its_status(stub_httpx, records):
    stub_httpx(status_code=500)
    app = _app_calling("https://registry.example.org/registry/co_people.json")

    with TestClient(app, raise_server_exceptions=False) as scratch_client:
        scratch_client.get("/call")

    lines = records()[0].getMessage().splitlines()
    assert len(lines) == 2
    assert "co_people.json 500 " in lines[1]


def test_backend_calls_outside_a_request_are_ignored(stub_httpx, records):
    """Cron jobs and startup hooks use `RestClient` too, with no request to
    attribute their calls to."""
    stub_httpx()
    asyncio.run(RestClient().request("https://registry.example.org/registry/x.json"))

    assert records() == []


# ---------------------------------------------------------------------------
# Handled exceptions folded into the record
# ---------------------------------------------------------------------------
def _app_raising_handled_error(stub_httpx=None) -> FastAPI:
    """An app whose route catches an error and converts it to a 400, the shape
    of the SES / argon2 handlers in the real app."""
    scratch = FastAPI()
    scratch.middleware("http")(log_requests)

    @scratch.get("/handled")
    async def _handled():
        if stub_httpx is not None:
            await RestClient().request("https://registry.example.org/registry/x.json")
        try:
            raise ValueError("SES said no")
        except ValueError:
            record_exception("Unexpected SES error for email=j**e@ex******org")
        raise HTTPException(400, "Email send failed")

    return scratch


def test_handled_exception_is_indented_under_the_request(records):
    app = _app_raising_handled_error()

    with TestClient(app) as scratch_client:
        assert scratch_client.get("/handled").status_code == 400

    (record,) = records()
    lines = record.getMessage().splitlines()
    assert " 400 " in lines[0]
    assert lines[1] == "    !! Unexpected SES error for email=j**e@ex******org"
    assert lines[2] == "       Traceback (most recent call last):"
    assert lines[-1] == "       ValueError: SES said no"


def test_handled_exception_escalates_the_record_to_error(records):
    """The call sites this replaces logged at ERROR; a 400 response would
    otherwise emit the whole record at INFO and hide them from alerting."""
    app = _app_raising_handled_error()

    with TestClient(app) as scratch_client:
        scratch_client.get("/handled")

    assert records()[0].levelno == logging.ERROR


def test_handled_exception_keeps_its_place_among_backend_calls(stub_httpx, records):
    stub_httpx()
    app = _app_raising_handled_error(stub_httpx=True)

    with TestClient(app) as scratch_client:
        scratch_client.get("/handled")

    lines = records()[0].getMessage().splitlines()
    assert "-> GET" in lines[1]  # the backend call came first
    assert lines[2].startswith("    !! ")


def test_record_exception_outside_a_request_falls_back_to_its_logger(caplog):
    """Cron jobs and startup hooks have no request to attach to, so the
    traceback still has to reach the log on its own."""
    caplog.set_level(logging.ERROR)
    fallback = logging.getLogger("access_account_api.email")

    try:
        raise ValueError("no request in flight")
    except ValueError:
        record_exception("SES ClientError while sending", fallback=fallback)

    (record,) = [r for r in caplog.records if r.name == fallback.name]
    assert record.levelno == logging.ERROR
    assert record.exc_info is not None
    assert "SES ClientError while sending" in record.getMessage()


def test_recorded_traceback_is_scrubbed_of_emails(records):
    """An exception's own message can carry an address the call site never saw."""
    scratch = FastAPI()
    scratch.middleware("http")(log_requests)

    @scratch.get("/leak")
    async def _leak():
        try:
            raise ValueError("rejected recipient jdoe@example.org")
        except ValueError:
            record_exception("SES rejected the recipient")
        return {"ok": True}

    with TestClient(scratch) as scratch_client:
        scratch_client.get("/leak")

    message = records()[0].getMessage()
    assert "jdoe@example.org" not in message
    assert "j**e@ex******org" in message
