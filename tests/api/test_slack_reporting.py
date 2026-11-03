"""Tests for which failed requests get reported to Slack, and what's reported.

The reporter itself (rate limiting, posting) is covered in
tests/unit/test_slack_reporter.py; here `slack_reporter.report` is replaced so
each test sees exactly the text that would be posted.
"""

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

import main
from services import logs_service
from services.http_errors import (
    ExpectedHTTPException,
    handle_http_exception,
    handle_validation_error,
)
from services.logs_service import log_requests, record_backend_call, record_exception

BASE = "/api/v1"


@pytest.fixture
def reports(monkeypatch):
    """Collect the reports that would be posted to Slack."""
    sent: list[str] = []
    monkeypatch.setattr(logs_service.slack_reporter, "report", sent.append)
    return sent


def scratch_app() -> FastAPI:
    """A throwaway app wired like the real one, for routes the real one lacks."""
    app = FastAPI()
    app.middleware("http")(log_requests)
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(RequestValidationError, handle_validation_error)  # pyright: ignore[reportArgumentType]
    return app


# --- What a report contains -------------------------------------------------
def test_report_masks_ip_and_emails_and_lists_only_failed_backend_calls(reports):
    app = scratch_app()

    @app.get("/fail")
    async def _fail():
        record_backend_call("GET", "https://registry.test/ok.json", 200, 12.0)
        record_backend_call(
            "POST", "https://registry.test/people", "ReadTimeout", 20000.0
        )
        raise HTTPException(400, "Failed to retrieve ACCESS ID for jdoe@example.com")

    client = TestClient(app, client=("144.80.66.87", 50000))
    assert client.get("/fail").status_code == 400

    (report,) = reports
    assert report.startswith("```\n") and report.endswith("\n```")
    lines = report.strip("`\n").split("\n")
    assert lines[0].startswith("400 GET /fail · 144.*.*.87 · - · ")
    assert lines[1] == "Failed to retrieve ACCESS ID for j**e@ex******com"
    assert lines[2:] == ["-> POST registry.test/people ReadTimeout 20000.0ms"]
    assert "80.66" not in report


def test_unhandled_error_reports_the_exception(reports):
    app = scratch_app()

    @app.get("/boom")
    async def _boom():
        raise RuntimeError("kaboom")

    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/boom").status_code == 500

    (report,) = reports
    assert report.split("\n")[1].startswith("500 GET /boom")
    assert "RuntimeError: kaboom" in report
    assert "Traceback" not in report


def test_recorded_exception_is_reported_even_when_the_error_is_routine(reports):
    app = scratch_app()

    @app.get("/handled")
    async def _handled():
        try:
            raise ValueError("bad value from a@b.com")
        except ValueError:
            record_exception("Could not parse the response")
        raise ExpectedHTTPException(400, "Try again")

    assert TestClient(app).get("/handled").status_code == 400

    (report,) = reports
    assert "!! Could not parse the response" in report
    assert "ValueError: bad value from *@b***m" in report
    assert "Traceback" not in report


def test_long_detail_is_truncated(reports):
    app = scratch_app()

    @app.get("/long")
    async def _long():
        raise HTTPException(502, "x" * 5000)

    TestClient(app).get("/long")

    (report,) = reports
    assert len(report) < 1000


# --- Which errors are reported ----------------------------------------------
def test_successful_requests_are_not_reported(client, reports):
    assert client.get(f"{BASE}/auth/info").status_code == 200
    assert reports == []


def test_unexpected_http_error_is_reported(reports):
    app = scratch_app()

    @app.get("/fail")
    async def _fail():
        raise HTTPException(400, "Failed to retrieve CoPerson ID")

    TestClient(app).get("/fail")
    assert len(reports) == 1


def test_expected_http_error_is_not_reported(reports):
    app = scratch_app()

    @app.get("/routine")
    async def _routine():
        raise ExpectedHTTPException(403, "Invalid verification code")

    response = TestClient(app).get("/routine")
    assert response.status_code == 403
    assert response.json() == {"detail": "Invalid verification code"}
    assert reports == []


def test_missing_token_is_not_reported(client, reports):
    assert client.get(f"{BASE}/account/user/ssh-key").status_code == 403
    assert reports == []


def test_invalid_otp_format_is_not_reported(client, reports):
    response = client.post(
        f"{BASE}/auth/verify-otp", json={"email": "a@example.org", "otp": "12"}
    )
    assert response.status_code == 400
    assert reports == []


@pytest.mark.parametrize(
    "method,path,status_code",
    [
        ("GET", f"{BASE}/.env", 404),
        ("GET", "/wp-login.php", 404),
        ("DELETE", f"{BASE}/auth/info", 405),
    ],
)
def test_unknown_paths_and_methods_are_not_reported(
    client, reports, method, path, status_code
):
    assert client.request(method, path).status_code == status_code
    assert reports == []


def test_validation_error_outside_the_forms_is_not_reported(client, reports):
    assert client.post(f"{BASE}/auth/verify-otp", json={}).status_code == 422
    assert reports == []


def test_validation_error_on_account_creation_is_reported(client, reports, auth_header):
    response = client.post(
        f"{BASE}/account",
        json={"firstName": "Ada"},
        headers=auth_header(token_type="otp", sub="ada@example.org", username=None),
    )
    assert response.status_code == 422

    (report,) = reports
    assert "422 POST /api/v1/account" in report
    assert "body." in report  # names the missing fields
    assert "Ada" not in report  # but not the values sent


def test_admin_looking_up_missing_account_is_not_reported(
    client, reports, auth_header, mock_comanage, mock_identity
):
    mock_comanage.get_user_info = AsyncMock(
        side_effect=HTTPException(404, "Could not find a user with ACCESS ID: ghost")
    )
    mock_identity.get_account = AsyncMock(return_value={})

    response = client.get(
        f"{BASE}/account/ghost", headers=auth_header(username="adminuser")
    )
    assert response.status_code == 404
    assert reports == []


def test_users_own_missing_account_is_reported(
    client, reports, auth_header, mock_comanage, mock_identity
):
    mock_comanage.get_user_info = AsyncMock(
        side_effect=HTTPException(404, "Could not find a user with ACCESS ID: ghost")
    )
    mock_identity.get_account = AsyncMock(return_value={})

    response = client.get(
        f"{BASE}/account/ghost", headers=auth_header(username="ghost")
    )
    assert response.status_code == 404
    assert len(reports) == 1


def test_rate_limited_request_is_not_reported(client, reports, temp_db):
    main.limiter.enabled = True
    main.limiter.reset()
    try:
        statuses = [
            client.post(
                f"{BASE}/auth/send-otp", json={"email": "ada@example.org"}
            ).status_code
            for _ in range(5)
        ]
    finally:
        main.limiter.reset()

    assert statuses == [200, 200, 200, 200, 429]
    assert reports == []
