"""API tests for the /auth/* routes.

External services are mocked via the `mock_comanage` / `mock_identity` singleton
fixtures; auth gates are bypassed with `override_auth` (the gates themselves are
proven with real tokens in tests/api/test_auth_gates.py).
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest
from fastapi import HTTPException

import main
from config import CILOGON_LINK_CLIENT_ID, CILOGON_LOGIN_CLIENT_ID, JWT_SECRET_KEY, \
    JWT_ALGORITHM, JWT_AUDIENCE, JWT_ISSUER

BASE = "/api/v1"


# --- POST /auth/send-otp ----------------------------------------------------
def test_send_otp_success(client, temp_db):
    # DEBUG=true in the test env -> OTP is logged, SES is never called. temp_db
    # gives store_otp a real (isolated) SQLite table to write to.
    resp = client.post(f"{BASE}/auth/send-otp", json={"email": "ada@example.org"})
    assert resp.status_code == 200
    assert resp.json() == {"success": True}


def test_send_otp_rejects_email_without_at(client, temp_db):
    resp = client.post(f"{BASE}/auth/send-otp", json={"email": "not-an-email"})
    assert resp.status_code == 400


# --- POST /auth/verify-otp --------------------------------------------------
def test_verify_otp_success_returns_otp_jwt(client, monkeypatch, mock_comanage):
    monkeypatch.setattr(main, "verify_stored_otp", MagicMock(return_value=None))
    mock_comanage.get_access_id_for_email = AsyncMock(return_value="ada")

    resp = client.post(
        f"{BASE}/auth/verify-otp", json={"email": "ada@example.org", "otp": "ABC234"}
    )
    assert resp.status_code == 200
    token = resp.json()["jwt"]
    payload = jwt.decode(
        token, str(JWT_SECRET_KEY), algorithms=[JWT_ALGORITHM],
        audience=JWT_AUDIENCE, issuer=JWT_ISSUER,
    )
    assert payload["typ"] == "otp"
    assert payload["uid"] == "ada"


def test_verify_otp_invalid_email(client):
    resp = client.post(
        f"{BASE}/auth/verify-otp", json={"email": "bad", "otp": "ABC234"}
    )
    assert resp.status_code == 400


def test_verify_otp_invalid_format(client):
    resp = client.post(
        f"{BASE}/auth/verify-otp", json={"email": "ada@example.org", "otp": "SHORT"}
    )
    assert resp.status_code == 400


def test_verify_otp_wrong_code_returns_403(client, monkeypatch):
    monkeypatch.setattr(
        main,
        "verify_stored_otp",
        MagicMock(side_effect=HTTPException(403, "Invalid verification code")),
    )
    resp = client.post(
        f"{BASE}/auth/verify-otp", json={"email": "ada@example.org", "otp": "ABC234"}
    )
    assert resp.status_code == 403


# --- GET /auth/info ---------------------------------------------------------
def test_get_oidc_info(client):
    resp = client.get(f"{BASE}/auth/info")
    assert resp.status_code == 200
    body = resp.json()
    assert body["clientIds"]["link"] == CILOGON_LINK_CLIENT_ID
    assert body["clientIds"]["login"] == CILOGON_LOGIN_CLIENT_ID


# --- POST /auth/oauth2/token ------------------------------------------------
def _token_request(client_id):
    return {
        "clientId": client_id,
        "grantType": "authorization_code",
        "redirectUri": "https://app.example.org/callback",
        "code": "auth-code",
    }


def test_oidc_token_link_client(client, monkeypatch):
    fake = SimpleNamespace(
        get_token=AsyncMock(
            return_value={"access_token": "at", "refresh_token": "rt"}
        ),
        get_user_info=AsyncMock(),
    )
    monkeypatch.setattr(main, "CILogonClient", lambda **kw: fake)

    resp = client.post(f"{BASE}/auth/oauth2/token", json=_token_request(CILOGON_LINK_CLIENT_ID))
    assert resp.status_code == 200
    assert resp.json()["accessToken"] == "at"
    # Non-login client: user info is not fetched.
    fake.get_user_info.assert_not_awaited()


def test_oidc_token_login_client_sets_is_admin(client, monkeypatch):
    fake = SimpleNamespace(
        get_token=AsyncMock(
            return_value={"access_token": "at", "refresh_token": "rt"}
        ),
        get_user_info=AsyncMock(return_value={"sub": "adminuser@access-ci.org"}),
    )
    monkeypatch.setattr(main, "CILogonClient", lambda **kw: fake)

    resp = client.post(f"{BASE}/auth/oauth2/token", json=_token_request(CILOGON_LOGIN_CLIENT_ID))
    assert resp.status_code == 200
    # ADMIN_USERNAMES=adminuser in the test env.
    assert resp.json()["isAdmin"] is True
