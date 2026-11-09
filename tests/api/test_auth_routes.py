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
from services.email_service import get_email_from_body, is_valid_email
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


# Shapes seen probing the API: lists, display names, comments, quoted local parts.
MALFORMED_EMAILS = [
    "a@example.com,b@example.edu",
    "a@example.com, b@example.edu",
    "a@example.com; b@example.edu",
    "a@example.com (b@example.edu)",
    "b@example.edu <a@example.com>",
    '"a@example.com"@example.edu',
    "a@b@example.com",
    "a@localhost",
    "a..b@example.com",
    "a@-example.com",
]


@pytest.mark.parametrize("email", MALFORMED_EMAILS)
def test_send_otp_rejects_malformed_email(client, temp_db, monkeypatch, email):
    send = MagicMock()
    monkeypatch.setattr(main, "send_verification_email", send)
    monkeypatch.setattr(main, "DEBUG", False)

    resp = client.post(f"{BASE}/auth/send-otp", json={"email": email})
    assert resp.status_code == 400
    send.assert_not_called()


@pytest.mark.parametrize(
    "email", ["ada@example.org", "Ada.Lovelace+otp@Mail.Example.co.uk", "a_b-c@xn--bcher-kva.ch"]
)
def test_is_valid_email_accepts_plain_addresses(email):
    assert is_valid_email(email.lower())


def test_email_rate_limit_key_is_memcache_safe():
    # memcached keys can't contain whitespace or exceed 250 bytes.
    request = SimpleNamespace(_json={"email": "a@example.com, b@example.edu" + "x" * 300})
    key = get_email_from_body(request)  # pyright: ignore[reportArgumentType]
    assert len(key) == 64 and key.isalnum()


def test_email_rate_limit_key_ignores_case_and_whitespace():
    def key(email):
        return get_email_from_body(SimpleNamespace(_json={"email": email}))  # pyright: ignore[reportArgumentType]

    assert key(" Ada@Example.org ") == key("ada@example.org")
    assert key(None) == key("")


def test_send_otp_ses_invalid_parameter_value_returns_400(client, temp_db, monkeypatch):
    from botocore.exceptions import ClientError

    error = ClientError(
        {"Error": {"Code": "InvalidParameterValue", "Message": "Illegal address"}},
        "SendEmail",
    )
    monkeypatch.setattr(main, "send_verification_email", MagicMock(side_effect=error))
    monkeypatch.setattr(main, "DEBUG", False)

    resp = client.post(f"{BASE}/auth/send-otp", json={"email": "ada@example.org"})
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


@pytest.mark.parametrize("email", MALFORMED_EMAILS)
def test_verify_otp_rejects_malformed_email(client, monkeypatch, email):
    verify = MagicMock(return_value=None)
    monkeypatch.setattr(main, "verify_stored_otp", verify)

    resp = client.post(f"{BASE}/auth/verify-otp", json={"email": email, "otp": "ABC234"})
    assert resp.status_code == 400
    verify.assert_not_called()


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
