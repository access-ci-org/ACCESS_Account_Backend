"""Auth-gate tests using REAL JWTs (auth.create_access_token) rather than
dependency overrides. These prove the gates themselves — token presence, type,
and username/ownership checks — end to end through require_auth.

Only local 3-part JWTs are exercised (the CILogon opaque-token branch of
require_auth makes a network call and is covered indirectly in the client tests).
"""

from unittest.mock import AsyncMock

import pytest

import main
from factories import make_comanage_user

BASE = "/api/v1"
GOOD_PASSWORD = "GoodPassword1!"


@pytest.fixture
def account_readable(mock_comanage, mock_identity):
    """Make GET /account/{u} succeed once the gate is passed."""
    mock_comanage.get_user_info = AsyncMock(
        return_value=make_comanage_user(access_id="ada", email="ada@example.org")
    )
    mock_identity.get_account = AsyncMock(return_value={"organizationId": 7})


@pytest.fixture
def password_updatable(mock_comanage):
    """Make POST /account/{u}/password succeed once the gate is passed."""
    mock_comanage.get_co_person_id_for_accessid = AsyncMock(return_value="500")
    mock_comanage.update_password_for_user = AsyncMock(return_value={})


# --- Presence / validity of the bearer token --------------------------------
def test_missing_bearer_is_403(client):
    assert client.get(f"{BASE}/account/ada").status_code == 403


def test_malformed_jwt_is_403(client):
    resp = client.get(
        f"{BASE}/account/ada", headers={"Authorization": "Bearer a.b.c"}
    )
    assert resp.status_code == 403


# --- require_otp (POST /auth/password-reset) ---------------------------------
def test_require_otp_accepts_otp_token(client, auth_header, mock_comanage):
    mock_comanage.get_co_person_id_for_email = AsyncMock(return_value="500")
    mock_comanage.update_password_for_user = AsyncMock(return_value={})
    resp = client.post(
        f"{BASE}/auth/password-reset",
        json={"password": GOOD_PASSWORD},
        headers=auth_header(token_type="otp", sub="ada@example.org", username=None),
    )
    assert resp.status_code == 200


def test_require_otp_rejects_login_token(client, auth_header):
    resp = client.post(
        f"{BASE}/auth/password-reset",
        json={"password": GOOD_PASSWORD},
        headers=auth_header(token_type="login", sub="ada", username="ada"),
    )
    assert resp.status_code == 403


# --- require_login (GET /account/{u} via require_username_access) ------------
def test_require_login_rejects_otp_token(client, auth_header, account_readable):
    resp = client.get(
        f"{BASE}/account/ada",
        headers=auth_header(token_type="otp", sub="ada@example.org", username=None),
    )
    assert resp.status_code == 403


# --- require_username_access (admin allowed) --------------------------------
def test_username_access_owner_allowed(client, auth_header, account_readable):
    resp = client.get(
        f"{BASE}/account/ada",
        headers=auth_header(token_type="login", sub="ada", username="ada"),
    )
    assert resp.status_code == 200


def test_username_access_admin_allowed(client, auth_header, account_readable):
    # ADMIN_USERNAMES=adminuser in the test env; admins may read any account.
    resp = client.get(
        f"{BASE}/account/ada",
        headers=auth_header(token_type="login", sub="adminuser", username="adminuser"),
    )
    assert resp.status_code == 200


def test_username_access_other_user_forbidden(client, auth_header, account_readable):
    resp = client.get(
        f"{BASE}/account/ada",
        headers=auth_header(token_type="login", sub="mallory", username="mallory"),
    )
    assert resp.status_code == 403


# --- require_own_username_access (admin NOT allowed) ------------------------
def test_own_access_owner_allowed(client, auth_header, password_updatable):
    resp = client.post(
        f"{BASE}/account/ada/password",
        json={"password": GOOD_PASSWORD},
        headers=auth_header(token_type="login", sub="ada", username="ada"),
    )
    assert resp.status_code == 200


def test_own_access_admin_forbidden(client, auth_header, password_updatable):
    # Even an admin cannot change another user's password.
    resp = client.post(
        f"{BASE}/account/ada/password",
        json={"password": GOOD_PASSWORD},
        headers=auth_header(token_type="login", sub="adminuser", username="adminuser"),
    )
    assert resp.status_code == 403


def test_own_access_other_user_forbidden(client, auth_header, password_updatable):
    resp = client.post(
        f"{BASE}/account/ada/password",
        json={"password": GOOD_PASSWORD},
        headers=auth_header(token_type="login", sub="mallory", username="mallory"),
    )
    assert resp.status_code == 403
