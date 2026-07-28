"""API tests for password endpoints: /account/{u}/password and /auth/password-reset."""

from unittest.mock import AsyncMock

import main

BASE = "/api/v1"
GOOD_PASSWORD = "GoodPassword1!"
# 12+ chars but only one character category -> fails the policy (not pydantic length).
WEAK_PASSWORD = "aaaaaaaaaaaa"


# --- POST /account/{username}/password --------------------------------------
def test_update_password_success(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.get_co_person_id_for_accessid = AsyncMock(return_value="500")
    mock_comanage.update_password_for_user = AsyncMock(return_value={})

    resp = client.post(f"{BASE}/account/ada/password", json={"password": GOOD_PASSWORD})
    assert resp.status_code == 200
    assert resp.json() == {"success": True}


def test_update_password_policy_violation(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")

    resp = client.post(f"{BASE}/account/ada/password", json={"password": WEAK_PASSWORD})
    assert resp.status_code == 400


def test_update_password_too_short_is_422(client, override_auth):
    override_auth(main.require_own_username_access, uid="ada")
    # < 12 chars is rejected by pydantic validation before the handler runs.
    resp = client.post(f"{BASE}/account/ada/password", json={"password": "short"})
    assert resp.status_code == 422


def test_update_password_user_not_found(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.get_co_person_id_for_accessid = AsyncMock(return_value=None)

    resp = client.post(f"{BASE}/account/ada/password", json={"password": GOOD_PASSWORD})
    assert resp.status_code == 404


# --- POST /auth/password-reset ----------------------------------------------
def test_password_reset_success(client, override_auth, mock_comanage):
    override_auth(main.require_otp, typ="otp", sub="ada@example.org", uid=None)
    mock_comanage.get_co_person_id_for_email = AsyncMock(return_value="500")
    mock_comanage.update_password_for_user = AsyncMock(return_value={})

    resp = client.post(f"{BASE}/auth/password-reset", json={"password": GOOD_PASSWORD})
    assert resp.status_code == 200
    assert resp.json() == {"success": True}


def test_password_reset_policy_violation(client, override_auth, mock_comanage):
    override_auth(main.require_otp, typ="otp", sub="ada@example.org", uid=None)

    resp = client.post(f"{BASE}/auth/password-reset", json={"password": WEAK_PASSWORD})
    assert resp.status_code == 400


def test_password_reset_no_account_for_email(client, override_auth, mock_comanage):
    override_auth(main.require_otp, typ="otp", sub="ada@example.org", uid=None)
    mock_comanage.get_co_person_id_for_email = AsyncMock(return_value=None)

    resp = client.post(f"{BASE}/auth/password-reset", json={"password": GOOD_PASSWORD})
    assert resp.status_code == 404
