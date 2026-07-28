"""API tests for /account create / get / update."""

from unittest.mock import AsyncMock

from fastapi import HTTPException

import main
from auth import create_access_token
from factories import make_comanage_user

BASE = "/api/v1"

CREATE_BODY = {
    "firstName": "Ada",
    "lastName": "Lovelace",
    "organizationId": 7,
    "academicStatusId": 1,
    "residenceCountryId": 2,
    "citizenshipCountryIds": [2],
    "department": "Computing",
}


def _mock_create_happy(mock_comanage, mock_identity):
    mock_comanage.check_account_does_not_exist = AsyncMock(return_value=None)
    mock_comanage.check_active_tandc_exists = AsyncMock(return_value={"Id": 42})
    mock_comanage.create_new_user = AsyncMock(
        return_value=[{"type": "accessid", "identifier": "ada123"}]
    )
    mock_comanage.get_co_person_id_for_email = AsyncMock(return_value="500")
    mock_comanage.create_linked_identity = AsyncMock(return_value=None)
    mock_comanage.create_new_tandc_agreement = AsyncMock(return_value={})
    mock_identity.check_organization_matches_domain = AsyncMock(
        return_value="Example University"
    )
    mock_identity.check_valid_academic_status_id = AsyncMock(return_value=None)
    mock_identity.create_person = AsyncMock(return_value={})


# --- POST /account ----------------------------------------------------------
def test_create_account_success(client, override_auth, mock_comanage, mock_identity):
    override_auth(main.require_otp, typ="otp", sub="ada@example.org", uid=None)
    _mock_create_happy(mock_comanage, mock_identity)

    resp = client.post(f"{BASE}/account", json=CREATE_BODY)
    assert resp.status_code == 200
    assert resp.json() == {"success": True, "access_id": "ada123"}


def test_create_account_bad_accessid_response(
    client, override_auth, mock_comanage, mock_identity
):
    override_auth(main.require_otp, typ="otp", sub="ada@example.org", uid=None)
    _mock_create_happy(mock_comanage, mock_identity)
    # create_new_user returns an unexpected shape -> 400 "Failed to retrieve ACCESS ID"
    mock_comanage.create_new_user = AsyncMock(return_value=[{"type": "other"}])

    resp = client.post(f"{BASE}/account", json=CREATE_BODY)
    assert resp.status_code == 400


def test_create_account_org_domain_mismatch(
    client, override_auth, mock_comanage, mock_identity
):
    override_auth(main.require_otp, typ="otp", sub="ada@example.org", uid=None)
    _mock_create_happy(mock_comanage, mock_identity)
    mock_identity.check_organization_matches_domain = AsyncMock(
        side_effect=HTTPException(400, "Domain does not match")
    )

    resp = client.post(f"{BASE}/account", json=CREATE_BODY)
    assert resp.status_code == 400


# --- GET /account/{username} ------------------------------------------------
IDENTITY_PERSON = {
    "organizationId": 7,
    "nsfStatusCodeId": 1,
    "countryId": 2,
    "citizenships": [{"countryId": 2}, {"countryId": 3}],
    "academicDegrees": [{"degreeId": 9, "degreeField": "CS"}],
    "department": "Computing",
}


def test_get_account_merges_comanage_and_identity(
    client, override_auth, mock_comanage, mock_identity
):
    override_auth(main.require_username_access, uid="ada")
    mock_comanage.get_user_info = AsyncMock(
        return_value=make_comanage_user(
            access_id="ada", given="Ada", family="Lovelace",
            email="ada@example.org", timezone="America/New_York",
        )
    )
    mock_identity.get_account = AsyncMock(return_value=IDENTITY_PERSON)

    resp = client.get(f"{BASE}/account/ada")
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "ada"
    assert body["firstName"] == "Ada"
    assert body["lastName"] == "Lovelace"
    assert body["email"] == "ada@example.org"
    assert body["timeZone"] == "America/New_York"
    assert body["organizationId"] == 7
    assert body["citizenshipCountryIds"] == [2, 3]
    assert body["degrees"] == [{"degreeId": 9, "degreeField": "CS"}]


def test_get_account_404_without_primary_name(
    client, override_auth, mock_comanage, mock_identity
):
    override_auth(main.require_username_access, uid="ada")
    mock_comanage.get_user_info = AsyncMock(
        return_value=make_comanage_user(access_id="ada", names=[])
    )
    mock_identity.get_account = AsyncMock(return_value=IDENTITY_PERSON)

    resp = client.get(f"{BASE}/account/ada")
    assert resp.status_code == 404


# --- POST /account/{username} (update) --------------------------------------
def _mock_update_happy(mock_comanage, mock_identity, email="ada@example.org"):
    mock_comanage.get_user_info = AsyncMock(
        return_value=make_comanage_user(access_id="ada", email=email)
    )
    mock_identity.get_account = AsyncMock(return_value={"organizationId": 7})
    mock_comanage.update_user = AsyncMock(return_value={})
    mock_identity.check_organization_matches_domain = AsyncMock(
        return_value="Example University"
    )
    mock_identity.check_valid_academic_status_id = AsyncMock(return_value=None)
    mock_identity.update_person = AsyncMock(return_value={})


def test_update_account_no_email_change(
    client, override_auth, mock_comanage, mock_identity
):
    override_auth(main.require_username_access, uid="ada")
    _mock_update_happy(mock_comanage, mock_identity)

    resp = client.post(f"{BASE}/account/ada", json={"firstName": "Adele"})
    assert resp.status_code == 200
    assert resp.json() == {"success": True}


def test_update_account_email_change_requires_otp_token(
    client, override_auth, mock_comanage, mock_identity
):
    override_auth(main.require_username_access, uid="ada")
    _mock_update_happy(mock_comanage, mock_identity)

    # New email but no emailOtpToken -> 400.
    resp = client.post(f"{BASE}/account/ada", json={"email": "new@example.org"})
    assert resp.status_code == 400


def test_update_account_email_change_with_valid_token(
    client, override_auth, mock_comanage, mock_identity
):
    override_auth(main.require_username_access, uid="ada")
    _mock_update_happy(mock_comanage, mock_identity)
    email_token = create_access_token(sub="new@example.org", token_type="otp")

    resp = client.post(
        f"{BASE}/account/ada",
        json={"email": "new@example.org", "emailOtpToken": email_token},
    )
    assert resp.status_code == 200
