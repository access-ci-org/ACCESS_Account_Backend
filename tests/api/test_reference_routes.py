"""API tests for the reference-data routes (all gated by require_otp_or_login)."""

from unittest.mock import AsyncMock

import main
from models import IdP

BASE = "/api/v1"


def _auth(override_auth):
    override_auth(main.require_otp_or_login, typ="otp", uid=None)


# --- GET /academic-status ---------------------------------------------------
def test_academic_status_filters_invalid_codes(client, override_auth, mock_identity):
    _auth(override_auth)
    mock_identity.get_academic_statuses = AsyncMock(
        return_value=[
            {"nsfStatusCodeId": 1, "nsfStatusCodeName": "Graduate", "nsfStatusCode": "GD"},
            {"nsfStatusCodeId": 2, "nsfStatusCodeName": "None", "nsfStatusCode": "N"},
        ]
    )
    # is_valid_academic_status is a *sync* method on the real client; replace the
    # mock attribute with the real predicate so the handler's filter works.
    mock_identity.is_valid_academic_status = (
        lambda item: item.get("nsfStatusCode") not in {"N", "UK"}
    )

    resp = client.get(f"{BASE}/academic-status")
    assert resp.status_code == 200
    statuses = resp.json()["academicStatuses"]
    assert statuses == [{"academicStatusId": 1, "name": "Graduate"}]


# --- GET /country -----------------------------------------------------------
def test_country_list(client, override_auth, mock_identity):
    _auth(override_auth)
    mock_identity.get_countries = AsyncMock(
        return_value=[
            {"countryId": 1, "countryName": "United States"},
            {"countryId": 2, "countryName": "Canada"},
        ]
    )

    resp = client.get(f"{BASE}/country")
    assert resp.status_code == 200
    countries = resp.json()["countries"]
    assert countries[0] == {"countryId": 1, "name": "United States"}


# --- GET /degree ------------------------------------------------------------
def test_degree_list(client, override_auth, mock_identity):
    _auth(override_auth)
    mock_identity.get_degrees = AsyncMock(
        return_value=[{"degreeId": 9, "description": "PhD"}]
    )

    resp = client.get(f"{BASE}/degree")
    assert resp.status_code == 200
    assert resp.json()["degrees"] == [{"degreeId": 9, "name": "PhD"}]


# --- GET /domain/{domain} ---------------------------------------------------
def test_domain_info_includes_idps(client, override_auth, mock_identity, set_idp_mapping):
    _auth(override_auth)
    mock_identity.get_organizations_by_domain = AsyncMock(
        return_value=[
            {"organization_id": 7, "organization_name": "Example University",
             "ignore_idp": False}
        ]
    )
    set_idp_mapping(
        {"example.org": [IdP(display_name="Example University", entity_id="https://idp")]}
    )

    resp = client.get(f"{BASE}/domain/example.org")
    assert resp.status_code == 200
    body = resp.json()
    assert body["domain"] == "example.org"
    assert body["organizations"][0]["organizationId"] == 7
    assert body["idps"][0]["entityId"] == "https://idp"


def test_domain_info_suppresses_idps_when_ignore_idp(
    client, override_auth, mock_identity, set_idp_mapping
):
    _auth(override_auth)
    mock_identity.get_organizations_by_domain = AsyncMock(
        return_value=[
            {"organization_id": 7, "organization_name": "Example University",
             "ignore_idp": True}
        ]
    )
    set_idp_mapping(
        {"example.org": [IdP(display_name="Example University", entity_id="https://idp")]}
    )

    resp = client.get(f"{BASE}/domain/example.org")
    assert resp.status_code == 200
    assert resp.json()["idps"] == []


# --- GET /terms-and-conditions ----------------------------------------------
def test_terms_and_conditions_returns_active(client, override_auth, mock_comanage):
    _auth(override_auth)
    mock_comanage.get_active_tandc = AsyncMock(
        return_value={
            "Id": 42,
            "Description": "AUP",
            "Url": "https://access-ci.org/aup",
            "Body": "Body text",
        }
    )

    resp = client.get(f"{BASE}/terms-and-conditions")
    assert resp.status_code == 200
    assert resp.json()["id"] == 42


def test_terms_and_conditions_404_when_none(client, override_auth, mock_comanage):
    _auth(override_auth)
    mock_comanage.get_active_tandc = AsyncMock(return_value=None)

    resp = client.get(f"{BASE}/terms-and-conditions")
    assert resp.status_code == 404
