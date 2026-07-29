"""Tests for IdentityServiceClient (XRAS) — services/identity_client.py.

Base URL from test env: XRAS_IDENTITY_SERVICE_BASE_URL=https://xras.test.
The `_clear_identity_cache` autouse fixture (conftest) resets the class-level
choice-list TTLCache around every test, so cache assertions are deterministic.
"""

import pytest
from fastapi import HTTPException

from services.identity_client import IdentityServiceClient

XRAS = "https://xras.test"


@pytest.fixture
def identity():
    return IdentityServiceClient(propagate_errors=True)


# --- get_countries: sorting + auth headers ----------------------------------
async def test_get_countries_sorts_united_states_first(identity, respx_mock):
    respx_mock.get(f"{XRAS}/profiles/v1/countries").respond(
        200,
        json=[
            {"countryName": "Canada"},
            {"countryName": "United States"},
            {"countryName": "Albania"},
        ],
    )
    countries = await identity.get_countries()
    assert countries[0]["countryName"] == "United States"


async def test_sends_xras_auth_headers(identity, respx_mock):
    route = respx_mock.get(f"{XRAS}/profiles/v1/countries").respond(200, json=[])
    await identity.get_countries()
    headers = route.calls.last.request.headers
    assert headers["xa-requester"] == "xras-requester"
    assert headers["xa-api-key"] == "xras-api-key"


# --- caching ----------------------------------------------------------------
async def test_choice_lists_are_cached(identity, respx_mock):
    route = respx_mock.get(f"{XRAS}/profiles/v1/countries").respond(
        200, json=[{"countryName": "United States"}]
    )
    await identity.get_countries()
    await identity.get_countries()
    # Second call served from the TTLCache -> only one HTTP request made.
    assert route.call_count == 1


# --- _request empty-response guard ------------------------------------------
async def test_empty_response_raises_502(identity, respx_mock):
    respx_mock.get(f"{XRAS}/profiles/v1/degrees").respond(204)
    with pytest.raises(HTTPException) as exc:
        await identity.get_degrees()
    assert exc.value.status_code == 502


async def test_update_person_tolerates_204_empty_response(identity, respx_mock):
    respx_mock.patch(f"{XRAS}/profiles/v1/people/ada").respond(204)
    result = await identity.update_person("ada", first_name="Ada")
    assert result is None


# --- get_account _expect guard ----------------------------------------------
async def test_get_account_returns_dict(identity, respx_mock):
    respx_mock.get(f"{XRAS}/profiles/v1/people/ada").respond(
        200, json={"firstName": "Ada"}
    )
    assert await identity.get_account("ada") == {"firstName": "Ada"}


async def test_get_account_non_dict_raises_502(identity, respx_mock):
    respx_mock.get(f"{XRAS}/profiles/v1/people/ada").respond(200, json=[1, 2])
    with pytest.raises(HTTPException) as exc:
        await identity.get_account("ada")
    assert exc.value.status_code == 502


# --- check_valid_academic_status_id -----------------------------------------
STATUSES = [
    {"nsfStatusCodeId": 1, "nsfStatusCode": "GD"},
    {"nsfStatusCodeId": 2, "nsfStatusCode": "N"},  # invalid per INVALID_ACADEMIC_STATUS_CODES
]


async def test_valid_academic_status_passes(identity, respx_mock):
    respx_mock.get(f"{XRAS}/profiles/v1/nsf_status_codes").respond(200, json=STATUSES)
    # Returns None (no exception) for a valid, allowed status id.
    assert await identity.check_valid_academic_status_id(1) is None


async def test_invalid_academic_status_code_rejected(identity, respx_mock):
    respx_mock.get(f"{XRAS}/profiles/v1/nsf_status_codes").respond(200, json=STATUSES)
    with pytest.raises(HTTPException) as exc:
        await identity.check_valid_academic_status_id(2)
    assert exc.value.status_code == 400


async def test_unknown_academic_status_id_rejected(identity, respx_mock):
    respx_mock.get(f"{XRAS}/profiles/v1/nsf_status_codes").respond(200, json=STATUSES)
    with pytest.raises(HTTPException) as exc:
        await identity.check_valid_academic_status_id(999)
    assert exc.value.status_code == 400


async def test_none_academic_status_id_is_noop(identity):
    # No id -> returns immediately, makes no HTTP call (no respx route needed).
    assert await identity.check_valid_academic_status_id(None) is None


# --- check_organization_matches_domain --------------------------------------
async def test_org_matches_domain_returns_name(identity, respx_mock):
    respx_mock.get(f"{XRAS}/profiles/v1/organizations").respond(
        200,
        json=[
            {
                "organization_id": 7,
                "organization_name": "Example University",
                "is_active": True,
                "is_eligible": True,
            }
        ],
    )
    name = await identity.check_organization_matches_domain(7, "example.org")
    assert name == "Example University"


async def test_org_does_not_match_domain_raises_400(identity, respx_mock):
    respx_mock.get(f"{XRAS}/profiles/v1/organizations").respond(200, json=[])
    respx_mock.get(f"{XRAS}/profiles/v1/organizations/7").respond(
        200, json={"organization_name": "Example University"}
    )
    with pytest.raises(HTTPException) as exc:
        await identity.check_organization_matches_domain(7, "example.org")
    assert exc.value.status_code == 400
