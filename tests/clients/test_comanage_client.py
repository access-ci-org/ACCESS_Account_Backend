"""Tests for CoManageRegistryClient (services/comanage_registry_client.py).

Uses respx to stub the Registry/Core-API responses. Base URL comes from the test
env (COMANAGE_REGISTRY_BASE_URL=https://comanage.test), COID=2.
"""

import pytest
from fastapi import HTTPException

from services.comanage_registry_client import CoManageRegistryClient, CoManageUser

REGISTRY = "https://comanage.test/registry"


@pytest.fixture
def comanage():
    # propagate_errors=True mirrors the app singleton.
    return CoManageRegistryClient(propagate_errors=True)


def core_person(co_person_id=123, co_person_status="A"):
    """A minimal Core API person payload for ACCESS ID "ada"."""
    return {
        "CoPerson": {
            "status": co_person_status,
            "meta": {"id": co_person_id},
        },
        "Identifier": [{"type": "accessid", "identifier": "ada"}],
        "Name": [{"primary_name": True, "given": "Ada", "family": "Lovelace",
                  "meta": {"deleted": False}}],
        "EmailAddress": [{"type": "official", "mail": "ada@example.org",
                          "meta": {"deleted": False}}],
    }


# --- get_co_person_id_for_email --------------------------------------------
async def test_get_co_person_id_found(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": [{"Id": 123, "Status": "Active"}]}
    )
    assert await comanage.get_co_person_id_for_email("ada@example.org") == "123"


async def test_get_co_person_id_none_when_empty(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(200, json={"CoPeople": []})
    assert await comanage.get_co_person_id_for_email("ada@example.org") is None


async def test_get_co_person_id_skips_inactive(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200,
        json={"CoPeople": [
            {"Id": 1, "Status": "Deleted"},
            {"Id": 2, "Status": "Active"},
        ]},
    )
    assert await comanage.get_co_person_id_for_email("ada@example.org") == "2"


async def test_get_co_person_id_none_when_no_active(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": [{"Id": 1, "Status": "Deleted"}]}
    )
    assert await comanage.get_co_person_id_for_email("ada@example.org") is None


# --- get_co_person_id_for_accessid ------------------------------------------
async def test_get_co_person_id_for_accessid_uses_core_api(comanage, respx_mock):
    # The Core API matches the ACCESS ID exactly, unlike search.identifier.
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(
        200, json=core_person(co_person_id=2)
    )
    assert await comanage.get_co_person_id_for_accessid("ada") == "2"


async def test_get_co_person_id_for_accessid_rejects_inactive(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(
        200, json=core_person(co_person_id=2, co_person_status="D")
    )
    with pytest.raises(HTTPException) as exc:
        await comanage.get_co_person_id_for_accessid("ada")
    assert exc.value.status_code == 400


async def test_get_co_person_id_for_accessid_404_when_no_user(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/nobody").respond(200, json={})
    with pytest.raises(HTTPException) as exc:
        await comanage.get_co_person_id_for_accessid("nobody")
    assert exc.value.status_code == 404


async def test_basic_auth_is_sent(comanage, respx_mock):
    route = respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": []}
    )
    await comanage.get_co_person_id_for_email("ada@example.org")
    assert route.calls.last.request.headers["authorization"].startswith("Basic ")


# --- get_access_id_for_email (chained lookups) ------------------------------
async def test_get_access_id_for_email(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": [{"Id": 123, "Status": "Active"}]}
    )
    respx_mock.get(f"{REGISTRY}/identifiers.json").respond(
        200, json={"Identifiers": [{"Type": "accessid", "Identifier": "ada"}]}
    )
    assert await comanage.get_access_id_for_email("ada@example.org") == "ada"


async def test_get_access_id_none_when_no_co_person(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(200, json={"CoPeople": []})
    assert await comanage.get_access_id_for_email("ada@example.org") is None


# --- get_user_info ----------------------------------------------------------
async def test_get_user_info_returns_comanage_user(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(
        200, json=core_person()
    )

    user = await comanage.get_user_info("ada")
    assert isinstance(user, CoManageUser)
    assert user.get_username() == "ada"
    assert user.get_primary_email() == "ada@example.org"


async def test_get_user_info_404_when_empty(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(200, json={})
    with pytest.raises(HTTPException) as exc:
        await comanage.get_user_info("ada")
    assert exc.value.status_code == 404


async def test_get_user_info_400_when_inactive(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(
        200, json=core_person(co_person_status="D")
    )
    with pytest.raises(HTTPException) as exc:
        await comanage.get_user_info("ada")
    assert exc.value.status_code == 400


async def test_get_user_info_non_dict_raises_502(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(200, json=[1, 2])
    with pytest.raises(HTTPException) as exc:
        await comanage.get_user_info("ada")
    assert exc.value.status_code == 502


# --- get_active_tandc -------------------------------------------------------
async def test_get_active_tandc_returns_active(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_terms_and_conditions.json").respond(
        200,
        json={"CoTermsAndConditions": [
            {"Id": 1, "Status": "Retired"},
            {"Id": 2, "Status": "Active"},
        ]},
    )
    tandc = await comanage.get_active_tandc()
    assert tandc["Id"] == 2


async def test_get_active_tandc_none_when_no_active(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_terms_and_conditions.json").respond(
        200, json={"CoTermsAndConditions": [{"Id": 1, "Status": "Retired"}]}
    )
    assert await comanage.get_active_tandc() is None


# --- error propagation through _request -------------------------------------
async def test_upstream_500_becomes_httpexception(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(500, text="boom")
    with pytest.raises(HTTPException) as exc:
        await comanage.get_co_person_id_for_email("ada@example.org")
    assert exc.value.status_code == 500


# --- add_ssh_key_for_user validation ----------------------------------------
async def test_add_ssh_key_rejects_invalid_type(comanage, respx_mock):
    # CoPerson lookup succeeds, then key-type validation fails locally.
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(
        200, json=core_person()
    )
    with pytest.raises(HTTPException) as exc:
        await comanage.add_ssh_key_for_user("ada", "not-a-real-type AAAAB3Nz")
    assert exc.value.status_code == 400


async def test_add_ssh_key_rejects_empty_key(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(
        200, json=core_person()
    )
    with pytest.raises(HTTPException) as exc:
        await comanage.add_ssh_key_for_user("ada", "   ")
    assert exc.value.status_code == 400


async def test_delete_ssh_key_404_when_not_owned(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(
        200, json=core_person()
    )
    respx_mock.get(f"{REGISTRY}/ssh_key_authenticator/ssh_keys.json").respond(
        200, json={"SshKeys": [{"Id": 999}]}
    )
    with pytest.raises(HTTPException) as exc:
        await comanage.delete_ssh_key_for_user("ada", 111)
    assert exc.value.status_code == 404
