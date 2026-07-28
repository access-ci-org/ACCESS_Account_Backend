"""Tests for CoManageRegistryClient (services/comanage_registry_client.py).

Uses respx to stub the Registry/Core-API responses. Base URL comes from the test
env (COMANAGE_REGISTRY_BASE_URL=https://comanage.test), COID=2.
"""

import httpx
import pytest
from fastapi import HTTPException

from services.comanage_registry_client import CoManageRegistryClient, CoManageUser

REGISTRY = "https://comanage.test/registry"


@pytest.fixture
def comanage():
    # propagate_errors=True mirrors the app singleton.
    return CoManageRegistryClient(propagate_errors=True)


# --- get_co_person_id_for_email --------------------------------------------
async def test_get_co_person_id_found(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": [{"Id": 123}]}
    )
    assert await comanage.get_co_person_id_for_email("ada@example.org") == "123"


async def test_get_co_person_id_none_when_empty(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(200, json={"CoPeople": []})
    assert await comanage.get_co_person_id_for_email("ada@example.org") is None


async def test_basic_auth_is_sent(comanage, respx_mock):
    route = respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": []}
    )
    await comanage.get_co_person_id_for_email("ada@example.org")
    assert route.calls.last.request.headers["authorization"].startswith("Basic ")


# --- get_access_id_for_email (chained lookups) ------------------------------
async def test_get_access_id_for_email(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": [{"Id": 123}]}
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
    payload = {
        "Identifier": [{"type": "accessid", "identifier": "ada"}],
        "Name": [{"primary_name": True, "given": "Ada", "family": "Lovelace",
                  "meta": {"deleted": False}}],
        "EmailAddress": [{"type": "official", "mail": "ada@example.org",
                          "meta": {"deleted": False}}],
    }
    respx_mock.get(f"{REGISTRY}/api/co/2/core/v1/people/ada").respond(200, json=payload)

    user = await comanage.get_user_info("ada")
    assert isinstance(user, CoManageUser)
    assert user.get_username() == "ada"
    assert user.get_primary_email() == "ada@example.org"


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
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": [{"Id": 123}]}
    )
    with pytest.raises(HTTPException) as exc:
        await comanage.add_ssh_key_for_user("ada", "not-a-real-type AAAAB3Nz")
    assert exc.value.status_code == 400


async def test_add_ssh_key_rejects_empty_key(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": [{"Id": 123}]}
    )
    with pytest.raises(HTTPException) as exc:
        await comanage.add_ssh_key_for_user("ada", "   ")
    assert exc.value.status_code == 400


async def test_delete_ssh_key_404_when_not_owned(comanage, respx_mock):
    respx_mock.get(f"{REGISTRY}/co_people.json").respond(
        200, json={"CoPeople": [{"Id": 123}]}
    )
    respx_mock.get(f"{REGISTRY}/ssh_key_authenticator/ssh_keys.json").respond(
        200, json={"SshKeys": [{"Id": 999}]}
    )
    with pytest.raises(HTTPException) as exc:
        await comanage.delete_ssh_key_for_user("ada", 111)
    assert exc.value.status_code == 404
