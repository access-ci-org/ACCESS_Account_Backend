"""Tests for CoManageRegistryClient (services/comanage_registry_client.py).

Uses respx to stub the Registry/Core-API responses. Base URL comes from the test
env (COMANAGE_REGISTRY_BASE_URL=https://comanage.test), COID=2.
"""

import asyncio

import httpx
import pytest
from factories import make_comanage_user
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


# --- check_cilogon_identifiers_available ------------------------------------
@pytest.fixture
def cilogon_user(monkeypatch):
    async def fake_user_info(*args):
        return {"idp_name": "Uni", "eppn": "ada@uni.edu", "sub": "http://cilogon.org/ada"}

    monkeypatch.setattr(
        "services.comanage_registry_client.get_token_user_info", fake_user_info
    )


def co_people_for(respx_mock, matches: dict[str, list[dict]]):
    """Answer co_people.json identifier searches from {identifier: CoPeople}."""

    def respond(request):
        identifier = request.url.params["search.identifier"]
        return httpx.Response(200, json={"CoPeople": matches.get(identifier, [])})

    return respx_mock.get(f"{REGISTRY}/co_people.json").mock(side_effect=respond)


def identifiers_for(respx_mock, co_person_id, identifiers: list[tuple[str, str]]):
    return respx_mock.get(
        f"{REGISTRY}/identifiers.json", params={"copersonid": co_person_id}
    ).respond(
        200,
        json={"Identifiers": [{"Type": t, "Identifier": i} for t, i in identifiers]},
    )


async def test_identifier_check_skipped_without_token(comanage, respx_mock):
    await comanage.check_cilogon_identifiers_available(None)
    assert not respx_mock.calls


async def test_identifier_check_searches_each_identifier_exactly(
    comanage, respx_mock, cilogon_user
):
    search = co_people_for(respx_mock, {})

    await comanage.check_cilogon_identifiers_available("token")

    searched = {call.request.url.params["search.identifier"] for call in search.calls}
    assert searched == {"ada@uni.edu", "http://cilogon.org/ada"}
    assert all(call.request.url.params["coid"] == "2" for call in search.calls)


async def test_identifier_check_rejects_identifier_on_another_account(
    comanage, respx_mock, cilogon_user
):
    co_people_for(respx_mock, {"ada@uni.edu": [{"Id": 77, "Status": "Active"}]})
    identifiers_for(respx_mock, 77, [("accessid", "zfang7"), ("eppn", "ada@uni.edu")])

    with pytest.raises(HTTPException) as exc:
        await comanage.check_cilogon_identifiers_available("token")
    assert exc.value.status_code == 400
    assert exc.value.detail == (
        "Your Uni login is already linked to ACCESS account zfang7. Please log in "
        "with that account, or open a help ticket if you need help."
    )


async def test_identifier_check_when_linking_suggests_duplicate_ticket(
    comanage, respx_mock, cilogon_user
):
    co_people_for(respx_mock, {"ada@uni.edu": [{"Id": 77, "Status": "Active"}]})
    identifiers_for(respx_mock, 77, [("accessid", "zfang7"), ("eppn", "ada@uni.edu")])

    with pytest.raises(HTTPException) as exc:
        await comanage.check_cilogon_identifiers_available("token", "500")
    assert exc.value.detail == (
        "Your Uni login is already linked to ACCESS account zfang7. If you believe "
        "that account is a duplicate of yours, please open a help ticket."
    )


async def test_identifier_check_ignores_same_value_of_another_type(
    comanage, respx_mock, cilogon_user
):
    # The search matches the value regardless of type; CoManage only rejects
    # an Identifier when both match.
    co_people_for(respx_mock, {"ada@uni.edu": [{"Id": 77, "Status": "Active"}]})
    identifiers_for(respx_mock, 77, [("accessid", "zfang7"), ("mail", "ada@uni.edu")])

    await comanage.check_cilogon_identifiers_available("token")


async def test_identifier_check_flags_inactive_account(
    comanage, respx_mock, cilogon_user
):
    # CoManage checks availability regardless of the CoPerson's status.
    co_people_for(
        respx_mock, {"http://cilogon.org/ada": [{"Id": 77, "Status": "Deleted"}]}
    )
    identifiers_for(
        respx_mock, 77, [("accessid", "zfang7"), ("oidcsub", "http://cilogon.org/ada")]
    )

    with pytest.raises(HTTPException) as exc:
        await comanage.check_cilogon_identifiers_available("token")
    assert exc.value.detail == (
        "Your Uni login is already linked to ACCESS account zfang7, which is not "
        "active. Please open a help ticket."
    )


async def test_identifier_check_reports_own_account(
    comanage, respx_mock, cilogon_user
):
    co_people_for(respx_mock, {"ada@uni.edu": [{"Id": 500, "Status": "Active"}]})
    identifiers_for(respx_mock, 500, [("accessid", "ada"), ("eppn", "ada@uni.edu")])

    with pytest.raises(HTTPException) as exc:
        await comanage.check_cilogon_identifiers_available("token", "500")
    assert exc.value.detail == "Your Uni login is already linked to this ACCESS account."


# --- create_new_identifier ---------------------------------------------------
async def test_create_identifier_403_becomes_400_and_is_logged(
    comanage, respx_mock, caplog
):
    respx_mock.post(f"{REGISTRY}/identifiers.json").respond(
        403, json={"error": "Identifier in use"}
    )

    with pytest.raises(HTTPException) as exc:
        await comanage.create_new_identifier(
            "ada@uni.edu", "eppn", True, linked_type="CO", linked_id="500"
        )
    # A 403 would tell the frontend its JWT is invalid.
    assert exc.value.status_code == 400
    assert "ada@uni.edu" in exc.value.detail
    # CoManage's response body is kept for debugging.
    assert any("Identifier in use" in r.getMessage() for r in caplog.records)


async def test_create_identifier_passes_other_errors_through(comanage, respx_mock):
    respx_mock.post(f"{REGISTRY}/identifiers.json").respond(500)

    with pytest.raises(HTTPException) as exc:
        await comanage.create_new_identifier(
            "ada@uni.edu", "eppn", True, linked_type="CO", linked_id="500"
        )
    assert exc.value.status_code == 500


# --- create_linked_identity -------------------------------------------------
@pytest.fixture
def record_creates(comanage, monkeypatch):
    """Stub the CoManage writes, recording their order and the most in flight."""
    calls = []
    in_flight = {"now": 0, "max": 0}

    def recorder(name, result=None):
        async def fake(*args, **kwargs):
            in_flight["now"] += 1
            in_flight["max"] = max(in_flight["max"], in_flight["now"])
            await asyncio.sleep(0.01)
            in_flight["now"] -= 1
            calls.append((name, kwargs.get("type"), kwargs.get("linked_type")))
            return result

        return fake

    async def user_info(access_id):
        return make_comanage_user(access_id=access_id)

    monkeypatch.setattr(comanage, "get_user_info", user_info)
    monkeypatch.setattr(comanage, "create_new_org_identity", recorder("org", 900))
    monkeypatch.setattr(comanage, "create_new_link", recorder("link"))
    monkeypatch.setattr(comanage, "create_new_name", recorder("name"))
    monkeypatch.setattr(comanage, "create_new_identifier", recorder("identifier"))
    return calls, in_flight


async def test_linked_identity_creates_records_one_at_a_time(
    comanage, cilogon_user, record_creates
):
    calls, in_flight = record_creates

    await comanage.create_linked_identity("500", "ada", "token")

    assert in_flight["max"] == 1
    assert [c[0] for c in calls[:3]] == ["org", "link", "name"]
    identifiers = [c[1:] for c in calls[3:]]
    assert len(identifiers) == 4
    assert {linked for _, linked in identifiers} == {"Org", "CO"}


async def test_linked_identity_stops_at_first_failed_identifier(
    comanage, cilogon_user, record_creates, monkeypatch
):
    calls, _ = record_creates

    async def reject(**kwargs):
        raise HTTPException(400, "rejected")

    monkeypatch.setattr(comanage, "create_new_identifier", reject)

    with pytest.raises(HTTPException):
        await comanage.create_linked_identity("500", "ada", "token")
    assert [c[0] for c in calls] == ["org", "link", "name"]


async def test_linked_identity_requires_primary_name(comanage, monkeypatch):
    async def user_info(access_id):
        return make_comanage_user(access_id=access_id, names=[])

    monkeypatch.setattr(comanage, "get_user_info", user_info)

    with pytest.raises(HTTPException) as exc:
        await comanage.create_linked_identity("500", "ada")
    assert exc.value.detail == "User ada does not have a primary name"
