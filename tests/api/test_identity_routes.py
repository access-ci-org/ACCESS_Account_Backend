"""API tests for /account/{username}/identity routes."""

from unittest.mock import AsyncMock

import main
from services.comanage_registry_client import CoManageUser

BASE = "/api/v1"


def _org_identity(identity_id, identifier, itype="eppn"):
    return {
        "meta": {"id": identity_id, "deleted": False},
        "o": "Example University",
        "Identifier": [
            {"type": itype, "identifier": identifier, "login": True,
             "meta": {"id": identity_id * 10}}
        ],
    }


# --- GET /account/{username}/identity ---------------------------------------
def test_get_identities(client, override_auth, mock_comanage):
    override_auth(main.require_username_access, uid="ada")
    mock_comanage.get_user_info = AsyncMock(
        return_value=CoManageUser(
            {"OrgIdentity": [_org_identity(10, "ada@idp.example.org")]}
        )
    )

    resp = client.get(f"{BASE}/account/ada/identity")
    assert resp.status_code == 200
    identities = resp.json()["identities"]
    assert identities[0]["identityId"] == 10
    assert identities[0]["organization"] == "Example University"


# --- POST /account/{username}/identity (link) -------------------------------
def test_link_identity_success(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.get_co_person_id_for_accessid = AsyncMock(return_value="500")
    mock_comanage.create_linked_identity = AsyncMock(return_value=None)

    resp = client.post(
        f"{BASE}/account/ada/identity", json={"cilogonToken": "tok123"}
    )
    assert resp.status_code == 200
    assert resp.json() == {"success": True}


def test_link_identity_user_not_found(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.get_co_person_id_for_accessid = AsyncMock(return_value=None)

    resp = client.post(
        f"{BASE}/account/ada/identity", json={"cilogonToken": "tok123"}
    )
    assert resp.status_code == 400


# --- DELETE /account/{username}/identity/{id} -------------------------------
def test_delete_identity_success(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.get_co_person_id_for_accessid = AsyncMock(return_value="500")
    mock_comanage.get_user_info = AsyncMock(
        return_value=CoManageUser(
            {
                "OrgIdentity": [_org_identity(5, "ada@idp.example.org")],
                "Identifier": [],
            }
        )
    )
    mock_comanage.delete_identifier = AsyncMock(return_value={})
    mock_comanage.get_org_identity_links = AsyncMock(return_value=[])
    mock_comanage.delete_org_identity = AsyncMock(return_value={})

    resp = client.request("DELETE", f"{BASE}/account/ada/identity/5")
    assert resp.status_code == 200
    mock_comanage.delete_org_identity.assert_awaited_once()


def test_delete_identity_not_found(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.get_co_person_id_for_accessid = AsyncMock(return_value="500")
    mock_comanage.get_user_info = AsyncMock(
        return_value=CoManageUser({"OrgIdentity": [], "Identifier": []})
    )

    resp = client.request("DELETE", f"{BASE}/account/ada/identity/999")
    assert resp.status_code == 404


def test_delete_identity_blocks_access_idp(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.get_co_person_id_for_accessid = AsyncMock(return_value="500")
    mock_comanage.get_user_info = AsyncMock(
        return_value=CoManageUser(
            {
                "OrgIdentity": [_org_identity(5, "ada@access-ci.org")],
                "Identifier": [],
            }
        )
    )

    resp = client.request("DELETE", f"{BASE}/account/ada/identity/5")
    assert resp.status_code == 400
    assert "ACCESS identity" in resp.json()["detail"]


def test_delete_identity_user_not_found(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.get_co_person_id_for_accessid = AsyncMock(return_value=None)

    resp = client.request("DELETE", f"{BASE}/account/ada/identity/5")
    assert resp.status_code == 400
