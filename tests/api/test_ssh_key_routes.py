"""API tests for /account/{username}/ssh-key routes."""

from unittest.mock import AsyncMock

import main
from services.comanage_registry_client import CoManageUser

BASE = "/api/v1"

# A valid key body (bare, one token) — the handler passes it to the fingerprint fn.
SSH_KEY_BODY = "AAAAC3NzaC1lZDI1NTE5AAAAIGm2vOvAVHbdQ7JkCDxqnNmXhgU3wNyzWQ5/fSS6R/3p"
PUBLIC_KEY = f"ssh-ed25519 {SSH_KEY_BODY} ada@example"


# --- GET /account/{username}/ssh-key ----------------------------------------
def test_get_ssh_keys_skips_deleted(client, override_auth, mock_comanage):
    override_auth(main.require_username_access, uid="ada")
    mock_comanage.get_user_info = AsyncMock(
        return_value=CoManageUser(
            {
                "SshKey": [
                    {"skey": SSH_KEY_BODY,
                     "meta": {"id": 1, "created": "2026-01-01", "deleted": False}},
                    {"skey": SSH_KEY_BODY,
                     "meta": {"id": 2, "created": "2026-01-02", "deleted": True}},
                ]
            }
        )
    )

    resp = client.get(f"{BASE}/account/ada/ssh-key")
    assert resp.status_code == 200
    keys = resp.json()["sshKeys"]
    assert len(keys) == 1
    assert keys[0]["keyId"] == 1
    assert keys[0]["hash"].startswith("SHA256:")


# --- POST /account/{username}/ssh-key ---------------------------------------
def test_add_ssh_key_success(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.add_ssh_key_for_user = AsyncMock(return_value={})

    resp = client.post(f"{BASE}/account/ada/ssh-key", json={"publicKey": PUBLIC_KEY})
    assert resp.status_code == 200
    assert resp.json() == {"success": True}
    mock_comanage.add_ssh_key_for_user.assert_awaited_once()


def test_add_ssh_key_empty_rejected(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")

    resp = client.post(f"{BASE}/account/ada/ssh-key", json={"publicKey": "   "})
    assert resp.status_code == 400


# --- DELETE /account/{username}/ssh-key/{key_id} ----------------------------
def test_delete_ssh_key_success(client, override_auth, mock_comanage):
    override_auth(main.require_own_username_access, uid="ada")
    mock_comanage.delete_ssh_key_for_user = AsyncMock(return_value={})

    resp = client.request("DELETE", f"{BASE}/account/ada/ssh-key/7")
    assert resp.status_code == 200
    mock_comanage.delete_ssh_key_for_user.assert_awaited_once_with("ada", 7)
