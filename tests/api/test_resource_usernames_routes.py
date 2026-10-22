"""API tests for the /account/{username}/resource-usernames route."""

from unittest.mock import AsyncMock

from fastapi import HTTPException

import main

BASE = "/api/v1"

# Shape returned by the XRAS Identity Service site_logins endpoint.
SITE_LOGINS = [
    {
        "organizationId": 844,
        "organizationName": "National Center for Supercomputing Applications",
        "logins": [
            {
                "resourceName": "delta-cpu.ncsa.xsede.org",
                "displayName": "NCSA Delta CPU",
                "rdrResourceId": 145281,
                "ciderResourceId": "delta-cpu.ncsa.access-ci.org",
                "username": "ada1",
            },
        ],
    },
    {
        "organizationId": 848,
        "organizationName": "Pittsburgh Supercomputing Center",
        "logins": [
            {
                "resourceName": "bridges2-rm.psc.xsede.org",
                "displayName": None,
                "rdrResourceId": None,
                "ciderResourceId": "bridges2-rm.psc.access-ci.org",
                "username": "ada2",
            },
        ],
    },
]


# --- GET /account/{username}/resource-usernames ------------------------------
def test_get_resource_usernames(client, override_auth, mock_identity):
    override_auth(main.require_username_access, uid="ada")
    mock_identity.get_site_logins = AsyncMock(return_value=SITE_LOGINS)

    resp = client.get(f"{BASE}/account/ada/resource-usernames")
    assert resp.status_code == 200
    assert resp.json() == {"organizations": SITE_LOGINS}
    mock_identity.get_site_logins.assert_awaited_once_with("ada")


def test_get_resource_usernames_empty(client, override_auth, mock_identity):
    override_auth(main.require_username_access, uid="ada")
    mock_identity.get_site_logins = AsyncMock(return_value=[])

    resp = client.get(f"{BASE}/account/ada/resource-usernames")
    assert resp.status_code == 200
    assert resp.json() == {"organizations": []}


def test_get_resource_usernames_unknown_person_is_empty(
    client, override_auth, mock_identity
):
    # A user without an XRAS person record has no resource usernames.
    override_auth(main.require_username_access, uid="ada")
    mock_identity.get_site_logins = AsyncMock(
        side_effect=HTTPException(404, "IdentityServiceClient API error: {}")
    )

    resp = client.get(f"{BASE}/account/ada/resource-usernames")
    assert resp.status_code == 200
    assert resp.json() == {"organizations": []}


def test_get_resource_usernames_upstream_unavailable(
    client, override_auth, mock_identity
):
    override_auth(main.require_username_access, uid="ada")
    mock_identity.get_site_logins = AsyncMock(
        side_effect=HTTPException(503, "IdentityServiceClient API is unavailable")
    )

    resp = client.get(f"{BASE}/account/ada/resource-usernames")
    assert resp.status_code == 503


def test_get_resource_usernames_other_user_forbidden(
    client, auth_header, mock_identity
):
    mock_identity.get_site_logins = AsyncMock(return_value=SITE_LOGINS)

    resp = client.get(
        f"{BASE}/account/ada/resource-usernames",
        headers=auth_header(token_type="login", sub="mallory", username="mallory"),
    )
    assert resp.status_code == 403
    mock_identity.get_site_logins.assert_not_awaited()


def test_get_resource_usernames_requires_auth(client):
    assert client.get(f"{BASE}/account/ada/resource-usernames").status_code == 403