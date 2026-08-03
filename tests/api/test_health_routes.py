"""API tests for GET /health.

The route builds fresh CoManageRegistryClient/IdentityServiceClient/CILogonClient
instances (not the shared account_service singletons), so services are mocked by
monkeypatching the class names imported into `main`, the same way
tests/api/test_auth_routes.py mocks the fresh CILogonClient(...) constructed
inside /auth/oauth2/token.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
from botocore.exceptions import ClientError, EndpointConnectionError

import main

BASE = "/api/v1"


def _patch_clients(
    monkeypatch, *, comanage=None, identity=None, cilogon=None, ses=None
):
    comanage_fake = SimpleNamespace(ping=comanage or AsyncMock(return_value=200))
    identity_fake = SimpleNamespace(ping=identity or AsyncMock(return_value=200))
    cilogon_fake = SimpleNamespace(ping=cilogon or AsyncMock(return_value=200))

    monkeypatch.setattr(main, "CoManageRegistryClient", lambda **kw: comanage_fake)
    monkeypatch.setattr(main, "IdentityServiceClient", lambda **kw: identity_fake)
    monkeypatch.setattr(main, "CILogonClient", lambda **kw: cilogon_fake)
    monkeypatch.setattr(main, "ses_ping", ses or AsyncMock(return_value=200))


def _client_error(code: str, status_code: int) -> ClientError:
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status_code}},
        "GetSendQuota",
    )


def test_health_all_services_reachable(client, monkeypatch):
    _patch_clients(monkeypatch)

    resp = client.get(f"{BASE}/health")
    assert resp.status_code == 200
    body = resp.json()
    for service in ("comanageRegistry", "cilogon", "identityService", "awsSes"):
        assert body[service]["reachable"] is True
        assert body[service]["statusCode"] == 200


def test_health_identity_service_unreachable(client, monkeypatch):
    _patch_clients(
        monkeypatch,
        identity=AsyncMock(side_effect=httpx.ConnectError("Connection refused")),
    )

    resp = client.get(f"{BASE}/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["identityService"]["reachable"] is False
    assert body["identityService"]["statusCode"] is None
    assert body["comanageRegistry"]["reachable"] is True
    assert body["cilogon"]["reachable"] is True


def test_health_cilogon_http_error_still_counts_as_reachable(client, monkeypatch):
    _patch_clients(monkeypatch, cilogon=AsyncMock(return_value=400))

    resp = client.get(f"{BASE}/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["cilogon"]["reachable"] is True
    assert body["cilogon"]["statusCode"] == 400


def test_health_ses_bad_credentials_still_counts_as_reachable(client, monkeypatch):
    _patch_clients(
        monkeypatch,
        ses=AsyncMock(side_effect=_client_error("InvalidClientTokenId", 403)),
    )

    resp = client.get(f"{BASE}/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["awsSes"]["reachable"] is True
    assert body["awsSes"]["statusCode"] == 403
    assert body["awsSes"]["detail"] == "InvalidClientTokenId"


def test_health_ses_unreachable_on_connection_failure(client, monkeypatch):
    _patch_clients(
        monkeypatch,
        ses=AsyncMock(
            side_effect=EndpointConnectionError(endpoint_url="https://email.example.com")
        ),
    )

    resp = client.get(f"{BASE}/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["awsSes"]["reachable"] is False
    assert body["awsSes"]["statusCode"] is None


def test_health_no_auth_required(client, monkeypatch):
    _patch_clients(monkeypatch)

    resp = client.get(f"{BASE}/health")
    assert resp.status_code == 200
