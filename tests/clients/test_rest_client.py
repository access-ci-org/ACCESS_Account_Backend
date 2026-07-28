"""Tests for the base RestClient httpx wrapper (services/rest_client.py).

respx stubs the outbound httpx layer so we exercise the real request building and,
crucially, the error-mapping behavior:
  * HTTPStatusError -> HTTPException(same status)   when propagate_errors=True
  * connection/timeout errors -> HTTPException(503) when propagate_errors=True
  * both re-raise the original httpx error           when propagate_errors=False
plus the _expect() JSON-shape guard.
"""

import httpx
import pytest
from fastapi import HTTPException

from services.rest_client import RestClient

URL = "https://api.test/thing"


async def test_returns_parsed_json_on_success(respx_mock):
    respx_mock.get(URL).respond(200, json={"a": 1})
    result = await RestClient().request(URL)
    assert result == {"a": 1}


async def test_returns_none_on_empty_body(respx_mock):
    respx_mock.get(URL).respond(204)
    assert await RestClient().request(URL) is None


async def test_sends_accept_json_header(respx_mock):
    route = respx_mock.get(URL).respond(200, json={})
    await RestClient().request(URL)
    assert route.calls.last.request.headers["accept"] == "application/json"


async def test_basic_auth_added_when_credentials_present(respx_mock):
    route = respx_mock.get(URL).respond(200, json={})
    await RestClient(username="alice", password="secret").request(URL)
    assert route.calls.last.request.headers["authorization"].startswith("Basic ")


async def test_no_auth_header_without_credentials(respx_mock):
    route = respx_mock.get(URL).respond(200, json={})
    await RestClient().request(URL)
    assert "authorization" not in route.calls.last.request.headers


async def test_http_error_maps_to_httpexception_when_propagating(respx_mock):
    respx_mock.get(URL).respond(404, text="nope")
    with pytest.raises(HTTPException) as exc:
        await RestClient(propagate_errors=True).request(URL)
    assert exc.value.status_code == 404
    assert "RestClient API error" in exc.value.detail


async def test_http_error_reraised_when_not_propagating(respx_mock):
    respx_mock.get(URL).respond(500)
    with pytest.raises(httpx.HTTPStatusError):
        await RestClient(propagate_errors=False).request(URL)


async def test_connection_error_maps_to_503_when_propagating(respx_mock):
    respx_mock.get(URL).mock(side_effect=httpx.ConnectError)
    with pytest.raises(HTTPException) as exc:
        await RestClient(propagate_errors=True).request(URL)
    assert exc.value.status_code == 503
    assert "unavailable" in exc.value.detail


async def test_connection_error_reraised_when_not_propagating(respx_mock):
    respx_mock.get(URL).mock(side_effect=httpx.ConnectError)
    with pytest.raises(httpx.RequestError):
        await RestClient(propagate_errors=False).request(URL)


# --- _expect (pure) ---------------------------------------------------------
def test_expect_returns_matching_shape():
    client = RestClient()
    assert client._expect({"a": 1}, dict) == {"a": 1}
    assert client._expect([1, 2], list) == [1, 2]


def test_expect_raises_502_on_shape_mismatch():
    with pytest.raises(HTTPException) as exc:
        RestClient()._expect([1, 2], dict)
    assert exc.value.status_code == 502


def test_expect_respects_custom_status_code():
    with pytest.raises(HTTPException) as exc:
        RestClient()._expect({"a": 1}, list, status_code=400)
    assert exc.value.status_code == 400
