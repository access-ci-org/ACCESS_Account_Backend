"""Tests for CILogonClient + get_token_user_info (services/cilogon_client.py).

Token/userinfo URLs come from the test env (https://cilogon.test/...).
`get_token_user_info` validates the `aud` claim against the expected client id.
"""

import httpx
import pytest
from fastapi import HTTPException

from config import CILOGON_LINK_CLIENT_ID
from services.cilogon_client import CILogonClient, get_token_user_info

TOKEN_URL = "https://cilogon.test/oauth2/token"
USERINFO_URL = "https://cilogon.test/oauth2/userinfo"


# --- get_token --------------------------------------------------------------
async def test_get_token_returns_dict(respx_mock):
    respx_mock.post(TOKEN_URL).respond(200, json={"access_token": "abc"})
    result = await CILogonClient().get_token(client_id="whatever")
    assert result == {"access_token": "abc"}


async def test_get_token_injects_client_secret_for_known_client(respx_mock):
    route = respx_mock.post(TOKEN_URL).respond(200, json={"access_token": "abc"})
    await CILogonClient().get_token(client_id=CILOGON_LINK_CLIENT_ID)
    body = route.calls.last.request.content.decode()
    assert "client_secret=" in body


async def test_requests_use_configured_timeout(respx_mock):
    # CILOGON_TIMEOUT=7 in the test env, not RestClient's 2s default.
    route = respx_mock.post(TOKEN_URL).respond(200, json={"access_token": "abc"})
    await CILogonClient().get_token(client_id="whatever")
    assert route.calls.last.request.extensions["timeout"]["read"] == 7


# --- get_user_info ----------------------------------------------------------
async def test_get_user_info_sends_bearer_and_returns_dict(respx_mock):
    route = respx_mock.get(USERINFO_URL).respond(200, json={"sub": "user@idp"})
    result = await CILogonClient().get_user_info("tok123")
    assert result == {"sub": "user@idp"}
    assert route.calls.last.request.headers["authorization"] == "Bearer tok123"


# --- get_token_user_info: aud validation ------------------------------------
async def test_token_user_info_accepts_matching_string_aud(respx_mock):
    respx_mock.get(USERINFO_URL).respond(
        200, json={"sub": "user@idp", "aud": CILOGON_LINK_CLIENT_ID}
    )
    info = await get_token_user_info("tok", CILOGON_LINK_CLIENT_ID, 400)
    assert info["sub"] == "user@idp"


async def test_token_user_info_accepts_matching_aud_in_list(respx_mock):
    respx_mock.get(USERINFO_URL).respond(
        200, json={"sub": "user@idp", "aud": ["other", CILOGON_LINK_CLIENT_ID]}
    )
    info = await get_token_user_info("tok", CILOGON_LINK_CLIENT_ID, 400)
    assert info["sub"] == "user@idp"


async def test_token_user_info_rejects_wrong_aud(respx_mock):
    respx_mock.get(USERINFO_URL).respond(
        200, json={"sub": "user@idp", "aud": "some-other-client"}
    )
    with pytest.raises(HTTPException) as exc:
        await get_token_user_info("tok", CILOGON_LINK_CLIENT_ID, 400)
    assert exc.value.status_code == 400
    assert exc.value.detail == "Invalid client ID"


async def test_token_user_info_maps_upstream_error_to_invalid_token(respx_mock):
    respx_mock.get(USERINFO_URL).respond(401, text="unauthorized")
    with pytest.raises(HTTPException) as exc:
        await get_token_user_info("tok", CILOGON_LINK_CLIENT_ID, 401)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"


@pytest.mark.parametrize("status_code", [500, 502, 503, 504])
async def test_token_user_info_maps_cilogon_server_error_to_503(
    respx_mock, status_code
):
    # A failing CILogon says nothing about the token, so don't call it invalid.
    respx_mock.get(USERINFO_URL).respond(status_code, text="down")
    with pytest.raises(HTTPException) as exc:
        await get_token_user_info("tok", CILOGON_LINK_CLIENT_ID, 401)
    assert exc.value.status_code == 503
    assert exc.value.detail == "CILogonClient API is unavailable"


@pytest.mark.parametrize(
    "error",
    [httpx.ConnectTimeout("timed out"), httpx.ReadTimeout("timed out"),
     httpx.ConnectError("refused")],
)
async def test_token_user_info_maps_unreachable_cilogon_to_503(respx_mock, error):
    respx_mock.get(USERINFO_URL).mock(side_effect=error)
    with pytest.raises(HTTPException) as exc:
        await get_token_user_info("tok", CILOGON_LINK_CLIENT_ID, 400)
    assert exc.value.status_code == 503


async def test_token_user_info_maps_non_json_response_to_503(respx_mock):
    respx_mock.get(USERINFO_URL).respond(200, text="<html>Maintenance</html>")
    with pytest.raises(HTTPException) as exc:
        await get_token_user_info("tok", CILOGON_LINK_CLIENT_ID, 400)
    assert exc.value.status_code == 503
