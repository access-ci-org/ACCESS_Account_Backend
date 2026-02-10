from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request

from config import (
    CILOGON_AUTHORIZATION_URL,
    CILOGON_CLIENT_ID,
    CILOGON_CLIENT_SECRET,
    CILOGON_TOKEN_URL,
    CILOGON_USER_INFO_URL,
)


class CILogonClient:
    def get_oidc_start_url(
        self, request: Request, idp: str | None = None, token_type: str | None = None
    ):
        """Get the URL to start the OIDC auth flow."""
        params = {
            "client_id": CILOGON_CLIENT_ID,
            "response_type": "code",
            "scope": "openid profile email org.cilogon.userinfo",
            "redirect_uri": request.url_for("complete_login"),
            "skin": "access",
        }
        if idp:
            params["idphint"] = idp
        if token_type:
            params["token_type"] = token_type

        return f"{CILOGON_AUTHORIZATION_URL}?{urlencode(params, doseq=True)}"

    async def get_access_token(self, request: Request, code: str):
        """Get an access token"""
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                CILOGON_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "client_id": CILOGON_CLIENT_ID,
                    "client_secret": CILOGON_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": request.url_for("complete_login"),
                },
            )
        if token_response.status_code != 200:
            raise HTTPException(
                status_code=token_response.status_code, detail=token_response.json()
            )

        access_token = token_response.json().get("access_token")
        return access_token

    async def get_user_info(self, access_token: str):
        """Get user information from CILogon using the access token."""
        async with httpx.AsyncClient() as client:
            userinfo_response = await client.get(
                CILOGON_USER_INFO_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )

            if userinfo_response.status_code != 200:
                raise HTTPException(
                    status_code=userinfo_response.status_code,
                    detail=userinfo_response.text,
                )

        return userinfo_response.json()
