from urllib.parse import urlencode

from fastapi import HTTPException

from config import (
    CILOGON_AUTHORIZATION_URL,
    CILOGON_LINK_CLIENT_ID,
    CILOGON_LINK_CLIENT_SECRET,
    CILOGON_LOGIN_CLIENT_ID,
    CILOGON_LOGIN_CLIENT_SECRET,
    CILOGON_TOKEN_URL,
    CILOGON_USER_INFO_URL,
)
from services.rest_client import RestClient


class CILogonClient(RestClient):
    def __init__(self, client: str = "login", **kwargs):
        super().__init__(**kwargs)
        self.client = client
        self.client_id = (
            CILOGON_LINK_CLIENT_ID if client == "link" else CILOGON_LOGIN_CLIENT_ID
        )
        self.client_secret = (
            str(CILOGON_LINK_CLIENT_SECRET)
            if client == "link"
            else str(CILOGON_LOGIN_CLIENT_SECRET)
        )

    def get_oidc_start_url(self, **kwargs):
        """Get the URL to start the OIDC auth flow."""
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": "openid profile email org.cilogon.userinfo",
            "skin": "access",
        }
        params.update(kwargs)

        return f"{CILOGON_AUTHORIZATION_URL}?{urlencode(params, doseq=True)}"

    async def get_token(self, **kwargs):
        """Get tokens"""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        data.update(kwargs)
        return await self.request(CILOGON_TOKEN_URL, method="POST", data=data)

    async def get_user_info(self, access_token: str):
        """Get user information from CILogon using the access token."""
        return await self.request(
            CILOGON_USER_INFO_URL, headers={"Authorization": f"Bearer {access_token}"}
        )


async def get_token_user_info(token: str, client_id: str, error_status_code: int):
    """Get user info using an access token."""
    try:
        user_info = await CILogonClient().get_user_info(token)
    except:
        # TODO: Handle specific exceptions
        raise HTTPException(
            status_code=error_status_code,
            detail="Invalid token",
        )
    if user_info["aud"] != client_id:
        raise HTTPException(
            status_code=error_status_code,
            detail="Invalid client ID",
        )

    return user_info
