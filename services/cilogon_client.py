from fastapi import HTTPException

from config import (
    CILOGON_LINK_CLIENT_ID,
    CILOGON_LINK_CLIENT_SECRET,
    CILOGON_LOGIN_CLIENT_ID,
    CILOGON_LOGIN_CLIENT_SECRET,
    CILOGON_TOKEN_URL,
    CILOGON_USER_INFO_URL,
)
from services.rest_client import RestClient


class CILogonClient(RestClient):
    async def get_token(self, **kwargs):
        """Get tokens"""
        data = dict(**kwargs)

        # Add the client secret if the client ID matches one of the known clients.
        client_id = kwargs.get("client_id", None)
        if client_id == CILOGON_LINK_CLIENT_ID:
            data["client_secret"] = CILOGON_LINK_CLIENT_SECRET
        elif client_id == CILOGON_LOGIN_CLIENT_ID:
            data["client_secret"] = CILOGON_LOGIN_CLIENT_SECRET

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
    aud = user_info.get("aud")
    if isinstance(aud, list):
        if client_id not in aud:
            raise HTTPException(
                status_code=error_status_code,
                detail="Invalid client ID",
            )
    elif aud != client_id:
        raise HTTPException(
            status_code=error_status_code,
            detail="Invalid client ID",
        )

    return user_info
