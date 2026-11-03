import ssl

import httpx
from fastapi import HTTPException

from config import (
    CILOGON_LINK_CLIENT_ID,
    CILOGON_LINK_CLIENT_SECRET,
    CILOGON_LOGIN_CLIENT_ID,
    CILOGON_LOGIN_CLIENT_SECRET,
    CILOGON_TOKEN_URL,
    CILOGON_USER_INFO_URL,
    CILOGON_WELL_KNOWN_URL,
)
from services.rest_client import RestClient


class CILogonClient(RestClient):
    async def get_token(self, **kwargs) -> dict:
        """Get tokens"""
        data = dict(**kwargs)

        # Add the client secret if the client ID matches one of the known clients.
        client_id = kwargs.get("client_id", None)
        if client_id == CILOGON_LINK_CLIENT_ID:
            data["client_secret"] = CILOGON_LINK_CLIENT_SECRET
        elif client_id == CILOGON_LOGIN_CLIENT_ID:
            data["client_secret"] = CILOGON_LOGIN_CLIENT_SECRET

        result = await self.request(CILOGON_TOKEN_URL, method="POST", data=data)
        return self._expect(result, dict)

    async def get_user_info(self, access_token: str) -> dict:
        """Get user information from CILogon using the access token."""
        result = await self.request(
            CILOGON_USER_INFO_URL, headers={"Authorization": f"Bearer {access_token}"}
        )
        return self._expect(result, dict)

    async def ping(self) -> int:
        """Make a lightweight, unauthenticated request and return the HTTP status code."""
        return await self.request_status(CILOGON_WELL_KNOWN_URL)


async def get_token_user_info(
    token: str, client_id: str, error_status_code: int
) -> dict:
    """Get user info using an access token.

    Raises:
        HTTPException: ``error_status_code`` if CILogon rejects the token or it
            was issued to another client; 503 if CILogon can't be reached or
            fails, since that says nothing about the token.
    """
    client = CILogonClient()
    try:
        user_info = await client.get_user_info(token)
    except httpx.HTTPStatusError as exc:
        # CILogon answers a bad or expired token with a 4xx. A 5xx means
        # CILogon itself is failing.
        if exc.response.status_code >= 500:
            raise client._unavailable() from exc
        raise HTTPException(
            status_code=error_status_code,
            detail="Invalid token",
        ) from exc
    except (httpx.RequestError, ssl.SSLError, ValueError) as exc:
        # Timeouts, refused connections and non-JSON bodies (e.g. a
        # maintenance page) all mean CILogon isn't answering.
        raise client._unavailable() from exc
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
