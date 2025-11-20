import httpx
from config import (
    XRAS_IDENTITY_SERVICE_BASE_URL,
    XRAS_IDENTITY_SERVICE_REQUESTER,
    XRAS_IDENTITY_SERVICE_KEY,
)

class IdentityServiceClient:
    def __init__(self):
        self.base_url = XRAS_IDENTITY_SERVICE_BASE_URL
        self.headers = {
            "XA-REQUESTER": XRAS_IDENTITY_SERVICE_REQUESTER,
            "XA-API-KEY": XRAS_IDENTITY_SERVICE_KEY,
        }
    
    async def _request(self, method: str, path: str) -> dict | list:
        url = f"{self.base_url}{path}"

        async with httpx.AsyncClient() as client:
            resp = await client.request(method, url, headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    async def get_academic_statuses(self) -> list[dict]:
        return await self._request("GET", "/profiles/v1/nsf_status_codes")

    async def get_countries(self) -> list[dict]:
        return await self._request("GET", "/profiles/v1/countries")
        