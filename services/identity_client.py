import httpx
from config import (
    XRAS_IDENTITY_SERVICE_REQUESTER,
    XRAS_IDENTITY_SERVICE_KEY,
    XRAS_IDENTITY_SERVICE_BASE_URL
)

class IdentityServiceClient:
    def __init__(self):
        self.base_url = XRAS_IDENTITY_SERVICE_BASE_URL
        self.headers = {
        "XA-REQUESTER": XRAS_IDENTITY_SERVICE_REQUESTER,
        "XA-API-KEY": XRAS_IDENTITY_SERVICE_KEY,
        }

    async def _request(self, path: str):
        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    async def get_countries(self) -> list[dict]:
        return await self._request("/profiles/v1/countries")