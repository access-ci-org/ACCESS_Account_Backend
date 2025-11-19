import httpx
from config import (
    XRAS_IDENTITY_SERVICE_ACCESS_REQUESTER,
    XRAS_IDENTITY_SERVICE_ACCESS_API_KEY,
    XRAS_IDENTITY_SERVICE_URL
)

class IdentityServiceClient:
    def __init__(self):
        self.base_url = XRAS_IDENTITY_SERVICE_URL
        self.headers = {
        "XA-REQUESTER": XRAS_IDENTITY_SERVICE_ACCESS_REQUESTER,
        "XA-API-KEY": XRAS_IDENTITY_SERVICE_ACCESS_API_KEY,
        }

    async def get_countries(self) -> list[dict]:
        url = f"{self.base_url}/profiles/v1/countries"

        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers = self.headers)
            resp.raise_for_status()
            return resp.json()
        