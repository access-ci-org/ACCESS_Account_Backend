import httpx
from config import (
    XRAS_IDENTITY_SERVICE_URL,
    XRAS_IDENTITY_SERVICE_REQUESTER,
    XRAS_IDENTITY_SERVICE_API_KEY,
)

class IdentityServiceClient:
    def __init__(self):
        self.base_url = XRAS_IDENTITY_SERVICE_URL
        self.headers = {
            "XA-REQUESTER": XRAS_IDENTITY_SERVICE_REQUESTER,
            "XA-API-KEY": XRAS_IDENTITY_SERVICE_API_KEY,
        }

    async def get_academic_statuses(self) -> list[dict]:
        url = f"{self.base_url}/profiles/v1/nsf_status_codes"

        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers = self.headers)
            resp.raise_for_status()
            return resp.json()
        