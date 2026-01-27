from urllib.parse import quote

import httpx
from fastapi import HTTPException, status

from config import (
    XRAS_IDENTITY_SERVICE_BASE_URL,
    XRAS_IDENTITY_SERVICE_KEY,
    XRAS_IDENTITY_SERVICE_REQUESTER,
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

    async def get_organizations_by_domain(self, domain: str) -> dict:
        check_domain = quote(domain, safe="")
        return await self._request(
            "GET",
            f"/profiles/v1/organizations?domain={check_domain}",
        )

    # High-level methods

    async def check_organization_matches_domain(
        self, organization_id: int, domain: str
    ):
        organizations = await self.get_organizations_by_domain(domain)
        for organization in organizations:
            if (
                organization["organization_id"] == organization_id
                and organization["is_active"]
                and organization["is_eligible"]
            ):
                return organization["organization_name"]

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Domain {domain} does not match organization {organization_id} or is ineligible",
        )
