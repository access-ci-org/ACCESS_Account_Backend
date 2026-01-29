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

    async def _request(self, method: str, path: str, **kwargs) -> dict | list:
        url = f"{self.base_url}{path}"

        async with httpx.AsyncClient() as client:
            resp = await client.request(method, url, headers=self.headers, **kwargs)
            resp.raise_for_status()
            return None if resp.status_code == 204 else resp.json()

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

    async def get_person(self, access_id: str):
        return await self._request(
            "GET",
            f"/profiles/v1/people/{quote(access_id, safe='')}",
        )

    async def create_person(self, access_id: str, person_data: dict):
        return await self._request(
            "POST", f"/profiles/v1/people/{quote(access_id, safe='')}", json=person_data
        )

    async def update_person(self, access_id: str, person_data: dict):
        return await self._request(
            "PATCH",
            f"/profiles/v1/people/{quote(access_id, safe='')}",
            json=person_data,
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

    async def create_or_update_person(
        self,
        access_id: str,
        first_name: str,
        last_name: str,
        organization_id: int,
        academic_status_id: int,
        residence_country_id: int,
        citizenship_country_ids: list[int],
    ):
        requested_person = {
            "firstName": first_name,
            "lastName": last_name,
            "organizationId": organization_id,
            "nsfStatusCodeId": academic_status_id,
            "countryId": residence_country_id,
            "citizenships": [
                {"countryId": country_id} for country_id in citizenship_country_ids
            ],
        }
        try:
            existing_person = await self.get_person(access_id)
        except httpx.HTTPStatusError as err:
            if err.response.status_code == 404:
                # Create the person
                return await self.create_person(access_id, requested_person)
            else:
                raise err

        # Update the person
        person_updates = {
            k: v
            for k, v in requested_person.items()
            if v != existing_person.get(k) and k != "citizenships"
        }

        # Check citizenships for equality
        if set(citizenship_country_ids) != set(
            [c.get("countryId") for c in existing_person.get("citizenships")]
        ):
            person_updates["citizenships"] = requested_person["citizenships"]

        return await self.update_person(access_id, person_updates)

    async def get_account(self, username: str) -> dict:
        check_username = quote(username, safe="")
        return await self._request(
            "GET",
            f"/profiles/v1/people/{check_username}",
        )