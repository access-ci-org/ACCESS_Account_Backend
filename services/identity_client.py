from typing import TypedDict
from urllib.parse import quote

import httpx
from fastapi import HTTPException, status

from config import (
    XRAS_IDENTITY_SERVICE_BASE_URL,
    XRAS_IDENTITY_SERVICE_KEY,
    XRAS_IDENTITY_SERVICE_REQUESTER,
)


class Degree(TypedDict):
    degree_id: int
    degree_field: str


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

    def _to_person(
        self,
        first_name: str | None = None,
        last_name: str | None = None,
        email: str | None = None,
        organization_id: int | None = None,
        academic_status_id: int | None = None,
        residence_country_id: int | None = None,
        citizenship_country_ids: list[int] | None = None,
        degrees: list[Degree] | None = None,
    ):
        person = {
            "firstName": first_name,
            "lastName": last_name,
            "email": email,
            "organizationId": organization_id,
            "nsfStatusCodeId": academic_status_id,
            "countryId": residence_country_id,
            "citizenships": [
                {"countryId": country_id}
                for country_id in citizenship_country_ids or []
            ]
            if citizenship_country_ids is not None
            else None,
            "academicDegrees": [
                {"degreeId": d["degree_id"], "degreeField": d["degree_field"]}
                for d in degrees
            ]
            if degrees is not None
            else None,
        }

        return {k: v for k, v in person.items() if v is not None}

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

    async def create_person(
        self,
        access_id: str,
        first_name: str,
        last_name: str,
        email: str,
        organization_id: int,
        academic_status_id: int,
        residence_country_id: int,
        citizenship_country_ids: list[int],
        degrees: list[Degree] = [],
        update_if_exists=False,
    ):
        person_kwargs = dict(
            first_name=first_name,
            last_name=last_name,
            email=email,
            organization_id=organization_id,
            academic_status_id=academic_status_id,
            residence_country_id=residence_country_id,
            citizenship_country_ids=citizenship_country_ids,
            degrees=degrees,
        )
        person_data = self._to_person(**person_kwargs)

        try:
            return await self._request(
                "POST",
                f"/profiles/v1/people/{quote(access_id, safe='')}",
                json=person_data,
            )
        except httpx.HTTPStatusError as err:
            if err.response.status_code == 409 and update_if_exists:
                return await self.update_person(access_id, **person_kwargs)
            else:
                raise err

    async def update_person(
        self,
        access_id: str,
        first_name: str | None = None,
        last_name: str | None = None,
        email: str | None = None,
        organization_id: int | None = None,
        academic_status_id: int | None = None,
        residence_country_id: int | None = None,
        citizenship_country_ids: list[int] | None = None,
        degrees: list[Degree] | None = None,
    ):
        person_data = self._to_person(
            first_name=first_name,
            last_name=last_name,
            email=email,
            organization_id=organization_id,
            academic_status_id=academic_status_id,
            residence_country_id=residence_country_id,
            citizenship_country_ids=citizenship_country_ids,
            degrees=degrees,
        )

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

    async def get_account(self, username: str) -> dict:
        check_username = quote(username, safe="")
        return await self._request(
            "GET",
            f"/profiles/v1/people/{check_username}",
        )
