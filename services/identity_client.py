from typing import TypedDict
from urllib.parse import quote

import httpx
import tldextract
from fastapi import HTTPException, status

from config import (
    XRAS_IDENTITY_SERVICE_BASE_URL,
    XRAS_IDENTITY_SERVICE_KEY,
    XRAS_IDENTITY_SERVICE_REQUESTER,
)
from services.rest_client import RestClient


class Degree(TypedDict):
    degree_id: int
    degree_field: str


class IdentityServiceClient(RestClient):
    def __init__(self, propagate_errors=False):
        super().__init__(propagate_errors=propagate_errors)
        self.base_url = XRAS_IDENTITY_SERVICE_BASE_URL
        self.headers = {
            "XA-REQUESTER": XRAS_IDENTITY_SERVICE_REQUESTER,
            "XA-API-KEY": XRAS_IDENTITY_SERVICE_KEY,
        }

    async def _request(self, method: str, path: str, **kwargs) -> dict | list:
        url = f"{self.base_url}{path}"
        return await self.request(url, method=method, headers=self.headers, **kwargs)

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
        department: str | None = None,
    ):
        person = {
            "firstName": first_name,
            "lastName": last_name,
            "email": email,
            "organizationId": organization_id,
            "nsfStatusCodeId": academic_status_id,
            "countryId": residence_country_id,
            "department": department,
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

    def _domain_chain(self, host: str) -> list[str]:
        if not host:
            return []

        host = host.strip().strip(".").lower()

        ext = tldextract.extract(host)

        # Newer tldextract preferred name
        base = getattr(ext, "top_domain_under_public_suffix", "") or getattr(
            ext, "registered_domain", ""
        )

        # If tldextract cannot determine a base (localhost /invalid)
        # use what was given
        if not base:
            return [host]

        # Build chain by repeatedly removing the leftmost label until base.
        parts = host.split(".")
        chain: list[str] = []
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            chain.append(candidate)
            if candidate == base:
                break

        # Ensure base is included even if host didn't end with it for some reason
        if chain and chain[-1] != base:
            chain.append(base)

        return chain

    async def get_academic_statuses(self) -> list[dict]:
        return await self._request("GET", "/profiles/v1/nsf_status_codes")

    async def get_countries(self) -> list[dict]:
        return await self._request("GET", "/profiles/v1/countries")

    async def get_degrees(self) -> list[dict]:
        return await self._request("GET", "/profiles/v1/degrees")

    async def get_organizations_by_domain(self, domain: str) -> dict:
        # check_domain = quote(domain, safe="")
        domains = self._domain_chain(domain)

        params = [("domain[]", d) for d in domains]
        return await self._request(
            "GET",
            "/profiles/v1/organizations",
            params=params,
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
        department: str | None = None,
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
            department=department,
        )
        person_data = self._to_person(**person_kwargs)

        try:
            return await self._request(
                "POST",
                f"/profiles/v1/people/{quote(access_id, safe='')}",
                json=person_data,
            )
        except (httpx.HTTPStatusError, HTTPException) as err:
            status_code = err.response.status_code if isinstance(err, httpx.HTTPStatusError) else err.status_code
            error_text = err.response.text if isinstance(err, httpx.HTTPStatusError) else str(err.detail)
            if status_code == 400 and "already exists" in error_text and update_if_exists:
                return await self.update_person(access_id, **person_kwargs)
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
        department: str | None = None,
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
            department=department,
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
