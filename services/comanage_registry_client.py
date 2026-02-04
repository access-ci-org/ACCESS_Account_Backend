import logging
from asyncio import gather
from collections import namedtuple
from urllib.parse import quote, urlencode

import httpx
from fastapi import HTTPException, status

from config import (
    COMANAGE_REGISTRY_BASE_URL,
    COMANAGE_REGISTRY_COID,
    COMANAGE_REGISTRY_PASSWORD,
    COMANAGE_REGISTRY_TIMEOUT,
    COMANAGE_REGISTRY_USER,
)
from services.cilogon_client import CILogonClient

# Map CILogon claims to identifier types and login status
# Based on the CILogon -> CoManage identifier mapping
CLAIM_TO_IDENTIFIER_MAPPING = [
    {"claim": "eppn", "type": "eppn", "login": True},
    {"claim": "eptid", "type": "eptid", "login": False},
    {"claim": "epuid", "type": "epuid", "login": False},
    {"claim": "sub", "type": "oidc", "login": True},
    {"claim": "orcid", "type": "orcid", "login": False},
    {"claim": "pairwise_id", "type": "samlpairwiseid", "login": False},
    {"claim": "subject_id", "type": "samlsubjectid", "login": False},
]

logger = logging.getLogger("access_account_api")
logger.setLevel(logging.INFO)


Identifier = namedtuple("Identifier", ["identifier", "type", "login"])


class CoManageUser(dict):
    def get_username(self) -> str | None:
        """Get the username for the current user."""
        for identifier in self["Identifier"]:
            if identifier.get("type") == "accessid":
                return identifier.get("identifier")
        return None

    def get_primary_name(self) -> dict | None:
        """Get the primary name dictionary."""
        for name in self["Name"]:
            if name["primary_name"] and not name["meta"]["deleted"]:
                return name
        return None

    def get_primary_email(self, address_only=True) -> str | None:
        """Get the primary email address."""
        for email in self.get("EmailAddress", []):
            if email["type"] == "official" and not email["meta"]["deleted"]:
                return email["mail"] if address_only else email
        return None

    def has_org_identity(self, identifier: Identifier):
        """Iterate over the existing OrgIdentity records and check whether there is one with the specified identifier."""
        if "OrgIdentity" not in self:
            # There are no OrgIdentity records
            return False

        for org_identity in self["OrgIdentity"]:
            if org_identity["meta"]["deleted"]:
                continue

            for identifier_dict in org_identity["Identifier"]:
                if identifier_dict["meta"]["deleted"]:
                    continue

                if (
                    identifier_dict["identifier"] == identifier.identifier
                    and identifier_dict["type"] == identifier.type
                ):
                    return True

        return False


class CoManageRegistryClient:
    def __init__(
        self,
        base_url=COMANAGE_REGISTRY_BASE_URL,
        username=COMANAGE_REGISTRY_USER,
        password=COMANAGE_REGISTRY_PASSWORD,
        coid=COMANAGE_REGISTRY_COID,
        timeout=COMANAGE_REGISTRY_TIMEOUT,
    ):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.coid = coid
        self.timeout = timeout

    async def _request(
        self, method: str, path: str, json: dict | None = None
    ) -> dict | list:
        url = f"{self.base_url}/registry/{path}"
        auth = httpx.BasicAuth(username=self.username, password=str(self.password))
        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        async with httpx.AsyncClient(auth=auth) as client:
            resp = await client.request(
                method, url, headers=headers, json=json, timeout=10.0
            )
            resp.raise_for_status()
            return resp.json()

    async def get_co_person_id_for_email(self, email: str) -> str | None:
        """Return the COPersonIdentifier associated with an email address.

        Args:
            email: Email address to check

        Returns:
            CoPersonId for email address, or None if not found
        """
        encoded_email = quote(email)
        result = await self._request(
            "GET", f"co_people.json?coid={self.coid}&search.mail={encoded_email}"
        )

        if isinstance(result, dict) and "CoPeople" in result:
            co_people = result["CoPeople"]
            if co_people and len(co_people) > 0:
                return str(co_people[0]["Id"])

        return None

    async def get_access_id_for_email(self, email: str) -> str | None:
        """Return the ACCESS ID associated with an email address.

        Args:
            email: Email address to check

        Returns:
            ACCESS ID for email address, or None if not found
        """
        co_person_id = await self.get_co_person_id_for_email(email)
        if not co_person_id:
            return None

        result = await self._request(
            "GET", f"identifiers.json?copersonid={co_person_id}"
        )

        if isinstance(result, dict) and "Identifiers" in result:
            for identifier in result["Identifiers"]:
                if identifier.get("Type") == "accessid":
                    return identifier.get("Identifier")

        return None

    async def get_user_info(self, accessid: str) -> CoManageUser:
        """Get full user info for a given ACCESS ID.

        Args:
            accessid: The ACCESS ID to search for

        Returns:
            Dictionary containing user information
        """
        user_info = await self._request(
            "GET", f"api/co/{self.coid}/core/v1/people/{quote(accessid, safe='')}"
        )
        return CoManageUser(user_info)

    async def get_active_tandc(self) -> dict | None:
        """Return the first active Terms and Conditions element.

        Returns:
            Active Terms and Conditions dictionary, or None if not found
        """
        params = {"coid": self.coid}
        result = await self._request(
            "GET", f"co_terms_and_conditions.json?{urlencode(params)}"
        )
        if isinstance(result, dict) and "CoTermsAndConditions" in result:
            for tandc in result["CoTermsAndConditions"]:
                if tandc.get("Status") == "Active":
                    return tandc

        return None

    async def create_new_user(
        self,
        firstname: str,
        lastname: str,
        organization: str,
        email: str,
    ) -> dict:
        """Create a new ACCESS user by calling the Core API.

        Args:
            firstname: First name of the user
            lastname: Last name of the user
            organization: Organization/university of the user
            email: Email of the user

        Returns:
            Response from API

        Raises:
            httpx.HTTPStatusError: If the API call fails
        """
        new_user_data = {
            "CoPerson": {
                "co_id": str(self.coid),
                "status": "A",
                "date_of_birth": None,
                "timezone": None,
            },
            "CoGroupMember": [
                {
                    "co_group_id": "5",
                    "member": True,
                    "owner": False,
                    "valid_from": None,
                    "valid_through": None,
                    "co_group_nesting_id": None,
                },
                {
                    "co_group_id": "6",
                    "member": True,
                    "owner": False,
                    "valid_from": None,
                    "valid_through": None,
                    "co_group_nesting_id": None,
                },
            ],
            "EmailAddress": [
                {
                    "mail": email,
                    "description": None,
                    "type": "official",
                    "verified": True,
                }
            ],
            "CoPersonRole": [
                {
                    "sponsor_co_person_id": None,
                    "cou_id": None,
                    "affiliation": "affiliate",
                    "title": None,
                    "o": organization,
                    "ou": None,
                    "valid_from": None,
                    "valid_through": None,
                    "ordr": None,
                    "status": "A",
                    "manager_co_person_id": None,
                    "Address": [],
                    "AdHocAttribute": [],
                    "TelephoneNumber": [],
                }
            ],
            "Name": [
                {
                    "honorific": None,
                    "given": firstname,
                    "middle": None,
                    "family": lastname,
                    "suffix": None,
                    "type": "official",
                    "language": None,
                    "primary_name": True,
                }
            ],
            "Url": [],
            "Krb": [],
            "SshKey": [],
        }

        return await self._request(
            "POST", f"api/co/{self.coid}/core/v1/people", json=new_user_data
        )

    async def update_user(
        self,
        access_id: str,
        first_name: str | None = None,
        last_name: str | None = None,
        email: str | None = None,
        organization: str | None = None,
        time_zone: str
        | None = "UNSET",  # Use UNSET as default, since None is a valid value.
    ):
        user = await self.get_user_info(access_id)

        if first_name or last_name:
            primary_name = user.get_primary_name()
            if primary_name and first_name:
                primary_name["given"] = first_name

            if primary_name and last_name:
                primary_name["family"] = last_name

        if email:
            primary_email = user.get_primary_email(address_only=False)
            if primary_email:
                primary_email["mail"] = email
            # TODO: Do we need to handle the case where there is not a primary email?

        if organization:
            for role in user.get("CoPersonRole", []):
                # TODO: Should we check the name to make sure it matches the previous organization?
                if "affiliation" == "affiliate":
                    role["o"] = organization

        if time_zone != "UNSET":
            user["CoPerson"]["timezone"] = time_zone

        return await self._request(
            "PUT",
            f"api/co/{self.coid}/core/v1/people/{quote(access_id, safe='')}",
            json=user,
        )

    async def create_new_org_identity(self) -> str:
        """Create a new Organizational Identity for the user.

        Returns:
            The ID for the newly created Organizational Identity

        Raises:
            httpx.HTTPStatusError: If the API call fails
        """
        org_identity_data = {
            "RequestType": "OrgIdentities",
            "Version": "1.0",
            "OrgIdentities": [
                {
                    "Version": "1.0",
                    "Affiliation": None,
                    "Title": None,
                    "O": None,
                    "Ou": None,
                    "CoId": str(self.coid),
                    "ValidFrom": None,
                    "ValidThrough": None,
                    "DateOfBirth": None,
                }
            ],
        }

        result = await self._request(
            "POST", "org_identities.json", json=org_identity_data
        )
        return str(result["Id"])

    async def create_new_link(self, co_person_id: str, org_identity_id: str) -> dict:
        """Create a new link between the CoPerson record and the Organizational Identity record.

        Args:
            co_person_id: The ID of the CoPerson record
            org_identity_id: The ID of the Organizational Identity record

        Returns:
            Response from API

        Raises:
            httpx.HTTPStatusError: If the API call fails
        """
        link_data = {
            "RequestType": "CoOrgIdentityLinks",
            "Version": "1.0",
            "CoOrgIdentityLinks": [
                {
                    "Version": "1.0",
                    "CoPersonId": co_person_id,
                    "OrgIdentityId": org_identity_id,
                }
            ],
        }

        return await self._request("POST", "co_org_identity_links.json", json=link_data)

    async def create_new_name(
        self,
        firstname: str,
        lastname: str,
        org_identity_id: str,
    ) -> dict:
        """Create a new Name object to add to the Organizational Identity record.

        Args:
            firstname: First name of the user
            lastname: Last name of the user
            org_identity_id: The ID of the Organizational Identity record

        Returns:
            Response from API

        Raises:
            httpx.HTTPStatusError: If the API call fails
        """
        name_data = {
            "RequestType": "Names",
            "Version": "1.0",
            "Names": [
                {
                    "Version": "1.0",
                    "Honorific": None,
                    "Given": firstname,
                    "Middle": None,
                    "Family": lastname,
                    "Suffix": None,
                    "Type": "official",
                    "Language": "",
                    "PrimaryName": True,
                    "Person": {"Type": "Org", "Id": org_identity_id},
                }
            ],
        }

        return await self._request("POST", "names.json", json=name_data)

    async def create_new_identifier(
        self, identifier: str, type: str, login: bool, org_identity_id: str
    ) -> dict:
        """Create a new Identity object to add to the Organizational Identity record.

        Args:
            identifier: The full identifier string
            type: The identifier type (e.g., 'eppn', 'oidc', 'eppnPlusOIDC')
            login: Whether this identifier can be used for login
            org_identity_id: The ID of the Organizational Identity record

        Returns:
            Response from API

        Raises:
            httpx.HTTPStatusError: If the API call fails
        """
        identifier_data = {
            "RequestType": "Identifiers",
            "Version": "1.0",
            "Identifiers": [
                {
                    "Version": "1.0",
                    "Type": type,
                    "Identifier": identifier,
                    "Login": login,
                    "Person": {"Type": "Org", "Id": org_identity_id},
                    "Status": "Active",
                }
            ],
        }

        return await self._request("POST", "identifiers.json", json=identifier_data)

    async def create_new_tandc_agreement(
        self, co_tandc_id: int, co_person_id: int
    ) -> dict:
        """Create new Terms & Conditions Agreement for the CoPerson record.

        Args:
            co_tandc_id: The ID of the active Terms & Conditions
            co_person_id: The ID of the CoPerson record

        Returns:
            Response from API

        Raises:
            httpx.HTTPStatusError: If the API call fails
        """
        tandc_data = {
            "RequestType": "CoTAndCAgreements",
            "Version": "1.0",
            "CoTAndCAgreements": [
                {
                    "Version": "1.0",
                    "CoTermsAndConditionsId": str(co_tandc_id),
                    "Person": {"Type": "CO", "Id": str(co_person_id)},
                }
            ],
        }

        return await self._request(
            "POST", "co_t_and_c_agreements.json", json=tandc_data
        )

    # Helper methods

    async def _get_identifiers(
        self,
        access_id: str,
        cilogon_token: str | None = None,
    ):
        # Determine the identifiers we expect the new OrgIdentity to have.
        identifiers = []
        if cilogon_token:
            # Get user info from CILogon using the token
            cilogon = CILogonClient()
            cilogon_user_info = await cilogon.get_user_info(cilogon_token)

            # Create an identifier for each claim that exists in the user info
            for mapping in CLAIM_TO_IDENTIFIER_MAPPING:
                claim_key = mapping["claim"]
                if claim_key in cilogon_user_info and cilogon_user_info[claim_key]:
                    identifiers.append(
                        Identifier(
                            str(cilogon_user_info[claim_key]),
                            mapping["type"],
                            mapping["login"],
                        )
                    )

        else:
            # Create a single ePPN identifier with login=True
            identifiers.append(Identifier(f"{access_id}@access-ci.org", "eppn", True))

        return identifiers

    async def _get_user(self, access_id: str):
        """Get the user info for the ACCESS ID."""
        user = await self.get_user_info(access_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not find a user with ACCESS ID: ${access_id}",
            )
        return user

    # High-level methods

    async def check_account_does_not_exist(self, email: str):
        """Check that a user account for the given email does not already exist.

        Args:
            email: The user's email address

        Returns:
            The existing ACCESS ID

        Raises:
            HTTPException: If the account already exists.
        """
        existing_access_id = await self.get_access_id_for_email(email)
        if existing_access_id:
            logger.warning(
                f"Account creation failed: email {email} already has ACCESS ID {existing_access_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"An ACCESS account already exists for email {email}",
            )
        return existing_access_id

    async def check_active_tandc_exists(self):
        active_tandc = await self.get_active_tandc()
        if not active_tandc:
            logger.error("No active terms and conditions found")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No active terms and conditions available",
            )
        return active_tandc

    async def create_linked_identity(
        self,
        co_person_id: str,
        access_id: str,
        cilogon_token: str | None = None,
    ):
        # Determine the identifiers we expect the new OrgIdentity to have.
        [identifiers, user] = await gather(
            self._get_identifiers(access_id, cilogon_token), self._get_user(access_id)
        )

        primary_name = user.get_primary_name()
        if not primary_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User ${access_id} does not have a primary name",
            )

        # Check to make sure the identifiers don't already exist:
        for identifier in identifiers:
            if user.has_org_identity(identifier):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Identifier already exists: ${identifier.identifier}",
                )

        # Create an OrgIdentity record
        org_identity_id = await self.create_new_org_identity()

        # Link the OrgIdentity to the CoPerson
        await self.create_new_link(co_person_id, org_identity_id)

        # In parallel:
        # - Create a Name record
        # - Create the desired Identifier records
        identifier_creation = []
        for identifier in identifiers:
            identifier_creation.append(
                self.create_new_identifier(
                    identifier=identifier.identifier,
                    type=identifier.type,
                    login=identifier.login,
                    org_identity_id=org_identity_id,
                )
            )

        await gather(
            self.create_new_name(
                firstname=primary_name["given"],
                lastname=primary_name["family"],
                org_identity_id=org_identity_id,
            ),
            *identifier_creation,
        )
