from urllib.parse import quote

import httpx

from config import (
    COMANAGE_REGISTRY_BASE_URL,
    COMANAGE_REGISTRY_PASSWORD,
    COMANAGE_REGISTRY_USER,
)


class COManageRegistryClient:
    def __init__(
        self,
        base_url=COMANAGE_REGISTRY_BASE_URL,
        username=COMANAGE_REGISTRY_USER,
        password=COMANAGE_REGISTRY_PASSWORD,
    ):
        self.base_url = base_url
        self.username = username
        self.password = password

    async def _request(
        self, method: str, path: str, json: dict | None = None
    ) -> dict | list:
        url = f"{self.base_url}/registry/{path}"
        auth = httpx.BasicAuth(username=self.username, password=self.password)
        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        async with httpx.AsyncClient(auth=auth) as client:
            resp = await client.request(method, url, headers=headers, json=json)
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
            "GET", f"co_people.json?coid=2&search.mail={encoded_email}"
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

    async def get_user_info(self, accessid: str) -> dict:
        """Get full user info for a given ACCESS ID.

        Args:
            accessid: The ACCESS ID to search for

        Returns:
            Dictionary containing user information
        """
        return await self._request("GET", f"api/co/2/core/v1/people/{accessid}")

    async def get_active_tandc_id(self) -> str | None:
        """Return the ID of the first active Terms and Conditions element.

        Returns:
            ID of active Terms and Conditions, or None if not found
        """
        result = await self._request("GET", "co_terms_and_conditions.json?coid=2")

        if isinstance(result, dict) and "CoTermsAndConditions" in result:
            for tandc in result["CoTermsAndConditions"]:
                if tandc.get("Status") == "Active":
                    return str(tandc["Id"])

        return None

    async def create_new_user(
        self,
        firstname: str,
        middlename: str | None,
        lastname: str,
        organization: str,
        email: str,
    ) -> dict:
        """Create a new ACCESS user by calling the Core API.

        Args:
            firstname: First name of the user
            middlename: Middle name of the user (can be None)
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
                "co_id": "2",
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
                    "middle": middlename,
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
            "POST", "api/co/2/core/v1/people", json=new_user_data
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
                    "CoId": "2",
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
        middlename: str | None,
        lastname: str,
        org_identity_id: str,
    ) -> dict:
        """Create a new Name object to add to the Organizational Identity record.

        Args:
            firstname: First name of the user
            middlename: Middle name of the user (can be None)
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
                    "Middle": middlename,
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

    async def create_new_identifier(self, accessid: str, org_identity_id: str) -> dict:
        """Create a new Identity object of type ePPN to add to the Organizational Identity record.

        Args:
            accessid: ACCESS ID of the user
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
                    "Type": "eppn",
                    "Identifier": f"{accessid}@access-ci.org",
                    "Login": True,
                    "Person": {"Type": "Org", "Id": org_identity_id},
                    "Status": "Active",
                }
            ],
        }

        return await self._request("POST", "identifiers.json", json=identifier_data)

    async def create_new_tandc(self, co_tandc_id: str, co_person_id: str) -> dict:
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
                    "CoTermsAndConditionsId": co_tandc_id,
                    "Person": {"Type": "CO", "Id": co_person_id},
                }
            ],
        }

        return await self._request(
            "POST", "co_t_and_c_agreements.json", json=tandc_data
        )
