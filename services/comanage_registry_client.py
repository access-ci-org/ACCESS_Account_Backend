import logging
from asyncio import gather
from collections import namedtuple
from urllib.parse import quote, urlencode

from fastapi import HTTPException, status

from config import (
    CILOGON_LINK_CLIENT_ID,
    COMANAGE_REGISTRY_BASE_URL,
    COMANAGE_REGISTRY_COID,
    COMANAGE_REGISTRY_KRB_AUTH_ID,
    COMANAGE_REGISTRY_PASSWORD,
    COMANAGE_REGISTRY_TIMEOUT,
    COMANAGE_REGISTRY_USER,
)
from services.cilogon_client import get_token_user_info
from services.rest_client import RestClient

# Map CILogon claims to identifier types and login status
# Based on the CILogon -> CoManage identifier mapping
CLAIM_TO_IDENTIFIER_MAPPING = [
    {"claim": "eppn", "type": "eppn", "login": True},
    {"claim": "eptid", "type": "eptid", "login": False},
    {"claim": "epuid", "type": "epuid", "login": False},
    {"claim": "sub", "type": "oidcsub", "login": True},
    {"claim": "orcid", "type": "orcid", "login": False},
    {"claim": "pairwise_id", "type": "pairwiseid", "login": False},
    {"claim": "subject_id", "type": "subjectid", "login": False},
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

    def get_recovery_emails(self) -> list[dict]:
        """Get the recovery (non-primary) email addresses.

        A recovery email is any non-deleted EmailAddress that is not the primary
        (the first non-deleted "official" address). This surfaces any additional
        addresses on the record regardless of their CoManage type.
        """
        primary = self.get_primary_email(address_only=False)
        primary_id = primary["meta"]["id"] if primary else None
        recoveries = []
        for email in self.get("EmailAddress", []):
            if email["meta"]["deleted"]:
                continue
            if primary_id is not None and email["meta"]["id"] == primary_id:
                continue
            recoveries.append(email)
        return recoveries

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


class CoManageRegistryClient(RestClient):
    def __init__(
        self,
        base_url=COMANAGE_REGISTRY_BASE_URL,
        username=COMANAGE_REGISTRY_USER,
        password=COMANAGE_REGISTRY_PASSWORD,
        coid=COMANAGE_REGISTRY_COID,
        krb_auth_id=COMANAGE_REGISTRY_KRB_AUTH_ID,
        timeout=COMANAGE_REGISTRY_TIMEOUT,
        propagate_errors=False,
    ):
        super().__init__(
            username=username,
            password=password,
            timeout=timeout,
            propagate_errors=propagate_errors,
        )
        self.base_url = base_url
        self.coid = coid
        self.krb_auth_id = krb_auth_id

    async def _request(
        self, method: str, path: str, json: dict | None = None
    ) -> dict | list | None:
        url = f"{self.base_url}/registry/{path}"
        return await self.request(url, method=method, json=json)

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
        emails: list[dict] | None = None,
        organization: str | None = None,
        time_zone: str
        | None = "UNSET",  # Use UNSET as default, since None is a valid value.
        user: CoManageUser | None = None,
    ):
        if user is None:
            user = await self.get_user_info(access_id)

        if first_name or last_name:
            primary_name = user.get_primary_name()
            if primary_name and first_name:
                primary_name["given"] = first_name

            if primary_name and last_name:
                primary_name["family"] = last_name

        if emails is not None:
            self._reconcile_email_addresses(user, emails)

        if organization:
            for role in user.get("CoPersonRole", []):
                # TODO: Should we check the name to make sure it matches the previous organization?
                if role["affiliation"] == "affiliate":
                    role["o"] = organization

        if time_zone != "UNSET":
            user["CoPerson"]["timezone"] = time_zone

        return await self._request(
            "PUT",
            f"api/co/{self.coid}/core/v1/people/{quote(access_id, safe='')}",
            json=user,
        )

    @staticmethod
    def _reconcile_email_addresses(user: "CoManageUser", emails: list[dict]) -> None:
        """Reconcile the user's EmailAddress list against the desired set in place.

        ``emails`` is the full desired set of addresses, each item being
        ``{"mail": str, "primary": bool}`` (addresses already normalized and, for
        new addresses, already OTP-verified upstream). The desired primary is
        written as ``type == "official"``; all other desired addresses as
        ``type == "delivery"``. Existing non-deleted addresses not in the desired
        set are marked deleted. New addresses are appended. Matching is done
        case-insensitively on ``mail``, consuming desired entries one-to-one so
        legacy duplicate addresses are collapsed rather than duplicated.
        """

        def desired_type(is_primary: bool) -> str:
            return "official" if is_primary else "delivery"

        # Desired addresses, with a flag tracking whether each has been matched to
        # an existing row (consumed one-to-one).
        desired = [
            {"mail": e["mail"].lower(), "primary": e["primary"], "consumed": False}
            for e in emails
        ]

        existing = user.setdefault("EmailAddress", [])
        for entry in existing:
            if entry["meta"]["deleted"]:
                continue
            match = next(
                (
                    d
                    for d in desired
                    if not d["consumed"] and d["mail"] == entry["mail"].lower()
                ),
                None,
            )
            if match is not None:
                entry["type"] = desired_type(match["primary"])
                # Preserve the existing verified flag for addresses already on the
                # record; only newly added (OTP-verified) addresses are marked True.
                match["consumed"] = True
            else:
                entry["meta"]["deleted"] = True

        # Append any desired addresses that were not already present.
        for d in desired:
            if d["consumed"]:
                continue
            existing.append(
                {
                    "mail": d["mail"],
                    "description": None,
                    "type": desired_type(d["primary"]),
                    "verified": True,
                }
            )

    async def create_new_org_identity(self, organization: str | None = None) -> str:
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
                    "O": organization,
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
        self, identifier: str, type: str, login: bool, linked_type: str, linked_id: str
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
                    "Person": {"Type": linked_type, "Id": linked_id},
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

    def _get_identifiers(
        self,
        access_id: str,
        cilogon_user_info: dict | None = None,
    ):
        # Determine the identifiers we expect the new OrgIdentity to have.
        identifiers = []
        if cilogon_user_info:
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
        async def get_cilogon_user_info():
            if cilogon_token:
                return await get_token_user_info(
                    cilogon_token,
                    CILOGON_LINK_CLIENT_ID,
                    status.HTTP_400_BAD_REQUEST,
                )
            return None

        [cilogon_user_info, user] = await gather(
            get_cilogon_user_info(), self._get_user(access_id)
        )

        # Determine the identifiers we expect the new OrgIdentity to have.
        identifiers = self._get_identifiers(access_id, cilogon_user_info)

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
        org_identity_id = await self.create_new_org_identity(
            cilogon_user_info.get("idp_name", None) if cilogon_user_info else None
        )

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
                    linked_type="Org",
                    linked_id=org_identity_id,
                )
            )

            # If this is not the ACCESS IdP, also add the identifiers to the CoPerson record.
            # (Identifiers for the ACCESS IdP are added to the CoPerson automatically.)
            if cilogon_token:
                identifier_creation.append(
                    self.create_new_identifier(
                        identifier=identifier.identifier,
                        type=identifier.type,
                        login=identifier.login,
                        linked_type="CO",
                        linked_id=co_person_id,
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

    async def get_co_person_id_for_accessid(self, accessid: str) -> str | None:
        """Return the CoPersonId (string instead of dict) associated with an ACCESS ID."""
        encoded_accessid = quote(accessid)
        result = await self._request(
            "GET",
            f"co_people.json?coid={self.coid}&search.identifier={encoded_accessid}",
        )

        if isinstance(result, dict) and "CoPeople" in result:
            co_people = result["CoPeople"]
            if co_people and len(co_people) > 0:
                return str(co_people[0]["Id"])

        return None

    async def delete_identifier(self, identifier_id: str | int):
        """Delete an Identifier record by ID"""
        return await self._request(
            "DELETE",
            f"identifiers/{identifier_id}.json",
        )

    async def get_org_identity_links(self, org_identity_id: str | int) -> list[dict]:
        """Gets all CoOrgIdenitity Link records given an OrgIdentity ID"""
        result = await self._request(
            "GET", f"co_org_identity_links.json?orgidentityid={org_identity_id}"
        )

        if isinstance(result, dict) and "CoOrgIdentityLinks" in result:
            return result.get("CoOrgIdentityLinks") or []
        return []

    async def delete_org_identity_link(self, link_id: str):
        """Delete an OrgIdentity record by Link ID"""
        return await self._request(
            "DELETE",
            f"co_org_identity_links/{link_id}.json",
        )

    async def delete_org_identity(self, identity_id: str | int):
        """Delete an OrgIdentity record by ID"""
        return await self._request(
            "DELETE",
            f"org_identities/{identity_id}.json",
        )

    async def add_ssh_key_for_user(self, accessid: str, public_key: str) -> dict:
        """Adds SSH Key for the CoPerson record."""
        # Gets user id
        coperson_id = await self.get_co_person_id_for_accessid(accessid)
        if not coperson_id:
            raise HTTPException(status_code=404, detail="User not found.")

        # Get SSH Key type
        public_key = public_key.strip()
        if not public_key:
            raise HTTPException(status_code=400, detail="Public key cannot be empty.")
        ssh_parts = public_key.split()
        if len(ssh_parts) < 2:
            raise HTTPException(
                status_code=400, detail="Invalid SSH public key format."
            )
        key_type = ssh_parts[0]
        key_value = ssh_parts[1]
        comment = " ".join(ssh_parts[2:]) if len(ssh_parts) > 2 else None

        allowed_key_types = [
            "ssh-rsa",
            "ssh-dss",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "ssh-ed25519",
        ]

        if key_type not in allowed_key_types:
            raise HTTPException(status_code=400, detail="Invalid SSH key type.")

        # Creating json response data
        data = {
            "RequestType": "SshKeys",
            "Version": "1.0",
            "SshKeys": [
                {
                    "Version": "1.0",
                    "Person": {"Type": "CO", "Id": str(coperson_id)},
                    "Type": key_type,
                    "Skey": key_value,
                    "Comment": comment,
                    "SshKeyAuthenticatorId": "1",
                }
            ],
        }

        return await self._request(
            "POST",
            f"ssh_key_authenticator/ssh_keys.json?coid={self.coid}",
            json=data,
        )

    async def get_ssh_keys_for_user(self, accessid: str) -> list[dict]:
        """Helper method to get all SSH keys for a user."""

        coperson_id = await self.get_co_person_id_for_accessid(accessid)
        if not coperson_id:
            raise HTTPException(status_code=404, detail="User not found.")

        # List keys for this CO Person
        result = await self._request(
            "GET",
            f"ssh_key_authenticator/ssh_keys.json?coid={self.coid}&copersonid={coperson_id}",
        )

        if isinstance(result, dict) and "SshKeys" in result:
            return result.get("SshKeys") or []

        return []

    async def delete_ssh_key_for_user(self, accessid: str, key_id: int) -> str:
        """Deletes SSH Key from the CoPerson record."""
        # Validates key_id
        if not key_id:
            raise HTTPException(status_code=400, detail="Key ID is required.")

        # Gets keys from user
        ssh_keys = await self.get_ssh_keys_for_user(accessid)
        # Checks if key exists for user before deleting
        key_exists_for_user = any(str(key.get("Id")) == str(key_id) for key in ssh_keys)
        # If key does not exist, raise 404 error
        if not key_exists_for_user:
            raise HTTPException(
                status_code=404, detail="The requested key does not exist."
            )

        return await self._request(
            "DELETE",
            f"ssh_key_authenticator/ssh_keys/{key_id}.json?coid={self.coid}",
        )

    async def get_krb_id_for_user(self, coperson_id: str) -> str | None:
        """Return the Krb row ID for a given CO Person under this instance's KrbAuthenticator."""

        result = await self._request(
            "GET",
            f"krb_authenticator/krbs.json?krbauthid={self.krb_auth_id}&copersonid={coperson_id}",
        )

        if isinstance(result, dict) and "Krbs" in result:
            krbs = result.get("Krbs") or []
            if krbs:
                return str(krbs[0]["Id"])

        return None

    async def update_password_for_user(
        self, coperson_id: str, new_password: str
    ) -> dict | None:
        """Set or update the Kerberos password for a CO Person via the KrbAuthenticator REST API.

        Follows the documented V1 workflow: GET existing row, then POST (new) or PUT (existing).
        """

        krb_id = await self.get_krb_id_for_user(coperson_id)

        if krb_id:
            data = {
                "Krbs": [
                    {
                        "Version": "1.0",
                        "Password": new_password,
                        "Password2": new_password,
                    }
                ]
            }
            return await self._request(
                "PUT",
                f"krb_authenticator/krbs/{krb_id}.json",
                json=data,
            )
        else:
            data = {
                "Krbs": [
                    {
                        "Version": "1.0",
                        "KrbAuthenticatorId": self.krb_auth_id,
                        "Person": {"Type": "CO", "Id": int(coperson_id)},
                        "Password": new_password,
                        "Password2": new_password,
                    }
                ]
            }
            return await self._request(
                "POST",
                "krb_authenticator/krbs.json",
                json=data,
            )
