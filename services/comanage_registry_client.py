import logging
import random
from asyncio import gather, sleep
from collections import namedtuple
from typing import Literal, overload
from urllib.parse import quote, urlencode

from fastapi import HTTPException, status

from config import (
    CILOGON_LINK_CLIENT_ID,
    COMANAGE_REGISTRY_BASE_URL,
    COMANAGE_REGISTRY_COID,
    COMANAGE_REGISTRY_CREATE_PERSON_RETRIES,
    COMANAGE_REGISTRY_KRB_AUTH_ID,
    COMANAGE_REGISTRY_PASSWORD,
    COMANAGE_REGISTRY_TIMEOUT,
    COMANAGE_REGISTRY_USER,
)
from services.async_utils import gather_all
from services.cilogon_client import get_token_user_info
from services.logs_service import obfuscate_email, record_exception
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

# How long to wait before looking again for a CoPerson that a timed-out create
# may still be making.
CREATED_PERSON_RECHECK_SECONDS = 5


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

    @overload
    def get_primary_email(self, address_only: Literal[True] = True) -> str | None: ...
    @overload
    def get_primary_email(self, address_only: Literal[False]) -> dict | None: ...
    def get_primary_email(self, address_only: bool = True) -> str | dict | None:
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
            password=str(password),
            timeout=timeout,
            propagate_errors=propagate_errors,
        )
        self.base_url = base_url
        self.coid = coid
        self.krb_auth_id = krb_auth_id

    async def _request(
        self,
        method: str,
        path: str,
        json: dict | None = None,
    ) -> dict | list | None:
        url = f"{self.base_url}/registry/{path}"
        return await self.request(url, method=method, json=json)

    @staticmethod
    def _active_co_person_id(result: dict | list | None) -> str | None:
        """Return the Id of the first Active CoPerson in a co_people.json response.

        Args:
            result: Parsed response body from a co_people.json request

        Returns:
            CoPersonId of the first CoPerson with status "Active", or None if the
            response holds no active CoPerson.
        """
        if isinstance(result, dict) and "CoPeople" in result:
            active_co_people = [
                cp for cp in result["CoPeople"] or [] if cp.get("Status") == "Active"
            ]
            if active_co_people:
                return str(active_co_people[0]["Id"])

        return None

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

        return self._active_co_person_id(result)

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
        response = await self._request(
            "GET", f"api/co/{self.coid}/core/v1/people/{quote(accessid, safe='')}"
        )

        if not response:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Could not find a user with ACCESS ID: {accessid}",
            )

        user_info = CoManageUser(self._expect(response, dict))

        if not user_info["CoPerson"]["status"] == "A":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"ACCESS ID is not active: {accessid}",
            )

        return user_info

    async def ping(self) -> int:
        """Make a lightweight request and return the HTTP status code."""
        params = {"coid": self.coid}
        url = (
            f"{self.base_url}/registry/co_terms_and_conditions.json?{urlencode(params)}"
        )
        return await self.request_status(url)

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
    ) -> list[dict]:
        """Create a new ACCESS user by calling the Core API.

        Args:
            firstname: First name of the user
            lastname: Last name of the user
            organization: Organization/university of the user
            email: Email of the user

        Returns:
            The list of identifiers provisioned for the new CoPerson

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

        # When two person creates run at the same time, CoManage can fail one of
        # them during identifier assignment, roll it back, and still return 201
        # with an empty list. Nothing is created, so it's safe to try again.
        attempts = COMANAGE_REGISTRY_CREATE_PERSON_RETRIES + 1
        attempt = 0
        while True:
            attempt += 1
            try:
                result = await self._request(
                    "POST", f"api/co/{self.coid}/core/v1/people", json=new_user_data
                )
            except HTTPException as exc:
                if exc.status_code != status.HTTP_503_SERVICE_UNAVAILABLE:
                    raise
                # A timeout doesn't mean the create failed: CoManage may finish it
                # after we stop waiting. If it did, carry on with that CoPerson so
                # the user isn't left with an account they can't finish creating.
                identifiers = await self._find_created_person(email)
                if identifiers is None:
                    raise
                return identifiers
            # A malformed response here means we can't complete account creation
            # for this request, so surface it as a 400 rather than a 502 the way
            # other CoManage response-shape guards do.
            result = self._expect(result, list, status_code=400)
            if result != []:
                return result

            # Make sure nothing was created before retrying, so a retry can't
            # make a duplicate account.
            if await self.get_co_person_id_for_email(email):
                logger.error(
                    f"Core API person create for {obfuscate_email(email)} returned "
                    "no identifiers, but a CoPerson was created; not retrying"
                )
                return result
            if attempt == attempts:
                logger.error(
                    f"Core API person create for {obfuscate_email(email)} failed "
                    f"{attempts} times due to concurrent creates; giving up"
                )
                return result

            logger.warning(
                f"Core API person create for {obfuscate_email(email)} failed due to "
                "a concurrent create (201 with no identifiers, nothing created); "
                f"retrying ({attempt} of {COMANAGE_REGISTRY_CREATE_PERSON_RETRIES})"
            )
            # A random wait keeps two failed creates from retrying in lockstep.
            await sleep(random.uniform(0.5, 1.5))

    async def _find_created_person(self, email: str) -> list[dict] | None:
        """Look for a CoPerson that a timed-out create made after all.

        Checks once right away and once more after a short wait, in case
        CoManage is still finishing the create.

        Returns:
            The new CoPerson's ACCESS ID in the shape the Core API create returns,
            or None if no CoPerson with an ACCESS ID was found.
        """
        access_id = await self.get_access_id_for_email(email)
        if not access_id:
            await sleep(CREATED_PERSON_RECHECK_SECONDS)
            access_id = await self.get_access_id_for_email(email)
        if not access_id:
            logger.error(
                f"Core API person create for {obfuscate_email(email)} failed (timed "
                "out or CoManage unavailable) and no CoPerson was found for it"
            )
            return None

        logger.warning(
            f"Core API person create for {obfuscate_email(email)} failed (timed "
            f"out or CoManage unavailable), but CoPerson {access_id} was created; "
            "continuing with it"
        )
        return [{"identifier": access_id, "type": "accessid"}]

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

        removed_email_ids: list = []
        if emails is not None:
            removed_email_ids = self._reconcile_email_addresses(user, emails)

        if organization:
            for role in user.get("CoPersonRole", []):
                # TODO: Should we check the name to make sure it matches the previous organization?
                if role["affiliation"] == "affiliate":
                    role["o"] = organization

        if time_zone != "UNSET":
            user["CoPerson"]["timezone"] = time_zone

        response = await self._request(
            "PUT",
            f"api/co/{self.coid}/core/v1/people/{quote(access_id, safe='')}",
            json=user,
        )

        # The Core API PUT does not delete EmailAddress rows on its own (unlike
        # updates/creates, which it does honor), so removed addresses have to be
        # deleted individually via the legacy REST endpoint, same as Identifier/
        # OrgIdentity/SshKey elsewhere in this client.
        for email_id in removed_email_ids:
            await self.delete_email_address(email_id)

        return response

    @staticmethod
    def _reconcile_email_addresses(user: "CoManageUser", emails: list[dict]) -> list:
        """Reconcile the user's EmailAddress list against the desired set in place.

        ``emails`` is the full desired set of addresses, each item being
        ``{"mail": str, "primary": bool}`` (addresses already normalized and, for
        new addresses, already OTP-verified upstream). The desired primary is
        written as ``type == "official"``; all other desired addresses as
        ``type == "delivery"``. Existing non-deleted addresses not in the desired
        set are dropped from ``user`` and their ids are returned so the caller can
        issue a follow-up delete request for each. New addresses are appended.
        Matching is done case-insensitively on ``mail``, consuming desired entries
        one-to-one so legacy duplicate addresses are collapsed rather than
        duplicated.
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
        kept = []
        removed_ids = []
        for entry in existing:
            if entry["meta"]["deleted"]:
                kept.append(entry)
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
                kept.append(entry)
            else:
                removed_ids.append(entry["meta"]["id"])

        # Append any desired addresses that were not already present.
        for d in desired:
            if d["consumed"]:
                continue
            kept.append(
                {
                    "mail": d["mail"],
                    "description": None,
                    "type": desired_type(d["primary"]),
                    "verified": True,
                }
            )

        user["EmailAddress"] = kept
        return removed_ids

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

        result = self._expect(
            await self._request("POST", "org_identities.json", json=org_identity_data),
            dict,
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

        return self._expect(
            await self._request("POST", "co_org_identity_links.json", json=link_data),
            dict,
        )

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

        return self._expect(
            await self._request("POST", "names.json", json=name_data), dict
        )

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

        try:
            response = await self._request(
                "POST", "identifiers.json", json=identifier_data
            )
        except HTTPException as exc:
            if exc.status_code != status.HTTP_403_FORBIDDEN:
                raise
            # CoManage answers 403 when an Identifier of this type and value
            # already exists on a CoPerson; `check_cilogon_identifiers_available`
            # should have caught that, so keep CoManage's response for debugging.
            # Don't pass the 403 on: to the frontend it means the JWT is invalid.
            record_exception(
                f"CoManage rejected {type} Identifier {identifier}: {exc.detail}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"The {type} identifier {identifier} could not be added. "
                "It may already be linked to another ACCESS account",
            ) from exc

        return self._expect(response, dict)

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

        return self._expect(
            await self._request("POST", "co_t_and_c_agreements.json", json=tandc_data),
            dict,
        )

    # Helper methods

    def _get_identifiers(
        self,
        access_id: str,
        cilogon_user_info: dict | None = None,
    ):
        # Determine the identifiers we expect the new OrgIdentity to have.
        if cilogon_user_info:
            return self._get_cilogon_identifiers(cilogon_user_info)

        # Create a single ePPN identifier with login=True
        return [Identifier(f"{access_id}@access-ci.org", "eppn", True)]

    @staticmethod
    def _get_cilogon_identifiers(cilogon_user_info: dict) -> list[Identifier]:
        # Create an identifier for each claim that exists in the user info
        identifiers = []
        for mapping in CLAIM_TO_IDENTIFIER_MAPPING:
            claim_key = mapping["claim"]
            if cilogon_user_info.get(claim_key):
                identifiers.append(
                    Identifier(
                        str(cilogon_user_info[claim_key]),
                        mapping["type"],
                        mapping["login"],
                    )
                )
        return identifiers

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
                f"Account creation failed: email {obfuscate_email(email)} already has ACCESS ID {existing_access_id}"
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

    async def check_cilogon_identifiers_available(
        self, cilogon_token: str | None, co_person_id: str | None = None
    ):
        """Check that no CoPerson already has the identifiers from a CILogon login.

        `create_linked_identity` copies these identifiers onto the CoPerson, and
        CoManage rejects an Identifier whose type and value already exist on any
        CoPerson in the CO, whatever that person's status, with a 403 -- by which
        point the OrgIdentity, its link and possibly other Identifiers have been
        created. Run this first to fail cleanly instead.

        Args:
            cilogon_token: Access token from the CILogon link client. If None,
                there is nothing to check.
            co_person_id: CoPerson the login is being linked to, if it exists yet

        Raises:
            HTTPException: 400 if any of the identifiers is already in use.
        """
        if not cilogon_token:
            return

        cilogon_user_info = await get_token_user_info(
            cilogon_token, CILOGON_LINK_CLIENT_ID, status.HTTP_400_BAD_REQUEST
        )
        identifiers = self._get_cilogon_identifiers(cilogon_user_info)

        # Exact match on the identifier value, of any type, across all CoPeople
        # regardless of status (unlike the browser's LIKE search).
        searches = await gather(
            *(
                self._request(
                    "GET",
                    f"co_people.json?coid={self.coid}"
                    f"&search.identifier={quote(identifier.identifier, safe='')}",
                )
                for identifier in identifiers
            )
        )
        candidates: dict[str, str] = {}
        for result in searches:
            if isinstance(result, dict):
                for co_person in result.get("CoPeople") or []:
                    candidates[str(co_person["Id"])] = co_person.get("Status", "")
        if not candidates:
            return

        # The search ignores the type, so check each candidate's Identifiers.
        candidate_ids = list(candidates)
        candidate_identifiers = await gather(
            *(
                self._request("GET", f"identifiers.json?copersonid={candidate_id}")
                for candidate_id in candidate_ids
            )
        )
        for candidate_id, result in zip(candidate_ids, candidate_identifiers):
            existing = (
                result.get("Identifiers") or [] if isinstance(result, dict) else []
            )
            in_use = [
                identifier
                for identifier in identifiers
                if any(
                    e.get("Type") == identifier.type
                    and e.get("Identifier") == identifier.identifier
                    for e in existing
                )
            ]
            if not in_use:
                continue

            login = f"Your {cilogon_user_info.get('idp_name') or 'CILogon'} login"
            # The frontend turns "open a help ticket" into its help ticket link.
            if candidate_id == co_person_id:
                detail = f"{login} is already linked to this ACCESS account."
            else:
                access_id = next(
                    (
                        e.get("Identifier")
                        for e in existing
                        if e.get("Type") == "accessid"
                    ),
                    None,
                )
                if not access_id:
                    detail = (
                        f"{login} is already linked to another ACCESS account. "
                        "Please open a help ticket."
                    )
                elif candidates[candidate_id] != "Active":
                    detail = (
                        f"{login} is already linked to ACCESS account {access_id}, "
                        "which is not active. Please open a help ticket."
                    )
                elif co_person_id:
                    # A logged-in user is linking a login from another account.
                    detail = (
                        f"{login} is already linked to ACCESS account {access_id}. "
                        "If you believe that account is a duplicate of yours, "
                        "please open a help ticket."
                    )
                else:
                    detail = (
                        f"{login} is already linked to ACCESS account {access_id}. "
                        "Please log in with that account, or open a help ticket "
                        "if you need help."
                    )
            logger.warning(
                f"CILogon identifiers {[i.type for i in in_use]} already in use by "
                f"CoPerson {candidate_id} ({candidates[candidate_id]})"
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

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
            get_cilogon_user_info(), self.get_user_info(access_id)
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

        await gather_all(
            self.create_new_name(
                firstname=primary_name["given"],
                lastname=primary_name["family"],
                org_identity_id=org_identity_id,
            ),
            *identifier_creation,
        )

    async def get_co_person_id_for_accessid(self, accessid: str) -> str:
        """Return the CoPersonId (string instead of dict) associated with an ACCESS ID.

        Raises:
            HTTPException: 404 if no user has this ACCESS ID, 400 if they are inactive
        """
        # Use the Core API to get the user by ACCESS ID. The REST API's
        # /co_people.<format>?coid=<id>&search.identifier=<identifier> endpoint does
        # a wildcard search on all identifier types, which can lead to incorrect matches.
        user = await self.get_user_info(accessid)
        return str(user["CoPerson"]["meta"]["id"])

    async def delete_identifier(self, identifier_id: str | int):
        """Delete an Identifier record by ID"""
        return await self._request(
            "DELETE",
            f"identifiers/{identifier_id}.json",
        )

    async def delete_email_address(self, email_address_id: str | int):
        """Delete an EmailAddress record by ID.

        The registry returns 404 on this endpoint even when the delete
        succeeds (confirmed against the live instance, contrary to the
        published API docs). Treat 404 as success rather than letting it
        propagate and fail the enclosing profile update.
        """
        try:
            return await self._request(
                "DELETE",
                f"email_addresses/{email_address_id}.json",
            )
        except HTTPException as exc:
            if exc.status_code == status.HTTP_404_NOT_FOUND:
                return None
            raise

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

        return self._expect(
            await self._request(
                "POST",
                f"ssh_key_authenticator/ssh_keys.json?coid={self.coid}",
                json=data,
            ),
            dict,
        )

    async def get_ssh_keys_for_user(self, accessid: str) -> list[dict]:
        """Helper method to get all SSH keys for a user."""

        coperson_id = await self.get_co_person_id_for_accessid(accessid)

        # List keys for this CO Person
        result = await self._request(
            "GET",
            f"ssh_key_authenticator/ssh_keys.json?coid={self.coid}&copersonid={coperson_id}",
        )

        if isinstance(result, dict) and "SshKeys" in result:
            return result.get("SshKeys") or []

        return []

    async def delete_ssh_key_for_user(self, accessid: str, key_id: int):
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
    ) -> dict:
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
            return self._expect(
                await self._request(
                    "PUT",
                    f"krb_authenticator/krbs/{krb_id}.json",
                    json=data,
                ),
                dict,
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
            return self._expect(
                await self._request(
                    "POST",
                    "krb_authenticator/krbs.json",
                    json=data,
                ),
                dict,
            )
