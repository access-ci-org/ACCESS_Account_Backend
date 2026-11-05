"""Consistency checks for an ACCESS account's CoManage and Identity Service records.

Used by the `account --verify` CLI command. A complete account matches one of
two registration patterns:

- Registered without an existing identity: the user can only log in with their
  ACCESS ID, so the CoPerson has a single OrgIdentity, for the ACCESS IdP, with
  a login eppn of <ACCESS ID>@access-ci.org.
- Registered with an existing identity: the user also logs in through another
  IdP via CILogon (registering with it or linking it later), which adds an
  OrgIdentity per IdP with a login oidcsub Identifier. Its Identifiers are also
  copied onto the CoPerson.

What the patterns require fails a check. Anything that only differs from what
this app's linking creates is a warning, since accounts made by the older
CILogon enrollment flow look different (e.g. they have a sorid, "System of
Record ID", Identifier equal to the oidcsub, and no organization).

Everything here is pure: callers fetch the records and pass them in.
"""

from dataclasses import dataclass, field
from enum import StrEnum

from services.comanage_registry_client import (
    CLAIM_TO_IDENTIFIER_MAPPING,
    CoManageUser,
)

ACCESS_IDP_DOMAIN = "access-ci.org"

# CoGroups every new CoPerson is added to by `create_new_user`.
REQUIRED_CO_GROUP_IDS = ("5", "6")

PATTERN_WITHOUT_EXISTING = "registered without an existing identity"
PATTERN_WITH_EXISTING = "registered with an existing identity"

# Login flag CILogon-derived identifiers are created with, by type.
CILOGON_IDENTIFIER_LOGIN = {m["type"]: m["login"] for m in CLAIM_TO_IDENTIFIER_MAPPING}

# Identifier types expected on a non-ACCESS OrgIdentity: what CILogon linking
# creates, plus the System of Record ID left by the older enrollment flow.
EXTERNAL_IDENTIFIER_TYPES = set(CILOGON_IDENTIFIER_LOGIN) | {"sorid"}

# Sections whose failures mean the CoManage records match neither pattern.
PROFILE_FIELDS_SECTION = "Profile fields"
PROFILE_CONSISTENCY_SECTION = "Profile consistency"
CO_PERSON_SECTION = "CoPerson"
PATTERN_SECTION = "Registration pattern"


class Status(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    SKIPPED = "SKIPPED"


@dataclass
class Check:
    section: str
    name: str
    status: Status
    # Why the check didn't pass.
    detail: str | None = None


@dataclass
class VerificationResult:
    checks: list[Check] = field(default_factory=list)
    # Which pattern the CoManage structure matches, or None if it matches neither.
    pattern: str | None = None

    def with_status(self, status: Status) -> list[Check]:
        return [c for c in self.checks if c.status == status]

    @property
    def failed(self) -> bool:
        return bool(self.with_status(Status.FAILED))


class _Checks:
    """Collects checks, grouped by the section most recently started."""

    def __init__(self):
        self.checks: list[Check] = []
        self.section = ""

    def check(
        self,
        name: str,
        passed: bool,
        detail: str | None = None,
        *,
        failure: Status = Status.FAILED,
    ) -> bool:
        self.checks.append(
            Check(
                self.section,
                name,
                Status.PASSED if passed else failure,
                None if passed else detail,
            )
        )
        return passed

    def warn_unless(self, name: str, passed: bool, detail: str | None = None):
        return self.check(name, passed, detail, failure=Status.WARNING)

    def skip(self, name: str, detail: str):
        self.checks.append(Check(self.section, name, Status.SKIPPED, detail))


def _active(records: list[dict] | None) -> list[dict]:
    return [r for r in records or [] if not (r.get("meta") or {}).get("deleted")]


def _blank(value) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _identifier_label(identifier: dict) -> str:
    return f"{identifier.get('type')} {identifier.get('identifier')}"


def _org_identity_id(org_identity: dict):
    return (org_identity.get("meta") or {}).get("id")


def access_eppn(access_id: str) -> str:
    return f"{access_id}@{ACCESS_IDP_DOMAIN}"


def _check_profile_fields(
    c: _Checks, comanage_user: CoManageUser, identity_person: dict | None
):
    """Check that every field the Profile page requires is present."""
    c.section = PROFILE_FIELDS_SECTION

    primary_name = comanage_user.get_primary_name() or {}
    c.check(
        "CoManage has a first name",
        not _blank(primary_name.get("given")),
        "no given name on a primary Name",
    )
    c.check(
        "CoManage has a last name",
        not _blank(primary_name.get("family")),
        "no family name on a primary Name",
    )
    c.check(
        "CoManage has a primary email",
        not _blank(comanage_user.get_primary_email()),
        "no official EmailAddress",
    )

    required = {
        "firstName": "a first name",
        "lastName": "a last name",
        "email": "an email",
        "organizationId": "an organization",
        "department": "a department",
        "nsfStatusCodeId": "an academic status",
        "countryId": "a country of residence",
        "citizenships": "a country of citizenship",
    }
    c.check(
        "Identity Service has a person record",
        identity_person is not None,
        "no person record for this ACCESS ID",
    )
    for key, label in required.items():
        name = f"Identity Service has {label}"
        if identity_person is None:
            c.skip(name, "no person record")
            continue
        value = identity_person.get(key)
        c.check(name, not _blank(value) and value != [], f"{key} is {value!r}")


def _check_profile_consistency(
    c: _Checks, comanage_user: CoManageUser, identity_person: dict | None
):
    """Warn about profile values the two services disagree on.

    Profile updates write both services, so a mismatch usually means one of
    the writes failed.
    """
    c.section = PROFILE_CONSISTENCY_SECTION

    primary_name = comanage_user.get_primary_name() or {}
    person = identity_person or {}
    pairs = [
        ("first name", primary_name.get("given"), person.get("firstName")),
        ("last name", primary_name.get("family"), person.get("lastName")),
        (
            "primary email",
            (comanage_user.get_primary_email() or "").lower() or None,
            (person.get("email") or "").lower() or None,
        ),
    ]
    for label, comanage_value, identity_value in pairs:
        name = f"{label} is the same in CoManage and the Identity Service"
        if comanage_value is None or identity_value is None:
            c.skip(name, f"{label} is missing")
            continue
        c.warn_unless(
            name,
            comanage_value == identity_value,
            f"CoManage has {comanage_value!r}, Identity Service has {identity_value!r}",
        )


def _check_co_person(
    c: _Checks, comanage_user: CoManageUser, tandc_agreements: list[dict]
) -> str | None:
    """Check the CoPerson's own records. Returns its ACCESS ID, if it has one."""
    c.section = CO_PERSON_SECTION

    co_person = comanage_user.get("CoPerson") or {}
    c.check(
        "status is Active",
        co_person.get("status") == "A",
        f"status is {co_person.get('status')!r}",
    )

    co_person_identifiers = _active(comanage_user.get("Identifier"))
    access_ids = [i for i in co_person_identifiers if i.get("type") == "accessid"]
    c.check(
        "has one accessid Identifier",
        len(access_ids) == 1,
        f"has {len(access_ids)}",
    )
    access_id = access_ids[0].get("identifier") if access_ids else None

    primary_names = [
        n for n in _active(comanage_user.get("Name")) if n.get("primary_name")
    ]
    c.check(
        "has one primary Name",
        len(primary_names) == 1,
        f"has {len(primary_names)}",
    )

    official_emails = [
        e
        for e in _active(comanage_user.get("EmailAddress"))
        if e.get("type") == "official"
    ]
    c.check(
        "has one official EmailAddress",
        len(official_emails) == 1,
        f"has {len(official_emails)}",
    )
    unverified = [e.get("mail") for e in official_emails if not e.get("verified")]
    c.check(
        "official EmailAddress is verified",
        not unverified,
        f"not verified: {', '.join(map(str, unverified))}",
    )

    c.check(
        "has an active affiliate CoPersonRole with an organization",
        any(
            r.get("affiliation") == "affiliate"
            and r.get("status") == "A"
            and not _blank(r.get("o"))
            for r in _active(comanage_user.get("CoPersonRole"))
        ),
    )

    group_ids = {
        str(m.get("co_group_id"))
        for m in _active(comanage_user.get("CoGroupMember"))
        if m.get("member")
    }
    for group_id in REQUIRED_CO_GROUP_IDS:
        c.check(f"is a member of CoGroup {group_id}", group_id in group_ids)

    c.check("has a Terms and Conditions agreement", bool(tandc_agreements))

    return access_id


def _check_access_org_identity(
    c: _Checks,
    org_identity: dict,
    access_id: str | None,
    co_person_identifier_keys: set[tuple],
):
    c.section = f"ACCESS IdP OrgIdentity {_org_identity_id(org_identity)}"
    _check_org_identity_name(c, org_identity)

    if access_id is None:
        c.skip("has a login eppn for the ACCESS ID", "the CoPerson has no ACCESS ID")
        return

    expected_eppn = access_eppn(access_id)
    eppns = [
        i for i in _active(org_identity.get("Identifier")) if i.get("type") == "eppn"
    ]
    c.check(
        f"has login eppn {expected_eppn}",
        any(i.get("identifier") == expected_eppn and i.get("login") for i in eppns),
    )
    others = [
        i.get("identifier") for i in eppns if i.get("identifier") != expected_eppn
    ]
    c.check(
        "has no eppn for another ACCESS ID",
        not others,
        f"also has {', '.join(map(str, others))}",
    )
    c.check(
        f"eppn {expected_eppn} is copied to the CoPerson",
        ("eppn", expected_eppn) in co_person_identifier_keys,
    )


def _check_external_org_identity(
    c: _Checks, org_identity: dict, co_person_identifier_keys: set[tuple]
):
    org_name = org_identity.get("o") or "no organization"
    c.section = f"OrgIdentity {_org_identity_id(org_identity)} ({org_name})"
    _check_org_identity_name(c, org_identity)

    identifiers = _active(org_identity.get("Identifier"))
    oidcsubs = {i.get("identifier") for i in identifiers if i.get("type") == "oidcsub"}
    c.check(
        "has a login oidcsub",
        any(i.get("type") == "oidcsub" and i.get("login") for i in identifiers),
    )

    for identifier in identifiers:
        identifier_type = identifier.get("type")
        label = _identifier_label(identifier)
        if not c.warn_unless(
            f"{identifier_type} is an expected Identifier type",
            identifier_type in EXTERNAL_IDENTIFIER_TYPES,
            f"unexpected {label}",
        ):
            continue

        if identifier_type == "sorid":
            c.check(
                f"{label} matches the oidcsub",
                identifier.get("identifier") in oidcsubs,
            )
        elif identifier_type != "oidcsub":
            expected_login = CILOGON_IDENTIFIER_LOGIN[identifier_type]
            c.warn_unless(
                f"{label} has the login flag linking sets",
                bool(identifier.get("login")) == expected_login,
                f"login is {bool(identifier.get('login'))}, linking sets "
                f"{expected_login}",
            )

        c.check(
            f"{label} is copied to the CoPerson",
            (identifier_type, identifier.get("identifier"))
            in co_person_identifier_keys,
        )


def _check_org_identity_name(c: _Checks, org_identity: dict):
    c.check(
        "has a primary Name",
        any(n.get("primary_name") for n in _active(org_identity.get("Name"))),
    )


def verify_account(
    comanage_user: CoManageUser,
    identity_person: dict | None,
    tandc_agreements: list[dict],
) -> VerificationResult:
    c = _Checks()
    _check_profile_fields(c, comanage_user, identity_person)
    _check_profile_consistency(c, comanage_user, identity_person)

    structure_start = len(c.checks)
    access_id = _check_co_person(c, comanage_user, tandc_agreements)
    co_person_identifier_keys = {
        (i.get("type"), i.get("identifier"))
        for i in _active(comanage_user.get("Identifier"))
    }

    # Split the OrgIdentities into the ACCESS IdP one and the rest.
    access_org_identities = []
    external_org_identities = []
    for org_identity in _active(comanage_user.get("OrgIdentity")):
        if any(
            i.get("type") == "eppn"
            and (i.get("identifier") or "").endswith(f"@{ACCESS_IDP_DOMAIN}")
            for i in _active(org_identity.get("Identifier"))
        ):
            access_org_identities.append(org_identity)
        else:
            external_org_identities.append(org_identity)

    c.check(
        "has one ACCESS IdP OrgIdentity",
        len(access_org_identities) == 1,
        f"has {len(access_org_identities)}",
    )
    for org_identity in access_org_identities:
        _check_access_org_identity(
            c, org_identity, access_id, co_person_identifier_keys
        )
    for org_identity in external_org_identities:
        _check_external_org_identity(c, org_identity, co_person_identifier_keys)

    structure_failures = [
        check for check in c.checks[structure_start:] if check.status == Status.FAILED
    ]
    pattern = None
    if not structure_failures:
        pattern = (
            PATTERN_WITH_EXISTING
            if external_org_identities
            else PATTERN_WITHOUT_EXISTING
        )

    c.section = PATTERN_SECTION
    c.check(
        f"matches {pattern}" if pattern else "matches a registration pattern",
        pattern is not None,
        f"{len(structure_failures)} CoManage structure "
        + ("check" if len(structure_failures) == 1 else "checks")
        + " failed",
    )

    return VerificationResult(checks=c.checks, pattern=pattern)
