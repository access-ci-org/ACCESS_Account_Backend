"""Unit tests for services/account_verification.py (pure, no I/O)."""

import pytest

from services.account_verification import (
    PATTERN_WITH_EXISTING,
    PATTERN_WITHOUT_EXISTING,
    Status,
    verify_account,
)
from services.comanage_registry_client import CoManageUser

TANDC = [{"Id": 1, "CoTermsAndConditionsId": 42}]


def _meta(id, deleted=False):
    return {"id": id, "deleted": deleted}


def _identifier(type, identifier, login=False, id=None):
    return {"type": type, "identifier": identifier, "login": login, "meta": _meta(id)}


def _org_identity(id, identifiers, o=None):
    return {
        "o": o,
        "meta": _meta(id),
        "Identifier": identifiers,
        "Name": [
            {
                "given": "Ada",
                "family": "Lovelace",
                "primary_name": True,
                "meta": _meta(1),
            }
        ],
    }


def access_org_identity(access_id="ada"):
    return _org_identity(
        10, [_identifier("eppn", f"{access_id}@access-ci.org", login=True)]
    )


def external_org_identity():
    return _org_identity(
        20,
        [
            _identifier("eppn", "ada@example.edu", login=True),
            _identifier("oidcsub", "http://cilogon.org/serverA/users/1", login=True),
            _identifier("eptid", "https://idp.example.edu!x!y"),
        ],
        o="Example University",
    )


def make_user(with_external=False, **overrides) -> CoManageUser:
    """A CoManage Core API record as registration leaves it."""
    org_identities = [access_org_identity()]
    co_person_identifiers = [
        _identifier("accessid", "ada"),
        _identifier("eppn", "ada@access-ci.org", login=True),
    ]
    if with_external:
        external = external_org_identity()
        org_identities.append(external)
        co_person_identifiers += [dict(i) for i in external["Identifier"]]

    user = {
        "CoPerson": {"status": "A", "timezone": None, "meta": _meta(123)},
        "CoGroupMember": [
            {"co_group_id": 5, "member": True, "meta": _meta(1)},
            {"co_group_id": 6, "member": True, "meta": _meta(2)},
        ],
        "CoPersonRole": [
            {
                "affiliation": "affiliate",
                "o": "Example University",
                "status": "A",
                "meta": _meta(1),
            }
        ],
        "EmailAddress": [
            {
                "mail": "ada@example.edu",
                "type": "official",
                "verified": True,
                "meta": _meta(1),
            }
        ],
        "Identifier": co_person_identifiers,
        "Name": [
            {
                "given": "Ada",
                "family": "Lovelace",
                "primary_name": True,
                "meta": _meta(1),
            }
        ],
        "OrgIdentity": org_identities,
        "SshKey": [],
    }
    user.update(overrides)
    return CoManageUser(user)


def make_person(**overrides) -> dict:
    person = {
        "firstName": "Ada",
        "lastName": "Lovelace",
        "email": "ada@example.edu",
        "organizationId": 7,
        "department": "Mathematics",
        "nsfStatusCodeId": 3,
        "countryId": 210,
        "citizenships": [{"countryId": 210}],
    }
    person.update(overrides)
    return person


# --- patterns ---------------------------------------------------------------
def _verify(user=None, person=None, tandc=TANDC):
    return verify_account(
        user if user is not None else make_user(),
        person if person is not None else make_person(),
        tandc,
    )


def _not_passed(result, *statuses):
    """(section, name, status, detail) for each check with one of `statuses`."""
    statuses = statuses or (Status.FAILED, Status.WARNING, Status.SKIPPED)
    return [
        (c.section, c.name, c.status, c.detail)
        for c in result.checks
        if c.status in statuses
    ]


def _failed(result):
    """(section, name) for each failed check, leaving out the pattern check."""
    return [
        (c.section, c.name)
        for c in result.checks
        if c.status == Status.FAILED and c.section != "Registration pattern"
    ]


def _assert_no_pattern(result):
    assert result.pattern is None
    assert result.failed
    pattern_check = result.checks[-1]
    assert (pattern_check.section, pattern_check.name, pattern_check.status) == (
        "Registration pattern",
        "matches a registration pattern",
        Status.FAILED,
    )


# --- patterns ---------------------------------------------------------------
def test_without_existing_pattern():
    result = _verify()
    assert _not_passed(result) == []
    assert result.pattern == PATTERN_WITHOUT_EXISTING
    assert not result.failed
    last = result.checks[-1]
    assert (last.section, last.name, last.status) == (
        "Registration pattern",
        f"matches {PATTERN_WITHOUT_EXISTING}",
        Status.PASSED,
    )


def test_with_existing_pattern():
    result = _verify(make_user(with_external=True))
    assert _not_passed(result) == []
    assert result.pattern == PATTERN_WITH_EXISTING


def test_every_check_is_listed():
    sections = {c.section for c in _verify(make_user(with_external=True)).checks}
    assert sections == {
        "Profile fields",
        "Profile consistency",
        "CoPerson",
        "ACCESS IdP OrgIdentity 10",
        "OrgIdentity 20 (Example University)",
        "Registration pattern",
    }


# --- structure problems -----------------------------------------------------
def test_missing_access_org_identity():
    result = _verify(make_user(OrgIdentity=[]))
    assert _failed(result) == [("CoPerson", "has one ACCESS IdP OrgIdentity")]
    _assert_no_pattern(result)


def test_deleted_access_org_identity_does_not_count():
    org_identity = access_org_identity()
    org_identity["meta"]["deleted"] = True
    result = _verify(make_user(OrgIdentity=[org_identity]))
    assert _failed(result) == [("CoPerson", "has one ACCESS IdP OrgIdentity")]


def test_access_eppn_must_match_access_id():
    result = _verify(make_user(OrgIdentity=[access_org_identity("bob")]))
    assert _failed(result) == [
        ("ACCESS IdP OrgIdentity 10", "has login eppn ada@access-ci.org"),
        ("ACCESS IdP OrgIdentity 10", "has no eppn for another ACCESS ID"),
    ]


def test_access_eppn_must_be_on_co_person():
    result = _verify(make_user(Identifier=[_identifier("accessid", "ada")]))
    assert _failed(result) == [
        (
            "ACCESS IdP OrgIdentity 10",
            "eppn ada@access-ci.org is copied to the CoPerson",
        )
    ]


def test_missing_accessid_skips_eppn_checks():
    user = make_user(Identifier=[_identifier("eppn", "ada@access-ci.org", True)])
    result = _verify(user)
    assert _failed(result) == [("CoPerson", "has one accessid Identifier")]
    assert _not_passed(result, Status.SKIPPED) == [
        (
            "ACCESS IdP OrgIdentity 10",
            "has a login eppn for the ACCESS ID",
            Status.SKIPPED,
            "the CoPerson has no ACCESS ID",
        )
    ]


def test_external_identifier_not_copied_to_co_person():
    user = make_user(with_external=True)
    user["Identifier"] = [i for i in user["Identifier"] if i["type"] != "oidcsub"]
    result = _verify(user)
    assert _failed(result) == [
        (
            "OrgIdentity 20 (Example University)",
            "oidcsub http://cilogon.org/serverA/users/1 is copied to the CoPerson",
        )
    ]
    _assert_no_pattern(result)


def test_external_identifier_wrong_login_flag_is_a_warning():
    user = make_user(with_external=True)
    user["OrgIdentity"][1]["Identifier"][2]["login"] = True  # eptid
    result = _verify(user)
    assert result.pattern == PATTERN_WITH_EXISTING
    assert _not_passed(result) == [
        (
            "OrgIdentity 20 (Example University)",
            "eptid https://idp.example.edu!x!y has the login flag linking sets",
            Status.WARNING,
            "login is True, linking sets False",
        )
    ]


def legacy_user(sorid="http://cilogon.org/serverA/users/1"):
    """An account made by the older CILogon enrollment flow."""
    oidcsub = "http://cilogon.org/serverA/users/1"
    user = make_user()
    user["OrgIdentity"].append(
        _org_identity(
            30,
            [
                _identifier("oidcsub", oidcsub, login=True),
                _identifier("sorid", sorid),
            ],
        )
    )
    user["Identifier"] += [
        _identifier("oidcsub", oidcsub, login=True),
        _identifier("sorid", sorid),
    ]
    return user


def test_legacy_enrollment_with_sorid_matches_with_existing():
    result = _verify(legacy_user())
    assert _not_passed(result) == []
    assert result.pattern == PATTERN_WITH_EXISTING


def test_sorid_must_match_oidcsub():
    result = _verify(legacy_user(sorid="something-else"))
    assert _failed(result) == [
        ("OrgIdentity 30 (no organization)", "sorid something-else matches the oidcsub")
    ]


def test_external_org_identity_needs_login_oidcsub():
    user = make_user(with_external=True)
    user["OrgIdentity"][1]["Identifier"][1]["login"] = False  # oidcsub
    result = _verify(user)
    assert _failed(result) == [
        ("OrgIdentity 20 (Example University)", "has a login oidcsub")
    ]


def test_unexpected_identifier_type_is_a_warning():
    user = make_user(with_external=True)
    user["OrgIdentity"][1]["Identifier"].append(_identifier("network", "ada"))
    result = _verify(user)
    assert result.pattern == PATTERN_WITH_EXISTING
    assert _not_passed(result) == [
        (
            "OrgIdentity 20 (Example University)",
            "network is an expected Identifier type",
            Status.WARNING,
            "unexpected network ada",
        )
    ]


def test_org_identity_without_name():
    user = make_user(with_external=True)
    user["OrgIdentity"][1]["Name"] = []
    assert _failed(_verify(user)) == [
        ("OrgIdentity 20 (Example University)", "has a primary Name")
    ]


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"CoPerson": {"status": "S", "meta": _meta(123)}}, "status is Active"),
        (
            {"CoGroupMember": [{"co_group_id": 5, "member": True, "meta": _meta(1)}]},
            "is a member of CoGroup 6",
        ),
        (
            {"CoPersonRole": []},
            "has an active affiliate CoPersonRole with an organization",
        ),
        (
            {
                "EmailAddress": [
                    {
                        "mail": "a@x.edu",
                        "type": "official",
                        "verified": True,
                        "meta": _meta(1),
                    },
                    {
                        "mail": "b@x.edu",
                        "type": "official",
                        "verified": True,
                        "meta": _meta(2),
                    },
                ]
            },
            "has one official EmailAddress",
        ),
        (
            {
                "EmailAddress": [
                    {
                        "mail": "ada@example.edu",
                        "type": "official",
                        "verified": False,
                        "meta": _meta(1),
                    },
                ]
            },
            "official EmailAddress is verified",
        ),
        (
            {
                "Name": [
                    {
                        "given": "Ada",
                        "family": "Lovelace",
                        "primary_name": True,
                        "meta": _meta(1),
                    },
                    {
                        "given": "Ada",
                        "family": "Lovelace",
                        "primary_name": True,
                        "meta": _meta(2),
                    },
                ]
            },
            "has one primary Name",
        ),
    ],
)
def test_co_person_problems(overrides, expected):
    result = _verify(make_user(**overrides))
    assert _failed(result) == [("CoPerson", expected)]
    _assert_no_pattern(result)


def test_missing_tandc_agreement():
    assert _failed(_verify(tandc=[])) == [
        ("CoPerson", "has a Terms and Conditions agreement")
    ]


# --- required fields --------------------------------------------------------
def test_missing_identity_person_skips_its_fields():
    result = verify_account(make_user(), None, TANDC)
    assert _failed(result) == [
        ("Profile fields", "Identity Service has a person record")
    ]
    skipped = _not_passed(result, Status.SKIPPED)
    assert (
        "Profile fields",
        "Identity Service has a department",
        Status.SKIPPED,
        "no person record",
    ) in skipped
    assert len([s for s in skipped if s[0] == "Profile fields"]) == 8
    # Without a person record there's nothing to compare against.
    assert len([s for s in skipped if s[0] == "Profile consistency"]) == 3
    # Profile problems don't affect the CoManage structure.
    assert result.pattern == PATTERN_WITHOUT_EXISTING


def test_missing_identity_fields():
    person = make_person(department="  ", nsfStatusCodeId=None, citizenships=[])
    result = _verify(person=person)
    assert _not_passed(result) == [
        (
            "Profile fields",
            "Identity Service has a department",
            Status.FAILED,
            "department is '  '",
        ),
        (
            "Profile fields",
            "Identity Service has an academic status",
            Status.FAILED,
            "nsfStatusCodeId is None",
        ),
        (
            "Profile fields",
            "Identity Service has a country of citizenship",
            Status.FAILED,
            "citizenships is []",
        ),
    ]


def test_missing_comanage_name_and_email():
    result = _verify(make_user(Name=[], EmailAddress=[]))
    assert ("Profile fields", "CoManage has a first name") in _failed(result)
    assert ("Profile fields", "CoManage has a primary email") in _failed(result)


# --- cross-service consistency ----------------------------------------------
def test_email_comparison_ignores_case():
    assert _not_passed(_verify(person=make_person(email="ADA@example.edu"))) == []


def test_name_mismatch_is_a_warning():
    result = _verify(person=make_person(lastName="Byron"))
    assert not result.failed
    assert _not_passed(result) == [
        (
            "Profile consistency",
            "last name is the same in CoManage and the Identity Service",
            Status.WARNING,
            "CoManage has 'Lovelace', Identity Service has 'Byron'",
        )
    ]
