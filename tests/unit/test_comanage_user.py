"""Unit tests for the CoManageUser dict-helper methods (pure, no I/O)."""

from factories import (
    make_comanage_user,
    make_email,
    make_identifier,
    make_name,
    make_org_identity,
    make_org_identity_identifier,
)


# --- get_username -----------------------------------------------------------
def test_get_username_returns_accessid():
    user = make_comanage_user(access_id="ada")
    assert user.get_username() == "ada"


def test_get_username_none_when_no_accessid():
    user = make_comanage_user(identifiers=[{"type": "eppn", "identifier": "x"}])
    assert user.get_username() is None


# --- get_primary_name -------------------------------------------------------
def test_get_primary_name_returns_primary_non_deleted():
    user = make_comanage_user(given="Ada", family="Lovelace")
    name = user.get_primary_name()
    assert name is not None
    assert name["given"] == "Ada"
    assert name["family"] == "Lovelace"


def test_get_primary_name_skips_deleted():
    user = make_comanage_user(
        names=[make_name("Ada", "Lovelace", primary_name=True, deleted=True)]
    )
    assert user.get_primary_name() is None


def test_get_primary_name_none_when_not_primary():
    user = make_comanage_user(
        names=[make_name("Ada", "Lovelace", primary_name=False)]
    )
    assert user.get_primary_name() is None


# --- get_primary_email ------------------------------------------------------
def test_get_primary_email_address_only():
    user = make_comanage_user(email="ada@example.org")
    assert user.get_primary_email() == "ada@example.org"


def test_get_primary_email_full_dict():
    user = make_comanage_user(email="ada@example.org")
    email = user.get_primary_email(address_only=False)
    assert email is not None
    assert email["mail"] == "ada@example.org"


def test_get_primary_email_skips_deleted():
    user = make_comanage_user(
        emails=[make_email("ada@example.org", deleted=True)]
    )
    assert user.get_primary_email() is None


def test_get_primary_email_ignores_non_official():
    user = make_comanage_user(
        emails=[make_email("ada@example.org", type="personal")]
    )
    assert user.get_primary_email() is None


# --- has_org_identity -------------------------------------------------------
def _user_with_org(identifier="ada@example.org", type="eppn", **kw):
    return make_comanage_user(
        org_identities=[
            make_org_identity(
                identifiers=[make_org_identity_identifier(identifier, type, **kw)]
            )
        ]
    )


def test_has_org_identity_true_on_match():
    user = _user_with_org("ada@example.org", "eppn")
    assert user.has_org_identity(make_identifier("ada@example.org", "eppn")) is True


def test_has_org_identity_false_when_no_org_identity_key():
    user = make_comanage_user()  # OrgIdentity defaults to []
    assert user.has_org_identity(make_identifier("ada@example.org", "eppn")) is False


def test_has_org_identity_false_on_type_mismatch():
    user = _user_with_org("ada@example.org", "eppn")
    assert user.has_org_identity(make_identifier("ada@example.org", "oidcsub")) is False


def test_has_org_identity_skips_deleted_org_identity():
    user = make_comanage_user(
        org_identities=[
            make_org_identity(
                identifiers=[make_org_identity_identifier("ada@example.org", "eppn")],
                deleted=True,
            )
        ]
    )
    assert user.has_org_identity(make_identifier("ada@example.org", "eppn")) is False


def test_has_org_identity_skips_deleted_identifier():
    user = _user_with_org("ada@example.org", "eppn", deleted=True)
    assert user.has_org_identity(make_identifier("ada@example.org", "eppn")) is False
