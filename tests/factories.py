"""Builders for realistic test payloads.

Keeping the shape of CoManage / JWT data in one place keeps the individual tests
short and makes it easy to tweak a single field per test (pass overrides as
kwargs). The CoManage builders mirror the exact structure consumed by
``services.comanage_registry_client.CoManageUser`` (``get_username``,
``get_primary_name``, ``get_primary_email``, ``has_org_identity``).

XRAS Identity-service payload builders are intentionally minimal for now and will
be fleshed out alongside the identity-client / account-endpoint tests.
"""

from datetime import UTC, datetime, timedelta

from services.comanage_registry_client import CoManageUser, Identifier
from models import TokenPayload


# ---------------------------------------------------------------------------
# JWT / auth payloads
# ---------------------------------------------------------------------------
def make_token_payload(
    sub: str = "user@example.org",
    typ: str = "login",
    uid: str | None = "user",
    exp: datetime | None = None,
) -> TokenPayload:
    """Build a decoded ``TokenPayload`` (the object auth dependencies return)."""
    return TokenPayload(sub=sub, typ=typ, uid=uid, exp=exp)


def expired_time(minutes: int = 5) -> datetime:
    """A timestamp `minutes` in the past — handy for expiry tests."""
    return datetime.now(UTC) - timedelta(minutes=minutes)


# ---------------------------------------------------------------------------
# CoManage Registry payloads
# ---------------------------------------------------------------------------
def _meta(deleted: bool = False) -> dict:
    return {"deleted": deleted}


def make_name(
    given: str = "Ada",
    family: str = "Lovelace",
    primary_name: bool = True,
    deleted: bool = False,
    type: str = "official",
) -> dict:
    return {
        "honorific": None,
        "given": given,
        "middle": None,
        "family": family,
        "suffix": None,
        "type": type,
        "language": None,
        "primary_name": primary_name,
        "meta": _meta(deleted),
    }


def make_email(
    mail: str = "ada@example.org",
    type: str = "official",
    deleted: bool = False,
) -> dict:
    return {"mail": mail, "type": type, "verified": True, "meta": _meta(deleted)}


def make_org_identity_identifier(
    identifier: str,
    type: str = "eppn",
    deleted: bool = False,
) -> dict:
    return {"identifier": identifier, "type": type, "meta": _meta(deleted)}


def make_org_identity(
    identifiers: list[dict] | None = None,
    deleted: bool = False,
    o: str | None = "Example University",
) -> dict:
    return {
        "O": o,
        "meta": _meta(deleted),
        "Identifier": identifiers
        if identifiers is not None
        else [make_org_identity_identifier("ada@example.org", "eppn")],
    }


def make_comanage_user(
    access_id: str = "user",
    given: str = "Ada",
    family: str = "Lovelace",
    email: str = "ada@example.org",
    organization: str = "Example University",
    timezone: str | None = None,
    names: list[dict] | None = None,
    emails: list[dict] | None = None,
    identifiers: list[dict] | None = None,
    org_identities: list[dict] | None = None,
) -> CoManageUser:
    """Build a ``CoManageUser`` with the full nested structure the client reads.

    Override any section by passing the corresponding list explicitly (e.g.
    ``names=[]`` to simulate a user with no primary name -> 404 path).
    """
    return CoManageUser(
        {
            "CoPerson": {"co_id": "2", "status": "A", "timezone": timezone},
            "Name": names if names is not None else [make_name(given, family)],
            "EmailAddress": emails if emails is not None else [make_email(email)],
            "Identifier": identifiers
            if identifiers is not None
            else [{"type": "accessid", "identifier": access_id}],
            "CoPersonRole": [{"affiliation": "affiliate", "o": organization}],
            "OrgIdentity": org_identities if org_identities is not None else [],
        }
    )


def make_identifier(
    identifier: str = "ada@example.org",
    type: str = "eppn",
    login: bool = True,
) -> Identifier:
    """Build the namedtuple used by ``CoManageUser.has_org_identity``."""
    return Identifier(identifier=identifier, type=type, login=login)


# ---------------------------------------------------------------------------
# CoManage list-endpoint envelopes (co_people.json, identifiers.json, ...)
# ---------------------------------------------------------------------------
def co_people_envelope(co_person_id: int | str = 123) -> dict:
    """Response shape for ``co_people.json`` lookups."""
    return {"CoPeople": [{"Id": co_person_id}]}


def identifiers_envelope(access_id: str = "user") -> dict:
    """Response shape for ``identifiers.json`` lookups."""
    return {"Identifiers": [{"Type": "accessid", "Identifier": access_id}]}


def active_tandc(tandc_id: int = 42) -> dict:
    """A single active Terms & Conditions record."""
    return {
        "Id": tandc_id,
        "Status": "Active",
        "Description": "ACCESS Acceptable Use Policy",
        "Url": "https://access-ci.org/aup",
    }
