from datetime import datetime
from enum import Enum
from typing import List, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,  # Allows creation using the field name (snake_case)
        from_attributes=True,  # Optional: good for ORM compatibility
    )


class TokenPayload(BaseModel):
    """JWT token payload structure."""

    sub: str  # email address for OTP tokens, CILogon sub claim for login tokens
    typ: Literal["otp", "login"]  # authentication type
    uid: str | None = None  # ACCESS username if exists
    exp: datetime | None = None  # expiration time


class SendOTPRequest(BaseSchema):
    email: str


class VerifyOTPRequest(BaseSchema):
    email: str
    otp: str


class OidcGrantType(str, Enum):
    authorization_code = "authorization_code"
    refresh_token = "refresh_token"


class CreateAccountRequest(BaseSchema):
    first_name: str
    last_name: str
    organization_id: int
    academic_status_id: int
    residence_country_id: int
    citizenship_country_ids: list[int]
    cilogon_token: str = ""
    department: str


class Degree(BaseSchema):
    degree_id: int
    degree_field: str


class EmailEntry(BaseSchema):
    email: str
    primary: bool
    # OTP token proving ownership. Required only for an email that is new to the
    # account (i.e. not already present on the CoManage record).
    otp_token: str | None = None


class UpdateAccountRequest(BaseSchema):
    first_name: str | None = None
    last_name: str | None = None
    # The full desired set of email addresses for the account, with exactly one
    # marked as primary. If None, the account's emails are left unchanged.
    emails: list[EmailEntry] | None = None
    organization_id: int | None = None
    academic_status_id: int | None = None
    residence_country_id: int | None = None
    citizenship_country_ids: list[int] | None = None
    program_role: str | None = None
    degrees: list[Degree] | None = None
    time_zone: str | None = None
    department: str | None = None


class UpdatePasswordRequest(BaseSchema):
    password: str = Field(
        ...,
        description="New password for the account",
        min_length=12,
        max_length=64,
    )


class AddSSHKeyRequest(BaseSchema):
    public_key: str


class JWTResponse(BaseSchema):
    """Response model for JWT token."""

    jwt: str


class Country(BaseSchema):
    country_id: int
    name: str


class CountriesResponse(BaseSchema):
    countries: List[Country]


class DegreeType(BaseSchema):
    degree_id: int
    name: str


class DegreesResponse(BaseSchema):
    degrees: List[DegreeType]


class AcademicStatus(BaseSchema):
    academic_status_id: int
    name: str


class AcademicStatusResponse(BaseSchema):
    academic_statuses: List[AcademicStatus]


class IdP(BaseSchema):
    displayName: str
    entityId: str


class Domain(BaseSchema):
    domain: str
    organizations: List[str]
    idps: List[str]


class Organization(BaseSchema):
    organization_id: int
    org_type_id: int | None = None
    organization_abbrev: str | None = None
    organization_name: str
    organization_url: str | None = None
    organization_phone: str | None = None
    nsf_org_code: str | None = None
    is_reconciled: bool | None = None
    amie_name: str | None = None
    country_id: int | None = None
    state_id: int | None = None
    latitude: str | None = None
    longitude: str | None = None
    is_msi: bool | None = None
    is_active: bool | None = None
    is_eligible: bool | None = None
    carnegie_categories: List[dict] = []
    state: str | None = None
    country: str | None = None
    org_type: str | None = None
    ignore_idp: bool | None = None


class DomainResponse(BaseSchema):
    domain: str
    organizations: List[Organization]
    idps: List[IdP] = Field(default_factory=list)


class BackupEmail(BaseSchema):
    email: str
    verified: bool


class AccountResponse(BaseSchema):
    # CoManage Registry (authoritative)
    username: str
    first_name: str
    last_name: str
    email: str
    backup_emails: List[BackupEmail] = Field(default_factory=list)
    time_zone: str | None = None

    # Allocations Profile (authoritative)
    organization_id: int | None = None
    academic_status_id: int | None = None
    residence_country_id: int | None = None
    citizenship_country_ids: List[int] = Field(default_factory=list)
    degrees: List[Degree] = Field(default_factory=list)

    department: str | None = None


class TermsAndConditionsResponse(BaseSchema):
    id: int
    description: str
    url: str
    body: str


class IdentityIdentifier(BaseSchema):
    type: str | None = None
    identifier: str | None = None
    login: bool | None = None


class Identity(BaseSchema):
    identity_id: int
    organization: str | None = None
    identifiers: List[IdentityIdentifier]


class IdentitiesResponse(BaseSchema):
    identities: List[Identity]


class SSHKey(BaseSchema):
    key_id: int
    hash: str
    created: str


class SSHKeysResponse(BaseSchema):
    ssh_keys: List[SSHKey]


class LinkIdentityRequest(BaseSchema):
    cilogon_token: str


class OidcClientIds(BaseSchema):
    link: str
    login: str


class OidcInfoResponse(BaseSchema):
    authorization_url: str
    client_ids: OidcClientIds


class OidcTokenRequest(BaseSchema):
    client_id: str
    code: str | None = None
    grant_type: OidcGrantType
    redirect_uri: str
    refresh_token: str | None = None


class OidcTokenResponse(BaseSchema):
    access_token: str
    id_token: str | None = None
    refresh_token: str
    is_admin: bool | None = None
