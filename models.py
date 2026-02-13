from typing import List

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,  # Allows creation using the field name (snake_case)
        from_attributes=True,  # Optional: good for ORM compatibility
    )


class SendOTPRequest(BaseSchema):
    email: str


class VerifyOTPRequest(BaseSchema):
    email: str
    otp: str


class LoginRequest(BaseSchema):
    idp: str | None = None


class CreateAccountRequest(BaseSchema):
    first_name: str
    last_name: str
    organization_id: int
    academic_status_id: int
    residence_country_id: int
    citizenship_country_ids: list[int]


class Degree(BaseSchema):
    degree_id: int
    degree_field: str


class UpdateAccountRequest(BaseSchema):
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    email_otp_token: str | None = None
    organization_id: int | None = None
    academic_status_id: int | None = None
    residence_country_id: int | None = None
    citizenship_country_ids: list[int] | None = None
    program_role: str | None = None
    degrees: list[Degree] | None = None
    time_zone: str | None = None


class UpdatePasswordRequest(BaseSchema):
    password: str


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


class DomainResponse(BaseSchema):
    domain: str
    organizations: List[Organization]
    idps: List[IdP] = Field(default_factory=list)


class AccountResponse(BaseSchema):
    # CoManage Registry (authoritative)
    username: str
    first_name: str
    last_name: str
    email: str
    time_zone: str | None = None

    # Allocations Profile (authoritative)
    organization_id: int | None = None
    academic_status_id: int | None = None
    residence_country_id: int | None = None
    citizenship_country_ids: List[int] = Field(default_factory=list)


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
