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


class UpdateAccountRequest(BaseSchema):
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    email_jwt: str | None = None
    organization_id: int | None = None


class UpdatePasswordRequest(BaseSchema):
    password: str


class AddSSHKeyRequest(BaseSchema):
    public_key: str


class JWTResponse(BaseSchema):
    """Response model for JWT token."""

    jwt: str


class Country(BaseSchema):
    country_id: int
    country_name: str


class CountriesResponse(BaseSchema):
    countries: List[Country]


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
    carnegie_categories: List[dict] = []
    state: str | None = None
    country: str | None = None
    org_type: str | None = None


class DomainResponse(BaseSchema):
    domain: str
    organizations: List[Organization]
    idps: List[IdP] = Field(default_factory=list)


class AccountResponse(BaseSchema):
    username: str
    first_name: str
    last_name: str
    email: str
    time_zone: str | None = None


class TermsAndConditionsResponse(BaseSchema):
    id: int
    description: str
    url: str
    body: str


class Identity(BaseSchema):
    identity_id: int
    eppn: str | None = None
    organization: str | None = None


class IdentitiesResponse(BaseSchema):
    identities: List[Identity]


class SSHKey(BaseSchema):
    key_id: int
    hash: str
    created: str


class SSHKeysResponse(BaseSchema):
    ssh_keys: List[SSHKey]
