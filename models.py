from pydantic import BaseModel
from typing import List


class SendOTPRequest(BaseModel):
    email: str


class VerifyOTPRequest(BaseModel):
    email: str
    otp: str


class LoginRequest(BaseModel):
    idp: str | None = None


class CreateAccountRequest(BaseModel):
    firstName: str
    lastName: str
    organizationId: int


class UpdateAccountRequest(BaseModel):
    firstName: str | None = None
    lastName: str | None = None
    email: str | None = None
    emailJWT: str | None = None
    organizationId: int | None = None


class UpdatePasswordRequest(BaseModel):
    password: str


class AddSSHKeyRequest(BaseModel):
    publicKey: str


class JWTResponse(BaseModel):
    """Response model for JWT token."""

    jwt: str

class Country(BaseModel):
    countryId: int
    countryName: str

class CountriesResponse(BaseModel):
    countries: List[Country]

class AcademicStatus(BaseModel):
    academicStatusId: int
    name: str

class AcademicStatusResponse(BaseModel):
    academicStatuses: List[AcademicStatus]

class Domain(BaseModel):
    domain: str
    organizations: List[str]
    idps: List[str]

class Organization(BaseModel):
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
    carnegieCategories: List[dict] = []
    state: str | None = None
    country: str | None = None
    org_type: str | None = None

class DomainResponse(BaseModel):
    domain: str
    organizations: List[Organization]
    idps: List[str]
