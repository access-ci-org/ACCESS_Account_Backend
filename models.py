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


class DomainResponse(BaseModel):
    domain: str
    organizations: List[str]
    idps: List[str]
