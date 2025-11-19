from fastapi import FastAPI, APIRouter, Depends, status
from fastapi.responses import JSONResponse, RedirectResponse
from urllib.parse import urlencode
import httpx # importing httpx library

from models import (
    SendOTPRequest,
    VerifyOTPRequest,
    LoginRequest,
    CreateAccountRequest,
    UpdateAccountRequest,
    UpdatePasswordRequest,
    AddSSHKeyRequest,
    JWTResponse,
)
from auth import (
    TokenPayload,
    create_access_token,
    require_otp_or_login,
    require_username_access,
    require_own_username_access,
)
from config import (
    FRONTEND_URL,
    XRAS_IDENTITY_SERVICE_ACCESS_REQUESTER,
    XRAS_IDENTITY_SERVICE_ACCESS_API_KEY,
    XRAS_IDENTITY_SERVICE_COUNTRIES_PATH,
    XRAS_IDENTITY_SERVICE_URL
)

app = FastAPI(
    title="ACCESS Account API",
    description="API for ACCESS CI accounts and registration",
    version="0.1.0",
)

# Create router with /api/v1 prefix
router = APIRouter(prefix="/api/v1")


# Auth Routes
@router.post(
    "/auth/send-otp",
    tags=["Authentication"],
    summary="Send OTP to email",
    description="Send a one-time password (OTP) to the specified email, if it exists. "
    "In order to avoid revealing whether the email has an associated account, "
    "we send the OTP regardless of whether the domain is allowed by ACCESS. "
    "Prohibited domains will be flagged after the user enters the OTP.",
    responses={
        200: {"description": "The OTP was sent"},
        400: {
            "description": "The OTP could not be sent (e.g., due to a malformed email address)"
        },
    },
)
async def send_otp(request: SendOTPRequest):
    # TODO: Implement OTP sending logic
    pass


@router.post(
    "/auth/verify-otp",
    response_model=JWTResponse,
    tags=["Authentication"],
    summary="Verify OTP",
    description="Verify an OTP provided by the user.",
    responses={
        200: {"description": "The OTP is valid. Returns a JWT of type 'otp'"},
        400: {"description": "The request body is malformed"},
        403: {"description": "The OTP is invalid"},
    },
)
async def verify_otp(request: VerifyOTPRequest):
    """Verify an OTP provided by the user."""
    # TODO: Implement actual OTP verification logic
    # For now, this is a placeholder that assumes the OTP is valid

    # Verify the OTP (placeholder - implement actual verification)
    # In production, this should:
    # 1. Check if the OTP exists and matches the email
    # 2. Verify the OTP hasn't expired
    # 3. Verify the OTP hasn't been used already
    # 4. Return 403 if invalid

    # Create a JWT token of type "otp"
    token = create_access_token(
        email=request.email,
        token_type="otp",
        username=None,  # OTP tokens don't have a username yet
    )

    return JWTResponse(jwt=token)


@router.post(
    "/auth/login",
    tags=["Authentication"],
    summary="Start CILogon authentication",
    description="Start the CILogon authentication flow. "
    "The preferred IDP can be included in the request body. "
    "Otherwise, the user is prompted to select an IDP by CILogon.",
    responses={
        307: {"description": "Redirect to the CILogon URL to start the login process"},
        400: {
            "description": "The redirect could not be sent (e.g., due to a malformed email address)"
        },
    },
)
async def start_login(request: LoginRequest):
    # TODO: Implement CILogon flow initiation
    pass


@router.get(
    "/auth/login",
    tags=["Authentication"],
    summary="Complete CILogon authentication",
    description="Receive the CILogon token after a successful login, and redirect to the front end URL.",
    responses={
        307: {
            "description": "Redirect to the account frontend URL with query string parameters: "
            "jwt (a JWT of type 'login'), first_name (the given_name OIDC claim), "
            "and last_name (the family_name OIDC claim)"
        },
    },
)
async def complete_login(token: str):
    """Receive the CILogon token after a successful login."""
    # TODO: Implement actual CILogon token handling
    # For now, this is a placeholder with hardcoded values

    # In production, this should:
    # 1. Validate the CILogon token
    # 2. Extract user information from the OIDC claims
    # 3. Look up the ACCESS username from the database
    # 4. Redirect to frontend with JWT and user info

    # Create a JWT token of type "login"
    jwt_token = create_access_token(
        email="user@example.edu",
        token_type="login",
        username="user",
    )

    # Build redirect URL with query parameters
    query_params = {
        "jwt": jwt_token,
        "first_name": "John",  # Placeholder - from OIDC given_name claim
        "last_name": "Doe",  # Placeholder - from OIDC family_name claim
    }
    redirect_url = f"{FRONTEND_URL}?{urlencode(query_params)}"

    return RedirectResponse(
        url=redirect_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT
    )


# Account Routes
@router.post(
    "/account",
    tags=["Account"],
    summary="Create new account",
    description="Create a new account.",
    responses={
        200: {"description": "The account was created"},
        400: {
            "description": "The input failed validation (e.g., the organization does not match "
            "the e-mail domain or an account for that email address already exists)"
        },
        403: {"description": "The JWT is invalid"},
    },
)
async def create_account(
    request: CreateAccountRequest,
    token: TokenPayload = Depends(require_otp_or_login),
):
    # TODO: Implement account creation logic
    pass


@router.get(
    "/account/{username}",
    tags=["Account"],
    summary="Get account profile",
    description="Get the profile for the given account.",
    responses={
        200: {"description": "Return the profile information for the user"},
        403: {
            "description": "The JWT is invalid or the user does not have permission to access the account"
        },
        404: {"description": "The requested user does not exist"},
    },
)
async def get_account(
    username: str,
    token: TokenPayload = Depends(require_username_access),
):
    # TODO: Implement account retrieval logic
    pass


@router.post(
    "/account/{username}",
    tags=["Account"],
    summary="Update account profile",
    description="Update the profile information for an account. "
    "If email is different from the email in the Authorization header, "
    "a valid emailJWT of type 'otp' must be provided to prove that the user owns the new email address.",
    responses={
        200: {"description": "The account profile was updated"},
        400: {
            "description": "The input failed validation (e.g., the organization does not match the e-mail domain)"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to update the account"
        },
    },
)
async def update_account(
    username: str,
    request: UpdateAccountRequest,
    token: TokenPayload = Depends(require_username_access),
):
    # TODO: Implement account update logic
    pass


@router.post(
    "/account/{username}/password",
    tags=["Account"],
    summary="Set or update password",
    description="Set or update the password for the account in the ACCESS IDP.",
    responses={
        200: {"description": "The password was updated"},
        400: {
            "description": "The password does not conform to the ACCESS password policy"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to update the password"
        },
    },
)
async def update_password(
    username: str,
    request: UpdatePasswordRequest,
    token: TokenPayload = Depends(require_own_username_access),
):
    # TODO: Implement password update logic
    pass


# Identity Routes
@router.get(
    "/account/{username}/identity",
    tags=["Identity"],
    summary="Get linked identities",
    description="Get a list of identities associated with this account.",
    responses={
        200: {
            "description": "Return the list of linked identities and associated IDPs"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to access the account"
        },
        404: {"description": "The requested user does not exist"},
    },
)
async def get_identities(
    username: str,
    token: TokenPayload = Depends(require_username_access),
):
    # TODO: Implement identity retrieval logic
    pass


@router.post(
    "/account/{username}/identity",
    tags=["Identity"],
    summary="Link new identity",
    description="Start the process of linking a new identity. "
    "Redirects to CILogon to start the linking flow.",
    responses={
        307: {
            "description": "Redirect to CILogon to start the linking flow. "
            "At the end of the flow, CILogon redirects back to /auth/login with the OIDC token"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to modify the account"
        },
    },
)
async def link_identity(
    username: str,
    token: TokenPayload = Depends(require_own_username_access),
):
    # TODO: Implement identity linking flow
    pass


@router.delete(
    "/account/{username}/identity/{identity_id}",
    tags=["Identity"],
    summary="Delete linked identity",
    description="Delete a linked identity.",
    responses={
        200: {"description": "The linked identity was deleted"},
        400: {
            "description": "The specified identity cannot be deleted "
            "(e.g., it is the last one associated with this account)"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to modify the account"
        },
        404: {"description": "The requested identity does not exist"},
    },
)
async def delete_identity(
    username: str,
    identity_id: int,
    token: TokenPayload = Depends(require_own_username_access),
):
    # TODO: Implement identity deletion logic
    pass


# SSH Key Routes
@router.get(
    "/account/{username}/ssh-key",
    tags=["SSH Keys"],
    summary="Get SSH keys",
    description="Get a list of SSH keys associated with this account.",
    responses={
        200: {"description": "Return the list of linked SSH keys"},
        403: {
            "description": "The JWT is invalid or the user does not have permission to access the account"
        },
        404: {"description": "The requested user does not exist"},
    },
)
async def get_ssh_keys(
    username: str,
    token: TokenPayload = Depends(require_username_access),
):
    # TODO: Implement SSH key retrieval logic
    pass


@router.post(
    "/account/{username}/ssh-key",
    tags=["SSH Keys"],
    summary="Add SSH key",
    description="Add a new SSH key to the account.",
    responses={
        200: {"description": "The key was added successfully"},
        400: {
            "description": "The provided key is not valid or is already associated with another account"
        },
        403: {
            "description": "The JWT is invalid or the user does not have permission to modify the account"
        },
    },
)
async def add_ssh_key(
    username: str,
    request: AddSSHKeyRequest,
    token: TokenPayload = Depends(require_own_username_access),
):
    # TODO: Implement SSH key addition logic
    pass


@router.delete(
    "/account/{username}/ssh-key/{key_id}",
    tags=["SSH Keys"],
    summary="Delete SSH key",
    description="Delete an SSH key.",
    responses={
        200: {"description": "The linked SSH key was deleted"},
        403: {
            "description": "The JWT is invalid or the user does not have permission to modify the account"
        },
        404: {"description": "The requested key does not exist"},
    },
)
async def delete_ssh_key(
    username: str,
    key_id: int,
    token: TokenPayload = Depends(require_own_username_access),
):
    # TODO: Implement SSH key deletion logic
    pass


# Reference Data Routes
@router.get(
    "/academic-status",
    tags=["Reference Data"],
    summary="Get academic statuses",
    description="Get a list of all possible academic statuses.",
    responses={
        200: {"description": "Return a list of possible academic statuses"},
        403: {"description": "The JWT is invalid"},
    },
)
async def get_academic_statuses(
    token: TokenPayload = Depends(require_otp_or_login),
):
    # TODO: Implement academic status retrieval logic
    pass


@router.get(
    "/country",
    tags=["Reference Data"],
    summary="Get countries",
    description="Get a list of all possible countries.",
    responses={
        200: {"description": "Return a list of possible countries"},
        403: {"description": "The JWT is invalid"},
    },
)
async def get_countries(
    token: TokenPayload = Depends(require_otp_or_login),
):
    # Build the full URL for the external identity service endpoint
    # This combines the base service URL with the specific path for country data.
    
    url = f"{XRAS_IDENTITY_SERVICE_URL.rstrip('/')}{XRAS_IDENTITY_SERVICE_COUNTRIES_PATH}"

    # Prepare the headers required by the external identity service.
    headers = {
        "XA-REQUESTER": XRAS_IDENTITY_SERVICE_ACCESS_REQUESTER,
        "XA-API-KEY": XRAS_IDENTITY_SERVICE_ACCESS_API_KEY,
    }

    # Create an asynchronous HTTP client to send the request
    async with httpx.AsyncClient() as client:
        try:
            # Send a GET request to the identity service with the headers created.
            response = await client.get(url, headers=headers)
            # If the response has an HTTP error status will raise an exception.
            response.raise_for_status()
        except httpx.HTTPError as exc:
            # If anything goes wrong return a 500 error.
            return JSONResponse(
                status_code = 500,
                content = {"error": f"Failed to fetch countries: {str(exc)}"},  
            )
    
    # Parse the response JSON
    data = response.json()

    # This extracts only the country ID and name from each item.
    transformed = {
        "countries": [
            {
                "countryId": item["countryId"],
                "countryName": item["countryName"]
            }
            for item in data
        ]
    }

    # Return the transformed list of countries back
    return JSONResponse(content = transformed)


@router.get(
    "/domain/{domain}",
    tags=["Reference Data"],
    summary="Get domain information",
    description="Get information about an email domain, including whether it meets ACCESS eligibility criteria, "
    "and associated organizations and IDPs, if any.",
    responses={
        200: {
            "description": "Return lists of associated organizations and IDPs for the domain"
        },
        403: {"description": "The JWT is invalid"},
        404: {"description": "The domain is not known to ACCESS/CILogon"},
    },
)
async def get_domain_info(
    domain: str,
    token: TokenPayload = Depends(require_otp_or_login),
):
    # TODO: Implement domain info retrieval logic
    pass


# Include router in the app
app.include_router(router)


def main():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
