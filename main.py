from fastapi import FastAPI, Depends, status
from fastapi.responses import JSONResponse, RedirectResponse
from urllib.parse import urlencode

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
from config import FRONTEND_URL

app = FastAPI(title="ACCESS Account API")


# Auth Routes
@app.post("/auth/send-otp")
async def send_otp(request: SendOTPRequest):
    """Send a one-time password (OTP) to the specified email."""
    # TODO: Implement OTP sending logic
    pass


@app.post("/auth/verify-otp", response_model=JWTResponse)
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


@app.post("/auth/login")
async def start_login(request: LoginRequest):
    """Start the CILogon authentication flow."""
    # TODO: Implement CILogon flow initiation
    pass


@app.get("/auth/login")
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
@app.post("/account")
async def create_account(
    request: CreateAccountRequest,
    token: TokenPayload = Depends(require_otp_or_login),
):
    """Create a new account."""
    # TODO: Implement account creation logic
    pass


@app.get("/account/{username}")
async def get_account(
    username: str,
    token: TokenPayload = Depends(require_username_access),
):
    """Get the profile for the given account."""
    # TODO: Implement account retrieval logic
    pass


@app.post("/account/{username}")
async def update_account(
    username: str,
    request: UpdateAccountRequest,
    token: TokenPayload = Depends(require_username_access),
):
    """Update the profile information for an account."""
    # TODO: Implement account update logic
    pass


@app.post("/account/{username}/password")
async def update_password(
    username: str,
    request: UpdatePasswordRequest,
    token: TokenPayload = Depends(require_own_username_access),
):
    """Set or update the password for the account in the ACCESS IDP."""
    # TODO: Implement password update logic
    pass


# Identity Routes
@app.get("/account/{username}/identity")
async def get_identities(
    username: str,
    token: TokenPayload = Depends(require_username_access),
):
    """Get a list of identities associated with this account."""
    # TODO: Implement identity retrieval logic
    pass


@app.post("/account/{username}/identity")
async def link_identity(
    username: str,
    token: TokenPayload = Depends(require_own_username_access),
):
    """Start the process of linking a new identity."""
    # TODO: Implement identity linking flow
    pass


@app.delete("/account/{username}/identity/{identity_id}")
async def delete_identity(
    username: str,
    identity_id: int,
    token: TokenPayload = Depends(require_own_username_access),
):
    """Delete a linked identity."""
    # TODO: Implement identity deletion logic
    pass


# SSH Key Routes
@app.get("/account/{username}/ssh-key")
async def get_ssh_keys(
    username: str,
    token: TokenPayload = Depends(require_username_access),
):
    """Get a list of SSH keys associated with this account."""
    # TODO: Implement SSH key retrieval logic
    pass


@app.post("/account/{username}/ssh-key")
async def add_ssh_key(
    username: str,
    request: AddSSHKeyRequest,
    token: TokenPayload = Depends(require_own_username_access),
):
    """Add a new SSH key to the account."""
    # TODO: Implement SSH key addition logic
    pass


@app.delete("/account/{username}/ssh-key/{key_id}")
async def delete_ssh_key(
    username: str,
    key_id: int,
    token: TokenPayload = Depends(require_own_username_access),
):
    """Delete an SSH key."""
    # TODO: Implement SSH key deletion logic
    pass


# Reference Data Routes
@app.get("/academic-status")
async def get_academic_statuses(
    token: TokenPayload = Depends(require_otp_or_login),
):
    """Get a list of all possible academic statuses."""
    # TODO: Implement academic status retrieval logic
    pass


@app.get("/country")
async def get_countries(
    token: TokenPayload = Depends(require_otp_or_login),
):
    """Get a list of all possible countries."""
    # TODO: Implement country retrieval logic
    pass


@app.get("/domain/{domain}")
async def get_domain_info(
    domain: str,
    token: TokenPayload = Depends(require_otp_or_login),
):
    """Get information about an email domain."""
    # TODO: Implement domain info retrieval logic
    pass


def main():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
