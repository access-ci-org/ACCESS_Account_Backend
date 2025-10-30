from fastapi import FastAPI, Header, status
from fastapi.responses import JSONResponse, RedirectResponse

from models import (
    SendOTPRequest,
    VerifyOTPRequest,
    LoginRequest,
    CreateAccountRequest,
    UpdateAccountRequest,
    UpdatePasswordRequest,
    AddSSHKeyRequest,
)

app = FastAPI(title="ACCESS Account API")


# Auth Routes
@app.post("/auth/send-otp")
async def send_otp(request: SendOTPRequest):
    """Send a one-time password (OTP) to the specified email."""
    # TODO: Implement OTP sending logic
    pass


@app.post("/auth/verify-otp")
async def verify_otp(request: VerifyOTPRequest):
    """Verify an OTP provided by the user."""
    # TODO: Implement OTP verification logic
    pass


@app.post("/auth/login")
async def start_login(request: LoginRequest):
    """Start the CILogon authentication flow."""
    # TODO: Implement CILogon flow initiation
    pass


@app.get("/auth/login")
async def complete_login(token: str):
    """Receive the CILogon token after a successful login."""
    # TODO: Implement CILogon token handling and redirect
    pass


# Account Routes
@app.post("/account")
async def create_account(
    request: CreateAccountRequest, authorization: str | None = Header(None)
):
    """Create a new account."""
    # TODO: Implement account creation logic
    pass


@app.get("/account/{username}")
async def get_account(username: str, authorization: str | None = Header(None)):
    """Get the profile for the given account."""
    # TODO: Implement account retrieval logic
    pass


@app.post("/account/{username}")
async def update_account(
    username: str,
    request: UpdateAccountRequest,
    authorization: str | None = Header(None),
):
    """Update the profile information for an account."""
    # TODO: Implement account update logic
    pass


@app.post("/account/{username}/password")
async def update_password(
    username: str,
    request: UpdatePasswordRequest,
    authorization: str | None = Header(None),
):
    """Set or update the password for the account in the ACCESS IDP."""
    # TODO: Implement password update logic
    pass


# Identity Routes
@app.get("/account/{username}/identity")
async def get_identities(username: str, authorization: str | None = Header(None)):
    """Get a list of identities associated with this account."""
    # TODO: Implement identity retrieval logic
    pass


@app.post("/account/{username}/identity")
async def link_identity(username: str, authorization: str | None = Header(None)):
    """Start the process of linking a new identity."""
    # TODO: Implement identity linking flow
    pass


@app.delete("/account/{username}/identity/{identity_id}")
async def delete_identity(
    username: str, identity_id: int, authorization: str | None = Header(None)
):
    """Delete a linked identity."""
    # TODO: Implement identity deletion logic
    pass


# SSH Key Routes
@app.get("/account/{username}/ssh-key")
async def get_ssh_keys(username: str, authorization: str | None = Header(None)):
    """Get a list of SSH keys associated with this account."""
    # TODO: Implement SSH key retrieval logic
    pass


@app.post("/account/{username}/ssh-key")
async def add_ssh_key(
    username: str,
    request: AddSSHKeyRequest,
    authorization: str | None = Header(None),
):
    """Add a new SSH key to the account."""
    # TODO: Implement SSH key addition logic
    pass


@app.delete("/account/{username}/ssh-key/{key_id}")
async def delete_ssh_key(
    username: str, key_id: int, authorization: str | None = Header(None)
):
    """Delete an SSH key."""
    # TODO: Implement SSH key deletion logic
    pass


# Reference Data Routes
@app.get("/academic-status")
async def get_academic_statuses(authorization: str | None = Header(None)):
    """Get a list of all possible academic statuses."""
    # TODO: Implement academic status retrieval logic
    pass


@app.get("/country")
async def get_countries(authorization: str | None = Header(None)):
    """Get a list of all possible countries."""
    # TODO: Implement country retrieval logic
    pass


@app.get("/domain/{domain}")
async def get_domain_info(domain: str, authorization: str | None = Header(None)):
    """Get information about an email domain."""
    # TODO: Implement domain info retrieval logic
    pass


def main():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
