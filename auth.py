from datetime import datetime, timedelta, timezone
from typing import Literal

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from config import (
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    JWT_SECRET_KEY,
)


class TokenPayload(BaseModel):
    """JWT token payload structure."""

    sub: str  # email address
    typ: Literal["otp", "login"]  # authentication type
    uid: str | None = None  # ACCESS username if exists
    exp: datetime | None = None  # expiration time


security = HTTPBearer(auto_error=False)


def create_access_token(
    email: str,
    token_type: Literal["otp", "login"],
    username: str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        email: The user's email address
        token_type: Either "otp" or "login"
        username: The ACCESS username (optional)
        expires_delta: Custom expiration time (optional)

    Returns:
        Encoded JWT token string
    """
    import uuid

    now = datetime.now(timezone.utc)

    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {
        "sub": email,
        "typ": token_type,
        "uid": username,
        "exp": expire,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "jti": str(uuid.uuid4()),
    }

    encoded_jwt = jwt.encode(to_encode, str(JWT_SECRET_KEY), algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> TokenPayload:
    """
    Decode and validate a JWT token.

    Args:
        token: The JWT token string

    Returns:
        TokenPayload object with decoded claims

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            str(JWT_SECRET_KEY),
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        return TokenPayload(**payload)
    except (jwt.InvalidTokenError, jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid authentication credentials",
        )


async def get_current_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> TokenPayload:
    """
    Dependency to get and validate the current JWT token.

    Args:
        credentials: HTTP Bearer credentials from request header

    Returns:
        TokenPayload with decoded token data

    Raises:
        HTTPException: If authorization header is missing or token is invalid
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authenticated",
        )

    return decode_token(credentials.credentials)


async def require_auth(
    token: TokenPayload = Depends(get_current_token),
) -> TokenPayload:
    """
    Dependency that requires any valid authentication (otp or login).

    Args:
        token: The decoded token payload

    Returns:
        TokenPayload
    """
    return token


async def require_otp_or_login(
    token: TokenPayload = Depends(get_current_token),
) -> TokenPayload:
    """
    Dependency that requires either OTP or login authentication.

    Args:
        token: The decoded token payload

    Returns:
        TokenPayload
    """
    if token.typ not in ["otp", "login"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid authentication type",
        )
    return token


async def require_login(
    token: TokenPayload = Depends(get_current_token),
) -> TokenPayload:
    """
    Dependency that requires login authentication (not OTP).

    Args:
        token: The decoded token payload

    Returns:
        TokenPayload

    Raises:
        HTTPException: If token type is not "login"
    """
    if token.typ != "login":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Login authentication required",
        )
    return token


def verify_username_access(
    token: TokenPayload, username: str, allow_admin: bool = False
) -> None:
    """
    Verify that the token has permission to access the given username.

    Args:
        token: The decoded token payload
        username: The username being accessed
        allow_admin: Whether to allow administrative users (not implemented yet)

    Raises:
        HTTPException: If user doesn't have permission
    """
    # TODO: Implement admin user check when allow_admin=True
    if token.uid != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this account",
        )


async def require_username_access(
    username: str,
    token: TokenPayload = Depends(require_login),
) -> TokenPayload:
    """
    Dependency that requires login and verifies access to a specific username.
    Allows admin users to access any account.

    Args:
        username: The username being accessed (from path parameter)
        token: The decoded token payload

    Returns:
        TokenPayload

    Raises:
        HTTPException: If user doesn't have permission
    """
    verify_username_access(token, username, allow_admin=True)
    return token


async def require_own_username_access(
    username: str,
    token: TokenPayload = Depends(require_login),
) -> TokenPayload:
    """
    Dependency that requires login and verifies access to own username only.
    Does not allow admin access.

    Args:
        username: The username being accessed (from path parameter)
        token: The decoded token payload

    Returns:
        TokenPayload

    Raises:
        HTTPException: If user doesn't have permission to their own account
    """
    verify_username_access(token, username, allow_admin=False)
    return token
