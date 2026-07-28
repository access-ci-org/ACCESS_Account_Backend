"""Unit tests for JWT creation/decoding in auth.py."""

from datetime import timedelta

import jwt
import pytest

from auth import create_access_token, decode_otp_token
from config import JWT_ALGORITHM, JWT_AUDIENCE, JWT_ISSUER, JWT_SECRET_KEY


def test_otp_token_round_trip():
    token = create_access_token(
        sub="ada@example.org", token_type="otp", username=None
    )
    payload = decode_otp_token(token)
    assert payload.sub == "ada@example.org"
    assert payload.typ == "otp"
    assert payload.uid is None


def test_login_token_round_trip_carries_username():
    token = create_access_token(
        sub="cilogon-sub", token_type="login", username="ada"
    )
    payload = decode_otp_token(token)
    assert payload.typ == "login"
    assert payload.uid == "ada"


def test_token_includes_standard_claims():
    token = create_access_token(sub="ada@example.org", token_type="otp")
    raw = jwt.decode(
        token,
        str(JWT_SECRET_KEY),
        algorithms=[JWT_ALGORITHM],
        audience=JWT_AUDIENCE,
        issuer=JWT_ISSUER,
    )
    assert raw["iss"] == JWT_ISSUER
    assert raw["aud"] == JWT_AUDIENCE
    assert "exp" in raw and "iat" in raw and "jti" in raw


def test_expired_token_is_rejected():
    token = create_access_token(
        sub="ada@example.org",
        token_type="otp",
        expires_delta=timedelta(minutes=-1),
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_otp_token(token)


def test_wrong_audience_is_rejected():
    bad = jwt.encode(
        {
            "sub": "ada@example.org",
            "typ": "otp",
            "aud": "https://evil.example.org",
            "iss": JWT_ISSUER,
        },
        str(JWT_SECRET_KEY),
        algorithm=JWT_ALGORITHM,
    )
    with pytest.raises(jwt.InvalidAudienceError):
        decode_otp_token(bad)


def test_wrong_signature_is_rejected():
    bad = jwt.encode(
        {
            "sub": "ada@example.org",
            "typ": "otp",
            "aud": JWT_AUDIENCE,
            "iss": JWT_ISSUER,
        },
        "the-wrong-secret",
        algorithm=JWT_ALGORITHM,
    )
    with pytest.raises(jwt.InvalidSignatureError):
        decode_otp_token(bad)
