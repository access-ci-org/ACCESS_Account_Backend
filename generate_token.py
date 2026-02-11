from datetime import timedelta

from auth import create_access_token


def generate_token(access_id_or_email: str, expiration_minutes: int = 525600):
    """Generate a token for use in development."""
    if "@" in access_id_or_email:
        # Generate OTP token.
        return create_access_token(
            access_id_or_email, "otp", None, timedelta(minutes=expiration_minutes)
        )
    else:
        # Generate login token.
        return create_access_token(
            f"{access_id_or_email}@access-ci.org",
            "login",
            access_id_or_email,
            timedelta(minutes=expiration_minutes),
        )


if __name__ == "__main__":
    access_id_or_email = input(
        "Enter ACCESS ID (for a login token) or email (for an OTP token): "
    )
    token = generate_token(access_id_or_email)
    is_otp = "@" in access_id_or_email
    token_type = "otp" if is_otp else "login"
    id_var = "EMAIL" if is_otp else "USERNAME"

    print(
        f"\nGenerated {token_type} token for {access_id_or_email}. "
        "To use the token in development, add these environment "
        "variables to .env in access-ci-account:\n\n"
    )
    print(f"VITE_INIT_{id_var}={access_id_or_email}")
    print(f"VITE_INIT_TOKEN={token}")
