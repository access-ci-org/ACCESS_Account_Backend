import os

from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings, Secret

# If APP_CONFIG is set, use that as the path to the .env file, or default to .env
env_file = os.getenv("APP_CONFIG", ".env")
if "APP_CONFIG" in os.environ and not os.path.isfile(env_file):
    raise FileNotFoundError(
        f"The configuration file specified in APP_CONFIG or the default .env does not exist: {env_file}"
    )

config = Config(env_file)

# Application Configuration
ADMIN_USERNAMES: CommaSeparatedStrings = config(
    "ADMIN_USERNAMES", cast=CommaSeparatedStrings, default=CommaSeparatedStrings([])
)
CORS_ORIGINS: CommaSeparatedStrings = config(
    "CORS_ORIGINS", cast=CommaSeparatedStrings, default=CommaSeparatedStrings([])
)
DATABASE_URL: str = config("DATABASE_URL", default="sqlite:///./otp_database.db")
DEBUG: bool = config("DEBUG", cast=bool, default=False)
FRONTEND_URL: str = config(
    "FRONTEND_URL", default="http://localhost:3000/access-ci-account/auth-token"
)

# AWS SES Configuration
AWS_ACCESS_KEY: Secret = config("AWS_ACCESS_KEY", cast=Secret)
AWS_REGION: str = config("AWS_REGION", default="us-east-2")
AWS_SECRET_ACCESS_KEY: Secret = config("AWS_SECRET_ACCESS_KEY", cast=Secret)
AWS_SES_SENDER_EMAIL: str = config(
    "AWS_SES_SENDER_EMAIL", default="allocations@access-ci.org"
)

# CILogon
CILOGON_AUTHORIZATION_URL: str = config(
    "CILOGON_AUTHORIZATION_URL", default="https://cilogon.org/authorize"
)
CILOGON_INTROSPECTION_URL: str = config(
    "CILOGON_INTROSPECTION_URL", default="https://cilogon.org/oauth2/introspect"
)
CILOGON_LINK_CLIENT_ID: str = config("CILOGON_LINK_CLIENT_ID")
CILOGON_LINK_CLIENT_SECRET: Secret = config("CILOGON_LINK_CLIENT_SECRET", cast=Secret)
CILOGON_LOGIN_CLIENT_ID: str = config("CILOGON_LOGIN_CLIENT_ID")
CILOGON_LOGIN_CLIENT_SECRET: Secret = config("CILOGON_LOGIN_CLIENT_SECRET", cast=Secret)
CILOGON_TOKEN_URL: str = config(
    "CILOGON_TOKEN_URL", default="https://cilogon.org/oauth2/token"
)
CILOGON_USER_INFO_URL: str = config(
    "CILOGON_USER_INFO_URL", default="https://cilogon.org/oauth2/userinfo"
)

# COManage Registry
COMANAGE_REGISTRY_BASE_URL: str = config("COMANAGE_REGISTRY_BASE_URL")
COMANAGE_REGISTRY_COID: int = config("COMANAGE_REGISTRY_COID", default=2)
COMANAGE_REGISTRY_PASSWORD: Secret = config("COMANAGE_REGISTRY_PASSWORD", cast=Secret)
COMANAGE_REGISTRY_TIMEOUT: int = config("COMANAGE_REGISTRY_TIMEOUT", default=10)
COMANAGE_REGISTRY_USER: str = config("COMANAGE_REGISTRY_USER")

# Cron Job Configuration
EXPIRED_OTP_CLEANUP_INTERVAL_SECONDS: int = config(
    "EXPIRED_OTP_CLEANUP_INTERVAL_SECONDS", cast=int, default=60
)
IDP_BY_DOMAIN_CACHE_REFRESH_INTERVAL_SECONDS: int = config(
    "IDP_BY_DOMAIN_CACHE_REFRESH_INTERVAL_SECONDS", cast=int, default=3600
)

# JWT Configuration
JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = config(
    "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", cast=int, default=60
)
JWT_ALGORITHM: str = config("JWT_ALGORITHM", default="HS256")
JWT_AUDIENCE: str = config("JWT_AUDIENCE", default="https://account.access-ci.org")
JWT_ISSUER: str = config("JWT_ISSUER", default="https://account.access-ci.org")
JWT_SECRET_KEY: Secret = config("JWT_SECRET_KEY", cast=Secret)

# OTP Configuration
OTP_CHARACTER_LENGTH: int = config("OTP_CHARACTER_LENGTH", cast=int, default=6)
OTP_LIFETIME_MINUTES: int = config("OTP_LIFETIME_MINUTES", cast=int, default=30)

# XRAS Identity Service Configuration
XRAS_IDENTITY_SERVICE_BASE_URL: str = config("XRAS_IDENTITY_SERVICE_BASE_URL")
XRAS_IDENTITY_SERVICE_KEY: str = config("XRAS_IDENTITY_SERVICE_KEY")
XRAS_IDENTITY_SERVICE_REQUESTER: str = config("XRAS_IDENTITY_SERVICE_REQUESTER")
