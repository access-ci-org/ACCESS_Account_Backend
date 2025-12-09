import os

from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings, Secret

# If APP_CONFIG is set, use that as the path to the .env file, or default to .env
env_file = os.getenv("APP_CONFIG", ".env")
if "APP_CONFIG" in os.environ and not os.path.isfile(env_file):
    raise FileNotFoundError(f"The configuration file specified in APP_CONFIG or the default .env does not exist: {env_file}")

config = Config(env_file)

# JWT Configuration
JWT_SECRET_KEY: Secret = config("JWT_SECRET_KEY", cast=Secret)
JWT_ALGORITHM: str = config("JWT_ALGORITHM", default="HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = config(
    "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", cast=int, default=60
)
JWT_ISSUER: str = config("JWT_ISSUER", default="https://account.access-ci.org")
JWT_AUDIENCE: str = config("JWT_AUDIENCE", default="https://account.access-ci.org")

# Application Configuration
CORS_ORIGINS: CommaSeparatedStrings = config(
    "CORS_ORIGINS", cast=CommaSeparatedStrings, default=CommaSeparatedStrings([])
)
DEBUG: bool = config("DEBUG", cast=bool, default=False)
FRONTEND_URL: str = config("FRONTEND_URL", default="http://localhost:3000")

#Identity Service Configuration
XRAS_IDENTITY_SERVICE_BASE_URL: str = config("XRAS_IDENTITY_SERVICE_BASE_URL")
XRAS_IDENTITY_SERVICE_REQUESTER: str = config("XRAS_IDENTITY_SERVICE_REQUESTER")
XRAS_IDENTITY_SERVICE_KEY: str = config("XRAS_IDENTITY_SERVICE_KEY")

# AWS SES Configuration
AWS_REGION: str = config("AWS_REGION", default="us-east-2")
AWS_ACCESS_KEY: Secret = config("AWS_ACCESS_KEY", cast=Secret)
AWS_SECRET_ACCESS_KEY: Secret = config("AWS_SECRET_ACCESS_KEY", cast=Secret)
AWS_SES_SENDER_EMAIL: str = config("AWS_SES_SENDER_EMAIL", default="allocations@access-ci.org")

# OTP Configuration
OTP_CHARACTER_LENGTH: int = config("OTP_CHARACTER_LENGTH", cast=int, default=6)
OTP_LIFETIME_MINUTES: int = config("OTP_LIFETIME_MINUTES", cast=int, default=30)

# Database Configuration
DATABASE_URL: str = config("DATABASE_URL", default="sqlite:///./otp_database.db")

# Cron Job Configuration
EXPIRED_OTP_CLEANUP_INTERVAL_SECONDS: int = config(
    "EXPIRED_OTP_CLEANUP_INTERVAL_SECONDS", cast=int, default=60
)