from starlette.config import Config
from starlette.datastructures import Secret

# Load environment variables from .env file if it exists
config = Config(".env")

# JWT Configuration
JWT_SECRET_KEY: Secret = config("JWT_SECRET_KEY", cast=Secret)
JWT_ALGORITHM: str = config("JWT_ALGORITHM", default="HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = config(
    "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", cast=int, default=60
)
JWT_ISSUER: str = config("JWT_ISSUER", default="https://account.access-ci.org")
JWT_AUDIENCE: str = config("JWT_AUDIENCE", default="https://account.access-ci.org")

# Application Configuration
DEBUG: bool = config("DEBUG", cast=bool, default=False)
FRONTEND_URL: str = config("FRONTEND_URL", default="http://localhost:3000")


# Identity Service Configuration
XRAS_IDENTITY_SERVICE_URL: str = config("XRAS_IDENTITY_SERVICE_URL")

# Fixed path for countries endpoint (not configurable via env)
XRAS_IDENTITY_SERVICE_COUNTRIES_PATH = "/profiles/v1/countries"

# Headers for identity service
XRAS_IDENTITY_SERVICE_ACCESS_REQUESTER: str = config("XRAS_IDENTITY_SERVICE_ACCESS_REQUESTER")
XRAS_IDENTITY_SERVICE_ACCESS_API_KEY: str = config("XRAS_IDENTITY_SERVICE_ACCESS_API_KEY")