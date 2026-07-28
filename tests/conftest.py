"""Shared pytest fixtures and test-suite bootstrap for the ACCESS Account API.

IMPORTANT — import ordering
---------------------------
`config.py` reads many required, no-default env vars via ``starlette.config.Config``
at import time, and it does so the first time *any* application module is imported.
pytest imports this ``conftest.py`` before collecting/importing the test modules, so
we set ``APP_CONFIG`` to the dummy ``tests/.env`` *before* importing ``config``/``main``.
That guarantees the real secrets .env symlink is never read during tests.

The application constructs several module-level singletons at import time
(``services.account_service.comanage_client`` / ``identity_client``, the AWS SES
client in ``services.email_service``, and the SQLModel engine in ``database``).
Fixtures below give you clean seams to override each of those per test.

Lifespan note: the FastAPI ``lifespan`` startup hits the network (InCommon MDQ) and
the DB. The ``client`` fixture instantiates ``TestClient`` WITHOUT the context-manager
form, so lifespan startup does NOT run and no real network/DB calls happen at setup.
Tests that need ``IDP_BY_DOMAIN`` populated should set it directly on ``main``.
"""

import os
from pathlib import Path

# --- Environment bootstrap: must happen before importing any app module ---
_TESTS_DIR = Path(__file__).resolve().parent
os.environ["APP_CONFIG"] = str(_TESTS_DIR / ".env.test")

from unittest.mock import AsyncMock  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import SQLModel, create_engine  # noqa: E402

# App imports (safe now that APP_CONFIG is set).
import auth  # noqa: E402
import database  # noqa: E402
import main  # noqa: E402
from models import TokenPayload  # noqa: E402
from services import account_service, identity_client  # noqa: E402


# ---------------------------------------------------------------------------
# Autouse hygiene fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _disable_rate_limiter():
    """slowapi keeps per-process fixed-window counters that would otherwise leak
    between tests and eventually return 429s. Disable the limiter by default; the
    dedicated rate-limit test re-enables it explicitly."""
    original = main.limiter.enabled
    main.limiter.enabled = False
    yield
    main.limiter.enabled = original


@pytest.fixture(autouse=True)
def _clear_identity_cache():
    """``IdentityServiceClient`` memoizes choice lists (academic statuses,
    countries, degrees) in a class-level ``TTLCache``. Clear it around every test
    so cached responses from one test don't bleed into another."""
    cache = getattr(identity_client.IdentityServiceClient, "choice_list_cache", None)
    if cache is not None:
        cache.clear()
    yield
    if cache is not None:
        cache.clear()


@pytest.fixture(autouse=True)
def _clear_dependency_overrides():
    """Ensure FastAPI dependency overrides never leak across tests."""
    yield
    main.app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# App / client
# ---------------------------------------------------------------------------
@pytest.fixture
def app():
    """The FastAPI application object."""
    return main.app


@pytest.fixture
def client(app):
    """A ``TestClient`` that does NOT run the network-hitting lifespan startup.

    Instantiating ``TestClient`` without ``with`` skips startup/shutdown events,
    so importing/using it performs no outbound calls. Use ``mock_comanage`` /
    ``mock_identity`` (and auth overrides) to control endpoint behavior.
    """
    return TestClient(app)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Isolated SQLite database for OTP-service tests.

    Rebinds ``database.engine`` to a fresh temp-file engine and creates the
    schema. ``get_session()`` / ``init_db()`` read the module-level ``engine`` at
    call time, so this monkeypatch is picked up everywhere the OTP code runs.
    """
    db_path = tmp_path / "otp_test.db"
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    monkeypatch.setattr(database, "engine", engine)
    SQLModel.metadata.create_all(engine)
    yield engine
    engine.dispose()  # close pooled connections (avoids ResourceWarning)


# ---------------------------------------------------------------------------
# External-service mocks
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_comanage(monkeypatch):
    """Replace the shared CoManage client singleton with an ``AsyncMock``.

    Patches the name in BOTH ``main`` and ``services.account_service`` so handlers
    that call it directly (``main.comanage_client``) and via ``get_account_data``
    (``account_service.comanage_client``) all hit the mock.
    """
    mock = AsyncMock(name="comanage_client")
    monkeypatch.setattr(main, "comanage_client", mock)
    monkeypatch.setattr(account_service, "comanage_client", mock)
    return mock


@pytest.fixture
def mock_identity(monkeypatch):
    """Replace the shared XRAS Identity client singleton with an ``AsyncMock``."""
    mock = AsyncMock(name="identity_client")
    monkeypatch.setattr(main, "identity_client", mock)
    monkeypatch.setattr(account_service, "identity_client", mock)
    return mock


@pytest.fixture
def mock_send_email(monkeypatch):
    """Stub ``send_verification_email`` so /auth/send-otp never touches AWS SES.

    (With DEBUG=true the OTP is logged rather than emailed, but patching makes the
    intent explicit and lets non-DEBUG paths be tested too.)
    """
    mock = AsyncMock(name="send_verification_email")
    monkeypatch.setattr(main, "send_verification_email", mock)
    return mock


@pytest.fixture
def set_idp_mapping(monkeypatch):
    """Helper to populate the module-global ``IDP_BY_DOMAIN`` used by /domain.

    Usage: ``set_idp_mapping({"example.org": [IdP(...)]})``.
    """

    def _set(mapping):
        monkeypatch.setattr(main, "IDP_BY_DOMAIN", mapping)
        return mapping

    return _set


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def make_token():
    """Factory that mints a real, app-accepted JWT via ``create_access_token``.

    Example::

        token = make_token(token_type="otp", sub="user@example.org")
    """

    def _make(
        sub: str = "user@example.org",
        token_type: str = "login",
        username: str | None = "user",
        **kwargs,
    ) -> str:
        return auth.create_access_token(
            sub=sub, token_type=token_type, username=username, **kwargs
        )

    return _make


@pytest.fixture
def auth_header(make_token):
    """Factory returning an Authorization header dict with a fresh JWT."""

    def _header(**kwargs) -> dict[str, str]:
        return {"Authorization": f"Bearer {make_token(**kwargs)}"}

    return _header


@pytest.fixture
def override_auth(app):
    """Override any ``require_*`` auth dependency with a fixed ``TokenPayload``.

    This bypasses signature/type/ownership checks entirely — use it for endpoint
    behavior tests. For proving the gates themselves, use real tokens via
    ``auth_header`` instead. Overrides are cleared automatically after the test.

    Example::

        override_auth(main.require_own_username_access, uid="user")
    """

    def _override(
        dependency,
        sub: str = "user@example.org",
        typ: str = "login",
        uid: str | None = "user",
    ) -> TokenPayload:
        payload = TokenPayload(sub=sub, typ=typ, uid=uid)
        app.dependency_overrides[dependency] = lambda: payload
        return payload

    return _override
