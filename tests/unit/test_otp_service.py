"""Unit tests for services.otp_service.

`generate_otp` is pure. `store_otp` / `verify_stored_otp` hit the DB, so they use
the `temp_db` fixture (isolated SQLite; see conftest.py).
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException

from database import OTPEntry, get_session
from services import otp_service
from services.otp_service import generate_otp, store_otp, verify_stored_otp

# Characters generate_otp is allowed to emit: uppercase + digits, minus 0/1/I/L/O.
ALLOWED_OTP_CHARS = set("ABCDEFGHJKMNPQRSTUVWXYZ23456789")


def test_generate_otp_default_length():
    assert len(generate_otp()) == 6


@pytest.mark.parametrize("length", [1, 4, 8, 16])
def test_generate_otp_custom_length(length):
    assert len(generate_otp(length)) == length


def test_generate_otp_only_uses_allowed_charset():
    # Sample many OTPs to make an accidental forbidden char very likely to show.
    for _ in range(200):
        assert set(generate_otp(12)) <= ALLOWED_OTP_CHARS


def test_generate_otp_is_not_constant():
    assert len({generate_otp() for _ in range(50)}) > 1


def _get_entry(email: str) -> OTPEntry | None:
    with get_session() as session:
        return session.get(OTPEntry, email)


def test_store_then_verify_success_and_consumes_otp(temp_db):
    email = "user@example.org"
    otp = "ABC234"
    store_otp(email, otp)
    assert _get_entry(email) is not None

    # Correct OTP verifies without raising...
    verify_stored_otp(email, otp)
    # ...and the entry is deleted (single-use).
    assert _get_entry(email) is None


def test_verify_missing_otp_raises_403(temp_db):
    with pytest.raises(HTTPException) as exc:
        verify_stored_otp("nobody@example.org", "ABC234")
    assert exc.value.status_code == 403


def test_verify_wrong_otp_raises_403_and_deletes_entry(temp_db):
    email = "user@example.org"
    store_otp(email, "ABC234")

    with pytest.raises(HTTPException) as exc:
        verify_stored_otp(email, "WRONG9")
    assert exc.value.status_code == 403
    # A wrong attempt still consumes the stored OTP.
    assert _get_entry(email) is None


def test_verify_expired_otp_raises_403_and_deletes_entry(temp_db):
    email = "user@example.org"
    otp = "ABC234"
    # Insert directly with a created_at older than OTP_LIFETIME_MINUTES.
    old = datetime.now(UTC) - timedelta(
        minutes=otp_service.OTP_LIFETIME_MINUTES + 1
    )
    with get_session() as session:
        session.merge(
            OTPEntry(email=email, hash=otp_service.ph.hash(otp), created_at=old)
        )
        session.commit()

    with pytest.raises(HTTPException) as exc:
        verify_stored_otp(email, otp)
    assert exc.value.status_code == 403
    assert "expired" in exc.value.detail.lower()
    assert _get_entry(email) is None
