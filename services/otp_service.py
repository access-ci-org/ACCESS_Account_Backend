import string
import secrets
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from fastapi import HTTPException
import logging

from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHash,
)

from config import OTP_CHARACTER_LENGTH, OTP_LIFETIME_MINUTES

from database import get_session
from otpmodel.otp_model import OTPEntry

logger = logging.getLogger("access_account_api.otp")

ph = PasswordHasher()

def generate_otp(length: int = OTP_CHARACTER_LENGTH) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))

def store_otp(email, otp):
    hashed = ph.hash(otp)
    now = datetime.now(timezone.utc)

    with get_session() as session:
        entry = OTPEntry(email=email, hash=hashed, created_at=now)
        session.merge(entry)
        session.commit()

def verify_stored_otp(email: str, submitted_otp: str) -> None:
    """
        Verify the submmited OTP against the stored hashed OTP for the given email.
        Raises an exception if verification fails.
        Deletes OTP after verification attempt whether successful or not.
    """
    
    with get_session() as session:
        entry = session.get(OTPEntry, email)

        if not entry:
            logger.warning(f"OTP verification failed: no OTP found for email={email}")
            raise HTTPException(status_code=403, detail="Invalid verification code")
        

        # Expiration check (30 minutes)
        created_at = entry.created_at
        # SQLite stores naive datetime, so replace tzinfo
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        expiration_time = created_at + timedelta(minutes=OTP_LIFETIME_MINUTES)
        
        if datetime.now(timezone.utc) > expiration_time:
            session.delete(entry)
            session.commit()

            logger.warning(f"OTP verification failed: OTP expired for email={email}")
            raise HTTPException(status_code=403, detail="Verification code has expired. Please request a new one.")    
        
        # Verify OTP
        try:
            ph.verify(entry.hash, submitted_otp)
        except VerifyMismatchError:
            # Wrong OTP but valid hash
            session.delete(entry)
            session.commit()

            logger.warning(f"OTP mismatch for email={email}")
            raise HTTPException(403, "Invalid verification code")

        except InvalidHash:
            # Stored hash is corrupted (should never happen unless storage corrupted)
            session.delete(entry)
            session.commit()

            logger.error(f"OTP verification failed due to invalid hash for email={email}")
            raise HTTPException(403, "Verification system error. Please request a new code.")

        except VerificationError:
            # Other argon2 internal error
            session.delete(entry)
            session.commit()

            logger.exception(f"General Argon2 verification error for email={email}")
            raise HTTPException(403, "Verification failed. Please request a new code.")
    
        # Delete OTP after successful verification
        session.delete(entry)
        session.commit()