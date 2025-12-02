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

logger = logging.getLogger("access_account_api.otp")

OTP_STORE = {}
ph = PasswordHasher()

def generate_otp(length: int = OTP_CHARACTER_LENGTH) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))

def store_otp(email, otp):
    OTP_STORE[email] = {
        "hash": ph.hash(otp),
        "timestamp": datetime.now(timezone.utc)
    }

def verify_stored_otp(email: str, submitted_otp: str) -> None:
    """
        Verify the submmited OTP against the stored hashed OTP for the given email.
        Raises an exception if verification fails.
        Deletes OTP after verification attempt whether successful or not.
    """

    entry = OTP_STORE.get(email)
    if not entry:
        logger.warning(f"OTP verification failed: no OTP found for email={email}")
        raise HTTPException(status_code=403, detail="Invalid verification code")
    
    # Expiration check (30 minutes)
    sent_time: datetime = entry["timestamp"]
    expiration_time = sent_time + timedelta(minutes=OTP_LIFETIME_MINUTES)
    
    if datetime.now(timezone.utc) > expiration_time:
        del OTP_STORE[email]
        logger.warning(f"OTP verification failed: OTP expired for email={email}")
        raise HTTPException(status_code=403, detail="Verification code has expired. Please request a new one.")    
    
    # Verify OTP
    try:
        ph.verify(entry['hash'], submitted_otp)
    except VerifyMismatchError:
        # Wrong OTP but valid hash
        del OTP_STORE[email]
        logger.warning(f"OTP mismatch for email={email}")
        raise HTTPException(403, "Invalid verification code")

    except InvalidHash:
        # Stored hash is corrupted (should never happen unless storage corrupted)
        del OTP_STORE[email]
        logger.error(f"OTP verification failed due to invalid hash for email={email}")
        raise HTTPException(403, "Verification system error. Please request a new code.")

    except VerificationError:
        # Other argon2 internal error
        del OTP_STORE[email]
        logger.exception(f"General Argon2 verification error for email={email}")
        raise HTTPException(403, "Verification failed. Please request a new code.")

    except Exception as e:
        # Unexpected issue
        del OTP_STORE[email]
        logger.exception(f"Unexpected OTP verification error for email={email}: {e}")
        raise HTTPException(403, "Invalid verification code")
    
    # Delete OTP after successful verification
    OTP_STORE.pop(email, None)