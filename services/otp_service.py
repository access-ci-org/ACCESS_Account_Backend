import string, random
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from fastapi import HTTPException

OTP_STORE = {}
ph = PasswordHasher()

def generate_otp(length=6):
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))

def store_otp(email, otp):
    OTP_STORE[email] = {
        "hash": ph.hash(otp),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def verify_stored_otp(email: str, submitted_otp: str) -> None:
    """
        Verify the submmited OTP against the stored hashed OTP for the given email.
        Raises an exception if verification fails.
        Deletes OTP after verification attempt whether successful or not.
    """

    entry = OTP_STORE.get(email)
    if not entry:
        raise HTTPException(status_code=403, detail="Invalid OTP")
    
    # Expiration check (30 minutes)
    sent_time = datetime.fromisoformat(entry["timestamp"]).astimezone(timezone.utc)
    expiration_time = sent_time + timedelta(minutes=1)
    
    if datetime.now(timezone.utc) > expiration_time:
        del OTP_STORE[email]
        raise HTTPException(status_code=403, detail="OTP has expired")    
    
    # Verify OTP
    try:
        ph.verify(entry['hash'], submitted_otp)
    except Exception:
        # Delete OTP after verification attempt fails
        del OTP_STORE[email]
        raise HTTPException(status_code=403, detail="Invalid OTP")
    
    # Delete OTP after successful verification
    del OTP_STORE[email]