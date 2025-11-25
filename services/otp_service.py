import string, random
from datetime import datetime
from argon2 import PasswordHasher

OTP_STORE = {}
ph = PasswordHasher()

def generate_otp(length=6):
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))

def store_otp(email, otp):
    OTP_STORE[email] = {
        "hash": ph.hash(otp),
        "timestamp": datetime.utcnow().isoformat()
    }
