import re
from dataclasses import dataclass

SYMBOL_RE = re.compile(r"[^A-Za-z0-9]")

@dataclass
class PasswordPolicyResult:
    valid: bool
    errors: list[str]

def validate_access_password(password: str) -> PasswordPolicyResult:
    errors: list[str] = []

    if password is None:
        return PasswordPolicyResult(valid=False, errors=["Password is required."])

    length = len(password)
    if length < 12 or length > 64:
        errors.append(
            "Your new password must be between 12 and 64 characters in length."
        )

    categories = 0
    if any(c.islower() for c in password):
        categories += 1
    if any(c.isupper() for c in password):
        categories += 1
    if any(c.isdigit() for c in password):
        categories += 1
    if SYMBOL_RE.search(password):
        categories += 1

    if categories < 3:
        errors.append(
            "Your new password must include characters from at least three of the following: lowercase letters, uppercase letters, numbers, and symbols."
        )

    return PasswordPolicyResult(valid=(len(errors) == 0), errors=errors)