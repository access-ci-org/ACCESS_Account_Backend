import base64
import hashlib


def calculate_ssh_fingerprint_sha256(public_key):
    """
    Calculates the SHA256 fingerprint from an SSH public key string.

    Args:
        public_key (str): The second part of an SSH public key string (e.g., 'AAAAB3Nz').

    Returns:
        str: The SHA256 fingerprint in the format used by OpenSSH (base64 encoded).
    """
    # Base64 decode the key part
    key_body_bytes = base64.b64decode(public_key)

    # Calculate the SHA256 hash of the decoded bytes
    sha256_hash = hashlib.sha256(key_body_bytes).digest()

    # Base64 encode the hash
    fingerprint_b64 = base64.b64encode(sha256_hash).decode("utf-8")

    # OpenSSH typically does not include padding '=' in the fingerprint display
    fingerprint_b64 = fingerprint_b64.rstrip("=")

    return f"SHA256:{fingerprint_b64}"
