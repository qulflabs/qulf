import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError


def generate_session_token() -> str:
    """
    Generates a cryptographically secure random session token.
    """
    # 32 bytes (256 bits) of entropy prevents brute-force session guessing.
    # We use URL-safe encoding to guarantee compatibility when tokens are
    # placed in HTTP headers, cookies, or URL queries without escaping.
    return secrets.token_urlsafe(32)


# total coincidence :)
ph = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hashes a raw password using the memory-hard Argon2id algorithm.
    """
    hash_string = ph.hash(password)
    return hash_string


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Safely verifies a password against a stored Argon2id hash.

    Prevents side-channel timing attacks by returning a boolean outcome.
    """
    try:
        return ph.verify(hashed_password, password)
    except (VerifyMismatchError, InvalidHashError):
        # We catch hash structure errors to avoid throwing 500 server crashes
        # if a legacy, corrupted, or non-Argon2 string is passed from the DB.
        return False
