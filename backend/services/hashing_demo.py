"""
hashing_demo.py
---------------
EDUCATIONAL DEMONSTRATION ONLY.

This module is deliberately NOT connected to the analyzer pipeline.
The analyzer never hashes user-submitted passwords, because storing or deriving
anything from an arbitrary user-submitted password creates unnecessary risk for
a tool that only needs to give advice.

Key concepts demonstrated:
    Password  ->  Salt  ->  Password Hashing Function  ->  Stored Hash
    verify_password() compares by re-hashing, never by decrypting.

Hashing is ONE-WAY. Encryption is TWO-WAY and is NOT the same thing.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(synthetic_password: str) -> str:
    """
    Hash a SYNTHETIC password for demonstration.
    Never call this with a real user's password in this project.
    """
    return _ph.hash(synthetic_password)


def verify_password(stored_hash: str, candidate: str) -> bool:
    """Return True if the candidate matches the stored hash."""
    try:
        return _ph.verify(stored_hash, candidate)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Return True if the stored hash should be upgraded to current parameters."""
    try:
        return _ph.check_needs_rehash(stored_hash)
    except Exception:
        return True