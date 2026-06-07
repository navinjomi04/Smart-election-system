import hashlib
import random
import string

import bcrypt


def hash_password(password):
    """Hash password with bcrypt (UTF-8 safe)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password, hashed):
    """Verify bcrypt hash; falls back to legacy SHA-256 hex for existing rows."""
    if not hashed:
        return False
    if isinstance(hashed, bytes):
        hashed = hashed.decode("utf-8")
    if hashed.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        except ValueError:
            return False
    # Legacy SHA-256 (hex digest, no salt)
    return hashlib.sha256(password.encode()).hexdigest() == hashed


def generate_verification_code():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=10))


def generate_vote_hash(voter_id, candidate_id, previous_hash):
    data = f"{voter_id}{candidate_id}{previous_hash}"
    return hashlib.sha256(data.encode()).hexdigest()
