"""
Authentication Module — Access Control for the Investigator Dashboard
=======================================================================
Implements password-based login and signed, expiring access tokens
(a lightweight JWT-style scheme) using only Python's standard library —
no extra dependencies to install.

Security notes for the demo / pitch:
  - Passwords are never stored in plaintext: each is hashed with PBKDF2-HMAC-SHA256
    (100,000 iterations) with a unique per-user salt.
  - Access tokens are signed with HMAC-SHA256 using a server-side secret key,
    so a client cannot forge or tamper with a token without detection.
  - Tokens expire after a fixed time window, limiting the damage if one leaks.
  - In production, SECRET_KEY would come from an environment variable / secrets
    manager, not be hardcoded — this is flagged clearly below.
"""

import hashlib
import hmac
import json
import base64
import time
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
USERS_FILE = PROJECT_ROOT / "data" / "users.json"

# NOTE: in a real deployment this MUST come from an environment variable
# (e.g. os.environ["APP_SECRET_KEY"]), never committed to source control.
SECRET_KEY = os.environ.get("APP_SECRET_KEY", "ncrb-hackathon-demo-secret-change-in-production")
DEMO_MODE = os.environ.get("NEXUS_DEMO_MODE", "1") == "1"

TOKEN_TTL_SECONDS = 60 * 60 * 8  # 8-hour shift-length session

if not DEMO_MODE and SECRET_KEY == "ncrb-hackathon-demo-secret-change-in-production":
    raise RuntimeError("APP_SECRET_KEY must be configured when NEXUS_DEMO_MODE=0")


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def hash_password(password: str, salt: str = None) -> tuple:
    """Return (hash_hex, salt_hex) using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(16).hex()
    salt_bytes = bytes.fromhex(salt)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, 100_000)
    return hashed.hex(), salt


def load_users() -> dict:
    if USERS_FILE.exists():
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}


def verify_credentials(username: str, password: str) -> dict | None:
    """Return the user record (without password data) if credentials are valid, else None."""
    users = load_users()
    user = users.get(username)
    if not user:
        return None
    computed_hash, _ = hash_password(password, user["salt"])
    if hmac.compare_digest(computed_hash, user["password_hash"]):
        return {"username": username, "role": user["role"], "full_name": user.get("full_name", username)}
    return None


def create_token(username: str, role: str) -> str:
    """Create a signed, expiring access token (JWT-style: header.payload.signature)."""
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    payload_b64 = _b64encode(json.dumps(payload).encode())
    signature = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).digest()
    signature_b64 = _b64encode(signature)
    return f"{payload_b64}.{signature_b64}"


def verify_token(token: str) -> dict | None:
    """Verify a token's signature and expiry. Returns the payload dict if valid, else None."""
    try:
        payload_b64, signature_b64 = token.split(".")
    except ValueError:
        return None

    expected_sig = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).digest()
    expected_sig_b64 = _b64encode(expected_sig)
    if not hmac.compare_digest(expected_sig_b64, signature_b64):
        return None  # signature mismatch — token was tampered with or forged

    try:
        payload = json.loads(_b64decode(payload_b64))
    except Exception:
        return None

    if payload.get("exp", 0) < time.time():
        return None  # expired

    return payload
