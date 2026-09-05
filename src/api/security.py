"""Security helpers for the NEXUS prototype.

Adds lightweight protections without introducing a new dependency stack:
- simple in-memory rate limiter for sensitive endpoints
- role-based authorization dependency
- production-safe secret guard
"""

import os
import time
from collections import defaultdict, deque
from fastapi import Depends, Header, HTTPException

from api.auth import verify_token

REQUEST_WINDOW_SECONDS = 60
MAX_REQUESTS_PER_WINDOW = 60
_login_attempts = defaultdict(deque)


def check_rate_limit(key: str, limit: int = MAX_REQUESTS_PER_WINDOW) -> None:
    now = time.time()
    q = _login_attempts[key]
    while q and now - q[0] > REQUEST_WINDOW_SECONDS:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again shortly.")
    q.append(now)


def require_role(*allowed_roles: str):
    def dependency(authorization: str = Header(None)) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or malformed Authorization header.")
        payload = verify_token(authorization.removeprefix("Bearer ").strip())
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired session.")
        if payload.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient role permissions.")
        return payload
    return dependency


def ensure_production_secret() -> None:
    """Fail closed outside demo mode if the default secret is still active."""
    demo_mode = os.environ.get("NEXUS_DEMO_MODE", "1") == "1"
    secret = os.environ.get("APP_SECRET_KEY", "")
    if not demo_mode and (not secret or secret == "ncrb-hackathon-demo-secret-change-in-production"):
        raise RuntimeError("APP_SECRET_KEY must be configured when NEXUS_DEMO_MODE=0")
