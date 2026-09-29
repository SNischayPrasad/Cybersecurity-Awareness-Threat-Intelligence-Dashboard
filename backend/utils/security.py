"""
Security utilities: input sanitisation, API-key RBAC, rate limiting, headers.

Defence in depth:
  * The backend strips HTML/control characters from free text before storing it.
  * The frontend ALSO escapes everything it renders (textContent / escapeHtml).
  * Writes require an API key mapped to a role (analyst/admin).
  * Every write is recorded in the audit_log table.
"""
from __future__ import annotations

import hmac
import re
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import current_app, g, jsonify, request

TAG_RE = re.compile(r"<[^>]*>")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


def sanitize_text(value, max_length: int = 2000) -> str:
    """Strip HTML tags and control characters, trim whitespace, cap length."""
    if value is None:
        return ""
    text = str(value)
    text = TAG_RE.sub("", text)
    text = CONTROL_RE.sub("", text)
    return text.strip()[:max_length]


def resolve_role(api_key: str | None) -> str:
    """Map an API key to a role using constant-time comparison."""
    if not api_key:
        return "viewer"
    admin_key = current_app.config.get("ADMIN_API_KEY") or ""
    analyst_key = current_app.config.get("ANALYST_API_KEY") or ""
    if admin_key and hmac.compare_digest(api_key, admin_key):
        return "admin"
    if analyst_key and hmac.compare_digest(api_key, analyst_key):
        return "analyst"
    return "invalid"


def require_role(minimum_role: str):
    """Decorator: allow the request only if the caller's role >= minimum_role."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            role = resolve_role(request.headers.get("X-API-Key"))
            if role == "invalid":
                return jsonify(error="unauthorized", message="Invalid API key."), 401
            if role == "viewer":
                return jsonify(error="unauthorized",
                               message="This action requires an API key (X-API-Key header)."), 401
            if ROLE_RANK[role] < ROLE_RANK[minimum_role]:
                return jsonify(error="forbidden",
                               message=f"Role '{role}' cannot perform this action (needs '{minimum_role}')."), 403
            g.role = role
            return fn(*args, **kwargs)

        return wrapper

    return decorator


class RateLimiter:
    """Simple in-memory sliding-window limiter (per client IP).

    Good enough for a single-process demo. Production would use Redis or an
    API gateway so limits are shared across workers.
    """

    def __init__(self):
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, client: str, limit_per_minute: int) -> bool:
        if limit_per_minute <= 0:
            return True
        now = time.monotonic()
        with self.lock:
            q = self.hits[client]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= limit_per_minute:
                return False
            q.append(now)
            return True


def apply_security_headers(response):
    """HTTP security headers for every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    # Scripts only from this origin + the Chart.js CDN. No inline scripts allowed.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    return response
