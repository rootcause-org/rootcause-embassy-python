"""HMAC signing shared by the action and analysis planes."""

from __future__ import annotations

import hashlib
import hmac

HEADER = "X-Webhook-Signature"
_PREFIX = "sha256="


def sign(body: bytes, secret: str) -> str:
    """Sign exact wire bytes; a blank secret fails closed."""

    if not secret:
        return ""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return _PREFIX + digest


def verify(header: str | None, body: bytes, secret: str) -> bool:
    """Constant-time verification; missing/malformed input is simply false."""

    if not header or not secret:
        return False
    return hmac.compare_digest(header, sign(body, secret))
