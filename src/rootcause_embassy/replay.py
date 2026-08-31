"""Freshness and replay protection."""

from __future__ import annotations

import re
import threading
import time
from datetime import UTC, datetime
from typing import Protocol

from .errors import replay

_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


class NonceStore(Protocol):
    """Atomic nonce store. ``seen`` records unseen nonces and reports duplicates."""

    def seen(self, nonce: str, ttl: float) -> bool: ...

    def release(self, nonce: str) -> None: ...


class MemoryNonceStore:
    """Single-process nonce store using monotonic expiry times."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._expiries: dict[str, float] = {}

    def seen(self, nonce: str, ttl: float) -> bool:
        now = time.monotonic()
        with self._lock:
            expired = [key for key, deadline in self._expiries.items() if deadline <= now]
            for key in expired:
                del self._expiries[key]
            if nonce in self._expiries:
                return True
            self._expiries[nonce] = now + ttl
            return False

    def release(self, nonce: str) -> None:
        with self._lock:
            self._expiries.pop(nonce, None)


def check_freshness(issued_at: str, skew: float, now: float) -> None:
    try:
        if not _RFC3339.fullmatch(issued_at):
            raise ValueError
        if issued_at.endswith("Z"):
            issued = datetime.fromisoformat(issued_at[:-1] + "+00:00")
        else:
            issued = datetime.fromisoformat(issued_at)
        if issued.tzinfo is None:
            raise ValueError
        issued_timestamp = issued.astimezone(UTC).timestamp()
    except (ValueError, OverflowError) as error:
        raise replay("issued_at is not a valid RFC3339 timestamp") from error
    if abs(now - issued_timestamp) > skew:
        drift = int(abs(now - issued_timestamp))
        raise replay(f"issued_at outside ±{int(skew)}s window (skew={drift}s)")


def record_nonce(nonce: str, store: NonceStore, skew: float) -> bool:
    if not nonce:
        raise replay("nonce missing")
    return store.seen(nonce, 2 * skew + 1)
