"""Fail-closed Embassy configuration."""

from __future__ import annotations

import io
import logging
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from .errors import Misconfigured
from .http import HTTPRequest, HTTPResponse, urllib_transport
from .replay import MemoryNonceStore, NonceStore
from .tenant import Tenant

if TYPE_CHECKING:
    from .result import Result


PLACEHOLDER_FETCH_URL = "https://rootcause.invalid/actions/script"
Runner = Callable[["ActionContext", dict[str, Any]], Any]
ResultHandler = Callable[["Result"], None]
Transport = Callable[[HTTPRequest], HTTPResponse]


@dataclass(slots=True)
class ActionContext:
    action_id: str
    digest: str
    script: str
    tenant: Tenant | None
    out: io.StringIO
    deadline: float


def _new_nonce() -> str:
    return str(uuid.uuid4())


@dataclass(slots=True)
class Config:
    secret: str = ""
    fetch_url: str = ""
    trigger_url: str = ""
    sent_message_url: str = ""
    api_base_url: str = ""
    api_key: str = ""
    chat_secret: str = ""
    chat_project: str = ""
    chat_base_url: str = ""

    runner: Runner | None = None
    result_handler: ResultHandler | None = None
    timeout: float = 20.0
    total_deadline: float = 22.0
    clock_skew: float = 300.0
    require_tenant_context: bool = False
    cache_dir: str = ""
    max_stdout_bytes: int = 64 * 1024
    max_attachment_bytes: int = 256 * 1024
    nonce_store: NonceStore = field(default_factory=MemoryNonceStore)
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("rootcause_embassy"))
    now: Callable[[], float] = time.time
    nonce: Callable[[], str] = _new_nonce
    transport: Transport = urllib_transport

    def __post_init__(self) -> None:
        self.secret = self.secret or os.getenv("ROOTCAUSE_ACTION_SECRET", "")
        self.fetch_url = self.fetch_url or os.getenv("ROOTCAUSE_FETCH_URL", "")
        self.trigger_url = self.trigger_url or os.getenv("ROOTCAUSE_TRIGGER_URL", "")
        self.sent_message_url = self.sent_message_url or os.getenv("ROOTCAUSE_SENT_MESSAGE_URL", "")
        self.api_base_url = self.api_base_url or os.getenv("ROOTCAUSE_API_BASE_URL", "")
        self.api_key = self.api_key or os.getenv("ROOTCAUSE_API_KEY", "")
        self.chat_secret = self.chat_secret or os.getenv("ROOTCAUSE_CHAT_SECRET", "")
        self.chat_project = self.chat_project or os.getenv("ROOTCAUSE_CHAT_PROJECT", "")
        self.chat_base_url = self.chat_base_url or os.getenv("ROOTCAUSE_CHAT_BASE_URL", "")
        if not self.fetch_url:
            self.fetch_url = PLACEHOLDER_FETCH_URL
        self._validate()

    def _validate(self) -> None:
        if not self.secret:
            raise Misconfigured(
                "Secret is required (ROOTCAUSE_ACTION_SECRET); a blank HMAC key is forgeable"
            )
        if _placeholder_url(self.fetch_url):
            raise Misconfigured(
                f"FetchURL is the placeholder ({self.fetch_url}); set ROOTCAUSE_FETCH_URL"
            )
        if self.timeout <= 0:
            raise Misconfigured("Timeout must be positive")
        if self.total_deadline <= self.timeout:
            raise Misconfigured("TotalDeadline must exceed Timeout")
        if self.clock_skew <= 0:
            raise Misconfigured("ClockSkew must be positive")
        if self.max_stdout_bytes <= 0 or self.max_attachment_bytes <= 0:
            raise Misconfigured("byte caps must be positive")
        self._validate_api()
        self._validate_chat()

    def _validate_api(self) -> None:
        if not self.api_base_url and not self.api_key:
            return
        if not self.api_base_url:
            raise Misconfigured("APIBaseURL is required when APIKey is set")
        if not self.api_key:
            raise Misconfigured("APIKey is required when APIBaseURL is set")
        if not _absolute_http_url(self.api_base_url):
            raise Misconfigured("APIBaseURL must be an absolute http(s) URL")

    def _validate_chat(self) -> None:
        if not self.chat_secret and not self.chat_project and not self.chat_base_url:
            return
        if not self.chat_secret:
            raise Misconfigured("ChatSecret is required when chat is configured")
        if not self.chat_project:
            raise Misconfigured("ChatProject is required when chat is configured")
        if self.chat_secret == self.secret:
            raise Misconfigured("ChatSecret must differ from Secret")
        if self.chat_base_url and not _absolute_http_url(self.chat_base_url):
            raise Misconfigured("ChatBaseURL must be an absolute http(s) URL")


def _absolute_http_url(raw: str) -> bool:
    try:
        parsed = urlsplit(raw)
        _ = parsed.port
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _placeholder_url(raw: str) -> bool:
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname or ""
    except ValueError:
        return True
    return (
        raw == PLACEHOLDER_FETCH_URL
        or not _absolute_http_url(raw)
        or hostname.casefold().endswith(".invalid")
    )
