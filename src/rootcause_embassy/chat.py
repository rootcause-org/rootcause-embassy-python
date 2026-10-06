"""Embedded-chat JWT minting and widget tag rendering."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import time
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import Misconfigured

DEFAULT_TTL = 7200
DEFAULT_ASSURANCE = "customer_backend_jwt"
_HEADER = b'{"alg":"HS256","typ":"JWT"}'
# Loader contract revision (hub decisions.md #23).
LOADER_PATH = "/chat/widget/v1/loader.js?v=4"


@dataclass(frozen=True, slots=True)
class Claims:
    project: str = ""
    external_id: str = ""
    kind: str = ""
    origin: str = ""
    tenant: str = ""
    locale: str = ""
    color_scheme: str = ""
    asserted_by: str = ""
    assurance: str = ""
    jti: str = ""
    ttl: float = DEFAULT_TTL
    issued_at: float | None = None


@dataclass(frozen=True, slots=True)
class Widget:
    base_url: str = ""
    project: str = ""
    token: str = ""
    mode: str = ""
    target: str = ""
    locale: str = ""
    color_scheme: str = ""


def mint_embed_token(secret: str, claims: Claims) -> str:
    if not secret:
        raise Misconfigured("chat secret is required")
    if not claims.project:
        raise Misconfigured("chat project is required")
    if not claims.external_id:
        raise Misconfigured("chat external_id is required")
    if not claims.kind:
        raise Misconfigured("chat kind is required")
    if claims.ttl <= 0:
        raise Misconfigured("chat ttl must be positive")
    origin = canonical_origin(claims.origin)
    issued = int(time.time() if claims.issued_at is None else claims.issued_at)
    jti = claims.jti or str(uuid.uuid4())
    asserted_by = claims.asserted_by or claims.project
    assurance = claims.assurance or DEFAULT_ASSURANCE

    payload: dict[str, object] = {
        "sub": claims.external_id,
        "aud": f"rootcause:chat:{claims.project}",
        "iss": claims.project,
        "jti": jti,
        "origin": origin,
        "iat": issued,
        "nbf": issued,
        "exp": issued + int(claims.ttl),
        "principal": {
            "kind": claims.kind,
            "external_id": claims.external_id,
            "asserted_by": asserted_by,
            "assurance": assurance,
        },
    }
    if claims.tenant:
        payload["tenant"] = claims.tenant
    if claims.locale:
        payload["locale"] = claims.locale
    if claims.color_scheme:
        payload["color_scheme"] = claims.color_scheme
    claims_bytes = json.dumps(
        payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    signing_input = f"{_b64(_HEADER)}.{_b64(claims_bytes)}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


def canonical_origin(raw: str) -> str:
    if not raw:
        raise Misconfigured("chat origin is required")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as error:
        raise Misconfigured("chat origin is not a valid URL") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise Misconfigured("chat origin must be scheme://host[:port] with no path")
    host = parsed.hostname.casefold()
    if ":" in host:
        host = f"[{host}]"
    if (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
        port = None
    suffix = f":{port}" if port is not None else ""
    return f"{parsed.scheme}://{host}{suffix}"


def widget_tag_html(widget: Widget) -> str:
    if not widget.base_url:
        raise Misconfigured("chat base_url is required")
    if not widget.project:
        raise Misconfigured("chat project is required")
    if not widget.token:
        raise Misconfigured("chat token is required")
    attributes = [
        ("src", widget.base_url.rstrip("/") + LOADER_PATH),
        ("data-rc-project", widget.project),
        ("data-rc-token", widget.token),
    ]
    optional = [
        ("data-rc-mode", widget.mode),
        ("data-rc-target", widget.target),
        ("data-rc-locale", widget.locale),
        ("data-rc-color-scheme", widget.color_scheme),
    ]
    attributes.extend((name, value) for name, value in optional if value)
    rendered = " ".join(f'{name}="{html.escape(value, quote=True)}"' for name, value in attributes)
    return f"<script {rendered}></script>"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
