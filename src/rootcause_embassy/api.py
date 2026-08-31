"""Generic bearer-authenticated rootcause API caller."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .config import Config
from .errors import Misconfigured
from .http import HTTPRequest

_OAUTH_CLIENT_ID = "rcocl_cli"
_REFRESH_PREFIX = "rcor_"
_EXPIRY_SKEW = 60.0
_DEFAULT_EXPIRES_IN = 3600.0


@dataclass(slots=True)
class APIResponse:
    ok: bool = False
    status: int | None = None
    body: Any = None
    field_errors: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    retryable: bool = False
    err: Exception | None = None


@dataclass(slots=True)
class _CachedToken:
    lock: threading.Lock = field(default_factory=threading.Lock)
    token: str = ""
    expires_at: float = 0.0


_cache_lock = threading.Lock()
_token_cache: dict[tuple[str, str], _CachedToken] = {}


class API:
    def __init__(
        self,
        config: Config,
        api_base_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self._config = config
        self._base_url = config.api_base_url if api_base_url is None else api_base_url
        self._api_key = config.api_key if api_key is None else api_key

    def get(
        self,
        path: str,
        body: Any = None,
        params: dict[str, Any] | None = None,
    ) -> APIResponse:
        return self._call("GET", path, body, params)

    def post(
        self,
        path: str,
        body: Any = None,
        params: dict[str, Any] | None = None,
    ) -> APIResponse:
        return self._call("POST", path, body, params)

    def patch(
        self,
        path: str,
        body: Any = None,
        params: dict[str, Any] | None = None,
    ) -> APIResponse:
        return self._call("PATCH", path, body, params)

    def put(
        self,
        path: str,
        body: Any = None,
        params: dict[str, Any] | None = None,
    ) -> APIResponse:
        return self._call("PUT", path, body, params)

    def delete(
        self,
        path: str,
        body: Any = None,
        params: dict[str, Any] | None = None,
    ) -> APIResponse:
        return self._call("DELETE", path, body, params)

    def _call(
        self,
        method: str,
        path: str,
        body: Any,
        params: dict[str, Any] | None,
    ) -> APIResponse:
        target = self._build_url(path, params)
        payload = _encode_body(body)
        try:
            bearer = self._bearer()
        except Exception as error:
            return APIResponse(error=f"auth: {error}", retryable=True, err=error)
        response = self._perform(method, target, bearer, payload)
        if response.status == 401 and self._api_key.startswith(_REFRESH_PREFIX):
            self._invalidate()
            try:
                bearer = self._bearer()
            except Exception as error:
                return APIResponse(error=f"auth: {error}", retryable=True, err=error)
            response = self._perform(method, target, bearer, payload)
        return response

    def _perform(self, method: str, target: str, bearer: str, payload: bytes | None) -> APIResponse:
        if method not in {"GET", "POST", "PATCH", "PUT", "DELETE"}:
            raise Misconfigured(f"unsupported API method: {method}")
        headers = {
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/json",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        try:
            response = self._config.transport(
                HTTPRequest(
                    method=method,
                    url=target,
                    headers=headers,
                    body=payload,
                    timeout=self._config.timeout,
                )
            )
        except Exception as error:
            return APIResponse(error=type(error).__name__, retryable=True, err=error)
        target_path = urlsplit(target).path
        self._config.logger.info(
            "rootcause api call",
            extra={"method": method, "path": target_path, "status": response.status},
        )
        parsed = _parse_body(response.body)
        if 200 <= response.status < 300:
            return APIResponse(ok=True, status=response.status, body=parsed)
        result = APIResponse(
            status=response.status,
            body=parsed,
            error=f"http_{response.status}",
            retryable=_retryable_status(response.status),
        )
        if isinstance(parsed, dict):
            field_errors = parsed.get("field_errors")
            if isinstance(field_errors, dict):
                result.field_errors = field_errors
            for key in ("error", "message"):
                message = parsed.get(key)
                if isinstance(message, str) and message:
                    result.error = message
                    break
        return result

    def _build_url(self, path: str, params: dict[str, Any] | None) -> str:
        if not self._base_url:
            raise Misconfigured("APIBaseURL is not configured")
        if not self._api_key:
            raise Misconfigured("APIKey is not configured")
        if not path:
            raise Misconfigured("API path is required")
        try:
            base = urlsplit(self._base_url.rstrip("/"))
            candidate = urlsplit(path)
        except ValueError as error:
            raise Misconfigured("API path is not a valid URL") from error
        if candidate.scheme or candidate.netloc:
            try:
                same_origin = _origin(candidate) == _origin(base)
            except ValueError as error:
                raise Misconfigured("API path has an invalid port") from error
            if not same_origin:
                raise Misconfigured("absolute API path is off-origin")
            target = candidate
        else:
            joined_path = base.path.rstrip("/") + "/" + candidate.path.lstrip("/")
            target = urlsplit(
                urlunsplit(
                    (
                        base.scheme,
                        base.netloc,
                        joined_path,
                        candidate.query,
                        candidate.fragment,
                    )
                )
            )
        query = list(parse_qsl(target.query, keep_blank_values=True))
        if params:
            for key, value in params.items():
                if isinstance(value, (list, tuple)):
                    query.extend((key, str(item)) for item in value)
                else:
                    query.append((key, str(value)))
        return urlunsplit(
            (target.scheme, target.netloc, target.path, urlencode(query), target.fragment)
        )

    def _bearer(self) -> str:
        if not self._api_key.startswith(_REFRESH_PREFIX):
            return self._api_key
        entry = _token_entry(self._base_url, self._api_key)
        with entry.lock:
            if entry.token and time.monotonic() < entry.expires_at - _EXPIRY_SKEW:
                return entry.token
            token, expires_in = self._exchange()
            entry.token = token
            entry.expires_at = time.monotonic() + expires_in
            return token

    def _exchange(self) -> tuple[str, float]:
        endpoint = self._base_url.rstrip("/") + "/oauth/token"
        body = urlencode(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", self._api_key),
                ("client_id", _OAUTH_CLIENT_ID),
            ]
        ).encode()
        try:
            response = self._config.transport(
                HTTPRequest(
                    method="POST",
                    url=endpoint,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=body,
                    timeout=self._config.timeout,
                )
            )
        except Exception as error:
            raise RuntimeError("token exchange transport error") from error
        if not 200 <= response.status < 300:
            raise RuntimeError(f"token exchange failed: http_{response.status}")
        parsed = _parse_body(response.body)
        if (
            not isinstance(parsed, dict)
            or not isinstance(parsed.get("access_token"), str)
            or not parsed["access_token"]
        ):
            raise RuntimeError("token exchange response missing access_token")
        expires = parsed.get("expires_in", _DEFAULT_EXPIRES_IN)
        if not isinstance(expires, (int, float)) or isinstance(expires, bool) or expires <= 0:
            expires = _DEFAULT_EXPIRES_IN
        return parsed["access_token"], float(expires)

    def _invalidate(self) -> None:
        entry = _token_entry(self._base_url, self._api_key)
        with entry.lock:
            entry.token = ""
            entry.expires_at = 0.0


def _token_entry(base_url: str, api_key: str) -> _CachedToken:
    key = (base_url, api_key)
    with _cache_lock:
        return _token_cache.setdefault(key, _CachedToken())


def _origin(url: Any) -> tuple[str, str, int | None]:
    return url.scheme.casefold(), (url.hostname or "").casefold(), url.port


def _encode_body(body: Any) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode()
    try:
        return json.dumps(body, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as error:
        raise Misconfigured("API body could not be encoded") from error


def _parse_body(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body.decode(errors="replace")


def _retryable_status(status: int) -> bool:
    return status >= 500 or status in {408, 429}
