"""Pure action-plane route functions."""

from __future__ import annotations

import io
import json
import time
import traceback
from typing import Any

from .config import ActionContext, Config
from .errors import (
    INTERNAL_ERROR,
    METHOD_NOT_ALLOWED,
    Refusal,
    bad_signature,
    invalid_request,
    replay,
)
from .replay import check_freshness, record_nonce
from .resolver import Resolver
from .schema import validate_params
from .signature import HEADER, sign, verify
from .tenant import extract_tenant

Response = tuple[int, dict[str, str], bytes]
_CAPABILITIES = ["actions", "dry_run", "analysis_result", "health"]


class _CappedStringIO(io.StringIO):
    def __init__(self, cap: int) -> None:
        super().__init__()
        self._cap = cap
        self._used_bytes = 0

    def write(self, value: str) -> int:
        remaining = max(0, self._cap - self._used_bytes)
        if remaining:
            accepted = value.encode()[:remaining].decode(errors="ignore")
            super().write(accepted)
            self._used_bytes += len(accepted.encode())
        return len(value)


class ActionPlane:
    def __init__(self, config: Config, resolver: Resolver) -> None:
        self._config = config
        self._resolver = resolver

    def handle(self, method: str, subpath: str, signature: str | None, body: bytes) -> Response:
        if subpath == "/health":
            return self._health(method, signature, body)
        if subpath:
            return 404, {}, b""
        if method.upper() != "POST":
            payload = _json_bytes(
                {
                    "ok": False,
                    "error": {
                        "class": METHOD_NOT_ALLOWED,
                        "message": "POST required",
                    },
                }
            )
            return 405, {"Content-Type": "application/json", "Allow": "POST"}, payload
        if len(body) > self._config.max_body_bytes:
            refusal = invalid_request("request body exceeds max_body_bytes")
            return self._signed(
                refusal.status,
                {
                    "ok": False,
                    "error": {
                        "class": refusal.error_class,
                        "message": refusal.message,
                    },
                },
            )
        return self._invocation(signature, body)

    def _health(self, method: str, signature: str | None, raw_query: bytes) -> Response:
        if method.upper() != "GET" or not verify(signature, raw_query, self._config.secret):
            return 404, {}, b""
        return self._signed(
            200,
            {
                "ok": True,
                "embassy": "python",
                "version": "0.1.0",
                "protocol": 1,
                "capabilities": _CAPABILITIES,
            },
        )

    def _invocation(self, signature: str | None, body: bytes) -> Response:
        started = time.monotonic()
        deadline = started + self._config.total_deadline
        try:
            if not verify(signature, body, self._config.secret):
                raise bad_signature()
            invocation = _parse_invocation(body)
            tenant = extract_tenant(invocation, self._config.require_tenant_context)
            issued_at = _required_string(invocation, "issued_at")
            check_freshness(issued_at, self._config.clock_skew, self._config.now())
            nonce = _required_string(invocation, "nonce")
            if record_nonce(nonce, self._config.nonce_store, self._config.clock_skew):
                raise replay("nonce has already been seen")
            params = validate_params(invocation.get("params"), invocation.get("schema"))
            action_id = _required_string(invocation, "action_id")
            digest = _required_string(invocation, "script_digest")
            project_id = _required_string(invocation, "project_id")
            script = self._resolver.resolve(action_id, digest, project_id, deadline)
            if invocation.get("dry_run") is True:
                self._config.logger.info(
                    "rootcause action dry-run validated",
                    extra={
                        "action_id": action_id,
                        "digest": digest,
                        "param_keys": sorted(params),
                    },
                )
                return self._signed(
                    200,
                    _result_envelope(
                        True,
                        {"dry_run": True, "would_execute": True},
                        "",
                        None,
                        _duration(started),
                    ),
                )
            if self._config.runner is None:
                raise invalid_request("runtime python is not executable in this Embassy")
            return self._run(started, deadline, action_id, digest, script, tenant, params)
        except Refusal as refusal:
            self._config.logger.warning(
                "rootcause invocation refused",
                extra={"error_class": refusal.error_class, "status": refusal.status},
            )
            return self._signed(
                refusal.status,
                {
                    "ok": False,
                    "error": {
                        "class": refusal.error_class,
                        "message": refusal.message,
                    },
                },
            )
        except Exception as error:
            self._config.logger.error(
                "rootcause invocation failed",
                extra={"error_type": type(error).__name__},
            )
            return self._signed(
                500,
                {
                    "ok": False,
                    "error": {
                        "class": INTERNAL_ERROR,
                        "message": type(error).__name__,
                    },
                },
            )

    def _run(
        self,
        started: float,
        total_deadline: float,
        action_id: str,
        digest: str,
        script: str,
        tenant: Any,
        params: dict[str, Any],
    ) -> Response:
        execution_deadline = min(total_deadline, time.monotonic() + self._config.timeout)
        output = _CappedStringIO(self._config.max_stdout_bytes)
        context = ActionContext(
            action_id=action_id,
            digest=digest,
            script=script,
            tenant=tenant,
            out=output,
            deadline=execution_deadline,
        )
        if time.monotonic() >= execution_deadline:
            return self._execution_failure(
                started, output, TimeoutError("invocation deadline elapsed before execution"), ""
            )
        try:
            assert self._config.runner is not None
            return_value = self._config.runner(context, dict(params))
            if time.monotonic() > execution_deadline:
                raise TimeoutError("runner exceeded its deadline")
            # Validate before building the signed response, including NaN/Infinity.
            json.dumps(return_value, ensure_ascii=False, allow_nan=False)
        except BaseException as error:
            self._config.logger.info(
                "rootcause action execution failed",
                extra={
                    "action_id": action_id,
                    "digest": digest,
                    "param_keys": sorted(params),
                    "error_type": type(error).__name__,
                },
            )
            return self._execution_failure(started, output, error, traceback.format_exc())
        self._config.logger.info(
            "rootcause action executed",
            extra={
                "action_id": action_id,
                "digest": digest,
                "param_keys": sorted(params),
                "duration_ms": _duration(started),
            },
        )
        return self._signed(
            200,
            _result_envelope(True, return_value, output.getvalue(), None, _duration(started)),
        )

    def _execution_failure(
        self,
        started: float,
        output: io.StringIO,
        error: BaseException,
        backtrace: str,
    ) -> Response:
        wire_error: dict[str, Any] = {
            "class": type(error).__name__,
            "message": str(error),
            "backtrace": backtrace,
        }
        return self._signed(
            200,
            _result_envelope(False, None, output.getvalue(), wire_error, _duration(started)),
        )

    def _signed(self, status: int, payload: dict[str, Any]) -> Response:
        try:
            body = _json_bytes(payload)
        except (TypeError, ValueError) as error:
            status = 500
            body = _json_bytes(
                {
                    "ok": False,
                    "error": {
                        "class": INTERNAL_ERROR,
                        "message": type(error).__name__,
                    },
                }
            )
        return (
            status,
            {"Content-Type": "application/json", HEADER: sign(body, self._config.secret)},
            body,
        )


def _parse_invocation(body: bytes) -> dict[str, Any]:
    try:
        raw: Any = json.loads(body, parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        raise invalid_request("body is not valid JSON") from error
    if not isinstance(raw, dict):
        raise invalid_request("body is not valid JSON")

    fields = ("action_id", "script_digest", "project_id", "nonce", "issued_at")
    missing = sorted(field for field in fields if not _string(raw.get(field)))
    if missing:
        raise invalid_request(f"missing field(s): {', '.join(missing)}")
    if "runtime" in raw and raw["runtime"] != "python":
        raise invalid_request(f"unsupported runtime: {raw['runtime']}")
    if "dry_run" in raw and not isinstance(raw["dry_run"], bool):
        raise invalid_request("dry_run must be a boolean")
    return raw


def _required_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise invalid_request(f"missing field(s): {key}")
    return value


def _string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _duration(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def _result_envelope(
    ok: bool,
    return_value: Any,
    stdout: str,
    error: dict[str, Any] | None,
    duration_ms: int,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "return_value": return_value,
        "stdout": stdout,
        "error": error,
        "duration_ms": duration_ms,
    }


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
