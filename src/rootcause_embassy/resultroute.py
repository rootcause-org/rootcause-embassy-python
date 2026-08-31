"""Pure analysis-result callback route."""

from __future__ import annotations

import json
from typing import Any

from .action import Response, _json_bytes
from .config import Config
from .errors import (
    INTERNAL_ERROR,
    METHOD_NOT_ALLOWED,
    Refusal,
    bad_signature,
    handler_error,
    invalid_request,
)
from .replay import check_freshness, record_nonce
from .result import decode_result
from .signature import HEADER, sign, verify


class ResultRoute:
    def __init__(self, config: Config) -> None:
        self._config = config

    def handle(self, method: str, signature: str | None, body: bytes) -> Response:
        if method.upper() != "POST":
            method_body = _json_bytes(
                {
                    "ok": False,
                    "error": {
                        "class": METHOD_NOT_ALLOWED,
                        "message": "POST required",
                    },
                }
            )
            return 405, {"Content-Type": "application/json", "Allow": "POST"}, method_body
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
        nonce = ""
        consumed = False
        try:
            if not verify(signature, body, self._config.secret):
                raise bad_signature()
            payload = _parse(body)
            missing = sorted(
                key
                for key in ("analysis_id", "nonce", "issued_at")
                if not _string(payload.get(key))
            )
            if missing:
                raise invalid_request(f"missing field(s): {', '.join(missing)}")
            check_freshness(
                _string(payload["issued_at"]),
                self._config.clock_skew,
                self._config.now(),
            )
            nonce = _string(payload["nonce"])
            if record_nonce(nonce, self._config.nonce_store, self._config.clock_skew):
                self._config.logger.info(
                    "rootcause result redelivery acked",
                    extra={"analysis_id": _string(payload["analysis_id"])},
                )
                return self._signed(200, {"ok": True})
            consumed = True
            if self._config.result_handler is None:
                raise handler_error("ResultHandler is not configured")
            try:
                self._config.result_handler(decode_result(payload))
            except Refusal:
                raise
            except BaseException as error:
                error_type = type(error).__name__
                self._config.logger.error(
                    "rootcause result handler failed",
                    extra={
                        "analysis_id": _string(payload["analysis_id"]),
                        "error_type": error_type,
                    },
                )
                raise Refusal(500, INTERNAL_ERROR, error_type) from error
            metadata = payload.get("metadata")
            metadata_keys = (
                sorted(str(key) for key in metadata) if isinstance(metadata, dict) else []
            )
            self._config.logger.info(
                "rootcause result dispatched",
                extra={
                    "analysis_id": _string(payload["analysis_id"]),
                    "metadata_keys": metadata_keys,
                },
            )
            return self._signed(200, {"ok": True})
        except Refusal as refusal:
            if consumed:
                self._config.nonce_store.release(nonce)
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
            if consumed:
                self._config.nonce_store.release(nonce)
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

    def _signed(self, status: int, payload: dict[str, Any]) -> Response:
        body = _json_bytes(payload)
        return (
            status,
            {"Content-Type": "application/json", HEADER: sign(body, self._config.secret)},
            body,
        )


def _parse(body: bytes) -> dict[str, Any]:
    try:
        payload: Any = json.loads(body, parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        raise invalid_request("body is not valid JSON") from error
    if not isinstance(payload, dict):
        raise invalid_request("body is not valid JSON")
    return payload


def _string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _reject_constant(value: str) -> None:
    raise ValueError(value)
