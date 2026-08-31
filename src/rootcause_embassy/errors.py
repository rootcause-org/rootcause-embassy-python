"""Contract error vocabulary."""

from __future__ import annotations

INVALID_REQUEST = "invalid_request"
BAD_SIGNATURE = "bad_signature"
REPLAY = "replay"
SCHEMA_VIOLATION = "schema_violation"
RESOLVE_FAILED = "resolve_failed"
HANDLER_ERROR = "handler_error"
INTERNAL_ERROR = "internal_error"
METHOD_NOT_ALLOWED = "method_not_allowed"


class EmbassyError(Exception):
    """A surfaced Embassy or remote-host failure."""

    def __init__(self, status: int, error_class: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.error_class = error_class
        self.message = message


class Misconfigured(EmbassyError):
    """A deploy or caller bug which must not be hidden as an API outcome."""

    def __init__(self, message: str) -> None:
        super().__init__(0, "misconfigured", message)


class Refusal(EmbassyError):
    """An inbound contract refusal rendered as a signed non-2xx response."""


def invalid_request(message: str) -> Refusal:
    return Refusal(400, INVALID_REQUEST, message)


def bad_signature(message: str = "signature missing or invalid") -> Refusal:
    return Refusal(401, BAD_SIGNATURE, message)


def replay(message: str) -> Refusal:
    return Refusal(409, REPLAY, message)


def schema_violation(message: str) -> Refusal:
    return Refusal(422, SCHEMA_VIOLATION, message)


def resolve_failed(message: str) -> Refusal:
    return Refusal(502, RESOLVE_FAILED, message)


def handler_error(message: str) -> Refusal:
    return Refusal(500, HANDLER_ERROR, message)
