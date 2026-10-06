"""Trusted, host-stamped principal context for one action invocation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .errors import invalid_request

ClaimValue = str | int | tuple[str, ...] | tuple[int, ...]
_CLAIM_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
CANONICAL_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


@dataclass(frozen=True, slots=True)
class ActionPrincipal:
    """Immutable identity assertion the host signed for a single action run."""

    kind: str
    external_id: str
    claims: Mapping[str, ClaimValue]


def extract_action_principal(raw: dict[str, Any]) -> ActionPrincipal | None:
    """Decode the optional signed principal without deriving any identity locally."""

    if "principal" not in raw:
        return None
    principal = raw["principal"]
    if not isinstance(principal, dict):
        raise invalid_request("principal must be an object")

    kind = _required_string(principal, "kind")
    external_id = _required_string(principal, "external_id")
    claims_raw = principal.get("claims")
    if not isinstance(claims_raw, dict):
        raise invalid_request("principal claims must be an object")

    claims: dict[str, ClaimValue] = {}
    for name, value in claims_raw.items():
        if not isinstance(name, str) or not _CLAIM_NAME.fullmatch(name):
            raise invalid_request("principal claim names are invalid")
        claims[name] = _claim_value(value)
    return ActionPrincipal(kind, external_id, MappingProxyType(claims))


def extract_action_run_id(raw: dict[str, Any]) -> str | None:
    """Decode the optional host-stamped ledger id; a present value must be a canonical UUID."""

    if "action_run_id" not in raw:
        return None
    value = raw["action_run_id"]
    if not isinstance(value, str) or not CANONICAL_UUID.fullmatch(value):
        raise invalid_request("action_run_id must be a canonical lowercase UUID")
    return value


def _required_string(raw: dict[str, Any], field: str) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise invalid_request(f"principal {field} must be a non-empty string without NUL")
    return value


def _claim_value(value: Any) -> ClaimValue:
    if isinstance(value, str):
        if "\x00" in value:
            raise invalid_request("principal claim values must not contain NUL")
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, list):
        raise invalid_request("principal claim values must be strings, integers, or arrays")
    if all(isinstance(item, str) and "\x00" not in item for item in value):
        return tuple(value)
    if all(isinstance(item, int) and not isinstance(item, bool) for item in value):
        return tuple(value)
    raise invalid_request("principal claim arrays must be homogeneous strings or integers")
