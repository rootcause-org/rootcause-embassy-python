"""Defense-in-depth parameter schema validation."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .errors import schema_violation

_TYPES = {"string", "integer", "number", "boolean", "string[]"}
_RESERVED = {
    "tenant_id",
    "tenant_slug",
    "tenant_scope_value",
    "rc_tenant_id",
    "rc_tenant_slug",
    "rc_tenant_scope_value",
}


def _reserved(name: str) -> bool:
    folded = name.casefold()
    return folded in _RESERVED or folded.startswith("rc_tenant_")


@dataclass(frozen=True, slots=True)
class _ParamSpec:
    type: str
    required: bool


def validate_params(raw_params: Any, raw_schema: Any) -> dict[str, Any]:
    specs = _normalize_schema(raw_schema)
    if raw_params is None:
        params: dict[str, Any] = {}
    elif isinstance(raw_params, dict):
        params = raw_params
    else:
        raise schema_violation("params must be an object")

    reserved = sorted({name for name in (*params, *specs) if _reserved(name)})
    if reserved:
        raise schema_violation(
            f"tenant scope is host-owned; reserved param(s): {', '.join(reserved)}"
        )
    unknown = sorted(set(params) - set(specs))
    if unknown:
        raise schema_violation(f"unknown param(s): {', '.join(unknown)}")

    normalized: dict[str, Any] = {}
    for name, spec in specs.items():
        if name not in params:
            if spec.required:
                raise schema_violation(f"missing required param: {name}")
            continue
        normalized[name] = _check_type(name, params[name], spec.type)
    return normalized


def _normalize_schema(raw: Any) -> dict[str, _ParamSpec]:
    if raw is None:
        raise schema_violation("schema is missing")
    if isinstance(raw, list):
        raise schema_violation("schema must be a JSON object, got array")
    if not isinstance(raw, dict):
        raise schema_violation("schema must be a JSON object")
    specs: dict[str, _ParamSpec] = {}
    for name, raw_spec in raw.items():
        if not isinstance(name, str):
            raise schema_violation("schema param names must be strings")
        if not isinstance(raw_spec, dict):
            raise schema_violation(f"param {name}: spec must be an object")
        type_name = raw_spec.get("type")
        if not isinstance(type_name, str) or type_name not in _TYPES:
            shown = type_name if isinstance(type_name, str) else ""
            raise schema_violation(f'param {name}: unsupported type "{shown}"')
        required = raw_spec.get("required", True)
        if not isinstance(required, bool):
            required = True
        specs[name] = _ParamSpec(type_name, required)
    return specs


def _check_type(name: str, value: Any, type_name: str) -> Any:
    valid = False
    normalized = value
    if type_name == "string":
        valid = isinstance(value, str)
    elif type_name == "boolean":
        valid = isinstance(value, bool)
    elif type_name == "integer":
        valid = isinstance(value, int) and not isinstance(value, bool)
    elif type_name == "number":
        valid = (
            isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
        )
    elif type_name == "string[]":
        valid = isinstance(value, list) and all(isinstance(item, str) for item in value)
        if isinstance(value, list) and not valid:
            raise schema_violation(f"param {name}: expected string[], got a non-string element")
        if valid:
            normalized = list(value)
    if not valid:
        raise schema_violation(f"param {name}: expected {type_name}, got {_json_kind(value)}")
    return normalized


def _json_kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"
