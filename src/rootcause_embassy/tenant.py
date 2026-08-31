"""Trusted tenant tuple validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .errors import invalid_request


@dataclass(frozen=True, slots=True)
class Tenant:
    id: str
    slug: str
    scope_value: str = ""


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$")
_NIL_UUID = "00000000-0000-0000-0000-000000000000"
_FIELDS = ("tenant_id", "tenant_slug", "tenant_scope_value")


def extract_tenant(raw: dict[str, Any], require_tenant: bool) -> Tenant | None:
    provided = [field for field in _FIELDS if field in raw]
    if not provided:
        if require_tenant:
            raise invalid_request("tenant context is required for this Embassy deployment")
        return None

    non_strings = [field for field in provided if not isinstance(raw[field], str)]
    if non_strings:
        raise invalid_request(f"tenant field(s) must be strings: {', '.join(non_strings)}")
    values = {field: str(raw[field]) for field in provided}
    if any("\x00" in value for value in values.values()):
        raise invalid_request("tenant field(s) must not contain NUL bytes")

    tenant_id = values.get("tenant_id", "")
    slug = values.get("tenant_slug", "")
    scope_value = values.get("tenant_scope_value", "")
    if not tenant_id and not slug and not scope_value:
        raise invalid_request("flat invocation must omit tenant fields")
    if not tenant_id:
        raise invalid_request("tenant_id missing for tenant-bound invocation")
    if not slug:
        raise invalid_request("tenant_slug missing for tenant-bound invocation")
    if not _UUID.fullmatch(tenant_id):
        raise invalid_request("tenant_id must be a UUID")
    if tenant_id.casefold() == _NIL_UUID:
        raise invalid_request("tenant_id must not be the nil UUID")
    if not _SLUG.fullmatch(slug):
        raise invalid_request("tenant_slug is invalid")
    return Tenant(tenant_id, slug, scope_value)
