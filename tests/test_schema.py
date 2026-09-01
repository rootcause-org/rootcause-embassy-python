from __future__ import annotations

import pytest

from rootcause_embassy.errors import Refusal
from rootcause_embassy.schema import validate_params


def test_schema_types_and_required_default() -> None:
    schema = {
        "s": {"type": "string"},
        "i": {"type": "integer"},
        "n": {"type": "number"},
        "b": {"type": "boolean"},
        "ss": {"type": "string[]"},
    }
    params = {"s": "x", "i": 1, "n": 1.5, "b": True, "ss": ["a", "b"]}
    assert validate_params(params, schema) == params
    with pytest.raises(Refusal, match="missing required param"):
        validate_params({}, {"s": {"type": "string"}})
    with pytest.raises(Refusal, match="expected integer"):
        validate_params({"i": True}, {"i": {"type": "integer"}})


def test_schema_reserved_names_refused_in_params_and_schema() -> None:
    with pytest.raises(Refusal, match="reserved"):
        validate_params(
            {"RC_Tenant_Slug": "acme"},
            {"RC_Tenant_Slug": {"type": "string"}},
        )
    with pytest.raises(Refusal, match="reserved"):
        validate_params({}, {"tenant_id": {"type": "string", "required": False}})
    with pytest.raises(Refusal, match="reserved"):
        validate_params({}, {"rc_tenant_custom": {"type": "string"}})
    with pytest.raises(Refusal, match="reserved"):
        validate_params(
            {"principal_kind": "acme_user"},
            {"principal_kind": {"type": "string"}},
        )
    with pytest.raises(Refusal, match="reserved"):
        validate_params({}, {"RC_Principal_Custom": {"type": "string"}})
