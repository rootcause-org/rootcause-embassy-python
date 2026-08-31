from __future__ import annotations

import pytest

from rootcause_embassy.chat import canonical_origin
from rootcause_embassy.errors import Misconfigured


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://Admin.Example.com", "https://admin.example.com"),
        ("https://admin.example.com/", "https://admin.example.com"),
        ("https://admin.example.com:443", "https://admin.example.com"),
        ("http://admin.example.com:80", "http://admin.example.com"),
        ("https://admin.example.com:8443", "https://admin.example.com:8443"),
    ],
)
def test_canonical_origin(raw: str, expected: str) -> None:
    assert canonical_origin(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "ftp://app.example.com",
        "https://app.example.com/chat",
        "https://app.example.com?a=1",
        "https://app.example.com/#fragment",
    ],
)
def test_canonical_origin_refusals(raw: str) -> None:
    with pytest.raises(Misconfigured):
        canonical_origin(raw)
