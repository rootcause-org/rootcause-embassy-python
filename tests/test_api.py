from __future__ import annotations

import pytest

from rootcause_embassy import Config, Embassy
from rootcause_embassy.errors import Misconfigured
from rootcause_embassy.http import HTTPRequest, HTTPResponse


@pytest.mark.parametrize(
    ("status", "retryable"),
    [
        (200, False),
        (400, False),
        (401, False),
        (408, True),
        (422, False),
        (429, True),
        (500, True),
        (503, True),
    ],
)
def test_api_retryable_table(status: int, retryable: bool) -> None:
    def transport(request: HTTPRequest) -> HTTPResponse:
        return HTTPResponse(status, body=b"{}")

    api = Embassy(
        Config(
            secret="secret",
            fetch_url="https://host.test/actions/script",
            api_base_url="https://api.test",
            api_key="static",
            transport=transport,
        )
    ).api
    response = api.get("/resource")
    assert response.retryable is retryable
    assert response.ok is (200 <= status < 300)


def test_api_blank_path_and_off_origin_raise() -> None:
    api = Embassy(
        Config(
            secret="secret",
            fetch_url="https://host.test/actions/script",
            api_base_url="https://api.test",
            api_key="static",
        )
    ).api
    with pytest.raises(Misconfigured):
        api.get("")
    with pytest.raises(Misconfigured):
        api.get("https://evil.test/resource")
    with pytest.raises(Misconfigured):
        api.get("https://api.test:bad/resource")


def test_api_relative_path_keeps_configured_base_path() -> None:
    requests: list[HTTPRequest] = []

    def transport(request: HTTPRequest) -> HTTPResponse:
        requests.append(request)
        return HTTPResponse(200, body=b"{}")

    api = Embassy(
        Config(
            secret="secret",
            fetch_url="https://host.test/actions/script",
            api_base_url="https://api.test/rootcause",
            api_key="static",
            transport=transport,
        )
    ).api
    assert api.get("/v1/resource", params={"limit": 10}).ok
    assert requests[0].url == "https://api.test/rootcause/v1/resource?limit=10"
