"""Small stdlib-only HTTP transport seam."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.error import HTTPError
from urllib.request import Request, urlopen


@dataclass(frozen=True, slots=True)
class HTTPRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    timeout: float = 20.0


@dataclass(frozen=True, slots=True)
class HTTPResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def header(headers: dict[str, str], name: str) -> str | None:
    wanted = name.casefold()
    for key, value in headers.items():
        if key.casefold() == wanted:
            return value
    return None


def urllib_transport(request: HTTPRequest) -> HTTPResponse:
    """Perform one request; HTTP statuses are values, transport failures raise."""

    raw = Request(
        request.url,
        data=request.body,
        headers=request.headers,
        method=request.method,
    )
    try:
        with urlopen(raw, timeout=request.timeout) as response:
            return HTTPResponse(
                status=response.status,
                headers=dict(response.headers.items()),
                body=response.read(),
            )
    except HTTPError as error:
        return HTTPResponse(
            status=error.code,
            headers=dict(error.headers.items()) if error.headers else {},
            body=error.read(),
        )
