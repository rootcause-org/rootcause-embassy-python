from __future__ import annotations

import hashlib
import time
from urllib.parse import parse_qs, urlsplit

import pytest

from rootcause_embassy import Config
from rootcause_embassy.errors import Refusal
from rootcause_embassy.http import HTTPRequest, HTTPResponse
from rootcause_embassy.resolver import Resolver
from rootcause_embassy.signature import HEADER, sign

PROJECT_A = "11111111-1111-1111-1111-111111111111"
PROJECT_B = "22222222-2222-2222-2222-222222222222"
SECRET_A = "project-a-secret"
SECRET_B = "project-b-secret"


def test_map_cache_is_partitioned_by_project_for_memory_and_disk(tmp_path) -> None:
    script = "return-value"
    digest = "sha256:" + hashlib.sha256(script.encode()).hexdigest()
    calls: list[str] = []

    def transport(request: HTTPRequest) -> HTTPResponse:
        project_id = parse_qs(urlsplit(request.url).query)["project_id"][0]
        calls.append(project_id)
        if project_id == PROJECT_A:
            body = (
                '{"action_id":"action","digest":"' + digest + '","script":"' + script + '"}'
            ).encode()
            return HTTPResponse(200, {HEADER: sign(body, SECRET_A)}, body)
        return HTTPResponse(403)

    def config() -> Config:
        return Config(
            secrets={PROJECT_A: SECRET_A, PROJECT_B: SECRET_B},
            fetch_url="https://host.test/actions/script",
            cache_dir=str(tmp_path),
            transport=transport,
        )

    resolver = Resolver(config())
    assert resolver.resolve("action", digest, PROJECT_A, time.monotonic() + 1) == script
    with pytest.raises(Refusal, match="script fetch returned 403"):
        resolver.resolve("action", digest, PROJECT_B, time.monotonic() + 1)
    assert calls == [PROJECT_A, PROJECT_B]

    # A fresh resolver exercises the disk path; a digest-only path would reuse A's entry.
    disk_resolver = Resolver(config())
    with pytest.raises(Refusal, match="script fetch returned 403"):
        disk_resolver.resolve("action", digest, PROJECT_B, time.monotonic() + 1)
    assert calls == [PROJECT_A, PROJECT_B, PROJECT_B]
