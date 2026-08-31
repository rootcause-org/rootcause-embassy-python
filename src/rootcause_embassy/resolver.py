"""Digest-pinned script resolution and caching."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from .config import Config
from .errors import resolve_failed
from .http import HTTPRequest, header
from .signature import HEADER, sign, verify

_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")


def digest_hex(digest: str) -> str:
    match = _DIGEST.fullmatch(digest)
    if not match:
        raise resolve_failed("malformed script_digest")
    return match.group(1)


class Resolver:
    """Resolve memory → optional disk → signed host fetch.

    Map-mode cache entries include the canonical project because fetch authorization is
    project-specific even when two projects approve the same digest.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._lock = threading.RLock()
        self._memory: dict[str, str] = {}

    def resolve(self, action_id: str, digest: str, project_id: str, deadline: float) -> str:
        hex_digest = digest_hex(digest)
        canonical_project_id = self._canonical_project_id(project_id)
        if self._config.map_mode and canonical_project_id is None:
            raise resolve_failed("script fetch failed")
        cached = self._from_cache(canonical_project_id, hex_digest)
        if cached is not None:
            return cached
        script = self._fetch(action_id, digest, project_id, deadline)
        if _sha256(script) != hex_digest:
            raise resolve_failed("digest mismatch: fetched body does not hash to script_digest")
        self._store(canonical_project_id, hex_digest, script)
        return script

    def _from_cache(self, project_id: str | None, hex_digest: str) -> str | None:
        key = self._cache_key(project_id, hex_digest)
        with self._lock:
            cached = self._memory.get(key)
        if cached is not None:
            return cached
        path = self._disk_path(project_id, hex_digest)
        if path is None:
            return None
        try:
            script = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None
        if _sha256(script) != hex_digest:
            return None
        with self._lock:
            self._memory[key] = script
        return script

    def _store(self, project_id: str | None, hex_digest: str, script: str) -> None:
        key = self._cache_key(project_id, hex_digest)
        with self._lock:
            self._memory[key] = script
        path = self._disk_path(project_id, hex_digest)
        if path is None:
            return
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{hex_digest}.",
                delete=False,
            ) as temporary:
                temporary.write(script)
                temporary_path = Path(temporary.name)
            os.replace(temporary_path, path)
        except OSError:
            return

    def _disk_path(self, project_id: str | None, hex_digest: str) -> Path | None:
        if not self._config.cache_dir or not re.fullmatch(r"[0-9a-f]{64}", hex_digest):
            return None
        if project_id is None:
            return Path(self._config.cache_dir) / f"{hex_digest}.py"
        return Path(self._config.cache_dir) / project_id / f"{hex_digest}.py"

    def _cache_key(self, project_id: str | None, hex_digest: str) -> str:
        if project_id is None:
            return hex_digest
        return f"{project_id}:{hex_digest}"

    def _canonical_project_id(self, project_id: str) -> str | None:
        if not self._config.map_mode:
            return None
        try:
            canonical = str(uuid.UUID(project_id))
        except (ValueError, AttributeError):
            return None
        return canonical if self._config.secret_for_project(canonical) is not None else None

    def _fetch(self, action_id: str, digest: str, project_id: str, deadline: float) -> str:
        secret = self._config.secret_for_project(project_id)
        if secret is None:
            raise resolve_failed("script fetch failed")
        query = urlencode(
            [("action_id", action_id), ("digest", digest), ("project_id", project_id)]
        )
        parsed = urlsplit(self._config.fetch_url)
        target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise resolve_failed("script fetch failed")
        request = HTTPRequest(
            method="GET",
            url=target,
            headers={HEADER: sign(query.encode(), secret)},
            timeout=min(self._config.timeout, remaining),
        )
        try:
            response = self._config.transport(request)
        except Exception as error:
            raise resolve_failed("script fetch failed") from error
        if not 200 <= response.status < 300:
            raise resolve_failed(f"script fetch returned {response.status}")
        if not verify(header(response.headers, HEADER), response.body, secret):
            raise resolve_failed("script fetch response signature invalid")
        try:
            payload: Any = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise resolve_failed("script fetch response was not valid JSON") from error
        if not isinstance(payload, dict):
            raise resolve_failed("script fetch response was not valid JSON")
        script = payload.get("script")
        if not isinstance(script, str) or not script:
            raise resolve_failed("script fetch response missing script")
        response_digest = payload.get("digest")
        if response_digest not in (None, "", digest):
            raise resolve_failed("script fetch returned a different digest")
        runtime = payload.get("runtime")
        if runtime not in (None, "", "python"):
            raise resolve_failed(f'script fetch returned runtime "{runtime}"')
        return script


def _sha256(script: str) -> str:
    return hashlib.sha256(script.encode()).hexdigest()
