"""Outbound analysis trigger and sent-message clients."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .config import Config
from .errors import EmbassyError
from .http import HTTPRequest
from .result import Attachment
from .signature import HEADER, sign

_MAX_TOTAL_ATTACHMENT_BYTES = 6 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Principal:
    kind: str
    external_id: str
    asserted_by: str = ""
    assurance: str = ""
    tenant_hint: str = ""
    source_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    body: str
    subject: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""
    principal: Principal | None = None
    tenant: str = ""
    project_id: str = ""


@dataclass(frozen=True, slots=True)
class Analysis:
    analysis_id: str
    session_id: str = ""
    status: str = ""


@dataclass(frozen=True, slots=True)
class SentMessageMetadata:
    resource_type: str = ""
    resource_id: str = ""


@dataclass(frozen=True, slots=True)
class Answer:
    id: str
    values: list[str]


@dataclass(frozen=True, slots=True)
class SentMessageRequest:
    session_id: str
    sent_body: str = ""
    sender: str = ""
    proposed_body: str = ""
    metadata: SentMessageMetadata = field(default_factory=SentMessageMetadata)
    answers: list[Answer] = field(default_factory=list)
    project_id: str = ""


@dataclass(frozen=True, slots=True)
class SentMessage:
    status: str = ""
    analysis_id: str = ""
    sent_message_id: str = ""


class AnalysisClient:
    def __init__(self, config: Config) -> None:
        self._config = config

    def start_analysis(self, request: AnalysisRequest, project_id: str | None = None) -> Analysis:
        if not self._config.trigger_url:
            raise EmbassyError(0, "misconfigured", "TriggerURL is not configured")
        if not request.body:
            raise EmbassyError(0, "invalid_request", "analysis body is required")
        self._check_attachments(request.attachments)
        if request.principal is not None and (
            not request.principal.kind or not request.principal.external_id
        ):
            raise EmbassyError(
                0,
                "invalid_request",
                "principal requires both kind and external_id",
            )

        payload: dict[str, Any] = {
            "subject": request.subject,
            "body": request.body,
            "attachments": [_attachment(item) for item in request.attachments],
            "metadata": request.metadata,
        }
        if request.session_id:
            payload["session_id"] = request.session_id
        if request.principal is not None:
            payload["principal"] = _principal(request.principal)
        payload["nonce"] = self._config.nonce()
        payload["issued_at"] = self._issued_at()
        if request.tenant:
            payload["tenant"] = request.tenant

        selected_project_id = request.project_id if project_id is None else project_id
        response = self._post_signed(
            self._config.trigger_url, _json_bytes(payload), "analysis trigger", selected_project_id
        )
        parsed = _response_object(response, "analysis trigger")
        analysis_id = _string(parsed.get("analysis_id"))
        if not analysis_id:
            raise EmbassyError(
                0,
                "invalid_response",
                "analysis trigger response missing analysis_id",
            )
        analysis = Analysis(
            analysis_id=analysis_id,
            session_id=_string(parsed.get("session_id")),
            status=_string(parsed.get("status")),
        )
        self._config.logger.info(
            "rootcause analysis triggered",
            extra={
                "analysis_id": analysis.analysis_id,
                "metadata_keys": sorted(request.metadata),
                "attachments": len(request.attachments),
            },
        )
        return analysis

    def capture_sent_message(
        self, request: SentMessageRequest, project_id: str | None = None
    ) -> SentMessage:
        if not self._config.sent_message_url:
            raise EmbassyError(0, "misconfigured", "SentMessageURL is not configured")
        if not request.session_id:
            raise EmbassyError(0, "invalid_request", "session_id is required")
        if not request.sent_body and not request.answers:
            raise EmbassyError(0, "invalid_request", "sent_body or answers is required")
        payload: dict[str, Any] = {
            "type": "sent_message",
            "session_id": request.session_id,
        }
        if request.sent_body:
            sent: dict[str, Any] = {"body": request.sent_body}
            if request.sender:
                sent["sender"] = request.sender
            payload["sent"] = sent
        if request.proposed_body:
            payload["proposed"] = {"body": request.proposed_body}
        payload["metadata"] = {
            "resource_type": request.metadata.resource_type,
            "resource_id": request.metadata.resource_id,
        }
        if request.answers:
            payload["answers"] = [
                {"id": answer.id, "values": answer.values} for answer in request.answers
            ]
        payload["nonce"] = self._config.nonce()
        payload["issued_at"] = self._issued_at()

        selected_project_id = request.project_id if project_id is None else project_id
        response = self._post_signed(
            self._config.sent_message_url,
            _json_bytes(payload),
            "sent-message capture",
            selected_project_id,
        )
        self._config.logger.info(
            "rootcause sent-message captured",
            extra={
                "session_id": request.session_id,
                "sent_bytes": len(request.sent_body.encode()),
                "proposed_bytes": len(request.proposed_body.encode()),
                "answers": len(request.answers),
            },
        )
        if not response:
            return SentMessage()
        parsed = _response_object(response, "sent-message capture")
        return SentMessage(
            status=_string(parsed.get("status")),
            analysis_id=_string(parsed.get("analysis_id")),
            sent_message_id=_string(parsed.get("sent_message_id")),
        )

    def _post_signed(self, url: str, body: bytes, label: str, project_id: str) -> bytes:
        secret = self._config.secret_for_project(project_id)
        if secret is None:
            raise EmbassyError(0, "misconfigured", "project_id is required for reverse-secret map")
        request = HTTPRequest(
            method="POST",
            url=url,
            headers={
                "Content-Type": "application/json",
                HEADER: sign(body, secret),
            },
            body=body,
            timeout=self._config.timeout,
        )
        try:
            response = self._config.transport(request)
        except Exception as error:
            raise EmbassyError(0, "transport_error", f"{label} failed") from error
        if not 200 <= response.status < 300:
            raise EmbassyError(
                response.status,
                "http_error",
                f"{label} returned {response.status}",
            )
        return response.body

    def _check_attachments(self, attachments: list[Attachment]) -> None:
        total = 0
        for index, attachment in enumerate(attachments):
            try:
                decoded = base64.b64decode(attachment.content_base64, validate=True)
            except (binascii.Error, ValueError) as error:
                raise EmbassyError(
                    0,
                    "invalid_request",
                    f"attachment {index}: content_base64 is not valid base64",
                ) from error
            if len(decoded) > self._config.max_attachment_bytes:
                raise EmbassyError(
                    0,
                    "invalid_request",
                    f"attachment {index} exceeds max_attachment_bytes",
                )
            total += len(decoded)
            if total > _MAX_TOTAL_ATTACHMENT_BYTES:
                raise EmbassyError(
                    0,
                    "invalid_request",
                    "attachments exceed the host's total decoded-byte cap",
                )

    def _issued_at(self) -> str:
        return datetime.fromtimestamp(self._config.now(), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _principal(principal: Principal) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "kind": principal.kind,
        "external_id": principal.external_id,
    }
    if principal.asserted_by:
        payload["asserted_by"] = principal.asserted_by
    if principal.assurance:
        payload["assurance"] = principal.assurance
    if principal.tenant_hint:
        payload["tenant_hint"] = principal.tenant_hint
    if principal.source_metadata:
        payload["source_metadata"] = principal.source_metadata
    return payload


def _attachment(attachment: Attachment) -> dict[str, str]:
    return {
        "filename": attachment.filename,
        "mime_type": attachment.mime_type,
        "content_base64": attachment.content_base64,
    }


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _response_object(body: bytes, label: str) -> dict[str, Any]:
    try:
        parsed: Any = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise EmbassyError(0, "invalid_response", f"{label} response was not valid JSON") from error
    if not isinstance(parsed, dict):
        raise EmbassyError(0, "invalid_response", f"{label} response was not an object")
    return parsed


def _string(value: Any) -> str:
    return value if isinstance(value, str) else ""
