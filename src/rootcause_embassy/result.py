"""Tolerant analysis-result decoding."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Note:
    key: str = ""
    body_markdown: str = ""
    body_html: str = ""
    body_text: str = ""


@dataclass(frozen=True, slots=True)
class Action:
    id: str = ""
    slug: str = ""
    label: str = ""
    description: str = ""
    url: str = ""
    color: str = ""


@dataclass(frozen=True, slots=True)
class ExecutedAction:
    id: str = ""
    slug: str = ""
    label: str = ""
    ok: bool = False
    summary: str = ""


@dataclass(frozen=True, slots=True)
class QuestionOption:
    value: str = ""
    label: str = ""


@dataclass(frozen=True, slots=True)
class Question:
    id: str = ""
    type: str = ""
    prompt: str = ""
    why: str = ""
    options: list[QuestionOption] = field(default_factory=list)
    allow_other: bool = False


@dataclass(frozen=True, slots=True)
class Attachment:
    filename: str
    mime_type: str
    content_base64: str


@dataclass(frozen=True, slots=True)
class Decline:
    reason: str = ""


@dataclass(frozen=True, slots=True)
class Result:
    analysis_id: str
    session_id: str = ""
    project_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    draft: str = ""
    draft_subject: str = ""
    note: str = ""
    notes: list[Note] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    executed_actions: list[ExecutedAction] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)
    delete_ids: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    decline: Decline | None = None

    @property
    def ok(self) -> bool:
        return self.decline is None


def decode_result(payload: dict[str, Any]) -> Result:
    draft_raw = _mapping(payload.get("draft"))
    draft = _flatten(draft_raw)
    draft_subject = _string(draft_raw.get("subject"))

    notes: list[Note] = []
    for raw in _mapping_list(payload.get("notes")):
        notes.append(
            Note(
                key=_string(raw.get("key")) or _string(raw.get("kind")),
                body_markdown=_string(raw.get("body_markdown")),
                body_html=_string(raw.get("body_html")),
                body_text=_string(raw.get("body_text")),
            )
        )
    summary = next((note for note in notes if note.key == "summary"), None)
    if summary is None and notes:
        summary = notes[0]

    actions = [
        Action(
            id=_string(raw.get("id")),
            slug=_string(raw.get("slug")),
            label=_string(raw.get("label")),
            description=_string(raw.get("description")),
            url=_string(raw.get("url")),
            color=_string(raw.get("color")),
        )
        for raw in _mapping_list(payload.get("actions"))
    ]
    executed = [
        ExecutedAction(
            id=_string(raw.get("id")),
            slug=_string(raw.get("slug")),
            label=_string(raw.get("label")),
            ok=raw.get("ok") is True,
            summary=_string(raw.get("summary")),
        )
        for raw in _mapping_list(payload.get("executed_actions"))
    ]
    questions = [_decode_question(raw) for raw in _mapping_list(payload.get("questions"))]
    attachments = [
        Attachment(
            filename=_string(raw.get("filename")),
            mime_type=_string(raw.get("mime_type")),
            content_base64=_string(raw.get("content_base64")),
        )
        for raw in _mapping_list(payload.get("attachments"))
    ]
    decline_value = payload.get("decline")
    decline_raw = _mapping(decline_value)
    decline = (
        Decline(_string(decline_raw.get("reason"))) if isinstance(decline_value, dict) else None
    )
    metadata = _mapping(payload.get("metadata"))
    delete_ids = [item for item in _list(payload.get("delete")) if isinstance(item, str)]

    return Result(
        analysis_id=_string(payload.get("analysis_id")),
        session_id=_string(payload.get("session_id")),
        project_id=_string(payload.get("project_id")),
        metadata=metadata,
        draft=draft,
        draft_subject=draft_subject,
        note=(
            summary.body_markdown or summary.body_html or summary.body_text
            if summary is not None
            else ""
        ),
        notes=notes,
        actions=actions,
        executed_actions=executed,
        questions=questions,
        delete_ids=delete_ids,
        attachments=attachments,
        decline=decline,
    )


def _decode_question(raw: dict[str, Any]) -> Question:
    options = [
        QuestionOption(_string(item.get("value")), _string(item.get("label")))
        for item in _mapping_list(raw.get("options"))
    ]
    return Question(
        id=_string(raw.get("id")),
        type=_string(raw.get("type")),
        prompt=_string(raw.get("prompt")),
        why=_string(raw.get("why")),
        options=options,
        allow_other=raw.get("allow_other") is True,
    )


def _flatten(raw: dict[str, Any]) -> str:
    return (
        _string(raw.get("body_markdown"))
        or _string(raw.get("body_html"))
        or _string(raw.get("body_text"))
    )


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _mapping_list(value: Any) -> list[dict[str, Any]]:
    return [_mapping(item) for item in _list(value) if isinstance(item, dict)]


def _string(value: Any) -> str:
    return value if isinstance(value, str) else ""
