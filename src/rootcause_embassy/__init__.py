"""rootcause's trusted in-app presence for Python services."""

from __future__ import annotations

from dataclasses import replace

from .action import ActionPlane, Response
from .action_principal import ActionPrincipal
from .api import API, APIResponse
from .chat import Claims, Widget, mint_embed_token, widget_tag_html
from .client import (
    Analysis,
    AnalysisClient,
    AnalysisRequest,
    Answer,
    ContextRef,
    Principal,
    SentMessage,
    SentMessageMetadata,
    SentMessageRequest,
)
from .config import ActionContext, Config
from .errors import EmbassyError, Misconfigured
from .resolver import Resolver
from .result import (
    Action,
    Attachment,
    Decline,
    ExecutedAction,
    Note,
    Question,
    QuestionOption,
    Result,
)
from .resultroute import ResultRoute
from .signature import HEADER, sign, verify
from .tenant import Tenant

VERSION = "0.3.0"
PROTOCOL = 1
RUNTIME = "python"


class Embassy:
    """Configured facade over all four Embassy planes; safe to share across threads."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._resolver = Resolver(config)
        self._actions = ActionPlane(config, self._resolver)
        self._results = ResultRoute(config)
        self._analysis = AnalysisClient(config)
        self.api = API(config)

    def handle_action(
        self,
        method: str,
        subpath: str,
        signature: str | None,
        body: bytes,
    ) -> Response:
        return self._actions.handle(method, subpath, signature, body)

    def handle_result(self, method: str, signature: str | None, body: bytes) -> Response:
        return self._results.handle(method, signature, body)

    def start_analysis(self, request: AnalysisRequest, project_id: str | None = None) -> Analysis:
        return self._analysis.start_analysis(request, project_id)

    def capture_sent_message(
        self, request: SentMessageRequest, project_id: str | None = None
    ) -> SentMessage:
        return self._analysis.capture_sent_message(request, project_id)

    def api_for(self, api_base_url: str, api_key: str) -> API:
        return API(self.config, api_base_url, api_key)

    def mint_chat_token(self, claims: Claims) -> str:
        effective = claims
        if not claims.project and self.config.chat_project:
            effective = replace(claims, project=self.config.chat_project)
        return mint_embed_token(self.config.chat_secret, effective)

    def chat_widget_tag_html(self, claims: Claims, widget: Widget) -> str:
        token = self.mint_chat_token(claims)
        effective = replace(
            widget,
            base_url=widget.base_url or self.config.chat_base_url,
            project=widget.project or claims.project or self.config.chat_project,
            token=token,
            locale=widget.locale or claims.locale,
            color_scheme=widget.color_scheme or claims.color_scheme,
        )
        return widget_tag_html(effective)


__all__ = [
    "API",
    "HEADER",
    "PROTOCOL",
    "RUNTIME",
    "VERSION",
    "APIResponse",
    "Action",
    "ActionContext",
    "ActionPrincipal",
    "Analysis",
    "AnalysisRequest",
    "Answer",
    "Attachment",
    "Claims",
    "Config",
    "ContextRef",
    "Decline",
    "Embassy",
    "EmbassyError",
    "ExecutedAction",
    "Misconfigured",
    "Note",
    "Principal",
    "Question",
    "QuestionOption",
    "Response",
    "Result",
    "SentMessage",
    "SentMessageMetadata",
    "SentMessageRequest",
    "Tenant",
    "Widget",
    "mint_embed_token",
    "sign",
    "verify",
    "widget_tag_html",
]
