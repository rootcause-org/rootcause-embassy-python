from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from rootcause_embassy import (
    HEADER,
    ActionContext,
    AnalysisRequest,
    Answer,
    Attachment,
    Claims,
    Config,
    Embassy,
    Principal,
    SentMessageMetadata,
    SentMessageRequest,
    Widget,
    mint_embed_token,
    sign,
    verify,
    widget_tag_html,
)
from rootcause_embassy.errors import Misconfigured, Refusal
from rootcause_embassy.http import HTTPRequest, HTTPResponse

DATA = Path(__file__).parent / "testdata"
REVERSE_SECRET = "contract-reverse-secret"
CHAT_SECRET = "contract-chat-secret"
PROJECT_ID = "11111111-1111-1111-1111-111111111111"
SESSION_ID = "44444444-4444-4444-4444-444444444444"
REFERENCE_CLOCK = 1781913600.0
PYTHON_SCRIPT = """\
print("looked up " + action_id, file=out)
result = {"found": True, "email": params["email"], "tenant": tenant.slug if tenant else ""}
"""


def fixture(name: str) -> bytes:
    return (DATA / name).read_bytes()


def json_fixture(name: str) -> Any:
    return json.loads(fixture(name))


def local_runner(ctx: ActionContext, params: dict[str, Any]) -> Any:
    namespace: dict[str, Any] = {
        "action_id": ctx.action_id,
        "out": ctx.out,
        "params": params,
        "tenant": ctx.tenant,
    }
    exec(ctx.script, namespace)
    return namespace["result"]


class FakeHost:
    def __init__(self, script: str = PYTHON_SCRIPT) -> None:
        self.script = script
        self.digest = "sha256:" + hashlib.sha256(script.encode()).hexdigest()
        self.runtime = "python"
        self.unsigned = False
        self.fetch_code = 200
        self.last_request: HTTPRequest | None = None
        self.response = b""

    def __call__(self, request: HTTPRequest) -> HTTPResponse:
        self.last_request = request
        if request.method == "GET":
            if self.fetch_code != 200:
                return HTTPResponse(self.fetch_code)
            query = parse_qs(urlsplit(request.url).query)
            body = wire_json(
                {
                    "action_id": query["action_id"][0],
                    "digest": query["digest"][0],
                    "script": self.script,
                    "runtime": self.runtime,
                }
            )
            headers = {} if self.unsigned else {HEADER: sign(body, REVERSE_SECRET)}
            return HTTPResponse(200, headers, body)
        return HTTPResponse(202, {}, self.response)


def embassy(host: FakeHost, *, runner=local_runner, result_handler=None, **overrides) -> Embassy:
    values = {
        "secret": REVERSE_SECRET,
        "fetch_url": "https://host.test/actions/script",
        "trigger_url": "https://host.test/analyses/demo",
        "sent_message_url": "https://host.test/analyses/demo/sent-message",
        "runner": runner,
        "result_handler": result_handler,
        "now": lambda: REFERENCE_CLOCK,
        "nonce": lambda: "contract-nonce",
        "transport": host,
    }
    values.update(overrides)
    return Embassy(Config(**values))


def map_embassy(host: FakeHost, *, runner=local_runner, result_handler=None) -> Embassy:
    return Embassy(
        Config(
            secrets={
                PROJECT_ID: REVERSE_SECRET,
                "22222222-2222-2222-2222-222222222222": "sibling-secret",
            },
            fetch_url="https://host.test/actions/script",
            trigger_url="https://host.test/analyses/demo",
            sent_message_url="https://host.test/analyses/demo/sent-message",
            runner=runner,
            result_handler=result_handler,
            now=lambda: REFERENCE_CLOCK,
            nonce=lambda: "contract-nonce",
            transport=host,
        )
    )


def invocation(host: FakeHost, **overrides: Any) -> bytes:
    payload: dict[str, Any] = {
        "action_id": "devise_send_password_reset",
        "script_digest": host.digest,
        "params": {"email": "x@acme.com"},
        "runtime": "python",
        "project_id": PROJECT_ID,
        "nonce": "nonce-test",
        "issued_at": "2026-06-20T00:00:00Z",
        "schema": {"email": {"type": "string", "required": True}},
    }
    for key, value in overrides.items():
        if value is None:
            payload.pop(key, None)
        else:
            payload[key] = value
    return wire_json(payload)


def wire_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()


def post_action(target: Embassy, body: bytes, signature: str | None = None):
    return target.handle_action("POST", "", signature or sign(body, REVERSE_SECRET), body)


def assert_signed(response) -> None:
    _, headers, body = response
    assert verify(headers.get(HEADER), body, REVERSE_SECRET)


def assert_refusal(response, status: int, golden: str) -> None:
    assert_signed(response)
    assert response[0] == status
    assert response[2] == fixture(golden)


def assert_class(response, status: int, error_class: str) -> None:
    assert_signed(response)
    assert response[0] == status
    payload = json.loads(response[2])
    assert payload["ok"] is False
    assert payload["error"]["class"] == error_class


def test_signing_vectors() -> None:
    vectors = json_fixture("signing_vectors.json")
    assert vectors["header"] == HEADER
    for vector in vectors["bodies"]:
        body = fixture(vector["file"])
        assert len(body) == vector["body_bytes"]
        assert hashlib.sha256(body).hexdigest() == vector["body_sha256"]
        assert sign(body, vector["secret"]) == vector["signature"]
        assert verify(vector["signature"], body, vector["secret"])
        assert not verify(vector["signature"], body + b" ", vector["secret"])
    for vector in vectors["query_strings"]:
        raw = fixture(vector["file"]).rstrip(b"\n")
        assert raw.decode() == vector["raw_query"]
        assert sign(raw, vector["secret"]) == vector["signature"]


def test_blank_secret_fails_closed() -> None:
    assert sign(b"x", "") == ""
    assert not verify("sha256=deadbeef", b"x", "")
    assert not verify(None, b"x", REVERSE_SECRET)


def test_action_round_trip_and_tenant() -> None:
    host = FakeHost()
    target = embassy(host)
    body = invocation(
        host,
        tenant_id="22222222-2222-2222-2222-222222222222",
        tenant_slug="acme",
        tenant_scope_value="account-42",
    )
    response = post_action(target, body)
    assert_signed(response)
    assert response[0] == 200
    payload = json.loads(response[2])
    assert payload["ok"] is True
    assert payload["return_value"] == {
        "found": True,
        "email": "x@acme.com",
        "tenant": "acme",
    }
    assert payload["stdout"] == "looked up devise_send_password_reset\n"
    assert host.last_request is not None
    raw_query = urlsplit(host.last_request.url).query
    assert raw_query.startswith("action_id=devise_send_password_reset&digest=sha256%3A")
    assert raw_query.endswith("&project_id=" + PROJECT_ID)
    assert host.last_request.headers[HEADER] == sign(raw_query.encode(), REVERSE_SECRET)


def test_dry_run_and_success_envelope_shape() -> None:
    host = FakeHost()
    target = embassy(host, runner=None)
    dry_body = invocation(host, dry_run=True)
    response = post_action(target, dry_body)
    assert_signed(response)
    got = response[2].decode()
    want = fixture("actions/result_dry_run.json").decode()
    assert normalize_duration(got) == normalize_duration(want)
    assert host.last_request is not None

    success_host = FakeHost()
    success_target = embassy(success_host)
    success_body = invocation(success_host)
    success = post_action(success_target, success_body)
    assert list(json.loads(success[2])) == list(json.loads(fixture("actions/result_ok.json")))


def normalize_duration(body: str) -> str:
    marker = '"duration_ms":'
    index = body.index(marker)
    return body[:index] + marker + "0}"


def test_refusal_envelopes_and_guardrails() -> None:
    host = FakeHost()
    target = embassy(host)
    body = invocation(host)
    assert_refusal(
        post_action(target, body, "sha256=deadbeef"),
        401,
        "actions/result_refusal_bad_signature.json",
    )

    replay_host = FakeHost()
    replay_target = embassy(replay_host)
    replay_body = invocation(replay_host)
    assert post_action(replay_target, replay_body)[0] == 200
    assert_refusal(
        post_action(replay_target, replay_body),
        409,
        "actions/result_refusal_replay.json",
    )

    schema_host = FakeHost()
    schema_body = invocation(schema_host, schema=[{"name": "email"}])
    assert_refusal(
        post_action(embassy(schema_host), schema_body),
        422,
        "actions/result_refusal_schema_violation.json",
    )

    digest_host = FakeHost()
    digest_body = invocation(digest_host, script_digest="sha256:" + "ab" * 32)
    assert_refusal(
        post_action(embassy(digest_host), digest_body),
        502,
        "actions/result_refusal_resolve_failed.json",
    )

    unsigned = FakeHost()
    unsigned.unsigned = True
    unsigned_body = invocation(unsigned)
    assert_class(post_action(embassy(unsigned), unsigned_body), 502, "resolve_failed")

    ruby_host = FakeHost()
    ruby = fixture("actions/invocation_flat.json")
    assert_class(post_action(embassy(ruby_host), ruby), 400, "invalid_request")

    optional_runtime_host = FakeHost()
    optional_runtime_body = invocation(optional_runtime_host, runtime=None)
    assert post_action(embassy(optional_runtime_host), optional_runtime_body)[0] == 200

    dry_type_host = FakeHost()
    dry_type_body = invocation(dry_type_host, dry_run="true")
    assert_class(post_action(embassy(dry_type_host), dry_type_body), 400, "invalid_request")
    assert dry_type_host.last_request is None

    stale_host = FakeHost()
    stale_body = invocation(stale_host, issued_at="2026-06-19T23:50:00Z")
    assert_class(post_action(embassy(stale_host), stale_body), 409, "replay")

    reserved_host = FakeHost()
    reserved_body = invocation(
        reserved_host,
        params={"email": "x@acme.com", "RC_Tenant_ID": "sneaky"},
        schema={
            "email": {"type": "string", "required": True},
            "RC_Tenant_ID": {"type": "string"},
        },
    )
    assert_class(post_action(embassy(reserved_host), reserved_body), 422, "schema_violation")

    partial_host = FakeHost()
    partial_body = invocation(partial_host, tenant_id="22222222-2222-2222-2222-222222222222")
    assert_class(post_action(embassy(partial_host), partial_body), 400, "invalid_request")


def test_no_runner_refuses_after_fetch_and_runner_exception_is_structured() -> None:
    host = FakeHost()
    body = invocation(host)
    response = post_action(embassy(host, runner=None), body)
    assert_class(response, 400, "invalid_request")
    assert host.last_request is not None

    def explode(ctx: ActionContext, params: dict[str, Any]) -> Any:
        raise LookupError("database unavailable")

    boom_host = FakeHost()
    boom_body = invocation(boom_host)
    boom = post_action(embassy(boom_host, runner=explode), boom_body)
    assert_signed(boom)
    payload = json.loads(boom[2])
    assert boom[0] == 200
    assert payload["ok"] is False
    assert payload["error"]["class"] == "LookupError"
    assert payload["error"]["message"] == "database unavailable"
    assert "LookupError" in payload["error"]["backtrace"]


def test_method_not_allowed_and_health() -> None:
    target = embassy(FakeHost())
    for method in ("GET", "PUT", "DELETE"):
        status, headers, body = target.handle_action(method, "", None, b"")
        assert status == 405
        assert headers["Allow"] == "POST"
        assert HEADER not in headers
        assert b"method_not_allowed" in body

    unsigned = target.handle_action("GET", "/health", None, b"")
    assert unsigned[0] == 404
    response = target.handle_action("GET", "/health", sign(b"", REVERSE_SECRET), b"")
    assert_signed(response)
    expected = (
        fixture("actions/health_response.json")
        .decode()
        .replace('"embassy":"ruby"', '"embassy":"python"')
        .replace('"version":"0.5.0"', '"version":"0.2.0"')
    )
    assert response[2].decode() == expected


def test_reverse_secret_map_action_hit_and_selector_failures() -> None:
    host = FakeHost()
    target = map_embassy(host)
    body = invocation(host)
    response = target.handle_action("POST", "", sign(body, REVERSE_SECRET), body)
    assert response[0] == 200
    assert verify(response[1][HEADER], response[2], REVERSE_SECRET)
    assert host.last_request is not None
    assert host.last_request.headers[HEADER] == sign(
        urlsplit(host.last_request.url).query.encode(), REVERSE_SECRET
    )

    sibling_body = invocation(
        host,
        project_id=PROJECT_ID,
    )
    sibling_refusal = target.handle_action(
        "POST", "", sign(sibling_body, "sibling-secret"), sibling_body
    )
    assert sibling_refusal[0] == 401
    assert verify(sibling_refusal[1][HEADER], sibling_refusal[2], REVERSE_SECRET)
    assert host.last_request is not None

    for selector in (None, "not-a-uuid", "33333333-3333-3333-3333-333333333333"):
        selector_body = wire_json({} if selector is None else {"project_id": selector})
        refusal = target.handle_action("POST", "", "sha256=deadbeef", selector_body)
        assert refusal[0] == 401
        assert HEADER not in refusal[1]
        assert json.loads(refusal[2])["error"]["class"] == "bad_signature"


def test_reverse_secret_map_result_health_and_outbound_calls() -> None:
    host = FakeHost()
    captured = []
    target = map_embassy(host, result_handler=captured.append)
    result_body = fixture("analysis/result_callback.json")
    result_response = target.handle_result("POST", sign(result_body, REVERSE_SECRET), result_body)
    assert result_response[0] == 200
    assert verify(result_response[1][HEADER], result_response[2], REVERSE_SECRET)
    assert captured[0].project_id == PROJECT_ID

    legacy_result = wire_json(
        {"analysis_id": "run", "nonce": "nonce", "issued_at": "2026-06-20T00:00:00Z"}
    )
    legacy_response = target.handle_result(
        "POST", sign(legacy_result, REVERSE_SECRET), legacy_result
    )
    assert legacy_response[0] == 401
    assert HEADER not in legacy_response[1]
    assert len(captured) == 1
    unknown_result = wire_json(
        {
            "analysis_id": "run-unknown",
            "project_id": "33333333-3333-3333-3333-333333333333",
            "nonce": "nonce-unknown",
            "issued_at": "2026-06-20T00:00:00Z",
        }
    )
    unknown_result_response = target.handle_result("POST", "sha256=deadbeef", unknown_result)
    assert unknown_result_response[0] == 401
    assert HEADER not in unknown_result_response[1]
    assert len(captured) == 1

    query = fixture("actions/health_query.txt").rstrip(b"\n")
    health = target.handle_action("GET", "/health", sign(query, REVERSE_SECRET), query)
    assert health[0] == 200
    assert verify(health[1][HEADER], health[2], REVERSE_SECRET)
    unknown_query = b"project_id=33333333-3333-3333-3333-333333333333"
    unknown_health = target.handle_action("GET", "/health", "sha256=deadbeef", unknown_query)
    assert unknown_health == (404, {}, b"")

    host.response = fixture("analysis/trigger_response.json")
    target.start_analysis(AnalysisRequest(project_id=PROJECT_ID, body="hello", metadata={}))
    assert host.last_request is not None
    assert host.last_request.headers[HEADER] == sign(host.last_request.body, REVERSE_SECRET)
    target.capture_sent_message(
        SentMessageRequest(project_id=PROJECT_ID, session_id=SESSION_ID, sent_body="sent")
    )
    assert host.last_request.headers[HEADER] == sign(host.last_request.body, REVERSE_SECRET)


def test_inbound_body_cap_precedes_authentication_on_both_routes() -> None:
    target = embassy(FakeHost(), max_body_bytes=4)
    oversized = b"12345"
    assert_class(target.handle_action("POST", "", None, oversized), 400, "invalid_request")
    assert_class(target.handle_result("POST", None, oversized), 400, "invalid_request")
    assert target.handle_action("PUT", "", None, oversized)[0] == 405
    assert target.handle_action("GET", "/health", None, oversized)[0] == 404
    assert target.handle_result("PUT", None, oversized)[0] == 405


def test_result_callback_decode_and_ack() -> None:
    captured = []
    target = embassy(FakeHost(), result_handler=captured.append)
    body = fixture("analysis/result_callback.json")
    response = target.handle_result("POST", sign(body, REVERSE_SECRET), body)
    assert_signed(response)
    assert response[0] == 200
    assert response[2] == fixture("analysis/result_ack.json")
    result = captured[0]
    assert result.analysis_id == "33333333-3333-3333-3333-333333333333"
    assert result.session_id == SESSION_ID
    assert result.draft.startswith("Your reset link expired")
    assert result.draft_subject == "Re: Login fails after password reset"
    assert result.note.startswith("Expired reset token")
    assert result.actions[0].slug == "devise_send_password_reset"
    assert result.executed_actions[0].slug == "recompute_record_formulas"
    assert result.executed_actions[0].ok
    assert result.questions[0].id == "country"
    assert len(result.questions[0].options) == 2
    assert result.delete_ids == ["77777777-7777-7777-7777-777777777777"]
    assert result.metadata["resource_id"] == "42"
    assert result.ok


def test_result_redelivery_semantics() -> None:
    body = fixture("analysis/result_callback.json")
    signature = sign(body, REVERSE_SECRET)
    dispatches = []
    target = embassy(FakeHost(), result_handler=dispatches.append)
    for _ in range(3):
        response = target.handle_result("POST", signature, body)
        assert response[0] == 200
        assert response[2] == fixture("analysis/result_ack.json")
    assert len(dispatches) == 1

    attempts = 0

    def flaky(result) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("database down")

    retry_target = embassy(FakeHost(), result_handler=flaky)
    first_failure = retry_target.handle_result("POST", signature, body)
    assert_class(first_failure, 500, "internal_error")
    assert json.loads(first_failure[2])["error"]["message"] == "RuntimeError"
    assert retry_target.handle_result("POST", signature, body)[0] == 200
    assert attempts == 2

    stale_target = embassy(
        FakeHost(),
        result_handler=lambda result: None,
        now=lambda: REFERENCE_CLOCK + 3600,
    )
    assert_class(stale_target.handle_result("POST", signature, body), 409, "replay")

    unconfigured = embassy(FakeHost(), result_handler=None)
    assert_class(unconfigured.handle_result("POST", signature, body), 500, "handler_error")

    bad = embassy(FakeHost(), result_handler=lambda result: None)
    assert_refusal(
        bad.handle_result("POST", "sha256=deadbeef", body),
        401,
        "actions/result_refusal_bad_signature.json",
    )

    base_attempts = 0

    def raises_base(result) -> None:
        nonlocal base_attempts
        base_attempts += 1
        if base_attempts == 1:
            raise BaseException("fatal handler failure")

    base_target = embassy(FakeHost(), result_handler=raises_base)
    first = base_target.handle_result("POST", signature, body)
    assert_class(first, 500, "internal_error")
    assert json.loads(first[2])["error"]["message"] == "BaseException"
    assert base_target.handle_result("POST", signature, body)[0] == 200
    assert base_attempts == 2

    def deliberate_refusal(result) -> None:
        raise Refusal(422, "schema_violation", "customer refusal")

    refusal_target = embassy(FakeHost(), result_handler=deliberate_refusal)
    deliberate = refusal_target.handle_result("POST", signature, body)
    assert_class(deliberate, 422, "schema_violation")
    assert json.loads(deliberate[2])["error"]["message"] == "customer refusal"
    assert_class(
        refusal_target.handle_result("POST", signature, body),
        422,
        "schema_violation",
    )


@pytest.mark.parametrize(
    ("name", "nonce", "analysis_request"),
    [
        (
            "analysis/trigger.json",
            "contract-nonce-trigger",
            AnalysisRequest(
                subject="Login fails after password reset",
                body="The reset mail arrives but the new password is refused.",
                metadata={"resource_type": "SupportTicket", "resource_id": "42"},
            ),
        ),
        (
            "analysis/trigger_with_principal.json",
            "contract-nonce-trigger-principal",
            AnalysisRequest(
                subject="Still failing after the reset",
                body="Same error on the second attempt.",
                attachments=[Attachment("error.log", "text/plain", "Ym9vbQo=")],
                metadata={"resource_type": "SupportTicket", "resource_id": "42"},
                session_id=SESSION_ID,
                tenant="acme",
                principal=Principal(
                    kind="kampadmin_admin",
                    external_id="user-8f3",
                    asserted_by="kampadmin",
                    assurance="customer_backend_jwt",
                    tenant_hint="acme",
                ),
            ),
        ),
    ],
)
def test_outbound_trigger_serialization(name, nonce, analysis_request) -> None:
    host = FakeHost()
    host.response = fixture("analysis/trigger_response.json")
    target = embassy(host, nonce=lambda: nonce)
    analysis = target.start_analysis(analysis_request)
    assert analysis.analysis_id
    assert analysis.session_id == SESSION_ID
    assert_outbound(host, name)


@pytest.mark.parametrize(
    ("name", "nonce", "message_request"),
    [
        (
            "analysis/sent_message.json",
            "contract-nonce-sent-message",
            SentMessageRequest(
                session_id=SESSION_ID,
                sent_body="Sent you a fresh reset link — it expires in an hour.",
                sender="Jane",
                proposed_body="Your reset link expired before you used it. I sent a fresh one.",
                metadata=SentMessageMetadata("SupportTicket", "42"),
            ),
        ),
        (
            "analysis/answers.json",
            "contract-nonce-answers",
            SentMessageRequest(
                session_id=SESSION_ID,
                metadata=SentMessageMetadata("SupportTicket", "42"),
                answers=[Answer("country", ["BE"])],
            ),
        ),
    ],
)
def test_outbound_sent_message_serialization(name, nonce, message_request) -> None:
    host = FakeHost()
    target = embassy(host, nonce=lambda: nonce)
    target.capture_sent_message(message_request)
    assert_outbound(host, name)


def assert_outbound(host: FakeHost, golden: str) -> None:
    assert host.last_request is not None
    assert json.loads(host.last_request.body) == json_fixture(golden)
    assert list(json.loads(host.last_request.body)) == list(json_fixture(golden))
    assert host.last_request.headers[HEADER] == sign(host.last_request.body, REVERSE_SECRET)


def test_chat_jwt_and_widget_vectors() -> None:
    vector = json_fixture("chat/jwt_vector.json")
    claims = Claims(
        project="kampadmin",
        external_id="user-8f3",
        kind="kampadmin_admin",
        origin="https://admin.kampadmin.be",
        tenant="acme",
        locale="nl",
        color_scheme="light",
        jti="88888888-8888-8888-8888-888888888888",
        ttl=vector["ttl_seconds"],
        issued_at=vector["now_unix"],
    )
    token = mint_embed_token(vector["secret"], claims)
    assert token == vector["token"]
    assert token.startswith(vector["signing_input"] + ".")
    header = json.loads(_b64decode(token.split(".")[0]))
    assert header == {"alg": "HS256", "typ": "JWT"}
    tag = widget_tag_html(
        Widget(
            base_url="https://app.replypen.com",
            project="kampadmin",
            token=token,
            mode="page",
            target="#rc-chat",
            locale="nl",
            color_scheme="light",
        )
    )
    assert tag == fixture("chat/widget_tag.html").decode().rstrip("\n")
    with pytest.raises(Misconfigured):
        mint_embed_token("", claims)


def test_api_exchange_cache_401_static_retryable_and_origin_floor() -> None:
    exchanges = 0
    calls = 0
    bearers: list[str] = []

    def cached_transport(request: HTTPRequest) -> HTTPResponse:
        nonlocal exchanges, calls
        if urlsplit(request.url).path == "/oauth/token":
            exchanges += 1
            assert request.body == (
                b"grant_type=refresh_token&refresh_token=rcor_contract_cache&client_id=rcocl_cli"
            )
            return HTTPResponse(
                200,
                body=b'{"access_token":"rcoa_live","expires_in":3600}',
            )
        calls += 1
        bearers.append(request.headers["Authorization"])
        return HTTPResponse(200, body=b'{"ok":true}')

    cached = Embassy(
        Config(
            secret=REVERSE_SECRET,
            fetch_url="https://host.test/actions/script",
            api_base_url="https://api-cache.test",
            api_key="rcor_contract_cache",
            transport=cached_transport,
        )
    ).api
    assert cached.get("/api/v1/projects", params={"limit": 10}).ok
    assert cached.get("/api/v1/projects").ok
    assert exchanges == 1
    assert calls == 2
    assert bearers == ["Bearer rcoa_live", "Bearer rcoa_live"]

    retry_exchanges = 0
    retry_calls = 0

    def retry_transport(request: HTTPRequest) -> HTTPResponse:
        nonlocal retry_exchanges, retry_calls
        if urlsplit(request.url).path == "/oauth/token":
            retry_exchanges += 1
            return HTTPResponse(
                200,
                body=wire_json({"access_token": f"rcoa_{retry_exchanges}", "expires_in": 3600}),
            )
        retry_calls += 1
        return HTTPResponse(401 if retry_calls == 1 else 200, body=b"{}")

    retry_api = Embassy(
        Config(
            secret=REVERSE_SECRET,
            fetch_url="https://host.test/actions/script",
            api_base_url="https://api-retry.test",
            api_key="rcor_contract_retry",
            transport=retry_transport,
        )
    ).api
    assert retry_api.get("/api/v1/me").ok
    assert retry_exchanges == 2
    assert retry_calls == 2

    static_requests: list[HTTPRequest] = []

    def static_transport(request: HTTPRequest) -> HTTPResponse:
        static_requests.append(request)
        return HTTPResponse(429, body=b'{"error":"slow down"}')

    static_api = Embassy(
        Config(
            secret=REVERSE_SECRET,
            fetch_url="https://host.test/actions/script",
            api_base_url="https://api-static.test",
            api_key="rcoa_static",
            transport=static_transport,
        )
    ).api
    response = static_api.get("/rate")
    assert response.status == 429 and response.retryable
    assert response.error == "slow down"
    assert static_requests[0].headers["Authorization"] == "Bearer rcoa_static"
    with pytest.raises(Misconfigured):
        static_api.get("https://evil.example.com/steal")


def _b64decode(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
