# rootcause-embassy-python

The Python **Embassy**: rootcause's trusted in-app presence inside your Python service.

It does four things, all on your side of the wire:

1. **Actions** — verify a signed, digest-pinned invocation, resolve its approved Python body, and
   execute it through the runner your application explicitly registered.
2. **Analysis** — ask rootcause to analyze something and receive the drafted answer later on a route
   you mount. No polling or custom callback protocol.
3. **Chat** — mint the short-lived token that lets a logged-in user chat with rootcause in your UI.
4. **API** — call any rootcause API endpoint, with bearer exchange and caching handled for you.

Python 3.13+. Zero runtime dependencies: the package uses only the standard library. The wire
contract lives in the
[`rootcause-embassy`](https://github.com/rootcause-org/rootcause-embassy) hub; this package vendors
and replays that hub's byte-exact fixtures.

## Install

```sh
uv add rootcause-embassy
```

## Configure

Build one `Embassy` at boot and share it. `Config` validates fail-closed: a blank action secret, a
placeholder fetch URL, a half-configured API/chat plane, or a chat key equal to the action key is a
boot error.

Use exactly one reverse-secret mode. `secret` preserves the single-project deployment and its
legacy result/health wire behavior. A shared mount can instead provide `secrets`, a non-empty mapping
of project UUIDs to non-blank reverse secrets; the project selector is read before HMAC verification
only to choose the key. Unknown, missing, or malformed selectors get an opaque unsigned refusal and
cannot reach replay, resolution, dispatch, or execution.

```python
from rootcause_embassy import Config, Embassy

embassy = Embassy(
    Config(
        # Every string falls back to its ROOTCAUSE_* environment variable:
        # secret            ROOTCAUSE_ACTION_SECRET
        # fetch_url         ROOTCAUSE_FETCH_URL
        # trigger_url       ROOTCAUSE_TRIGGER_URL
        # sent_message_url  ROOTCAUSE_SENT_MESSAGE_URL
        # api_base_url      ROOTCAUSE_API_BASE_URL
        # api_key           ROOTCAUSE_API_KEY
        # chat_secret       ROOTCAUSE_CHAT_SECRET  (webhook_secret, never secret)
        # chat_project      ROOTCAUSE_CHAT_PROJECT
        # chat_base_url     ROOTCAUSE_CHAT_BASE_URL
        runner=run_action,
        result_handler=handle_analysis_result,
    )
)

# Shared mount variant:
# Config(
#     secrets={"11111111-1111-1111-1111-111111111111": project_secret},
#     fetch_url="https://app.replypen.com/actions/script",
# )
```

### Litestar mount

The package is framework-agnostic: adapters only translate request bytes and the returned
`(status, headers, body)` tuple. A sync handler is deliberately used so Litestar puts execution in
its thread pool.

```python
from litestar import Request, Response, get, post, route

NON_POST_METHODS = ["GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


def embassy_response(result: tuple[int, dict[str, str], bytes]) -> Response[bytes]:
    status, headers, body = result
    return Response(body, status_code=status, headers=headers, media_type=None)


@post("/rootcause/action", sync_to_thread=True)
def rootcause_action_post(request: Request, data: bytes) -> Response[bytes]:
    return embassy_response(
        embassy.handle_action("POST", "", request.headers.get("X-Webhook-Signature"), data)
    )


@route("/rootcause/action", http_method=NON_POST_METHODS, sync_to_thread=True)
def rootcause_action_probe(request: Request) -> Response[bytes]:
    return embassy_response(embassy.handle_action(request.method, "", None, b""))


@get("/rootcause/action/health", sync_to_thread=True)
def rootcause_action_health(request: Request) -> Response[bytes]:
    raw_query = str(request.url.query).encode()
    return embassy_response(
        embassy.handle_action(
            "GET",
            "/health",
            request.headers.get("X-Webhook-Signature"),
            raw_query,
        )
    )


@post("/rootcause/result", sync_to_thread=True)
def rootcause_result_post(request: Request, data: bytes) -> Response[bytes]:
    return embassy_response(
        embassy.handle_result("POST", request.headers.get("X-Webhook-Signature"), data)
    )


@route("/rootcause/result", http_method=NON_POST_METHODS, sync_to_thread=True)
def rootcause_result_probe(request: Request) -> Response[bytes]:
    return embassy_response(embassy.handle_result(request.method, None, b""))
```

In reverse-secret map mode, the health request must include the raw signed query
`project_id=<uuid>`; single-secret mode continues to accept the legacy empty query.

The Litestar adapter is illustrative and is not executed by this package's test suite. Configure
Litestar or the ASGI server to reject request bodies above `Config.max_body_bytes` before buffering;
the Embassy repeats the 8 MiB check after receiving bytes.

### FastAPI mount

FastAPI runs ordinary `def` route functions in its thread pool. The async dependency reads the
exact raw POST bytes before dispatching the sync handler.

```python
from typing import Annotated

from fastapi import Depends, FastAPI, Request, Response

app = FastAPI()
NON_POST_METHODS = ["GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


async def raw_body(request: Request) -> bytes:
    return await request.body()


def embassy_response(result: tuple[int, dict[str, str], bytes]) -> Response:
    status, headers, body = result
    return Response(body, status_code=status, headers=headers, media_type=None)


@app.post("/rootcause/action")
def rootcause_action_post(request: Request, data: Annotated[bytes, Depends(raw_body)]) -> Response:
    return embassy_response(
        embassy.handle_action("POST", "", request.headers.get("X-Webhook-Signature"), data)
    )


@app.api_route("/rootcause/action", methods=NON_POST_METHODS)
def rootcause_action_probe(request: Request) -> Response:
    return embassy_response(embassy.handle_action(request.method, "", None, b""))


@app.get("/rootcause/action/health")
def rootcause_action_health(request: Request) -> Response:
    return embassy_response(
        embassy.handle_action(
            "GET",
            "/health",
            request.headers.get("X-Webhook-Signature"),
            request.url.query.encode(),
        )
    )


@app.post("/rootcause/result")
def rootcause_result_post(request: Request, data: Annotated[bytes, Depends(raw_body)]) -> Response:
    return embassy_response(
        embassy.handle_result("POST", request.headers.get("X-Webhook-Signature"), data)
    )


@app.api_route("/rootcause/result", methods=NON_POST_METHODS)
def rootcause_result_probe(request: Request) -> Response:
    return embassy_response(embassy.handle_result(request.method, None, b""))
```

Set an ASGI-server or reverse-proxy request limit no larger than `Config.max_body_bytes`; the core
limit cannot prevent the framework from buffering an oversized request first.

## Registering an action runner

The Embassy ships **no built-in interpreter**. A real `runtime: "python"` invocation without a
runner is a signed `400 invalid_request`; dry-run still performs the complete signed fetch and skips
only execution. This keeps executing fetched source an explicit application choice.

```python
import time
from types import MappingProxyType
from typing import Any

from rootcause_embassy import ActionContext


def run_action(ctx: ActionContext, params: dict[str, Any]) -> Any:
    if time.monotonic() >= ctx.deadline:
        raise TimeoutError("action deadline elapsed")

    scope = {
        "__builtins__": {"len": len, "str": str},  # your explicit policy
        "params": MappingProxyType(params),  # data, never interpolated into source
        "tenant": ctx.tenant,  # trusted typed tuple, never params/env
        "principal": ctx.principal,  # host-stamped identity, only for this invocation
        "action_run_id": ctx.action_run_id,  # host ledger id; None on dry run/older hosts
        "out": ctx.out,  # captured stdout, capped at 64 KiB
    }
    exec(compile(ctx.script, f"<rootcause:{ctx.digest}>", "exec"), scope)
    return scope["result"]
```

That example is an explicit in-process `exec` policy, not a sandbox. In production, expose only the
globals your approved scripts need. A runner exception becomes a signed `200` with `ok:false`, the
Python exception class/message/backtrace, and captured output.

Python cannot safely kill a running thread. `timeout` (20s) and `total_deadline` (22s) therefore act
as boundary backstops: fetch receives the remaining timeout, execution is refused if no budget
remains, the runner receives `ctx.deadline`, and elapsed time is checked again on return. Pass that
deadline into your I/O and make actions idempotent; a timeout is not a transaction boundary.

## What happens, in order

| Step | Refusal |
|---|---|
| verify HMAC over the exact request bytes | `401 bad_signature` |
| parse required fields; validate optional `runtime` when present | `400 invalid_request` |
| refuse malformed or nonempty inline action `attachments`, including dry-run | `400 invalid_request` |
| validate the tenant tuple | `400 invalid_request` |
| validate optional host-stamped principal context | `400 invalid_request` |
| validate optional host-stamped `action_run_id` (canonical UUID) | `400 invalid_request` |
| require fresh `issued_at` and an unseen `nonce` | `409 replay` |
| re-validate params against the invocation schema | `422 schema_violation` |
| signed script fetch plus digest/runtime verification | `502 resolve_failed` |
| require a runner unless dry-run | `400 invalid_request` |
| execute through the registered runner | signed `200`, possibly `ok:false` |

Every outcome is signed, including refusals. The deliberate exceptions are the unsigned
`405 + Allow: POST` mount probe and the unsigned `404` returned by an unauthenticated health probe.

Inline action attachments are not supported: a nonempty or malformed `attachments` field is refused
before script resolution or execution, even on dry-run. An absent field or empty object preserves
normal behavior. Health does not advertise `attachments_inline`. The inbound body limit remains
8 MiB by default; enforce it before buffering in your HTTP adapter.

## Async analysis

```python
from rootcause_embassy import AnalysisRequest, Principal

analysis = embassy.start_analysis(
    AnalysisRequest(
        subject=ticket.subject,
        body=ticket.body,
        project_id=ticket.project_id,  # required when using reverse-secret map mode
        metadata={"resource_type": "SupportTicket", "resource_id": str(ticket.id)},
        session_id=ticket.rootcause_session_id,  # omit on turn one
        principal=Principal(
            kind="acme_admin",
            external_id=str(current_user.id),  # from your authenticated session
            assurance="session",
        ),
    )
)
# Persist analysis.analysis_id and analysis.session_id.
```

A ticket created by a chat escalation action can hand that chat to its analysis: store the action's
`ctx.action_run_id` with the ticket and pass `context_refs=[ContextRef("action_run", stored_id)]`
(at most one, validated before sending). Never take the id from params or user text; the id locates,
the host authorizes, and the action's approved manifest must opt in.

Your `result_handler(result)` must be idempotent: upsert by `result.analysis_id` or metadata. A
handler failure is not acknowledged, the nonce is released, and rootcause redelivers. Render
`result.actions` as human-confirmed proposals; never execute them automatically.
`result.executed_actions` already ran host-side and must be rendered as outcomes.

After a human sends a reply or answers a question:

```python
from rootcause_embassy import Answer, SentMessageMetadata, SentMessageRequest

embassy.capture_sent_message(
    SentMessageRequest(
        session_id=ticket.rootcause_session_id,
        project_id=ticket.project_id,  # required when using reverse-secret map mode
        sent_body=reply.body,
        proposed_body=ticket.draft,
        sender=agent.name,
        metadata=SentMessageMetadata("SupportTicket", str(ticket.id)),
        answers=[Answer("country", ["BE"])],
    )
)
```

Sent-message metadata is fixed to `resource_type` and `resource_id`; trigger metadata is free-form.
Attachments are strict base64 and capped before transport at 256 KiB each and 6 MiB decoded total.

## Embedded chat

```python
from rootcause_embassy import Claims, Widget, mint_embed_token, widget_tag_html

claims = Claims(
    project="acme",
    external_id=str(current_user.id),
    kind="acme_admin",
    origin="https://admin.acme.com",
    tenant=current_tenant.slug,  # server-authorized context, never browser input
    locale="nl",
    color_scheme="light",
)
token = mint_embed_token(chat_secret, claims)
tag = widget_tag_html(
    Widget("https://app.replypen.com", "acme", token, mode="page", target="#rc-chat")
)
```

Mint a fresh token per render: the host burns its `jti` when a session opens. Chat uses the project's
`webhook_secret`, never the action secret.

## Generic API plane

```python
response = embassy.api.patch(
    "/api/v1/tenants/acme/profile",
    body={"settings": settings, "source": "embassy"},
)
if not response.ok and response.retryable:
    retry_later()  # transport/auth, 5xx, 429, or 408
```

HTTP and auth failures are `APIResponse` values. Invalid configuration or arguments (blank path,
off-origin absolute URL) raise `Misconfigured`. An `rcor_` key is exchanged and cached per
`(api_base_url, api_key)` behind a lock; any other key is used verbatim. Use
`embassy.api_for(base_url, key)` for another project.

## Multi-worker deployments

The default `MemoryNonceStore` is correct for one process only. A multi-worker deployment must
provide an atomic shared implementation of `seen(nonce, ttl) -> bool` and `release(nonce)`. `seen`
records an unseen nonce and returns `True` only for a duplicate. `release` matters on the result
route: a failed dispatch must be genuinely retried.

Script bodies cache in memory and optionally under `cache_dir`. Disk reads are re-hashed before use;
malformed digests never become filenames.

## Development

```sh
make check        # ruff + mypy strict + pytest
make conformance  # fixture replay; prints the vendored hub SHA
```
