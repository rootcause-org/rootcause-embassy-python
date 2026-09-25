# rootcause-embassy-python — build plan (WP4)

The Python **Embassy**: rootcause's trusted in-app presence inside a customer's Python service.
Package `rootcause_embassy`, `uv` project, Python ≥ 3.13, **zero runtime dependencies** (stdlib
only: `hmac`, `hashlib`, `json`, `urllib.request`, `threading`, `base64`, `html`, `urllib.parse`).

**The contract lives in `~/code/rootcause-org/rootcause-embassy`** (`CONTRACT.md`, `planes/*.md`,
`decisions.md`, `fixtures/`). Read all of it first. Vendor `fixtures/` from hub commit
`249b9eb58ce4aec2a717668ee9f87efb7ae65ba2` into `tests/contract/testdata/` (wholesale copy, no
trailing-newline edits) and write that SHA to `tests/contract/testdata/HUB_SHA`. Never fix a
fixture here — an ambiguity goes back to the hub as a decision.

Reference implementation to mirror (structure, tests, README tone): `~/code/rootcause-org/rootcause-embassy-go`
(`contract_test.go` is the conformance suite to port 1:1). Ruby: `~/code/rootcause-org/rootcause-embassy-ruby`.

First consumer: DentAI (Litestar, 3.13). It needs **chat embed JWT mint immediately**; actions +
api planes next. Zero DentAI-specific code in this repo.

## Locked decisions

1. **Framework-agnostic core.** Inbound routes are pure functions over bytes:
   `Embassy.handle_action(method: str, subpath: str, signature: str | None, body: bytes) -> Response`
   and `Embassy.handle_result(method, signature, body) -> Response`, where
   `Response = (status: int, headers: dict[str, str], body: bytes)`. `subpath` is `""` for the
   mount, `"/health"` for health. No ASGI/WSGI adapter in the package; README shows a ~10-line
   Litestar mount and a FastAPI one. Sync API only (Litestar runs sync handlers in a threadpool).
2. **Runtime token `"python"`, execution via `Config.runner` only** (hub decision 12). Signature:
   `runner(ctx: ActionContext, params: dict) -> Any` where `ActionContext` carries `action_id`,
   `digest`, `script: str`, `tenant: Tenant | None`, `out: io.StringIO` (captured stdout, 64 KiB
   cap), `deadline: float` (monotonic). No built-in `exec` runner. No runner + real invocation →
   signed `400 invalid_request`. `dry_run` works without a runner and MUST perform the signed fetch.
   Runner exceptions → signed `200` with `ok:false, error:{class:<ExceptionType name>, message,
   backtrace}` (decision 6e). Timeout: `Config.timeout` (20s) inside `Config.total_deadline` (22s);
   Python cannot kill a thread, so the deadline is a backstop enforced at the boundaries (fetch
   timeout + elapsed check before run + runner may read `ctx.deadline`) — document this honestly.
3. **Tenant tuple as a typed argument** (`Tenant(id, slug, scope_value)`), never `RC_TENANT_*` env
   (decision 9). All-or-nothing, partial tuple = 400, reserved names refused in params AND schema,
   NUL refused, `require_tenant_context` knob.
4. **Signing**: `sign(body: bytes, secret: str) -> "sha256=<hex>"`, `verify(header, body, secret)
   -> bool`, constant-time (`hmac.compare_digest`), blank secret fails closed on both sides. Every
   response is signed except the unsigned `405 + Allow: POST` probe (`class: method_not_allowed`).
   Health: unsigned GET → 404; signed (over the raw query string, `""` when none) → 200 golden with
   `"embassy":"python"`, `"version":"0.1.0"`, `protocol: 1`, capabilities
   `["actions","dry_run","analysis_result","health"]`.
5. **JSON on the wire**: `json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()` —
   no trailing newline, insertion order (Python dicts) so envelopes/refusals match the goldens
   byte-for-byte. Sign the bytes you write; verify the bytes you received; never re-serialize.
6. **Replay**: `NonceStore` protocol (`seen(nonce, ttl) -> bool`, `release(nonce)`), default
   in-memory with `threading.Lock` and TTL ≥ window. Action route: dup nonce → 409. Result route:
   dup nonce after a successful dispatch → idempotent `200 {"ok":true}`; failed dispatch releases
   the nonce; stale `issued_at` → 409 on both routes (decision 1). `issued_at` RFC3339 UTC, ±300s
   symmetric.
7. **Resolver**: memory → optional `cache_dir` (digest-shaped filename only: `sha256:` + 64 lowercase
   hex, validated before use) → signed `GET fetch_url?action_id=&digest=&project_id=` (that order,
   signature over the raw query string). Unsigned/mis-signed response or `sha256(script) != digest`
   → `502 resolve_failed`; the body never runs. Re-hash on every disk read.
8. **Analysis client**: `start_analysis(AnalysisRequest) -> Analysis`, `capture_sent_message(
   SentMessageRequest)` (sent body and/or `answers[]`). Outbound bodies in golden key order, signed.
   Attachment caps enforced client-side (256 KiB per, 6 MiB total decoded) — raise before sending.
   Non-2xx/transport → raise `EmbassyError` to the caller (never swallowed).
9. **Result decode** (`Result` dataclass): tolerant-inbound; `notes[].key == "summary"` → `note`,
   `kind` legacy fallback; `draft` markdown-first; `actions[]` (with `slug`), `executed_actions[]`,
   `questions[]`, `delete[]` → `delete_ids`, `attachments`, `decline`, `metadata`. `ok` property =
   no decline. `Config.result_handler: Callable[[Result], None]` — unset/unloadable = signed 500
   `handler_error`; an unexpected handler exception = signed 500 `internal_error` whose message is
   the exception class name only. A handler-raised contract `Refusal` propagates unchanged.
10. **Chat** (`rootcause_embassy.chat`): `mint_embed_token(secret, Claims) -> str` with pinned claim
    order `sub,aud,iss,jti,origin,iat,nbf,exp,principal{kind,external_id,asserted_by,assurance},
    tenant?,locale?,color_scheme?` (optionals omitted, never null), header exactly
    `{"alg":"HS256","typ":"JWT"}`, base64url unpadded. `canonical_origin()` per `planes/chat.md`
    (refuse path/query/fragment at mint). `widget_tag_html(Widget) -> str`, loader
    `/chat/widget/v1/loader.js?v=3`, attributes HTML-escaped, optional attrs only when set. Key =
    `chat_secret` (webhook_secret) and boot-time refusal when it equals `secret`.
11. **API plane** (`rootcause_embassy.api`): `API.get/post/patch/put/delete(path, body=None,
    params=None) -> APIResponse(ok, status, body, field_errors, error, retryable, err)`; `rcor_`
    refresh exchange at `{api_base_url}/oauth/token` (`client_id=rcocl_cli`), in-process cache per
    `(api_base_url, api_key)` behind a lock, refresh 60s early on `time.monotonic()`, one re-exchange
    on 401, `expires_in` default 3600; non-`rcor_` key used verbatim. Off-origin absolute URL /
    blank path / unset config → raise `Misconfigured`. Retryable: transport, auth, 5xx, 429, 408.
12. **Config** (`dataclass`, validated fail-closed at construction), env fallbacks identical to Go:
    `ROOTCAUSE_ACTION_SECRET`, `ROOTCAUSE_FETCH_URL`, `ROOTCAUSE_TRIGGER_URL`,
    `ROOTCAUSE_SENT_MESSAGE_URL`, `ROOTCAUSE_API_BASE_URL`, `ROOTCAUSE_API_KEY`,
    `ROOTCAUSE_CHAT_SECRET`, `ROOTCAUSE_CHAT_PROJECT`, `ROOTCAUSE_CHAT_BASE_URL`. Determinism seams:
    `now: Callable[[], float]` (unix seconds), `nonce: Callable[[], str]`,
    `transport: Callable[[HTTPRequest], HTTPResponse]` (default urllib, 20s timeout) — the
    conformance suite injects all three; no live server needed. `max_body_bytes` defaults to 8 MiB
    and both inbound routes check it before authentication/decoding.
13. **Logging**: stdlib `logging` logger `rootcause_embassy`; identifiers, shapes, byte counts only.
    `internal_error` message = exception class name only.
14. **Taxonomy**: project / run / session / principal / tenant tuple / action / Embassy. No aliases.

## Layout

```
pyproject.toml            uv, hatchling build, no runtime deps; dev: pytest, ruff, mypy(strict)
mise.toml                 [tools] python = "3.13"
Makefile                  check: lint test · lint: ruff check + ruff format --check + mypy · test: pytest · conformance: pytest tests/contract -s
README.md                 install, configure, Litestar + FastAPI mount snippets, chat mint, runner example, step table
AGENTS.md                 repo map + rules (mirror the Go one; contract lives in the hub)
src/rootcause_embassy/
  __init__.py             Embassy, Config, Response, public re-exports, VERSION = "0.1.0", PROTOCOL = 1, RUNTIME = "python"
  config.py               Config + env fallbacks + fail-closed validation
  signature.py            sign / verify / HEADER
  replay.py               freshness window, NonceStore protocol, MemoryNonceStore
  schema.py               param re-validation (string, integer, number, boolean, string[]), reserved names
  tenant.py               Tenant, tuple extraction
  resolver.py             script by digest
  action.py               action route: verify → parse → tenant → replay → schema → resolve → run → sign; health; 405
  result.py               Result dataclasses + tolerant decode
  resultroute.py          result route incl. idempotent ack + nonce release
  client.py               start_analysis, capture_sent_message
  api.py                  API + rcor_ exchange
  chat.py                 mint_embed_token, canonical_origin, widget_tag_html
  errors.py               EmbassyError(status, class, message), Misconfigured, class constants
  http.py                 HTTPRequest/HTTPResponse + urllib transport
tests/
  contract/test_contract.py   the conformance suite (below) — prints HUB_SHA at session start
  contract/testdata/          vendored hub fixtures + HUB_SHA
  test_*.py                   a minimal set of unit tests where conformance does not reach (config validation, schema types, api retryable table, origin canonicalization)
```

Target ≈ 2k LOC source, tests lean — port the Go `contract_test.go` cases, don't invent more.

## Conformance suite (must all pass; `make conformance` prints `SYNC: fixtures vendored from rootcause-embassy commit <sha>`)

1. Every `signing_vectors.json.bodies` entry: file byte length, sha256, `sign()` match, own
   `verify()` accepts, mutated body rejected. Every `query_strings` entry: raw query signature match.
   Blank-secret fails closed (sign returns refusal, verify false), missing header false.
2. Action round trip with a fake host (injected transport) serving a **Python** script (fixture
   script is Ruby — the wire shapes are what conformance pins) and a test-local runner that
   `exec`s it; asserts envelope, `stdout`, tenant reaches the runner, fetch query order + signature.
3. Dry-run bytes == `result_dry_run.json` (duration normalized); success envelope key order ==
   `result_ok.json`; fetch performed during dry run.
4. Refusals byte-exact vs the four `result_refusal_*.json` (401/409/422/502) + class-only checks:
   unsigned fetch response 502, `runtime: ruby` fixture → 400, non-boolean `dry_run` → 400 without
   reaching fetch, stale `issued_at` → 409, reserved tenant param → 422, partial tuple → 400,
   **no runner + real invocation → 400** (decision 12), runner exception → signed 200 `ok:false`.
   Every refusal signed.
5. `405 + Allow: POST`, unsigned, `method_not_allowed` body. Health: unsigned 404; signed → golden
   with `embassy`/`version` swapped.
6. Result callback decode of `result_callback.json` → all fields asserted; ack bytes ==
   `result_ack.json`; redelivery semantics (3× → 1 dispatch; failed dispatch releases nonce; stale
   → 409; unconfigured handler → 500 `handler_error`; bad signature → golden 401 bytes).
7. Outbound `trigger.json`, `trigger_with_principal.json`, `sent_message.json`, `answers.json`:
   structural equality + top-level key order + signature over transmitted bytes.
8. Chat: `jwt_vector.json` → exact `signing_input` and `token`; `widget_tag.html` byte-exact;
   `alg` header exact; blank secret refused; origin canonicalization cases.
9. API: `rcor_` exchange round trip via injected transport, cache hit, 401 → single re-exchange,
   static bearer verbatim, retryable table, off-origin refusal.

## Definition of done

- `make check` green (ruff, mypy strict, pytest), conformance prints the HUB_SHA.
- README + AGENTS.md written. `.gitignore` (`.venv/`, `__pycache__/`, `dist/`, `.pytest_cache/`,
  `.mypy_cache/`, `.ruff_cache/`).
- One commit on `main` (local only — **do not push**, no remote yet).
- Report back: what changed, LOC, anything the contract left ambiguous (do NOT resolve it locally).
