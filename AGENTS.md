# rootcause-embassy-python — agent map

The Python Embassy. Customer-facing usage is in [README.md](README.md); this file maps ownership and
the rules for changing the implementation.

## Contract authority

The wire contract lives in `~/code/rootcause-org/rootcause-embassy`: `CONTRACT.md`,
`planes/{actions,analysis,chat,api}.md`, `decisions.md`, and `fixtures/`.

- Start every wire/behavior change in the hub. Never resolve an ambiguity only here.
- `tests/contract/testdata/` is a wholesale vendored fixture copy. Never edit a fixture locally;
  re-copy it from a named hub commit and update `HUB_SHA`.
- The two invariants no port may drop: no Embassy auto-executes an analysis `actions[]` proposal,
  and no principal ever originates from model output.

## Repo map

| Path | Owns |
|---|---|
| `src/rootcause_embassy/config.py` | env fallbacks, seams, fail-closed boot validation |
| `signature.py` / `replay.py` | exact-byte HMAC and nonce/freshness protection |
| `tenant.py` / `schema.py` | trusted tenant tuple and param re-validation |
| `resolver.py` | memory/disk/signed-fetch resolution, digest verification |
| `action.py` | pure action/health route and registered-runner execution |
| `result.py` / `resultroute.py` | tolerant result decode, ack/dedupe/release behavior |
| `client.py` | analysis trigger and sent-message/answers clients |
| `chat.py` | HS256 embed token and widget tag; separate chat key |
| `api.py` | generic API caller and `rcor_` token exchange/cache |
| `http.py` | injected transport types and urllib default |
| `tests/contract/` | byte-exact hub conformance suite |

## Rules

- Python 3.13 via mise; `uv` only. Runtime dependencies stay zero.
- Public inbound routes stay framework-agnostic pure functions over bytes. Adapters belong in app
  code or README examples, not this package.
- `runtime: "python"` executes only through `Config.runner`. Never add a built-in `exec` fallback.
- Sign exact transmitted bytes once. Every action/result answer is signed except the unsigned 405
  probe and unauthenticated health 404.
- The tenant tuple is a typed runner argument, never process-global environment state.
- Log identifiers, shapes, byte counts, and statuses only: never bodies, values, secrets, bearer
  tokens, query strings, or unexpected exception messages.
- Run `make check`; run `make conformance` when the hub or wire behavior is touched.

Python cannot kill a running thread. Execution timeouts remain boundary checks plus
`ActionContext.deadline`; document this honestly rather than implying cancellation.
