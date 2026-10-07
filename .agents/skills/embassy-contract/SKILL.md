---
name: embassy-contract
description: Change the Python Embassy while preserving the hub-owned Host ↔ Embassy contract.
---

# Python Embassy contract work

Read [../../../AGENTS.md](../../../AGENTS.md), then read the authority in
`~/code/rootcause-org/rootcause-embassy` before changing wire behavior.

## Route by intent

- Actions/signing/replay: `signature.py`, `replay.py`, `tenant.py`, `action_principal.py`,
  `schema.py`, `resolver.py`, `action.py`. `ActionContext.principal` is the immutable, per-invocation
  host assertion for in-process runners; its `claims` mapping is always present (possibly empty), and
  action params/schemas cannot select principal selectors or `principal_claim_*` fields.
  Inline action attachments are unsupported: `action.py` refuses any malformed or nonempty
  `attachments` envelope before resolution, including dry-run. Absence/empty maps remain accepted;
  health must not advertise `attachments_inline` until invocation-scoped materialization exists.
- Analysis callback/result shape: `result.py`, `resultroute.py`.
- Analysis outbound messages: `client.py`.
- Chat key/JWT/widget: `chat.py`. Loader revision follows hub decision 25 (`?v=5`);
  page-context callbacks and queued snapshots belong to the hosted loader. `chat/page_url.json`
  is unsigned normalization data, not a JWT claim or signing vector.
- Bearer API/exchange/cache: `api.py`.
- Construction and deterministic seams: `config.py`, `http.py`, `__init__.py`.

Vendored fixtures are immutable locally. A contract ambiguity goes back to the hub as a numbered
decision and, when wire-visible, a golden fixture. Verify with `make check`; the conformance command
must print `tests/contract/testdata/HUB_SHA`.
