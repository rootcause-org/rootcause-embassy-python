---
name: embassy-contract
description: Change the Python Embassy while preserving the hub-owned Host ↔ Embassy contract.
---

# Python Embassy contract work

Read [../../../AGENTS.md](../../../AGENTS.md), then read the authority in
`~/code/rootcause-org/rootcause-embassy` before changing wire behavior.

## Route by intent

- Actions/signing/replay: `signature.py`, `replay.py`, `tenant.py`, `schema.py`, `resolver.py`,
  `action.py`.
- Analysis callback/result shape: `result.py`, `resultroute.py`.
- Analysis outbound messages: `client.py`.
- Chat key/JWT/widget: `chat.py`.
- Bearer API/exchange/cache: `api.py`.
- Construction and deterministic seams: `config.py`, `http.py`, `__init__.py`.

Vendored fixtures are immutable locally. A contract ambiguity goes back to the hub as a numbered
decision and, when wire-visible, a golden fixture. Verify with `make check`; the conformance command
must print `tests/contract/testdata/HUB_SHA`.
