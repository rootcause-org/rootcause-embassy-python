.PHONY: check lint test conformance

check: lint test

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

test:
	uv run pytest

conformance:
	uv run pytest tests/contract -s
