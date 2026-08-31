from __future__ import annotations

import pytest

from rootcause_embassy import Config
from rootcause_embassy.errors import Misconfigured

FETCH = "https://app.replypen.com/actions/script"


def test_config_validation_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "ROOTCAUSE_ACTION_SECRET",
        "ROOTCAUSE_FETCH_URL",
        "ROOTCAUSE_API_BASE_URL",
        "ROOTCAUSE_API_KEY",
        "ROOTCAUSE_CHAT_SECRET",
        "ROOTCAUSE_CHAT_PROJECT",
        "ROOTCAUSE_CHAT_BASE_URL",
    ):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(Misconfigured, match="Secret is required"):
        Config(fetch_url=FETCH)
    with pytest.raises(Misconfigured, match="placeholder"):
        Config(secret="secret")
    with pytest.raises(Misconfigured, match="TotalDeadline"):
        Config(secret="secret", fetch_url=FETCH, timeout=23)
    with pytest.raises(Misconfigured, match="byte caps"):
        Config(secret="secret", fetch_url=FETCH, max_body_bytes=0)
    with pytest.raises(Misconfigured, match="APIBaseURL"):
        Config(secret="secret", fetch_url=FETCH, api_key="rcor_x")
    with pytest.raises(Misconfigured, match="ChatProject"):
        Config(secret="secret", fetch_url=FETCH, chat_secret="chat")
    with pytest.raises(Misconfigured, match="must differ"):
        Config(
            secret="secret",
            fetch_url=FETCH,
            chat_secret="secret",
            chat_project="demo",
        )


def test_config_env_fallback_and_explicit_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROOTCAUSE_ACTION_SECRET", "from-env")
    monkeypatch.setenv("ROOTCAUSE_FETCH_URL", FETCH)
    monkeypatch.setenv("ROOTCAUSE_TRIGGER_URL", "https://app.replypen.com/analyses/demo")
    config = Config()
    assert config.secret == "from-env"
    assert config.trigger_url.endswith("/analyses/demo")
    assert Config(secret="explicit").secret == "explicit"
