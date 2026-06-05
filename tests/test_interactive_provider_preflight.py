from __future__ import annotations

from types import SimpleNamespace

from clearwing.ui.commands.interactive import _effective_model_for_display, _preflight_check


class _Console:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, message: str, *args, **kwargs) -> None:
        self.messages.append(str(message))


class _Config:
    def __init__(self, provider: dict) -> None:
        self._provider = provider

    def get_provider_section(self) -> dict:
        return self._provider


def _cli(provider: dict):
    return SimpleNamespace(console=_Console(), config=_Config(provider))


def _args(**overrides):
    values = {
        "model": "claude-sonnet-4-6",
        "base_url": None,
        "api_key": None,
        "target": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_interactive_preflight_accepts_llm_config(monkeypatch):
    for name in (
        "CLEARWING_BASE_URL",
        "CLEARWING_API_KEY",
        "CLEARWING_MODEL",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    assert _preflight_check(_cli({"adapter": "llm"}), _args())


def test_interactive_display_uses_configured_llm_model(monkeypatch):
    for name in (
        "CLEARWING_BASE_URL",
        "CLEARWING_API_KEY",
        "CLEARWING_MODEL",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    model = _effective_model_for_display(
        _cli({"adapter": "llm", "model": "deepseek-v4-round-robin-9router"}),
        _args(),
    )
    assert model == "deepseek-v4-round-robin-9router"


def test_interactive_preflight_still_errors_without_any_provider(monkeypatch):
    for name in (
        "CLEARWING_BASE_URL",
        "CLEARWING_API_KEY",
        "CLEARWING_MODEL",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    cli = _cli({})
    assert not _preflight_check(cli, _args())
    assert any("No LLM credentials found" in message for message in cli.console.messages)
