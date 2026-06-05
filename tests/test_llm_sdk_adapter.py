from __future__ import annotations

import builtins
import sys
from types import SimpleNamespace

import pytest
from genai_pyo3 import ChatMessage

from clearwing.llm.native import AsyncLLMClient, NativeToolSpec, response_text


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self._text = text

    def text(self) -> str:
        return self._text


class _FakeModel:
    def __init__(self, *, reject_tools: bool = False) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.reject_tools = reject_tools

    def prompt(self, prompt: str, **kwargs):
        self.calls.append((prompt, kwargs))
        if self.reject_tools and kwargs.get("tools"):
            raise RuntimeError("OpenAI Chat: test-model does not support tools")
        return _FakeResponse("PONG")


@pytest.mark.asyncio
async def test_llm_sdk_adapter_uses_configured_model(monkeypatch):
    fake_model = _FakeModel()
    fake_module = SimpleNamespace(get_model=lambda model_id=None: fake_model)
    monkeypatch.setitem(sys.modules, "llm", fake_module)

    client = AsyncLLMClient(
        model_name="my-llm-alias",
        provider_name="llm",
        api_key="",
    )
    response = await client.achat(
        messages=[ChatMessage("user", "Reply with PONG")],
        system="system prompt",
        temperature=0.2,
    )

    assert response_text(response) == "PONG"
    prompt, kwargs = fake_model.calls[0]
    assert prompt == "Reply with PONG"
    assert kwargs["system"] == "system prompt"
    assert kwargs["options"] == {"temperature": 0.2}


@pytest.mark.asyncio
async def test_llm_sdk_adapter_reports_missing_package(monkeypatch):
    monkeypatch.delitem(sys.modules, "llm", raising=False)
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "llm":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    client = AsyncLLMClient(model_name="", provider_name="llm", api_key="")
    with pytest.raises(RuntimeError, match="llm.*not installed"):
        await client.achat(messages=[ChatMessage("user", "hi")])


@pytest.mark.asyncio
async def test_llm_sdk_adapter_retries_without_tools_when_model_rejects_them(monkeypatch):
    fake_model = _FakeModel(reject_tools=True)
    fake_module = SimpleNamespace(get_model=lambda model_id=None: fake_model)
    monkeypatch.setitem(sys.modules, "llm", fake_module)

    async def handler(value: str) -> str:
        return value

    client = AsyncLLMClient(model_name="deepseek-v4-9router", provider_name="llm", api_key="")
    response = await client.achat(
        messages=[ChatMessage("user", "hi")],
        tools=[
            NativeToolSpec(
                name="echo",
                description="Echo a value",
                schema={
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                },
                handler=handler,
            )
        ],
    )

    assert response_text(response) == "PONG"
    assert "tools" in fake_model.calls[0][1]
    assert "tools" not in fake_model.calls[1][1]
