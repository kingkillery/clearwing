"""Regression test: configured MCP servers must actually connect at startup.

`graph._connect_configured_mcp_servers()` is called during graph build —
including from async WebUI/operator contexts where an event loop is already
running. `AgentTool.invoke()` returns an unawaited coroutine in that case,
so the connection silently never happened (RuntimeWarning: coroutine
'AgentTool.ainvoke' was never awaited). The fix calls the tool's sync func
directly via `__call__`; these tests pin that behavior.
"""

from __future__ import annotations

import asyncio
import warnings

import pytest

from clearwing.agent import graph as agent_graph
from clearwing.agent.tools.ops import mcp_tools


class _FakeMCPClient:
    """Records connect() and reports one tool."""

    instances: list[_FakeMCPClient] = []

    def __init__(self, command, args):
        self.command = command
        self.args = args
        self.connected = False
        _FakeMCPClient.instances.append(self)

    def connect(self):
        self.connected = True

    def list_tools(self):
        return [{"name": "fake_tool"}]


@pytest.fixture
def fake_mcp_env(monkeypatch):
    """One configured MCP server + a recording fake client."""
    _FakeMCPClient.instances = []
    mcp_tools._MCP_CLIENTS.clear()

    class FakeConfig:
        def get_mcp_servers(self):
            return {"srv1": {"command": "fake-mcp", "args": ["--flag"]}}

    monkeypatch.setattr(agent_graph, "Config", FakeConfig)
    monkeypatch.setattr(mcp_tools, "MCPClient", _FakeMCPClient)
    yield
    mcp_tools._MCP_CLIENTS.clear()


class TestMcpStartupConnect:
    def test_connects_without_running_loop(self, fake_mcp_env):
        agent_graph._connect_configured_mcp_servers()
        assert len(_FakeMCPClient.instances) == 1
        assert _FakeMCPClient.instances[0].connected is True
        assert "srv1" in mcp_tools._MCP_CLIENTS

    def test_connects_inside_running_loop(self, fake_mcp_env):
        """The WebUI case: a loop is already running. Connection must still
        execute — and no coroutine may leak."""

        async def _build():
            agent_graph._connect_configured_mcp_servers()

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            asyncio.run(_build())

        assert len(_FakeMCPClient.instances) == 1, (
            "MCP connect did not execute inside a running loop — "
            "invoke() returned an unawaited coroutine"
        )
        assert _FakeMCPClient.instances[0].connected is True
        assert "srv1" in mcp_tools._MCP_CLIENTS
        coroutine_warnings = [
            w for w in caught if "never awaited" in str(w.message)
        ]
        assert not coroutine_warnings

    def test_error_does_not_block_startup(self, fake_mcp_env, monkeypatch):
        class ExplodingClient:
            def __init__(self, command, args):
                pass

            def connect(self):
                raise ConnectionError("server unreachable")

        monkeypatch.setattr(mcp_tools, "MCPClient", ExplodingClient)
        # Must not raise — optional external servers never block startup
        agent_graph._connect_configured_mcp_servers()
        assert "srv1" not in mcp_tools._MCP_CLIENTS

    def test_skips_servers_without_command(self, monkeypatch):
        _FakeMCPClient.instances = []
        mcp_tools._MCP_CLIENTS.clear()

        class EmptyConfig:
            def get_mcp_servers(self):
                return {"no_cmd": {"command": "", "args": []}}

        monkeypatch.setattr(agent_graph, "Config", EmptyConfig)
        agent_graph._connect_configured_mcp_servers()
        assert _FakeMCPClient.instances == []
