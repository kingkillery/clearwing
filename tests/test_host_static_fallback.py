"""Host-mode (no sandbox) static-only fallback tests.

Regression coverage for docs/known-issues.md: "Host-mode hunters can get
stuck on sandbox-only tool calls". Without Docker, sandbox-backed tools
(execute/read_file/write_file/compile_file/run_with_sanitizer/
write_test_case/fuzz_harness) only returned "no sandbox available" while
burning hunter steps (session sh-70f0d515). Now every non-propagation
hunter downgrades to the static-only tool set (discovery + reporting),
gets the constrained repeat-throttle, and its prompt names the tools it
actually has.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.hunter import (
    build_hunter_agent,
    build_subsystem_hunter_agent,
)
from clearwing.sourcehunt.state import SubsystemTarget
# Sandbox-only tool names that must never be registered in host mode.
_SANDBOX_TOOLS = {
    "execute",
    "read_file",
    "write_file",
    "compile_file",
    "run_with_sanitizer",
    "write_test_case",
    "fuzz_harness",
}
_STATIC_TOOLS = {"read_source_file", "list_source_tree", "grep_source", "find_callers", "record_finding"}


def _ft(path: str = "src/app.c", tier: str = "A") -> dict:
    return {
        "path": path,
        "absolute_path": f"/abs/{path}",
        "surface": 4,
        "influence": 3,
        "reachability": 3,
        "priority": 3.4,
        "tier": tier,
        "tags": [],
        "language": "c",
        "loc": 100,
        "static_hint": 0,
        "imports_by": 0,
        "defines_constants": False,
        "semgrep_hint": 0,
        "transitive_callers": 0,
        "has_fuzz_entry_point": False,
        "fuzz_harness_path": None,
        "surface_rationale": "",
        "influence_rationale": "",
        "reachability_rationale": "",
    }


def _build(sandbox, agent_mode, prompt_mode="unconstrained", tier="A"):
    return build_hunter_agent(
        file_target=_ft(tier=tier),
        repo_path="/tmp/repo",
        sandbox=sandbox,
        llm=MagicMock(),
        session_id="test-session",
        agent_mode=agent_mode,
        prompt_mode=prompt_mode,
    )


class TestHostStaticOnlyFallback:
    def test_deep_mode_without_sandbox_gets_static_tools(self):
        hunter, _ctx = _build(sandbox=None, agent_mode="deep")
        names = {t.name for t in hunter.tools}
        assert not (names & _SANDBOX_TOOLS)
        assert _STATIC_TOOLS <= names

    def test_deep_mode_without_sandbox_uses_constrained_throttle(self):
        hunter, _ctx = _build(sandbox=None, agent_mode="deep")
        # Effective mode drives repeat-throttling in NativeHunter.arun.
        assert hunter.agent_mode == "constrained"

    def test_deep_mode_without_sandbox_prompt_declares_static_only(self):
        hunter, _ctx = _build(sandbox=None, agent_mode="deep")
        assert "STATIC-ONLY MODE" in hunter.prompt
        assert "read_source_file" in hunter.prompt

    def test_deep_mode_without_sandbox_preserves_step_limit(self):
        hunter, _ctx = _build(sandbox=None, agent_mode="deep")
        assert hunter.max_steps == 500

    def test_constrained_mode_without_sandbox_drops_analysis_tools(self):
        hunter, _ctx = _build(sandbox=None, agent_mode="constrained")
        names = {t.name for t in hunter.tools}
        assert not (names & _SANDBOX_TOOLS)
        assert _STATIC_TOOLS <= names
        assert hunter.max_steps == 20

    def test_specialist_prompt_mode_without_sandbox_also_downgrades(self):
        hunter, _ctx = _build(sandbox=None, agent_mode="deep", prompt_mode="specialist")
        names = {t.name for t in hunter.tools}
        assert not (names & _SANDBOX_TOOLS)
        assert "STATIC-ONLY MODE" in hunter.prompt
        # The deep prompt's false claims must be gone, not just contradicted
        # by a later block — otherwise the model still retries shell tools.
        assert "full shell access" not in hunter.prompt
        assert "execute(command)" not in hunter.prompt

    def test_specialist_fallback_preserves_entry_point_context(self):
        ep = MagicMock()
        ep.function_name = "parse_header"
        ep.start_line = 10
        ep.end_line = 80
        ep.entry_type = "parser"
        hunter, _ctx = build_hunter_agent(
            file_target=_ft(),
            repo_path="/tmp/repo",
            sandbox=None,
            llm=MagicMock(),
            session_id="test-session",
            agent_mode="deep",
            prompt_mode="specialist",
            entry_point=ep,
        )
        assert "parse_header" in hunter.prompt

    def test_deep_mode_with_sandbox_keeps_deep_tools(self):
        hunter, _ctx = _build(sandbox=MagicMock(), agent_mode="deep")
        names = {t.name for t in hunter.tools}
        assert {"execute", "read_file", "write_file"} <= names
        assert hunter.agent_mode == "deep"
        assert "STATIC-ONLY MODE" not in hunter.prompt

    def test_propagation_hunter_unchanged_without_sandbox(self):
        hunter, _ctx = _build(sandbox=None, agent_mode="constrained", tier="C")
        names = {t.name for t in hunter.tools}
        # Propagation is already discovery+reporting; no sandbox tools either way.
        assert not (names & _SANDBOX_TOOLS)
        assert "STATIC-ONLY MODE" not in hunter.prompt


class TestSubsystemHunterFallback:
    def _subsystem(self):
        return SubsystemTarget(
            name="auth",
            root_path="src/auth",
            files=[_ft("src/auth/login.c")],
        )

    def test_subsystem_without_sandbox_gets_static_tools(self):
        hunter, _ctx = build_subsystem_hunter_agent(
            subsystem=self._subsystem(),
            repo_path="/tmp/repo",
            sandbox=None,
            llm=MagicMock(),
            session_id="test-session",
        )
        names = {t.name for t in hunter.tools}
        assert not (names & _SANDBOX_TOOLS)
        assert _STATIC_TOOLS <= names
        assert hunter.agent_mode == "constrained"
        assert "STATIC-ONLY MODE" in hunter.prompt
        assert hunter.max_steps == 2000  # branch limit preserved

    def test_subsystem_with_sandbox_keeps_deep_tools(self):
        hunter, _ctx = build_subsystem_hunter_agent(
            subsystem=self._subsystem(),
            repo_path="/tmp/repo",
            sandbox=MagicMock(),
            llm=MagicMock(),
            session_id="test-session",
        )
        names = {t.name for t in hunter.tools}
        assert {"execute", "read_file", "write_file"} <= names
        assert hunter.agent_mode == "deep"


class TestUnknownToolRecovery:
    @pytest.mark.asyncio
    async def test_unknown_tool_error_lists_available_tools(self):
        hunter, ctx = _build(sandbox=None, agent_mode="deep")
        tools_by_name = {t.name: t for t in hunter.tools}
        call = MagicMock()
        call.fn_name = "execute"  # hallucinated sandbox tool in host mode
        call.fn_arguments = {}
        result = await hunter._run_tool(tools_by_name, call)
        assert "unknown tool: execute" in result["error"]
        assert "read_source_file" in result["error"]
        assert "grep_source" in result["error"]
