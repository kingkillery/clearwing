"""Tests for the hunter's record_finding tool (hunt/reporting.py)."""

from __future__ import annotations

from unittest.mock import MagicMock

from clearwing.agent.tools.hunt.reporting import build_reporting_tools


def _ctx():
    ctx = MagicMock()
    ctx.specialist = "memory_safety"
    ctx.session_id = "sess-test"
    ctx.seeded_crash = None
    ctx.findings = []
    return ctx


def _tool(ctx):
    return build_reporting_tools(ctx)[0]


class TestRecordFinding:
    def test_records_with_all_fields(self):
        ctx = _ctx()
        result = _tool(ctx).handler(
            file="src/parse.c",
            line_number=42,
            finding_type="memory_safety",
            severity="high",
            description="heap overflow in parse_header",
            cwe="CWE-787",
        )
        assert "Finding recorded" in result
        assert len(ctx.findings) == 1
        f = ctx.findings[0]
        assert f.cwe == "CWE-787"
        assert f.file == "src/parse.c"
        assert f.evidence_level == "suspicion"

    def test_cwe_is_optional(self):
        """A finding must never be rejected for lacking a CWE.

        Regression: cwe used to be a required positional, so a hunter
        omitting it got `missing 1 required positional argument: 'cwe'`
        and the finding was silently lost.
        """
        ctx = _ctx()
        result = _tool(ctx).handler(
            file="src/types.ts",
            line_number=10,
            finding_type="analysis_blocked",
            severity="low",
            description="suspect lifetime bug in HubMessage handler",
        )
        assert "Finding recorded" in result
        assert len(ctx.findings) == 1
        assert ctx.findings[0].cwe == ""

    def test_schema_does_not_require_cwe(self):
        ctx = _ctx()
        schema = _tool(ctx).schema
        assert "cwe" not in schema["required"]
        assert "cwe" in schema["properties"]

    def test_seeded_from_crash_flag(self):
        ctx = _ctx()
        ctx.seeded_crash = {"report": "asan"}
        _tool(ctx).handler(
            file="a.c",
            line_number=1,
            finding_type="memory_safety",
            severity="high",
            description="x",
        )
        assert ctx.findings[0].seeded_from_crash is True
