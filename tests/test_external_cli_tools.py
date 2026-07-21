from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from clearwing.agent.tools.recon.external_cli_tools import (
    amass_enum_domains,
    amass_list_subdomains,
    get_external_cli_tools,
    raptor_doctor,
    raptor_scan_code,
    reaper_get_entry,
    reaper_search_logs,
    reaper_start_proxy,
)


def _completed(args: list[str], stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr="")


def test_get_external_cli_tools_returns_expected_tools():
    names = {t.name for t in get_external_cli_tools()}
    assert names == {
        "amass_enum_domains",
        "amass_list_subdomains",
        "reaper_start_proxy",
        "reaper_search_logs",
        "reaper_get_entry",
        "reaper_stop_proxy",
        "raptor_scan_code",
        "raptor_doctor",
    }


def test_external_cli_tool_schema_uses_runtime_annotation_types():
    schema = reaper_start_proxy.input_schema["properties"]
    assert schema["domains"] == {"type": "array", "items": {"type": "string"}}
    assert schema["hosts"] == {"type": "array", "items": {"type": "string"}}
    assert schema["port"] == {"type": "integer"}
    assert schema["daemon"] == {"type": "boolean"}
    assert "binary" not in schema

    raptor_schema = raptor_scan_code.input_schema["properties"]
    assert raptor_schema["timeout_seconds"] == {"type": "integer"}
    assert raptor_schema["no_llm"] == {"type": "boolean"}
    assert "raptor_path" not in raptor_schema


def test_amass_enum_runs_enum_then_reads_subdomains():
    with patch("clearwing.agent.tools.recon.external_cli_tools.interrupt", return_value=True), patch(
        "clearwing.agent.tools.recon.external_cli_tools.subprocess.run"
    ) as run:
        run.side_effect = [
            _completed(["amass", "enum"], ""),
            _completed(["amass", "subs"], "www.example.com\napi.example.com 192.0.2.1\n"),
        ]

        result = amass_enum_domains.invoke({"domain": "Example.com", "timeout_minutes": 1})

    assert result["status"] == "ok"
    assert result["subdomains"] == ["www.example.com", "api.example.com"]
    assert run.call_args_list[0].args[0] == ["amass", "enum", "-d", "example.com", "-timeout", "1"]
    assert run.call_args_list[1].args[0] == ["amass", "subs", "-d", "example.com", "-names", "-nocolor"]


def test_amass_list_subdomains_limits_parsed_names():
    with patch("clearwing.agent.tools.recon.external_cli_tools.interrupt", return_value=True), patch(
        "clearwing.agent.tools.recon.external_cli_tools.subprocess.run"
    ) as run:
        run.return_value = _completed(
            ["amass", "subs"],
            "one.example.com\ntwo.example.com\nignored.other.net\n",
        )

        result = amass_list_subdomains.invoke({"domain": "example.com", "limit": 1})

    assert result["subdomains"] == ["one.example.com"]


def test_amass_list_subdomains_normalizes_timeout_bytes():
    with patch("clearwing.agent.tools.recon.external_cli_tools.interrupt", return_value=True), patch(
        "clearwing.agent.tools.recon.external_cli_tools.subprocess.run"
    ) as run:
        run.side_effect = subprocess.TimeoutExpired(
            ["amass", "subs"],
            timeout=120,
            output=b"partial.example.com\n",
            stderr=b"still running",
        )

        result = amass_list_subdomains.invoke({"domain": "example.com"})

    assert result["status"] == "timeout"
    assert result["result"]["stdout"] == "partial.example.com\n"
    assert result["result"]["stderr"] == "still running"


def test_reaper_start_requires_scope_and_builds_daemon_command():
    with patch("clearwing.agent.tools.recon.external_cli_tools.interrupt", return_value=True), patch(
        "clearwing.agent.tools.recon.external_cli_tools.subprocess.run"
    ) as run:
        run.return_value = _completed(["reaper", "start"], "reaper daemon started\n")

        result = reaper_start_proxy.invoke(
            {"domains": ["example.com"], "hosts": ["api.example.com"], "port": 9443}
        )

    assert result["status"] == "ok"
    assert run.call_args.args[0] == [
        "reaper",
        "start",
        "--port",
        "9443",
        "--daemon",
        "--domains",
        "example.com",
        "--hosts",
        "api.example.com",
    ]


def test_reaper_search_accepts_wildcard_host_filter():
    with patch("clearwing.agent.tools.recon.external_cli_tools.interrupt", return_value=True), patch(
        "clearwing.agent.tools.recon.external_cli_tools.subprocess.run"
    ) as run:
        run.return_value = _completed(["reaper", "search"], "")

        reaper_search_logs.invoke({"host": "*.example.com", "limit": 5})

    assert run.call_args.args[0] == ["reaper", "search", "--limit", "5", "--host", "*.example.com"]


def test_reaper_get_entry_selects_request_command():
    with patch("clearwing.agent.tools.recon.external_cli_tools.interrupt", return_value=True), patch(
        "clearwing.agent.tools.recon.external_cli_tools.subprocess.run"
    ) as run:
        run.return_value = _completed(["reaper", "req", "7"], "GET / HTTP/1.1\n")

        result = reaper_get_entry.invoke({"entry_id": 7, "part": "request"})

    assert result["status"] == "ok"
    assert run.call_args.args[0] == ["reaper", "req", "7"]


def test_raptor_scan_code_uses_python_for_script_path(tmp_path):
    raptor = tmp_path / "raptor.py"
    raptor.write_text("", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch.dict("os.environ", {"RAPTOR_PATH": str(raptor)}), patch(
        "clearwing.agent.tools.recon.external_cli_tools.interrupt", return_value=True
    ), patch("clearwing.agent.tools.recon.external_cli_tools.subprocess.run") as run:
        run.return_value = _completed(["python", "raptor.py"], "")

        result = raptor_scan_code.invoke(
            {
                "repo_path": str(repo),
                "mode": "scan",
                "policy_groups": "secrets,owasp",
            }
        )

    assert result["status"] == "ok"
    command = run.call_args.args[0]
    assert command[0]
    assert command[1:] == [
        str(raptor),
        "scan",
        "--repo",
        str(repo),
        "--policy-groups",
        "secrets,owasp",
        "--no-llm",
    ]


def test_raptor_scan_code_rejects_unsafe_mode(tmp_path):
    with pytest.raises(ValueError, match="unsupported RAPTOR mode"):
        raptor_scan_code.invoke({"repo_path": str(tmp_path), "mode": "agentic"})


def test_raptor_doctor_runs_doctor_mode():
    with patch("clearwing.agent.tools.recon.external_cli_tools.interrupt", return_value=True), patch(
        "clearwing.agent.tools.recon.external_cli_tools.subprocess.run"
    ) as run:
        run.return_value = _completed(["raptor.py", "doctor"], "ok\n")

        result = raptor_doctor.invoke({})

    assert result["status"] == "ok"
    assert run.call_args.args[0] == ["raptor.py", "doctor"]
