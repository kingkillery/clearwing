import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from clearwing.agent.tooling import interrupt, tool

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-zA-Z0-9_.:-]+$")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_RAPTOR_SAFE_MODES = frozenset({"scan", "codeql", "sca", "web", "doctor"})
_AMASS_BINARY = "amass"
_REAPER_BINARY = "reaper"


def _run_command(args: list[str], timeout_seconds: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        return {
            "status": "missing_binary",
            "exit_code": None,
            "command": shlex.join(args),
            "stdout": "",
            "stderr": str(exc),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout",
            "exit_code": None,
            "command": shlex.join(args),
            "stdout": _clean_process_output(exc.stdout),
            "stderr": _clean_process_output(exc.stderr) or f"timed out after {timeout_seconds} seconds",
        }

    return {
        "status": "ok" if completed.returncode == 0 else "error",
        "exit_code": completed.returncode,
        "command": shlex.join(args),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _clean_process_output(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output


def _validate_host_filter(host: str) -> str:
    value = host.strip().lower().rstrip(".")
    if value == "*":
        return value
    candidate = value.replace("*", "")
    if not candidate or not _HOST_RE.fullmatch(candidate) or "/" in candidate:
        raise ValueError(f"invalid host filter: {host!r}")
    return value


def _validate_domain(domain: str) -> str:
    value = domain.strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(value):
        raise ValueError(f"invalid domain: {domain!r}")
    return value


def _validate_host(host: str) -> str:
    value = host.strip().lower().rstrip(".")
    if not value or not _HOST_RE.fullmatch(value) or "/" in value:
        raise ValueError(f"invalid host: {host!r}")
    return value


def _validate_nonnegative_int(value: int, name: str) -> int:
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _parse_subdomain_lines(output: str, root_domain: str) -> list[str]:
    root = root_domain.lower()
    names: list[str] = []
    seen: set[str] = set()
    for raw_line in output.splitlines():
        line = _ANSI_RE.sub("", raw_line).strip()
        if not line or line.startswith("No names"):
            continue
        name = line.split()[0].strip().lower().rstrip(".")
        if (name == root or name.endswith(f".{root}")) and name not in seen:
            names.append(name)
            seen.add(name)
    return names


def _add_optional_file_arg(args: list[str], flag: str, value: str) -> None:
    if value:
        args.extend([flag, value])


def _approve_host_command(tool_name: str, args: list[str]) -> bool:
    approval = interrupt(
        f"Approve running local host CLI tool {tool_name}: {shlex.join(args)}?"
    )
    return bool(approval)


@tool
def amass_enum_domains(
    domain: str,
    active: bool = False,
    brute_force: bool = False,
    output_dir: str = "",
    timeout_minutes: int = 30,
) -> dict[str, Any]:
    """Run OWASP Amass enumeration for an authorized root domain.

    Passive enumeration is the default. Active probing and brute forcing request
    human approval before execution because they can generate target traffic.
    The tool returns raw command output plus parsed discovered names when Amass
    can read its result database through `amass subs`.
    """
    root = _validate_domain(domain)
    timeout = max(1, timeout_minutes)
    if active or brute_force:
        approval = interrupt(
            f"Approve Amass {'active ' if active else ''}{'brute-force ' if brute_force else ''}enumeration for {root}?"
        )
        if not approval:
            return {"status": "denied", "domain": root, "subdomains": []}

    enum_args = [_AMASS_BINARY, "enum", "-d", root, "-timeout", str(timeout)]
    if active:
        enum_args.append("-active")
    if brute_force:
        enum_args.append("-brute")
    _add_optional_file_arg(enum_args, "-dir", output_dir)
    if not _approve_host_command("amass_enum_domains", enum_args):
        return {"status": "denied", "domain": root, "subdomains": []}

    enum_result = _run_command(enum_args, timeout * 60 + 60)
    subs_result: dict[str, Any] | None = None
    subdomains: list[str] = []
    if enum_result["status"] == "ok":
        subs_args = [_AMASS_BINARY, "subs", "-d", root, "-names", "-nocolor"]
        _add_optional_file_arg(subs_args, "-dir", output_dir)
        subs_result = _run_command(subs_args, 120)
        if isinstance(subs_result.get("stdout"), str):
            subdomains = _parse_subdomain_lines(subs_result["stdout"], root)

    return {
        "status": enum_result["status"],
        "domain": root,
        "subdomains": subdomains,
        "enum": enum_result,
        "subs": subs_result,
    }


@tool
def amass_list_subdomains(
    domain: str,
    output_dir: str = "",
    include_ips: bool = False,
    limit: int = 500,
) -> dict[str, Any]:
    """Read discovered subdomains from an existing OWASP Amass result database."""
    root = _validate_domain(domain)
    max_items = _validate_nonnegative_int(limit, "limit")
    args = [_AMASS_BINARY, "subs", "-d", root, "-names", "-nocolor"]
    if include_ips:
        args.append("-ip")
    _add_optional_file_arg(args, "-dir", output_dir)
    if not _approve_host_command("amass_list_subdomains", args):
        return {"status": "denied", "domain": root, "subdomains": [], "result": None}

    result = _run_command(args, 120)
    subdomains = _parse_subdomain_lines(result.get("stdout", ""), root)[:max_items]
    return {"status": result["status"], "domain": root, "subdomains": subdomains, "result": result}


@tool
def reaper_start_proxy(
    domains: list[str] = None,
    hosts: list[str] = None,
    port: int = 8443,
    daemon: bool = True,
) -> dict[str, Any]:
    """Start Ghost Security Reaper as an in-scope HTTPS MITM proxy.

    Reaper intercepts HTTP(S) traffic and writes request/response logs locally.
    Starting the proxy always requires human approval because it changes traffic
    routing expectations for the operator/browser using the proxy.
    """
    scope_domains = [_validate_domain(d) for d in domains or []]
    scope_hosts = [_validate_host(h) for h in hosts or []]
    if not scope_domains and not scope_hosts:
        raise ValueError("at least one domain or host is required")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    approval = interrupt(
        f"Approve starting Reaper MITM proxy on port {port} for domains={scope_domains} hosts={scope_hosts}?"
    )
    if not approval:
        return {"status": "denied", "domains": scope_domains, "hosts": scope_hosts, "port": port}

    args = [_REAPER_BINARY, "start", "--port", str(port)]
    if daemon:
        args.append("--daemon")
    if scope_domains:
        args.extend(["--domains", ",".join(scope_domains)])
    if scope_hosts:
        args.extend(["--hosts", ",".join(scope_hosts)])
    result = _run_command(args, 60)
    return {"status": result["status"], "domains": scope_domains, "hosts": scope_hosts, "port": port, "result": result}


@tool
def reaper_search_logs(
    method: str = "",
    host: str = "",
    domains: list[str] = None,
    path: str = "",
    status: int = 0,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Ghost Security Reaper proxy logs captured by a running daemon."""
    if status and not 100 <= status <= 599:
        raise ValueError("status must be an HTTP status code")
    max_items = _validate_nonnegative_int(limit, "limit")
    scope_domains = [_validate_domain(d) for d in domains or []]
    args = [_REAPER_BINARY, "search", "--limit", str(max_items)]
    if method:
        args.extend(["--method", method.upper()])
    if host:
        args.extend(["--host", _validate_host_filter(host)])
    if scope_domains:
        args.extend(["--domains", ",".join(scope_domains)])
    if path:
        args.extend(["--path", path])
    if status:
        args.extend(["--status", str(status)])
    if not _approve_host_command("reaper_search_logs", args):
        return {"status": "denied", "result": None}
    result = _run_command(args, 30)
    return {"status": result["status"], "result": result}


@tool
def reaper_get_entry(entry_id: int, part: str = "full") -> dict[str, Any]:
    """Fetch one Ghost Security Reaper log entry as full exchange, request, or response."""
    if entry_id < 1:
        raise ValueError("entry_id must be positive")
    command_by_part = {"full": "get", "request": "req", "response": "res"}
    command = command_by_part.get(part)
    if command is None:
        raise ValueError("part must be one of: full, request, response")
    args = [_REAPER_BINARY, command, str(entry_id)]
    if not _approve_host_command("reaper_get_entry", args):
        return {"status": "denied", "entry_id": entry_id, "part": part, "result": None}
    result = _run_command(args, 30)
    return {"status": result["status"], "entry_id": entry_id, "part": part, "result": result}


@tool
def reaper_stop_proxy() -> dict[str, Any]:
    """Stop a running Ghost Security Reaper daemon."""
    args = [_REAPER_BINARY, "stop"]
    if not _approve_host_command("reaper_stop_proxy", args):
        return {"status": "denied", "result": None}
    result = _run_command(args, 30)
    return {"status": result["status"], "result": result}


def _raptor_command() -> list[str]:
    configured = os.environ.get("RAPTOR_PATH", "raptor.py")
    path = Path(configured)
    if path.exists() and path.suffix == ".py":
        return [sys.executable, str(path)]
    resolved = shutil.which(configured)
    if resolved and resolved.endswith(".py"):
        return [sys.executable, resolved]
    return [resolved or configured]


@tool
def raptor_scan_code(
    repo_path: str,
    mode: str = "scan",
    output_dir: str = "",
    policy_groups: str = "",
    no_llm: bool = True,
    timeout_seconds: int = 3600,
) -> dict[str, Any]:
    """Run a safe RAPTOR code-security workflow against a local repo path.

    Supported modes are scan, codeql, sca, web, and doctor. RAPTOR scan and
    codeql modes are scan-only; SCA receives --no-llm by default.
    """
    selected_mode = mode.strip().lower()
    if selected_mode not in _RAPTOR_SAFE_MODES:
        raise ValueError(f"unsupported RAPTOR mode: {mode!r}")
    target = Path(repo_path).expanduser()
    if selected_mode != "web" and not target.exists():
        raise ValueError(f"repo_path does not exist: {repo_path}")
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive")

    args = _raptor_command() + [selected_mode]
    if selected_mode == "doctor":
        pass
    elif selected_mode == "web":
        args.extend(["--url", repo_path])
    else:
        args.extend(["--repo", str(target)])
    if output_dir:
        args.extend(["--out", output_dir])
    if selected_mode == "scan" and policy_groups:
        args.extend(["--policy-groups", policy_groups])
    if no_llm and selected_mode in {"scan", "sca"}:
        args.append("--no-llm")
    if not _approve_host_command("raptor_scan_code", args):
        return {"status": "denied", "mode": selected_mode, "target": repo_path, "result": None}

    result = _run_command(args, timeout_seconds)
    return {"status": result["status"], "mode": selected_mode, "target": repo_path, "result": result}


@tool
def raptor_doctor() -> dict[str, Any]:
    """Run RAPTOR's setup doctor/status command."""
    args = _raptor_command() + ["doctor"]
    if not _approve_host_command("raptor_doctor", args):
        return {"status": "denied", "result": None}
    result = _run_command(args, 120)
    return {"status": result["status"], "result": result}


def get_external_cli_tools() -> list[Any]:
    return [
        amass_enum_domains,
        amass_list_subdomains,
        reaper_start_proxy,
        reaper_search_logs,
        reaper_get_entry,
        reaper_stop_proxy,
        raptor_scan_code,
        raptor_doctor,
    ]
