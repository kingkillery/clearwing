"""Crash parsing, ClusterFuzz-style signature dedup, and Finding conversion.

Raw sanitizer output is noisy — addresses, PIDs, and allocation contexts
change run to run. ``crash_signature`` normalizes a report to the triple
ClusterFuzz dedups on: sanitizer + crash type + top-N normalized stack
frames. That gives Clearwing cheap deterministic dedup *before* the
findings pool's LLM clustering, and a stable identity for patch validation
("the crash with THIS signature is gone").

``crash_to_finding`` lifts a crash onto the canonical evidence ladder at
``crash_reproduced`` — the gate the exploiter stage requires.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field

from clearwing.findings.types import Finding, Severity

logger = logging.getLogger(__name__)

# --- Parsing ------------------------------------------------------------------

_SANITIZER_HEADER = re.compile(
    r"==\d+==\s*ERROR:\s*(AddressSanitizer|UndefinedBehaviorSanitizer|"
    r"MemorySanitizer|ThreadSanitizer|LeakSanitizer|libFuzzer)",
)

# ASan: "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
_ASAN_TYPE = re.compile(
    r"AddressSanitizer:\s*([a-zA-Z-]+(?:overflow|free|use-after-[\w-]+|"
    r"double-free|wild-[\w-]+|alloc-dealloc-mismatch|"
    r"stack-overflow|SEGV)[a-zA-Z-]*)",
)
# UBSan: "runtime error: signed integer overflow: ..."
_UBSAN_TYPE = re.compile(r"runtime error:\s*([^:\n]+)")
# libFuzzer: "ERROR: libFuzzer: deadly signal" / "timeout after ..."
_LIBFUZZER_TYPE = re.compile(r"libFuzzer:\s*([a-zA-Z0-9 _-]+?)(?:\s*$|\n)", re.MULTILINE)

# Stack frames:
#   "    #1 0x55f3a2 in parse_header /src/proj/src/parse.c:217:9"
#   "    #2 0x... in foo /src/proj/lib/a.cc:10"
_FRAME = re.compile(
    r"^\s*#\d+\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(\S+)\s+(\S+?)(?::(\d+))?(?::(\d+))?\s*$",
    re.MULTILINE,
)

_HEX_ADDR = re.compile(r"0x[0-9a-fA-F]+")


@dataclass
class StackFrame:
    function: str
    location: str  # path, possibly with :line
    line: int | None = None


@dataclass
class ParsedCrash:
    """Structured view of one sanitizer/fuzzer report."""

    sanitizer: str = ""  # "address" | "undefined" | "memory" | "libfuzzer" | ""
    crash_type: str = ""  # "heap-buffer-overflow" | "deadly signal" | ...
    summary_line: str = ""
    frames: list[StackFrame] = field(default_factory=list)
    raw: str = ""

    @property
    def top_project_frame(self) -> StackFrame | None:
        """First frame pointing into /src/ (the target's own code)."""
        for f in self.frames:
            if "/src/" in f.location:
                return f
        return self.frames[0] if self.frames else None


def parse_sanitizer_report(raw: str) -> ParsedCrash:
    """Parse ASan/UBSan/MSan/libFuzzer output into a ParsedCrash."""
    crash = ParsedCrash(raw=raw)
    if not raw:
        return crash

    m = _SANITIZER_HEADER.search(raw)
    if m:
        kind = m.group(1)
        crash.sanitizer = {
            "AddressSanitizer": "address",
            "UndefinedBehaviorSanitizer": "undefined",
            "MemorySanitizer": "memory",
            "ThreadSanitizer": "thread",
            "LeakSanitizer": "leak",
            "libFuzzer": "libfuzzer",
        }.get(kind, kind)
        crash.summary_line = m.group(0)

    type_m = _ASAN_TYPE.search(raw)
    if type_m:
        crash.crash_type = type_m.group(1)
    else:
        ubsan_m = _UBSAN_TYPE.search(raw)
        if ubsan_m:
            crash.crash_type = ubsan_m.group(1).strip()
        else:
            lf_m = _LIBFUZZER_TYPE.search(raw)
            if lf_m:
                crash.crash_type = lf_m.group(1).strip()

    for fm in _FRAME.finditer(raw):
        func, location, line, _col = fm.group(1), fm.group(2), fm.group(3), fm.group(4)
        crash.frames.append(
            StackFrame(
                function=func,
                location=location,
                line=int(line) if line else None,
            )
        )
    return crash


# --- Signatures & dedup ---------------------------------------------------------


def _normalize_frame(frame: StackFrame) -> str:
    """Strip run-specific noise (addresses, /src/<proj>/ prefix) from a frame."""
    func = _HEX_ADDR.sub("0x", frame.function)
    location = _HEX_ADDR.sub("0x", frame.location)
    # /src/<project>/ paths are container-specific; keep the path tail
    if "/src/" in location:
        parts = location.split("/src/", 1)[1].split("/", 1)
        location = parts[1] if len(parts) == 2 else parts[0]
    return f"{func}@{location}"


def crash_signature(crash: ParsedCrash, depth: int = 3) -> str:
    """Stable signature: sanitizer | crash_type | top-N normalized frames.

    Two reports with the same signature are the same bug for dedup and
    patch-validation purposes.
    """
    frames = "|".join(_normalize_frame(f) for f in crash.frames[:depth])
    basis = f"{crash.sanitizer}|{crash.crash_type}|{frames}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]


class CrashDeduplicator:
    """Set-backed signature dedup. Cheap, deterministic, pre-LLM."""

    def __init__(self, depth: int = 3):
        self._depth = depth
        self._seen: dict[str, ParsedCrash] = {}

    def add(self, crash: ParsedCrash) -> tuple[bool, str]:
        """Register a crash. Returns (is_new, signature)."""
        sig = crash_signature(crash, depth=self._depth)
        if sig in self._seen:
            return False, sig
        self._seen[sig] = crash
        return True, sig

    def __len__(self) -> int:
        return len(self._seen)

    @property
    def signatures(self) -> list[str]:
        return sorted(self._seen)


# --- Finding conversion ---------------------------------------------------------

# Sanitizer crash type → CWE. Mirrors the pool's _CWE_PRIMITIVE_MAP values
# so downstream primitive classification stays consistent.
CRASH_TYPE_CWE: dict[str, str] = {
    "heap-buffer-overflow": "CWE-787",
    "stack-buffer-overflow": "CWE-121",
    "global-buffer-overflow": "CWE-787",
    "heap-use-after-free": "CWE-416",
    "stack-use-after-return": "CWE-416",
    "double-free": "CWE-415",
    "alloc-dealloc-mismatch": "CWE-762",
    "use-after-poison": "CWE-416",
    "stack-overflow": "CWE-674",
    "SEGV": "CWE-476",
    "signed-integer-overflow": "CWE-190",
    "unsigned-integer-overflow": "CWE-191",
    "shift-exponent": "CWE-682",
    "division-by-zero": "CWE-369",
    "null-dereference": "CWE-476",
    "uninitialized-value": "CWE-457",
    "data-race": "CWE-362",
    "deadly signal": "CWE-476",
    "timeout": "CWE-400",
    "out-of-memory": "CWE-400",
}

# Severity heuristics by crash class. Memory-corruption writes/UAF start
# high; reads/UB start medium; resource exhaustion low. The verifier and
# exploiter stages can only move these up with more evidence.
_CRASH_TYPE_SEVERITY: dict[str, Severity] = {
    "heap-buffer-overflow": "high",
    "stack-buffer-overflow": "high",
    "global-buffer-overflow": "high",
    "heap-use-after-free": "high",
    "stack-use-after-return": "high",
    "double-free": "high",
    "alloc-dealloc-mismatch": "medium",
    "use-after-poison": "medium",
    "stack-overflow": "medium",
    "SEGV": "medium",
    "signed-integer-overflow": "medium",
    "division-by-zero": "low",
    "null-dereference": "medium",
    "uninitialized-value": "medium",
    "data-race": "medium",
    "deadly signal": "medium",
    "timeout": "low",
    "out-of-memory": "low",
}


def _normalized_type(crash: ParsedCrash) -> str:
    """Normalize free-text crash types (UBSan uses spaces; ASan hyphens)."""
    return crash.crash_type.lower().replace(" ", "-").strip()


def severity_for_crash(crash: ParsedCrash) -> Severity:
    """Map a parsed crash to a starting severity."""
    norm = _normalized_type(crash)
    if norm in _CRASH_TYPE_SEVERITY:
        return _CRASH_TYPE_SEVERITY[norm]
    if crash.crash_type in _CRASH_TYPE_SEVERITY:
        return _CRASH_TYPE_SEVERITY[crash.crash_type]
    # Substring fallback for UBSan free-text types
    for key, sev in _CRASH_TYPE_SEVERITY.items():
        if key in norm or key in crash.crash_type:
            return sev
    return "medium" if crash.crash_type else "low"


def cwe_for_crash(crash: ParsedCrash) -> str:
    """Map a parsed crash to a CWE id (empty string when unknown)."""
    norm = _normalized_type(crash)
    if norm in CRASH_TYPE_CWE:
        return CRASH_TYPE_CWE[norm]
    if crash.crash_type in CRASH_TYPE_CWE:
        return CRASH_TYPE_CWE[crash.crash_type]
    for key, cwe in CRASH_TYPE_CWE.items():
        if key in norm or key in crash.crash_type:
            return cwe
    return ""


def repo_relative_location(frame: StackFrame, project_name: str = "") -> str:
    """Convert a container frame location to a repo-relative path."""
    location = frame.location
    if "/src/" in location:
        tail = location.split("/src/", 1)[1]
        if project_name and tail.startswith(f"{project_name}/"):
            tail = tail[len(project_name) + 1 :]
        elif "/" in tail:
            tail = tail.split("/", 1)[1]
        location = tail
    if frame.line:
        return location
    return location


def crash_to_finding(
    crash: ParsedCrash,
    *,
    project_name: str,
    fuzzer_name: str = "",
    poc_path: str = "",
    signature: str = "",
    session_id: str = "",
) -> Finding:
    """Lift a parsed crash to a canonical Finding at crash_reproduced.

    The finding enters the pipeline at the evidence level the exploiter
    stage gates on, with the sanitizer report as crash_evidence and the
    top in-project frame as file/line when parseable.
    """
    frame = crash.top_project_frame
    file_path: str | None = None
    line_number: int | None = None
    if frame is not None:
        file_path = repo_relative_location(frame, project_name)
        line_number = frame.line

    crash_type = crash.crash_type or "unknown crash"
    description = (
        f"{crash_type}"
        + (f" in {frame.function}" if frame else "")
        + (f" ({file_path}:{line_number})" if file_path and line_number else "")
        + f" — reproduced by fuzzer {fuzzer_name or 'unknown'}"
    )

    sig = signature or crash_signature(crash)
    finding = Finding(
        finding_type="fuzz_crash",
        file=file_path,
        line_number=line_number,
        severity=severity_for_crash(crash),
        description=description,
        crash_evidence=crash.raw[:8000],
        poc=poc_path or None,
        cwe=cwe_for_crash(crash),
        discovered_by="ossfuzz_runner",
        evidence_level="crash_reproduced",
        seeded_from_crash=True,
        hunter_session_id=session_id,
    )
    finding.extra["crash_signature"] = sig
    finding.extra["sanitizer"] = crash.sanitizer
    finding.extra["crash_type"] = crash.crash_type
    if fuzzer_name:
        finding.extra["fuzzer"] = fuzzer_name
    return finding
