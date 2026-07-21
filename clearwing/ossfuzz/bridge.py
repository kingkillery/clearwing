"""Adapters from OSS-Fuzz run artifacts into sourcehunt pipeline shapes.

Two bridges:

- ``fuzz_run_to_findings`` — crashes become canonical ``Finding`` objects at
  ``crash_reproduced``, ready for the shared findings pool, the adversarial
  verifier (which can steel-man a concrete sanitizer report far better than
  a suspicion), and the exploit-triage gate.

- ``fuzz_run_to_seeded_crashes`` — crashes become dicts shaped like
  ``sourcehunt.harness_generator.SeededCrash``, so hunter agents for the
  affected files get the "explain this crash" prompt instead of
  cold-reading — the same mechanism the deep-depth HarnessGenerator uses,
  now fed by real fuzzing instead of one-shot harness compiles.
"""

from __future__ import annotations

import logging
from typing import Any

from clearwing.findings.types import Finding

from .crashes import crash_to_finding
from .runner import FuzzRunResult

logger = logging.getLogger(__name__)


def fuzz_run_to_findings(
    result: FuzzRunResult,
    *,
    project_name: str,
    session_id: str = "",
    include_duplicates: bool = False,
) -> list[Finding]:
    """Convert a fuzz run's crashes into canonical Findings.

    Only signature-unique crashes are converted by default — duplicates
    would just spend verifier budget on the same bug.
    """
    findings: list[Finding] = []
    for crash in result.crashes:
        if not include_duplicates and not crash.is_new:
            continue
        findings.append(
            crash_to_finding(
                crash.report,
                project_name=project_name,
                fuzzer_name=crash.fuzzer_name,
                poc_path=crash.input_path,
                signature=crash.signature,
                session_id=session_id,
            )
        )
    logger.info(
        "ossfuzz bridge: %d unique findings from %d crashes (fuzzer=%s)",
        len(findings),
        len(result.crashes),
        result.fuzzer_name,
    )
    return findings


def fuzz_run_to_seeded_crashes(
    result: FuzzRunResult,
    *,
    project_name: str,
) -> list[dict[str, Any]]:
    """Convert crashes into SeededCrash-shaped dicts for hunter seeding.

    The dict shape matches ``sourcehunt.harness_generator.SeededCrash``
    field-for-field (that type is a dataclass; hunters consume the fields,
    not the class, so dicts are interchangeable at the consumer boundary).
    """
    seeds: list[dict[str, Any]] = []
    for crash in result.crashes:
        if not crash.is_new:
            continue
        frame = crash.report.top_project_frame
        file_path = ""
        if frame is not None:
            location = frame.location
            if "/src/" in location:
                tail = location.split("/src/", 1)[1]
                if tail.startswith(f"{project_name}/"):
                    tail = tail[len(project_name) + 1 :]
                elif "/" in tail:
                    tail = tail.split("/", 1)[1]
                location = tail
            file_path = location
        seeds.append(
            {
                "file": file_path,
                "target_function": frame.function if frame else "",
                "report": crash.report.raw[:6000],
                "minimized_input": b"",  # libFuzzer artifacts are pre-minimized
                "harness_source": "",
                "crashed": True,
                "duration_seconds": 0.0,
                "crash_signature": crash.signature,
                "poc_path": crash.input_path,
                "fuzzer": crash.fuzzer_name,
            }
        )
    return seeds
