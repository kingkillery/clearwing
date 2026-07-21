"""Sourcehunt fuzz stage — OSS-Fuzz-backed crash-first seeding (spec 018 v2).

An upgrade path for the stage-2.5 Harness Generator: instead of one-shot
harness compiles in the hunter sandbox, this stage

    1. selects eligible parser/fuzzable C/C++ files (same criteria as the
       legacy generator),
    2. synthesizes a harness per file with the OSS-Fuzz-Gen repair loop
       (``ossfuzz.synthesize.HarnessSynthesizer`` — build errors are fed
       back to the LLM until the harness compiles),
    3. fuzzes each accepted harness with real libFuzzer budgets via
       ``ossfuzz.runner.FuzzRunner``,
    4. emits SeededCrash records (so hunters for fuzzed files get the
       "explain this crash" prompt) AND canonical Findings at
       ``crash_reproduced`` (so the exploit triage gate unlocks).

Fail-open like every pipeline stage: any subsystem failure logs and
returns what it has; the pipeline proceeds with zero seeded crashes in
the worst case. Never touches the host checkout — harnesses are injected
into the build container (``OssFuzzBuilder.build(extra_files=...)``).

Sync by design (docker + LLM calls are blocking); the runner invokes it
via ``asyncio.to_thread``.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clearwing.findings.types import Finding
from clearwing.ossfuzz.bridge import fuzz_run_to_findings
from clearwing.ossfuzz.builder import BuildConfig, OssFuzzBuilder
from clearwing.ossfuzz.project import OssFuzzProject
from clearwing.ossfuzz.runner import FuzzConfig, FuzzRunner
from clearwing.ossfuzz.synthesize import HarnessSynthesizer

from .harness_generator import SeededCrash
from .state import FileTarget

logger = logging.getLogger(__name__)


@dataclass
class FuzzStageConfig:
    """Budget and selection knobs for the fuzz stage."""

    max_harnesses: int = 5  # synthesis is build-heavy; keep the cap low
    repair_rounds: int = 4  # OSS-Fuzz-Gen-style generate→build→repair rounds
    fuzz_seconds: int = 60  # per-fuzzer libFuzzer budget
    sanitizer: str = "address"
    min_surface: int = 4
    required_tags: tuple = ("parser", "fuzzable")
    languages: tuple = ("c", "cpp")
    total_time_budget_seconds: int = 3600
    image: str | None = None  # override base-builder image


@dataclass
class FuzzStageResult:
    """What the stage produced. Both channels flow downstream."""

    seeded_crashes: list[SeededCrash] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    harnesses_attempted: int = 0
    harnesses_succeeded: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


def run_fuzz_stage(
    file_targets: list[FileTarget],
    repo_path: str,
    llm: Any,
    *,
    config: FuzzStageConfig | None = None,
    work_dir: str | Path,
    project_name: str | None = None,
    session_id: str = "",
) -> FuzzStageResult:
    """Run the fuzz stage over ranked file targets.

    Args:
        file_targets: ranked FileTarget list from the preprocessor/ranker.
        repo_path: host checkout of the target repo (mounted read-only).
        llm: client for harness synthesis (``aask_text`` interface).
        config: stage knobs.
        work_dir: scratch area for the triple, $OUT dirs, and crashes.
        project_name: OSS-Fuzz project name (default: sanitized repo dir
            basename).
        session_id: stamped onto findings for session tracking.

    Returns:
        FuzzStageResult; never raises for per-file/subsystem failures.
    """
    start = time.monotonic()
    cfg = config or FuzzStageConfig()
    result = FuzzStageResult()

    eligible = _select_eligible(file_targets, cfg)[: cfg.max_harnesses]
    if not eligible:
        logger.info("Fuzz stage: no eligible files")
        return result

    name = project_name or _sanitize_name(Path(repo_path).name or "target")
    language = "cpp" if any(ft.get("language") == "cpp" for ft in eligible) else "c"
    try:
        project = OssFuzzProject(name=name, language=language)
    except ValueError as exc:
        result.errors.append(f"invalid project name {name!r}: {exc}")
        return result

    work = Path(work_dir)
    triple_dir = work / "triple"
    out_dir = work / "out"
    crashes_dir = work / "crashes"
    for d in (triple_dir, out_dir, crashes_dir):
        d.mkdir(parents=True, exist_ok=True)

    builder = OssFuzzBuilder(BuildConfig(sanitizer=cfg.sanitizer, image=cfg.image))
    synthesizer = HarnessSynthesizer(llm, builder, max_rounds=cfg.repair_rounds)
    runner = FuzzRunner(
        FuzzConfig(
            image=cfg.image,
            crashes_dir=str(crashes_dir),
            max_total_time_seconds=cfg.fuzz_seconds,
        )
    )
    deadline = start + cfg.total_time_budget_seconds

    for ft in eligible:
        if time.monotonic() > deadline:
            logger.info("Fuzz stage: total time budget exceeded")
            break
        outcome = _fuzz_one_file(
            ft, project, repo_path, synthesizer, runner,
            triple_dir=triple_dir, out_dir=out_dir, session_id=session_id,
        )
        result.errors.extend(outcome.errors)
        if outcome.attempted:
            result.harnesses_attempted += 1
        if outcome.succeeded:
            result.harnesses_succeeded += 1
        result.crashes += outcome.crashes
        result.unique_crashes += outcome.unique_crashes
        result.seeded_crashes.extend(outcome.seeded_crashes)
        result.findings.extend(outcome.findings)

    result.duration_seconds = time.monotonic() - start
    logger.info(
        "Fuzz stage: %d/%d harnesses compiled, %d crashes (%d unique), "
        "%d findings in %.0fs",
        result.harnesses_succeeded,
        result.harnesses_attempted,
        result.crashes,
        result.unique_crashes,
        len(result.findings),
        result.duration_seconds,
    )
    return result



@dataclass
class _FileOutcome:
    """Per-file processing result for aggregation into FuzzStageResult."""

    attempted: bool = False
    succeeded: bool = False
    crashes: int = 0
    unique_crashes: int = 0
    seeded_crashes: list[SeededCrash] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _fuzz_one_file(
    ft: FileTarget,
    project: OssFuzzProject,
    repo_path: str,
    synthesizer: HarnessSynthesizer,
    runner: FuzzRunner,
    *,
    triple_dir: Path,
    out_dir: Path,
    session_id: str,
) -> _FileOutcome:
    """Synthesize → build → fuzz one file. Fail-open per step."""
    outcome = _FileOutcome()
    target_file = ft.get("path", "")
    abs_path = ft.get("absolute_path", "")
    if not target_file or not abs_path or not Path(abs_path).is_file():
        return outcome

    outcome.attempted = True
    try:
        file_source = Path(abs_path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        outcome.errors.append(f"{target_file}: unreadable: {exc}")
        return outcome

    harness_name = _harness_name(target_file)
    try:
        synthesis = synthesizer.synthesize(
            project,
            triple_dir,
            repo_path,
            out_dir,
            target_file=target_file,
            file_source=file_source,
            harness_name=harness_name,
        )
    except Exception as exc:
        logger.warning("Synthesis failed for %s", target_file, exc_info=True)
        outcome.errors.append(f"{target_file}: synthesis error: {exc}")
        return outcome

    if not synthesis.success:
        logger.info(
            "Fuzz stage: no compiling harness for %s after %d rounds",
            target_file, synthesis.rounds,
        )
        return outcome
    outcome.succeeded = True

    try:
        fuzz_result = runner.fuzz(out_dir, synthesis.fuzzer_name)
    except Exception as exc:
        logger.warning("Fuzzing failed for %s", harness_name, exc_info=True)
        outcome.errors.append(f"{target_file}: fuzz error: {exc}")
        return outcome
    if not fuzz_result.success:
        outcome.errors.append(f"{target_file}: {fuzz_result.error}")
        return outcome

    outcome.crashes = len(fuzz_result.crashes)
    outcome.unique_crashes = fuzz_result.unique_crash_count

    # Channel 1: seeded crashes keyed by the FUZZED FILE's path — the
    # runner's seeded_by_file lookup hands these to the file's hunter.
    for crash in fuzz_result.crashes:
        if not crash.is_new:
            continue
        frame = crash.report.top_project_frame
        primary = ft.get("primary_function") or ""
        outcome.seeded_crashes.append(
            SeededCrash(
                file=target_file,
                target_function=str(primary) or (frame.function if frame else ""),
                report=crash.report.raw[:6000],
                harness_source=synthesis.harness_source,
                crashed=True,
                duration_seconds=fuzz_result.duration_seconds,
            )
        )

    # Channel 2: canonical findings at crash_reproduced. Fall back to
    # the fuzzed file when the crash frames don't resolve to a path.
    for finding in fuzz_run_to_findings(
        fuzz_result, project_name=project.name, session_id=session_id,
    ):
        if not finding.file:
            finding.file = target_file
        finding.extra["fuzz_stage_harness"] = harness_name
        outcome.findings.append(finding)

    return outcome
# --- Selection (mirrors HarnessGenerator._select_eligible) -------------------


def _select_eligible(
    file_targets: list[FileTarget], cfg: FuzzStageConfig
) -> list[FileTarget]:
    """High-surface parser/fuzzable C/C++ files, priority-ordered."""
    required = set(cfg.required_tags)
    out = []
    for ft in file_targets:
        if ft.get("surface", 0) < cfg.min_surface:
            continue
        if not (set(ft.get("tags", [])) & required):
            continue
        if ft.get("language") not in cfg.languages:
            continue
        out.append(ft)
    out.sort(key=lambda f: -f.get("priority", 0.0))
    return out


def _harness_name(target_file: str) -> str:
    """Unique harness name from the full repo-relative path.

    Same-stem files (``src/parser.c`` vs ``vendor/parser.c``) must not
    collide: the name keys the $OUT binary and the per-fuzzer crash dir,
    so a short path hash suffix guarantees uniqueness while the readable
    prefix keeps logs/provenance legible.
    """
    digest = hashlib.sha256(target_file.replace("\\", "/").encode("utf-8")).hexdigest()[:8]
    readable = _sanitize_name(target_file.replace("\\", "/").replace("/", "-"))
    return f"fuzz_{readable[-48:]}-{digest}"


_NAME_SANITIZE = re.compile(r"[^a-z0-9_-]+")


def _sanitize_name(raw: str) -> str:
    """Coerce a string into a valid OSS-Fuzz project name."""
    name = _NAME_SANITIZE.sub("-", raw.lower()).strip("-")
    if not name or not name[0].isalnum():
        name = f"p-{name}"
    return name or "target"
