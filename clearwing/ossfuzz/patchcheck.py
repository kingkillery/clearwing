"""Buttercup-style patch validation for OSS-Fuzz targets.

The load-bearing loop, adapted from Trail of Bits' Buttercup patch
validation to Clearwing's substrate:

    1. REPRODUCE — replay the crash input against the unpatched build;
       the original signature must appear (otherwise we can't prove
       anything about the patch).
    2. PATCH     — apply the candidate diff inside the build container's
       staged source copy (host checkout is never touched).
    3. REBUILD   — same build.sh, same sanitizer.
    4. CONFIRM   — replay the same input; the crash is gone → validated.

Fail-closed like ``clearwing.sourcehunt.poc_runner``: any error along the
way counts as *not validated*, never as success. A NEW crash signature
after patching is reported separately — the patch may have moved the bug.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from .builder import BuildConfig, BuildResult, OssFuzzBuilder
from .project import OssFuzzProject
from .runner import FuzzConfig, FuzzRunner, ReplayResult

logger = logging.getLogger(__name__)


@dataclass
class PatchCheckResult:
    """Outcome of one patch validation attempt."""

    validated: bool = False  # crash reproduced before, gone after
    reproduced_on_vulnerable: bool = False
    patch_applied: bool = False
    rebuilt: bool = False
    original_signature: str = ""
    post_patch_signature: str = ""  # empty when the input no longer crashes
    new_crash_after_patch: bool = False  # crash gone but a DIFFERENT one appeared
    notes: str = ""
    duration_seconds: float = 0.0


def validate_patch(
    project: OssFuzzProject,
    project_dir: str | Path,
    source_dir: str | Path,
    patch_diff: str,
    crash_input_path: str | Path,
    *,
    fuzzer_name: str | None = None,
    vulnerable_build: BuildResult | None = None,
    build_config: BuildConfig | None = None,
    fuzz_config: FuzzConfig | None = None,
    work_dir: str | Path | None = None,
) -> PatchCheckResult:
    """Validate that ``patch_diff`` fixes the crash at ``crash_input_path``.

    Args:
        project / project_dir / source_dir: the OSS-Fuzz project triple and
            target checkout (as for ``OssFuzzBuilder.build``).
        patch_diff: unified diff, applied with ``patch -p1``.
        crash_input_path: reproducer input (e.g. from a fuzz run artifact).
        fuzzer_name: binary to replay; inferred when the build produced
            exactly one fuzzer.
        vulnerable_build: reuse an existing unpatched build instead of
            rebuilding (its ``out_dir`` must still exist).
        build_config / fuzz_config: plumbing overrides.
        work_dir: base for the patched build's $OUT (default:
            ``<vulnerable out_dir>-patched`` or ``<source_dir>/.ossfuzz-out``
            when no vulnerable build is supplied).

    Returns:
        PatchCheckResult — never raises for build/run failures; inspect
        ``validated`` and ``notes``.
    """
    start = time.monotonic()
    result = PatchCheckResult()
    builder = OssFuzzBuilder(build_config)
    runner = FuzzRunner(fuzz_config)

    crash_input = Path(crash_input_path)
    if not crash_input.is_file():
        result.notes = f"crash input not found: {crash_input}"
        return _finish(result, start)

    # --- Step 1: obtain an unpatched build and reproduce the crash -----------
    if vulnerable_build is None:
        out_dir = _default_out_dir(source_dir, suffix="")
        vulnerable_build = builder.build(project, project_dir, source_dir, out_dir)
        if not vulnerable_build.success:
            result.notes = f"vulnerable build failed: {vulnerable_build.error}"
            return _finish(result, start)

    fuzzer = fuzzer_name or _single_fuzzer(vulnerable_build)
    if fuzzer is None:
        result.notes = (
            "cannot determine fuzzer binary: pass fuzzer_name "
            f"(build produced {vulnerable_build.fuzzer_binaries})"
        )
        return _finish(result, start)

    pre = runner.replay(vulnerable_build.out_dir, fuzzer, crash_input)
    if pre.error:
        result.notes = f"pre-patch replay error: {pre.error}"
        return _finish(result, start)
    if not pre.crashed:
        result.notes = "crash input does not reproduce on the unpatched build"
        return _finish(result, start)
    result.reproduced_on_vulnerable = True
    result.original_signature = pre.signature

    # --- Steps 2+3: patch and rebuild ----------------------------------------
    patched_out = _default_out_dir(source_dir, suffix="-patched")
    if work_dir is not None:
        patched_out = str(Path(work_dir) / "out-patched")
    elif vulnerable_build.out_dir:
        patched_out = f"{vulnerable_build.out_dir}-patched"

    patched_build = builder.build(
        project, project_dir, source_dir, patched_out, patch_diff=patch_diff
    )
    result.patch_applied = not patched_build.error.startswith("patch apply failed")
    if not patched_build.success:
        result.notes = f"patched build failed: {patched_build.error}"
        return _finish(result, start)
    result.rebuilt = True

    if fuzzer not in patched_build.fuzzer_binaries:
        result.notes = f"patched build did not produce fuzzer {fuzzer!r}"
        return _finish(result, start)

    # --- Step 4: replay against the patched build ------------------------------
    post: ReplayResult = runner.replay(patched_build.out_dir, fuzzer, crash_input)
    if post.error:
        result.notes = f"post-patch replay error: {post.error}"
        return _finish(result, start)

    if not post.crashed:
        result.validated = True
        result.notes = "crash reproduced on vulnerable build, gone after patch"
    elif post.signature and post.signature == result.original_signature:
        result.post_patch_signature = post.signature
        result.notes = "original crash signature still present after patch"
    else:
        result.post_patch_signature = post.signature
        result.new_crash_after_patch = True
        result.notes = (
            "original crash gone but the input triggers a DIFFERENT crash "
            "after patching — the fix may have moved the bug"
        )

    return _finish(result, start)


def _single_fuzzer(build: BuildResult) -> str | None:
    if len(build.fuzzer_binaries) == 1:
        return build.fuzzer_binaries[0]
    return None


def _default_out_dir(source_dir: str | Path, suffix: str) -> str:
    return str(Path(source_dir) / f".ossfuzz-out{suffix}")


def _finish(result: PatchCheckResult, start: float) -> PatchCheckResult:
    result.duration_seconds = time.monotonic() - start
    return result
