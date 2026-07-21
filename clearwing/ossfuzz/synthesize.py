"""OSS-Fuzz-Gen-style harness synthesis with a build-error repair loop.

The one-shot harness generators (including Clearwing's legacy
``HarnessGenerator``) share a structural weakness: most LLM-written
harnesses don't compile on the first try, and one-shot designs discard
them. OSS-Fuzz-Gen's central result is that feeding the compiler's stderr
back to the model — generate → build → repair, a few rounds — multiplies
the rate of working harnesses. This module implements exactly that loop
on top of ``OssFuzzBuilder``:

    round 1:  prompt for a harness → build → success?
    round N:  prompt with the failed harness + stderr tail → build → …

Each accepted harness is compiled *with the target file* against
``$LIB_FUZZING_ENGINE`` inside the OSS-Fuzz base-builder contract, so a
successful synthesis yields a fuzzer binary in ``$OUT`` ready for
``FuzzRunner``. Harnesses are injected into the build container via
``extra_files`` — the host checkout is never touched.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .builder import BuildResult, OssFuzzBuilder
from .project import OssFuzzProject
from .project import validate_repo_rel_path as _validate_repo_rel_path

logger = logging.getLogger(__name__)

DEFAULT_MAX_ROUNDS = 4
_MAX_STDERR_FEEDBACK_CHARS = 3000
_MAX_FILE_SOURCE_CHARS = 8000

HARNESS_SYSTEM_PROMPT = """You are a security researcher writing a libFuzzer harness for a single C/C++ file so a fuzzer can find crashes.

The harness is compiled TOGETHER with the target file and linked against the libFuzzer engine:

    $CC $CFLAGS -I<repo-root> harness.c target_file.c -o fuzzer $LIB_FUZZING_ENGINE

Produce ONLY a complete C/C++ source file that:

1. Includes <stdint.h>, <stddef.h>, and any project headers the target needs (paths relative to the repo root).
2. Defines `int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)`.
3. Calls the target function with buffer data derived from Data/Size, handling input-shape parsing (length prefixes, minimum sizes, pointer wrapping). Guard against NULL/size-0 inputs.
4. Returns 0 on a successful non-crashing run.

Requirements:
- No `main()`. libFuzzer provides its own.
- No network, no filesystem, no global state that breaks across runs.
- No infinite loops; bound any data-driven loops by Size.
- Under 80 lines.

Return ONLY the source code, no markdown fences, no prose."""

REPAIR_SYSTEM_PROMPT = """You are fixing a libFuzzer harness that failed to compile.

You are given the failing harness source and the compiler output. Return a COMPLETE corrected harness source file that fixes the compilation errors while preserving the fuzzing intent. Common fixes: wrong function signatures, missing includes, implicit declarations, C vs C++ linkage (wrap project includes in `extern "C"` when compiling C targets as C++).

Return ONLY the corrected source code, no markdown fences, no prose."""


@dataclass
class SynthesisAttempt:
    """One generate→build round."""

    round: int
    build_success: bool
    error_excerpt: str = ""


@dataclass
class SynthesisResult:
    """Outcome of the repair loop for one target file."""

    success: bool = False
    harness_source: str = ""
    fuzzer_name: str = ""  # binary name in $OUT when success
    rounds: int = 0
    attempts: list[SynthesisAttempt] = field(default_factory=list)
    build: BuildResult | None = None  # final build (successful one when success)
    cost_usd: float = 0.0
    duration_seconds: float = 0.0


class HarnessSynthesizer:
    """Generate a compiling fuzz harness for one target file.

    Usage:
        synth = HarnessSynthesizer(llm, OssFuzzBuilder())
        result = synth.synthesize(
            project, project_dir, source_dir, out_dir,
            target_file="src/parse.c",
            file_source=open(...).read(),
        )
        if result.success:
            ...  # out_dir / result.fuzzer_name exists

    The LLM client must expose ``aask_text(system=..., user=...)`` like
    ``clearwing.llm.native.AsyncLLMClient``; calls are driven synchronously
    via ``asyncio.run`` — call ``synthesize`` from a thread when inside a
    running event loop (the runner does ``asyncio.to_thread``).
    """

    def __init__(
        self,
        llm: Any,
        builder: OssFuzzBuilder | None = None,
        *,
        max_rounds: int = DEFAULT_MAX_ROUNDS,
    ) -> None:
        self.llm = llm
        self.builder = builder or OssFuzzBuilder()
        self.max_rounds = max_rounds

    def synthesize(
        self,
        project: OssFuzzProject,
        project_dir: str | Path,
        source_dir: str | Path,
        out_dir: str | Path,
        *,
        target_file: str,
        file_source: str,
        harness_name: str | None = None,
        target_function: str = "",
    ) -> SynthesisResult:
        """Run the generate→build→repair loop for one target file.

        Never raises for LLM/build failures — inspect ``result.success``.
        """
        start = time.monotonic()
        result = SynthesisResult()
        harness_name = harness_name or _default_harness_name(target_file)
        harness_rel = f".fuzzstage/{harness_name}.c"
        is_cpp = Path(target_file).suffix.lower() in (".cpp", ".cc", ".cxx", ".c++")

        harness_source = ""
        last_error = ""
        for round_no in range(1, self.max_rounds + 1):
            harness_source = self._generate(
                target_file=target_file,
                file_source=file_source,
                target_function=target_function,
                previous_harness=harness_source,
                compiler_error=last_error,
            )
            result.rounds = round_no
            if not harness_source:
                result.attempts.append(
                    SynthesisAttempt(round=round_no, build_success=False, error_excerpt="LLM returned no harness")
                )
                continue

            try:
                build_sh = _render_single_harness_build_sh(
                    project.name, harness_rel, target_file, harness_name, is_cpp,
                )
            except ValueError as exc:
                # Unsafe repo path (traversal/absolute) — deterministic,
                # retrying won't help; treat as failed synthesis.
                logger.warning("Harness build.sh render rejected: %s", exc)
                result.attempts.append(
                    SynthesisAttempt(round=round_no, build_success=False, error_excerpt=str(exc))
                )
                break
            build = self.builder.build(
                project,
                project_dir,
                source_dir,
                out_dir,
                build_sh_override=build_sh,
                extra_files={f"/src/{project.name}/{harness_rel}": harness_source.encode("utf-8")},
            )
            result.build = build
            result.attempts.append(
                SynthesisAttempt(
                    round=round_no,
                    build_success=build.success,
                    error_excerpt="" if build.success else (build.error or build.log)[-300:],
                )
            )
            if build.success:
                result.success = True
                result.harness_source = harness_source
                result.fuzzer_name = harness_name
                logger.info(
                    "Harness for %s compiled on round %d", target_file, round_no,
                )
                break
            last_error = (build.log or build.error)[-_MAX_STDERR_FEEDBACK_CHARS:]
            logger.debug(
                "Harness round %d for %s failed: %s",
                round_no, target_file, (build.error or "")[:200],
            )

        result.duration_seconds = time.monotonic() - start
        return result

    # --- LLM -----------------------------------------------------------------

    def _generate(
        self,
        *,
        target_file: str,
        file_source: str,
        target_function: str,
        previous_harness: str,
        compiler_error: str,
    ) -> str:
        try:
            if previous_harness and compiler_error:
                user = (
                    f"Target file: {target_file}\n\n"
                    f"FAILING HARNESS:\n{previous_harness}\n\n"
                    f"COMPILER OUTPUT (tail):\n{compiler_error}\n"
                )
                response = asyncio.run(
                    self.llm.aask_text(system=REPAIR_SYSTEM_PROMPT, user=user)
                )
            else:
                user = (
                    f"Target file: {target_file}\n"
                    f"Target function hint: {target_function or 'choose the main entry function'}\n\n"
                    f"File source (may be truncated):\n\n"
                    f"{file_source[:_MAX_FILE_SOURCE_CHARS]}\n"
                )
                response = asyncio.run(
                    self.llm.aask_text(system=HARNESS_SYSTEM_PROMPT, user=user)
                )
            text = response.first_text() or ""
        except Exception:
            logger.debug("Harness synthesis LLM call failed", exc_info=True)
            return ""
        return _strip_markdown_fences(text)


# --- Helpers -----------------------------------------------------------------


def _default_harness_name(target_file: str) -> str:
    """Unique, shell-safe name from the repo-relative path.

    Same-stem files (``src/parser.c`` vs ``vendor/parser.c``) must not
    share a fuzzer binary name in $OUT, and the name is interpolated
    into a shell build script — so the readable stem is restricted to
    [a-z0-9_-] and uniqueness comes from a path-hash suffix.
    """
    import hashlib

    digest = hashlib.sha256(target_file.replace("\\", "/").encode("utf-8")).hexdigest()[:8]
    stem = re.sub(r"[^a-z0-9_-]+", "-", Path(target_file).stem.lower()).strip("-")
    return f"fuzz_{stem or 'target'}-{digest}"



# Fuzzer names become $OUT filenames and appear in shell fragments —
# restrict to a strict allowlist (path validation handles repo paths;
# fuzzer names are Clearwing-generated so there is no legitimate need
# for anything beyond this).
_SAFE_FUZZER_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


def _require_safe_fuzzer_name(name: str) -> None:
    """Fuzzer names become $OUT filenames and shell fragments."""
    if not _SAFE_FUZZER_NAME.match(name):
        raise ValueError(f"unsafe fuzzer name: {name!r}")


def _render_single_harness_build_sh(
    project_name: str,
    harness_rel: str,
    target_file: str,
    fuzzer_name: str,
    is_cpp: bool,
) -> str:
    """Build script compiling one harness together with its target file.

    Raises ValueError on unsafe paths — callers treat this as a failed
    synthesis, never as a pipeline error.
    """
    target = _validate_repo_rel_path(target_file)
    harness = _validate_repo_rel_path(harness_rel)
    _require_safe_fuzzer_name(fuzzer_name)
    compiler = "$CXX" if is_cpp else "$CC"
    flags = "$CXXFLAGS" if is_cpp else "$CFLAGS"
    return (
        "#!/bin/bash -eu\n"
        f"TARGET_FILE={shlex.quote(target)}\n"
        f"HARNESS={shlex.quote(harness)}\n"
        f"{compiler} {flags} "
        f'-I"$SRC/{project_name}" '
        f'-I"$SRC/{project_name}/$(dirname "$TARGET_FILE")" '
        f'"$SRC/{project_name}/$HARNESS" '
        f'"$SRC/{project_name}/$TARGET_FILE" '
        f'-o "$OUT/{fuzzer_name}" '
        "$LIB_FUZZING_ENGINE\n"
    )


_MD_FENCE = re.compile(r"^```(?:c|cpp|c\+\+)?\s*\n([\s\S]*?)\n```\s*$")


def _strip_markdown_fences(content: str) -> str:
    """Remove ```c ... ``` fences if the model added them."""
    content = content.strip()
    m = _MD_FENCE.match(content)
    return m.group(1) if m else content
