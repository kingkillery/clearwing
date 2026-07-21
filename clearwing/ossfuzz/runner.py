"""Fuzzer execution, crash artifact collection, and single-input replay.

Runs binaries produced by ``OssFuzzBuilder`` inside fresh containers with
no network, collects libFuzzer crash artifacts (``crash-*``, ``oom-*``,
``timeout-*``), and replays individual inputs — the primitive both crash
confirmation and patch validation are built on.

Crash detection is artifact-first (libFuzzer writes the reproducer before
exiting), with exit-code fallback for non-libFuzzer engines. Every crash
artifact is copied to the host crashes dir so PoCs survive the container.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from clearwing.sandbox.container import SandboxConfig, SandboxContainer

from .crashes import CrashDeduplicator, ParsedCrash, parse_sanitizer_report
from .project import DEFAULT_RUNNER_IMAGE

logger = logging.getLogger(__name__)

ARTIFACT_PREFIXES = ("crash-", "oom-", "timeout-", "leak-")

# libFuzzer exit codes: 77 = crash found, 70 = timeout, 71 = OOM.
# 0 = clean exit (max_total_time reached), 124/137 = our timeout wrapper.
_CRASH_EXIT_CODES = {70, 71, 77}


@dataclass
class FuzzConfig:
    """Knobs for one fuzz run."""

    image: str | None = None  # default: OSS-Fuzz base-runner, builder fallback
    corpus_dir: str | None = None  # host dir mounted ro at /corpus
    crashes_dir: str = ""  # host dir receiving artifacts (default: <out_dir>/crashes)
    max_total_time_seconds: int = 60
    exec_timeout_slack_seconds: int = 30
    rss_limit_mb: int = 2048
    memory_mb: int = 4096
    dictionary: str | None = None  # host path to a -dict= file
    extra_args: list[str] = field(default_factory=list)
    dedup_depth: int = 3


@dataclass
class CrashArtifact:
    """One crashing input plus its parsed report."""

    fuzzer_name: str
    artifact_name: str = ""
    input_path: str = ""  # host path where the reproducer was saved
    exit_code: int = -1
    report: ParsedCrash = field(default_factory=ParsedCrash)
    signature: str = ""
    is_new: bool = True  # False when dedup'd against an earlier crash in the run


@dataclass
class FuzzRunResult:
    """Outcome of one fuzzer invocation."""

    fuzzer_name: str
    success: bool = False  # the fuzzer ran at all (crashes are NOT failures)
    error: str = ""
    runs_executed: int = 0  # libFuzzer "#12345 DONE" pulse count, when parseable
    crashes: list[CrashArtifact] = field(default_factory=list)
    unique_crash_count: int = 0
    log: str = ""
    duration_seconds: float = 0.0


@dataclass
class ReplayResult:
    """Outcome of replaying a single input against a fuzzer binary."""

    crashed: bool
    exit_code: int = -1
    report: ParsedCrash = field(default_factory=ParsedCrash)
    signature: str = ""
    output: str = ""
    error: str = ""


class FuzzRunner:
    """Run OSS-Fuzz-built fuzzers and collect crashes.

    Usage:
        runner = FuzzRunner(FuzzConfig(max_total_time_seconds=120))
        result = runner.fuzz(out_dir, "fuzz_parse")
        for crash in result.crashes:
            finding = crash_to_finding(crash.report, project_name=...)

    A fresh container is used per ``fuzz`` / ``replay`` call. The $OUT dir
    is mounted read-only; crash artifacts land in ``config.crashes_dir``
    (default ``<out_dir>/crashes``) via a read-write mount.
    """

    def __init__(self, config: FuzzConfig | None = None):
        self.config = config or FuzzConfig()

    # --- Fuzzing -----------------------------------------------------------

    def fuzz(self, out_dir: str | Path, fuzzer_name: str) -> FuzzRunResult:
        """Run one fuzzer for ``max_total_time_seconds`` and collect crashes."""
        start = time.monotonic()
        result = FuzzRunResult(fuzzer_name=fuzzer_name)
        out = Path(out_dir)
        binary = out / fuzzer_name
        if not binary.is_file():
            result.error = f"fuzzer binary not found: {binary}"
            return result

        crashes_dir = Path(self.config.crashes_dir) if self.config.crashes_dir else out / "crashes"
        crashes_dir.mkdir(parents=True, exist_ok=True)

        mounts = [
            (str(out.resolve()), "/out", "ro"),
            (str(crashes_dir.resolve()), "/artifacts", "rw"),
        ]
        corpus_mount: tuple[str, str, str] | None = None
        if self.config.corpus_dir:
            corpus = Path(self.config.corpus_dir)
            if corpus.is_dir():
                corpus_mount = (str(corpus.resolve()), "/corpus", "ro")
                mounts.append(corpus_mount)
            else:
                logger.warning("corpus dir not found: %s — seed corpus skipped", corpus)

        cfg = SandboxConfig(
            image=self._runner_image(),
            network_mode="none",
            mounts=mounts,
            memory_mb=self.config.memory_mb,
            timeout_seconds=self.config.max_total_time_seconds
            + self.config.exec_timeout_slack_seconds,
            working_dir="/out",
            name=f"clearwing-ossfuzz-fuzz-{fuzzer_name}-{int(start)}",
        )

        try:
            with SandboxContainer(cfg) as sb:
                cmd = self._fuzz_command(fuzzer_name, corpus_mount is not None)
                run = sb.exec(
                    ["sh", "-c", cmd],
                    timeout=self.config.max_total_time_seconds
                    + self.config.exec_timeout_slack_seconds,
                )
                output = run.stdout + run.stderr
                result.log = output[-8000:]
                result.success = True
                result.runs_executed = _parse_runs_executed(output)

                artifact_names = self._list_artifacts(sb)
                dedup = CrashDeduplicator(depth=self.config.dedup_depth)
                for name in artifact_names:
                    artifact = self._collect_artifact(sb, fuzzer_name, name, crashes_dir, dedup)
                    if artifact is not None:
                        result.crashes.append(artifact)

                # Exit-code fallback: crash reported but artifact missing
                if not artifact_names and run.exit_code in _CRASH_EXIT_CODES:
                    report = parse_sanitizer_report(output)
                    sig_is_new, sig = dedup.add(report)
                    result.crashes.append(
                        CrashArtifact(
                            fuzzer_name=fuzzer_name,
                            exit_code=run.exit_code,
                            report=report,
                            signature=sig,
                            is_new=sig_is_new,
                        )
                    )

                result.unique_crash_count = sum(1 for c in result.crashes if c.is_new)
        except Exception as exc:
            logger.warning("Fuzz run failed for %s", fuzzer_name, exc_info=True)
            result.error = f"{type(exc).__name__}: {exc}"

        result.duration_seconds = time.monotonic() - start
        return result

    # --- Replay ---------------------------------------------------------------

    def replay(
        self,
        out_dir: str | Path,
        fuzzer_name: str,
        crash_input_path: str | Path,
        *,
        timeout_seconds: int = 60,
    ) -> ReplayResult:
        """Replay one input against a fuzzer binary. The patch-check primitive.

        ``crashed`` is True when the run produced a sanitizer/libFuzzer
        report or a crash-class exit code; the parsed report and signature
        let callers compare against the original crash (patch validation
        wants: same signature before, absent after).
        """
        out = Path(out_dir)
        binary = out / fuzzer_name
        crash_input = Path(crash_input_path)
        result = ReplayResult(crashed=False)
        if not binary.is_file():
            result.error = f"fuzzer binary not found: {binary}"
            return result
        if not crash_input.is_file():
            result.error = f"crash input not found: {crash_input}"
            return result

        input_dir = crash_input.parent.resolve()
        cfg = SandboxConfig(
            image=self._runner_image(),
            network_mode="none",
            mounts=[
                (str(out.resolve()), "/out", "ro"),
                (str(input_dir), "/input", "ro"),
            ],
            memory_mb=self.config.memory_mb,
            timeout_seconds=timeout_seconds,
            working_dir="/out",
        )

        try:
            with SandboxContainer(cfg) as sb:
                run = sb.exec(
                    ["sh", "-c", f"/out/{fuzzer_name} /input/{crash_input.name} 2>&1"],
                    timeout=timeout_seconds,
                )
                output = run.stdout + run.stderr
                result.output = output[-8000:]
                result.exit_code = run.exit_code
                result.report = parse_sanitizer_report(output)
                has_report = bool(result.report.sanitizer or result.report.crash_type)
                result.crashed = has_report or run.exit_code in _CRASH_EXIT_CODES
                if result.crashed:
                    from .crashes import crash_signature

                    result.signature = crash_signature(result.report, depth=self.config.dedup_depth)
        except Exception as exc:
            logger.warning("Replay failed for %s", fuzzer_name, exc_info=True)
            result.error = f"{type(exc).__name__}: {exc}"
        return result

    # --- Internals ------------------------------------------------------------

    def _runner_image(self) -> str:
        # OSS-Fuzz convention: fuzzers run in base-runner (a small image
        # with the sanitizer runtimes). Operators can point at base-builder
        # or a custom image via FuzzConfig.image when a target needs more.
        return self.config.image or DEFAULT_RUNNER_IMAGE

    def _fuzz_command(self, fuzzer_name: str, has_corpus: bool) -> str:
        args = [
            f"-max_total_time={self.config.max_total_time_seconds}",
            f"-rss_limit_mb={self.config.rss_limit_mb}",
            "-artifact_prefix=/artifacts/",
            "-print_final_stats=1",
        ]
        if self.config.dictionary:
            # Dictionary is expected inside the mounted $OUT dir
            args.append(f"-dict=/out/{Path(self.config.dictionary).name}")
        args.extend(self.config.extra_args)
        corpus_arg = "/corpus" if has_corpus else ""
        return f"/out/{fuzzer_name} {' '.join(args)} {corpus_arg} 2>&1"

    def _list_artifacts(self, sb: SandboxContainer) -> list[str]:
        """List crash artifact filenames written by libFuzzer."""
        res = sb.exec(["sh", "-c", "ls /artifacts 2>/dev/null"], timeout=15)
        if res.exit_code != 0:
            return []
        return sorted(
            name
            for name in (line.strip() for line in res.stdout.splitlines())
            if name.startswith(ARTIFACT_PREFIXES)
        )

    def _collect_artifact(
        self,
        sb: SandboxContainer,
        fuzzer_name: str,
        artifact_name: str,
        crashes_dir: Path,
        dedup: CrashDeduplicator,
    ) -> CrashArtifact | None:
        """Copy one artifact to the host and confirm it with a replay."""
        try:
            data = sb.read_file(f"/artifacts/{artifact_name}")
        except Exception:
            logger.debug("Could not read artifact %s", artifact_name, exc_info=True)
            return None

        fuzzer_crash_dir = crashes_dir / fuzzer_name
        fuzzer_crash_dir.mkdir(parents=True, exist_ok=True)
        host_path = fuzzer_crash_dir / artifact_name
        host_path.write_bytes(data)

        # Confirm inside the same container: run the fuzzer on the artifact
        run = sb.exec(
            ["sh", "-c", f"/out/{fuzzer_name} /artifacts/{artifact_name} 2>&1"],
            timeout=60,
        )
        output = run.stdout + run.stderr
        report = parse_sanitizer_report(output)
        is_new, sig = dedup.add(report)
        return CrashArtifact(
            fuzzer_name=fuzzer_name,
            artifact_name=artifact_name,
            input_path=str(host_path),
            exit_code=run.exit_code,
            report=report,
            signature=sig,
            is_new=is_new,
        )


def _parse_runs_executed(output: str) -> int:
    """Extract the final exec count from libFuzzer stats output."""
    import re

    counts = re.findall(r"#(\d+)\s+(?:DONE|pulse)", output)
    if counts:
        return int(counts[-1])
    stat = re.search(r"stat::number_of_executed_units:\s*(\d+)", output)
    return int(stat.group(1)) if stat else 0
