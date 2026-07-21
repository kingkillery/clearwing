"""OSS-Fuzz-style build plumbing on Clearwing's sandbox substrate.

Implements the OSS-Fuzz build contract used by base-builder images and by
the AIxCC cyber-reasoning systems (Buttercup/OSS-CRS):

    $SRC   — source tree (read-write *copy*; the host checkout is never
             mutated — it is mounted read-only and copied in-container)
    $OUT   — fuzzer binaries land here (host-mounted, survives the container)
    $WORK  — scratch build directory
    $CC/$CXX/$CFLAGS/$CXXFLAGS — sanitizer-instrumented toolchain flags
    $LIB_FUZZING_ENGINE        — engine stub to link fuzz targets against

Sanitizer flag computation is delegated to
``clearwing.sandbox.builders.compute_sanitizer_env`` so there is exactly one
place in the codebase that knows what ``-fsanitize=...`` means.

Scope note: this builds against the *base-builder image + build.sh*, not
the project's Dockerfile (which may apt-install deps). Projects whose
Dockerfile installs extra packages can pass them via
``BuildConfig.apt_packages``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from clearwing.sandbox.builders import BuildRecipe, compute_sanitizer_env
from clearwing.sandbox.container import SandboxConfig, SandboxContainer

from .project import (
    LANGUAGE_BUILDER_IMAGES,
    SANITIZER_TO_CLEARWING,
    OssFuzzProject,
)

logger = logging.getLogger(__name__)

DEFAULT_BUILD_TIMEOUT_SECONDS = 1800


@dataclass
class BuildConfig:
    """Knobs for one OSS-Fuzz-style build."""

    sanitizer: str = "address"  # OSS-Fuzz name: address|undefined|memory|thread
    fuzzing_engine: str = "libfuzzer"
    image: str | None = None  # default: language-mapped base-builder
    build_timeout_seconds: int = DEFAULT_BUILD_TIMEOUT_SECONDS
    memory_mb: int = 4096
    network_mode: str = "none"  # flip to "bridge" when apt_packages are used
    apt_packages: list[str] = field(default_factory=list)
    extra_env: dict[str, str] = field(default_factory=dict)


@dataclass
class BuildResult:
    """Outcome of one build attempt."""

    success: bool
    fuzzer_binaries: list[str] = field(default_factory=list)  # names inside $OUT
    out_dir: str = ""
    log: str = ""  # tail of build output
    error: str = ""
    sanitizer: str = "address"
    image: str = ""
    duration_seconds: float = 0.0


class OssFuzzBuilder:
    """Build fuzz targets for an OSS-Fuzz project in a base-builder container.

    Usage:
        builder = OssFuzzBuilder(BuildConfig(sanitizer="address"))
        result = builder.build(project, project_dir, source_dir, out_dir)
        if result.success:
            ...  # result.fuzzer_binaries are files in out_dir

    The container is always torn down, even on failure. The host source
    tree is mounted read-only; the build works on an in-container copy, so
    ``patch_diff`` application (for patch validation) cannot dirty the host
    checkout either.
    """

    def __init__(self, config: BuildConfig | None = None):
        self.config = config or BuildConfig()

    def build(
        self,
        project: OssFuzzProject,
        project_dir: str | Path,
        source_dir: str | Path,
        out_dir: str | Path,
        *,
        patch_diff: str | None = None,
        extra_files: dict[str, bytes] | None = None,
        build_sh_override: str | None = None,
    ) -> BuildResult:
        """Run build.sh inside a base-builder container.

        Args:
            project: the OSS-Fuzz project model (language → image, name →
                $SRC subdir).
            project_dir: directory containing build.sh (an OSS-Fuzz project
                triple dir, e.g. from ``scaffold`` or the corpus).
            source_dir: host checkout of the target source.
            out_dir: host dir receiving fuzzer binaries ($OUT).
            patch_diff: optional unified diff applied with ``patch -p1``
                inside $SRC/<name> before building (patch validation).
            extra_files: optional ``{container_path: content}`` written into
                the container after source staging, before building — used
                to inject LLM-synthesized harnesses without touching the
                host checkout.
            build_sh_override: optional build script text used instead of
                ``<project_dir>/build.sh`` (synthesized per-harness builds).
        Returns:
            BuildResult; never raises for build failures — check
            ``result.success`` / ``result.error``.
        """
        start = time.monotonic()
        image = self.config.image or project.builder_image
        result = BuildResult(
            success=False,
            out_dir=str(out_dir),
            sanitizer=self.config.sanitizer,
            image=image,
        )

        build_sh_path = Path(project_dir) / "build.sh"
        if build_sh_override is None and not build_sh_path.is_file():
            result.error = f"build.sh not found in {project_dir}"
            return result
        build_sh_text = (
            build_sh_override.encode("utf-8")
            if build_sh_override is not None
            else build_sh_path.read_bytes()
        )
        source = Path(source_dir)
        if not source.is_dir():
            result.error = f"source dir not found: {source_dir}"
            return result
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)

        try:
            env = self._build_env(project)
        except ValueError as exc:
            result.error = str(exc)
            return result

        cfg = SandboxConfig(
            image=image,
            network_mode=self._effective_network_mode(),
            mounts=[
                (str(source.resolve()), f"/src-ro/{project.name}", "ro"),
                (str(out.resolve()), "/out", "rw"),
            ],
            memory_mb=self.config.memory_mb,
            timeout_seconds=self.config.build_timeout_seconds,
            env=env,
            working_dir=f"/src/{project.name}",
            name=f"clearwing-ossfuzz-build-{project.name}-{int(start)}",
        )

        try:
            with SandboxContainer(cfg) as sb:
                ok, err = self._stage_source(sb, project)
                if not ok:
                    result.error = err
                    return self._finish(result, start)

                ok, err = self._install_apt_packages(sb)
                if not ok:
                    result.error = err
                    return self._finish(result, start)

                if patch_diff is not None:
                    ok, err = self._apply_patch(sb, project, patch_diff)
                    if not ok:
                        result.error = f"patch apply failed: {err}"
                        return self._finish(result, start)

                if extra_files:
                    ok, err = self._write_extra_files(sb, extra_files)
                    if not ok:
                        result.error = err
                        return self._finish(result, start)

                sb.write_file("/src/build.sh", build_sh_text)
                chmod = sb.exec(["chmod", "+x", "/src/build.sh"], timeout=10)
                if chmod.exit_code != 0:
                    result.error = f"chmod build.sh failed: {chmod.stderr[:300]}"
                    return self._finish(result, start)

                build = sb.exec(
                    ["bash", "/src/build.sh"],
                    timeout=self.config.build_timeout_seconds,
                )
                result.log = (build.stdout + build.stderr)[-8000:]
                if build.timed_out:
                    result.error = f"build.sh timed out after {self.config.build_timeout_seconds}s"
                    return self._finish(result, start)
                if build.exit_code != 0:
                    result.error = f"build.sh exited {build.exit_code}"
                    return self._finish(result, start)

                result.fuzzer_binaries = self._enumerate_out(sb)
                result.success = True
                if not result.fuzzer_binaries:
                    logger.warning(
                        "Build succeeded but $OUT has no executables for %s",
                        project.name,
                    )
        except Exception as exc:  # docker daemon down, image pull failed, …
            logger.warning("OSS-Fuzz build failed for %s", project.name, exc_info=True)
            result.error = f"{type(exc).__name__}: {exc}"

        return self._finish(result, start)

    # --- Internals ----------------------------------------------------------

    def _build_env(self, project: OssFuzzProject) -> dict[str, str]:
        """Compute the $SRC/$OUT/$WORK + toolchain env contract."""
        cw_sanitizer = SANITIZER_TO_CLEARWING.get(self.config.sanitizer)
        if cw_sanitizer is None:
            raise ValueError(
                f"unsupported sanitizer {self.config.sanitizer!r}; "
                f"supported: {sorted(SANITIZER_TO_CLEARWING)}"
            )

        lang = "cpp" if project.language in ("c++", "cpp") else "c"
        recipe = BuildRecipe(
            system="ossfuzz",
            primary_language=lang,
            base_image=LANGUAGE_BUILDER_IMAGES["c"],
        )
        env = compute_sanitizer_env(recipe, [cw_sanitizer])

        if self.config.fuzzing_engine == "libfuzzer" and lang in ("c", "cpp"):
            # Compile objects with fuzzer-no-link; targets link the engine
            # stub via $LIB_FUZZING_ENGINE (OSS-Fuzz convention).
            no_link = "-fsanitize=fuzzer-no-link"
            for var in ("CFLAGS", "CXXFLAGS"):
                env[var] = f"{env.get(var, '')} {no_link}".strip()
            env["LIB_FUZZING_ENGINE"] = "/usr/lib/libFuzzingEngine.a"
            env["CC"] = "clang"
            env["CXX"] = "clang++"

        env.update(
            {
                "SRC": "/src",
                "OUT": "/out",
                "WORK": "/work",
                "SANITIZER": self.config.sanitizer,
                "FUZZING_ENGINE": self.config.fuzzing_engine,
                "ARCHITECTURE": "x86_64",
            }
        )
        env.update(self.config.extra_env)
        return env

    def _effective_network_mode(self) -> str:
        if self.config.apt_packages and self.config.network_mode == "none":
            logger.info("apt_packages requested — switching build network to bridge")
            return "bridge"
        return self.config.network_mode

    def _stage_source(self, sb: SandboxContainer, project: OssFuzzProject) -> tuple[bool, str]:
        """Copy the ro-mounted host tree into writable $SRC/<name>."""
        cmd = (
            f"mkdir -p /src/{project.name} /out /work && "
            f"cp -a /src-ro/{project.name}/. /src/{project.name}/"
        )
        res = sb.exec(["sh", "-c", cmd], timeout=300)
        if res.exit_code != 0:
            return False, f"source staging failed: {res.stderr[:400]}"
        return True, ""

    def _install_apt_packages(self, sb: SandboxContainer) -> tuple[bool, str]:
        if not self.config.apt_packages:
            return True, ""
        pkgs = " ".join(self.config.apt_packages)
        res = sb.exec(
            ["sh", "-c", f"apt-get update -qq && apt-get install -y -qq {pkgs}"],
            timeout=600,
        )
        if res.exit_code != 0:
            return False, f"apt-get install failed: {(res.stdout + res.stderr)[-400:]}"
        return True, ""

    def _write_extra_files(
        self, sb: SandboxContainer, extra_files: dict[str, bytes]
    ) -> tuple[bool, str]:
        """Write caller-supplied files into the container (harness injection)."""
        for container_path, content in extra_files.items():
            parent = str(Path(container_path).parent).replace("\\", "/")
            mkdir = sb.exec(["mkdir", "-p", parent], timeout=10)
            if mkdir.exit_code != 0:
                return False, f"mkdir for {container_path} failed: {mkdir.stderr[:200]}"
            try:
                sb.write_file(container_path, content)
            except Exception as exc:
                return False, f"write {container_path} failed: {exc}"
        return True, ""

    def _apply_patch(
        self, sb: SandboxContainer, project: OssFuzzProject, diff: str
    ) -> tuple[bool, str]:
        """Apply a unified diff inside the staged (in-container) source copy."""
        sb.write_file("/tmp/candidate.diff", diff.encode("utf-8"))
        res = sb.exec(
            ["sh", "-c", f"cd /src/{project.name} && patch -p1 --forward < /tmp/candidate.diff"],
            timeout=60,
        )
        if res.exit_code != 0:
            return False, (res.stdout + res.stderr)[:600]
        return True, ""

    @staticmethod
    def _enumerate_out(sb: SandboxContainer) -> list[str]:
        """List executable regular files directly under $OUT."""
        res = sb.exec(
            ["sh", "-c", "find /out -maxdepth 1 -type f -perm -u+x -printf '%f\n'"],
            timeout=30,
        )
        if res.exit_code != 0:
            # Fallback for minimal images without -printf
            res = sb.exec(["sh", "-c", "ls /out"], timeout=30)
        names = [
            line.strip()
            for line in res.stdout.splitlines()
            if line.strip() and not line.strip().endswith((".options", ".dict", ".zip"))
        ]
        return sorted(names)

    @staticmethod
    def _finish(result: BuildResult, start: float) -> BuildResult:
        result.duration_seconds = time.monotonic() - start
        return result
