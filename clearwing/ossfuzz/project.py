"""OSS-Fuzz project format: model, triple rendering, and corpus loading.

The OSS-Fuzz project format is three files living in one directory::

    projects/<name>/
    ├── project.yaml   # metadata: language, sanitizers, repo, contacts
    ├── Dockerfile     # FROM gcr.io/oss-fuzz-base/base-builder ... fetch source
    └── build.sh       # compile with $CC $CFLAGS, link $LIB_FUZZING_ENGINE → $OUT

Adopting it gives Clearwing two things at once:

1. A portable target description — anything Clearwing scaffolds can be
   upstreamed to google/oss-fuzz, and anything in google/oss-fuzz can be
   consumed here.
2. Access to the 1,000+ project corpus in a local ``google/oss-fuzz``
   checkout (``load_oss_fuzz_corpus``) — the target list OSS-CRS uses to
   run AIxCC-grade systems against real projects without per-project work.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# --- Language → base-builder image mapping ----------------------------------
# Mirrors https://github.com/google/oss-fuzz/tree/master/infra/base-images
LANGUAGE_BUILDER_IMAGES: dict[str, str] = {
    "c": "gcr.io/oss-fuzz-base/base-builder",
    "c++": "gcr.io/oss-fuzz-base/base-builder",
    "cpp": "gcr.io/oss-fuzz-base/base-builder",
    "rust": "gcr.io/oss-fuzz-base/base-builder-rust",
    "go": "gcr.io/oss-fuzz-base/base-builder-go",
    "python": "gcr.io/oss-fuzz-base/base-builder-python",
    "jvm": "gcr.io/oss-fuzz-base/base-builder-jvm",
    "java": "gcr.io/oss-fuzz-base/base-builder-jvm",
    "javascript": "gcr.io/oss-fuzz-base/base-builder-javascript",
    "swift": "gcr.io/oss-fuzz-base/base-builder-swift",
}

DEFAULT_RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"

# Sanitizers OSS-Fuzz knows how to build for. "coverage"/"introspector" are
# infra configs, not crash finders — excluded from the default set.
OSSFUZZ_SANITIZERS: tuple[str, ...] = ("address", "undefined", "memory", "thread")

# Map OSS-Fuzz sanitizer names → Clearwing's internal short names used by
# clearwing.sandbox.builders.compute_sanitizer_env.
SANITIZER_TO_CLEARWING: dict[str, str] = {
    "address": "asan",
    "undefined": "ubsan",
    "memory": "msan",
    "thread": "tsan",
}

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


@dataclass
class OssFuzzProject:
    """One OSS-Fuzz project — the contents of ``project.yaml``.

    Only fields Clearwing consumes are modeled; unknown keys in a parsed
    project.yaml are preserved in ``extra`` so a load→save round-trip does
    not destroy upstream metadata.
    """

    name: str
    language: str = "c"
    sanitizers: list[str] = field(default_factory=lambda: ["address", "undefined"])
    fuzzing_engines: list[str] = field(default_factory=lambda: ["libfuzzer"])
    main_repo: str = ""
    homepage: str = ""
    primary_contact: str = ""
    vendor_ccs: list[str] = field(default_factory=list)
    architectures: list[str] = field(default_factory=lambda: ["x86_64"])
    file_github_issue: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.name = self.name.strip()
        if not _NAME_RE.match(self.name):
            raise ValueError(
                f"invalid OSS-Fuzz project name {self.name!r}: must match "
                "[a-z0-9][a-z0-9_-]* (google/oss-fuzz naming rules)"
            )
        self.language = self.language.strip().lower()
        unknown = [s for s in self.sanitizers if s not in OSSFUZZ_SANITIZERS]
        if unknown:
            raise ValueError(
                f"unknown sanitizers {unknown!r}; supported: {list(OSSFUZZ_SANITIZERS)}"
            )

    # --- Serialization ------------------------------------------------------

    def to_yaml_dict(self) -> dict[str, Any]:
        """Serialize to the project.yaml shape (upstream field order)."""
        d: dict[str, Any] = {}
        if self.homepage:
            d["homepage"] = self.homepage
        if self.main_repo:
            d["main_repo"] = self.main_repo
        if self.primary_contact:
            d["primary_contact"] = self.primary_contact
        if self.vendor_ccs:
            d["vendor_ccs"] = list(self.vendor_ccs)
        d["language"] = self.language
        if self.architectures != ["x86_64"]:
            d["architectures"] = list(self.architectures)
        d["sanitizers"] = list(self.sanitizers)
        if self.fuzzing_engines != ["libfuzzer"]:
            d["fuzzing_engines"] = list(self.fuzzing_engines)
        if self.file_github_issue:
            d["file_github_issue"] = True
        d.update(self.extra)
        return d

    @classmethod
    def from_yaml_dict(cls, name: str, data: dict[str, Any]) -> OssFuzzProject:
        """Parse a project.yaml dict. Unknown keys land in ``extra``."""
        known = {
            "homepage",
            "main_repo",
            "primary_contact",
            "vendor_ccs",
            "language",
            "architectures",
            "sanitizers",
            "fuzzing_engines",
            "file_github_issue",
        }
        sanitizers = data.get("sanitizers") or ["address", "undefined"]
        # Tolerate infra-only configs in upstream project.yamls
        sanitizers = [s for s in sanitizers if s in OSSFUZZ_SANITIZERS] or ["address"]
        vendor_ccs = data.get("vendor_ccs") or []
        architectures = data.get("architectures") or ["x86_64"]
        return cls(
            name=name,
            language=str(data.get("language", "c")),
            sanitizers=list(sanitizers),
            fuzzing_engines=list(data.get("fuzzing_engines") or ["libfuzzer"]),
            main_repo=str(data.get("main_repo", "") or ""),
            homepage=str(data.get("homepage", "") or ""),
            primary_contact=str(data.get("primary_contact", "") or ""),
            vendor_ccs=list(vendor_ccs),
            architectures=list(architectures),
            file_github_issue=bool(data.get("file_github_issue", False)),
            extra={k: v for k, v in data.items() if k not in known},
        )

    @property
    def builder_image(self) -> str:
        """The OSS-Fuzz base-builder image for this project's language."""
        return LANGUAGE_BUILDER_IMAGES.get(self.language, LANGUAGE_BUILDER_IMAGES["c"])

    # --- Triple rendering ---------------------------------------------------

    def render_dockerfile(self, *, local_source: bool = False) -> str:
        """Render the OSS-Fuzz Dockerfile.

        Args:
            local_source: when True, ``COPY`` a pre-cloned tree instead of
                ``git clone``-ing ``main_repo`` (used for hunting local
                checkouts and for hermetic rebuilds).
        """
        lines = [f"FROM {self.builder_image}", ""]
        if local_source:
            lines.append(f"COPY . $SRC/{self.name}")
        elif self.main_repo:
            lines.append(f"RUN git clone --depth 1 {self.main_repo} $SRC/{self.name}")
        else:
            raise ValueError("render_dockerfile needs main_repo set or local_source=True")
        lines += [
            f"WORKDIR $SRC/{self.name}",
            "COPY build.sh $SRC/build.sh",
            "",
        ]
        return "\n".join(lines)

    def render_build_sh(self, harnesses: list[str] | None = None) -> str:
        """Render a build.sh skeleton following OSS-Fuzz conventions.

        The emitted script compiles every listed harness with
        ``$CXX $CXXFLAGS ... $LIB_FUZZING_ENGINE -o $OUT/<name>``. Project
        library compilation is left as a marked section — this skeleton is
        meant to be completed by an operator or by Clearwing's LLM harness
        generator, then exercised by ``OssFuzzBuilder``.
        """
        harnesses = harnesses or ["fuzz_target"]
        out = [
            "#!/bin/bash -eu",
            "# OSS-Fuzz build script — https://google.github.io/oss-fuzz/",
            "# Env contract provided by the base-builder image / Clearwing:",
            "#   $SRC $OUT $WORK $CC $CXX $CFLAGS $CXXFLAGS $LIB_FUZZING_ENGINE",
            "",
            f"cd $SRC/{self.name}",
            "",
            "# --- Build the project with sanitizer instrumentation ------------",
            "# (add the project's own build here, using $CC/$CXX and",
            "#  $CFLAGS/$CXXFLAGS so instrumentation is applied)",
            "",
            "# --- Link fuzz targets against $LIB_FUZZING_ENGINE -----------------",
        ]
        for harness in harnesses:
            stem = Path(harness).stem
            out.append(
                f"$CXX $CXXFLAGS -I$SRC/{self.name} "
                f"$SRC/{self.name}/{harness} "
                f"-o $OUT/{stem} $LIB_FUZZING_ENGINE"
            )
        out.append("")
        return "\n".join(out)

    def scaffold(self, out_dir: str | Path, harnesses: list[str] | None = None) -> Path:
        """Write the project triple (project.yaml, Dockerfile, build.sh).

        Returns the directory written: ``<out_dir>/<name>/``.
        """
        project_dir = Path(out_dir) / self.name
        project_dir.mkdir(parents=True, exist_ok=True)

        yaml_text = yaml.safe_dump(self.to_yaml_dict(), sort_keys=False, default_flow_style=False)
        (project_dir / "project.yaml").write_text(yaml_text, encoding="utf-8")

        dockerfile = self.render_dockerfile(local_source=not self.main_repo)
        (project_dir / "Dockerfile").write_text(dockerfile, encoding="utf-8")

        build_sh = self.render_build_sh(harnesses)
        build_path = project_dir / "build.sh"
        build_path.write_text(build_sh, encoding="utf-8", newline="\n")
        try:
            build_path.chmod(0o755)
        except OSError:
            pass  # Windows — the container reads it regardless

        logger.info("Scaffolded OSS-Fuzz project at %s", project_dir)
        return project_dir


# --- Loading ----------------------------------------------------------------


def load_project_yaml(path: str | Path) -> OssFuzzProject:
    """Load a project.yaml (or a project directory containing one)."""
    p = Path(path)
    if p.is_dir():
        p = p / "project.yaml"
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"project.yaml at {p} is not a mapping")
    return OssFuzzProject.from_yaml_dict(p.parent.name, data)


def scaffold_project(
    name: str,
    language: str,
    out_dir: str | Path,
    *,
    main_repo: str = "",
    homepage: str = "",
    sanitizers: list[str] | None = None,
    harnesses: list[str] | None = None,
) -> Path:
    """Convenience wrapper: build an OssFuzzProject and write its triple."""
    project = OssFuzzProject(
        name=name,
        language=language,
        main_repo=main_repo,
        homepage=homepage,
        sanitizers=sanitizers or ["address", "undefined"],
    )
    return project.scaffold(out_dir, harnesses=harnesses)


# --- The corpus: a local google/oss-fuzz checkout ----------------------------

DEFAULT_CORPUS_SUBDIR = "projects"


def resolve_oss_fuzz_dir(explicit: str | None = None) -> Path | None:
    """Locate a local google/oss-fuzz checkout.

    Resolution order: explicit argument → ``CLEARWING_OSS_FUZZ_DIR`` env →
    ``~/.clearwing/oss-fuzz``. Returns None when nothing is checked out.
    """
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    env_dir = os.environ.get("CLEARWING_OSS_FUZZ_DIR", "")
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.append(Path.home() / ".clearwing" / "oss-fuzz")

    for cand in candidates:
        if (cand / DEFAULT_CORPUS_SUBDIR).is_dir():
            return cand
    return None


@dataclass
class CorpusProject:
    """A project entry from a google/oss-fuzz checkout."""

    name: str
    project_dir: Path
    project: OssFuzzProject

    @property
    def has_build_sh(self) -> bool:
        return (self.project_dir / "build.sh").exists()

    @property
    def has_dockerfile(self) -> bool:
        return (self.project_dir / "Dockerfile").exists()


def load_oss_fuzz_corpus(
    oss_fuzz_dir: str | Path | None = None,
    *,
    language: str | None = None,
    sanitizer: str | None = None,
    require_build_sh: bool = True,
) -> list[CorpusProject]:
    """Enumerate projects from a local google/oss-fuzz checkout.

    Args:
        oss_fuzz_dir: checkout root (resolved via ``resolve_oss_fuzz_dir``
            when None).
        language: keep only projects of this language (e.g. ``"c"``).
        sanitizer: keep only projects that build for this sanitizer
            (e.g. ``"address"``).
        require_build_sh: skip projects without a build.sh (unbuildable
            here regardless of metadata).

    Returns:
        CorpusProject entries sorted by name. Malformed project.yamls are
        logged and skipped, never fatal.
    """
    root = resolve_oss_fuzz_dir(str(oss_fuzz_dir) if oss_fuzz_dir else None)
    if root is None:
        logger.warning("No google/oss-fuzz checkout found. Clone it or set CLEARWING_OSS_FUZZ_DIR.")
        return []

    projects_dir = root / DEFAULT_CORPUS_SUBDIR
    out: list[CorpusProject] = []
    for entry in sorted(projects_dir.iterdir()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        yaml_path = entry / "project.yaml"
        if not yaml_path.exists():
            continue
        try:
            project = load_project_yaml(yaml_path)
        except Exception as exc:
            logger.debug("Skipping %s: %s", entry.name, exc)
            continue
        if language and project.language != language.lower():
            continue
        if sanitizer and sanitizer not in project.sanitizers:
            continue
        cp = CorpusProject(name=entry.name, project_dir=entry, project=project)
        if require_build_sh and not cp.has_build_sh:
            continue
        out.append(cp)

    logger.info("Loaded %d corpus projects from %s", len(out), projects_dir)
    return out
