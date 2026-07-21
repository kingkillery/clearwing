"""OSS-Fuzz project format + OSS-CRS-style build/crash/patch plumbing.

This package adopts the OSS-Fuzz project format (``project.yaml`` +
``Dockerfile`` + ``build.sh``) as Clearwing's canonical fuzz-target
description, and implements the hardened build → fuzz → dedup →
patch-validate loop that the DARPA AIxCC cyber-reasoning systems
(Buttercup, Atlantis, OSS-CRS) proved out in competition.

Modules:
    project    — OSS-Fuzz project model, triple rendering, corpus loading
    builder    — base-builder container builds (the ``$SRC/$OUT/$WORK`` contract)
    runner     — fuzzer execution, crash artifact collection, crash replay
    crashes    — sanitizer report parsing, ClusterFuzz-style signature dedup,
                 conversion to the canonical ``Finding`` type
    patchcheck — Buttercup-style patch validation (reproduce → patch →
                 rebuild → confirm the crash is gone), fail-closed
    bridge     — adapters into sourcehunt shapes (``SeededCrash``/``Finding``)
"""

from .project import (
    CorpusProject,
    OssFuzzProject,
    load_oss_fuzz_corpus,
    load_project_yaml,
    resolve_oss_fuzz_dir,
    scaffold_project,
)

__all__ = [
    "CorpusProject",
    "OssFuzzProject",
    "load_oss_fuzz_corpus",
    "load_project_yaml",
    "resolve_oss_fuzz_dir",
    "scaffold_project",
]
