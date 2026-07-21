# OSS-Fuzz integration

Clearwing adopts the **OSS-Fuzz project format** as its canonical fuzz-target
description and implements the build → fuzz → dedup → patch-validate loop
that the DARPA AIxCC cyber-reasoning systems (Buttercup, Atlantis,
[OSS-CRS](https://github.com/oss-crs/oss-crs)) proved out in competition —
on Clearwing's own sandbox substrate, with results landing on the canonical
evidence ladder.

Two things fall out of adopting the format:

1. **Portability.** A project Clearwing scaffolds can be upstreamed to
   [google/oss-fuzz](https://github.com/google/oss-fuzz), and any of the
   1,000+ projects there can be consumed by Clearwing.
2. **A massive target corpus.** Point Clearwing at a local `google/oss-fuzz`
   checkout and every project in it becomes a hunt/bench target.

## The project format

An OSS-Fuzz project is three files in one directory:

```
projects/<name>/
├── project.yaml   # metadata: language, sanitizers, main_repo, contacts
├── Dockerfile     # FROM gcr.io/oss-fuzz-base/base-builder; fetch source
└── build.sh       # compile with $CC $CFLAGS, link $LIB_FUZZING_ENGINE → $OUT
```

`clearwing.ossfuzz.project.OssFuzzProject` models `project.yaml` (unknown
upstream keys survive a load→save round-trip), renders the Dockerfile and
build.sh, and scaffolds the triple:

```bash
clearwing ossfuzz scaffold myproj --language c \
    --repo https://github.com/example/myproj --out ./projects
```

## The corpus

Clone google/oss-fuzz once and list what you can hunt:

```bash
git clone --depth 1 https://github.com/google/oss-fuzz ~/.clearwing/oss-fuzz
clearwing ossfuzz list --language c --sanitizer address
```

Resolution order for the checkout: `--oss-fuzz-dir` →
`CLEARWING_OSS_FUZZ_DIR` env → `~/.clearwing/oss-fuzz`.

## Build: the $SRC/$OUT/$WORK contract

`OssFuzzBuilder` runs `build.sh` inside a `base-builder` container with the
full OSS-Fuzz env contract (`$SRC`, `$OUT`, `$WORK`, `$CC/$CXX`,
`$CFLAGS/$CXXFLAGS`, `$LIB_FUZZING_ENGINE`, `$SANITIZER`). Sanitizer flags
come from the same `compute_sanitizer_env` the hunter sandbox uses — one
place in the codebase knows what `-fsanitize=...` means.

Isolation properties inherited from `clearwing.sandbox`:

- The host checkout is mounted **read-only** and copied in-container; the
  build (and any patch application) can never dirty it.
- Network is **none** by default (flipped to bridge automatically when
  `apt_packages` are requested, e.g. for corpus projects whose Dockerfile
  installs extra deps).
- Builds are bounded: memory limit, exec timeout, disposable container.

```bash
clearwing ossfuzz build ./projects/myproj --source ./myproj --out ./out \
    --sanitizer address
```

## Fuzz: artifact-first crash collection

`FuzzRunner` executes a built fuzzer with a bounded `-max_total_time`,
collects libFuzzer artifacts (`crash-*`, `oom-*`, `timeout-*`) to a host
crashes dir, confirms each with an in-container replay, and dedups on a
ClusterFuzz-style signature (sanitizer + crash type + top-3 normalized
frames — addresses and container paths stripped):

```bash
clearwing ossfuzz fuzz ./out --fuzzer fuzz_parse --seconds 300 \
    --corpus ./corpus --project myproj --findings-json findings.json
```

`--findings-json` converts unique crashes to canonical `Finding` records at
**`crash_reproduced`** — the evidence level the sourcehunt exploiter stage
gates on — with the sanitizer report as `crash_evidence`, the reproducer as
`poc`, CWE inferred from the crash type, and the top in-project frame as
file/line.

## Patch validation (Buttercup-style)

`clearwing ossfuzz check-patch` validates a candidate fix the way
Buttercup's patch-validation stage does, fail-closed:

1. **Reproduce** — the crash input must crash the unpatched build with its
   original signature (no reproduction → nothing can be proven).
2. **Patch** — the diff is applied with `patch -p1` inside the build
   container's staged copy (host tree untouched).
3. **Rebuild** — same `build.sh`, same sanitizer.
4. **Confirm** — replay the same input. Crash gone → **validated**. The
   same signature surviving → not validated. A *different* signature
   appearing → flagged as "the fix may have moved the bug".

```bash
clearwing ossfuzz check-patch ./projects/myproj --source ./myproj \
    --diff ./fix.patch --crash ./out/crashes/fuzz_parse/crash-ab12 \
    --fuzzer fuzz_parse
```

Exit code is 0 only when the patch validates, so this drops straight into
CI gates.

## One-shot runs

`clearwing ossfuzz run` chains build → fuzz (all built fuzzers, or
`--fuzzer`) → findings JSON:

```bash
clearwing ossfuzz run ./projects/myproj --source ./myproj --seconds 300 \
    --work-dir ./results/ossfuzz/myproj
```

## Bridge into sourcehunt

`clearwing.ossfuzz.bridge` adapts fuzz results into pipeline shapes:

- `fuzz_run_to_findings(...)` → `Finding` objects at `crash_reproduced`,
  ready for the shared findings pool, adversarial verifier, and exploit
  triage.
- `fuzz_run_to_seeded_crashes(...)` → dicts shaped like the deep-depth
  `HarnessGenerator`'s `SeededCrash`, so hunter agents get the "explain
  this crash" prompt fed by real fuzzing instead of one-shot harness
  compiles.

Programmatic use:

```python
from clearwing.ossfuzz.builder import BuildConfig, OssFuzzBuilder
from clearwing.ossfuzz.runner import FuzzConfig, FuzzRunner
from clearwing.ossfuzz.bridge import fuzz_run_to_findings
from clearwing.ossfuzz.project import load_project_yaml

project = load_project_yaml("./projects/myproj")
build = OssFuzzBuilder(BuildConfig(sanitizer="address")).build(
    project, "./projects/myproj", "./myproj", "./out",
)
result = FuzzRunner(FuzzConfig(max_total_time_seconds=300)).fuzz(
    "./out", build.fuzzer_binaries[0],
)
findings = fuzz_run_to_findings(result, project_name=project.name)
```

## Scope notes

- Builds use **base-builder + build.sh**, not the project Dockerfile.
  Corpus projects whose Dockerfile installs extra packages need
  `--apt pkg1 pkg2` on the build command.
- C/C++ are first-class (libFuzzer engine, sanitizer flags). Other
  languages map to their OSS-Fuzz base-builder images but the flag/env
  contract is C/C++-oriented in v1 — same scoping as the existing
  HarnessGenerator.
- Fuzzing runs default to `gcr.io/oss-fuzz-base/base-runner` (small,
  sanitizer runtimes only); override with `--image`.
