# Known issues

Tracked defects that haven't been fixed yet. (GitHub Issues are disabled
on this repo; this file is the tracker.)

## Open

### 1. Sourcehunt budget cap is not enforced globally

**Observed:** session `sh-70f0d515` (`--budget 5`, depth=standard)
finished with total spend **$13.58** — 2.7× the cap. Every hunter
reported `cost_limit=5.00` per file, but the pool kept dispatching.

**Details:** 22 hunter runs across 17 files; tier-A files were re-hunted
3–4× each (`auth.ts` ×4, `cli-mcp-adapter.ts` ×3, `device-registry.ts` ×3,
`directory-policy.ts` ×3, `directory-tools.ts` ×3, `index.ts` ×3).
`HunterPool` appears to gate only per-hunter `cost_limit`, never
cumulative pool spend.

**Questions:** Is `--budget` meant to be a hard global cap, per-file, or
advisory? If global, the pool must stop dispatching when cumulative spend
crosses the cap, and redundancy/band logic needs to account for
cumulative spend before re-hunting the same file.

**Until fixed:** treat `--budget` as a soft guideline; price runs from
the final Spend line, not the flag.

### 2. Host-mode hunters can get stuck on sandbox-only tool calls

**Observed:** with Docker unavailable, `HunterSandbox` falls back to host
mode, but at least one hunter (`src/types.ts`, session `sh-70f0d515`)
burned its steps on `read_file`/`execute` calls that all returned
`"no sandbox available"` — it never read the file and ended by trying to
record an `analysis_blocked` finding (which was itself dropped, see
Fixed below). Other hunters in the same session read files fine, so the
degradation is inconsistent — likely tool-name mismatch (hallucinated
`read_file`/`execute` vs. the actual host-fallback tools
`read_source_file`/`grep_source`) or a context that never got host
tools.

**Impact:** hunts without Docker can silently degrade file coverage.
**Until fixed:** start Docker for sanitizer-backed containers, or treat
sandbox-less runs as reduced-confidence.

## Fixed

### record_finding dropped findings without a CWE

**Fixed in `d824aff`.** `record_finding` required `cwe` positionally and
the schema marked it required; lenient models omit it, the call failed,
and the finding was silently lost. `cwe` is now optional in the
signature and schema (`tests/test_hunt_reporting.py` pins it).
