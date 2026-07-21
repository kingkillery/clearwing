# Known issues

Tracked defects that haven't been fixed yet. (GitHub Issues are disabled
on this repo; this file is the tracker.)

## Open

### 1. Host-mode hunters can get stuck on sandbox-only tool calls

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

### Sourcehunt budget cap is not enforced globally

**Fixed in this change.** `HunterPool._run_tier_phase` now
gates dispatch on `spent + reserved`, not `spent` alone: each submitted
hunter reserves `min(band_cap, remaining / divisor)` where
`divisor = min(available_slots, unsubmitted_items)`, so a full wave of
`max_parallel` hunters cannot collectively commit more than the remaining
budget before any result lands. Reservations are stored per-task and
released on completion/cancel/timeout (timeout now cancels **and awaits**
in-flight tasks before returning). Band caps (`BandBudget`) keep their
per-run semantics; the global cap is enforced only through reservations.

**Residual risk (by design):** a hunter checks cost only *before* each LLM
call, so one already-in-flight call can overrun its reservation. This is
detected (`overspent its reservation` WARNING) and stops all further
dispatch, but the overshoot itself — bounded by one LLM call per
in-flight hunter — still bills. A truly hard dollar cap would need
call-level token limiting in the provider layer.

**Tests:** `tests/test_sourcehunt_pool_budget.py::TestReservationHardCap`
(parallel wave can't exceed budget, slot shares shrink, breach halts
dispatch).

### record_finding dropped findings without a CWE

**Fixed in `d824aff`.** `record_finding` required `cwe` positionally and
the schema marked it required; lenient models omit it, the call failed,
and the finding was silently lost. `cwe` is now optional in the
signature and schema (`tests/test_hunt_reporting.py` pins it).
