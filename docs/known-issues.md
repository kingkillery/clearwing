# Known issues

Tracked defects that haven't been fixed yet. (GitHub Issues are disabled
on this repo; this file is the tracker.)

## Open

(none)

## Fixed

### Host-mode hunters can get stuck on sandbox-only tool calls

**Fixed in this change.** When `sandbox is None` (Docker unavailable),
`build_hunter_agent` and `build_subsystem_hunter_agent` now register the
static-only tool set (`build_static_only_tools`: read_source_file,
list_source_tree, grep_source, find_callers, record_finding [+ pool
query]) instead of sandbox-backed tools that only returned
`"no sandbox available"`. Effective `NativeHunter.agent_mode` becomes
`"constrained"` so repeat-throttling applies; branch step limits are
unchanged. Specialist deep-mode hunts no longer get the
"full shell access" deep prompt — they get the static prompt plus
`STATIC_ONLY_BLOCK` naming exactly the tools available, with
entry-point/seed/pool context blocks preserved. Unknown-tool errors now
list the registered tool names so a hallucinated call recovers in one
step instead of looping.

**Tests:** `tests/test_host_static_fallback.py` (12 tests: both agent
modes, subsystem hunter, propagation unchanged, prompt claims absent,
entry-point context preserved, unknown-tool recovery). Existing tests
that asserted sandbox tools with `sandbox=None` now pass a mock sandbox.

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
