---
phase: 03-advanced-current-diagnosis
plan: 11
subsystem: ui
tags: [advanced-workspace, services-table, absent-vs-zero, playwright, gap-closure]
status: complete

requires:
  - "dashboard/advanced.js::displayValue (03-04, the string half of this codebase's absent-value rule)"
  - "dashboard/advanced.js::stableServiceSort / renderServices (03-04 services renderer)"
  - "dashboard/advanced.js::state.serviceSort persistence (03-09, the operator's chosen order)"
  - "tests/test_advanced_ui.py::AdvancedUiTests (werkzeug live server + Chromium, production /advanced route)"
  - ".planning/phases/03-advanced-current-diagnosis/03-VERIFICATION.md (Gap A, missing bullets 1 and 3)"
provides:
  - "dashboard/advanced.js::finiteMeasurement — the numeric sibling of displayValue: null/undefined/'' reject before any coercion"
  - "An offline service renders its failure class in the latency/failure column instead of a fabricated 0 ms"
  - "An unknown service with no failure class and no last error renders the workspace's explicit Unknown copy"
  - "An unmeasured latency ranks as POSITIVE_INFINITY, so ascending sort places it after every real measurement"
  - "An unestablished state_duration_seconds renders Unknown duration instead of 0 seconds"
  - "tests/test_advanced_ui.py::UNMEASURED_SERVICES + _unmeasured_services_page + live-DOM cell/order readers"
  - "Two browser regressions locking the corrected cells and ranking on the production /advanced route"
affects:
  - "03-13 (collection_gaps server population — the remaining half of Gap A)"
  - "03-14 (DIA-03 traceability reconciliation, which depends on this and 03-13)"
  - "Any later plan touching the services renderer or its sort keys"

actuals:
  tokens: 27164
  tasks: 2
  commits: 4

tech-stack:
  added: []
  patterns:
    - "Absent-versus-zero is one shared module-local rule, never repeated per call site"
    - "Reject null/undefined/empty BEFORE Number(), because Number(null) === 0 passes Number.isFinite"
    - "An unmeasured value ranks as an extreme (POSITIVE_INFINITY), never as zero"
    - "Renderer contracts are asserted against the live DOM on the production route, never against a helper in isolation"

key-files:
  created: []
  modified:
    - dashboard/advanced.js
    - tests/test_advanced_ui.py

key-decisions:
  - "finiteMeasurement performs no rounding, clamping, or sign check — callers keep their own domain guards, so a genuine 0 ms measurement stays distinguishable from an absent one"
  - "serviceDuration keeps its >= 0 guard layered on top of the shared helper rather than folding it in"
  - "The latency sort ties two unmeasured services at Infinity; Infinity - Infinity is NaN, which is falsy, so the existing left.index - right.index tiebreak keeps them deterministically ordered"
  - "DIA-03 was deliberately NOT marked Complete: this plan closes Gap A missing-bullets 1 and 3 only; collection_gaps (bullet 2) is deferred to 03-13 and reconciliation to 03-14"
  - "The pre-existing latency_ms: None fixtures at tests/test_advanced_ui.py:417 and :872 were left in place — their own tests cover other contracts"

patterns-established:
  - "finiteMeasurement is the numeric counterpart to displayValue; new numeric server fields read through it"
  - "UNMEASURED_SERVICES is the canonical fixture for absent-versus-zero services coverage"
  - "_service_row_cells reads th+td together, matching the documented column order (identity is a th scope=row)"

requirements-completed: []

coverage:
  - id: D1
    description: "An offline service carrying a failure class renders that failure class in the latency/failure column of the production /advanced route; an unknown service with no failure class and no last error renders explicit Unknown copy; a genuine 0 ms measurement still renders as a measurement"
    requirement: "DIA-03"
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_unmeasured_service_shows_its_failure_class_instead_of_a_fabricated_latency"
        status: pass
    human_judgment: false
  - id: D2
    description: "An ascending latency sort ranks every unmeasured service after every measured one (zero first) and descending ranks them first; an unestablished state duration reads Unknown duration; the operator's latency sort, its aria-sort, and the Reset control survive an automatic poll"
    requirement: "DIA-03"
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_unmeasured_latency_and_duration_never_rank_or_read_as_zero"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_service_sort_survives_automatic_poll_and_manual_refresh"
        status: pass
    human_judgment: false
  - id: D3
    description: "On the target Pi, the services table shows an operator why a service is down rather than a latency it never had"
    requirement: "DIA-03"
    verification: []
    human_judgment: true
    rationale: "Operator trust in the rendered snapshot on real hardware cannot be asserted programmatically; collected at the end-of-phase human checkpoint per workflow.human_verify_mode."

duration: 8min
completed: 2026-08-19
---

# Phase 03 Plan 11: Services Absent-vs-Zero Fabrication Summary

**One shared `finiteMeasurement` rule now rejects `null` before coercion at all three services coercion sites, so an offline service shows `ConnectionRefused` instead of a fabricated `0 ms`, an unmeasured latency sorts last instead of fastest, and an unestablished state duration reads `Unknown duration`.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-08-19T05:43:00Z
- **Completed:** 2026-08-19T05:51:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added `dashboard/advanced.js::finiteMeasurement`, the numeric sibling of `displayValue`: it returns `null` for `null`, `undefined` and `''` **before** any `Number()` call, then returns the coerced value only when `Number.isFinite` holds. This is the single rule the three former coercion sites now derive from.
- Made the `03-UI-SPEC.md:118` / D-07 failure-class fallback reachable from a real server payload for the first time. The server sets `latency_ms=None` for every non-online service by construction, so `Number(null) === 0` meant every offline and unknown row reported `0 ms` beside a red offline marker and the fallback was dead code.
- Made the `Number.POSITIVE_INFINITY` unmeasured branch of the latency sort key reachable, so a broken service is no longer ranked the fastest thing on the Pi under an ascending latency sort.
- Made `formatDuration`'s existing `Unknown duration` branch reachable through `serviceDuration`, so an unestablished state duration is no longer reported as a definite `0 seconds`.
- Added two browser regressions that drive the **production `/advanced` route** through the live werkzeug server and Chromium and read the rendered cells and row order from the live DOM — the same shape the verifier used to reproduce the defect. Both were written failing first and reproduced the verifier's exact evidence (`'ConnectionRefused' not found in '0 ms'`, and ascending order `['9090','7070','8081','8080']`).

## Task Commits

Each task was committed atomically (TDD: test → feat):

1. **Task 1 (tracer): One absent latency, end to end, rendered as its failure class in a real browser**
   - `7af2b67` (test) — `UNMEASURED_SERVICES` fixture, `_unmeasured_services_page`, live-DOM cell readers, failing assertion
   - `001542a` (feat) — `finiteMeasurement` helper + latency cell branching on a strict `null`
2. **Task 2: Expand the same rule to the latency sort key and the state-duration reader**
   - `c81d7d2` (test) — failing rank/duration/sort-survival regression
   - `12989c8` (feat) — `stableServiceSort` latency branch + `serviceDuration` both read through the helper

## Files Created/Modified

- `dashboard/advanced.js` — added `finiteMeasurement` beside `displayValue`; rewrote the `renderServices` latency cell, the `stableServiceSort` latency key, and `serviceDuration` to derive from it. No column order, element type, `textContent` write, comparison logic, direction multiplier, or index tiebreak was changed. `formatDuration` untouched.
- `tests/test_advanced_ui.py` — added `UNMEASURED_SERVICES` (offline+failure class, unknown+no evidence, 12 ms, genuine 0 ms), `_unmeasured_services_page`, `_service_row_cells` / `_service_latency_cell` / `_service_duration_cell` / `_service_port_order`, and the two regressions.

## Decisions Made

- **`finiteMeasurement` does no rounding, clamping or sign check.** Callers keep their own domain guards. This is what keeps a genuine `0 ms` measurement (port 8081 in the fixture) a measurement rather than collapsing it into the absent case — the exact confusion this gap was made of.
- **`serviceDuration` keeps its `>= 0` guard layered on top** of the helper rather than pushing the guard into the shared rule, so the rule stays a pure absent-vs-present question.
- **Two unmeasured services tie at `Infinity`.** `Infinity - Infinity` is `NaN`, which is falsy, so control reaches the existing `left.index - right.index` tiebreak — unmeasured services keep a deterministic, stable relative order in both directions. This is asserted in the descending branch of the new test and is the mechanism behind the plan's `adjacency` backstop truth.
- **Cell readers use `th, td` together.** The identity cell is a `th scope="row"`, so a `td`-only selector silently shifts every column index by one; the first RED run surfaced this by returning the duration cell.

## Deviations from Plan

### 1. [Judgment — honesty prohibition] DIA-03 was NOT marked Complete

- **Found during:** State updates after Task 2.
- **Issue:** The standard executor state step marks every requirement in the plan's `requirements:` frontmatter complete. This plan lists `DIA-03`, but it closes only Gap A `missing` bullets 1 and 3. Bullet 2 (`service['collection_gaps']` is a hardcoded empty list rendered as the literal string `[]`) is explicitly **DEFERRED to plan 03-13** by this plan's own `<gap_coverage>` table, and 03-VERIFICATION.md requires DIA-03 to stay off `Complete` "until the Services fabrication gap is closed **and re-verified**".
- **Fix:** `requirements.mark-complete` was not run. `.planning/REQUIREMENTS.md:130` correctly remains `| DIA-03 | Phase 3 | Gaps Found |`, and `requirements-completed` in this summary is `[]`.
- **Rationale:** Flipping DIA-03 to `Complete` here would be exactly the prohibition this plan exists to enforce — presenting a status derivable from no completed evidence. 03-14 owns the reconciliation once 03-13 lands.

### 2. [Process] Tracer feedback gate resolved automatically rather than as an interactive checkpoint

- **Found during:** End of Task 1.
- **Issue:** The tracer gate normally emits a `checkpoint:human-verify` in an interactive run.
- **Fix:** The tracer's `<verify>` was re-run end to end and passed (`ONE_ABSENT_VALUE_RULE`), then execution continued to the expansion task. The plan declares `autonomous: true`, contains no `checkpoint:*` task, and the workspace runs `human_verify_mode: end-of-phase`, so the human judgment for this surface (D3 above) is collected at the phase checkpoint rather than mid-plan.

**Total deviations:** 2 (1 honesty-driven omission, 1 process). No auto-fixed bugs — the plan's pinned counts and line references all matched the live tree.
**Impact on plan:** None on scope. Every `<action>` instruction was followed literally.

## Verification Evidence

- `uv run --project dashboard python -m pytest tests/test_advanced_ui.py -k unmeasured_service_shows_its_failure_class -q` → **1 passed**
- `uv run --project dashboard python -m pytest tests/test_advanced_ui.py -k 'unmeasured_latency_and_duration or service_sort_survives or deliberate_controls_still_clear' -q` → **3 passed**
- `grep -c 'function finiteMeasurement' dashboard/advanced.js` → `1`
- `grep -c 'finiteMeasurement(service.latency_ms)' dashboard/advanced.js` → `2`
- `grep -c 'finiteMeasurement(service.state_duration_seconds)' dashboard/advanced.js` → `1`
- `uv run --project dashboard python -m pytest tests/test_advanced_ui.py -q` → **31 passed, 55 subtests passed**
- `uv run --project dashboard python -m pytest -q` → **283 passed, 369 subtests passed** (was 281 / 369 — exactly the two new regressions, no subtest change, no regression)

### Plan-pinned counts checked before editing

Every count and line reference the plan pinned against the live tree matched: `Number(service.latency_ms)` at the latency cell and at the sort key, `Number(service.state_duration_seconds)` in `serviceDuration`, the `th`-based row identity, and the existing `SORTABLE_SERVICES` / `_await_new_snapshot` helpers. Nothing had drifted.

## Issues Encountered

- The first RED run returned `'0 seconds'` rather than `'0 ms'` for the latency cell, because `row.locator('td')` skips the `th scope="row"` identity cell and shifts every index by one. Fixed by selecting `th, td` so the reader's indices match the documented column order in `advanced.html`. The corrected RED then reproduced the verifier's evidence exactly.

## Known Stubs

None introduced. The pre-existing `JSON.stringify(service.collection_gaps || ...)` hollow-prop at `dashboard/advanced.js:648` and the hardcoded `'collection_gaps': []` at `dashboard/beacon/diagnosis.py:167` are untouched and remain open — they are Gap A `missing` bullet 2, owned by plan 03-13.

## Threat Flags

None. No new network endpoint, auth path, file access pattern, or schema change. The failure-class and last-error strings newly reaching the latency cell (T-03-70) are already server-emitted, already rendered in the expanded detail row, and are written with `textContent`, so no markup is interpreted. No dependency was added, removed, or upgraded.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- The blocking half of Gap A is closed and locked by real-browser regressions.
- **Still open for Phase 3:** 03-12 (worker job health `succeeded` bookkeeping), 03-13 (`collection_gaps` server population — Gap A bullet 2), 03-14 (REQUIREMENTS.md reconciliation, which must wait on 03-13).
- DIA-03 remains `Gaps Found` by design and must not be promoted until 03-13 lands and the phase is re-verified.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-19*

## Self-Check: PASSED

- Files verified present: `dashboard/advanced.js`, `tests/test_advanced_ui.py`, `.planning/phases/03-advanced-current-diagnosis/03-11-SUMMARY.md`
- Commits verified in git history: `7af2b67`, `001542a`, `c81d7d2`, `12989c8`
