---
phase: 05-theme-parity-analytics-experience
plan: 01
subsystem: ui
tags: [flask, playwright, sqlite, worker-heartbeat, safety-banner, dual-theme]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: freshness_state() four-tier classifier and the compose_pipeline_diagnosis worker payload
provides:
  - "worker_heartbeat_cadence_seconds(settings) and worker_freshness(now, heartbeat_ts, settings) in dashboard/beacon/diagnosis.py — the one shared classifier both diagnosis surfaces call"
  - "safety.worker_degraded on /api/advanced/current, additive alongside the unchanged safety.worker_stale"
  - "/api/scan-status worker_freshness (full three-tier object) and worker_degraded (aging and not worker_stale) fields"
  - "#degraded-warning banner, byte-identical copy, in both dashboard/index.html and dashboard/advanced.html, wired from the new field only"
  - ".degraded-warning / .degraded-warning[hidden] in style.css, distinguished from .recovery-warning by the absence of a border rather than by hue"
  - "First dual-theme, unstubbed, real-database end-to-end test proving a real aging heartbeat raises the banner on both documents in both themes"
affects: [05-02, 05-05]

# Actuals (#2632)
actuals:
  tokens: 4534
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Single shared server-side classifier extracted from an existing inline computation, called from every surface that needs it (worker_heartbeat_cadence_seconds / worker_freshness), rather than a second threshold"
    - "Global safety-banner cluster extended by appending a fourth `.safety-warning` member, driven by one server-emitted boolean, with hidden toggled and nothing else"
    - "Non-hue disambiguation between two --accent2 banners via border presence/absence (A-05)"

key-files:
  created: []
  modified:
    - dashboard/beacon/diagnosis.py
    - dashboard/app.py
    - dashboard/index.html
    - dashboard/advanced.html
    - dashboard/style.css
    - dashboard/app.js
    - dashboard/advanced.js
    - tests/test_advanced_diagnosis_api.py
    - tests/test_api_and_auth.py
    - tests/test_ui_safety_integration.py

key-decisions:
  - "worker_heartbeat_cadence_seconds and worker_freshness sit beside freshness_state in diagnosis.py, called from both compose_pipeline_diagnosis and dashboard/app.py's api_scan_status — no second cadence lookup, no second age-threshold comparison"
  - "/api/scan-status publishes the full worker_freshness object as the primary representation (A-03) and worker_degraded as a derived convenience boolean guarded by `not worker_stale` (A-04), so an operator-configured WORKER_READY_SECONDS below 4x cadence can never make the page assert both conditions about one heartbeat"
  - ".degraded-warning carries no border property at all, where .recovery-warning keeps border-bottom — the two --accent2 banners stay distinguishable by shape, not hue (A-05)"
  - "Re-seed the end-to-end test's heartbeat against a freshly read clock immediately before each of the four (theme, path) subtests, rather than once before the loop — self.now is captured in setUp before the Playwright/Chromium launch, and under full-suite load that latency plus four sequential real browser navigations can drift the heartbeat out of the aging tier before the last subtest runs"

patterns-established:
  - "Server classifies, client renders: a new safety fact reaches the browser as a literal field toggling hidden; JavaScript never recomputes an age threshold"

requirements-completed: [UX-07, OPS-06]

coverage:
  - id: D1
    description: "One shared worker-freshness classifier (worker_heartbeat_cadence_seconds, worker_freshness) computes the tier once; both compose_pipeline_diagnosis and /api/scan-status call it, and worker_stale/worker_degraded can never both be true for the same heartbeat"
    requirement: "OPS-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_worker_freshness_is_one_shared_classification_for_both_surfaces"
        status: pass
      - kind: integration
        ref: "tests/test_api_and_auth.py#test_scan_status_never_reports_degraded_and_stale_together"
        status: pass
    human_judgment: false
  - id: D2
    description: "Both documents render one identically-worded, unboxed #degraded-warning banner as the fourth member of the safety-warning cluster, driven only by the server field"
    requirement: "UX-07"
    verification:
      - kind: e2e
        ref: "tests/test_ui_safety_integration.py#test_degraded_banner_reads_identically_in_both_themes_on_both_documents"
        status: pass
    human_judgment: false
  - id: D3
    description: "A real aging heartbeat in a real SQLite database drives the degraded banner through an unstubbed Flask app in both dark and light themes, on both / and /advanced, with the recovery/worker banners staying hidden and the two --accent2 banners staying distinguishable by border shape"
    requirement: "OPS-06"
    verification:
      - kind: e2e
        ref: "tests/test_ui_safety_integration.py#test_degraded_banner_reads_identically_in_both_themes_on_both_documents"
        status: pass
      - kind: e2e
        ref: "tests/test_ui_safety_integration.py#test_stale_heartbeat_shows_worker_banner_and_not_the_degraded_banner"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-08-27
status: complete
---

# Phase 5 Plan 01: Worker-Freshness Degraded State Tracer Summary

**One shared server-side worker-freshness classifier now emits a `degraded` fact both diagnosis surfaces publish, rendered as an identically-worded, unboxed safety banner in both dashboard documents and both themes, proven end-to-end against a real SQLite heartbeat with no stubbed route.**

## Performance

- **Duration:** 55 min
- **Started:** 2026-08-27T12:17:00Z (approx.)
- **Completed:** 2026-08-27T13:12:22Z
- **Tasks:** 3
- **Files modified:** 10

## Accomplishments
- Extracted `worker_heartbeat_cadence_seconds(settings)` and `worker_freshness(now, heartbeat_ts, settings)` in `dashboard/beacon/diagnosis.py`, called from both `compose_pipeline_diagnosis` and `/api/scan-status` — a single classifier, not a second threshold
- `safety.worker_degraded` (advanced payload) and `worker_freshness`/`worker_degraded` (`/api/scan-status`) are additive: every existing field and consumer is unchanged, and the two payloads can never assert `stale` and `degraded` about the same heartbeat
- `#degraded-warning` appended as the fourth, byte-identical, unboxed banner in both `dashboard/index.html` and `dashboard/advanced.html`, wired from `updateScanStatus` (`app.js`) and `renderSafety` (`advanced.js`)
- `.degraded-warning` in `style.css` carries no border, distinguishing it from `.recovery-warning`'s `border-bottom` by shape rather than hue
- A real, unstubbed end-to-end Playwright test drives a genuine SQLite heartbeat into the `aging` tier through the real Flask app and asserts the banner text, exclusivity, border shape, and per-theme color re-resolution across all four `(theme, path)` combinations

## Task Commits

Each task was committed atomically:

1. **Task 1: One shared worker-freshness classification, emitted by both surfaces** - `5722047` (feat)
2. **Task 2: The degraded banner — one form, two documents, both themes** - `12a8fc0` (feat)
3. **Task 3: End-to-end proof — a real aging heartbeat raises the banner in both themes** - `c4c3d40` (test)

_Note: Task 1 is `type="tracer"` — a real, production-quality implementation with real `<verify>`, not a throwaway slice._

## Files Created/Modified
- `dashboard/beacon/diagnosis.py` - `worker_heartbeat_cadence_seconds`, `worker_freshness`, `safety.worker_degraded`
- `dashboard/app.py` - `/api/scan-status` `worker_freshness`/`worker_degraded` fields
- `dashboard/index.html`, `dashboard/advanced.html` - `#degraded-warning` banner markup, byte-identical
- `dashboard/style.css` - `.degraded-warning` / `.degraded-warning[hidden]`, no border
- `dashboard/app.js`, `dashboard/advanced.js` - toggle `#degraded-warning.hidden` from `worker_degraded`
- `tests/test_advanced_diagnosis_api.py` - shared-classifier and four-tier regression coverage
- `tests/test_api_and_auth.py` - overlapping-`WORKER_READY_SECONDS` never-both-true regression
- `tests/test_ui_safety_integration.py` - dual-theme, dual-document, unstubbed end-to-end proof

## Decisions Made
- `worker_freshness`/`worker_heartbeat_cadence_seconds` placed beside `freshness_state` in `diagnosis.py`, following the plan's read-first analog exactly (05-PATTERNS.md "Server classifies, client renders")
- `/api/scan-status` publishes the full `worker_freshness` object as primary representation per assumption A-03, with `worker_degraded` derived and guarded by `not worker_stale` per A-04
- `.degraded-warning` intentionally carries zero border declarations (A-05) — verified both statically (`grep`) and dynamically (`getComputedStyle(...).borderBottomStyle === 'none'`)
- End-to-end test re-seeds the heartbeat against a freshly read clock immediately before each subtest rather than once before the loop, after a full-suite run revealed the original single up-front seed could drift past the aging/stale boundary under Playwright/Chromium launch latency (see Deviations)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] End-to-end test's heartbeat drifted into the wrong tier under full-suite load**
- **Found during:** Task 3, full-suite verification (`uv run --project dashboard python -m pytest -q`)
- **Issue:** The initial implementation seeded the aging heartbeat once, using `self.now` (captured in `setUp` before the Playwright/Chromium launch) and `2 * cadence` age, then ran four sequential real browser navigations. Under full-suite resource contention this took long enough that the heartbeat's real age crossed the `aging`→`stale` boundary before some subtests' assertions ran, so `#degraded-warning` never became visible: 3 of 4 subtests timed out waiting for it, and the isolated single-file run (`pytest tests/test_ui_safety_integration.py`) passed cleanly, masking the defect until the full suite ran.
- **Fix:** Moved heartbeat seeding into a `seed_aging_heartbeat()` helper called immediately before each subtest's `page.goto`, using a freshly read `int(time.time())` each time instead of the stale `self.now`.
- **Files modified:** tests/test_ui_safety_integration.py
- **Verification:** `uv run --project dashboard python -m pytest tests/test_ui_safety_integration.py -q` (3 passed, 4 subtests passed) and two full-suite runs (`uv run --project dashboard python -m pytest -q`), the second with zero failures from this test
- **Committed in:** c4c3d40 (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary for a reliable, non-flaky end-to-end proof under real full-suite conditions. No scope creep — the fix is confined to the new test's own heartbeat-seeding mechanics.

## Issues Encountered
- A pre-existing, unrelated flake surfaced while running the full suite twice for verification: `tests/test_runtime_ownership.py::RuntimeOwnershipTests::test_lease_takeover_records_one_monitoring_gap` fails intermittently in the full suite (`AssertionError: 0 != 1`) but passes reliably in isolation. This test does not touch `diagnosis.py`, `worker_freshness`, or any file this plan modified — confirmed out of scope per the deviation rules' scope boundary. Logged to `.planning/phases/05-theme-parity-analytics-experience/deferred-items.md` (row 1) and `.planning/WINDOWS.md` (entry 17, kind `deviation`), not fixed.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The shared `worker_heartbeat_cadence_seconds`/`worker_freshness` classifier and the `.safety-warning` cluster's fourth-member pattern are now proven end-to-end; plans 05-02 and 05-05 (which also declare UX-07) can build on this spine without re-discovering the server→wire→render→theme→test seam.
- `UX-07` and `OPS-06` are NOT marked complete in `REQUIREMENTS.md` — `requirements.ready-ids` confirmed 0/2 ready, since sibling plans 05-02 through 05-06 also declare these IDs and have not yet produced their own `*-SUMMARY.md`. This plan's `requirements-completed` frontmatter records its own contribution only; the checkbox flips once the last declaring plan finishes.
- No blockers for the remaining Phase 5 plans.

## Self-Check: PASSED

All created/modified files and all commit hashes referenced above verified present:
- `dashboard/beacon/diagnosis.py`, `.planning/phases/05-theme-parity-analytics-experience/05-01-SUMMARY.md`, `.planning/phases/05-theme-parity-analytics-experience/deferred-items.md` — found
- Commits `5722047`, `12a8fc0`, `c4c3d40`, `c160e6d` — found in `git log --oneline --all`

---
*Phase: 05-theme-parity-analytics-experience*
*Completed: 2026-08-27*
