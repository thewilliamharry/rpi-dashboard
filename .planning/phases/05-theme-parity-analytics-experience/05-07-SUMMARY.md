---
phase: 05-theme-parity-analytics-experience
plan: 07
subsystem: ui
tags: [flask, playwright, sqlite, keyboard-accessibility, safety-banners]

# Dependency graph
requires:
  - phase: 05-theme-parity-analytics-experience
    provides: "05-01's shared worker-freshness classifier and dual-banner safety surface; 05-04's keyboard range-anchor gesture and shared applySelectedRange; 05-05's advanced.js render path"
provides:
  - "A mouse drag (commit, Escape, or pointercancel) always abandons a pending keyboard range anchor, so a stale anchor can never apply a range from a plain Enter on an unrelated point"
  - "worker_degraded is false whenever recovery_required is true, on both /api/scan-status and /api/advanced/current's safety block, so the operator never sees the reassuring degraded banner beside the paused-monitoring recovery banner"
affects: [05-theme-parity-analytics-experience]

# Actuals (#2632)
actuals:
  tokens: 5668
  tasks: 3
  commits: 4

tech-stack:
  added: []
  patterns:
    - "Defense-in-depth anchor clearing: both the drag-entry call site (beginDragSelect) and the drag-exit call site (cancelDragSelect) independently clear pendingRangeAnchor, so no drag lifecycle path can leave a stale anchor"
    - "A synthetic pointercancel event (not Escape) is the confound-free way to test cancelDragSelect's own defensive behavior when a separate, unconditional window-level Escape listener already clears the same state"

key-files:
  created: []
  modified:
    - dashboard/advanced.js
    - dashboard/app.py
    - dashboard/beacon/diagnosis.py
    - tests/test_history_investigation_ui.py
    - tests/test_api_and_auth.py
    - tests/test_advanced_diagnosis_api.py
    - tests/test_ui_safety_integration.py

key-decisions:
  - "Test 2 (the cancelled-drag variant) could not use Escape as its abandonment vector, despite the plan's own idiom naming Escape: a pre-existing window-level listener (05-04 Task 3, A-22, bindTimeCursorHandlers) already unconditionally clears pendingRangeAnchor on every Escape keydown, independent of drag state. Using Escape would have passed whether or not cancelDragSelect's own defensive call existed, silently failing to reproduce the gap. Rewrote the test to dispatch a synthetic pointercancel event instead -- cancelDragSelect's own registered listener -- which exercises the exact call site with no confound."
  - "UX-06 and UX-07 are NOT marked complete in REQUIREMENTS.md by this plan. This project has repeated, explicit precedent (03-14, 03-17, 03-21, 03-22 decisions) that a gap-closure round's own implementation claim is insufficient evidence to promote a requirement it closed -- only an independent verifier may promote. Left at Pending for 05-VERIFICATION.md's next round to decide, consistent with that precedent."

requirements-completed: []  # Deliberately empty -- see key-decisions. UX-06/UX-07 code-level gaps are closed and tests pass; promotion to Complete is deferred to independent re-verification.

coverage:
  - id: D1
    description: "A mouse drag (commit, or a drag abandoned mid-gesture) always abandons a pending keyboard range anchor, so a later plain Enter on an unrelated point applies no stale range"
    requirement: "UX-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py::HistoryInvestigationUiTests::test_mouse_drag_abandons_a_pending_keyboard_anchor_so_a_later_plain_enter_applies_nothing"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py::HistoryInvestigationUiTests::test_cancelled_mouse_drag_also_abandons_a_pending_keyboard_anchor"
        status: pass
    human_judgment: false
  - id: D2
    description: "worker_degraded is false whenever recovery_required is true, on both server safety surfaces, so a contradictory pair of safety banners can never render together"
    requirement: "UX-07"
    verification:
      - kind: e2e
        ref: "tests/test_ui_safety_integration.py::UiSafetyIntegrationTests::test_recovery_marker_with_aging_heartbeat_renders_only_the_recovery_banner_on_both_documents"
        status: pass
      - kind: integration
        ref: "tests/test_api_and_auth.py::ApiAndAuthTests::test_scan_status_never_reports_degraded_while_recovery_is_required"
        status: pass
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests::test_safety_never_reports_degraded_while_recovery_is_required"
        status: pass
    human_judgment: false

duration: ~40min
completed: 2026-08-27
status: complete
---

# Phase 05 Plan 07: Gap Closure — Keyboard Range Anchor Leak and Contradictory Safety Banners Summary

**Two RED-before-GREEN gap closures: `advanced.js` now clears a pending keyboard range anchor on every mouse-drag exit path, and `app.py`/`diagnosis.py` now gate `worker_degraded` on `not recovery_required` so the degraded and recovery banners can never render together.**

## Performance

- **Duration:** ~40 min
- **Completed:** 2026-08-27T20:50Z
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments

- Closed gap 1 (CR-01, blocks ROADMAP SC3 / UX-06): `beginDragSelect` now calls `cancelKeyboardRangeAnchor()` before un-hiding the drag overlay, and `cancelDragSelect` calls it defensively on every drag exit path (commit, Escape, pointercancel) — a pending keyboard anchor can no longer survive a mouse gesture and apply a stale range on a later plain Enter.
- Closed gap 2 (WR-01, blocks ROADMAP SC4 / UX-07): `api_scan_status`'s `worker_degraded` expression and `get_current_diagnosis`'s `safety['worker_degraded']` both now require `not recovery_required` in addition to their existing conjuncts — the operator can never see the reassuring degraded banner beside the paused-monitoring recovery banner about the same worker.
- Five new regression tests, each observed failing against the unfixed code before its fix commit, with full failure evidence recorded below.
- Zero regressions: the phase's own UI/safety surface (280 passed, 144 subtests, up from the 277/140 baseline) and the project-wide suite (776 passed, 552 subtests, up from the 771/548 baseline) both stay green.

## Task Commits

Each task was committed atomically:

1. **Task 1: A mouse gesture always abandons a pending keyboard range anchor (gap 1 / CR-01)**
   - `3330c37` (test) — reproduce the keyboard range-anchor leak across an intervening mouse drag
   - `f69fbb8` (fix) — abandon a pending keyboard range anchor on any mouse drag gesture
2. **Task 2: Reproduce the contradictory-banner combination (gap 2 / WR-01, RED)**
   - `13a8960` (test) — reproduce the simultaneous degraded and recovery banners
3. **Task 3: Gate worker_degraded on recovery_required in both server surfaces (gap 2 / WR-01, GREEN)**
   - `db9f2a4` (fix) — gate worker_degraded on recovery_required in both server surfaces

_Tasks 1 is a single RED→GREEN TDD cycle (test commit then fix commit, both under Task 1). Tasks 2 and 3 are deliberately split across two commits — the test commit lands before its fix commit, per the plan's RED-before-GREEN gate — recorded above under their respective task headings for traceability._

## Files Created/Modified

- `dashboard/advanced.js` — `beginDragSelect` and `cancelDragSelect` both clear `pendingRangeAnchor`
- `dashboard/app.py` — `api_scan_status`: `recovery_required` reordered above `worker_degraded`; `worker_degraded` gains a `not recovery_required` conjunct
- `dashboard/beacon/diagnosis.py` — `get_current_diagnosis`'s `safety['worker_degraded']` gains a `not recovery_required` conjunct
- `tests/test_history_investigation_ui.py` — two new regression tests for gap 1
- `tests/test_ui_safety_integration.py` — one new regression test for gap 2 (rendered page, both documents, both themes)
- `tests/test_api_and_auth.py` — one new regression test for gap 2 (`/api/scan-status` payload)
- `tests/test_advanced_diagnosis_api.py` — one new regression test for gap 2 (`/api/advanced/current` safety block)

## Pre-fix Failure Evidence (RED, as required by `<verification>` step 1)

**Task 1, Test 1 — `test_mouse_drag_abandons_a_pending_keyboard_anchor_so_a_later_plain_enter_applies_nothing`:**
```
AssertionError: '2023-11-15 09:13' != '2023-11-15 14:01'
tests/test_history_investigation_ui.py:2260: AssertionError
```
(Failed on the post-drag `#range-start` comparison: the stale keyboard anchor's plain-Enter completion silently overwrote the operator's actual drag-selected range.)

**Task 1, Test 2 — `test_cancelled_mouse_drag_also_abandons_a_pending_keyboard_anchor`:**
```
AssertionError: '2023-11-15 09:13' != '2026-08-27 06:35'
tests/test_history_investigation_ui.py:2321: AssertionError
```
(Failed on the `#range-start` comparison after a `pointercancel`-abandoned drag: `cancelDragSelect` did not yet clear the anchor, so the later plain Enter on an unanchored point applied a new range.)

**Task 2, Test A — `test_recovery_marker_with_aging_heartbeat_renders_only_the_recovery_banner_on_both_documents`:**
```
AssertionError: True is not false
tests/test_ui_safety_integration.py:283: AssertionError
```
Failed on `self.assertFalse(page.locator('#degraded-warning').is_visible())`, for all four subtests (`theme='dark', path='/'`; `theme='dark', path='/advanced'`; `theme='light', path='/'`; `theme='light', path='/advanced'`) — both banners rendered simultaneously on both documents and both themes.

**Task 2, Test B — `test_scan_status_never_reports_degraded_while_recovery_is_required`:**
```
AssertionError: True is not false
tests/test_api_and_auth.py:409: AssertionError
```
Failed on `self.assertFalse(response['worker_degraded'])` — `/api/scan-status` reported `worker_degraded: true` alongside `recovery_required: true`.

**Task 2, Test C — `test_safety_never_reports_degraded_while_recovery_is_required`:**
```
AssertionError: True is not false
tests/test_advanced_diagnosis_api.py:245: AssertionError
```
Failed on `self.assertFalse(payload['safety']['worker_degraded'])` — `/api/advanced/current`'s `safety` block reported the same contradiction.

All five tests were committed in a `test(05-07): ...` commit preceding their fix commit (`git log --oneline` confirms: `3330c37` before `f69fbb8`; `13a8960` before `db9f2a4`).

## Decisions Made

1. **Test 2's abandonment vector changed from Escape to a synthetic `pointercancel` event.** The plan's own action text named "the existing `test_escape_during_drag_cancels_no_range_change_and_overlay_hidden` idiom" (Escape) for the cancelled-drag variant. During RED-gate verification, this passed *before* the fix was applied — it did not reproduce the gap. Investigation traced the cause to a pre-existing, unconditional window-level Escape listener (`dashboard/advanced.js` ~line 1906, `05-04 Task 3, A-22, bindTimeCursorHandlers`) that already calls `cancelKeyboardRangeAnchor()` on every Escape keydown regardless of drag state — a listener entirely independent of `cancelDragSelect`. Using Escape as the cancellation vector therefore always cleared the anchor via that separate listener, masking whether `cancelDragSelect`'s own defensive call (the actual code under test) existed at all. Rewrote the test to dispatch a synthetic `pointercancel` event via `page.evaluate` instead — the event `cancelDragSelect` is registered against directly in `beginDragSelect` — which exercises exactly the call site the fix adds, with no confound. Verified: the rewritten test fails pre-fix and passes post-fix, as required. The test still satisfies the plan's literal acceptance criterion (source contains a `Shift+Enter` press, `page.mouse.down()` and `page.mouse.up()`, and a final `Enter` press) since those calls remain in the test; only the cancellation mechanism between them changed.
2. **UX-06 / UX-07 deliberately left at "Pending" in `REQUIREMENTS.md`, not promoted to Complete.** This plan closes both code-level gaps `05-VERIFICATION.md` recorded and all five new regression tests pass, satisfying this plan's own `<success_criteria>`. However this project has repeated, explicit precedent (STATE.md decisions from 03-14, 03-17, 03-21, 03-22) that a gap-closure round's own implementation claim about its own work is not the independent re-verification required to promote a requirement — only the next verification round may do that. Followed that precedent here rather than the generic workflow default of marking the plan's frontmatter `requirements` complete on task completion.

## Deviations from Plan

None beyond the Test 2 redesign documented above (Decision 1), which is a same-scope test-authoring correction, not a change to the fix's scope, files, or behavior. No architectural change, no new file, no new dependency. Both prohibitions in `must_haves.prohibitions` held: the keyboard range gesture itself is unchanged (only the stale-anchor-clearing paths were added), and the recovery banner's copy, visibility precedence, and the "server decides" rule (05-CONTEXT D-01) were untouched — no client-side precedence logic was added to `app.js` or `advanced.js`.

## Issues Encountered

- Playwright's bundled Chromium precondition for Task 1 was already satisfied (verified before starting): `test_pending_range_anchor_is_abandoned_without_applying_anything` passed on first run.
- Task 2's precondition (`tests/fixtures/legacy/operator/production.db` present, Chromium launchable) was already satisfied via the existing `test_ui_safety_integration.py` suite passing before this plan's changes.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Both `05-VERIFICATION.md` gaps are closed with regression evidence; the phase's own UI/safety suite and the project-wide suite are both green and exceed their recorded baselines.
- `D-DEBT-01` (light-mode `--green` WCAG contrast), `IN-01` (unreachable `'aging'` branch), and everything in `deferred-items.md` remain deliberately unaddressed, as scoped.
- UX-06 and UX-07 remain at "Pending" in `REQUIREMENTS.md` pending the phase's next independent verification round, which should find both gaps closed and the requirements ready for promotion.

---
*Phase: 05-theme-parity-analytics-experience*
*Completed: 2026-08-27*
