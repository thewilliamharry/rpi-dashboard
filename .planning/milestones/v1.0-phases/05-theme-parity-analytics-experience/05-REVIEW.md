---
phase: 05-theme-parity-analytics-experience
reviewed: 2026-08-28T00:00:00Z
depth: standard
files_reviewed: 16
files_reviewed_list:
  - dashboard/advanced.css
  - dashboard/advanced.html
  - dashboard/advanced.js
  - dashboard/app.js
  - dashboard/app.py
  - dashboard/beacon/diagnosis.py
  - dashboard/index.html
  - dashboard/style.css
  - tests/test_advanced_diagnosis_api.py
  - tests/test_advanced_ui.py
  - tests/test_api_and_auth.py
  - tests/test_history_investigation_ui.py
  - tests/test_theme_parity_ui.py
  - tests/test_ui_contract.py
  - tests/test_ui_safety_integration.py
  - tests/test_ui_states.py
findings:
  critical: 0
  warning: 0
  info: 2
  total: 2
status: issues_found
---

# Phase 05: Code Review Report

**Reviewed:** 2026-08-28T00:00:00Z
**Depth:** standard
**Files Reviewed:** 16
**Status:** issues_found

## Summary

This is a re-review of phase 05 after the gap-closure plan `05-07` (commits `3330c37`,
`f69fbb8`, `13a8960`, `db9f2a4`), which targeted the two defects raised in the previous
`05-REVIEW.md`: `CR-01` (stale keyboard range-anchor leak across a mouse drag) and
`WR-01` (simultaneous, contradictory degraded/recovery banners). Both are confirmed
fixed by direct code trace and by running their regression tests against the live
codebase; neither is re-reported here. The previously-recorded `IN-01` (an unreachable
`'aging'` branch in `freshnessWord()`) was not in scope for `05-07` and remains open, so
it is carried forward. One new, very minor code-quality observation from the `05-07`
diff itself is also recorded (`IN-02`).

**CR-01 — verified fixed.** `beginDragSelect` now calls `cancelKeyboardRangeAnchor()`
before un-hiding the drag overlay (`dashboard/advanced.js:2265-2266`), and
`cancelDragSelect` calls it defensively as well (`dashboard/advanced.js:2245`), which
covers every drag exit path: `commitDragSelect` (unconditionally calls
`cancelDragSelect` before applying its own range), the window-level Escape listener
`dragEscapeListener` (`dashboard/advanced.js:2224-2225`), and the direct
`pointercancel` listener registered in `beginDragSelect`
(`dashboard/advanced.js:2281`). `cancelKeyboardRangeAnchor()` itself
(`dashboard/advanced.js:2362-2366`) is idempotent and safe to call whether or not an
anchor is held. Traced through: a right/middle mouse button press
(`event.button !== 0`) returns before touching the anchor, which is correct — it never
starts a drag, so it must not disturb a pending keyboard gesture either. The
uninterrupted keyboard-only gesture (`Shift+Enter` → `Tab` → `Enter`) never fires any
`pointerdown`/`pointercancel` event, so it is unaffected. Ran the two new regression
tests (`test_mouse_drag_abandons_a_pending_keyboard_anchor_so_a_later_plain_enter_applies_nothing`,
`test_cancelled_mouse_drag_also_abandons_a_pending_keyboard_anchor` in
`tests/test_history_investigation_ui.py`) plus the full existing drag/anchor/escape
test group (11 tests) — all pass. The executor's reported deviation (substituting a
synthetic `pointercancel` for Escape in the cancelled-drag regression test) is verified
correct: `bindTimeCursorHandlers` registers an unconditional, drag-independent
`window.addEventListener('keydown', ...)` at `dashboard/advanced.js:1906-1908` that
calls `cancelKeyboardRangeAnchor()` on every Escape keypress regardless of drag state.
A test using Escape as the abandonment vector would have passed identically whether or
not `cancelDragSelect`'s own defensive call existed, masking the exact call site under
test. The `pointercancel` substitution is a genuine improvement, not a regression in
coverage.

**WR-01 — verified fixed.** Both surfaces now gate `worker_degraded` on
`not recovery_required` in addition to the pre-existing `not worker_stale` guard:
`dashboard/app.py:3056` and `dashboard/beacon/diagnosis.py:682`. Ordering is correct in
both places — `state['recovery_required']` is assigned at `dashboard/app.py:3044`
before it is read at line 3056; `recovery_required` is computed at
`dashboard/beacon/diagnosis.py:666` before it is read at line 682. A repo-wide search
confirms these are the only two places `worker_degraded` is computed — no third surface
derives it independently, and the two client renderers (`dashboard/app.js:151`,
`dashboard/advanced.js:3193`) both consume the server-computed boolean directly rather
than re-deriving it. Ran all three new regression tests
(`test_scan_status_never_reports_degraded_while_recovery_is_required`,
`test_safety_never_reports_degraded_while_recovery_is_required`,
`test_recovery_marker_with_aging_heartbeat_renders_only_the_recovery_banner_on_both_documents`)
— all pass, including the 4-way theme/document subtest matrix in the UI-level test.

## Critical Issues

None found.

## Warnings

None found.

## Info

### IN-01: `freshnessWord()`'s `'aging'` branch remains unreachable dead code

**File:** `dashboard/advanced.js:369-372`, `dashboard/beacon/diagnosis.py:559-573`
**Issue:** Carried forward from the previous review round; unchanged by `05-07`, which
did not touch this code path. `freshnessWord()` has `if (state === 'aging') return
'degraded';`, but its only callers are the `EXCEPTION_COPY` builders for
`host_freshness`/`worker_freshness`/`service_freshness`
(`dashboard/advanced.js:391-409`), which only ever render for exception items the
server actually emits. `compose_active_exceptions` only appends those three exception
kinds when `state in {'stale', 'unknown'}` (`dashboard/beacon/diagnosis.py:559-573`
confirmed still unchanged) — `'aging'` is never included, so the branch cannot execute
under the current exception-composition contract.
**Fix:** Either remove the dead branch and its comment until an `'aging'` exception
kind actually exists, or add a comment stating it is intentionally
forward-defensive so a future reader does not assume it is reachable today.

### IN-02: `cancelDragSelect` redundantly re-does the overlay hide/reset that `cancelKeyboardRangeAnchor` already performs

**File:** `dashboard/advanced.js:2243-2248`
**Issue:** `05-07`'s fix has `cancelDragSelect` call `cancelKeyboardRangeAnchor()`
(line 2245), which itself hides the overlay and resets its width to `0px`
(`dashboard/advanced.js:2362-2366`). The very next two lines in `cancelDragSelect`
(2246-2247) then perform the identical `overlay.hidden = true; overlay.style.width =
'0px';` a second time. This is harmless (idempotent DOM writes, no observable
behavior difference) but is duplicate work introduced by the fix, and a future reader
might reasonably wonder whether the two hide-and-reset steps are expected to ever
diverge.
**Fix:** Optional cleanup — since `cancelKeyboardRangeAnchor()` already hides the
overlay unconditionally, the `overlay` hide/reset lines in `cancelDragSelect` could be
removed (or a one-line comment added noting the duplication is intentional
belt-and-suspenders rather than an oversight). Not worth a dedicated fix pass on its
own.

---

_Reviewed: 2026-08-28T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
