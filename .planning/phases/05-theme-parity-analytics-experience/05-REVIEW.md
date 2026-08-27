---
phase: 05-theme-parity-analytics-experience
reviewed: 2026-08-27T18:25:48Z
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
  critical: 1
  warning: 1
  info: 1
  total: 3
status: issues_found
---

# Phase 05: Code Review Report

**Reviewed:** 2026-08-27T18:25:48Z
**Depth:** standard
**Files Reviewed:** 16
**Status:** issues_found

## Summary

Reviewed the phase-05 diff (theme-parity degraded banner, shared freshness vocabulary,
density-driven disclosure defaults, keyboard/ARIA parity for the history chart stack,
and the 719px→720px narrow-breakpoint reconciliation) against `c28706b68a4861e16a467c40c96094a44f1dd9da^..HEAD`.
The backend classification work (`worker_freshness`/`worker_degraded` in
`dashboard/beacon/diagnosis.py` and `dashboard/app.py`) is careful and well-tested,
including the documented, intentionally-handled overlap between the operator-configured
`WORKER_READY_SECONDS` cutoff and the fixed 4x-cadence aging boundary. The frontend
freshness-vocabulary consolidation (`freshnessPresentation`/`freshnessBadge`) is a
genuine improvement and is used consistently everywhere a freshness reading renders.

One confirmed functional defect was found in the new 05-04 keyboard range-selection
gesture: the module-level pending keyboard anchor is never cleared by the pre-existing
mouse-drag lifecycle, so a later plain Enter keypress can silently apply a stale,
unrelated date range. One narrower defect was found in the new degraded-worker safety
banner: its visibility is gated only on the cadence-based "aging" state and never
checks `recovery_required`, so it can render simultaneously with, and directly
contradict, the existing recovery banner. Both are detailed below along with one
minor dead-code observation.

## Critical Issues

### CR-01: Stale keyboard range anchor silently applies a wrong range after any intervening mouse drag

**File:** `dashboard/advanced.js:2238-2270` (`cancelDragSelect`/`beginDragSelect`), consumed at `dashboard/advanced.js:2669-2684`
**Issue:**
The 05-04 keyboard range-selection gesture (`beginKeyboardRangeAnchor`/`completeKeyboardRange`,
`dashboard/advanced.js:2326-2364`) stores its pending state in a single module-level
variable, `pendingRangeAnchor`. Every chart point target's `keydown` handler checks this
variable unconditionally:

```js
target.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    if (pendingRangeAnchor) {
      event.preventDefault();
      completeKeyboardRange(point.ts);   // fires on a PLAIN Enter too
    } else if (event.shiftKey) {
      event.preventDefault();
      beginKeyboardRangeAnchor(point.ts, target);
    }
    return;
  }
  ...
});
```

The mouse-drag lifecycle (`beginDragSelect`, `updateDragSelect`, `commitDragSelect`,
`cancelDragSelect` — `dashboard/advanced.js:2238-2312`) reuses the exact same
`#history-drag-overlay` element the keyboard gesture uses, but none of these four
functions ever call `cancelKeyboardRangeAnchor()` or otherwise touch `pendingRangeAnchor`.

Reproduction:
1. Operator focuses a chart point and presses `Shift+Enter` — `pendingRangeAnchor` is set,
   overlay becomes visible.
2. Operator changes their mind and performs an ordinary mouse drag on any chart instead
   (or clicks an unrelated preset). `beginDragSelect` repositions/shows the same overlay;
   `commitDragSelect` → `cancelDragSelect` hides it again on completion. `pendingRangeAnchor`
   is never cleared.
3. Later, the operator tabs to a chart point and presses a **plain Enter** — per the
   comment above renderPointTargets ("A plain Enter with no anchor held matches none of
   these and does nothing at all"), this is documented and tested (in
   `tests/test_history_investigation_ui.py::test_pending_range_anchor_is_abandoned_without_applying_anything`
   and `test_empty_points_fixture_renders_no_point_targets_and_no_key_applies_a_range`)
   to be a no-op — but because `pendingRangeAnchor` is stale and non-null,
   `completeKeyboardRange(point.ts)` fires anyway, silently applying a range built from
   a timestamp captured long before the intervening drag, with the operator never having
   pressed Shift+Enter this time and with no overlay ever having reappeared to warn them.

No test in `tests/test_history_investigation_ui.py` exercises "begin a keyboard anchor,
then perform a mouse drag, then press Enter" — the gap is untested as well as unfixed.

**Fix:** Clear the pending anchor whenever a mouse drag begins (and, defensively, when
one completes/cancels):
```js
function beginDragSelect(event) {
  if (event.pointerType === 'mouse' && event.button !== 0) return;
  cancelKeyboardRangeAnchor(); // a mouse gesture must never leave a keyboard anchor pending
  const chartSvg = event.currentTarget;
  ...
```
(`cancelKeyboardRangeAnchor` is already defined at `dashboard/advanced.js:2350` and is
safe to call unconditionally.)

## Warnings

### WR-01: The new degraded-worker banner and the existing recovery banner can render simultaneously with contradictory text

**File:** `dashboard/app.py:3034-3051`, `dashboard/beacon/diagnosis.py:666-679`, `dashboard/app.js:148-151`, `dashboard/advanced.js:3175-3181`
**Issue:**
`worker_degraded` is computed purely from the cadence-based freshness classification,
guarded only against `worker_stale`:
```python
# app.py
state['worker_degraded'] = (not worker_stale) and state['worker_freshness']['state'] == 'aging'
```
```python
# diagnosis.py
'worker_degraded': pipeline['worker']['freshness']['state'] == 'aging',
```
`recovery_required`, however, is computed independently, from the on-disk recovery
marker file, with no reference to the freshness/aging state at all:
```python
state['recovery_required'] = worker_stale or (Path(DB_PATH).parent / RECOVERY_MARKER).is_file()
# and, identically in diagnosis.py:
recovery_required = (Path(db_path).parent / RECOVERY_MARKER).exists()
```
Both `#recovery-warning` and `#degraded-warning` are rendered independently from these
two orthogonal booleans (`dashboard/app.js:150-151`, `dashboard/advanced.js:3178-3180`).
If the recovery marker file exists (a failed/pending DB migration) while the worker's
heartbeat is still within the "aging" window (past 1x cadence but not yet past the
operator's `WORKER_READY_SECONDS` cutoff or the 4x-cadence stale boundary — a real,
reachable window, not merely theoretical, since `WORKER_READY_SECONDS` and the 4x-cadence
boundary are independently configurable per the code's own A-04 comment), both banners
render at once with directly contradictory copy:

> "Upgrade recovery is required. Monitoring is paused. Follow the documented recovery
> command before restarting Beacon." *(recovery-warning)*
>
> "Degraded — Beacon's worker heartbeat is aging. Monitoring continues; this is not a
> failure." *(degraded-warning)*

This is precisely the kind of safety-banner state confusion the project's safety
boundary constraints exist to prevent, and it is a new interaction introduced by this
phase (the degraded banner did not exist before). `tests/test_ui_safety_integration.py`'s
new tests (`test_degraded_banner_reads_identically_in_both_themes_on_both_documents`,
`test_stale_heartbeat_shows_worker_banner_and_not_the_degraded_banner`) cover the
degraded/stale exclusivity but never seed a recovery marker file alongside an aging
heartbeat, so this combination is untested.

**Fix:** Gate `worker_degraded` on `not recovery_required` as well, matching the existing
`not worker_stale` guard:
```python
state['worker_degraded'] = (not worker_stale) and (not state['recovery_required']) and state['worker_freshness']['state'] == 'aging'
```
(reorder so `recovery_required` is computed first), and the equivalent change in
`dashboard/beacon/diagnosis.py::get_current_diagnosis`'s `safety` dict construction.

## Info

### IN-01: `freshnessWord()`'s `'aging'` branch is currently unreachable dead code

**File:** `dashboard/advanced.js:369-372`, `dashboard/beacon/diagnosis.py:559-573`
**Issue:** `freshnessWord()` was extended with `if (state === 'aging') return 'degraded';`,
but its only callers are the three `EXCEPTION_COPY` builders (`host_freshness`,
`worker_freshness`, `service_freshness` at `dashboard/advanced.js:391-409`), which are
only ever invoked for exception items the server actually emits. The server's
`compose_active_exceptions` only appends `host_freshness`/`worker_freshness`/
`service_freshness` exceptions when `state in {'stale', 'unknown'}`
(`dashboard/beacon/diagnosis.py:559-573`) — `'aging'` is never included. The new branch
therefore can never execute given the current exception-composition contract.
**Fix:** Either remove the dead branch (and its comment) until an `'aging'` exception
kind actually exists, or add a code comment explaining it is intentionally
forward-defensive/future-proofing so a future reader does not assume it is reachable
today.

---

_Reviewed: 2026-08-27T18:25:48Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
