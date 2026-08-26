---
phase: 04-historical-investigation
plan: 11
reviewed: 2026-08-26T09:00:00Z
depth: standard
files_reviewed: 2
files_reviewed_list:
  - dashboard/advanced.js
  - tests/test_history_investigation_ui.py
findings:
  critical: 0
  warning: 0
  info: 1
  total: 1
status: issues_found
---

# Phase 04 Plan 11: Code Review Report (delta review)

**Reviewed:** 2026-08-26T09:00:00Z
**Depth:** standard
**Files Reviewed:** 2 (`dashboard/advanced.js`, `tests/test_history_investigation_ui.py`)
**Diff range:** `1368ba6..f1fb094`
**Status:** issues_found (Info only — no Critical or Warning findings)

## Summary

This is a delta review scoped to plan `04-11`, which closes `04-REVIEW.md`'s WR-01 (new) /
`04-VERIFICATION.md`'s single open gap: `renderIncidentsSection` silently substituting the
filtered incident count for the unfiltered baseline total when the baseline fetch fails, rendering
a misleading `"N of N incidents"`. The nine prior plans (04-01 through 04-10) were reviewed in
full previously in `04-REVIEW.md` and are not re-litigated here.

The actual diff is exactly what the plan and summary describe: `updateMatchingIncidentCount`
widens `total` to `number | null` with a strict `total === null` check (never a falsy check, so a
real `0` count is never conflated with an absent total), both branches unconditionally write both
`textContent` and `dataset.totalKnown` on every call, and `renderIncidentsSection` derives
`totalKnown`/`total` from an explicit guard rather than falling back to `episodes.length`. The
both-succeeded path (`` `${matching} of ${total} incidents` ``) is byte-identical to the pre-change
template — confirmed by diff inspection, not just by the plan's own claim.

Verification performed independently, not taken on the summary's word:

- Ran the two new regressions plus the two pre-existing exact-count tests
  (`test_incident_criticality_filter_issues_request_and_narrows_count`,
  `test_zero_match_incidents_renders_empty_copy_and_matching_count`) directly: all 4 pass.
- Traced the pre-change code path by hand against the new tests' fixtures: with the old
  `: episodes.length` fallback, a baseline 503 leaves `totalOutcome.status === 'rejected'`, so the
  ternary falls through to `episodes.length` (1), producing the old text `"1 of 1 incidents"` and
  no `data-total-known` attribute at all (the attribute did not exist pre-change). Both of the new
  test's assertions (`assertEqual(count_text, '1 of ? incidents (total unavailable)')` and
  `assertEqual(get_attribute('data-total-known'), 'false')`) would fail against that pre-change
  behavior — the regressions are genuine, not vacuously true.
- Confirmed only one call site of `updateMatchingIncidentCount` exists in the whole file (line
  1437), so no other consumer can pass a stringly-typed or `undefined` total that would slip past
  the `total === null` check and fall into the `else` branch's `${undefined}` interpolation.
- Confirmed `grep -n -iE "console\.log|debugger|TODO|FIXME|XXX|HACK|innerHTML|insertAdjacentHTML|eval\("`
  against the diff hunks returns nothing — no debug artifacts or HTML sinks introduced.

**Review-focus findings:**

1. **Fix completeness.** The only reachable path inside `renderIncidentsSection` that calls
   `updateMatchingIncidentCount` is the one this plan changed, and both of its branches
   (`totalKnown` true/false) always write both `textContent` and `dataset.totalKnown`. There is
   one other reachable path in the function — the early `return` when `filteredOutcome.status !==
   'fulfilled'` (lines 1421-1430) — that never reaches `updateMatchingIncidentCount` at all, so a
   previous render's count text/attribute (known or unknown) survives untouched into that error
   state. This is **pre-existing, unmodified-by-this-diff behavior** (the same early return, same
   lack of a count reset, existed before 04-11 and is explicitly called out as out of scope in the
   plan's own scope fence, citing `beginIncidentsLoadingState`'s identical non-reset of the same
   element). It is not a new defect this delta introduces; noted below as Info because the residual
   surface it now leaves stale is a second copy variant (`"... (total unavailable)"`) rather than
   only the original `"N of M"` text.

2. **`null` vs `0` handling.** `total === null` is a strict check; `0` renders `"0 of 0 incidents"`
   through the ordinary branch, exactly as required. No `if (!total)`-style conflation exists
   anywhere in the touched code.

3. **Test quality.** Both new tests genuinely drive the filtered-succeeds/baseline-fails
   combination via a query-predicate latch (`events_failure_fn`) rather than stubbing a fixed
   response shape that would pass regardless of the fix. The recovery test asserts the transition
   from `data-total-known="false"` back to `"true"` via `wait_for_function`, which is a state
   assertion independent of copy wording, and then also re-asserts the exact recovered text.
   Verified genuine by manual trace against the pre-change code above.

4. **Unchanged path.** The both-succeeded template is byte-for-byte identical
   (`` `${matching} of ${total} incidents` ``); the diff shows no other line touched in that
   branch.

5. **Accessibility.** The new copy renders inside the pre-existing `aria-live="polite"`
   `#matching-incident-count` region, so the uncertainty state is announced to assistive
   technology through the same mechanism the ordinary count already used — no new AT-facing gap is
   introduced by this delta. `data-total-known` itself carries no ARIA semantics, but nothing in
   this delta depends on it for accessibility (it exists as a state hook, per the plan's own
   Planner assumption 3, for a later Phase 5 styling need). `renderMarkerSingle`'s pre-recorded
   `role="img"`/`role="button"` mismatch (WR-02 new) is confirmed untouched by this diff
   (`grep -c "setAttribute('role', 'img')"` unaffected) and is correctly left for Phase 5 per
   `04-CONTEXT.md`'s domain fence — not re-reported here.

## Info

### IN-01: A stale matching-count render (including the new uncertainty text) can survive into a filtered-request failure — pre-existing, not introduced by this delta

**File:** `dashboard/advanced.js:1421-1430` (unchanged by this diff)

**Issue:** When `filteredOutcome` itself fails, `renderIncidentsSection` returns early
(`advanced.js:1421-1430`) without ever calling `updateMatchingIncidentCount`. Whatever the element
last displayed — including, after this plan, the new `"N of ? incidents (total unavailable)"`
state — remains on screen beside the freshly-shown `#incidents-error` banner claiming the list
itself failed to load. This exact non-reset behavior already existed before 04-11 for the ordinary
`"N of M incidents"` text (the plan's own scope fence explicitly names it as pre-existing and
declines to touch `beginIncidentsLoadingState` for this reason), so this delta does not introduce
the underlying defect — it only means the same pre-existing staleness can now also leave the
`(total unavailable)` copy on screen. Not blocking this delta's own must-haves (which are scoped
to the baseline-failure path with a *successful* filtered fetch), and correctly out of scope per
the plan's explicit scope fence.

**Fix:** Not applicable to this plan given its stated scope fence. If addressed in a future plan,
`beginIncidentsLoadingState` (or the `filteredOutcome`-failure branch itself) could reset
`#matching-incident-count` to a neutral state before showing the error banner, so a stale count
never coexists with an unrelated fetch-failure notice.

---

_Reviewed: 2026-08-26T09:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard (delta review of plan 04-11 against diff 1368ba6..f1fb094)_
