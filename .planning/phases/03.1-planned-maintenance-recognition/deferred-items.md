# Deferred Items — Phase 03.1

Out-of-scope discoveries logged during plan execution, per the executor's scope-boundary rule
(only auto-fix issues directly caused by the current task's changes).

## From 03.1-08 (Suggestion card)

**`.meta-window-empty[hidden]` does not actually hide the element.**

- **File:** `dashboard/style.css`
- **Found during:** Writing Task 3's `#meta-suggestion` visibility tests, plan 03.1-08. The exact
  same bug pattern was independently discovered and fixed for the new `.meta-suggestion` class
  (see this plan's own fix commit) — while confirming that fix, the identical pattern was found to
  already exist in `.meta-window-empty`, introduced by plan 03.1-05.
- **Issue:** `.meta-window-empty { display: flex; ... }` sets `display` unconditionally. This wins
  the CSS cascade over the browser's built-in `[hidden] { display: none }` rule, so toggling the
  `hidden` DOM property on `#meta-window-empty` (as `updateMaintenanceWindowCount()` does) has no
  visible effect — the "No maintenance windows yet" empty-state box stays rendered even when the
  service has one or more windows.
- **Verified independently:** a Playwright probe against the live dev server (not a `file://` load,
  which never applies the stylesheet and masks the bug) confirms `getComputedStyle(...).display`
  is `"flex"` while `hasAttribute("hidden")` is `true`, for a service with a non-empty window list.
- **Why deferred rather than fixed here:** `dashboard/style.css` line 749 (`.meta-window-empty`) is
  outside plan 03.1-08's declared scope — it is owned by the completed, merged plan 03.1-05, and
  none of plan 03.1-08's tasks touch that selector. Per the executor's scope boundary, only bugs
  directly caused by the current task's own changes are auto-fixed; this one predates 03.1-08.
- **Suggested fix (for whichever future plan next touches `dashboard/style.css`):** add
  `.meta-window-empty[hidden] { display: none; }` immediately after the existing
  `.meta-window-empty { ... }` rule, mirroring the fix now in place for `.meta-suggestion[hidden]`.
- **User-visible impact:** low but real — a service with existing maintenance windows briefly (or
  persistently, depending on layout) shows a stray "No maintenance windows yet" box above its real
  window list inside the editor modal. No test in the existing suite asserts the empty-state box is
  actually invisible once windows exist, so this has not been caught by CI.
