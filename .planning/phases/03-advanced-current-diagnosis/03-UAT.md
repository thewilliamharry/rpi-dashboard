---
status: testing
phase: 03-advanced-current-diagnosis
source: [03-VERIFICATION.md]
started: 2026-08-20T22:55:00Z
updated: 2026-08-20T22:55:00Z
---

## Current Test

number: 2
name: Perceptibility of hover feedback across the workspace
expected: |
  On the Pi, in each theme, point in turn at `Pause updates`, the refresh-interval
  dropdown, a section tab, a Services table column header, a row's `Show details`
  control, and a filter dropdown. Every one shows the pointing hand and visibly
  answers hover (cyan border in dark mode, darker slate border and label in light
  mode); the search box keeps a text caret (no pointer); an unselected section tab
  does not turn accent-coloured on hover.
awaiting: user response

## Tests

### 1. The reported defect, directly (NEW, G-03-4-specific)
expected: On the target Pi, open `/advanced` in dark mode. Point at `Refresh now` without clicking. Then switch to light mode and repeat. Pointing-hand cursor; the button's background visibly brightens toward the accent colour on hover; and — before hovering anything — `Refresh now` already reads as the primary action of the header (accent text, accent border, heavier weight), plainly distinct from `Pause updates`.
result: pass
evidence: |
  Confirmed by the operator on real hardware during the 03-23 tracer checkpoint,
  2026-08-20 ~22:39 local, from a dark-mode screenshot of `/advanced` Overview
  showing `Refresh now` rendered with accent text, accent border and heavier
  weight against the neutral `Pause updates` beside it.
  Operator's verbatim assessment: "refresh now is looking good now, but other
  buttons are still lacking."
  The second clause is the scope of test 2 below, not a defect against this item —
  it described the pre-Task-2 state, and Task 2 (commit 07ac39c) extended the same
  affordance to every remaining control afterwards.
  This records as a git-tracked artifact the confirmation 03-VERIFICATION.md round 9
  noted was outstanding.

### 2. Perceptibility of hover feedback across the workspace (NEW, G-03-4-specific)
expected: On the Pi, in each theme, point in turn at `Pause updates`, the refresh-interval dropdown, a section tab, a Services table column header, a row's `Show details` control, and a filter dropdown. Every one shows the pointing hand and visibly answers hover (cyan border in dark mode, darker slate border and label in light mode); the search box keeps a text caret (no pointer); an unselected section tab does not turn accent-coloured on hover.
result: [pending]
note: |
  Why human: the tints are 8-12% alpha and the light-mode border shift is subtle by
  design — whether they are actually visible at the Pi's own display brightness and
  viewing angle is a judgement call outside `getComputedStyle`'s reach. The computed
  deltas themselves are already pinned by
  `test_every_interactive_control_reads_as_interactive_in_both_themes`.

### 3. Real collection gap and stale host on the target Pi (standing, unaffected by this round)
expected: Open `/advanced` on the Pi while a real collection gap is active and while host evidence is stale. The workspace shows the open gap and the stale host as real, correctly labelled exceptions, and shows no resolved or retention-expired interval as an open actionable gap.
result: [pending]
note: |
  Carried forward for re-confirmation only. Recorded PASS on real hardware
  2026-08-20 ~13:00 (see this file's git history at the round-8 UAT). Round 9's
  change is stylesheet-only and touches no logic file this test depends on —
  `git diff 2633b9e..07ac39c -- dashboard/beacon/diagnosis.py` is empty.

### 4. Idle Pi, one minute, Active exceptions region (standing, unaffected by this round)
expected: Start the worker, leave the system idle for one minute, open `/advanced`, read the Overview "Active exceptions" region. No "Background job failed" card for any job, no "Background job outcome not recorded" card for any job that is simply working.
result: [pending]
note: |
  Carried forward for re-confirmation only. Recorded PASS on real hardware
  2026-08-20 13:03 (see this file's git history at the round-8 UAT).

### 5. Deliberately broken browser, two minutes, Pipeline region (standing, unaffected by this round)
expected: With Chromium/Playwright deliberately unavailable, leave the worker running for two minutes, open `/advanced`, read the Pipeline region. A "Background job failed" card names J6.
result: [pending]
note: |
  Carried forward for re-confirmation only. Recorded PASS on real hardware
  2026-08-20 21:43 (see this file's git history at the round-8 UAT), with a noted
  caveat that the render itself was not photographed within the transient failure
  window — tracked as a Deferred Follow-Up, not a gap.

## Summary

total: 5
passed: 1
issues: 0
pending: 4
skipped: 0
blocked: 0

## Gaps

- gap_id: G-03-4
  truth: "Interactive controls in the /advanced workspace read as interactive (pointer cursor, hover state), and `Refresh now` carries the accent treatment 03-UI-SPEC.md reserves for it."
  status: closed
  closed_by: "03-23-PLAN.md (commits 2b12c4b, 07ac39c)"
  closed_at: 2026-08-20T22:41:00Z
  evidence: |
    Code-level closure independently reproduced by 03-VERIFICATION.md round 9: all
    13 of the plan's acceptance-criteria grep counts re-run and matching, the
    real-Chromium regression re-run (1 passed), the full suite re-run (307 passed,
    454 subtests), and the scope fence confirmed (exactly `dashboard/advanced.css`
    and `tests/test_advanced_ui.py` across both commits). 03-REVIEW.md round 5 found
    zero defects in this diff. Operator confirmed the `Refresh now` half on real
    hardware — recorded as test 1 above. Test 2 remains open for the perception half
    across the remaining controls.
