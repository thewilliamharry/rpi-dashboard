---
phase: 05-theme-parity-analytics-experience
verified: 2026-08-27T18:35:46Z
status: gaps_found
score: 3/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
gaps:
  - truth: "Operator can use the dashboard and advanced workspace at supported narrow and desktop viewport widths, including keyboard-accessible status and chart interactions with text labels that do not rely on colour alone (ROADMAP SC3 / UX-06)"
    status: failed
    reason: >
      The keyboard chart-range-selection gesture built by 05-04 is not reliably safe. Its
      pending-anchor state (`pendingRangeAnchor`, a module-level variable set by
      `beginKeyboardRangeAnchor` on Shift+Enter) is never cleared by the pre-existing mouse-drag
      lifecycle (`beginDragSelect`/`updateDragSelect`/`commitDragSelect`/`cancelDragSelect`), even
      though both gestures share the same `#history-drag-overlay` element. Reproduction, confirmed
      by direct code read (not just trusting 05-REVIEW.md's CR-01): (1) operator focuses a chart
      point and presses Shift+Enter, arming `pendingRangeAnchor`; (2) operator performs an ordinary
      mouse drag on any chart instead (or clicks an unrelated preset) — the drag lifecycle never
      calls `cancelKeyboardRangeAnchor()`, so the stale anchor survives; (3) operator later tabs to
      a chart point and presses a plain Enter (documented and tested elsewhere to be a no-op when no
      anchor is held) — because the anchor is stale and non-null, `completeKeyboardRange(point.ts)`
      fires anyway, silently applying a range built from a timestamp captured before the intervening
      drag, with no visual warning and no Shift held this time. This directly contradicts 05-04-PLAN.md's
      own declared must-have truth: "A pending keyboard range anchor can always be abandoned without
      applying anything, and abandoning it leaves the current range untouched" — a mouse drag is not
      one of the anchor's documented abandon paths (only completion or Escape are), so the anchor is
      never abandoned, and it does not leave a later, unrelated keyboard action untouched. No test in
      tests/test_history_investigation_ui.py exercises "keyboard-anchor, then mouse-drag, then plain
      Enter" — confirmed absent by search; the gap is untested as well as unfixed.
    artifacts:
      - path: "dashboard/advanced.js"
        issue: "beginDragSelect (~line 2251), updateDragSelect, commitDragSelect, and cancelDragSelect (~lines 2238-2312) never call cancelKeyboardRangeAnchor() (defined ~line 2350), so pendingRangeAnchor set by beginKeyboardRangeAnchor (~line 2328) is never cleared by an intervening mouse gesture."
    missing:
      - "Call cancelKeyboardRangeAnchor() at the start of beginDragSelect (and defensively on drag commit/cancel) so a mouse gesture always clears any pending keyboard anchor."
      - "A regression test in tests/test_history_investigation_ui.py exercising: keyboard-anchor a point (Shift+Enter) -> perform a mouse drag elsewhere -> plain Enter on an unrelated point -> assert the range is unchanged."
  - truth: "Loading, empty, stale, unknown, degraded, and error states are visibly and meaningfully distinct in both themes (ROADMAP SC4 / UX-07)"
    status: failed
    reason: >
      The new degraded-worker safety banner (#degraded-warning, built by 05-01) and the pre-existing
      recovery banner (#recovery-warning) can render simultaneously with directly contradictory copy.
      Confirmed by direct code read: `dashboard/app.py:3047` computes
      `state['worker_degraded'] = (not worker_stale) and state['worker_freshness']['state'] == 'aging'`
      and `dashboard/beacon/diagnosis.py:676` computes
      `'worker_degraded': pipeline['worker']['freshness']['state'] == 'aging'` — both guarded only
      against `worker_stale`, never against `recovery_required`. `recovery_required`
      (`dashboard/app.py:3051`, `dashboard/beacon/diagnosis.py:666`) is computed independently, purely
      from whether an on-disk recovery-marker file exists (a failed/pending DB migration), with no
      reference to heartbeat freshness at all — so the marker file existing while the heartbeat is
      merely "aging" (not yet past `WORKER_READY_SECONDS` or the fixed 4x-cadence stale boundary,
      both independently configurable per the code's own A-04 comment) is a real, reachable
      combination, not a theoretical one. Both `#recovery-warning` and `#degraded-warning` are toggled
      independently from these two orthogonal booleans in both `dashboard/app.js:150-151` and
      `dashboard/advanced.js:3178-3180`, with no mutual-exclusion guard. When both fire, the operator
      sees "Upgrade recovery is required. Monitoring is paused. Follow the documented recovery
      command..." beside "Degraded — Beacon's worker heartbeat is aging. Monitoring continues; this
      is not a failure." at the same instant — the opposite of "meaningfully distinct" safety states.
      Confirmed untested: no test in tests/test_ui_safety_integration.py seeds a recovery-marker file
      alongside an aging (not stale) heartbeat (grep for RECOVERY_MARKER/recovery_required in that
      file returns nothing).
    artifacts:
      - path: "dashboard/app.py"
        issue: "state['worker_degraded'] (line 3047) is guarded by 'not worker_stale' only, not by 'not recovery_required'."
      - path: "dashboard/beacon/diagnosis.py"
        issue: "the safety dict's 'worker_degraded' (line 676) has no recovery_required guard at all."
    missing:
      - "Gate worker_degraded on 'not recovery_required' as well as 'not worker_stale' in both dashboard/app.py's api_scan_status and dashboard/beacon/diagnosis.py's get_current_diagnosis."
      - "A regression test seeding a recovery-marker file alongside an aging (not stale) heartbeat, asserting #degraded-warning and #recovery-warning never both render."
---

# Phase 5: Theme-Parity Analytics Experience Verification Report

**Phase Goal:** Beacon provides a cohesive, responsive, accessible monitoring experience in which
light and dark themes expose the same advanced capability while retaining the calm everyday
dashboard.
**Verified:** 2026-08-27T18:35:46Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth (ROADMAP Success Criterion) | Status | Evidence |
|---|---|---|---|
| 1 | Operator continues to see compact analytics and history previews on the main dashboard in both light and dark themes | ✓ VERIFIED | `05-CONTEXT.md` D-03 records the deliberate-calm interpretation; `tests/test_ui_contract.py::THEME_HIDDEN_RULES` enumerates and classifies all 8 `html.light` display:none rules by regex (source-derived, not hand-transcribed); `tests/test_ui_states.py::test_shared_dashboard_capability_is_present_and_displayed_in_both_themes` and `test_deliberate_light_mode_calm_is_hidden_not_absent_and_has_a_named_substitute` both pass, proving every contract-shared element renders in both themes and every deliberate-calm omission is CSS-hidden (not absent) with a named substitute. Ran the module: passes. |
| 2 | Both themes expose the same advanced analytics data, filters, settings, and investigation workflows, with light mode using calmer progressive disclosure and dark mode allowing denser simultaneous context | ✓ VERIFIED | `grep "html.light" dashboard/advanced.css \| grep "display: *none"` returns zero matches — confirmed directly, not only via the test — so the advanced workspace hides nothing by theme. `densityDisclosureDefault()` (dashboard/advanced.js:244) drives two named disclosure surfaces from the density body class only (never the theme class); `tests/test_advanced_ui.py::test_density_drives_disclosure_defaults_and_theme_only_supplies_the_default_density` and `test_every_advanced_control_is_present_and_operable_in_both_themes` (the directly-asserted D-02 reachability invariant, Counter-based control-descriptor parity) both pass. |
| 3 | Operator can use the dashboard and advanced workspace at supported narrow and desktop viewport widths, including keyboard-accessible status and chart interactions with text labels that do not rely on colour alone | ✗ FAILED | Responsive half is solid: `dashboard/advanced.css`/`dashboard/style.css` share one 720px boundary, pinned at source level by `tests/test_theme_parity_ui.py::NarrowBoundaryPinTests`; `test_at_risk_narrow_layouts_scroll_rather_than_hide_in_both_themes` passes. Keyboard-access half is mostly solid (marker role fix, coverage-strip focus, focus-driven time cursor, uptime-strip `aria-label` all confirmed present and test-covered) but the new keyboard range-selection gesture has a confirmed, reproducible correctness defect (CR-01, independently confirmed by direct code read) — see gap 1 above. |
| 4 | Loading, empty, stale, unknown, degraded, and error states are visibly and meaningfully distinct in both themes | ✗ FAILED | The four-tier freshness vocabulary itself (fresh/degraded/stale/unknown, glyph+word+shape, WCAG-checked) is genuinely solid — `tests/test_advanced_ui.py::test_six_states_are_distinct_in_both_themes` passes and its assertions were read directly, not trusted. But the new degraded-worker safety banner can render simultaneously with the pre-existing recovery banner with directly contradictory text (WR-01, independently confirmed by direct code read of `dashboard/app.py`/`dashboard/beacon/diagnosis.py`) — see gap 2 above. |
| 5 | UI-contract or visual-regression coverage verifies shared capabilities and important states in both themes | ✓ VERIFIED | Six dedicated dual-theme Playwright/contract test files exist and pass (`tests/test_ui_contract.py`, `tests/test_ui_states.py`, `tests/test_advanced_ui.py`, `tests/test_history_investigation_ui.py`, `tests/test_ui_safety_integration.py`, `tests/test_theme_parity_ui.py`, the last created new by this phase). `grep -rho 'to_have_screenshot\|page.screenshot' tests/` confirmed to return nothing — coverage is DOM/computed-style/geometry contracts, not pixel snapshots, per the plan's own OPS-06 requirement. Ran the six files directly (excluding full-suite scope): 277 passed, 140 subtests passed, 0 failures. |

**Score:** 3/5 truths verified (2 present-and-mostly-working but blocked by a confirmed, reproducible code defect each)

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `dashboard/beacon/diagnosis.py` | `worker_heartbeat_cadence_seconds`, `worker_freshness`, `safety.worker_degraded` | ✓ VERIFIED (with defect) | Present, substantive, wired into both `compose_pipeline_diagnosis` and `dashboard/app.py`. `worker_degraded` itself has the WR-01 guard gap (see gap 2). |
| `dashboard/app.py` | `/api/scan-status` `worker_freshness`/`worker_degraded` fields | ✓ VERIFIED (with defect) | Same WR-01 guard gap. |
| `dashboard/index.html` / `dashboard/advanced.html` | `#degraded-warning` banner, byte-identical | ✓ VERIFIED | Confirmed present in both documents, wired from `updateScanStatus`/`renderSafety`. |
| `dashboard/style.css` | `.degraded-warning` unboxed, distinguished from `.recovery-warning` by border absence | ✓ VERIFIED | Confirmed no border declaration on `.degraded-warning`; `.recovery-warning` keeps `border-bottom`. |
| `dashboard/advanced.js` | `FRESHNESS_PRESENTATION`, `freshnessBadge`, degraded evidence sentence | ✓ VERIFIED | `FRESHNESS_PRESENTATION = new Map([...])` at line 347, consumed by every freshness-rendering call site. |
| `dashboard/advanced.css` | `.freshness-badge`/`.freshness-degraded`/etc., inline unbordered, token-only colour | ✓ VERIFIED | Confirmed present and distinct from `.advanced-error`'s bordered-box shape. |
| `tests/test_ui_contract.py` | exhaustive theme-gated visibility inventory, zero-rule guard for advanced workspace | ✓ VERIFIED | `THEME_HIDDEN_RULES` (8 entries) and `test_advanced_workspace_hides_nothing_by_theme` both present; directly confirmed advanced.css has zero `html.light ... display:none` rules. |
| `tests/test_ui_states.py` | main-dashboard dual-theme parity assertions | ✓ VERIFIED | Present, passes. |
| `dashboard/advanced.js` (05-04) | corrected marker role, keyboard-reachable coverage strip, focus-driven cursor, `applySelectedRange`, keyboard range-anchor gesture | ⚠️ VERIFIED, WITH A REPRODUCIBLE DEFECT | All artifacts present and wired; `applySelectedRange` and the anchor gesture exist exactly as described, but see gap 1 (CR-01) — the anchor-clearing invariant is incomplete. |
| `dashboard/app.js` (05-04) | uptime-strip segment `aria-label` | ✓ VERIFIED | Confirmed `role`/`aria-label` computed once alongside `title`. |
| `dashboard/advanced.js` (05-05) | `densityDisclosureDefault`, per-instance overrides, `clearMatchingIncidentCount` | ✓ VERIFIED | All three functions present and wired as described. |
| `dashboard/advanced.css` (05-06) | reconciled narrow breakpoint, `max-width: 720px` | ✓ VERIFIED | Confirmed both stylesheets share 720px; `test_advanced_ui.py`'s two boundary assertions were correctly updated to the new value (the cross-plan scope conflict 05-06-SUMMARY.md flagged was reconciled in commit `54ba02b`, confirmed present in the current tree). |
| `tests/test_theme_parity_ui.py` | dedicated cross-surface dual-theme contract module | ✓ VERIFIED | New file present, `NARROW_BOUNDARY_PX = 720`, both test classes present and pass. |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `dashboard/app.py` | `dashboard/beacon/diagnosis.py` | `api_scan_status` calls `worker_freshness()` | ✓ WIRED | Confirmed via `gsd-tools query verify.key-links` (3/3 for 05-01). |
| `dashboard/advanced.js` | `dashboard/beacon/diagnosis.py` | freshness presentation keyed off server literal | ✓ WIRED | Confirmed via tool (05-02, link 1/2). |
| `dashboard/advanced.css` | `dashboard/style.css` | badge colours resolve `--accent2`/`--text`/`--green` from existing tokens | ✓ WIRED (tool false-negative corrected) | The automated `verify.key-links` query reported this link as unverified ("Pattern \"var(--accent2)\" not found in source or target"), but direct `grep` confirms `var(--accent2)` is present in both `dashboard/advanced.css` (`.freshness-degraded { color: var(--accent2); }` and others) and `dashboard/style.css` (token declarations at lines 14/34 and multiple consumers) — a tool query false negative, not a real gap. |
| `dashboard/advanced.js` | `dashboard/advanced.js` | `commitDragSelect` and the keyboard gesture both call `applySelectedRange` | ✓ WIRED, but see gap 1 | Both call sites confirmed. The shared-function invariant literally holds; the anchor-clearing invariant around it does not (CR-01). |
| `tests/test_theme_parity_ui.py` | `dashboard/app.py` | module stubs every endpoint both documents call | ✓ WIRED | Confirmed via tool (05-06, 2/2). |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Six-state dual-theme distinctness test | `pytest tests/test_advanced_ui.py -k test_six_states_are_distinct_in_both_themes` | passed (part of full module run) | ✓ PASS |
| Advanced workspace has zero theme-gated hide rules | `grep "html.light" dashboard/advanced.css \| grep "display: *none"` | no matches | ✓ PASS |
| `renderMarkerSingle` role fix | direct code read, `dashboard/advanced.js:1745` | `circle.setAttribute('role', 'button')` present | ✓ PASS |
| Keyboard range-anchor state leak (CR-01) | direct code read + grep for `cancelKeyboardRangeAnchor` call sites | zero calls from any drag-lifecycle function | ✗ FAIL (gap 1) |
| Degraded/recovery banner mutual exclusion (WR-01) | direct code read of `worker_degraded` computation in both `app.py` and `diagnosis.py` | no `recovery_required` guard in either | ✗ FAIL (gap 2) |
| Full phase-relevant test suite | `pytest tests/test_ui_safety_integration.py tests/test_advanced_ui.py tests/test_theme_parity_ui.py tests/test_ui_contract.py tests/test_ui_states.py tests/test_history_investigation_ui.py -q` | 277 passed, 140 subtests passed, 0 failures | ✓ PASS |
| Zero screenshot-API usage (OPS-06) | `grep -rho 'to_have_screenshot\|page.screenshot' tests/` | no matches | ✓ PASS |
| Debt-marker scan | `grep -n -E "TBD\|FIXME\|XXX" <all 16 reviewed files>` | no matches | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|---|---|---|---|---|
| UX-01 | 05-03 | Compact analytics/history previews remain on main dashboard in both themes | ✓ SATISFIED | D-03 documented interpretation + passing dual-theme parity tests |
| UX-03 | 05-03, 05-05 | Advanced analytics exposes same data/filters/settings/investigations in both themes | ✓ SATISFIED | Zero theme-gated rules in advanced.css + D-02 reachability invariant test passing |
| UX-04 | 05-05 | Light calmer disclosure, dark denser context, density-driven | ✓ SATISFIED | `densityDisclosureDefault()` present, tested, theme-independent per D-02 |
| UX-05 | 05-06 | Advanced analytics usable at narrow and desktop widths | ✓ SATISFIED | Shared 720px boundary, at-risk-layout scroll-not-hide tests passing |
| UX-06 | 05-02, 05-04 | Status/chart info via text/labels/keyboard, not colour alone | ✗ BLOCKED (partial) | Marker role, coverage-strip, cursor, uptime-strip `aria-label` all satisfied; the keyboard range-selection gesture has the CR-01 defect (gap 1) undermining "usable" keyboard chart interaction |
| UX-07 | 05-01, 05-02, 05-05 | Loading/empty/stale/unknown/degraded/error visibly distinct | ✗ BLOCKED (partial) | Freshness vocabulary itself solid; degraded-vs-recovery banner overlap (WR-01, gap 2) undermines distinctness for the safety-banner cluster |
| OPS-06 | all six plans | UI-contract/visual-regression coverage for both themes | ✓ SATISFIED | Six dual-theme contract test files, zero pixel-snapshot usage, all passing |

No orphaned requirements: the union of all six plans' declared `requirements` fields (`UX-01, UX-03, UX-04, UX-05, UX-06, UX-07, OPS-06`) exactly matches `REQUIREMENTS.md`'s Phase 5 mapping and the ROADMAP's declared Phase 5 requirement list.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| `dashboard/advanced.js` | 369-372 | `freshnessWord()`'s `'aging'` branch is currently unreachable dead code (05-REVIEW.md IN-01, confirmed) | ℹ️ Info | No functional impact; `compose_active_exceptions` never emits `state: 'aging'` for the exceptions this function serves today. Not a gap. |
| — | — | No `TBD`/`FIXME`/`XXX` debt markers found in any of the 16 phase-touched files | — | — |

### Human Verification Required

None required to reach a status determination — both open issues (gap 1, gap 2) are code-level defects with a clear, deterministic reproduction and fix, not matters of visual/UX judgment. One disclosed, deliberately-deferred product decision remains open but does not block this phase's own closure (see Gaps Summary).

### Gaps Summary

Phase 5 delivers a genuinely strong theme-parity foundation: an exhaustive, self-maintaining,
regex-derived theme-gated-visibility contract; zero theme-gated hiding anywhere in the advanced
workspace; a real four-tier freshness vocabulary distinguished by glyph, word, shape and verified
WCAG contrast; a reconciled, source-pinned 720px responsive boundary; a directly-asserted D-02
control-reachability invariant; and six dedicated dual-theme Playwright contract modules with zero
pixel-snapshot usage. 771/771 project-wide tests (548 subtests) pass, and the 277 tests most
directly touching this phase's own six new/modified test modules pass cleanly when re-run in
isolation.

However, two functional defects survive that this phase's own code review (05-REVIEW.md) found and
that direct code inspection during this verification independently confirmed — not merely trusted
from the review document:

1. **CR-01 (blocks part of SC3/UX-06):** the keyboard chart-range-selection gesture leaks its
   pending-anchor state across an intervening mouse drag, so a later, unrelated plain Enter keypress
   can silently apply a stale, unintended date range with no visual warning. This directly
   contradicts 05-04-PLAN.md's own declared truth that a pending anchor "can always be abandoned
   without applying anything." No regression test exercises the mixed-gesture sequence that triggers
   it.
2. **WR-01 (blocks part of SC4/UX-07):** the new degraded-worker banner and the pre-existing
   recovery banner can render simultaneously with directly contradictory copy, because
   `worker_degraded` is guarded against `worker_stale` but never against `recovery_required` — a
   real, reachable combination (an on-disk recovery marker plus a merely-aging, not-yet-stale
   heartbeat) that this phase's own end-to-end tests never seed.

Both fixes are small, precisely diagnosed (in 05-REVIEW.md, and re-confirmed here at the exact line
numbers), and scoped: a one-line `cancelKeyboardRangeAnchor()` call plus a regression test for gap
1; a one-clause guard change in two files plus a regression test for gap 2.

**Separately tracked, not a phase-closure blocker:** `05-DEBT.md` D-DEBT-01 records that light-mode
`--green` fails WCAG AA (3.30:1 against the 4.5:1 requirement) for `.freshness-fresh` text, and is
deliberately left unfixed pending a human decision about retuning an app-wide colour token. This is
appropriately disclosed, scoped, and reasoned in the phase's own artifacts — it is a legitimate
scope decision awaiting a human product call, not an oversight, and is noted here for visibility
rather than raised as a gap.

---

_Verified: 2026-08-27T18:35:46Z_
_Verifier: Claude (gsd-verifier)_
