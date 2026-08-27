---
phase: 05-theme-parity-analytics-experience
verified: 2026-08-28T00:20:00Z
status: passed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 3/5
  gaps_closed:
    - "Operator can use the dashboard and advanced workspace at supported narrow and desktop viewport widths, including keyboard-accessible status and chart interactions with text labels that do not rely on colour alone (ROADMAP SC3 / UX-06) — CR-01 fixed"
    - "Loading, empty, stale, unknown, degraded, and error states are visibly and meaningfully distinct in both themes (ROADMAP SC4 / UX-07) — WR-01 fixed"
  gaps_remaining: []
  regressions: []
---

# Phase 5: Theme-Parity Analytics Experience Verification Report

**Phase Goal:** Beacon provides a cohesive, responsive, accessible monitoring experience in which
light and dark themes expose the same advanced capability while retaining the calm everyday
dashboard.
**Verified:** 2026-08-28T00:20:00Z
**Status:** passed
**Re-verification:** Yes — after gap closure (plan 05-07)

## Goal Achievement

### Observable Truths

| # | Truth (ROADMAP Success Criterion) | Status | Evidence |
|---|---|---|---|
| 1 | Operator continues to see compact analytics and history previews on the main dashboard in both light and dark themes | ✓ VERIFIED (no regression) | Untouched by 05-07 (`dashboard/style.css`, `dashboard/index.html` not in `files_modified`). `tests/test_ui_contract.py`/`test_ui_states.py` re-run: pass, part of the confirmed 776/552 full-suite run. |
| 2 | Both themes expose the same advanced analytics data, filters, settings, and investigation workflows, with light mode using calmer progressive disclosure and dark mode allowing denser simultaneous context | ✓ VERIFIED (no regression) | `densityDisclosureDefault()` and the disclosure/density surfaces untouched by 05-07's diff (confirmed via `git show f69fbb8`/`db9f2a4` — only the drag/anchor functions and the two `worker_degraded` expressions changed). `tests/test_advanced_ui.py` re-run: pass. |
| 3 | Operator can use the dashboard and advanced workspace at supported narrow and desktop viewport widths, including keyboard-accessible status and chart interactions with text labels that do not rely on colour alone | ✓ VERIFIED | CR-01 closed. Direct read of `dashboard/advanced.js:2264-2266` confirms `beginDragSelect` calls `cancelKeyboardRangeAnchor()` before `overlay.hidden = false`; `dashboard/advanced.js:2243-2250` confirms `cancelDragSelect` also calls it, covering commit (`commitDragSelect` calls `cancelDragSelect()` unconditionally), Escape (`dragEscapeListener`), and `pointercancel` (registered directly in `beginDragSelect`) — every mouse-gesture exit path. Independently ran `test_mouse_drag_abandons_a_pending_keyboard_anchor_so_a_later_plain_enter_applies_nothing` and `test_cancelled_mouse_drag_also_abandons_a_pending_keyboard_anchor`: both pass. Read both test bodies directly — Test 1 genuinely exercises anchor → real mouse drag (down/move/up) → plain Enter on an unrelated target, asserting the drag's own range survives unchanged and no stale request fires. Confirmed the uninterrupted keyboard gesture is unaffected: `Shift+Enter` → `Tab` → `Enter` fires no `pointerdown`/`pointercancel`, so `beginDragSelect`/`cancelDragSelect` never run; `test_keyboard_range_selection_applies_the_same_range_as_the_mouse_drag` and `test_pending_range_anchor_is_abandoned_without_applying_anything` (the two pre-existing gesture tests) both re-run and pass. |
| 4 | Loading, empty, stale, unknown, degraded, and error states are visibly and meaningfully distinct in both themes | ✓ VERIFIED | WR-01 closed. Direct read confirms `dashboard/app.py:3056` — `state['worker_degraded'] = (not worker_stale) and (not state['recovery_required']) and state['worker_freshness']['state'] == 'aging'` — and `dashboard/beacon/diagnosis.py:682` — `'worker_degraded': pipeline['worker']['freshness']['state'] == 'aging' and not recovery_required`. `recovery_required` is assigned above `worker_degraded` in both files (line 3044 before 3056 in `app.py`; line 666 before 682 in `diagnosis.py`). Repo-wide `grep -rn "worker_degraded"` confirms these are the only two computation sites; both client renderers (`dashboard/app.js:151`, `dashboard/advanced.js:3193`) only consume the server boolean, never re-derive it — D-01 honored (server classifies, client renders, no client-side heuristic added). Independently ran `test_recovery_marker_with_aging_heartbeat_renders_only_the_recovery_banner_on_both_documents` (4-way theme × document subtest matrix, seeds a real on-disk `RECOVERY_MARKER` file plus a real aging-not-stale heartbeat — read the test body, confirmed no payload stub), `test_scan_status_never_reports_degraded_while_recovery_is_required`, and `test_safety_never_reports_degraded_while_recovery_is_required`: all pass. |
| 5 | UI-contract or visual-regression coverage verifies shared capabilities and important states in both themes | ✓ VERIFIED (extended, no regression) | Five new regression tests added across four existing dual-theme/DOM-contract test modules — no new pixel-snapshot infra introduced. `grep -rho 'to_have_screenshot\|page.screenshot' tests/` independently re-run: zero matches. |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `dashboard/advanced.js` | `beginDragSelect`/`cancelDragSelect` both clear `pendingRangeAnchor` | ✓ VERIFIED | Both call sites confirmed present by direct read; `grep -c "let pendingRangeAnchor"` returns 1 (no state restructure). |
| `dashboard/app.py` | `worker_degraded` gated on `not recovery_required` in addition to `not worker_stale` | ✓ VERIFIED | Confirmed at line 3056; `recovery_required` reordered above it (line 3044). |
| `dashboard/beacon/diagnosis.py` | `safety['worker_degraded']` gated on `not recovery_required` | ✓ VERIFIED | Confirmed at line 682; local `recovery_required` already in scope from line 666. |
| `tests/test_history_investigation_ui.py` | Two regression tests for the anchor-leak gap | ✓ VERIFIED | Both present, both pass independently re-run; bodies confirmed to exercise the exact anchor→mouse-gesture→Enter sequence. |
| `tests/test_ui_safety_integration.py` | Rendered-page regression test, 4-way theme/document matrix | ✓ VERIFIED | Present, passes; seeds a real on-disk recovery marker and a real aging heartbeat — not a payload stub. |
| `tests/test_api_and_auth.py` | `/api/scan-status` payload regression test | ✓ VERIFIED | Present, passes; asserts all four facts plus the direct exclusivity invariant. |
| `tests/test_advanced_diagnosis_api.py` | `/api/advanced/current` safety-block regression test | ✓ VERIFIED | Present, passes; asserts the equivalent invariant on the second surface. |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `dashboard/advanced.js: beginDragSelect` | `dashboard/advanced.js: cancelKeyboardRangeAnchor` | direct call, ordered before `overlay.hidden = false` | ✓ WIRED | Confirmed by direct read and by the plan's own source-order assertion re-derived manually. |
| `dashboard/advanced.js: cancelDragSelect` | `dashboard/advanced.js: cancelKeyboardRangeAnchor` | direct call | ✓ WIRED | Confirmed; covers commit/Escape/pointercancel via `cancelDragSelect`'s three callers. |
| `dashboard/app.py: api_scan_status` | `state['recovery_required']` | assigned before `worker_degraded` reads it | ✓ WIRED | Line 3044 precedes line 3056. |
| `dashboard/beacon/diagnosis.py: get_current_diagnosis` | local `recovery_required` | in scope before the `safety` dict is built | ✓ WIRED | Line 666 precedes line 682; no reorder needed (was already correctly ordered). |
| `dashboard/app.js` / `dashboard/advanced.js` | `worker_degraded`/`recovery_required` payload fields | banner `hidden` toggles consume server booleans directly | ✓ WIRED, no client-side precedence logic | Confirmed no mutual-exclusion guard was added client-side — D-01 and 05-07's prohibition 4 both honored. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Gap-1 regression pair | `pytest tests/test_history_investigation_ui.py -k "keyboard_anchor or range_anchor or drag"` | 10 passed | ✓ PASS |
| Gap-2 regression trio + surrounding modules | `pytest tests/test_ui_safety_integration.py tests/test_api_and_auth.py tests/test_advanced_diagnosis_api.py` | 92 passed, 199 subtests passed | ✓ PASS |
| Phase-relevant six-module suite | `pytest tests/test_ui_safety_integration.py tests/test_advanced_ui.py tests/test_theme_parity_ui.py tests/test_ui_contract.py tests/test_ui_states.py tests/test_history_investigation_ui.py` | 280 passed, 144 subtests passed (up from prior round's 277/140) | ✓ PASS |
| Full project-wide suite (run once) | `uv run --project dashboard python -m pytest -q` | 776 passed, 552 subtests passed, 0 failures (up from prior round's 771/548) | ✓ PASS |
| Zero screenshot-API usage (OPS-06) | `grep -rho 'to_have_screenshot\|page.screenshot' tests/` | no matches | ✓ PASS |
| No third `worker_degraded` computation site | `grep -rn "worker_degraded" dashboard/` | exactly 2 assignment sites (`app.py:3056`, `diagnosis.py:682`), 2 client-consume sites | ✓ PASS |
| Debt-marker scan on 05-07-touched files | `grep -n -E "TBD\|FIXME\|XXX"` across all 7 files_modified | no matches | ✓ PASS |
| Pointercancel-vs-Escape reasoning (claim 4) | Direct read of `dashboard/advanced.js:1904-1908` | Confirmed: unconditional window-level `keydown` listener calls `cancelKeyboardRangeAnchor()` on every Escape regardless of drag state, independent of `cancelDragSelect` | ✓ PASS — the substitution is sound, not under-testing |

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|---|---|---|---|---|
| UX-01 | 05-03 | Compact analytics/history previews remain on main dashboard in both themes | ✓ SATISFIED (unchanged, re-confirmed no regression) | Not touched by 05-07; prior round's evidence still holds, `tests/test_ui_states.py` re-run passes as part of full suite. |
| UX-03 | 05-03, 05-05 | Advanced analytics exposes same data/filters/settings/investigations in both themes | ✓ SATISFIED (unchanged, re-confirmed no regression) | Not touched by 05-07; `tests/test_advanced_ui.py` re-run passes. |
| UX-04 | 05-05 | Light calmer disclosure, dark denser context, density-driven | ✓ SATISFIED (unchanged, re-confirmed no regression) | Not touched by 05-07. |
| UX-05 | 05-06 | Advanced analytics usable at narrow and desktop widths | ✓ SATISFIED (unchanged, re-confirmed no regression) | Not touched by 05-07; `tests/test_theme_parity_ui.py` re-run passes. |
| UX-06 | 05-02, 05-04, 05-07 | Status/chart info via text/labels/keyboard, not colour alone | ✓ SATISFIED | CR-01 closed; the mouse-gesture-abandons-keyboard-anchor invariant is now real and tested. **Ready for promotion in REQUIREMENTS.md** (currently `Pending` — 05-07's executor deliberately left it unpromoted per project precedent that only an independent verifier may promote; this round is that independent verification and confirms the gap is closed). |
| UX-07 | 05-01, 05-02, 05-05, 05-07 | Loading/empty/stale/unknown/degraded/error visibly distinct | ✓ SATISFIED | WR-01 closed; the two worker safety banners can no longer render simultaneously with contradictory copy. **Ready for promotion in REQUIREMENTS.md** (same reasoning as UX-06 — currently `Pending`, this round confirms closure). |
| OPS-06 | all plans incl. 05-07 | UI-contract/visual-regression coverage for both themes | ✓ SATISFIED (extended, no regression) | Five new regression tests added, zero pixel-snapshot usage confirmed. |

No orphaned requirements: the declared `requirements` field across all seven plans (`UX-01, UX-03, UX-04, UX-05, UX-06, UX-07, OPS-06`) exactly matches REQUIREMENTS.md's Phase 5 mapping and this phase's stated requirement IDs.

**Note for orchestrator:** REQUIREMENTS.md currently shows all seven of this phase's requirements (`UX-01, UX-03, UX-04, UX-05, UX-06, UX-07, OPS-06`) as `Pending`, even though five were already ✓ SATISFIED in the prior verification round — the whole-phase `gaps_found` status blocked promotion of any of them. With this round returning `status: passed` at 5/5, all seven requirements are ready to be promoted to `Complete`.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| `dashboard/advanced.js` | 369-372 | `freshnessWord()`'s `'aging'` branch remains unreachable dead code (05-REVIEW.md IN-01, carried forward, untouched by 05-07) | ℹ️ Info | No functional impact; not a gap; explicitly out of scope for gap closure. |
| `dashboard/advanced.js` | 2243-2248 | `cancelDragSelect` redundantly re-does the overlay hide/reset that `cancelKeyboardRangeAnchor` already performs (05-REVIEW.md IN-02, new, from the 05-07 diff) | ℹ️ Info | Harmless idempotent duplicate DOM writes, no observable behavior difference. Not a gap. |
| — | — | No `TBD`/`FIXME`/`XXX` debt markers found in any of the 7 files 05-07 modified | — | — |

### Human Verification Required

None. Both previously-open defects (CR-01, WR-01) were code-level correctness gaps with deterministic reproductions and fixes, independently confirmed here by direct code read and by re-running every relevant test myself (not trusting SUMMARY.md's or 05-REVIEW.md's claims). No visual/UX judgment call remains open for this phase's closure.

### Gaps Summary

None. Both gaps recorded in the prior `05-VERIFICATION.md` round are closed:

1. **CR-01 (was blocking SC3/UX-06):** confirmed fixed by direct read of `dashboard/advanced.js` — `beginDragSelect` now calls `cancelKeyboardRangeAnchor()` before un-hiding the overlay, and `cancelDragSelect` calls it defensively, covering every mouse-gesture exit path (commit, Escape, pointercancel). The uninterrupted keyboard-only gesture is unaffected — it fires no pointer events at all, and both pre-existing gesture tests still pass. The two new regression tests genuinely reproduce the original defect sequence (anchor → intervening mouse gesture → plain Enter) and were independently re-run here, passing.

2. **WR-01 (was blocking SC4/UX-07):** confirmed fixed by direct read of `dashboard/app.py` and `dashboard/beacon/diagnosis.py` — both `worker_degraded` computations now require `not recovery_required` alongside their existing conjuncts, with `recovery_required` computed before it is read in each. A repo-wide grep confirms no third computation site exists, and both client renderers consume the server boolean directly with no added client-side precedence logic — honoring 05-CONTEXT D-01. The new rendered-page regression test seeds a real on-disk recovery marker alongside a real aging-not-stale heartbeat (not a stubbed payload) and independently re-run here across all four theme/document combinations, passing.

3. **The `Escape` → `pointercancel` test-substitution claim (05-07-SUMMARY.md Decision 1) checked and confirmed sound:** `dashboard/advanced.js:1904-1908` contains a pre-existing, unconditional window-level `keydown` listener (`bindTimeCursorHandlers`, from 05-04 Task 3 A-22) that calls `cancelKeyboardRangeAnchor()` on every Escape keypress regardless of drag state, entirely independent of `cancelDragSelect`. Using Escape as the cancelled-drag test's abandonment vector would have passed whether or not `cancelDragSelect`'s own new defensive call existed, silently under-testing that call site. The synthetic `pointercancel` dispatch used instead exercises exactly that call site with no confound — this is a genuine test-quality improvement, not a coverage gap.

4. All previously-verified truths (SC1, SC2, SC5, and requirements UX-01/UX-03/UX-04/UX-05/OPS-06) re-checked for regression: the 05-07 diff touches only `dashboard/advanced.js` (the drag/anchor functions), `dashboard/app.py` and `dashboard/beacon/diagnosis.py` (the two `worker_degraded` expressions), and four test files — no overlap with the main-dashboard, disclosure/density, or responsive-boundary surfaces those truths depend on. The full project-wide test suite (776 passed, 552 subtests, 0 failures) and the phase's own six-module suite (280 passed, 144 subtests, up from 277/140) were both independently re-run here, confirming zero regressions.

**Separately tracked, not a phase-closure blocker (unchanged from prior round):** `05-DEBT.md` D-DEBT-01 (light-mode `--green` WCAG AA contrast at 3.30:1) remains deliberately deferred pending a human product decision; `dashboard/style.css` was not touched by 05-07, so this is confirmed unworsened. `05-REVIEW.md` IN-01 (unreachable `'aging'` branch) remains open and untouched, still Info-severity with no functional impact. A new, equally minor IN-02 (redundant overlay reset) was introduced by the fix itself, also Info-severity with no functional impact — noted above, not a gap.

---

_Verified: 2026-08-28T00:20:00Z_
_Verifier: Claude (gsd-verifier)_
