---
phase: 03-advanced-current-diagnosis
verified: 2026-08-20T22:50:00Z
status: human_needed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
overrides: []
re_verification:
  round: 9
  previous_status: human_needed
  previous_score: 4/4
  gaps_closed:
    - "G-03-4 (03-UAT.md, opened 2026-08-20) — the /advanced workspace's interactive controls had zero cursor/hover affordance and #advanced-refresh carried none of the accent 03-UI-SPEC.md:76 reserves for it. CLOSED at the code level and independently reproduced closed. `dashboard/advanced.css` gained a nine-line interactive-affordance block (comment + 5 general rules + 3 #advanced-refresh-specific rules) across commits 2b12c4b and 07ac39c. I independently re-ran every acceptance-criteria grep the plan specifies (cursor: pointer=2, both header hover pairs=1 each, both nav hover pairs=1 each, .service-filters input=1 unchanged, min-height:44px=6 unchanged, focus-visible=1 unchanged, font-weight:600=4 with exactly 1 on #advanced-refresh, both @media blocks still last, test method count=36) — every count matches exactly. I ran `test_every_interactive_control_reads_as_interactive_in_both_themes` myself (not trusted from SUMMARY.md): 1 passed. I ran the full suite myself: 307 passed, 454 subtests, 0 failures — no regression. `git diff 2b12c4b~1..07ac39c --name-only` confirms the scope fence held: exactly `dashboard/advanced.css` and `tests/test_advanced_ui.py`, nothing else."
  gaps_remaining: []
  regressions: []
  newly_found: []
  over_credit_corrected: []
  round_8_record_condensed: "Round 8 (03-VERIFICATION.md, superseded): status human_needed, 4/4 roadmap success criteria VERIFIED via direct reproduction against a real SQLite database (not symbol presence). TEL-06's background-job-health clause — open for seven consecutive rounds — closed at the code level via 03-22-PLAN.md (J6 machinery-fault signal at the collaborator boundary, J5 fail-closed discovery vocabulary, scoped/guarded job_outcome_unrecorded floor). Five judgment-tier prohibitions all upheld. Three standing hardware human-verification items carried forward (unaffected by round 8's own changes). Full round 7-and-earlier history condensed inside round 8's own frontmatter (recoverable from this file's git history at commit 2633b9e and earlier); not restated here a second time."
prohibitions:
  - source: "03-08-PLAN.md"
    statement: "MUST NOT present resolved, retention-expired, or otherwise inferred evidence to the operator as a current, open, actionable fault -- every operator-facing open/actionable/kind label must be derivable from the durable row it describes, never from a neighbouring row or a stream-level fact."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UNCHANGED this round. 03-23 touches only dashboard/advanced.css and tests/test_advanced_ui.py — no gap/inference logic file. `git diff 2633b9e..07ac39c -- dashboard/beacon/diagnosis.py` (the file that owns this logic) is empty since round 8."
  - source: "03-08-PLAN.md"
    statement: "MUST NOT suppress a genuine collection failure while narrowing false positives -- restricting promotion by reason must never cause a real collection_gap, or a reason value the code does not recognise, to go unreported to the operator."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UNCHANGED. Not touched by this round's presentation-only diff."
  - source: "03-09-PLAN.md"
    statement: "MUST NOT let automatic background refresh silently override an operator's explicit presentation choice, and MUST NOT present a machine identifier or a placeholder as the operator's primary safety evidence when the server supplied real evidence."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UNCHANGED. `dashboard/advanced.js` is byte-unchanged since round 7 through this round (git diff confirms 07ac39c touches only advanced.css and the test file)."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT let test scaffolding mutate process-global state so that suite greenness depends on execution order."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UPHELD. The one new/extended test in this round (`test_every_interactive_control_reads_as_interactive_in_both_themes`) uses only per-test Playwright page objects created and closed inside a try/finally; it patches no module-level state. Full suite run once by me confirms 307 passed / 454 subtests, no order-dependent failures observed."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT record a requirement, plan, or phase as complete on the strength of an implementation claim rather than independent verification -- the traceability table is the project's own memory of what is actually true."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UPHELD, and STILL not reconciled after two consecutive rounds. `.planning/REQUIREMENTS.md` line 25/123 still read `- [ ] **TEL-06**` / `Gaps Found`, and 03-23-SUMMARY.md/03-23-PLAN.md do not touch REQUIREMENTS.md (git log confirms the file's last touching commit is still b3879f3, round 3). Round 8 independently determined TEL-06 SATISFIED and explicitly deferred the promotion edit to a downstream reconciliation step; that step has now been skipped for two rounds running. This verification report records ITS OWN independent determination below (Requirements Coverage) and flags the outstanding reconciliation-commit debt rather than silently promoting the file itself."
---

# Phase 3: Advanced Current Diagnosis Verification Report — Round 9 (gap-closure: G-03-4)

**Phase Goal:** The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.

**Verified:** 2026-08-20T22:50:00Z
**Status:** human_needed
**Re-verification:** Yes — round 9, after gap-closure plan 03-23 (the only plan new since round 8), closing UAT gap G-03-4.

This report supersedes round 8's `03-VERIFICATION.md` for status/score purposes while preserving its record
(condensed above in `re_verification.round_8_record_condensed`; full text recoverable from this file's git
history). Nothing below is taken from `03-23-SUMMARY.md` on trust — every grep count, the named test, and the
full suite were re-run by me against the live tree.

## Context

Round 8 found all four ROADMAP success criteria truthful at the code level but left the phase at
`human_needed` because of three standing real-hardware verification items. Those three items were then run on
the actual Pi via `03-UAT.md`: three passed, one (`test 4`, the control-affordance test) found a real cosmetic
defect and was recorded as gap `G-03-4` — `dashboard/advanced.css` had zero `cursor` declarations and zero
`:hover` rules anywhere, so no control in `/advanced` looked or answered like a button, and `Refresh now`
carried none of the accent 03-UI-SPEC.md:76 reserves for it. Gap-closure plan `03-23-PLAN.md` fixed this with a
presentation-only, nine-line CSS addition plus a real-Chromium regression test. This report independently
verifies that fix and re-confirms the phase goal is unaffected elsewhere.

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Operator can open the dedicated advanced page from the dashboard and return without losing theme. (Roadmap SC1) | ✓ VERIFIED | Unaffected this round — `dashboard/advanced.js`/`.html` byte-unchanged since round 7; `git diff 2b12c4b~1..07ac39c --name-only` shows only `advanced.css` and `tests/test_advanced_ui.py`. Carried forward from round 8's own reproduction, regression-confirmed by full suite pass (307/454). |
| 2 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, and host freshness. (Roadmap SC2) | ✓ VERIFIED | Unaffected this round. Carried forward from round 8, regression-confirmed. |
| 3 | Operator can inspect every current service's status, latency or failure class, state duration, criticality, tags, and effective health rule. (Roadmap SC3) | ✓ VERIFIED | Unaffected this round. Carried forward from round 8, regression-confirmed. |
| 4 | Operator can view truthful retention, resolution, database pressure, worker freshness, collection gaps, and background-job health, and change presentation/refresh/filtering preferences without remote controls. (Roadmap SC4) | ✓ VERIFIED | Unaffected this round — no server/diagnosis file touched by 03-23. Carried forward from round 8's independent reproduction (two J6 fault routes, J5 fail-closed both consumers, full malformed-input matrix). |
| 5 | Interactive controls in `/advanced` read as interactive (pointer cursor, hover state) in both themes, and `Refresh now` carries the accent treatment 03-UI-SPEC.md:76 reserves for it, without widening accent to any ordinary control. (G-03-4 / UX-02, 03-23-PLAN.md must-have) | ✓ VERIFIED (code/test level) | `dashboard/advanced.css:57-66` verified present and correct (see Required Artifacts). `test_every_interactive_control_reads_as_interactive_in_both_themes` (36 test methods total, was 35) run by me: 1 passed, 24 subTest-level assertions (pointer sweep, negative on `#service-search`, neutral/nav hover deltas, accent equality against the Dashboard link, accent inequality against `#pause-updates` and the unselected `Host` tab both at rest and while hovered, 44px non-regression) — all green. Human PERCEPTION of this fix (does it actually read as a button to a person, on the real Pi's own display) is inherently outside grep/test reach and is tracked separately below, not folded into this truth's automated status. |

**Score:** 5/5 truths verified at the code/automated-test level (0 present-but-behavior-unverified — truth 5's
automated component was exercised by a real-Chromium computed-style test I ran myself, not accepted on the
SUMMARY's word).

> **On G-03-4.** This is the ninth verification round of this phase and the first to close a gap surfaced by
> real-hardware UAT rather than by re-verification's own reproduction. The fix is deliberately narrow
> (presentation-only, four files touched across the whole phase reduced to two for this plan) and the review
> pass (`03-REVIEW.md` round 5, see below) independently re-derived the CSS specificity argument for why the
> new low-specificity hover rules cannot strip `#advanced-refresh`'s ID-scoped accent, rather than trusting the
> plan's own claim.

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/advanced.css` | Interactive-affordance block: grouped pointer rule, theme-scoped hover pairs (neutral + nav), `#advanced-refresh`'s accent treatment | ✓ VERIFIED | Read in full (69 lines). Lines 57-66 exactly match the plan's Artifacts table: 1 comment, 1 grouped `cursor: pointer` rule, 2 neutral hover pairs (dark/light), 1 nav-hover comment + 2 nav hover pairs, 3 `#advanced-refresh`-specific rules (base + 2 hover). All 13 independent grep counts I ran match the plan's stated acceptance values exactly (see re_verification.gaps_closed above for the full list). |
| `tests/test_advanced_ui.py` | `test_every_interactive_control_reads_as_interactive_in_both_themes` — real-browser computed-style sweep | ✓ VERIFIED | Present, 36th test method (was 35). Run by me in isolation (`-k reads_as_interactive_in_both_themes`): 1 passed in 2.11s. Run as part of the file's full 36-test suite and the whole-repo suite: all green, no interaction with pre-existing tests. |
| `dashboard/advanced.html`, `dashboard/advanced.js`, `dashboard/style.css`, `dashboard/app.py`, `dashboard/beacon/diagnosis.py`, `dashboard/beacon/previews.py` | Byte-unchanged by this plan | ✓ VERIFIED | `git diff 2b12c4b~1..07ac39c --name-only` returns exactly `dashboard/advanced.css` and `tests/test_advanced_ui.py`. Scope fence held. |
| `.planning/REQUIREMENTS.md` | Not self-promoted by 03-23 | ✓ VERIFIED (but see prohibition 5 above — reconciliation debt now 2 rounds old) | `git log -1 -- .planning/REQUIREMENTS.md` still shows round-3 commit `b3879f3`; 03-23 did not touch it. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `.advanced-header-controls button/select, .section-navigation button, .service-filters button/select, .settings-grid select, .service-details-toggle, #services-table th button` | visible pointer cursor | grouped `cursor: pointer` rule, advanced.css:58 | ✓ WIRED | Confirmed by the pointer-sweep subTest (11 selectors, both themes) and independently by reading the selector list against `advanced.html`/`advanced.js`'s actual markup. |
| Neutral controls' `:hover` | a visible `borderTopColor`/`color` change | theme-scoped hover pairs, advanced.css:59-60 | ✓ WIRED | Confirmed by hover-delta subTest on `#pause-updates` and `.service-details-toggle`, both themes. |
| `.section-navigation button:hover` | a visible border change WITHOUT stealing the `aria-selected` tab's accent | advanced.css:62-63, deliberately sets no `color` | ✓ WIRED, SEMANTICALLY CORRECT | Confirmed by the negative accent subTest: `[data-section="host"]` (unselected) while hovered still differs from `#advanced-refresh`'s accent color, and `button[aria-selected="true"]` still equals it. Independently corroborated by `03-REVIEW.md`'s own specificity analysis: ID rule `(1,0,0)` beats class rule `(0,3,2)`. |
| `#advanced-refresh` | accent text/border/weight equal to the Dashboard link's, distinct from `#pause-updates`'s | ID-scoped rule, advanced.css:64-66 | ✓ WIRED | Confirmed by the equality/inequality subTest against `.advanced-header a` and `#pause-updates`. |
| `03-UI-SPEC.md:76`'s accent reservation | the CSS that implements it | test's explicit equality (positive) + inequality (negative, 3 controls, at rest and hovered) assertions | ✓ WIRED, asserted not assumed | Both directions exercised in both themes. |

### Data-Flow Trace (Level 4)

Not applicable to this round in the usual sense — this is a presentation-only CSS/test change with no new
data source. No rendered value in `/advanced` changed source or shape; only its interactive/visual styling
changed. Data flow for the four ROADMAP success criteria is unaffected and carried forward from round 8.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| G-03-4's own named test | `pytest -q tests/test_advanced_ui.py -k reads_as_interactive_in_both_themes -x -v` | 1 passed, 35 deselected | ✓ PASS |
| Every acceptance-criteria grep from 03-23-PLAN.md, re-run independently | 13 separate `grep -c` commands against `dashboard/advanced.css` and `tests/test_advanced_ui.py` | all 13 values match the plan's stated targets exactly (see gaps_closed list) | ✓ PASS |
| Full whole-repo test suite (run once) | `pytest -q` | 307 passed, 454 subtests, 0 failures, 87.23s | ✓ PASS |
| Scope fence | `git diff 2b12c4b~1..07ac39c --name-only` | exactly `dashboard/advanced.css`, `tests/test_advanced_ui.py` | ✓ PASS |
| Debt-marker gate on modified files | `grep -n -E "TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER"` on both files | zero matches, exit 1 (no match) on both | ✓ PASS |

### Probe Execution

| Probe | Command | Result | Status |
| --- | --- | --- | --- |
| — | `find scripts -path '*/tests/probe-*.sh'` | no matches | ? SKIP (project defines no probe scripts) |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| **TEL-06** | 03-01…03-22 | Operator can see effective retention, displayed resolution, database pressure, worker freshness, collection gaps, and background-job health. | ✓ SATISFIED (independently re-confirmed unaffected; traceability table still reads pre-promotion state) | Round 8 independently reproduced all six clauses truthful, including background-job health for every job. 03-23 touches no file this requirement depends on (`app.py`, `beacon/diagnosis.py`, `beacon/previews.py` all byte-unchanged since round 8). `.planning/REQUIREMENTS.md` still reads `- [ ] **TEL-06**` / `Gaps Found` — this is a documentation-reconciliation debt, not a functional gap; see prohibition 5 above. |
| **DIA-01** | 03-01 | Operator can open a dedicated advanced page from either theme. | ✓ SATISFIED | Unaffected this round. Table already reads `Complete`. |
| **DIA-02** | 03-02 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, freshness. | ✓ SATISFIED | Unaffected this round. Table already reads `Complete`. |
| **DIA-03** | 03-03, 03-11, 03-16 | Operator can inspect every service's status, latency/failure class, duration, criticality, tags, health rule. | ✓ SATISFIED | Unaffected this round. Table already reads `Complete`. |
| **DIA-08** | 03-04 | Operator can view effective monitoring settings and change presentation, refresh, **range**, and filtering preferences without remote-control actions. | ⏸ DEFERRED to Phase 4 | Unaffected this round. `dashboard/advanced.html` still has no range control; ROADMAP Phase 4 SC1 explicitly covers it. Table already reads `Deferred to Phase 4`. |
| **UX-02** | 03-01, 03-05, **03-23** | Operator can move between dashboard and advanced without losing theme choice. | ✓ SATISFIED | Original theme-preservation mechanism unaffected this round. 03-23-PLAN.md additionally declares `requirements: [UX-02]` for the control-affordance fix (a UX-quality dimension of the same requirement's underlying workspace); its own three backstop truths asserting the theme round-trip and scroll-precision contracts are unaffected are independently confirmed here: the diff adds only `cursor`, `color`, `border-color`, `font-weight`, and `background` declarations — no `position`, `width`, `height`, `margin`, `padding`, `display`, `grid`, or theme/storage/navigation JS touched. |

**Orphaned requirements:** none. `grep -E "\| Phase 3 \|" .planning/REQUIREMENTS.md` returns exactly the six
IDs this task lists, matching every prior round.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| — | — | Debt markers (`TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER`) on `dashboard/advanced.css` and `tests/test_advanced_ui.py` | — | ✓ NONE FOUND — gate passes. |
| `dashboard/app.py` | 1831, 1334-1343 | WR-03 (lease-loss-on-busy-branch escalation), WR-05 (uptime-disclosure boundary jitter comment) | ⚠️ Warning (carried forward, unaffected) | `03-REVIEW.md` round 5, re-confirmed present, not touched by 03-23. Pre-existing, not new. |
| `dashboard/beacon/diagnosis.py` | 482-508 | WR-01 (a job whose start-write silently fails reads as permanently healthy — no regression test drives this path) | ⚠️ Warning (carried forward, unaffected) | `03-REVIEW.md` round 5. Not touched by 03-23; not part of G-03-4. |
| `dashboard/beacon/repositories.py` | 143-149 | WR-02 (a noisy telemetry stream can starve other services' gap evidence) | ⚠️ Warning (carried forward, unaffected) | `03-REVIEW.md` round 5. Not touched by 03-23. |
| `dashboard/app.py` | (dead function) | `_table_columns` — new-in-round-5 Info finding, unused f-string SQL builder | ℹ️ Info (carried forward, unaffected) | `03-REVIEW.md` round 5 (IN-07). Not touched by 03-23; not reachable, not a live vulnerability. |

**Debt-marker gate:** PASSED. Zero matches on both files this round touched.

**03-23 diff review:** `03-REVIEW.md` round 5 explicitly reviewed the interactive-affordance CSS and its test,
independently re-deriving the CSS-specificity argument for why the new low-specificity hover rules cannot
strip `#advanced-refresh`'s ID-scoped accent, and found **no defect** in the diff. I independently re-confirm
this by reading the actual `advanced.css` rule order and specificity myself (see Key Link Verification above).

### Human Verification Required

The following five items are the closure evidence for G-03-4 that no automated check can supply, carried into
this report per `workflow.human_verify_mode: end-of-phase` (2 new perception items from 03-23's Task 2 human-check
block, plus 3 standing hardware items carried forward unchanged from round 8's `human_verification` block).

#### 1. The reported defect, directly (NEW, G-03-4-specific)

**Test:** On the target Pi, open `/advanced` in dark mode. Point at `Refresh now` without clicking. Then switch to light mode and repeat.
**Expected:** Pointing-hand cursor; the button's background visibly brightens toward the accent color on hover; and — before hovering anything — `Refresh now` already reads as the primary action of the header (accent text, accent border, heavier weight), plainly distinct from `Pause updates`.
**Why human:** Perception cannot be proven by a computed-style delta alone — this is the exact complaint that opened G-03-4.
**Status this round:** Per the task context supplied for this verification run, the user has visually confirmed on the real Pi that `Refresh now` now reads as the primary action. This confirmation is not yet recorded as a git-tracked artifact (no `03-UAT.md` update or commit reflects it as of this report); recording it is a follow-up documentation step, not a code gap.

#### 2. Perceptibility of hover feedback across the workspace (NEW, G-03-4-specific)

**Test:** On the Pi, in each theme, point in turn at `Pause updates`, the refresh-interval dropdown, a section tab, a Services table column header, a row's `Show details` control, and a filter dropdown.
**Expected:** Every one shows the pointing hand and visibly answers hover (cyan border in dark mode, darker slate border and label in light mode); the search box keeps a text caret (no pointer); an unselected section tab does not turn accent-colored on hover.
**Why human:** The tints are 8-12% alpha and the light-mode border shift is subtle by design — whether they are actually visible at the Pi's own display brightness and viewing angle is a judgement call outside `getComputedStyle`'s reach.
**Status this round:** Not confirmed. No evidence in the task context or the repository indicates this item has been checked on real hardware yet.

#### 3. Real collection gap and stale host on the target Pi (standing, unaffected by this round)

**Test:** Open `/advanced` on the Pi while a real collection gap is active and while host evidence is stale.
**Expected:** The workspace shows the open gap and the stale host as real, correctly labelled exceptions, and shows no resolved or retention-expired interval as an open actionable gap.
**Why human:** `03-UAT.md` test 1 already recorded this as PASS on real hardware on 2026-08-20 ~13:00. Carried forward only to re-confirm this round's stylesheet-only change did not disturb it — no logic file this test depends on was touched.

#### 4. Idle Pi, one minute, Active exceptions region (standing, unaffected by this round)

**Test:** Start the worker, leave the system idle for one minute, open `/advanced`, read the Overview "Active exceptions" region.
**Expected:** No "Background job failed" card for any job, no "Background job outcome not recorded" card for any job that is simply working.
**Why human:** `03-UAT.md` test 2 already recorded this as PASS on real hardware on 2026-08-20 13:03. Carried forward only to re-confirm this round's stylesheet-only change did not disturb it.

#### 5. Deliberately broken browser, two minutes, Pipeline region (standing, unaffected by this round)

**Test:** With Chromium/Playwright deliberately unavailable, leave the worker running for two minutes, open `/advanced`, read the Pipeline region.
**Expected:** A "Background job failed" card names J6.
**Why human:** `03-UAT.md` test 3 already recorded this as PASS on real hardware on 2026-08-20 21:43 (with a noted caveat that the render itself was not photographed within the transient failure window — tracked as a Deferred Follow-Up, not a gap). Carried forward only to re-confirm this round's stylesheet-only change did not disturb it.

### Gaps Summary

**None.** G-03-4 is closed at the code level: the interactive-affordance CSS is present, correctly scoped, and
independently reproduced correct by a real-Chromium test I ran myself (not accepted from SUMMARY.md); every
one of the plan's 13 acceptance-criteria grep counts matches exactly; the scope fence held (exactly two files
touched across both commits); the full 307-test/454-subtest suite passes with no regression; and
`03-REVIEW.md`'s independent code review of this exact diff found zero defects.

Two of the five human-verification items are new to this round (both perception-only, both stemming from
G-03-4). Item 1 has an informal real-Pi confirmation from the user recorded in this session's context but not
yet as a git-tracked artifact; item 2 has not yet been checked on real hardware. Items 3-5 are standing,
already-passed-on-hardware items carried forward for re-confirmation only, at essentially zero risk given the
presentation-only nature of this round's change. Overall status is `human_needed`, not `passed`, solely because
these items exist — not because any observable truth failed. This mirrors the same convention round 8 applied
to its own three standing items, and is consistent with this project's precedent that a real-hardware
perception/behavior check is a standing human-verification item, not a promotion blocker, once the code-level
truth is independently reproduced.

**One outstanding process item, not a functional gap:** the `.planning/REQUIREMENTS.md` reconciliation for
TEL-06 (independently determined SATISFIED by round 8 and re-confirmed unaffected by this round) has now been
deferred for two consecutive rounds. This report recommends the next phase-completion step include the
`docs(phase-03): record requirement statuses established by re-verification round 9` reconciliation commit this
project's own established convention calls for, rather than leaving the traceability table further out of date.

---

_Verified: 2026-08-20T22:50:00Z_
_Verifier: Claude (gsd-verifier), round 9, adversarial goal-backward, gap-closure focus on G-03-4_
_Every grep count, the named test, and the full test suite in this report were run by me directly against the
live tree — none accepted from `03-23-SUMMARY.md` on trust. `git diff 2b12c4b~1..07ac39c` was read in full to
confirm the scope fence held._
