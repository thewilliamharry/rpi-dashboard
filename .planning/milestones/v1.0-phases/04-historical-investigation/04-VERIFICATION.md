---
phase: 04-historical-investigation
verified: 2026-08-27T01:20:00Z
status: passed
score: 6/6 must-haves verified
behavior_unverified: 0
overrides_applied: 0
overrides: []
re_verification:
  previous_status: gaps_found
  previous_score: 5/6
  gaps_closed:
    - "WR-01 (new, 04-REVIEW.md 2026-08-26) -- renderIncidentsSection no longer substitutes the filtered incident count for the unfiltered baseline total when the baseline fetch fails. updateMatchingIncidentCount(matching, total) now takes total: number | null; renderIncidentsSection derives an explicit totalKnown const (the baseline outcome fulfilled AND its value.episodes an array) and passes null -- never episodes.length -- when it is false. The null branch renders '{N} of ? incidents (total unavailable)' and sets data-total-known=\"false\"; the ordinary branch is byte-identical to the pre-change '{N} of {M} incidents' text and sets data-total-known=\"true\". Independently re-confirmed: grep for the deleted ': episodes.length' fallback returns nothing; the two new regression tests pass; and I independently reproduced the RED state by checking out the pre-fix commit (a7436c8, test added, fix not yet landed) into a scratch worktree and re-running the new test there -- it failed with the exact text the SUMMARY records ('1 of 1 incidents' != '1 of ? incidents (total unavailable)'), confirming the test is a genuine regression, not vacuously true."
  gaps_remaining: []
  regressions: []
gaps: []
deferred: []
human_verification: []
---

# Phase 4: Historical Investigation Verification Report

**Phase Goal:** The operator can investigate a selected time range, service, or incident through correlated history that is detailed, bounded, and candid about what Beacon did and did not observe.

**Verified:** 2026-08-27T01:20:00Z
**Status:** passed
**Re-verification:** Yes — third round, after gap-closure plan 04-11

## Context

This is the third verification round for Phase 4. Round 1 found `gaps_found` (4/6): two blocking
gaps (HIS-04's CR-01/CR-02/WR-01, and DIA-05/WR-02's DST gap). Round 2, after gap-closure plans
04-09/04-10, found `gaps_found` (5/6): both round-1 gaps genuinely closed, but a fresh code review
(`04-REVIEW.md`) found one new, narrower defect in the same Incidents view — `renderIncidentsSection`
silently substituted the filtered count for the unfiltered baseline total on a partial fetch
failure, rendering a misleading `"N of N incidents"`. Gap-closure plan `04-11` was planned and
executed specifically to close that one remaining gap, plus reconcile `REQUIREMENTS.md` for DIA-04
and HIS-04's residual-finding note.

I independently re-verified this round rather than trusting `04-11-SUMMARY.md` or `04-11-REVIEW.md`
prose:

- **Read the live source** (`dashboard/advanced.js` lines 1080-1440) directly, not the diff excerpt
  in the SUMMARY. Confirmed `updateMatchingIncidentCount`'s `total === null` branch, both branches'
  unconditional `textContent`/`dataset.totalKnown` writes, and `renderIncidentsSection`'s
  `totalKnown` const/derivation are exactly as claimed, with no remaining `: episodes.length`
  fallback anywhere in the file (`grep -n ': episodes.length' dashboard/advanced.js` returns
  nothing) and exactly one call site of `updateMatchingIncidentCount` (line 1437).
- **Ran the two new regression tests myself** — both pass. To rule out a vacuously-true test, I
  created a scratch git worktree at commit `a7436c8` (the RED commit — test added, fix not yet
  landed) and ran `test_baseline_total_fetch_failure_never_claims_the_filtered_count_is_the_total`
  there directly. It failed with `AssertionError: '1 of 1 incidents' != '1 of ? incidents (total
  unavailable)'` — the exact pre-fix behavior and the exact text the SUMMARY's TDD note claims. This
  is independent, first-hand confirmation the regression is genuine, not a restatement of the
  SUMMARY's own claim.
- **Re-confirmed round-2 closures are untouched.** `git diff ad942e8..HEAD -- dashboard/beacon/incidents.py dashboard/app.py`
  returns zero lines — 04-11 did not touch either file. Re-ran
  `tests/test_incidents_api.py::EpisodeScopeRegressionTests` (11/11 pass) and the WR-02/episode-scope
  disclosure tests in `tests/test_history_investigation_ui.py` (6 passed, 3 subtests) directly, fresh
  in this round — both hold.
- **Checked REQUIREMENTS.md honestly.** DIA-04 is now `[x]` Complete with a note that names the
  round-2 hold, cites round-2's own Requirements Coverage determination, and records the discharge —
  the required verbatim sentence is present exactly once, matching the plan's gate. HIS-04's note is
  appended (not overwritten) with the WR-01 (new) closure and its pinning test name. Both are
  accurate; neither overstates what was found.
- **Weighed the 04-11-REVIEW.md Info item** (see below) rather than silently dropping it.

## Goal Achievement

### Observable Truths

| # | Truth (source: ROADMAP.md Success Criteria) | Status | Evidence |
|---|---|---|---|
| 1 | Operator can choose shared preset ranges from 1h through 90d, or a validated custom range | ✓ VERIFIED | Unaffected by 04-11 (scope fence confirmed — `parseLocalRangeInput`/`validateCustomRange` untouched). Re-confirmed present and unmodified. |
| 2 | Operator can inspect CPU/memory/disk/temperature history with units, threshold context, tooltips, visible gaps, and latest/min/max/avg/trend comparisons | ✓ VERIFIED | Unaffected by 04-11; unmodified since round 2. |
| 3 | Operator can inspect time-weighted availability, state timeline, latency, failure classes, and unknown intervals for a selected service | ✓ VERIFIED | Unaffected by 04-11; unmodified since round 2. |
| 4 | Operator can filter incidents and transitions by service, criticality, event type, and time range, and the result is an honest picture of what happened | ✓ VERIFIED (gap closed) | CR-01/CR-02/WR-01(original) remain closed (`dashboard/beacon/incidents.py`/`dashboard/app.py` untouched since 04-10, 11/11 `EpisodeScopeRegressionTests` re-run and pass). WR-01 (new) — the "N of N" baseline-substitution defect — is now closed: `renderIncidentsSection` derives an explicit `totalKnown` flag and renders `"{N} of ? incidents (total unavailable)"` with `data-total-known="false"` on a baseline failure, independently confirmed live in source and by a self-reproduced RED→GREEN test run. |
| 5 | Selecting a service, incident, or time range updates related host, service, and event views together, presenting observed correlation without an unsupported causal claim | ✓ VERIFIED | Unaffected by 04-11; `grep -in "root cause\|caused by\|because of\|due to" dashboard/advanced.js dashboard/advanced.html` returns zero matches (re-run this round). |
| 6 | The Incidents view is candid when a partial fetch fails — a number never claims parity it does not have | ✓ VERIFIED (new truth, closing round 2's residual gap) | `updateMatchingIncidentCount`'s `null`-total branch and `renderIncidentsSection`'s `totalKnown` derivation replace the silent fallback; both requests succeeding still renders the byte-identical `"{N} of {M} incidents"` (confirmed unchanged by diff inspection and by re-running the two pre-existing exact-count tests); a recovered baseline restores a known total (`test_recovered_baseline_fetch_restores_a_known_total`, independently re-run, passes). |

**Score:** 6/6 truths verified. (Truth 6 is split out from round 2's single "filtering" truth to give
the closed WR-01 (new) defect its own line, since it was the phase's sole remaining gap.)

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `dashboard/advanced.js` | Explicit `totalKnown` flag; `updateMatchingIncidentCount(matching, total: number \| null)` | ✓ VERIFIED | Read directly at lines 1104-1440. `total === null` strict check (never a falsy check — `0` stays distinguishable); both branches write `textContent` and `dataset.totalKnown` unconditionally; `renderIncidentsSection`'s `totalKnown`/`total` derivation at lines 1435-1436 replaces the old ternary; zero remaining `: episodes.length` fallback in the file. |
| `tests/test_history_investigation_ui.py` | `test_baseline_total_fetch_failure_never_claims_the_filtered_count_is_the_total`, `test_recovered_baseline_fetch_restores_a_known_total` | ✓ VERIFIED | Both independently run and pass. RED state independently reproduced against pre-fix commit `a7436c8` in a scratch worktree — genuine regression, not vacuous. 134 tests collected (was 132 in round 2, +2 new). |
| `.planning/phases/04-historical-investigation/04-UI-SPEC.md` | Copywriting Contract row for the unknown-total state; E4's `partial` category extended | ✓ VERIFIED | `Incidents matching-count — unfiltered total unavailable` row present with copy `{N} of ? incidents (total unavailable)`; E4's Resolution/Reason cell extended with the failed-baseline-read clause; note beneath the Copywriting Contract table names 04-11. |
| `.planning/REQUIREMENTS.md` | DIA-04 promoted to Complete on cited evidence; HIS-04's note names the WR-01 (new) closure | ✓ VERIFIED | `[x] **DIA-04**` and `\| DIA-04 \| Phase 4 \| Complete \|` present; note records the round-2 hold, its discharge, and the cited evidence (the required verbatim sentence present exactly once). HIS-04's note appended with the WR-01 (new) finding, its closure by 04-11, and the pinning test name — the original CR-01/CR-02/WR-01 history preserved, not overwritten. |
| `dashboard/beacon/incidents.py`, `dashboard/app.py` | Untouched by 04-11 (scope fence) | ✓ VERIFIED | `git diff ad942e8..HEAD` for both files returns zero lines — confirmed independently, not merely asserted by the scope fence. |
| `dashboard/advanced.html` | No new element; existing `#matching-incident-count` reused | ✓ VERIFIED | Not in 04-11's changed-file list; no new id, no CSS change required (`dataset.totalKnown` is a plain data attribute). |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `dashboard/advanced.js` (`renderIncidentsSection`) | `dashboard/advanced.js` (`updateMatchingIncidentCount`) | Explicit `totalKnown` flag, `null` on baseline failure | ✓ WIRED | Confirmed at lines 1435-1437 — no remaining silent-fallback path; only one call site in the file. |
| `dashboard/advanced.js` (`updateMatchingIncidentCount`) | `dashboard/advanced.html` (`#matching-incident-count`) | `textContent` + `dataset.totalKnown` | ✓ WIRED | Both branches write both on every call — a stale uncertainty state cannot survive into a later successful render (confirmed by the recovery test). |
| `tests/test_history_investigation_ui.py` | `dashboard/advanced.js` (`renderIncidentsSection`) | `events_failure_fn` route predicate stubbing the unfiltered baseline request only | ✓ WIRED | Confirmed via independent re-run and RED-state reproduction. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| New regressions pass (fresh run, this round) | `pytest tests/test_history_investigation_ui.py::HistoryInvestigationUiTests::test_baseline_total_fetch_failure_never_claims_the_filtered_count_is_the_total test_recovered_baseline_fetch_restores_a_known_total test_incident_criticality_filter_issues_request_and_narrows_count test_zero_match_incidents_renders_empty_copy_and_matching_count -q` | `4 passed in 3.32s` | ✓ PASS |
| New regression is genuinely RED against pre-fix code (not vacuous) | Checked out commit `a7436c8` (test-added, fix-not-landed) into scratch worktree, ran the new test | `AssertionError: '1 of 1 incidents' != '1 of ? incidents (total unavailable)'` | ✓ CONFIRMS GENUINE REGRESSION |
| Round-2 closure regressions still pass (fresh run, this round) | `pytest tests/test_incidents_api.py::EpisodeScopeRegressionTests -q` | `11 passed in 1.06s` | ✓ PASS |
| Round-2 WR-02/episode-scope disclosure tests still pass (fresh run) | `pytest tests/test_history_investigation_ui.py -k "CustomRangeDstGapTests or test_event_type_narrowing_is_disclosed_in_the_incidents_section or test_no_narrowing_leaves_the_episode_scope_note_absent" -q` | `6 passed, 128 deselected, 3 subtests passed` | ✓ PASS |
| `incidents.py`/`app.py` untouched by 04-11 (scope fence, verified not assumed) | `git diff ad942e8..HEAD -- dashboard/beacon/incidents.py dashboard/app.py \| wc -l` | `0` | ✓ PASS |
| Silent fallback fully gone from source | `grep -n ': episodes.length' dashboard/advanced.js` | No match | ✓ PASS |
| No debt markers introduced | `grep -n -E "TBD\|FIXME\|XXX\|TODO\|HACK\|PLACEHOLDER" dashboard/advanced.js tests/test_history_investigation_ui.py` | No matches | ✓ PASS |
| No causal-language leak | `grep -in "root cause\|caused by\|because of\|due to" dashboard/advanced.js dashboard/advanced.html` | No matches | ✓ PASS |
| No HTML sink introduced | `grep -c "innerHTML\|insertAdjacentHTML" dashboard/advanced.js` | `0` | ✓ PASS |
| Phase 5 accessibility item stayed out of scope | `grep -c "setAttribute('role', 'img')" dashboard/advanced.js` | `3` (unchanged) | ✓ PASS |

### Requirements Coverage

| Requirement | REQUIREMENTS.md (current) | My independent determination | Evidence |
|---|---|---|---|
| DIA-04 | `[x]` Complete | **CONFIRMED SATISFIED** | Note names the round-2 hold and its discharge; preset ladder, active-state indication and persisted preference unaffected by any round-3 change; note's required verbatim sentence present exactly once. |
| DIA-05, DIA-06, DIA-07, DIA-08 | `[x]` Complete | **CONFIRMED SATISFIED — no change this round** | Untouched by 04-11 (scope fence verified via `git diff`); WR-02 closure previously confirmed and re-confirmed by re-run test this round. |
| HIS-01, HIS-02, HIS-03, HIS-06 | `[x]` Complete | **CONFIRMED SATISFIED — no change** | Unaffected by 04-11. |
| HIS-04 | `[x]` Complete | **CONFIRMED SATISFIED — WR-01 (new) now closed** | CR-01/CR-02/WR-01(original) genuinely closed since round 2 (11/11 re-run and pass, source untouched); WR-01 (new) baseline-substitution defect now closed and independently re-confirmed (source read + genuine RED→GREEN reproduction). Note updated to name the closure and its pinning test. |
| HIS-05 | `[x]` Complete | **CONFIRMED SATISFIED — no change** | `focusIncident`'s precondition unaffected. |

**Orphaned requirements:** None. All 11 phase requirement IDs (DIA-04 through DIA-08, HIS-01 through
HIS-06) appear in a plan's `requirements` field across 04-01 through 04-11, and all are accounted for
above.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| `dashboard/advanced.js` | 1421-1430 | `filteredOutcome`-failure early return in `renderIncidentsSection` never calls `updateMatchingIncidentCount`, so a stale count (including, since 04-11, the new `"(total unavailable)"` text) can persist beside the `#incidents-error` banner | Info — pre-existing, unmodified by any Phase 4 plan; see judgment below | Confirmed live at the cited lines; independently re-read, matches `04-11-REVIEW.md`'s IN-01 exactly. |
| `dashboard/advanced.js` | 1582-1601 | `renderMarkerSingle` uses `role="img"` on a click/keydown-interactive SVG circle, inconsistent with `role="button"` used elsewhere | Info/Warning — explicitly Phase 5 scope | `04-CONTEXT.md` places accessibility work in Phase 5; re-confirmed untouched this round (`role="img"` count still 3, no new diff line touches any ARIA role). Carried forward again for Phase 5 to inherit. |
| — | — | No TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER markers in any 04-11-modified file | Info | Clean. |

**Judgment on the IN-01 stale-count Info item (as the verification brief explicitly asks):** I weighed
this against the phase's own candour standard and conclude it does **not** rise to a Phase 4 gap, for
four reasons. First, it is not new: it existed for the ordinary `"N of M"` text since `renderIncidentsSection`
was created in 04-07, predating even round 1's verification — 04-11 only means the same pre-existing
staleness can now also leave `"(total unavailable)"` on screen instead of `"N of M"`, which is not a
worse failure mode, just a different stale string. Second, when the *filtered* request itself fails
(the path this Info item concerns), an explicit, visible error banner is shown
(`"Beacon could not load incidents for this range. Try again, or narrow the range."`) — the operator
is not left believing a false number is authoritative with zero indication anything is wrong; they see
an unambiguous failure notice. This is materially different from the closed WR-01 (new) defect, where
the filtered request *succeeded* and no error indication of any kind accompanied the misleading count.
Third, both `04-11-REVIEW.md` and `04-11-PLAN.md`'s own scope fence treat this as deliberately
out-of-scope, citing the identical, longer-standing non-reset behavior of `beginIncidentsLoadingState`
for the same element — accepting this scope fence is consistent with round 2's own precedent of
carrying forward a confirmed, real defect (the accessibility mismatch) to Anti-Patterns rather than
blocking on it. Fourth, it is genuinely narrow: it requires the filtered request itself to fail (not a
normal filter selection, not even the baseline-only failure this round's gap concerned) at the exact
moment a previous render had already populated a count. I record it here as tracked debt, not as a gap,
consistent with the "recorded, not silently dropped" standard the brief sets — it should be picked up
opportunistically or in Phase 5's loading/error-state hygiene work, but it does not block Phase 4.

### Gaps Summary

None. The single gap remaining after round 2 (WR-01 new — the baseline-fetch-failure "N of N"
substitution) is closed, independently re-confirmed at the source level, the test level (with a
self-reproduced genuine RED state, not merely a passing GREEN taken on faith), and the scope-fence
level (round-2's closures untouched). `REQUIREMENTS.md` is honestly reconciled: DIA-04 promoted with
cited evidence and a preserved history of the hold; HIS-04's note names both the original breakage
and its full restoration, including this round's closure.

**What is genuinely resolved across all three rounds:**

- CR-01 (silently-down services vanishing from a filtered Incidents view) — closed, round 2 and
  round 3 both re-confirm.
- CR-02 (a recovered incident mislabelled "Ongoing," or silently dropped) — closed, re-confirmed.
- WR-01 (original — a suppressed anchor's evidence leaking through `maintenance=exclude`) — closed,
  re-confirmed.
- WR-02 (a custom range typed into the DST spring-forward gap silently accepted) — closed,
  re-confirmed.
- WR-01 (new — the baseline-fetch-failure "N of N" substitution) — closed this round, independently
  verified with a self-reproduced RED→GREEN cycle, not merely taken on the SUMMARY's word.

**Remaining bookkeeping (not a phase gap):** `.planning/ROADMAP.md`'s `04-11-PLAN.md` line item is
still `- [ ]` (unchecked) as of this verification; the phase-level `10/10` plan-count line and the
`In Progress` phase status also predate this closure. These are ROADMAP bookkeeping fields the
orchestrator updates as part of closing out a passed verification, not evidence of unfinished
implementation work — every artifact and test the checkbox would represent is independently confirmed
above.

Everything examined outside the Incidents section — the preset ladder, the four-chart host stack,
the comparison/trend row, the service state band and time-weighted availability, the navigation
stack and drag-to-select, and the neutral marker rail/hover cursor — remains genuinely implemented,
wired, and unaffected by any of this round's changes.

---

_Verified: 2026-08-27T01:20:00Z_
_Verifier: Claude (gsd-verifier)_
