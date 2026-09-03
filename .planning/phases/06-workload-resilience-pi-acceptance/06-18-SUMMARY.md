---
phase: 06-workload-resilience-pi-acceptance
plan: 18
subsystem: infra
tags: [lock-instrumentation, raspberry-pi, acceptance-harness, hardware-evidence, three-valued-verdict]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-17's lock-profile collection, three-valued verdict logic, and rehearsed operator command path; 06-15's instrument_cost_ns_per_acquisition error bar; 06-16's held-region decomposition"
provides:
  - "06-LOCK-DIAGNOSTIC.md — the durable record of the real hardware verdict (INCONCLUSIVE) with per-route wait/hold tables from both instrumented passes"
  - "D-DEBT-06-11 — a durable ID for the pre-existing _OFFLINE_INTERVALS_BULK_ROW_LIMIT / maintenance_attributed_seconds truncation finding"
  - "D-DEBT-06-12 — the seven still-open 06-REVIEW-ROUND3.md findings (WR-01, WR-02, WR-04, WR-05, IN-01, IN-02, IN-03), consolidated with file/line/severity/disposition"
  - "An open checkpoint:decision (Task 3) awaiting the user's choice among defer-to-round-5, fix-now, refuted-replan, inconclusive-remeasure"
affects: [round-5-planning, ops-07-promotion]

actuals:
  tokens: 8800
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Diagnostic instrumented hardware pass, kept explicitly separate from OPS-07 acceptance evidence (PROH-OPS-07-11)"
    - "Verdict figures traced field-by-field to two attached JSON reports rather than narrated from memory"

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-DIAGNOSTIC.md
  modified:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md

key-decisions:
  - "Verdict recorded as INCONCLUSIVE, not upgraded — four of five checks held (including both decisive ones: scan_status_lock_wait_share_of_wall 0.9902, utilisation_above_superlinear_threshold 0.9639); one absolute-band check (services_median_hold_in_band, 596.2ms measured vs [200,500]ms band) failed high, which strengthens rather than refutes the attribution given the dataset grew 2.24x since the band was calibrated"
  - "D-DEBT-06-09, D-DEBT-06-01 (decision-coupled clause), and D-DEBT-06-10's closure were deliberately left for the continuation agent — Task 3's own <action> gates those updates on 'after the decision is recorded', and the decision has not been recorded yet"
  - "D-DEBT-06-11 and D-DEBT-06-12 were filed now because their content does not depend on which option the user selects at the checkpoint"

patterns-established:
  - "A relational check (scan_status_wait_tracks_services_hold, held) vs. an absolute-band check (services_median_hold_in_band, failed) on the same underlying quantity — flagged in the Verdict section for round 5's prediction design, since the absolute band is what broke under dataset growth"

requirements-completed: []

coverage:
  - id: D1
    description: "06-LOCK-DIAGNOSTIC.md answers all five of Truth 5's missing items with figures traceable to the two attached hardware JSON reports, and states an explicit verdict"
    requirement: "OPS-07"
    verification:
      - kind: other
        ref: "grep -cE '^## Missing item [1-5] —' 06-LOCK-DIAGNOSTIC.md == 5; grep -qE '^\\*\\*Verdict:\\*\\* (CONFIRMED|REFUTED|INCONCLUSIVE)\\b'"
        status: pass
    human_judgment: false
  - id: D2
    description: "The fix decision (Task 3, checkpoint:decision) — narrow _db_lock now, defer to round 5, or replan against a refutation/inconclusive result"
    verification: []
    human_judgment: true
    rationale: "One-way door per T-06-24/PROH-OPS-04-02/06-CONTEXT.md D-01; the plan requires this to be an explicit human decision against the measurement, not a planner inference"

duration: N/A (single continuous execution session)
completed: 2026-09-03
status: halted
---

# Phase 06 Plan 18: Real hardware lock diagnostic — INCONCLUSIVE verdict, decision pending

**Instrumented concurrency-1/concurrency-8 passes on real Raspberry Pi hardware (d9cecb8) reach an explicit INCONCLUSIVE verdict on the `_db_lock` attribution — four of five checks held, including both decisive ones — and the fix decision now waits at Task 3's blocking checkpoint.**

## Performance

- **Tasks:** 2 of 3 (Task 1 was performed by the operator before this execution and is not
  re-verified here per the calling context; Task 2 complete; Task 3 halted at its
  `checkpoint:decision`)
- **Files created:** 1 (`06-LOCK-DIAGNOSTIC.md`)
- **Files modified:** 1 (`06-DEBT.md`)
- **Commits:** 2 (plus this SUMMARY commit)

## Accomplishments

- Wrote `06-LOCK-DIAGNOSTIC.md`: all five of `06-VERIFICATION.md` Truth 5's `missing:` items
  answered with figures traced to `beacon-lockdiag-c1.json` / `beacon-lockdiag-c8.json` field names,
  an explicit `**Verdict:** INCONCLUSIVE` line, and the full `checks` list with thresholds.
- Separated the GIL's contribution from the lock's, independently: `/api/advanced/current` (0.0ms
  lock wait, by construction) degraded 12.31x with ~534ms+ of measured contention-driven off-CPU
  growth; `/api/scan-status`'s off-CPU share of its own degradation is 0.33% (negligible) against a
  99.0% lock-wait share.
- Measured the Pi's own SQL share of `/api/services`' held region (42.3% uncontended, 74.8% under
  load) against `06-PROFILE.md`'s laptop figure (17.958%) — the hardware **contradicts** the laptop
  split, and by a widening margin under contention, which materially changes the candidate fix's
  sizing (recomputed here at ~90.9% of total hold rather than a smaller share).
- Filed `D-DEBT-06-11` (the previously-unticketed `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` /
  `maintenance_attributed_seconds` truncation finding) and `D-DEBT-06-12` (the seven still-open
  `06-REVIEW-ROUND3.md` findings, with the WR-01/WR-02 avoidance-not-fix note this round's own CPU
  reasoning depended on).
- Confirmed `.planning/REQUIREMENTS.md` untouched (`git diff --quiet` holds) — OPS-07 stays Pending,
  `PROH-OPS-07-08` intact.

## Task Commits

Each task was committed atomically:

1. **Task 2: Write `06-LOCK-DIAGNOSTIC.md`** — `f5eeb13`
   (`docs(06-18): write 06-LOCK-DIAGNOSTIC.md -- hardware verdict INCONCLUSIVE`)
2. **Task 3 (decision-independent portion): File `D-DEBT-06-11` and `D-DEBT-06-12`** — `6771692`
   (`docs(06-18): file D-DEBT-06-11 and D-DEBT-06-12`)

**Plan metadata:** this SUMMARY's own commit (below).

_Task 1 (the blocking hardware `checkpoint:human-verify`) was performed by the operator directly on
the Pi, outside this execution session; its results were supplied as the input to Task 2 and are
not re-committed here._

## Files Created/Modified

- `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-DIAGNOSTIC.md` — new. Provenance
  block, in-situ overhead caveat (measured 23.05% gap against the 15% `T-06-81` band — recorded, not
  discarded), five Truth-5 sections, full per-route tables from both passes, the utilisation
  arithmetic, the GIL/lock separation, the SQL-share contradiction of `06-PROFILE.md`, and the
  Verdict section.
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — two new entries appended to
  §1 Deferred: `D-DEBT-06-11`, `D-DEBT-06-12`. `D-DEBT-06-09`, `D-DEBT-06-01`, and `D-DEBT-06-10`'s
  closure are **not yet updated** — the plan's own Task 3 `<action>` gates those three on "after the
  decision is recorded," and no decision has been recorded yet.

## Decisions Made

- **Verdict reported exactly as measured: INCONCLUSIVE, not upgraded.** The failed check
  (`services_median_hold_in_band`, 596.2ms measured against a [200ms, 500ms] band) failed on the
  *high* side, because the band was calibrated to round 3's 25,278-row dataset and this Pi now holds
  2.24x that (56,828 rows). A longer hold on more data is the mechanism getting stronger with scale,
  not weaker — but the artifact does not paper over a failed prediction to call the run CONFIRMED.
- **A relational-vs-absolute distinction was surfaced and flagged for round 5.**
  `scan_status_wait_tracks_services_hold` (a ratio, held at 0.5141) survived the dataset growth that
  broke `services_median_hold_in_band` (an absolute millisecond band). Recorded in the Verdict
  section as guidance for how round 5 should phrase any new predictions.
- **The three decision-coupled `06-DEBT.md` updates were deliberately deferred**, not omitted by
  oversight — the plan's own Task 3 text scopes `D-DEBT-06-09`'s, `D-DEBT-06-01`'s, and
  `D-DEBT-06-10`'s updates to happen *after* the checkpoint's decision is recorded, and this
  execution halts at that checkpoint without choosing.

## Deviations from Plan

None — plan executed exactly as written through the decision-independent portion of Task 3.
`06-LOCK-DIAGNOSTIC.md`'s automated verify string passed on first write (all five `## Missing item
N —` headings, all five distinctive grep fragments, the `**Verdict:**` line, and
`git diff --quiet -- .planning/REQUIREMENTS.md`).

## Issues Encountered

**A numerical inconsistency in the plan's own illustrative arithmetic was found and corrected,
sourced honestly rather than propagated.** The plan's guidance text estimated `/api/services` at
"roughly 61% of total hold." Recomputing directly from the measured figures
(`882 acquisitions × 596.245129ms exact median hold = 525,888.19ms` against `total_hold =
578,783.964515ms`) gives **90.9%**, not 61% — and the residual for the other five lock-taking
routes combined (`578,783.96ms − 525,888.19ms = 52,895.77ms`, 9.1%) reconciles cleanly against the
per-route bucketed figures. `06-LOCK-DIAGNOSTIC.md` uses the recomputed 90.9%/9.1% split throughout,
with the arithmetic shown, and the resulting fix-ceiling estimate (utilisation to ~0.745 after a 25%
Python cut, rather than the plan's illustrative ~0.82) is presented as a larger estimated payoff than
the rougher figure implied — consistent with `D-DEBT-06-10`'s own lesson about verifying arithmetic
rather than trusting a stated conclusion.

## User Setup Required

None — no external service configuration required. The Pi hardware session itself (Task 1) has
already been completed by the operator.

## Next Phase Readiness

**Blocked at Task 3's `checkpoint:decision`.** See the `CHECKPOINT REACHED` message accompanying
this SUMMARY for the four options (`defer-to-round-5`, `fix-now`, `refuted-replan`,
`inconclusive-remeasure`) framed against the INCONCLUSIVE verdict. Once the user selects an option,
a continuation agent must: update `D-DEBT-06-09` (measured verdict + pointer to
`06-LOCK-DIAGNOSTIC.md`), update `D-DEBT-06-01` (withdraw the second reopening test, record the
checkpoint's decision), close `D-DEBT-06-10`'s process half (citing all four
`plan_review_against_d_debt_06_10` sections across `06-15`–`06-18`), and run
`uv run --project dashboard python -m pytest -q` to confirm at least 859 passed / 0 failed before
this plan is marked complete.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-03 (halted at checkpoint)*
