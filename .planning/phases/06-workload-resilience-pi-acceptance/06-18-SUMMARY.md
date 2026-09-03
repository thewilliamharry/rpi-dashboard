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
  - "D-DEBT-06-14 — the relational-vs-absolute prediction lesson for round 5's LOCK_ATTRIBUTION_PREDICTIONS"
  - "D-DEBT-06-15 — narrowing _db_lock cannot fix /api/advanced/current's GIL-bound budget failure; corrected fix-sizing arithmetic (0.745-0.82 utilisation range, not the laptop-implied deeper cut)"
  - "The user's fix-now decision recorded verbatim in D-DEBT-06-09 and D-DEBT-06-01, with D-01's fence explicitly lifted for the follow-up plan (06-19+) and PROH-OPS-04-05's audit prerequisites restated for it"
affects: [round-5-planning, 06-19-fix-plan, ops-07-promotion]

actuals:
  tokens: 16400
  tasks: 3
  commits: 3

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
  - "D-DEBT-06-11 and D-DEBT-06-12 were filed in the first execution because their content does not depend on which option the user selects at the checkpoint"
  - "USER DECISION at Task 3's checkpoint: fix-now, selected against the recorded planner recommendation (defer-to-round-5). Recorded as the user's decision made on the evidence: four of five checks held including both decisive ones, and the lone failure is a stale absolute band (rescaling it to this run's own dataset growth, ~[246ms,615ms], the measured 596.2ms would read CONFIRMED), not a missing measurement. The verdict itself stays INCONCLUSIVE in 06-LOCK-DIAGNOSTIC.md -- the decision is not a retroactive upgrade of that verdict."
  - "06-CONTEXT.md D-01's fence on _db_lock's scope is explicitly lifted by this decision for the follow-up plan (06-19 or later), not by this plan and not implicitly -- no line touching _db_lock changes here"
  - "D-DEBT-06-01's second reopening test is withdrawn as non-diagnostic (retired, not merely unfired): it uses the unlocked, GIL-bound /api/advanced/current as the discriminator for a lock, and round 4 measured that route's lock_wait_ns_total at exactly 0.0ms, confirming it can never carry evidence about _db_lock in either direction"
  - "D-DEBT-06-10's process half closed: all four round-4 plans (06-15 through 06-18) carry a plan_review_against_d_debt_06_10 section that changed a real defect (unsatisfiable AST clause, two demoted tautological identities, an isinstance-to-call-count inertness check, a failure-reasons leak, a non-empty assertion) -- this is the entry's own stated closure bar, met four times"
  - "D-DEBT-06-02's CPU trigger could not be re-read against a round-4 figure: 06-LOCK-DIAGNOSTIC.md does not transcribe cpu_sampling.mean_cpu_percent for either pass, and the raw JSON reports are Pi-host-only, not committed to this repository -- the trigger stays NOT TRIGGERED on round 3's 165.504% reading, unchanged by round 4"
  - "Filed D-DEBT-06-14 (relational-vs-absolute prediction lesson for round 5) and D-DEBT-06-15 (narrowing _db_lock alone cannot fix /api/advanced/current's GIL-bound failure; the SQL/Python split contradiction sizes the fix's payoff at 0.745-0.82 utilisation, not the deeper cut the laptop profile implied)"

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
    rationale: "One-way door per T-06-24/PROH-OPS-04-02/06-CONTEXT.md D-01; the plan requires this to be an explicit human decision against the measurement, not a planner inference. RESOLVED: the user selected fix-now. Recorded verbatim in D-DEBT-06-09 and D-DEBT-06-01; the narrowing itself is implemented in a follow-up plan (06-19+), not this one."

duration: N/A (two execution sessions: initial hardware-diagnostic write-up, then this decision-recording continuation)
completed: 2026-09-03
status: complete
---

# Phase 06 Plan 18: Real hardware lock diagnostic — INCONCLUSIVE verdict, user selected fix-now

**Instrumented concurrency-1/concurrency-8 passes on real Raspberry Pi hardware (d9cecb8) reach an explicit INCONCLUSIVE verdict on the `_db_lock` attribution — four of five checks held, including both decisive ones. At Task 3's blocking checkpoint, against that measurement and the planner's recommendation to defer, the user selected `fix-now`; the decision and its debt-register consequences (withdrawn reopening test, D-01's fence lifted, PROH-OPS-04-05's audit prerequisites restated, D-DEBT-06-10 closed, two new debt entries) are recorded here. The narrowing itself is not implemented in this plan — it is scoped into a follow-up plan (06-19 or later).**

## Performance

- **Tasks:** 3 of 3 complete (Task 1 performed by the operator directly on the Pi, outside any
  execution session; Task 2 complete in the first session; Task 3's decision-independent filings
  completed in the first session, its decision-coupled debt updates completed in this
  continuation session after the checkpoint was resolved)
- **Files created:** 1 (`06-LOCK-DIAGNOSTIC.md`)
- **Files modified:** 1 (`06-DEBT.md`, across two commits)
- **Commits:** 3 task commits (plus this SUMMARY commit)

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
- **The checkpoint resolved: the user selected `fix-now`.** Recorded verbatim in `D-DEBT-06-09` and
  `D-DEBT-06-01`, against the recorded INCONCLUSIVE verdict and the planner's recommendation to
  defer. `06-CONTEXT.md` D-01's fence on `_db_lock`'s scope is explicitly lifted for the follow-up
  plan (`06-19` or later) that implements the narrowing — no line touching `_db_lock` changes in
  this plan.
- `D-DEBT-06-01`'s second reopening test is withdrawn as non-diagnostic and retired (not merely
  unfired): round 4 measured `/api/advanced/current`'s `lock_wait_ns_total` at exactly 0.0ms,
  confirming by direct measurement that the route can never carry evidence about `_db_lock`.
- `D-DEBT-06-10`'s process half is closed, citing all four round-4 plans'
  `plan_review_against_d_debt_06_10` sections and what each one changed.
- `D-DEBT-06-02`'s CPU-starvation trigger was re-read against round 4's evidence: no round-4
  `mean_cpu_percent` figure exists in any committed artifact (`06-LOCK-DIAGNOSTIC.md` reports
  per-request CPU accounting, not process-level `cpu_sampling`; the raw JSON is Pi-host-only), so
  the trigger stays NOT TRIGGERED on round 3's 165.504% reading.
- Filed `D-DEBT-06-14` (the relational-check-survived / absolute-band-failed prediction lesson for
  round 5's `LOCK_ATTRIBUTION_PREDICTIONS`) and `D-DEBT-06-15` (narrowing `_db_lock` cannot fix
  `/api/advanced/current`'s GIL-bound budget failure; the hardware SQL/Python split — 74.8%/25.0%,
  not the laptop's 17.958%/82.042% — sizes the achievable fix payoff at roughly 0.745–0.82
  utilisation, materially smaller than a laptop-based estimate would have implied).

## Task Commits

Each task was committed atomically, across two execution sessions:

1. **Task 2: Write `06-LOCK-DIAGNOSTIC.md`** — `f5eeb13`
   (`docs(06-18): write 06-LOCK-DIAGNOSTIC.md -- hardware verdict INCONCLUSIVE`)
2. **Task 3 (decision-independent portion): File `D-DEBT-06-11` and `D-DEBT-06-12`** — `6771692`
   (`docs(06-18): file D-DEBT-06-11 and D-DEBT-06-12`)
3. **Task 3 (decision-coupled portion, this continuation session): record the `fix-now` decision
   and its debt-register consequences** — `34062a0`
   (`docs(06-18): record fix-now decision and debt consequences`)

**Plan metadata:** this SUMMARY's own commit (below).

_Task 1 (the blocking hardware `checkpoint:human-verify`) was performed by the operator directly on
the Pi, outside any execution session; its results were supplied as the input to Task 2 and are
not re-committed here._

## Files Created/Modified

- `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-DIAGNOSTIC.md` — new. Provenance
  block, in-situ overhead caveat (measured 23.05% gap against the 15% `T-06-81` band — recorded, not
  discarded), five Truth-5 sections, full per-route tables from both passes, the utilisation
  arithmetic, the GIL/lock separation, the SQL-share contradiction of `06-PROFILE.md`, and the
  Verdict section.
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — first session appended two
  entries to §1 Deferred (`D-DEBT-06-11`, `D-DEBT-06-12`); this continuation session updated
  `D-DEBT-06-09` (measured verdict, checks table, the closure this satisfies), `D-DEBT-06-01`
  (withdrawn second reopening test, the `fix-now` decision, D-01's fence lifted, `PROH-OPS-04-05`'s
  prerequisites restated for the follow-up plan), `D-DEBT-06-10` (process half closed, citing all
  four `plan_review_against_d_debt_06_10` sections), `D-DEBT-06-02` (re-read against round 4;
  no new figure available, stays NOT TRIGGERED), and filed two further new entries,
  `D-DEBT-06-14` (relational-vs-absolute prediction lesson) and `D-DEBT-06-15` (narrowing `_db_lock`
  alone cannot fix `/api/advanced/current`; corrected fix-sizing arithmetic).

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
- **The three decision-coupled `06-DEBT.md` updates were deliberately deferred in the first
  session**, not omitted by oversight — the plan's own Task 3 text scopes `D-DEBT-06-09`'s,
  `D-DEBT-06-01`'s, and `D-DEBT-06-10`'s updates to happen *after* the checkpoint's decision is
  recorded, and that session halted at the checkpoint without choosing.
- **The checkpoint's decision: `fix-now`, selected by the user.** Recorded verbatim, against the
  INCONCLUSIVE verdict and the planner's recorded recommendation to defer. This is a legitimate
  engineering call on the evidence: four of five checks held, including both decisive ones
  (`scan_status_lock_wait_share_of_wall` 0.9902, `utilisation_above_superlinear_threshold` 0.9639),
  and the single failure is a stale absolute band, not a missing measurement — rescaling that band
  to this run's own dataset growth reproduces a CONFIRMED reading on the identical figures. The
  verdict recorded in `06-LOCK-DIAGNOSTIC.md` stays INCONCLUSIVE; the decision does not retroactively
  upgrade it.
- **`D-DEBT-06-01`'s second reopening test is withdrawn as retired, not merely unfired.** Round 4's
  own measurement (`/api/advanced/current`'s `lock_wait_ns_total` at exactly 0.0ms across 880
  requests) confirms the mechanism that made the test non-diagnostic does not depend on load or
  dataset size — a route with zero lock exposure cannot discriminate a lock hypothesis in any run.
- **`06-CONTEXT.md` D-01's fence is explicitly lifted for the follow-up plan, not implicitly
  overridden and not lifted in this plan.** `PROH-OPS-04-05`'s audit prerequisites (per-call-site
  `_db_lock` audit across all 28 sites, a cross-process/concurrent-writer integrity test, and
  `/gsd-secure-phase 06` re-run because `T-06-24`'s closure evidence is invalidated by construction)
  are restated verbatim in `D-DEBT-06-01`, not re-derived, as the gate that plan must pass. `06-15`'s
  AST scope pin is expected and correct to fail once the narrowing lands — that failure routes the
  implementer back to this record, not something to suppress.
- **`D-DEBT-06-10`'s process half is closed**, citing all four round-4 plans'
  `plan_review_against_d_debt_06_10` sections and quoting what each one changed: `06-15`'s
  unsatisfiable-AST-clause correction and its `isinstance`-to-call-count inertness fix; `06-16`'s
  demotion of two by-construction summing identities from load-bearing guards to sanity checks;
  `06-17`'s collection-failure-no-longer-feeds-`failure_reasons` fix and its boolean-to-three-valued
  verdict change; `06-18`'s deterministic-arm non-empty assertion.
- **`D-DEBT-06-02`'s CPU trigger could not be re-read against a new round-4 figure.**
  `06-LOCK-DIAGNOSTIC.md` reports per-request CPU accounting (from `lock_profile.requests[*]`), not
  the process-level `cpu_sampling.mean_cpu_percent` this entry's trigger is defined against, and the
  raw hardware JSON reports are not committed to this repository. The trigger reading is therefore
  carried forward unchanged from round 3 (165.504%, NOT TRIGGERED) rather than fabricated from an
  unavailable source.

## Deviations from Plan

None — plan executed exactly as written across both sessions. `06-LOCK-DIAGNOSTIC.md`'s automated
verify string passed on first write (all five `## Missing item N —` headings, all five distinctive
grep fragments, the `**Verdict:**` line, and `git diff --quiet -- .planning/REQUIREMENTS.md`). This
continuation session's `06-DEBT.md` updates are documentation-only, per the calling context's
explicit instruction not to implement the narrowing itself — that is scoped into a follow-up plan
(`06-19` or later) the orchestrator plans separately. `git diff --quiet -- dashboard/ tests/` holds:
no code changed. `git diff --quiet -- .planning/REQUIREMENTS.md` holds: OPS-07 stays Pending.

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

**The full suite reports one failure not in the two-test known-flaky set named by `D-DEBT-06-13`.**
`uv run --project dashboard python -m pytest -q` reported **918 passed, 1 failed, 561 subtests
passed** — the failure is
`tests/test_lock_profile.py::LockProfileInertnessTests::test_disabled_wrapper_path_costs_nothing_measurable`,
which asserts the flag-off `_db_lock` wrapper costs no more than 1.02x a bare `threading.Lock` over
30 interleaved iterations. Re-run in isolation per this task's instruction, it failed again,
consistently: 1.0238x on the first run, 1.0268x on the isolated re-run — a real, reproducible
measurement on this environment, not an intermittent flake in the pass/fail sense (it did not pass
on either attempt). It is the same *class* of defect `D-DEBT-06-13` already tracks: a razor-thin
(2%) timing-tolerance assertion that is inherently sensitive to the executing environment's load,
just measured on a different environment than whichever one last calibrated the 1.02 threshold.
This entry is scoped to record the fix decision and its debt consequences, not to touch `tests/` —
`git diff --quiet -- dashboard/ tests/` holds unmodified — so the test is left as observed rather
than adjusted. A future round should fold this into `D-DEBT-06-13`'s named set or recalibrate the
threshold against a measured baseline, the same remedy that entry already proposes for its two
named tests.

## User Setup Required

None — no external service configuration required. The Pi hardware session itself (Task 1) has
already been completed by the operator.

## Next Phase Readiness

**Plan complete.** All three tasks are done: Task 1 (operator hardware run), Task 2
(`06-LOCK-DIAGNOSTIC.md`), and Task 3 (the checkpoint's decision — `fix-now` — recorded verbatim,
with `D-DEBT-06-09`, `D-DEBT-06-01`, `D-DEBT-06-10`, and `D-DEBT-06-02` updated, and `D-DEBT-06-14` /
`D-DEBT-06-15` filed).

**What the follow-up plan (`06-19` or later) inherits, so the orchestrator can plan it directly
rather than re-deriving scope:**
- The narrowing itself: `_db_lock`'s scope, per the measured attribution in `06-LOCK-DIAGNOSTIC.md`
  and `D-DEBT-06-01`'s "Round 4 reopening" section.
- `PROH-OPS-04-05`'s four prerequisites, restated verbatim in `D-DEBT-06-01`: the per-call-site
  `_db_lock` audit across all 28 sites (superseding `06-15`'s `LockScopePreservationTests` pin,
  which will and should fail once the narrowing lands), the WAL-specific no-longer-blocks-behind-a-
  writer demonstration, the cross-process/concurrent-writer integrity test extending
  `PROH-OPS-04-01`'s guarantee, and a `/gsd-secure-phase 06` re-run to re-close `T-06-24` on new
  evidence.
- `D-DEBT-06-15`'s scoping input: the fix's estimated payoff is 0.745-0.82 post-fix utilisation
  (not the deeper cut the laptop profile implied), and it does not touch `/api/advanced/current`'s
  separate GIL-bound budget failure — the follow-up plan should either accept that as a second
  known gap or scope a topology-level remedy for it too.
- `D-DEBT-06-14`'s guidance for any diagnostic-harness prediction changes: relational, not absolute,
  or explicitly dataset-scaled.
- `D-DEBT-06-13`'s known-flaky floor should be read as "no NEW failures outside the known set" —
  and this session's own `test_disabled_wrapper_path_costs_nothing_measurable` failure (see Issues
  Encountered) should be folded into that set or recalibrated before it is mistaken for a
  regression introduced by the fix plan.
- `.planning/REQUIREMENTS.md` remains unedited by this plan; OPS-07 stays Pending
  (`PROH-OPS-07-08`) until an independent verification round promotes it, per `D-DEBT-06-08`'s
  precedent.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-03*

## Self-Check: PASSED

- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md`
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-DIAGNOSTIC.md`
- FOUND commit `f5eeb13` (Task 2)
- FOUND commit `6771692` (Task 3, decision-independent filings)
- FOUND commit `34062a0` (Task 3, decision-coupled debt updates — this session)
- Confirmed: `git diff --quiet -- .planning/REQUIREMENTS.md` holds
- Confirmed: `git diff --quiet -- dashboard/ tests/` holds
