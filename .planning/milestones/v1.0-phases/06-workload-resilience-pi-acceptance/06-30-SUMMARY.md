---
phase: 06-workload-resilience-pi-acceptance
plan: 30
subsystem: database
tags: [sqlite, uptime, gap-closure, ops-07, decision-record, debt-tracking]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-29's CTE reshape, its narrowed rounding guard, and 06-PROFILE-4.md's FAIL-BUT-IMPROVED verdict against the pre-06-25 56.820ms baseline"
provides:
  - "06-GUARD-DECISION.md: 06-25's unmet acceptance criterion recorded against 06-25 (not absorbed here), the guard narrowing's stated legitimacy distinction (proxy was wrong, not code-couldn't-comply), the three-mutation re-proof it is not weaker, two rejected division-avoiding alternatives, the enumerated 06-27/06-28 amendments, and the operator's revert-route-wiring checkpoint decision with reasoning"
  - "D-DEBT-06-22: the execute-to-summary verification-path gap that let 06-25 report 3/3 complete while omitting an acceptance criterion"
  - "D-DEBT-06-23: the SQL formulation's cost floor (ordered_points' LEAD window alone ~= the Python sweep's total cost) with the held-in-reserve ordered_points restructure"
  - "D-DEBT-06-21 updated with option C's measured outcome under the reshape and the operator's decision"
affects: [06-27, 06-28]

actuals:
  tokens: 7200
  tasks: 3
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Recording an executed plan's unmet acceptance criterion against the plan that owned it, with a grep-proven omission check run at two historical commits, rather than absorbing the gap into the round that later works around it"
    - "Stating a guard-narrowing's legitimacy as a standalone sentence naming the exact distinction it turns on (premise was wrong vs. code could not comply), citing the project's own precedent for drawing that line"

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-GUARD-DECISION.md
  modified:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md

key-decisions:
  - "The operator selected `revert-route-wiring` at Task 2's blocking checkpoint: /api/services reverts to the Python sweep (restoring the 56.820ms baseline) while read_uptime_strips_by_port and its full test suite stay in the tree as a proven-correct implementation and evidence base for a future round. The revert itself is a separate plan — no .py file appears in this plan's diff."
  - "06-25's unmet UPTIME_STRIP_QUERY regression-guard criterion is recorded against 06-25 (PROH-OPS-07-27), not absorbed into this round's record; 06-25-PLAN.md and 06-25-SUMMARY.md are left unedited so both the original specification and the original omission stay legible."
  - "The rounding guard's narrowing is recorded as legitimate specifically because the original proxy ('/' not in query) was wrong about what it protected, not because the reshaped code could not meet it — cited against PROH-OPS-07-01, PROH-OPS-07-10, and PROH-OPS-07-23, and against the project's own criterion-5 amendment precedent in ROADMAP.md."

requirements-completed: []

coverage:
  - id: D1
    description: "06-25's unimplemented acceptance criterion is recorded as unmet against 06-25, quoted verbatim from 06-25-PLAN.md lines 508-522, with the grep proving the omission at two historical commits, and with 06-25-SUMMARY.md's undisclosed 3/3-complete report named"
    requirement: OPS-07
    verification:
      - kind: other
        ref: "grep -rn 'UPTIME_STRIP_QUERY' tests/ (returns nothing at 9da5e5e and at 8a84139~1); git diff -- 06-25-PLAN.md 06-25-SUMMARY.md (empty)"
        status: pass
    human_judgment: true
    rationale: "Whether the record quotes rather than paraphrases the criterion, and whether it discloses the omission honestly rather than softening it, requires human review of prose, not keyword presence."
  - id: D2
    description: "The rounding guard's narrowing is recorded as a reasoned decision stating the exact distinction it turns on, and the narrowed form is shown (via 06-29's three reproduced mutation messages) not to be weaker than the original against the hazard it exists for"
    requirement: OPS-07
    verification:
      - kind: other
        ref: "grep -c 'PROH-OPS-07-23|PROH-OPS-07-27|PROH-OPS-07-01|PROH-OPS-07-10' 06-GUARD-DECISION.md (4 matches, all four IDs present)"
        status: pass
    human_judgment: true
    rationale: "Whether the standalone legitimacy sentence is honestly stated (premise-was-wrong vs. code-could-not-comply) and whether the mutation evidence is reproduced rather than asserted requires human review of the argument, not a keyword count."
  - id: D3
    description: "06-27 and 06-28 are not left describing a build that no longer exists: the specific amendments each needs after this round are enumerated, and the append-contract reason neither PLAN.md is edited is stated"
    requirement: OPS-07
    verification:
      - kind: other
        ref: "git diff --stat -- '*-PLAN.md' (empty — no PLAN.md modified); grep -c '06-27' and '06-28' in 06-GUARD-DECISION.md (9 and 8 respectively)"
        status: pass
    human_judgment: false
  - id: D4
    description: "The operator decides, at a blocking checkpoint, between keeping the reshape and reverting /api/services' wiring, with 06-PROFILE-4.md's measured verdict and the cost of each branch in front of them; the outcome is recorded in both 06-GUARD-DECISION.md section 8 and D-DEBT-06-21's update"
    requirement: OPS-04
    verification:
      - kind: other
        ref: "grep -n 'revert-route-wiring' 06-GUARD-DECISION.md 06-DEBT.md (present in both)"
        status: pass
    human_judgment: false
  - id: D5
    description: "06-DEBT.md records D-DEBT-06-22 (the unimplemented-and-undisclosed criterion) and D-DEBT-06-23 (the SQL cost floor with the held-in-reserve restructure), and D-DEBT-06-21 is appended to, not rewritten"
    requirement: OPS-07
    verification:
      - kind: other
        ref: "grep -c 'D-DEBT-06-22|D-DEBT-06-23' 06-DEBT.md (3 matches); git diff -- 06-DEBT.md | grep -c '^-[^-]' (0 deletions)"
        status: pass
    human_judgment: false

duration: ~25min
completed: 2026-09-06
status: complete
---

# Phase 6 Plan 30: Record the Round's Findings and the Operator's Decision Summary

**Recorded `06-25`'s unmet UPTIME_STRIP_QUERY regression-guard criterion against `06-25` itself (never absorbed into this fixing round), the guard narrowing's stated legitimacy distinction with a three-mutation re-proof it is not weaker, the enumerated `06-27`/`06-28` amendments neither PLAN.md may carry directly, and the operator's `revert-route-wiring` decision against `06-PROFILE-4.md`'s FAIL-BUT-IMPROVED verdict (69.191ms vs. a 56.820ms bar).**

## Performance

- **Duration:** ~25 min
- **Tasks:** 3 (Task 2 was a pre-resolved checkpoint recorded per the operator's instructions, not re-prompted)
- **Files modified:** 2 (1 created)

## Accomplishments

- **`06-25`'s unmet acceptance criterion is on the record, against `06-25`.** `06-25-PLAN.md` lines 508-522 specified a static test asserting `'/' not in UPTIME_STRIP_QUERY` and `'round(' not in UPTIME_STRIP_QUERY.lower()`; it was never written. `grep -rn "UPTIME_STRIP_QUERY" tests/` returns nothing at both `9da5e5e` (the commit `06-25-SUMMARY.md` reports landed) and `8a84139~1` (HEAD immediately before `06-29`), confirming the gap spanned the entire `06-25`..`06-28` interval. `06-25-SUMMARY.md` reported 3/3 tasks complete with `Self-Check: PASSED` and never disclosed it. `06-25-PLAN.md` and `06-25-SUMMARY.md` are left unedited (`git diff` empty on both) so the original specification and the original omission both stay legible.
- **The guard narrowing's legitimacy is recorded as a stated distinction, not an assertion.** `06-GUARD-DECISION.md` section 4 states, in a standalone sentence, that the guard was narrowed because the original proxy (`'/' not in query`) was wrong about what it protected — not because `06-29`'s reshape could not meet it — citing `PROH-OPS-07-01`, `PROH-OPS-07-10`, `PROH-OPS-07-23`, and the project's own `ROADMAP.md` criterion-5 amendment precedent for drawing exactly this line.
- **The narrowed guard is shown, not claimed, to still catch the hazard.** Section 5 reproduces `06-29` Task 2's three mutation messages verbatim (mutation (c), (c-prime), (c-double-prime)) and draws the specific inference each supports, concluding on that evidence that the narrowed allowlist closes the same surface the original's blanket division ban covered.
- **Two division-avoiding alternatives are named and rejected on evidence**, not merely on preference: computing indices in Python (blocked by `PROH-OPS-07-24`'s boundedness guards, since the segments never reach Python before the range is needed) and recursive-increment expansion (reproduces the `O(UPTIME_BUCKETS)`-per-segment cost the reshape exists to remove).
- **`06-27` and `06-28` are not orphaned.** Neither PLAN.md is edited (per the append contract); `06-GUARD-DECISION.md` section 7 enumerates three required amendments for `06-27` (both build SHAs restated, the `PROH-OPS-07-20` gate now sitting behind `06-PROFILE-4.md`, and the explicit statement that `06-27` stays blocked because `06-PROFILE-4.md`'s verdict is FAIL-BUT-IMPROVED, not PASS) and two for `06-28` (a fourth threat — the reshape's data-dependent intermediate row count, with its bound `segments + len(ports) * (UPTIME_BUCKETS - 1)` and `06-29`'s measured 22,247-against-23,583 figure — and `PROH-OPS-07-21`'s extension to any stale `06-SECURITY.md` citation of the previous query shape).
- **The operator's Task 2 checkpoint decision is recorded verbatim.** Given `06-PROFILE-4.md`'s FAIL-BUT-IMPROVED verdict (69.191ms mean against the 56.820ms pass bar), the operator selected `revert-route-wiring`: `/api/services` reverts to the Python sweep, restoring the 56.820ms baseline immediately, while `read_uptime_strips_by_port` and its full 1,824-case differential, three golden fixtures, and boundedness suite stay in the tree as a proven-correct implementation for a future round. The reasoning — that the `ordered_points` LEAD window alone costs approximately what the whole Python sweep cost, re-scoping OPS-07's remedy toward a worker-precomputed strip rather than continued per-request optimization — is reproduced in full in `06-GUARD-DECISION.md` section 8.
- **`06-DEBT.md` carries the round's technical substance independently of the one-word verdict.** `D-DEBT-06-22` classifies the unimplemented criterion as an execute-to-summary verification-path gap (not a code bug) and poses, without answering, whether the phase wants a mechanical acceptance-criteria checker. `D-DEBT-06-23` records the measured cost-floor components (the reshaped query's 5.4x reduction, the Python sweep's ~23ms cost, the `ordered_points` LEAD window's ~23ms floor, and the reintroduced double-read of `service_checks`) and the held-in-reserve `ordered_points` restructure (~10ms saving, carrying `PROH-OPS-07-22`'s correctness obligation if taken). `D-DEBT-06-21` is appended (not rewritten — confirmed zero deletions in the diff) with a dated subsection recording option C's measured outcome and the operator's decision.

## Task Commits

1. **Task 1: Write the record — the unmet criterion, the narrowing, and what 06-27 and 06-28 now need** - `30e75aa` (docs)
2. **Task 2: The operator decides — keep the reshape, or revert the route wiring** - pre-resolved by the operator per this plan's spawn instructions (`revert-route-wiring`); no separate commit — recorded in Task 1's `06-GUARD-DECISION.md` section 8 and finalized alongside Task 3
3. **Task 3: Record the debt — the verification gap, the SQL cost floor, and option C's measured outcome** - `9bb17a5` (docs)

## Files Created/Modified

- `.planning/phases/06-workload-resilience-pi-acceptance/06-GUARD-DECISION.md` - created: eight sections covering the unmet criterion, the hazard demonstration, the criterion-forbids-the-fix statement, the narrowing's legitimacy distinction, the mutation re-proof, the rejected alternatives, the `06-27`/`06-28` amendments, and the checkpoint outcome
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` - `D-DEBT-06-22` and `D-DEBT-06-23` appended; `D-DEBT-06-21` appended with a dated subsection (no existing line deleted)

## Decisions Made

- **The operator selected `revert-route-wiring`** at Task 2's blocking checkpoint, over `keep-reshape`, `keep-and-extend`, and `unblock-27` (the last not selectable on a non-PASS verdict). Full reasoning reproduced verbatim in `06-GUARD-DECISION.md` section 8.
- **Task 2's checkpoint was recorded as pre-resolved, not re-prompted**, per this plan's explicit spawn instructions stating the operator had already been shown the numbers and decided. Section 8's content was written in full as part of Task 1's commit rather than left as a placeholder until after a separate Task 2 commit — a sequencing deviation from the plan's literal "left as a placeholder heading in this task and completed after Task 2" instruction, with no content difference, documented below.
- **The unmet criterion is recorded against `06-25`, never absorbed into this round or `06-29`'s**, per `PROH-OPS-07-27` — both `06-25` artifacts are confirmed unedited.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - process sequencing, no content impact] Section 8 was written in full during Task 1's commit rather than left as a placeholder until after Task 2**

- **Found during:** Task 1, drafting `06-GUARD-DECISION.md`
- **Issue:** The plan's Task 1 action instructs leaving Section 8 "as a placeholder heading in this task and completed after Task 2." Because this plan's spawn instructions supplied the operator's already-made decision and its full verbatim reasoning up front (the checkpoint's numbers had already been shown to the operator outside this execution), there was no separate interactive step to defer the content to — writing a placeholder and then editing it in a near-simultaneous second pass would have added a no-op intermediate commit without changing what either commit ultimately contains.
- **Fix:** Section 8 was written in full within Task 1's commit, using the operator's verbatim reasoning as supplied. Task 3 still independently records the outcome in `D-DEBT-06-21`'s dated subsection, satisfying the plan's cross-artifact consistency requirement (the outcome appears in both `06-GUARD-DECISION.md` section 8 and `D-DEBT-06-21`'s update, per the plan's own verification checklist) without a placeholder-then-fill intermediate state.
- **Files modified:** `.planning/phases/06-workload-resilience-pi-acceptance/06-GUARD-DECISION.md`
- **Verification:** `grep -n "revert-route-wiring"` matches in both `06-GUARD-DECISION.md` and `06-DEBT.md`; Section 8 is fully populated in the committed file, not a placeholder.
- **Committed in:** `30e75aa` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 process-sequencing deviation, no content or acceptance-criteria impact)
**Impact on plan:** None on substance — every acceptance criterion this plan states for Section 8 (named option, reproduced reasoning, presence in both `06-GUARD-DECISION.md` and `D-DEBT-06-21`) is met. Only the internal task-to-task sequencing implied by "placeholder, then filled" differs from what was executed.

## Issues Encountered

None beyond the sequencing note above.

## User Setup Required

None — no external service configuration required. Task 2's checkpoint was a `checkpoint:decision`, not a `checkpoint:human-action`; it was resolved per the operator's pre-supplied decision, not re-prompted during this execution.

## Self-Audit Against This Plan's Own Acceptance Criteria

Walked individually, per this plan's `self_audit_before_summary` instruction:

- Task 1's acceptance criteria (existence, frontmatter, quoted criterion, grep+diff checks, Section 4's standalone distinction sentence with all three prohibition IDs, Section 5's three reproduced mutation messages, Section 6's three named alternatives, Section 7's amendment counts and PASS/FAIL statement, no OPS-07-passes claim, no prohibition re-minted with new text): **all confirmed present in the committed file**, checked directly against the file content and `git diff` output, not from memory.
- Task 3's acceptance criteria (`D-DEBT-06-22`/`-23` existence and format, `D-DEBT-06-22`'s classification and unanswered-question framing, `D-DEBT-06-23`'s four measured components and held-in-reserve figures, `D-DEBT-06-21`'s append-not-rewrite, `06-GUARD-DECISION.md` section 8's completeness, `.planning/REQUIREMENTS.md`'s empty diff, no `.py` file in the diff, no PLAN.md modified): **all confirmed** via `grep -c`, `git diff --stat`, and `git diff | grep -c '^-[^-]'` (0 deletions) run directly, not asserted.
- No criterion from either task is reported here as unmet. The one process deviation (Section 8 written during Task 1 rather than after a separate Task 2 step) does not correspond to any stated acceptance criterion in the plan text — the plan's actual checks are about content presence and correctness, both satisfied.

## Next Phase Readiness

- **`06-27` stays blocked.** `06-PROFILE-4.md`'s verdict is FAIL-BUT-IMPROVED; `PROH-OPS-07-20` forbids spending Pi time on a build whose own local predictor measured worse than the bar. This is unaffected by the operator's `revert-route-wiring` choice, since a revert plan has not yet been executed.
- **What the next round inherits:** a scoped-out remedy direction (move the 168-bucket strip off the request path, precomputed by the worker) per the operator's Section 8 reasoning; a separate revert plan not yet written (restore `_uptime_summary`/`checks_by_port` in `api_services`, rewrite `LockScopePreservationTests`' scope pin a second time, realign `06-LOCK-AUDIT.md` a fourth time); and `06-27`/`06-28`'s enumerated amendments (this plan's `06-GUARD-DECISION.md` section 7) for whichever round next touches those PLANs.
- `.planning/REQUIREMENTS.md` is unedited by this plan: `OPS-07` stays Pending in both halves (`PROH-OPS-07-08`) — confirmed via `git diff --stat -- .planning/REQUIREMENTS.md` producing no output.
- No `.py` file appears in this plan's diff; no existing PLAN.md is modified — both confirmed via `git diff --stat`.

## Self-Check: PASSED

All modified/created files confirmed present on disk:
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-GUARD-DECISION.md`
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` (diff confirmed: `D-DEBT-06-22`, `D-DEBT-06-23` added; `D-DEBT-06-21` appended, zero deletions)

Both commit hashes confirmed in `git log`:
- FOUND: `30e75aa`
- FOUND: `9bb17a5`

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-06*
