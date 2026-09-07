---
phase: 03-advanced-current-diagnosis
plan: 14
subsystem: planning
tags: [traceability, requirements-record, verification-evidence, gap-closure, prohibition-compliance]
status: complete

requires:
  - ".planning/phases/03-advanced-current-diagnosis/03-VERIFICATION.md (the `gaps:` frontmatter Gap C `missing` list — the authoritative statement of the required end state)"
  - ".planning/REQUIREMENTS.md (both halves: the `## v1 Requirements` body checklist and the `## Traceability` table)"
  - "commit eed5ccb (the precedent revert of a premature promotion, and the reason this plan must not recreate it)"
  - "03-11 / 03-12 / 03-13 executed and committed — the precondition this record describes, though their completion changes none of the six statuses"
provides:
  - ".planning/REQUIREMENTS.md — DIA-01, DIA-02 and UX-02 recorded Complete in the traceability table and checked in the body checklist"
  - ".planning/REQUIREMENTS.md — TEL-06, DIA-03 and DIA-08 confirmed at Gaps Found and unchecked, pending independent re-verification"
  - "Both halves of the file now report the same status for all six Phase 3 identifiers — the self-contradiction reported as Gap C is closed"
  - "A record a re-verification pass can promote from, rather than one it has to revert again"
affects:
  - "Phase 03 re-verification (the record it will read, and the three requirements it alone may promote)"
  - "Phase 4 planning (DIA-08's range clause remains open and Phase 4 owns it)"
  - "Any later phase that reads the traceability table as established fact"

actuals:
  tokens: 114
  tasks: 1
  commits: 2

tech-stack:
  added: []
  patterns:
    - "A recorded status is derivable from the verification that established it, never from a neighbouring requirement's result or from a plan summary"
    - "A record correction edits both halves of a two-surface file in one task, so no committed state exists in which the halves disagree"
    - "Scoped in-place replacements anchored to full-line patterns, never a whole-file rewrite, when correcting a record that carries rows outside the edit window"
    - "A contradiction inside an authority document is adjudicated in writing with its reasons, not silently resolved by picking one side"

key-files:
  created:
    - .planning/phases/03-advanced-current-diagnosis/03-14-SUMMARY.md
  modified:
    - .planning/REQUIREMENTS.md

key-decisions:
  - "DIA-01, DIA-02 and UX-02 promoted to Complete on both surfaces: 03-VERIFICATION.md establishes each through executed behavioural evidence (production asset routes plus theme continuity; the full host projection plus its own host_freshness exception; the persisted beacon-theme with a scroll offset consumed exactly once) and names none of them in any entry of the gaps list"
  - "TEL-06 and DIA-03 deliberately NOT promoted despite 03-11..03-13 closing Gaps A and B this very round — a plan closing its own gap is an implementation claim, and only independent re-verification may convert that into a recorded completion; promoting them would repeat the 03-10 prohibition currently judged violated and recreate the exact condition commit eed5ccb had to revert"
  - "DIA-08 deliberately NOT promoted: the `range` clause of its own requirement text ('presentation, refresh, range, and filtering preferences') is deferred to Phase 4 and no range control exists in the workspace, so a clause of the requirement is undelivered by this phase"
  - "The contradiction inside 03-VERIFICATION.md was resolved in favour of the gap frontmatter's `missing` end state over the closing narrative — verified against the files rather than taken from the plan: the Gap C `missing` bullet says verbatim 'DIA-01, DIA-02, UX-02 checked; TEL-06, DIA-03, DIA-08 unchecked', while the narrative at line 286 says 'TEL-06 / DIA-01 / DIA-02 / DIA-08 / UX-02 satisfied'. TEL-06's requirement text does enumerate background-job health (against which Gap B, status partial, is filed) and DIA-08's does contain the range clause, so the frontmatter is corroborated by the requirements' own wording"
  - "`requirements mark-complete` was invoked with only DIA-01, DIA-02 and UX-02 — never the plan's full six-ID `requirements` frontmatter list, which the executor workflow's default would have passed wholesale and which would have re-promoted the three requirements this plan exists to keep open"
  - "The status vocabulary was not extended: Complete and Gaps Found were both already in use in the table, and no identifier, phase mapping, coverage count or requirement wording was touched"

patterns-established:
  - "Requirement promotion is gated on the verifier's per-requirement result AND absence from every open gap AND delivery of every clause of the requirement's own text — all three, not any one"
  - "When a plan's `requirements` frontmatter is a superset of what it may promote, the promotion call is narrowed by hand and the narrowing is recorded as a decision"
  - "A traceability edit is proved by a numstat bound (exactly six lines moved in exactly one file), so 'nothing else moved' is asserted rather than assumed"

requirements-completed: [DIA-01, DIA-02, UX-02]

coverage:
  - id: D1
    description: "The traceability table records DIA-01, DIA-02 and UX-02 as Complete and TEL-06, DIA-03 and DIA-08 as Gaps Found, and the body checklist agrees with it for all six"
    requirement: "DIA-01"
    verification:
      - kind: other
        ref: "REQUIREMENTS_RECONCILED gate — five grep counts (3/3/3/3/6) over .planning/REQUIREMENTS.md"
        status: pass
      - kind: other
        ref: "gsd-tools query requirements.mark-complete DIA-01 DIA-02 UX-02 → already_complete on both the checkbox and traceability surfaces, updated:false"
        status: pass
    human_judgment: false
  - id: D2
    description: "Exactly six requirements map to Phase 3 and the edit moved exactly six lines in exactly one file — no row added, removed, re-mapped, or reworded"
    verification:
      - kind: other
        ref: "git diff --numstat -- .planning/REQUIREMENTS.md → 6 6; git diff --name-only → .planning/REQUIREMENTS.md alone"
        status: pass
    human_judgment: false
  - id: D3
    description: "Carried forward, NOT delivered by this plan: on the target Pi, open /advanced while a real collection gap is active and while host evidence is stale; the workspace shows the open gap and the stale host as real, correctly labelled exceptions and shows no resolved or retention-expired interval as an open actionable gap"
    requirement: "TEL-06"
    verification: []
    human_judgment: true
    rationale: "Operator trust in the rendered snapshot on real hardware cannot be asserted programmatically. The synthetic reproductions in 03-VERIFICATION.md establish the server contract; this establishes that it reads correctly to the person using it. Carried from the verification report's human_verification item 1, re-declared in 03-08-SUMMARY.md, and collected at the end-of-phase human checkpoint per workflow.human_verify_mode: end-of-phase. Preserved verbatim, not automated away."

duration: 8min
completed: 2026-08-19
---

# Phase 03 Plan 14: Requirements Record Reconciliation Summary

**Both halves of REQUIREMENTS.md now tell the same story for all six Phase 3 identifiers — DIA-01, DIA-02 and UX-02 promoted on independent verification, TEL-06, DIA-03 and DIA-08 held open despite this round having just closed their gaps.**

## Performance

- **Duration:** 8 min
- **Tasks:** 1
- **Files modified:** 1 (`.planning/REQUIREMENTS.md`)
- **Lines moved:** 6 added, 6 removed

## Accomplishments

- **Closed Gap C.** The traceability table and the body checklist now agree for every Phase 3 requirement. Before this plan the table read `Gaps Found` for all six while the checklist read `[ ]` for all six — internally consistent, but under-crediting three requirements that verification did establish.
- **Promoted exactly the three the evidence supports.** DIA-01, DIA-02 and UX-02 moved to `Complete` in the table and `[x]` in the checklist. Each is recorded satisfied in 03-VERIFICATION.md's Requirements Coverage table on executed behavioural evidence, and each is named in no entry of the report's `gaps:` list.
- **Refused the three it does not.** TEL-06, DIA-03 and DIA-08 stay at `Gaps Found` and `[ ]`. This is the substantive output of the plan, not an omission from it.
- **Adjudicated a contradiction inside the authority document, and checked the adjudication against the files.** 03-VERIFICATION.md's Gap C frontmatter and its closing narrative disagree about TEL-06 and DIA-08. The frontmatter was chosen, and the choice was corroborated independently from the requirements' own text rather than accepted from the plan.

## Task Commits

1. **Task 1: Reconcile both halves of REQUIREMENTS.md to the verification-established statuses in one pass** — `b654b14` (docs)

**Plan metadata:** see the final commit of this plan.

## Files Created/Modified

- `.planning/REQUIREMENTS.md` — three traceability rows promoted to `Complete`, three body checkboxes checked. Six lines total. No other row, checkbox, phase mapping, identifier, status value, coverage count or requirement wording touched.

## Decisions Made

### Why DIA-01, DIA-02 and UX-02 were promoted

| ID | Evidence in 03-VERIFICATION.md | Named in a gap? |
| --- | --- | --- |
| DIA-01 | Requirements Coverage: SATISFIED — "Production asset routes plus theme continuity, behaviorally tested." | No |
| DIA-02 | Requirements Coverage: SATISFIED — "Full projection plus the `host_freshness` exception with real operator copy." | No |
| UX-02 | Requirements Coverage: SATISFIED — "`beacon-theme` persisted; scroll restored exactly once; behaviorally tested." | No |

Commit `eed5ccb` reverted these three (plus DIA-03) from `Complete` in one blanket sweep after gaps were found. That revert was right about DIA-03 and over-broad about the other three. This plan corrects it from the other side.

### Why TEL-06, DIA-03 and DIA-08 were not

This is the load-bearing refusal.

- **DIA-03** — Observable Truth 3 is `failed` in the report; Gap A is filed at status `failed`; Requirements Coverage records it BLOCKED. Plan 03-11 closed the absent-vs-zero fabrication and 03-13 closed the `collection_gaps` hollow property, so the gap is *believed* closed. Belief by the round that did the work is an implementation claim. Only independent re-verification may convert it.
- **TEL-06** — Gap B (status `partial`) is filed against "background-job health reported to the operator reflects what the job actually did", and TEL-06's own requirement text enumerates "background-job health" as one of its six clauses. Plan 03-12 restructured `dispatch_callback` and added `JobHealthBookkeepingError`. Same reasoning: the round cannot promote itself.
- **DIA-08** — Not a gap-closure case at all. Its requirement text reads "presentation, refresh, **range**, and filtering preferences"; the report's `deferred` block confirms no range control exists in the workspace and assigns the clause to Phase 4. A requirement with an undelivered clause of its own text is not complete in this phase.

The 03-10 prohibition — *"MUST NOT record a requirement, plan, or phase as complete on the strength of an implementation claim rather than independent verification"* — is currently judged **violated** in 03-VERIFICATION.md. This plan is its correction. Promoting the requirements this very round implemented would have been that same prohibition violated a second time, in the act of correcting it.

### The contradiction inside 03-VERIFICATION.md

| Source | Says |
| --- | --- |
| `gaps:` frontmatter, Gap C `missing` bullet 2 | "DIA-01, DIA-02, UX-02 checked; TEL-06, DIA-03, DIA-08 unchecked" |
| Closing narrative (line 286) | "The verified end state is TEL-06 / DIA-01 / DIA-02 / DIA-08 / UX-02 satisfied, DIA-03 blocked" |

Resolved in favour of the frontmatter. The plan's `<attribution_audit>` gave three reasons; two were re-checked against the files rather than accepted:

- TEL-06's requirement text at `.planning/REQUIREMENTS.md:25` does enumerate "background-job health", and the report's Gap B is filed against exactly that clause at status `partial`. **Confirmed.**
- DIA-08's requirement text at `.planning/REQUIREMENTS.md:43` does contain the `range` clause, and the report's `deferred` block assigns it to Phase 4 on the evidence that no range control exists in `advanced.html`. **Confirmed.**

The narrative is a summary of *capability satisfaction*; the frontmatter `missing` list is the report's statement of *required record state*. Those are different axes, which is how the report came to say both things without either being a typo. Nothing here re-opens the adjudication; it records that the adjudication survives contact with the files.

## Deviations from Plan

The plan's single task executed exactly as written. Two workflow-level adjustments were required and are recorded rather than absorbed:

**1. [Rule 2 — Missing Critical] The `requirements mark-complete` call was narrowed from six IDs to three**

- **Found during:** Task 1 state updates
- **Issue:** The executor workflow instructs "Extract the `requirements` array from the plan's frontmatter, then mark each complete" and "Pass all IDs". This plan's frontmatter carries all six Phase 3 IDs, because the plan is *about* all six. Following the instruction literally would have marked TEL-06, DIA-03 and DIA-08 complete — writing the exact falsehood the plan exists to prevent, one command after the task that prevented it.
- **Fix:** Invoked `gsd-tools query requirements.mark-complete DIA-01 DIA-02 UX-02` only. It returned `updated: false` with all three `already_complete` on both the checkbox and traceability surfaces, which doubles as an independent cross-check that the two halves of the file agree.
- **Files modified:** none (the tool made no write)
- **Verification:** `git diff` on `.planning/REQUIREMENTS.md` was empty after the call.

**2. [Rule 3 — Blocking] `state.advance-plan` could not advance and left the position prose stale**

- **Found during:** state updates
- **Issue:** The tool returned `advanced: false, reason: last_plan` (plan 14 of 14) and reported `status: ready_for_verification`, but did not rewrite the `## Current Position` prose or `last_activity_desc`, which still described 03-13.
- **Fix:** Updated the frontmatter `status` to `ready_for_verification` and the three position lines by scoped in-place replacement.
- **Files modified:** `.planning/STATE.md`

---

**Total deviations:** 2 (1 prohibition-compliance narrowing, 1 tool edge case)
**Impact on plan:** None on scope. Deviation 1 is the difference between this plan working and this plan silently undoing itself.

## Issues Encountered

None. The precondition was confirmed before the edit: `uv run --project dashboard python -m pytest -q` → **288 passed, 395 subtests passed in 84s**, matching the wave 1–2 reported state.

No acceptance criterion proved unsatisfiable — all seven passed on the first run, including the `6 6` numstat bound.

## Known Stubs

None. This plan touches no source file.

## Outstanding Human Verification (carried, not closed)

**Real-hardware collection-health trust.** On the target Pi, open `/advanced` while a real collection gap is active and while host evidence is stale. Expected: the workspace shows the open gap and the stale host as real, correctly labelled exceptions, and shows no resolved or retention-expired interval as an open actionable gap.

Preserved verbatim from the plan's `<human-check>` and the verification report's `human_verification` item 1. Collected at the end-of-phase human checkpoint per `workflow.human_verify_mode: end-of-phase`. This plan does not close it and does not automate it away.

## Next Phase Readiness

- **Phase 3 is ready for independent re-verification, not for completion.** All fourteen plans are executed. Gaps A and B are believed closed by 03-11/03-12/03-13; Gap C is closed by this plan.
- **What re-verification must decide:** whether the Services surface now reports failure classes rather than fabricated `0 ms` (DIA-03), and whether a succeeded callback can still be durably recorded as failed (TEL-06). Both are held at `Gaps Found` waiting for exactly that answer.
- **DIA-08 will not be promotable in Phase 3 at all.** Its `range` clause belongs to Phase 4; a re-verifier should expect it to stay open and should not read that as a gap-closure failure.
- **No blockers.** No source file, schema, dependency or runtime behaviour was touched by this plan.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-19*

## Self-Check: PASSED

- `.planning/phases/03-advanced-current-diagnosis/03-14-SUMMARY.md` exists
- `.planning/REQUIREMENTS.md` exists and passes the REQUIREMENTS_RECONCILED gate
- Task 1 commit `b654b14` exists in git history
