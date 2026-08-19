---
phase: 03-advanced-current-diagnosis
plan: 13
subsystem: api
tags: [advanced-workspace, collection-gaps, read-model, completeness-disclosure, playwright, gap-closure]
status: complete

requires:
  - "dashboard/beacon/diagnosis.py::compose_pipeline_diagnosis (03-08, the truthful per-stream gap composition this join reads)"
  - "dashboard/beacon/diagnosis.py::compose_service_diagnosis (03-02, the service read model that carried the hollow field)"
  - "dashboard/beacon/repositories.py::read_pipeline_evidence (bounded stream and coverage reads plus their own truncation flags)"
  - "dashboard/advanced.js::countLabel (03-04, the singular/plural rule already contracted for Pipeline counts)"
  - "dashboard/advanced.js::finiteMeasurement (03-11, reject absent before coercing)"
  - ".planning/phases/03-advanced-current-diagnosis/03-VERIFICATION.md (Gap A, missing bullet 2)"
provides:
  - "dashboard/beacon/diagnosis.py::attach_service_collection_gaps — a per-service join over the composed per-stream gap list"
  - "A four-state completeness disclosure (complete / possibly_incomplete / absent / not_established), each derived from a durable read's own truncation flag"
  - "pipeline.streams.gap_evidence_truncated — the gap read's own bound, kept distinct from the stream read's bound"
  - "dashboard/advanced.js::formatServiceGapEvidence — operator copy replacing the serialized container at the detail row"
  - "SCHEMA_VERSION 3, so a stale consumer cannot misread the new block as the old list"
  - "tests/test_advanced_diagnosis_api.py::test_service_collection_gap_evidence_is_joined_and_discloses_its_completeness"
  - "tests/test_advanced_diagnosis_api.py::test_service_gap_completeness_never_defaults_to_an_unestablished_absence"
  - "tests/test_advanced_ui.py::test_service_detail_gap_evidence_reads_as_operator_copy"
  - "tests/test_advanced_ui.py::gap_block / gap_item — the shared fixture builders every gap fixture now uses"
affects:
  - "03-14 (DIA-03 and TEL-06 traceability reconciliation)"
  - "Phase 03 re-verification (Gap A closure evidence)"
  - "Any later plan touching the services read model, the services renderer, or the pipeline streams block"

actuals:
  tokens: 7998
  tasks: 2
  commits: 4

tech-stack:
  added: []
  patterns:
    - "A read-model field is owned by exactly one writer; a composer never emits a default the join will overwrite"
    - "A completeness claim is derived from the durable read's own truncation flag, never defaulted or inferred"
    - "An unavailable or non-boolean truncation flag resolves to not-established, never to a derived absence"
    - "Two bounds over two populations stay two named fields (gap_evidence_truncated vs truncated)"
    - "One copy rule (countLabel) owns singular/plural wording across every surface that counts the same noun"

key-files:
  created: []
  modified:
    - dashboard/beacon/diagnosis.py
    - dashboard/advanced.js
    - tests/test_advanced_diagnosis_api.py
    - tests/test_advanced_ui.py

key-decisions:
  - "Populate rather than drop collection_gaps: dropping it and rendering a fixed no-evidence string would replace a hollow property with a false one, asserting an absence the code never established"
  - "The four states are literals on the server (complete / possibly_incomplete / absent / not_established); the browser recognises exactly those four and treats every other value as unavailable"
  - "gap_evidence_truncated lives in the streams block beside truncated but is projected from evidence['gaps_truncated'] — the gap read's bound, not the stream read's; conflating them is how prior Gap 3 came to describe two populations with one flag"
  - "A matched stream whose gap_evidence_truncated is missing or non-boolean resolves to not_established, not complete — a completeness claim is a claim, and an unavailable flag establishes nothing"
  - "The join copies the composed per-stream list verbatim: no sort, filter, dedupe or bound, so the deterministic composition order and the 03-08 per-row `open` derivation both survive"
  - "open_count sums each item's own `open` key with an identity check (`is True`), never a stream-level fact"
  - "formatServiceGapEvidence resolves count and open_count to finite numbers through finiteMeasurement BEFORE calling countLabel, so countLabel's own non-finite fallback is never what decides the operator's number"
  - "The legacy singular service.collection_gap fallback was removed as dead rather than kept as a compatibility branch — the field never existed on any server payload"
  - "Fixture migration used shared module-level gap_block/gap_item builders that derive count and open_count from the item list, so no fixture can describe a population it does not carry"

patterns-established:
  - "gap_block(evidence, items) is the canonical per-service gap fixture builder in tests/test_advanced_ui.py"
  - "A per-surface view of a shared population carries its own count and its own completeness rather than borrowing another view's flag"
  - "Server state literals are mirrored as an explicit allow-list in the renderer; an unrecognised literal degrades to the workspace's unavailable copy"

requirements-completed: []

coverage:
  - id: D1
    description: "A service's collection-gap evidence is joined from the composed pipeline gap items for its own stream, replacing the hardcoded empty list nothing populated"
    requirement: "DIA-03"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_service_collection_gap_evidence_is_joined_and_discloses_its_completeness"
        status: pass
    human_judgment: false
  - id: D2
    description: "The per-service gap block discloses its own completeness in four states, each derived from a durable read's own truncation flag, with an unavailable or non-boolean flag resolving to not-established"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_service_gap_completeness_never_defaults_to_an_unestablished_absence"
        status: pass
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_service_collection_gap_evidence_is_joined_and_discloses_its_completeness"
        status: pass
    human_judgment: false
  - id: D3
    description: "The expanded service detail row renders operator copy in every completeness state, including an absent or malformed block, and never a serialized container"
    requirement: "TEL-06"
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_service_detail_gap_evidence_reads_as_operator_copy"
        status: pass
    human_judgment: false
  - id: D4
    description: "Gap counts in the service detail row use singular copy for exactly one gap and plural copy for zero or many, matching the Pipeline copy rule"
    requirement: "TEL-06"
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_service_detail_gap_evidence_reads_as_operator_copy"
        status: pass
    human_judgment: false
  - id: D5
    description: "The truthful gap projection closed by 03-08 is provably unchanged by the join: per-row open, reason-to-kind mapping, and one bounded population for the top-level count and truncation flag"
    requirement: "DIA-03"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py -q (34 passed, 78 subtests)"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py -k 'open_stream_gap_renders or resolved_history_never or every_emitted_exception_kind or unmeasured'"
        status: pass
    human_judgment: false
  - id: D6
    description: "The read model's version identifier changed with its shape (SCHEMA_VERSION 2 -> 3), with both pinning fixtures updated and the unrelated migration version line untouched"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_host_tracer_returns_one_current_snapshot_with_server_freshness"
        status: pass
    human_judgment: false

duration: 21min
completed: 2026-08-19
---

# Phase 03 Plan 13: Per-Service Collection-Gap Evidence Summary

**A service's collection-gap evidence is now joined from the same durable composition the Pipeline section uses, states which of four completeness levels it actually established, and reads as a sentence instead of the literal string `[]`.**

## Performance

- **Duration:** 21 min
- **Started:** 2026-08-19T09:00:00Z
- **Completed:** 2026-08-19T09:21:00Z
- **Tasks:** 2 of 2
- **Files modified:** 4

## Accomplishments

- **The hollow property is gone.** `compose_service_diagnosis` no longer emits `'collection_gaps': []`; the field is owned solely by `attach_service_collection_gaps`, so there is no window in which a hardcoded default exists to be mistaken for evidence.
- **The join is real and keyed on the durable vocabulary.** Each service looks up `('service', str(port))` among the composed pipeline stream items and takes that stream's already-composed gap list verbatim — no sort, no filter, no dedupe, no second bound. `count` is the length of that list and `open_count` sums each item's own `open` key, so a count and the items beside it always describe one population.
- **Completeness is disclosed, not assumed.** The block carries one of `complete`, `possibly_incomplete`, `absent`, `not_established`. A matched stream reads the gap read's own bound (`streams.gap_evidence_truncated`); an unmatched one reads the stream read's own bound (`streams.truncated`). A complete stream list that omits a service is itself evidence of absence; a truncated one establishes nothing, and says so.
- **A missing flag never becomes a claim.** `_service_gap_evidence_state` accepts only a literal `False`/`True`; `None`, a string, or an absent key resolves to `not_established`. This is the specific guard against recreating prior Gap 3, where a flag from one population described another.
- **The operator reads English.** `formatServiceGapEvidence` replaced `JSON.stringify(...)` at the detail row. `1 gap (1 open)`, `3 gaps (2 open)`, `2 gaps (1 open); more gap evidence may exist`, `No gap evidence`, `Gap evidence unavailable`. The singular/plural wording derives through the existing `countLabel` helper — the same one the Pipeline collection-gaps region uses — so the two surfaces cannot drift.
- **The empty case is reachable again.** The old fallback was unreachable because `[]` is truthy; the formatter now branches on the block's own declared state rather than its truthiness.
- **The read model versioned its shape change.** `SCHEMA_VERSION` 2 → 3, with both pinning fixtures updated. `migrations.py` and `support_floor.json` were left untouched — their `minimum_schema_version` is a database-migration version line, not this one.

## Task Commits

1. **Task 1 (tracer, TDD): Join each service to its own stream's gap evidence** — `5bdd1cf` (test, RED) → `4a96f95` (feat, GREEN)
2. **Task 2 (TDD): Render that evidence as operator copy** — `cd3a934` (test, RED) → `35d5af7` (feat, GREEN)

No REFACTOR commit was needed on either task.

## Files Created/Modified

- `dashboard/beacon/diagnosis.py` — `SCHEMA_VERSION` 3; the hollow `collection_gaps` default removed from `compose_service_diagnosis`; `gap_evidence_truncated` added to the `streams` block; new `SERVICE_GAP_EVIDENCE_*` state literals, `_service_gap_evidence_state`, and `attach_service_collection_gaps`; the join called once from `get_current_diagnosis` after both compositions.
- `dashboard/advanced.js` — new `SERVICE_GAP_EVIDENCE_STATES` allow-list and `formatServiceGapEvidence` beside `formatFreshnessEvidence`; the `Collection-gap evidence` detail line now passes `service.collection_gaps` through it; `JSON.stringify` and the legacy singular `service.collection_gap` fallback removed.
- `tests/test_advanced_diagnosis_api.py` — `_seed_service` / `_reset_service_evidence` helpers; the four-state endpoint regression; the flag-degradation unit regression; the schema pin raised to 3.
- `tests/test_advanced_ui.py` — module-level `gap_item` / `gap_block` fixture builders; **all nine** gap fixtures migrated to the block shape (2 legacy singular + 7 empty lists, including the four `UNMEASURED_SERVICES` entries plan 03-11 added); the eight-branch browser regression; the `_snapshot` schema pin raised to 3.

## Decisions Made

Recorded in `key-decisions` above. The load-bearing ones:

- **Populate over drop** (the plan's `<decision_record>`, rated `costly`). Dropping the field and rendering a fixed `No gap evidence` string would have replaced a hollow property with a *false* one — asserting an absence without ever having looked, which is the same prohibition class this phase already failed for.
- **Two bounds stay two fields.** `gap_evidence_truncated` (the coverage read's bound, decides complete vs. possibly-incomplete for a *matched* stream) is deliberately separate from `truncated` (the stream read's bound, decides absent vs. not-established for an *unmatched* one). Collapsing them into one flag is precisely the defect 03-08 closed.
- **`is True` for the open count.** `sum(1 for item in items if item.get('open') is True)` rather than a truthiness test, so a truthy non-boolean can never inflate an operator-facing open count.

## Deviations from Plan

### 1. [Rule 3 — Unsatisfiable acceptance gate] `gap_evidence_truncated` occurrence count

- **Found during:** Task 1
- **Issue:** The plan's acceptance criteria state `grep -c 'gap_evidence_truncated' dashboard/beacon/diagnosis.py` outputs `1`. The plan's own required wiring makes that arithmetically impossible: the field must be **written** once in the `streams` block of `compose_pipeline_diagnosis` and **read** once in the completeness derivation. That is two lines. The count is `2`.
- **Fix:** Left the code correct at 2 occurrences (one producer, one consumer) and did **not** contort it. The only way to reach 1 would be to introduce a `GAP_EVIDENCE_TRUNCATED_KEY` string constant purely so the literal appears once — an indirection with no design justification, added solely to satisfy a grep. That is gaming the gate, not passing it.
- **Impact:** None on behaviour or on the plan's intent, which the criterion was written to protect ("the field exists once in the streams block, projected from the durable flag"). Task 1's `<verify>` block — the authoritative automated gate — does **not** include this grep, and it passed (`SERVICE_GAP_JOIN_WIRED`).
- **Files:** `dashboard/beacon/diagnosis.py`
- **Committed in:** `4a96f95`

### 2. [Rule 2 — Missing critical coverage] Added a second server regression

- **Found during:** Task 1
- **Issue:** The plan's four endpoint fixtures cover the four states when the truncation flags are well-formed booleans. They do **not** cover the plan's explicit rule that *"an unavailable or non-boolean flag resolves to not-established, never to absent"* — the exact rule guarding threat T-03-81. That rule was implemented but unproven.
- **Fix:** Added `test_service_gap_completeness_never_defaults_to_an_unestablished_absence`, driving `attach_service_collection_gaps` directly across `False` / `True` / `None` / `'no'` / key-absent for both flags, and asserting the items are the composed list byte-for-byte.
- **Files:** `tests/test_advanced_diagnosis_api.py`
- **Verification:** Passes; failed before the implementation existed.
- **Committed in:** `5bdd1cf` (RED) / `4a96f95` (GREEN)

### 3. [Rule 2 — Missing critical coverage] Two extra formatter branches in the browser regression

- **Found during:** Task 2
- **Issue:** The plan named six branches for the browser test. Two more branches exist in the formatter's contract and would otherwise be unproven in a real browser: a `complete` block with a **zero count** (must read `No gap evidence`, not `0 gaps (0 open)`), and a **legacy container** value (`[]` — the exact pre-migration shape, which must read `Gap evidence unavailable` rather than being stringified).
- **Fix:** The regression serves eight services rather than six, covering both.
- **Files:** `tests/test_advanced_ui.py`
- **Verification:** Passes; both branches produced serialized containers before the fix.
- **Committed in:** `cd3a934` (RED) / `35d5af7` (GREEN)

---

**Total deviations:** 3 (1 unsatisfiable-gate report, 2 coverage additions under Rule 2).
**Impact on plan:** No scope creep. Both additions prove rules the plan itself mandated but left unasserted. The one criterion not met is reported rather than worked around.

## Issues Encountered

**Fixture inventory had grown since planning.** The plan warned that its `<read_first>` line numbers were stale because 03-11 modelled `UNMEASURED_SERVICES` on `SORTABLE_SERVICES`, which carries the list shape. Confirmed: the shape-based `grep` found **7** empty-list fixtures (plan-time inventory: 3) plus 2 legacy singular ones. All nine were migrated; both zero-count gates now read `0`.

**Both plan-pinned zero-count gates reached 0** — no pattern was loosened:

```
grep -c "'collection_gap':" tests/test_advanced_ui.py        -> 0
grep -cE "'collection_gaps': \[\]" tests/test_advanced_ui.py -> 0
```

**Tracer feedback gate.** Task 1 is `type="tracer"`. Its `<verify>` was re-run end-to-end after the commit and passed (`SERVICE_GAP_JOIN_WIRED`, plus the full suite green) before any expansion work began. No human-verify checkpoint was raised: the plan declares `autonomous: true`, the project config sets `human_verify_mode: end-of-phase`, and the tracer's `<verify>` is purely `<automated>` with no human-observable step.

## Verification Evidence

```
uv run --project dashboard python -m pytest -q
  288 passed, 395 subtests passed          (baseline going in: 285 / 373)

uv run --project dashboard python -m pytest tests/test_advanced_diagnosis_api.py -q
  34 passed, 78 subtests passed
  && grep -c 'attach_service_collection_gaps(' dashboard/beacon/diagnosis.py == 2
  -> SERVICE_GAP_JOIN_WIRED

uv run --project dashboard python -m pytest tests/test_advanced_ui.py -q
  33 passed, 63 subtests passed
  && grep -c 'formatServiceGapEvidence(service.collection_gaps)' == 1
  && both zero-count fixture gates == 0
  -> GAP_EVIDENCE_IS_OPERATOR_COPY

uv run --project dashboard python -m pytest tests/test_advanced_ui.py \
  -k 'open_stream_gap_renders or resolved_history_never or every_emitted_exception_kind or unmeasured' -q
  5 passed, 40 subtests passed             (03-08 gap-copy guards + 03-11 regressions intact)
```

## Known Stubs

None. This plan exists to remove one (`'collection_gaps': []`), and no new hardcoded, placeholder, or unwired value was introduced. The field now has exactly one writer, and every value it can take is asserted in both the API and browser suites.

## Threat Flags

None. No new network endpoint, auth path, file access pattern, or schema change at a trust boundary. The join is a pure in-memory composition adding no query; the endpoint stays GET-only, parameterless and effect-free; all DOM writes remain on `textContent`.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

**Gap A is now fully closed.** 03-11 closed missing-bullets 1 and 3 (absent-vs-zero on the services surface); this plan closes bullet 2 (`collection_gaps`), the anti-patterns at `diagnosis.py:167` and `advanced.js:648`, the `NOT WIRED` key link, and the `HOLLOW_PROP` data-flow row.

**DIA-03 and TEL-06 remain at Gaps Found by design.** Following the phase's own standing rule — only *independently verified* requirements are promoted in REQUIREMENTS.md, never on the strength of a plan summary — this plan marks no requirement complete. 03-14 owns the reconciliation, and it must wait on a re-verification of this gap-closure round.

**One note for the re-verifier:** the `gap_evidence_truncated` acceptance criterion (`grep -c` == 1) is not met and cannot be, for the reason documented under Deviations. The substantive intent behind it — a single field in the streams block projected from the durable gap read's own flag — is satisfied and asserted.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-19*

## Self-Check: PASSED

All four modified files exist on disk; all four task commits (`5bdd1cf`, `4a96f95`, `cd3a934`, `35d5af7`) are present in git history.
