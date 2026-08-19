---
phase: 03-advanced-current-diagnosis
plan: 16
subsystem: frontend
tags: [vanilla-js, playwright, operator-copy, contract-test, python, defensive-normalisation]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: "03-13's four SERVICE_GAP_EVIDENCE_* server constants, _service_gap_evidence_state, attach_service_collection_gaps, and the eight-port browser fixture in tests/test_advanced_ui.py"
  - phase: 03-advanced-current-diagnosis
    provides: "03-09/03-13's finiteMeasurement absent-value helper and the two fabrication regressions that pin an absent latency and duration in both sort directions"
  - phase: 03-advanced-current-diagnosis
    provides: "03-15's job_outcome_unrecorded exception kind, its EXCEPTION_COPY entry, and RUNNING_JOB_STATE — all left intact"
provides:
  - "A service the telemetry pipeline has established no collection stream for reads as exactly that, distinct from a service that was collected and found clean, asserted as two unequal strings in a real browser at the production route"
  - "An absent-value rule decided on type rather than on a list of observed values, so no boolean, array, object or blank string can become the measurement zero on the latency, state-duration or per-service gap-count surfaces"
  - "An element-level isinstance guard on the per-service gap join's open-count derivation, with its own regression, so a malformed gap element cannot raise into a request path that catches only database conditions"
  - "A source-level contract test binding the client's four completeness literals to the server's four constants as sets, so a rename on either side fails a test instead of greying out every service row"
  - ".planning/phases/03-advanced-current-diagnosis/deferred-items.md recording this round's five deliberate round-3 exclusions with reasons, plus one grouped entry for the seventeen round-1 carried-forward findings"
affects: [advanced-diagnosis, operator-copy, services-surface, phase-03-reverification]

actuals:
  tokens: 58297
  tasks: 2
  commits: 7

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Two adjacent states that produce the same empty container are distinguished by copy at the branch that renders them, and the distinction is protected by its own inequality assertion rather than by two independently reworded expectations"
    - "An absent-value rule is a statement about types, not an enumeration of observed values: accept number-when-finite and string-when-non-blank-and-parsing-finite, reject everything else"
    - "A wire vocabulary array is kept complete and commented as complete, with its dead-looking member justified in place and its membership made load-bearing by a source-level contract test"
    - "Two independently declared copies of one vocabulary are bound by comparing sets of literal values read from the shipped artifact, so a rename fails and a reordering does not"
    - "A defensive normalising boundary guards every hop including the last: the element-level guard matches the container-level guards the same function already applies"

key-files:
  created: []
  modified:
    - dashboard/advanced.js
    - dashboard/beacon/diagnosis.py
    - tests/test_advanced_ui.py
    - tests/test_advanced_diagnosis_api.py
    - .planning/phases/03-advanced-current-diagnosis/deferred-items.md

key-decisions:
  - "Return both gap-evidence literals directly at their use sites rather than through named constants, so the shipped operator copy stays greppable where it is decided — which is also what the plan's count gates measure"
  - "Word the absent sentence as a statement of the observed condition (no collection stream established) and not as a diagnosis (not misconfigured, not newly discovered, not unmonitored by choice), because the payload establishes none of those causes — D-11"
  - "Assert the two absences unequal in a statement of its own, read from the live DOM by port, rather than relying on the expectation map alone: a future edit that rewords both map entries together would otherwise re-collapse the distinction and stay green"
  - "Keep 'not_established' in SERVICE_GAP_EVIDENCE_STATES and justify it in a comment rather than dropping it, because the array is the wire vocabulary the contract test binds to the server — dropping the member would make the contract test compare three literals against four"
  - "Compare the two vocabularies as sets of literal values, not by constant name or order, and assert the extracted set has exactly four members so a regex that silently matched nothing cannot pass vacuously"
  - "Generalise the production-route browser fixture into _services_page(services) and have _gap_evidence_page delegate to it, rather than duplicating the route-fulfilment block for the second regression"
  - "Avoid a second occurrence of the 'No gap evidence' literal in the test module: the control service's genuine zero count is asserted by absence of any digit and of the counted phrase's parenthesis, which keeps Task 1's count gate satisfiable and still proves no fabricated '0 gaps (0 open)'"
  - "Add a committed regression for the new element guard (Rule 2 deviation) after finding the plan's intended proof selector unsatisfiable, because a guard whose only evidence is an executor's transient shell run is the exact pattern this phase's process prohibition forbids"

patterns-established:
  - "Adjacency copy gate: where the server derives two states that yield the same empty container, the browser regression asserts the rendered strings unequal by port, so the distinction cannot be re-collapsed by a symmetric edit"
  - "Cross-language vocabulary contract: extract the client's literals from the shipped artifact with a regex over one declaration, assert the extracted cardinality, then compare as a set against the server's constants"
  - "Guard-removal proof: after adding a defensive guard, temporarily remove it and confirm the new regression fails with the exact exception the guard prevents, then restore from git — the guard's test is evidence only once it has been observed to fail without it"

requirements-completed: []

coverage:
  - id: D1
    description: "A service whose server block declares the absent state renders a sentence stating that no collection stream has been established for it, while a service whose block declares complete with a zero count renders the existing no-gap-evidence sentence byte-identical to before; the two strings are asserted unequal, read from the live DOM at the production /advanced route"
    requirement: "TEL-06"
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_service_detail_gap_evidence_reads_as_operator_copy"
        status: pass
      - kind: other
        ref: "grep gates: 'No collection stream established for this service' == 1 and 'No gap evidence' == 1 in dashboard/advanced.js; each == 1 in tests/test_advanced_ui.py"
        status: pass
    human_judgment: false
  - id: D2
    description: "The possibly-incomplete state, the state the server never established, a malformed container block and an omitted block all render exactly the copy they rendered before, and no rendered gap-evidence line contains a bracket, brace or quotation mark"
    requirement: "TEL-06"
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_service_detail_gap_evidence_reads_as_operator_copy (six unchanged port expectations, the serialized-container scan over all eight, and the malformed-block name assertion)"
        status: pass
    human_judgment: false
  - id: D3
    description: "A non-numeric value arriving where the server would normally send a number never becomes the measurement zero: an empty-array latency renders the row's failure class with no digit, a whitespace-string state duration renders the unknown-duration copy with no digit, and a non-numeric gap count beside one real open gap renders one gap with one open rather than an absence — while a genuine numeric zero still renders as a measurement on latency and duration"
    requirement: "TEL-06"
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_non_numeric_server_values_never_become_a_measurement"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_unmeasured_service_shows_its_failure_class_instead_of_a_fabricated_latency (unchanged, still green after the helper rewrite)"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_unmeasured_latency_and_duration_never_rank_or_read_as_zero (unchanged, both sort directions still green)"
        status: pass
      - kind: other
        ref: "grep gate: 'function finiteMeasurement' == 1 in dashboard/advanced.js — rewritten in place, not duplicated"
        status: pass
    human_judgment: false
  - id: D4
    description: "A non-dictionary element inside a per-service gap list is skipped by the open-count derivation instead of raising out of the diagnosis composition, and the real open gap beside it is still counted"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests::test_a_malformed_gap_element_cannot_raise_out_of_the_service_join"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests::test_service_gap_completeness_never_defaults_to_an_unestablished_absence and ::test_service_collection_gap_evidence_is_joined_and_discloses_its_completeness (the existing direct gap-join tests, still green with the guard added)"
        status: pass
      - kind: other
        ref: "guard-removal proof: with the isinstance guard temporarily removed the new regression fails with AttributeError: 'str' object has no attribute 'get' at dashboard/beacon/diagnosis.py:393; guard restored from git and the count gate re-checked"
        status: pass
    human_judgment: false
  - id: D5
    description: "The four completeness literals the client accepts are asserted equal, as a set, to the four the server derives, so a rename on either side fails a test and a reordering does not"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_gap_evidence_vocabulary_matches_the_server"
        status: pass
      - kind: other
        ref: "mutation probe of the extraction and comparison logic: as shipped equal; a client-side rename unequal; a client-side reorder still equal; a server-side rename unequal"
        status: pass
    human_judgment: false
  - id: D6
    description: "Every round-3 review finding this round deliberately did not implement is recorded with its reason, and the seventeen round-1 carried-forward findings are recorded as one grouped entry citing 03-REVIEW.md's own table, with the file stating the scope it actually covers"
    requirement: "TEL-06"
    verification:
      - kind: other
        ref: "grep gates over .planning/phases/03-advanced-current-diagnosis/deferred-items.md: rows for WR-04, IN-02, IN-04, IN-06, IN-08 each with a reason; CF-WR-01, CF-WR-10, CF-IN-01, CF-IN-08 each >= 1; original row 1 intact; scope paragraph states the file does not record every review finding"
        status: pass
    human_judgment: false
  - id: D7
    description: "TEL-06 remains open and the DIA-03 and DIA-08 rows remain exactly as the verifier settled them"
    requirement: "TEL-06"
    verification:
      - kind: other
        ref: "grep gates: '| TEL-06 | Phase 3 | Gaps Found |' == 1, '- [ ] **TEL-06**' == 1, '| DIA-03 | Phase 3 | Complete |' == 1, '| DIA-08 | Phase 3 | Deferred to Phase 4 |' == 1; git diff over this plan's commit range shows zero changes to .planning/REQUIREMENTS.md"
        status: pass
    human_judgment: false
  - id: D8
    description: "On the target Pi, /advanced reads correctly to the operator while a real collection gap is active and while host evidence is stale — the open gap and the stale host appear as real, correctly labelled exceptions, and no resolved or retention-expired interval appears as an open actionable gap"
    verification: []
    human_judgment: true
    rationale: "Carried forward from all three verification reports, from 03-14's and 03-15's human-check blocks, and from this plan's own <human-check>. The synthetic reproductions establish the server contract and the browser regressions establish that the copy renders at the production route; whether the new sentence reads to the operator as an observation about monitoring rather than an alarm about the service is human judgment. Collected at the end-of-phase human checkpoint (config human_verify_mode: end-of-phase), not automated here."

# Metrics
duration: 22min
completed: 2026-08-19
status: complete
---

# Phase 03 Plan 16: Stop an unmonitored service from reading as a clean bill of health Summary

**A service the telemetry pipeline has never established a collection stream for now says so in the operator's own browser, distinct from a service that was watched and found clean — and the absent-value rule that stands between every server value and a fabricated measurement is now a statement about types rather than a list of values someone happened to observe.**

## Performance

- **Duration:** 22 min
- **Started:** 2026-08-19T09:07:00Z
- **Completed:** 2026-08-19T09:29:00Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- **The conflation is gone, and the test now protects the distinction instead of pinning it shut.** 03-13's server work derives four completeness states from durable truncation flags, and the verifier reproduced all four end-to-end — then the client collapsed two of them into one string. `absent` means the stream list was complete and carried no stream for this service, so the pipeline has no record of ever observing it; `complete` with a zero count means it was collected and is clean. They rendered byte-identically as `No gap evidence`, and the browser regression asserted that same literal for both ports, so the test was load-bearing in the wrong direction. The absent state now has its own branch, placed first, returning `No collection stream established for this service`, and the complete-with-zero case keeps its sentence unchanged in wording and in position.
- **The distinction is defended by its own statement.** Splitting the expectation map alone would still permit a future edit that rewords both entries together. `self.assertNotEqual(rendered[9002], rendered[9003])` reads both values from the live DOM by port, so re-collapsing the two states now costs a test failure rather than a code review.
- **The sentence states the condition and stops.** Per D-11 Beacon reports observations and does not assert an inferred cause, so the copy does not say the service is unmonitored by choice, misconfigured, or newly discovered — the payload establishes none of those. It says what `_service_gap_evidence_state` actually derived.
- **The absent-value rule became a rule.** `finiteMeasurement` was `''`-aware but not `'  '`-aware, which is the tell that its emptiness check was written against observed values. Verified against the shipped helper, `' '`, `[]` and `false` all became the measurement `0`, and `[5]` became `5`. It now decides on type: a number is a measurement when finite, a string only when trimming leaves a value that parses finite, and every other type is an absence. The return contract is unchanged, a genuine zero from either accepted type is still a measurement, and none of the three call sites moved.
- **The one path where a fabricated zero would hide a real fault is pinned.** On the gap count a `0` renders a non-empty gap list as `No gap evidence`. The new regression drives a non-numeric count and a non-numeric open count beside one real open gap through the production route and asserts `1 gap (1 open)` — the count derived from the items it is rendered beside. This is the phase's completeness prohibition applied as a guard rather than as a live fix: no current server path emits a non-numeric count, because the server derives count, open count and items from one list.
- **The last unguarded hop in the gap join is guarded, and the guard has been seen to fail without itself.** `attach_service_collection_gaps` applies `isinstance` to `streams_block`, `stream_items`, each `stream` and `items`, then dropped the discipline on the open-count derivation. A non-dictionary element there raises `AttributeError` inside `/api/advanced/current`, whose only handlers are `MaintenanceBusy` and `sqlite3.OperationalError` — so the operator would get an unparseable HTML 500 instead of the workspace's bounded error copy.
- **The two vocabularies are bound.** The server's four `SERVICE_GAP_EVIDENCE_*` constants and the client's four-literal array were declared independently with nothing asserting they agreed; a rename on either side would have degraded every service row to the unavailable copy with a green suite. A source-level test extracts the client's literals from the shipped `advanced.js`, asserts the extracted set has exactly four members, and compares it to the server constants as a set. A probe confirmed it fails on a rename from either side and tolerates a reordering.
- **`not_established` earned its place in the array.** IN-01 flagged its membership as dead, since the next statement rejects it. It stays, with a comment recording that the array is the *wire* vocabulary — the complete set the server can send, which is why it lists a state the workspace cannot render — and that the new contract test binds it to the server. Dropping the member would have made the contract test compare three literals against four.

## Task Commits

Both tasks were TDD; each contributed a `test` (RED) commit followed by a `feat` (GREEN) commit. No refactor pass was needed.

1. **Task 1: Give an absence of collection its own words, and split the test that pins it shut** (tracer)
   - `67cde82` (test) — the split expectation map, the dedicated inequality assertion, the updated docstring; failed with `9002: 'No gap evidence' != 'No collection stream established for this service'`
   - `3094e3a` (feat) — the absent branch and its sentence, the unchanged complete-with-zero branch, the wire-vocabulary comment
2. **Task 2: Make the absent-value rule a rule, guard the last unguarded element, and bind the two vocabularies**
   - `832c445` (test) — `test_non_numeric_server_values_never_become_a_measurement`, `test_gap_evidence_vocabulary_matches_the_server`, and the `_services_page(services)` fixture generalisation; failed with `'0 ms' != 'TlsHandshakeFailed'`
   - `477c1f9` (feat) — the type-based `finiteMeasurement` and the element-level `isinstance` guard
   - `99ad44e` (docs) — the `deferred-items.md` exclusion rows and the grouped carried-forward row
   - `523ef6d` (test) — the element-guard regression added under Rule 2 (see Deviations)

**Plan metadata:** see the trailing `docs(03-16)` commit.

### Tracer feedback gate

Task 1 was `type="tracer"`. Its `<verify>` was re-run end-to-end against the committed slice before any Task 2 work began, and passed (`TWO_ABSENCES_READ_DIFFERENTLY`, 1 passed / 8 subtests). The full browser module was also green at 33 passed / 67 subtests at that point. No expansion work was poured onto an unproven foundation.

## Files Created/Modified

- `dashboard/advanced.js` — `formatServiceGapEvidence`'s single two-state branch split into two: `absent` returns `No collection stream established for this service` at its use site, ahead of `complete`-with-zero returning the unchanged `No gap evidence`, with a comment recording that the sentence states the derived condition and does not diagnose a cause. `SERVICE_GAP_EVIDENCE_STATES` gained a comment recording that it is the wire vocabulary, that it therefore deliberately lists the state the next statement rejects, and that a source-level contract test binds it to the server's constants; no member removed. `finiteMeasurement` rewritten in place to decide on type, with a comment stating why anything it accepts becomes an assertion about the Pi. The three call sites (latency cell, latency sort key, `serviceDuration`) are untouched.
- `dashboard/beacon/diagnosis.py` — `attach_service_collection_gaps`'s `open_count` derivation gained `isinstance(item, dict)`, matching the container-level guards the function already applies, with a comment naming the concrete failure it prevents. Nothing else in the function changed; no payload field, no `SCHEMA_VERSION` bump, and 03-15's `RUNNING_JOB_STATE` and `job_outcome_unrecorded` branch untouched.
- `tests/test_advanced_ui.py` — the gap-evidence expectation map split at ports 9002 and 9003 with a dedicated `assertNotEqual` read from the live DOM and an updated docstring; the six other port expectations, the serialized-container scan and the malformed-block assertion unchanged. Added `_fabrication_services` (empty-array latency with a failure class, whitespace-string duration, non-numeric count and open count beside one real open gap, and a genuine-zero control), `test_non_numeric_server_values_never_become_a_measurement`, and `test_gap_evidence_vocabulary_matches_the_server`. `_gap_evidence_page`'s route-fulfilment body was extracted into `_services_page(services)` and `_gap_evidence_page` now delegates to it with no behaviour change. Added `import re` and `from dashboard.beacon import diagnosis as beacon_diagnosis`.
- `tests/test_advanced_diagnosis_api.py` — added `test_a_malformed_gap_element_cannot_raise_out_of_the_service_join` (four non-dictionary shapes plus one real open gap through the shipped join, asserting no raise, the open gap still counted, and the composed order preserved verbatim). This file is a Rule 2 deviation from the plan's `files` list; see Deviations. 03-15's additions to this module were not modified.
- `.planning/phases/03-advanced-current-diagnosis/deferred-items.md` — a scope paragraph stating what the file records and stating plainly that it does not record every review finding; five rows for the round-3 findings this round deliberately did not implement (WR-04, IN-02, IN-04, IN-06, IN-08), each with its reason; and one grouped row naming all seventeen round-1 carried-forward identifiers, citing `03-REVIEW.md`'s own table, and naming `CF-WR-10` and `CF-IN-07` explicitly as the two sitting in code this round edits. The original row 1 is unchanged and unreworded.

## Decisions Made

Recorded in the `key-decisions` frontmatter. The three that mattered most during execution:

- **Keep `not_established` in the client array.** IN-01 offered two remedies — drop the member, or keep it and comment why. IN-03's contract test forces the choice: dropping it would leave the client declaring three literals against the server's four, so the contract test would fail on a divergence that is not one. Keeping the member and commenting it makes its membership load-bearing rather than dead, which is what the plan's `gap_coverage` row for IN-01 asserts.
- **Do not spell the `No gap evidence` literal a second time in the test module.** Task 1's acceptance gate requires exactly one occurrence in `tests/test_advanced_ui.py`, which is what proves the conflation was removed rather than relocated. The control service's genuine zero count is therefore asserted by the absence of any digit and of the counted phrase's opening parenthesis — which still proves no fabricated `0 gaps (0 open)`, without making a satisfiable gate unsatisfiable. The genuine-zero gap rendering itself remains pinned by port 9003 in the other test.
- **Prove the guard by removing it.** A defensive `isinstance` guard passes its own test whether or not the test is capable of failing. The guard was temporarily removed, the new regression observed to fail with the exact `AttributeError` the guard prevents, and the file restored from git before the commit. Similarly, the vocabulary contract test passes on arrival by construction, so its extraction and comparison logic was probed against a simulated client rename, a client reorder and a server rename to confirm it fails on the first and third and not the second.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing correctness evidence] The new element guard shipped with no committed regression**

- **Found during:** Task 2, running the acceptance criterion `uv run --project dashboard python -m pytest tests/test_advanced_diagnosis_api.py -k attach -q`
- **Issue:** That selector deselects all 37 tests and exits 5 (`NO_TESTS_COLLECTED`), because pytest `-k` filters test ids and no test name in that module contains `attach` — the review's citation `attach(services, {'streams': …})` is a local alias inside a test body, not a test name. The criterion's intended proof of the guard therefore did not exist, and the guard would have shipped with nothing pinning it: a future edit could delete it and the whole suite would stay green. This is the second occurrence in this phase of the same plan-defect class, after 03-13's arithmetically unsatisfiable `grep -c 'gap_evidence_truncated'` gate.
- **Fix:** Ran the two tests that actually exercise the gap join (`test_service_collection_gap_evidence_is_joined_and_discloses_its_completeness`, `test_service_gap_completeness_never_defaults_to_an_unestablished_absence` — both pass, 14 subtests), then added `test_a_malformed_gap_element_cannot_raise_out_of_the_service_join` to the same module. Verified it fails with `AttributeError: 'str' object has no attribute 'get'` when the guard is removed.
- **Files modified:** `tests/test_advanced_diagnosis_api.py` — outside the plan's `files` list for Task 2, which named only `advanced.js`, `diagnosis.py`, `test_advanced_ui.py` and `deferred-items.md`. A server-side unit regression does not belong in the browser module, and the plan's own `<behavior>` block states the guard's behaviour as a deliverable, so the regression was added where its subject lives. 03-15's additions to that module were not touched.
- **Commit:** `523ef6d`
- **Also recorded in:** `.planning/WINDOWS.md` as a `deviation` window, so the plan-defect class stays visible to the next planning round even though this instance is closed.

No other deviation occurred. No architectural decision was needed (Rule 4 never triggered), no package was installed, no out-of-scope failure was touched, `.planning/REQUIREMENTS.md` was not modified, and no pre-existing warning or unrelated test was fixed.

## Issues Encountered

- **The plan's read_first cited ports 9090 and 6060; the fixture uses 9001-9008.** `03-VERIFICATION.md`'s reproduction block names the ports the verifier used in its own synthetic payload, not the ports in the committed browser fixture. The conflated pair in `tests/test_advanced_ui.py` is 9002 (`absent`) and 9003 (`complete` with a zero count), which is what was split. Worth noting because a reader following the citation to the test file would find neither port.
- **The vocabulary contract test passes on arrival.** That is correct for a test whose job is to lock existing agreement, but it means the TDD RED gate cannot be observed for it in the ordinary way. Rather than leave it as an unfalsified claim, its extraction-and-comparison logic was probed in isolation against a client rename, a client reorder and a server rename; only the reorder leaves it passing. Recorded in coverage D5 as a second verification ref.
- **`timeout(1)` is not available on this host.** The first precondition check used `timeout 300 …` and failed with `command not found`; re-run without it. The precondition itself was satisfied — the browser suite launched Chromium and ran `service_detail_gap_evidence` to a real pass (1 passed, 8 subtests) before any edit.

## Known Stubs

None. A scan of all five modified files for hardcoded empty values flowing to the UI, placeholder text, `TODO`/`FIXME`/`XXX`/`HACK` markers, and skipped or todo tests returned nothing. The suite reports no skips and no xfails. Every `<verify>` block in the plan was executed: Task 1's `<automated>` passed as `TWO_ABSENCES_READ_DIFFERENTLY`, Task 2's `<automated>` passed as `RULE_IS_A_RULE_RECORD_UNTOUCHED`, and Task 2's `<human-check>` is carried forward to the end-of-phase human checkpoint by the plan's own instruction and the project's `human_verify_mode: end-of-phase` setting, recorded as coverage D8.

## Threat Flags

None. No new network endpoint, route, auth path, file access pattern, payload field, or schema change at a trust boundary was introduced; `SCHEMA_VERSION` was not touched. All new operator copy is written through the existing `textContent`-only evidence path, and the serialized-container scan over the whole services table is preserved and still forbids brackets, braces and quotation marks in rendered gap-evidence lines. No package was installed, added, removed, upgraded or pinned, so no `## Package Legitimacy Audit` applies (threat register T-03-98, disposition `accept`).

All eight `mitigate` dispositions in the plan's threat register are implemented: T-03-90 and T-03-91 by the split branch plus the dedicated inequality assertion; T-03-92 and T-03-93 by the type-based rewrite plus the three fabrication shapes driven through the production route with a genuine-zero control; T-03-94 by the element guard and its new regression; T-03-95 by the source-level vocabulary contract; T-03-96 by the preserved `textContent` path and container scan; T-03-97 by keeping the edit to the named branches and one helper and re-running the sort, refresh-guard, section-navigation and accessibility regressions.

## Verification

- `uv run --project dashboard python -m pytest -q` → **294 passed, 406 subtests passed** in 86s. The immediate pre-plan baseline (after 03-15) was 291 passed / 406 subtests; this plan adds three tests and no subtests. The condition is monotonic as the plan specifies, not an equality: nothing previously green went red, and the plan's own note that the recorded 288/395 figure predates 03-15 holds.
- `uv run --project dashboard python -m pytest tests/test_advanced_ui.py -q` → 33 passed, 67 subtests passed. The sort, refresh-generation-guard, section-navigation, accessibility, asset-header and both prior fabrication regressions all survived the renderer edits.
- Task 1 `<verify>`: `pytest tests/test_advanced_ui.py -k service_detail_gap_evidence` passed, and the four count gates held — `No collection stream established for this service` occurs exactly once in `dashboard/advanced.js` and once in `tests/test_advanced_ui.py`; `No gap evidence` occurs exactly once in each. Measured before the change: the new literal occurred zero times in both files and `No gap evidence` occurred twice in the test file, which was the conflation itself.
- Task 2 `<verify>`: `pytest tests/test_advanced_ui.py -k 'non_numeric_server_values or gap_evidence_vocabulary_matches or unmeasured_service_shows_its_failure_class or unmeasured_latency_and_duration_never_rank'` → 4 passed. `function finiteMeasurement` occurs exactly once in `dashboard/advanced.js` — rewritten in place, not duplicated beside the old one.
- The two absences render as two different strings in the live DOM at the production `/advanced` route, and the difference is asserted by its own statement rather than inferred from two map entries.
- The genuine-zero control still renders `0 ms` and `0 seconds`, and its zero gap count renders with no digit and no counted phrase — so hardening the rule did not cost a real measurement.
- The element guard: the existing direct gap-join tests pass unchanged (2 passed, 14 subtests), the new regression passes, and with the guard temporarily removed the new regression fails with `AttributeError: 'str' object has no attribute 'get'` at `dashboard/beacon/diagnosis.py:393`. The guard was restored from git and re-counted at exactly one occurrence before committing.
- `.planning/REQUIREMENTS.md` is byte-unchanged by this plan (`git diff` over the plan's whole commit range reports zero changes to it). `| TEL-06 | Phase 3 | Gaps Found |`, `- [ ] **TEL-06**`, `| DIA-03 | Phase 3 | Complete |` and `| DIA-08 | Phase 3 | Deferred to Phase 4 |` each occur exactly once.
- `deferred-items.md` carries rows for WR-04, IN-02, IN-04, IN-06 and IN-08 each with a reason, one grouped row naming all seventeen carried-forward identifiers, its original row 1 unchanged, and a scope paragraph that states plainly it does not record every review finding.
- 03-15's work was not regressed: `job_outcome_unrecorded` still occurs exactly once in `dashboard/beacon/diagnosis.py` and once in `dashboard/advanced.js`, `RUNNING_JOB_STATE` is untouched, and `test_every_emitted_exception_kind_renders_operator_copy` is green inside the full browser module run.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Both `missing` bullets of `03-VERIFICATION.md`'s second gap are implemented, and the behavioural spot-check recorded as `absent distinguishable from clean — FAIL` now passes through the same route in a real browser. With 03-15 closing the first gap, both of the round-3 verification gaps are ready for independent re-verification.
- **TEL-06 is deliberately NOT promoted.** This plan closes a TEL-06 gap, and the phase's carried-forward process prohibition forbids recording a requirement complete on the strength of an implementation claim. `requirements-completed` is empty by design and `.planning/REQUIREMENTS.md` is untouched. Only the next independent re-verification round may promote it, and the DIA-03 and DIA-08 rows were left exactly as the verifier settled them.
- One human verification item (D8) is outstanding across 03-14, 03-15 and 03-16, and is collected once at the end-of-phase human checkpoint on the target Pi.
- The seventeen round-1 carried-forward findings remain open and are now recorded in `deferred-items.md` with a citation to their argument, so the next planning round can triage them from the record rather than rediscovering them. Five round-3 findings are recorded there as deliberate exclusions with reasons; `WR-04` is the one with real substance behind its deferral, because the review's proposed remedy would dispatch work without a confirmed lease and therefore touches Phase 1's duplicate-execution contract.
- One process item for the next planner: two acceptance criteria in this phase have now been unsatisfiable as written (03-13's `grep -c` arithmetic, this plan's `pytest -k attach`). Both were caught by executing the gate rather than by reading it. Recorded in `.planning/WINDOWS.md`.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-19*

## Self-Check: PASSED

All five modified source files, the `deferred-items.md` record and this SUMMARY exist on disk. All seven commits (`67cde82`, `3094e3a`, `832c445`, `477c1f9`, `99ad44e`, `523ef6d`, `66fc367`) are present in repository history. All three newly named tests are present at their claimed paths. No claimed artifact, test or commit is missing.
