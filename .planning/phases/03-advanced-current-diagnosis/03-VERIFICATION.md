---
phase: 03-advanced-current-diagnosis
verified: 2026-08-18T19:17:28Z
status: gaps_found
score: 3/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
unverified_prohibitions: 5
re_verification:
  previous_status: gaps_found
  previous_score: 3/4
  gaps_closed:
    - "Current collection health truthfully reports collection gaps and promotes only real collection failures as actionable exceptions. (prior Gap 1 — per-row `open` derivation)"
    - "Only genuine collection failures are promoted as collection_gap exceptions; other coverage reasons keep their own meaning. (prior Gap 2 — reason-to-kind mapping)"
    - "The bounded gap projection discloses incomplete gap evidence rather than presenting a capped list as complete. (prior Gap 3 — same-population count/truncated)"
  gaps_remaining: []
  regressions: []
  newly_found:
    - "Success Criterion 3 was over-credited in the previous report: the Services table fabricates a `0 ms` latency for every offline and unknown service. Origin commits are 2f506ea (03-04 renderer) and 911ee75 (03-02 server) — this predates the gap-closure round and is NOT a regression introduced by 03-08/03-09/03-10."
gaps:
  - truth: "Operator can inspect every configured or discovered service's status, latency or failure class, state duration, criticality, tags, and effective health rule."
    status: failed
    reason: "The Services table renders a fabricated `0 ms` latency for every offline and unknown service instead of its failure class, and ranks those fabricated zeros as the fastest services under the latency sort. Reproduced in a real browser through the production /advanced route: an offline service carrying failure_class='ConnectionRefused' renders latency_cell='0 ms'. `Number(null) === 0` passes `Number.isFinite`, so the failure-class fallback is unreachable from any real server payload — the server sets latency_ms=None for every non-online service by construction."
    artifacts:
      - path: "dashboard/advanced.js"
        issue: "Line 629-630 `Number(service.latency_ms)` coerces null to 0, so `Number.isFinite` is true and the `displayValue(service.failure_class || service.last_error, '')` fallback is dead code. Line 500-501 repeats the coercion in the latency sort key, so the `Number.POSITIVE_INFINITY` unmeasured-last branch is also dead. Line 453-454 repeats it a third time in `serviceDuration`, so a null `state_duration_seconds` renders `0 seconds` instead of `Unknown duration`."
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Line 150 `'latency_ms': row.get('probe_latency_ms') if availability == 'online' else None` makes null the guaranteed value for every non-online service, so the defect is systematic rather than an edge case."
      - path: "dashboard/advanced.js"
        issue: "Line 648 `JSON.stringify(service.collection_gaps || service.collection_gap || 'No gap evidence')` renders the literal string `[]` in every expanded service row, because `[]` is truthy."
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Line 167 `'collection_gaps': []` is a hardcoded empty list that nothing in the module populates — a HOLLOW_PROP. The composer does attach per-stream gaps (`stream['gaps'].append(item)`) but never per-service ones."
      - path: "tests/test_advanced_ui.py"
        issue: "Lines 417 and 872 place `latency_ms: None` services into the browser fixtures but never assert the latency cell's text for the null case, and the sort survival test exercises `duration`, not `latency` — so the defect is uncovered rather than locked in."
    missing:
      - "Distinguish absent from zero at every coercion site: reject `null`/`undefined` before `Number()` in the latency cell, the latency sort key, and `serviceDuration`, so an unmeasured service shows its failure class (per 03-UI-SPEC.md:118) and an unknown state duration shows `Unknown duration`."
      - "Populate `service['collection_gaps']` from the composed pipeline gap items for the matching `service:<port>` stream, or drop the field and render an explicit `No gap evidence` string — never `JSON.stringify` a raw container into operator copy."
      - "Add a browser regression asserting an offline service renders its failure class (not `0 ms`), an unknown-duration service renders `Unknown duration`, and an ascending latency sort places unmeasured services last."
  - truth: "Background-job health reported to the operator reflects what the job actually did."
    status: partial
    reason: "`dispatch_callback` performs the durable `succeeded` write inside the same `try` as the work, so a raising `succeeded` write is caught by the generic `except Exception` and durably recorded as `state='failed'` for a callback that succeeded. `compose_active_exceptions` then promotes it as a `job_failed` exception on the Overview safety surface. Reproduced: with `_invoke_callback` returning True and the `succeeded` write raising `sqlite3.OperationalError`, the transition sequence written was `[('started', None), ('succeeded', None), ('failed', 'OperationalError')]`."
    artifacts:
      - path: "dashboard/beacon/worker_main.py"
        issue: "Lines 272-296: the `_write_job_health_transition(..., 'succeeded')` call at line 280 sits inside the try block whose `except Exception` at line 287 writes `failed`, so a bookkeeping failure is indistinguishable from a work failure."
    missing:
      - "Move the `succeeded` bookkeeping write outside the work's `except Exception` scope, or record the outcome first and let a bookkeeping-write failure surface as its own distinct condition rather than as a work failure."
      - "Add a regression proving a callback whose work returned True never produces durable `state='failed'` evidence."
  - truth: "REQUIREMENTS.md records each Phase 3 requirement at the status independent verification actually established."
    status: failed
    reason: "The traceability table marks DIA-03 `Complete` (line 130). Independent verification now establishes DIA-03 is not satisfied — the Services surface fabricates latency for every offline service. Separately the body checklist still shows `[ ]` for all six Phase 3 IDs (lines 25, 36-38, 43, 57) while the table shows four of them `Complete`, so the file contradicts itself. Plan 03-10 left the body boxes untouched by explicit instruction."
    artifacts:
      - path: ".planning/REQUIREMENTS.md"
        issue: "Line 130 `| DIA-03 | Phase 3 | Complete |` is now a false record. Lines 25/36/37/38/43/57 body checkboxes are unchecked while lines 128/129/130/143 claim Complete."
    missing:
      - "Move DIA-03 back off `Complete` to `Gaps Found` until the Services fabrication gap is closed and re-verified."
      - "Reconcile the body checklist with the traceability table in one pass so the two halves of the file agree (DIA-01, DIA-02, UX-02 checked; TEL-06, DIA-03, DIA-08 unchecked)."
    note: "Not corrected by this verifier. Editing the project's own record of truth is an executor action; the verifier reports the required end state."
deferred:
  - truth: "Operator can change supported *range* preferences in the advanced workspace (the `range` clause of Success Criterion 4)."
    addressed_in: "Phase 4"
    evidence: "Phase 4 success criterion 1: 'Operator can choose shared ranges from one hour through 90 days or a validated custom range within retained history.' No range control exists in advanced.html; the only preference controls present are refresh interval, density, pause, filters, and sort. Phase 3 is scoped to current diagnosis."
human_verification:
  - test: "On the target Pi, open /advanced while a real collection gap is active and while host evidence is stale."
    expected: "The workspace shows the open gap and the stale host as real, correctly labelled exceptions — and shows no resolved or retention-expired interval as an open actionable gap."
    why_human: "Carried forward from the previous report and re-declared as `human_judgment: true` in 03-08-SUMMARY.md coverage. Operator trust in the rendered snapshot on real hardware cannot be asserted programmatically. Collected at the end-of-phase human checkpoint per workflow.human_verify_mode."
prohibitions:
  - source: "03-08-PLAN.md"
    statement: "MUST NOT present resolved, retention-expired, or otherwise inferred evidence to the operator as a current, open, actionable fault -- every operator-facing open/actionable/kind label must be derivable from the durable row it describes, never from a neighbouring row or a stream-level fact."
    verification: judgment
    llm_judge_verdict: violated
    flagged: true
    detail: "UPHELD for collection gaps (independently reproduced). VIOLATED on the services surface: `0 ms` latency and `0 seconds` state duration are derivable from no durable row — they are artefacts of `Number(null)`."
  - source: "03-08-PLAN.md"
    statement: "MUST NOT suppress a genuine collection failure while narrowing false positives -- restricting promotion by reason must never cause a real collection_gap, or a reason value the code does not recognise, to go unreported to the operator."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    detail: "Reproduced: a real open collection_gap still promotes; an out-of-enum reason surfaces as coverage_unknown rather than being dropped."
  - source: "03-09-PLAN.md"
    statement: "MUST NOT let automatic background refresh silently override an operator's explicit presentation choice, and MUST NOT present a machine identifier or a placeholder as the operator's primary safety evidence when the server supplied real evidence."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    detail: "Reproduced in a real browser: sort and aria-sort survive both automatic poll and manual Refresh; every emitted exception kind renders operator copy and an unrecognised kind renders an explicit card."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT let test scaffolding mutate process-global state so that suite greenness depends on execution order."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    detail: "Reproduced with the previous report's own probe shape: running the phase module followed by a real-clock probe module now passes."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT record a requirement, plan, or phase as complete on the strength of an implementation claim rather than independent verification -- the traceability table is the project's own memory of what is actually true."
    verification: judgment
    llm_judge_verdict: violated
    flagged: true
    detail: "DIA-03 stands at `Complete` in REQUIREMENTS.md while independent verification establishes it is not satisfied. 03-10 inherited this from the previous report's over-credit rather than inventing it, but the record is false now and must be corrected."
---

# Phase 3: Advanced Current Diagnosis Verification Report

**Phase Goal:** The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.

**Verified:** 2026-08-18T19:17:28Z
**Status:** gaps_found
**Re-verification:** Yes — after gap-closure plans 03-08, 03-09, 03-10 (prior Gaps 1-3).

## Gap-Closure Outcome (03-08 / 03-09 / 03-10)

**All three prior BLOCKER gaps are genuinely closed.** Each was re-run through `GET /api/advanced/current` on the production Flask route using the previous report's own reproduction shapes — not read from a SUMMARY.

| Prior gap | Claimed | Verifier result | Reproduction |
| --- | --- | --- | --- |
| Gap 1 — per-row `open` borrowed from the stream | Closed | ✓ CLOSED | Open-gap stream + resolved-30d + retention-expired row on the same stream now returns exactly one `open=True` item and exactly **one** `collection_gap` exception. Was three open + three exceptions. |
| Gap 2 — `reason` discarded, kind hard-coded | Closed | ✓ CLOSED | `reason='unknown'` → `coverage_unknown` (its own kind). `reason='expired'` and `'not_yet_monitored'` → `actionable=False`, promoted as nothing. Out-of-enum → `coverage_unknown`, never dropped. |
| Gap 3 — `count`/`truncated` over different populations | Closed | ✓ CLOSED | 65 open-gap streams + 0 coverage rows → `count=48, truncated=True` (was 64/False). 64 open-gap streams + 60 coverage rows → `count=48, truncated=True` (was 112/True). Mirror case — 65 streams of which only 2 carry an open gap + 5 coverage rows → all 7 items returned, `truncated=False`, while `streams.truncated` correctly stays `True`. |

Three adjacent items 03-09/03-10 carried are also confirmed by execution, not presence:

| Item | Verifier result | Evidence |
| --- | --- | --- |
| Exception cards read as raw kinds + "Unknown evidence" | ✓ CLOSED | Real browser render: `Critical service offline — Broken service on port 9090`, `Coverage could not be determined — metric: temp`, and an unknown kind renders `Unrecognised exception — totally_new_kind` and is still counted. |
| Operator's service sort reset on every poll | ✓ CLOSED | Real browser render: order, `aria-sort=ascending`, and the visible Reset control all survive an automatic poll and a manual Refresh. Only Reset / Clear-all-filters clear it. |
| Frozen `time.time` leaking into later modules | ✓ CLOSED | `pytest tests/test_advanced_diagnosis_api.py tests/<real-clock probe>` → 31 passed. The previous report's leak probe no longer trips. |
| `MaintenanceBusy` escaping as an unparseable HTML 500 | ✓ CLOSED | `app.py:2131-2138` returns JSON 503 for `MaintenanceBusy` and for `sqlite3.OperationalError`; `advanced.js:702-707` names the server-supplied reason. |

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Operator can open the dedicated advanced page from the dashboard and return without losing theme. | ✓ VERIFIED | Asset routes at `app.py:2096-2118`; `beacon-theme` persisted and scroll captured at `app.js:418-444`. Behavioral: `test_theme_or_return_round_trip_preserves_theme_and_consumes_scroll_once` and `test_production_routes_serve_the_advanced_document_bundle` executed, passed. |
| 2 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, and host freshness. | ✓ VERIFIED | `_host_payload` + `freshness_state` project every named field (`diagnosis.py:59-107`); stale/unknown host raises its own `host_freshness` exception, which renders as `Host evidence is stale`. Named host tracer tests executed, passed. |
| 3 | Operator can inspect every current service's status, **latency or failure class**, **state duration**, criticality, tags, and effective health rule. | ✗ FAILED | Real-browser reproduction: an offline service carrying `failure_class='ConnectionRefused'` renders its latency/failure-class cell as **`0 ms`**; an unknown service also renders `0 ms`. Ascending latency sort places both fabricated zeros ahead of the genuine 12 ms measurement. `state_duration_seconds: null` renders `0 seconds`. Every expanded row reads `Collection-gap evidence: []`. |
| 4 | Operator can view truthful retention, resolution, database pressure, worker freshness, **collection gaps**, and background-job health, and change presentation/refresh/filtering preferences without remote controls. | ✓ VERIFIED | All three prior gap-projection blockers reproduced closed (table above). Only one browser fetch exists (`advanced.js:58`, `cache: 'no-store'`), no method other than GET, no mutation affordance. Preferences behavioral evidence executed and passing. The `range` clause is deferred to Phase 4 (below). One warning recorded against background-job health (CR-03, gap 2). |

**Score:** 3/4 roadmap success criteria verified (0 present-but-behavior-unverified).

> **This is not the same 3/4 as the previous report.** Success Criterion 4 moved from FAILED to VERIFIED — the gap-closure round did what it was written to do. Success Criterion 3 moved from VERIFIED to FAILED because the previous report credited it on symbol presence ("unchanged and not regressed by 03-07") without ever rendering an offline service. `git log -L` places the defect at `2f506ea` (03-04) and `911ee75` (03-02): it is a pre-existing Phase 3 defect that was over-credited, **not** a regression introduced by 03-08/03-09/03-10.

### Reproduction Evidence (verifier-executed)

Production route, `GET /api/advanced/current` — the previous report's own shapes:

```
--- one open gap + resolved-30d + retention-expired on the SAME stream ---
  GAP reason=collection_gap   open=True  actionable=True
  GAP reason=collection_gap   open=False actionable=False
  GAP reason=expired          open=False actionable=False
  gaps.count=3 truncated=False
  EXCEPTION KINDS: ['host_freshness','worker_freshness','collection_gap']      <- was 3x collection_gap

--- single reason='unknown' interval, NO open gap ---
  GAP reason=unknown open=False actionable=True
  EXCEPTION KINDS: [...,'coverage_unknown']                                    <- was 'collection_gap'

--- reason='expired' + 'not_yet_monitored', recent, no open gap ---
  both open=False actionable=False; EXCEPTION KINDS: ['host_freshness','worker_freshness']

--- 65 open-gap streams, zero coverage rows ---
  gaps.count=48  gaps.truncated=True   (was 64 / False)   all items open=True

--- 64 open-gap streams + 60 coverage rows ---
  gaps.count=48  gaps.truncated=True   (was 112)          all items open=True

--- MIRROR: 65 streams, only 2 with open gaps, + 5 coverage rows ---
  gaps.count=7   gaps.truncated=False  streams.truncated=True
```

Real browser, production `/advanced` route, Playwright + Chromium:

```
=== LATENCY COLUMN ===
  Broken service:9090   status=● offline   latency_cell='0 ms'     (failure_class='ConnectionRefused')
  Unknown service:7070  status=● unknown   latency_cell='0 ms'
  Fast service:8080     status=● online    latency_cell='12 ms'

=== ASCENDING LATENCY SORT ===
  ['Broken service:9090', 'Unknown service:7070', 'Fast service:8080']   <- unmeasured ranked fastest

=== SERVICE DETAIL ROW ===
  ... Freshness: fresh — 5 seconds ago; expected every 60 secondsCollection-gap evidence: []
```

```
Number(null) = 0   isFinite: true   ->  rendered latency cell: '0 ms'
formatDuration(serviceDuration({state_duration_seconds: null})) -> '0 seconds'
formatDuration(serviceDuration({}))                             -> 'Unknown duration'   (unreachable: server always sends null)
Boolean([]) = true   JSON.stringify([]) = '[]'
```

Worker bookkeeping (`dispatch_callback`, work succeeds, `succeeded` write raises a transient `OperationalError`):

```
dispatch raised: OperationalError database is locked
transitions written: [('started', None), ('succeeded', None), ('failed', 'OperationalError')]
```

### Deferred Items

| # | Item | Addressed In | Evidence |
| --- | --- | --- | --- |
| 1 | The `range` clause of Success Criterion 4 — no range preference control exists in the advanced workspace. | Phase 4 | Phase 4 success criterion 1: "Operator can choose shared ranges from one hour through 90 days or a validated custom range within retained history." Phase 3 is scoped to current diagnosis; `advanced.html` exposes refresh interval, density, pause, filters, and sort only. |

Neither Phase 03.1 (planned maintenance recognition, MNT-01..04) nor Phase 4 owns service latency rendering, per-service collection-gap evidence, or worker job bookkeeping. Those are Phase 3's own current-diagnosis contract and are reported as gaps, not deferrals.

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/app.py` | Asset routes + GET-only current endpoint that fails legibly | ✓ VERIFIED | `MaintenanceBusy` → JSON 503, `sqlite3.OperationalError` → JSON 503 with a fixed message and the class name logged, not returned. Query params still 400, `Cache-Control: no-store` intact. |
| `dashboard/advanced.html` / `advanced.css` | Semantic responsive workspace | ✓ VERIFIED | Served through the real WSGI app; browser regressions assert the section/table structure. |
| `dashboard/advanced.js` | Snapshot rendering, preferences, refresh safety | ⚠️ HOLLOW | `EXCEPTION_COPY` (131-183), the guarded `selectSection` (685-699), sort survival, and the server-reason error region are all real and behaviorally proven. The service latency cell, latency sort key, and duration formatter all coerce `null` to `0`, rendering fabricated measurements; `collection_gaps` is stringified straight into operator copy. |
| `dashboard/beacon/diagnosis.py` | Truthful bounded composition | ⚠️ PARTIAL | The gap projection is now fully truthful — per-row `open`, `GAP_REASON_EXCEPTION_KINDS`, one bounded population, `SCHEMA_VERSION` 2. `collection_gaps: []` (line 167) remains a hardcoded empty list nothing populates. |
| `dashboard/beacon/repositories.py` | Bounded readers with completeness metadata | ✓ VERIFIED | `gaps_limit` and the narrow `open_gap_streams_truncated` are exposed and are sound because the `ORDER BY` places open-gap streams strictly first (repositories.py:126-142). |
| `dashboard/beacon/worker_main.py` | Durable authority-fenced job health | ⚠️ PARTIAL | The authority fence and lease-loss handling are correct; the `succeeded` write sits inside the work's `except Exception`, so a bookkeeping failure is recorded as a work failure. |
| `tests/test_advanced_diagnosis_api.py` | Current-diagnosis regressions, no global clock leak | ✓ VERIFIED | 30 tests; `_freeze_clock` uses `addCleanup(patcher.stop)`; `ClockIsolationTests` runs a nested probe and asserts the real clock is restored. Cross-module leak probe passes. |
| `tests/test_advanced_ui.py` | Browser regressions | ⚠️ PARTIAL | 30 browser tests covering exception copy, unknown kind, unknown section, sort survival, resolved-vs-open gap copy, reverse-order refresh. `latency_ms: None` appears in two fixtures but the latency cell is never asserted for the null case and the sort test uses `duration`, so the SC3 defect is uncovered. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `advanced.js` | `/api/advanced/current` | cache-disabled same-origin GET | ✓ WIRED | Sole browser fetch (line 58); parameterless and effect-free. |
| Flask adapter | diagnosis composer | no-store JSON + typed error branches | ✓ WIRED | `app.py:2121-2141`. |
| gap row `reason` | exception kind | `GAP_REASON_EXCEPTION_KINDS` / `gap_exception_kind` | ✓ WIRED | Reproduced for all four enum values plus an out-of-enum value. |
| per-row gap state | `open` / `actionable` | row-level derivation | ✓ WIRED | `diagnosis.py:236` `'open': False` unconditional for coverage rows; synthesis is the sole producer of `open: True`. |
| `open_gap_streams_truncated` + `gaps_limit` | `gaps.truncated` / `gaps.count` | one bounded population | ✓ WIRED | Reproduced in both directions, including the false-incompleteness mirror case. |
| server exception kinds | Overview exception cards | `EXCEPTION_COPY` Map + unrecognised branch | ✓ WIRED | Every emitted kind rendered as operator copy in a real browser. |
| `MaintenanceBusy` | refresh error region | JSON 503 → `apiFetch` → `renderRefreshError` | ✓ WIRED | `test_refresh_error_names_the_server_supplied_reason` passes. |
| refresh controller | newest response only | generation guard on both branches | ✓ WIRED | Reverse-order behavioral tests executed, passed. |
| server `service.failure_class` | Services table latency/failure-class column | fallback when latency is unmeasured | ✗ NOT WIRED | The fallback is unreachable: `Number(null) === 0` satisfies `Number.isFinite`. |
| composed pipeline gap items | `service['collection_gaps']` | per-service gap attachment | ✗ NOT WIRED | Streams get their gaps; services never do. |

### Data-Flow Trace (Level 4)

| Artifact | Data variable | Source | Produces real data | Status |
| --- | --- | --- | --- | --- |
| Host renderer | `snapshot.host` | `system_stats` via `read_current_host` | Yes | ✓ FLOWING |
| Services table — status/criticality/tags/health rule | `snapshot.services[*]` | services + meta + latest checks | Yes | ✓ FLOWING |
| Services table — latency cell | `service.latency_ms` | `probe_latency_ms` when online, hardcoded `None` otherwise | Renders `0 ms` from `null` | ✗ FABRICATED |
| Services table — state duration | `service.state_duration_seconds` | `now - state_since`, `None` when unknown | Renders `0 seconds` from `null` | ✗ FABRICATED |
| Service detail — collection-gap evidence | `service.collection_gaps` | hardcoded `[]`, nothing populates it | No | ✗ HOLLOW_PROP |
| Exception cards | `EXCEPTION_COPY.get(kind)(item)` | server-emitted kinds + their own fields | Yes | ✓ FLOWING |
| Streams / pending / gaps regions | `pipeline.*` | sentinel-measured bounded reads | Yes | ✓ FLOWING |
| Pipeline job health | `pipeline.jobs[*].state` | `background_job_health` durable rows | Yes, except the CR-03 write path | ⚠️ CONDITIONALLY FALSE |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Full workspace suite (run once) | `uv run --project dashboard python -m pytest -q` | 281 passed, 369 subtests passed | ✓ PASS |
| Prior gaps 1-3 through the production HTTP route | verifier repro script | all three shapes corrected | ✓ PASS |
| Theme round trip + scroll consumed once | `pytest tests/test_advanced_ui.py -k theme_or_return_round_trip` | passed | ✓ PASS |
| Service sort survives poll and manual refresh | `pytest tests/test_advanced_ui.py -k service_sort_survives` | passed | ✓ PASS |
| Resolved history never renders as an open gap | `pytest tests/test_advanced_ui.py -k resolved_history_never` | passed | ✓ PASS |
| Unknown section never blanks the workspace | `pytest tests/test_advanced_ui.py -k unknown_section_value` | passed | ✓ PASS |
| Every emitted exception kind renders operator copy | `pytest tests/test_advanced_ui.py -k every_emitted_exception_kind` | passed | ✓ PASS |
| Reverse-order refresh ordering invariant | `pytest tests/test_advanced_ui.py -k reverse_order` | passed | ✓ PASS |
| Global clock isolation across modules | `pytest tests/test_advanced_diagnosis_api.py <real-clock probe module>` | 31 passed; real clock restored | ✓ PASS |
| Offline service renders its failure class | real-browser render via production route | rendered `0 ms`, never `ConnectionRefused` | ✗ FAIL |
| Ascending latency sort ranks unmeasured last | real-browser render via production route | unmeasured ranked first | ✗ FAIL |
| Unknown state duration renders `Unknown duration` | JS evaluation of the shipped functions | rendered `0 seconds` | ✗ FAIL |
| Service detail shows real collection-gap evidence | real-browser render via production route | rendered the literal `[]` | ✗ FAIL |
| Succeeded callback never records durable `failed` | `dispatch_callback` fault injection | wrote `('failed', 'OperationalError')` | ✗ FAIL |

Suite greenness is now accepted as supporting evidence: the order-dependence caveat from the previous report is resolved and was independently re-tested.

### Probe Execution

No `scripts/*/tests/probe-*.sh` exists in this repository and no plan declares a probe path. Step 7c: SKIPPED (no probes declared or conventional).

### Requirements Coverage

All six phase requirement IDs are claimed by at least one plan — 03-01 (DIA-01, DIA-02), 03-02 (TEL-06, DIA-02/03/08), 03-03 (TEL-06, DIA-01/02/08), 03-04 (DIA-01/03/08, UX-02), 03-05 (TEL-06, DIA-01/03/08, UX-02), 03-06 (TEL-06, DIA-02/03/08), 03-07 (TEL-06, DIA-02/03/08), 03-08 (TEL-06, DIA-08), 03-09 (TEL-06, DIA-03/08), 03-10 (all six). No orphaned Phase 3 requirements in REQUIREMENTS.md.

| Requirement | Description | Status | Evidence |
| --- | --- | --- | --- |
| TEL-06 | Effective retention, resolution, pressure, worker freshness, collection gaps, background-job health | ✓ SATISFIED | The collection-gap projection is now truthful in every reproduced shape; retention, resolution, pressure, and worker freshness project real durable evidence. The CR-03 job-health write path is a warning, not an absence of the capability. |
| DIA-01 | Open dedicated advanced page from either theme | ✓ SATISFIED | Production asset routes plus theme continuity, behaviorally tested. |
| DIA-02 | Current host metrics, identity, sample time, freshness | ✓ SATISFIED | Full projection plus the `host_freshness` exception with real operator copy. |
| DIA-03 | Every service's status, latency/failure class, duration, criticality, tags, health rule | ✗ BLOCKED | Latency and state duration are fabricated for the exact services an operator opens the page to diagnose; the failure-class fallback is unreachable. |
| DIA-08 | Effective settings + presentation/refresh/filter preferences, no remote control | ✓ SATISFIED | Settings project real effective values; preferences are local-only and survive refresh; the endpoint is GET-only and effect-free. The `range` clause is Phase 4's. |
| UX-02 | Move between dashboard and advanced without losing theme | ✓ SATISFIED | `beacon-theme` persisted; scroll restored exactly once; behaviorally tested. |

**REQUIREMENTS.md is currently wrong in two ways** and is reported as gap 3: DIA-03 stands at `Complete` (line 130) but is BLOCKED, and the body checklist (lines 25, 36-38, 43, 57) shows every Phase 3 ID unchecked while the table claims four are Complete. The verified end state is TEL-06 / DIA-01 / DIA-02 / DIA-08 / UX-02 satisfied, DIA-03 blocked.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `dashboard/advanced.js` | 629-630 | `Number(null)` coercion makes the fallback unreachable | 🛑 BLOCKER | Every offline and unknown service reports a fabricated `0 ms` latency instead of its failure class. |
| `dashboard/advanced.js` | 499-501 | Same coercion in the sort key | 🛑 BLOCKER | Unmeasured services rank as the fastest under the latency sort; the `POSITIVE_INFINITY` branch is dead. |
| `dashboard/advanced.js` | 452-454 | Same coercion in `serviceDuration` | ⚠️ WARNING | An unknown state duration renders `0 seconds` rather than `Unknown duration`. |
| `dashboard/beacon/diagnosis.py` | 167 | Hardcoded `'collection_gaps': []` nothing populates | 🛑 BLOCKER | HOLLOW_PROP rendered to the operator as the literal string `[]`. |
| `dashboard/advanced.js` | 648 | `JSON.stringify` of a raw container into operator copy | ⚠️ WARNING | `[]` is truthy, so the `'No gap evidence'` fallback is unreachable. |
| `dashboard/beacon/worker_main.py` | 272-296 | Bookkeeping write inside the work's `except Exception` | ⚠️ WARNING | A succeeded callback can be durably recorded as `failed` and promoted as a `job_failed` exception. |
| `tests/test_advanced_ui.py` | 417, 872 | Fixtures exercise `latency_ms: None` but assert nothing about it | ⚠️ WARNING | The SC3 defect is uncovered by an otherwise thorough browser suite. |

No `TBD`, `FIXME`, `XXX`, `HACK`, `TODO`, or `PLACEHOLDER` markers exist in any file modified by this phase. No mutation or remote-control affordance exists in the browser bundle; all DOM writes use `textContent`/`replaceChildren`, all SQL is parameterized, and `alert_webhook_url` is reduced to a boolean.

### Unverified Prohibitions (human review recommended)

Five judgment-tier prohibitions were declared across plans 03-08/09/10, all at `status: flagged-unverified`. No automated enforcement is wired for any of them, so the verdicts below are **non-authoritative LLM-judge assessments** and are flagged for human review rather than counted as green.

| Source | Prohibition (abbreviated) | Judge verdict | Basis |
| --- | --- | --- | --- |
| 03-08 | Never present inferred evidence as fact; every operator-facing label derivable from its durable row | ⚠️ VIOLATED | Upheld for gaps; violated by `0 ms` / `0 seconds` on the services surface. |
| 03-08 | Narrowing false positives must never suppress a genuine collection failure | ✓ UPHELD | Real gaps still promote; out-of-enum reasons surface rather than drop. |
| 03-09 | Background refresh must not override an operator choice; no machine identifiers as primary safety evidence | ✓ UPHELD | Both reproduced in a real browser. |
| 03-10 | Test scaffolding must not make suite greenness order-dependent | ✓ UPHELD | Cross-module clock probe passes. |
| 03-10 | Never record a requirement complete on an implementation claim rather than verification | ⚠️ VIOLATED | DIA-03 stands at `Complete` while blocked. |

### Human Verification Required

Carried forward and re-declared by 03-08-SUMMARY.md as `human_judgment: true`. Collected at the end-of-phase human checkpoint.

#### 1. Real-hardware collection-health trust

**Test:** On the target Pi, open `/advanced` while a real collection gap is active and while host evidence is stale.
**Expected:** The workspace shows the open gap and the stale host as real, correctly labelled exceptions — and shows no resolved or retention-expired interval as an open actionable gap.
**Why human:** Operator trust in the rendered snapshot on real hardware cannot be asserted programmatically. The synthetic reproductions above establish the server contract; this establishes that it reads correctly to the person using it.

The previous report's second human item — deciding whether to accept order-dependent suite evidence — is **resolved and withdrawn**: the process-global clock is now restored on teardown and the cross-module leak probe passes.

### Gaps Summary

The gap-closure round succeeded at what it was written to do. All three BLOCKER gaps from the previous report are closed, each confirmed by re-running that report's own reproduction shapes through the production HTTP route: a resolved-30-days-ago interval is no longer labelled open and actionable, a `reason='unknown'` interval is no longer reported as a collection failure, and 65 open gaps can no longer hide behind `truncated: false` — while the mirror defect (claiming incompleteness that cannot be substantiated) is prevented rather than merely avoided. The four carried adjacent items — operator copy for every exception kind, sort survival across refresh, the guarded section selector, and the restored process-global clock — are equally real and equally proven by execution. Success Criterion 4 is genuinely achieved.

The phase nonetheless cannot pass, because the same failure mode the last three plans were written to eliminate on the collection-health surface is still live, unaddressed, on the services surface — and it is the surface named by the phase goal's own words, "every monitored service". `Number(null) === 0` means the shipped code cannot distinguish *unmeasured* from *zero*. The result is that every offline and every unknown service — precisely the rows an operator opens this workspace to look at — reports a latency of `0 ms`, presents it beside a red offline marker, and is ranked by the latency sort as the fastest thing on the Pi. Its failure class, which the server did supply and which `03-UI-SPEC.md:118` explicitly contracts for this cell, is unreachable from any real payload. The same coercion renders an unknown state duration as `0 seconds`, and a hardcoded empty `collection_gaps` reaches the operator as the literal string `[]`. Fabricated evidence at the point of diagnosis is exactly the defect class this phase has already failed for once; that it lives in the services table rather than the gaps table does not change what it does to the operator.

Two things should be stated plainly. First, this is **not a regression**: `git log -L` places both halves of the defect at `2f506ea` (03-04) and `911ee75` (03-02), before the gap-closure round began. The previous report marked Success Criterion 3 verified on the strength of "unchanged and not regressed by 03-07" — presence-level reasoning that never rendered an offline row. `deferred-items.md` recorded the null-latency behaviour but scoped it as a `latency_ms: null` edge case belonging to service-table presentation work; the server guarantees `latency_ms = None` for every non-online service, so it is not an edge case, and the phase that owns "service-table presentation work" is this one. Second, the closure is small and local: reject `null`/`undefined` before `Number()` at three call sites, populate or remove `collection_gaps`, and move one bookkeeping write out of a `try`. What is missing is not design, it is a browser assertion on a row the fixtures already contain.

Alongside the code fix, `REQUIREMENTS.md` needs one reconciling pass: DIA-03 must come off `Complete`, and the body checklist must be brought into agreement with the traceability table, which currently contradicts it for all six Phase 3 requirements.

---

_Verified: 2026-08-18T19:17:28Z_
_Verifier: Claude (gsd-verifier)_
