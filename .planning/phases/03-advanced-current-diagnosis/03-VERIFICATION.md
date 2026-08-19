---
phase: 03-advanced-current-diagnosis
verified: 2026-08-19T06:54:41Z
status: gaps_found
score: 3/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
unverified_prohibitions: 5
re_verification:
  round: 3
  previous_status: gaps_found
  previous_score: 3/4
  gaps_closed:
    - "Gap A — Services surface fabricated evidence. Independently reproduced closed end-to-end: an offline service renders `ConnectionRefused`, an unknown service renders `Unknown`, a genuine `0` still renders `0 ms`, an unestablished state duration renders `Unknown duration`, an ascending latency sort places unmeasured services last, and no expanded row renders a serialized container."
    - "Gap C — REQUIREMENTS.md record. Both halves of the file now agree; nothing is recorded Complete ahead of verification. The record under-credits rather than over-credits, which is the correct failure direction."
  gaps_remaining:
    - "Gap B — Background-job health. Half closed and half regressed: the false-failure half is genuinely fixed, and a new suppression of a genuine failure was introduced in the same edit."
  regressions:
    - "dashboard/beacon/worker_main.py — 03-12 removed the implicit exception chaining that previously carried a genuine work failure out of dispatch. Proven by construction: the pre-03-12 shape produced the chain `OperationalError <- WorkBlewUp`; the post-03-12 shape produces `JobHealthBookkeepingError <- OperationalError` with the work error absent from `__cause__`, `__context__`, the durable row, and the log."
  newly_found:
    - "The client collapses the server's `absent` and `complete`-with-zero gap-evidence states into one identical `No gap evidence` string, so a service the telemetry pipeline has no record of ever observing reads exactly like a fully collected clean one. Introduced by 03-13 and pinned in place by its own browser regression (ports 9002 and 9003 assert the same literal)."
  over_credit_corrected:
    - "Success Criterion 4 was credited VERIFIED in the previous report while that same report filed Gap B (`partial`) against the background-job-health clause the criterion enumerates, and discounted it as 'a warning, not an absence of the capability'. That is the same presence-level reasoning that over-credited Success Criterion 3 one round earlier. SC4 is reported FAILED here on reproduced evidence."
gaps:
  - truth: "Background-job health reported to the operator reflects what the job actually did."
    status: partial
    reason: "The false-failure half is genuinely closed and was reproduced closed: with the work returning True and the `succeeded` write raising `sqlite3.OperationalError`, the durable row is now `running` and no `job_failed` exception is composed — it was `('failed','OperationalError')` before. But the same edit created the mirror defect. With the work raising `WorkBlewUp('the real cause')` and the `failed` write raising `sqlite3.OperationalError`, the genuine failure is erased from every channel simultaneously: the durable row stays `running`, `compose_active_exceptions` emits nothing, the raised `JobHealthBookkeepingError` names `error_class=OperationalError` (the write error, not the work error), `__cause__` and `__context__` are both the write error, and nothing logs the work error. Before 03-12 the work error survived in `__context__` and reached the container log through APScheduler's `exc_info=True`; it no longer does. The narrowing of a false positive removed the last channel carrying a real one."
    artifacts:
      - path: "dashboard/beacon/worker_main.py"
        issue: "Lines 335-339: `except Exception as exc: raise JobHealthBookkeepingError(callback_id, transition, _job_error_class(exc)) from exc` shadows the write error over `work_error`. Line 341 `if work_error is not None: raise work_error` is unreachable from this branch. No log statement exists on either the `work_error = exc` branch (line 316-318) or the write-failure branch."
      - path: "dashboard/beacon/worker_main.py"
        issue: "Four paths now leave the durable row at `running` (or absent) with no outcome ever written: lease loss during the work (311-315), lease loss during the outcome write (329-334), a non-lease outcome-write failure (335-339), and a `started`-write failure that skips the work entirely (297-302). Reproduced for three of the four."
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Line 421 `compose_active_exceptions` promotes only `job['state'] == 'failed'`, so a job wedged at `running` produces no exception on the Overview safety surface while `last_success_ts` silently ages. The state is still readable in the Pipeline `Background jobs` card, so it is not invisible — but it is never promoted as actionable, which is where an operator looks."
      - path: "dashboard/beacon/worker_main.py"
        issue: "`JobHealthBookkeepingError` has no handler anywhere in `dashboard/`. `run_worker` (444-486) catches only `(KeyboardInterrupt, SystemExit)`, so a transient `OperationalError` or `MaintenanceBusy` on the S1/S2/S3 bookkeeping write terminates the worker process before the scheduler is built. Not a regression — the pre-03-12 code raised the raw exception the same way — but the round named and documented the condition without deciding what to do about it."
      - path: "dashboard/beacon/worker_main.py"
        issue: "Line 330 logs 'Beacon worker lease lost while recording callback failure' on a branch now reached for `succeeded` as well. A callback that completed successfully logs a claim its own transition contradicts."
      - path: "tests/test_advanced_diagnosis_api.py"
        issue: "`test_outcome_paths_survive_the_bookkeeping_split` covers the raising callback and, separately, the failing `succeeded` write, but never both at once — which is exactly why the erased-failure path survived the round that created it."
    missing:
      - "Carry the work's bounded error class in the raised bookkeeping condition and chain from the work error, not from the write error, so a genuine failure survives in at least one channel: `raise JobHealthBookkeepingError(callback_id, transition, _job_error_class(exc), work_error_class=...) from (work_error or exc)`."
      - "Log the work error before raising, at error level, using `_job_error_class` only, so the no-message discipline is preserved while the cause stops disappearing."
      - "Promote a job whose outcome was never recorded onto the safety surface from its own durable row — a `running` state whose `last_started_ts` is older than a small multiple of its own cadence — with a matching `EXCEPTION_COPY` entry, so a wedged job is actionable rather than merely readable."
      - "Decide explicitly what `run_worker` does with `JobHealthBookkeepingError` on S1/S2/S3 rather than letting a named condition kill the worker by default."
      - "Correct the lease-loss log line so it names the transition being written instead of asserting a failure."
      - "Add the compound regression the round is missing: a raising callback whose outcome write also fails must leave the work's error class recoverable from the raised condition, and must not report the job as running."
  - truth: "Per-service collection-gap evidence tells the operator what the server actually established about that service."
    status: partial
    reason: "The join, the four completeness literals, and the operator copy are real and were reproduced end-to-end through the production route in a real browser — `1 gap (0 open)`, `1 gap (1 open)`, `Gap evidence unavailable`, and no serialized container anywhere. But the client collapses two of the four states the server deliberately derives. `absent` means the stream list is complete and contains no stream for this service at all — the telemetry pipeline has no record of ever observing it, which is reachable for a newly discovered service before its first persisted probe and for any service probed while `historical_persistence_allowed` is False under storage pressure (`app.py:1397-1416`, `telemetry.py:474-480` — the pressure gap lives in `runtime_state` and creates no stream row). Reproduced: port 9090 with `evidence='absent'` and port 6060 with `evidence='complete', count=0` render the byte-identical string `No gap evidence`. An unmonitored service reads as a clean bill of health. The new browser regression pins the collapse in place by asserting the same literal for both states."
    artifacts:
      - path: "dashboard/advanced.js"
        issue: "Line 266 `if (state === 'absent' || (state === 'complete' && count === 0)) return 'No gap evidence';` discards a distinction the server spent `_service_gap_evidence_state` deriving."
      - path: "tests/test_advanced_ui.py"
        issue: "`test_service_detail_gap_evidence_reads_as_operator_copy` expects `9002: 'No gap evidence'` (absent) and `9003: 'No gap evidence'` (complete), locking the conflation in."
    missing:
      - "Give `absent` its own operator copy naming what it means — that no collection stream has been established for this service — and keep `No gap evidence` for the `complete`-with-zero case that has actually been collected and is clean."
      - "Split the two assertions in the browser regression so the distinction is protected rather than pinned shut."
deferred:
  - truth: "Operator can change supported *range* preferences in the advanced workspace (the `range` clause of Success Criterion 4 and of DIA-08's requirement text)."
    addressed_in: "Phase 4"
    evidence: "Phase 4 success criterion 1: 'Operator can choose shared ranges from one hour through 90 days or a validated custom range within retained history.' No range control exists in advanced.html; the only preference controls present are refresh interval, density, pause, filters, and sort. Phase 3 is scoped to current diagnosis. This is a deferral, not a gap, and no closure plan should be written for it."
human_verification:
  - test: "On the target Pi, open /advanced while a real collection gap is active and while host evidence is stale."
    expected: "The workspace shows the open gap and the stale host as real, correctly labelled exceptions — and shows no resolved or retention-expired interval as an open actionable gap."
    why_human: "Carried forward from both previous reports and re-declared as human judgment in 03-08-SUMMARY.md and in 03-14-PLAN.md's own human-check block. Operator trust in the rendered snapshot on real hardware cannot be asserted programmatically. The synthetic reproductions below establish the server contract; this establishes that it reads correctly to the person using it. Collected at the end-of-phase human checkpoint."
prohibitions:
  - source: "03-08-PLAN.md"
    statement: "MUST NOT present resolved, retention-expired, or otherwise inferred evidence to the operator as a current, open, actionable fault -- every operator-facing open/actionable/kind label must be derivable from the durable row it describes, never from a neighbouring row or a stream-level fact."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: violated
    detail: "Was VIOLATED on the services surface. Now UPHELD, reproduced: the `0 ms` and `0 seconds` fabrications are gone at all three coercion sites, a genuine `0` still renders `0 ms`, and per-service gap evidence is joined from the service's own durable stream rather than hardcoded. The collection-gap projection was independently re-run through all six of the previous report's shapes and is unchanged."
  - source: "03-08-PLAN.md"
    statement: "MUST NOT suppress a genuine collection failure while narrowing false positives -- restricting promotion by reason must never cause a real collection_gap, or a reason value the code does not recognise, to go unreported to the operator."
    verification: judgment
    llm_judge_verdict: violated
    flagged: true
    previous_verdict: upheld
    detail: "UPHELD on the collection-gap surface (re-reproduced: a real open gap still promotes exactly once; `unknown` surfaces as `coverage_unknown`; `expired` and `not_yet_monitored` promote as nothing). VIOLATED on background-job health: 03-12 narrowed the false positive and, in the same edit, removed the last channel carrying a genuine work failure. Proven by construction, not inferred — the pre-03-12 structure yields `OperationalError <- WorkBlewUp`, the post-03-12 structure yields `JobHealthBookkeepingError <- OperationalError`."
  - source: "03-09-PLAN.md"
    statement: "MUST NOT let automatic background refresh silently override an operator's explicit presentation choice, and MUST NOT present a machine identifier or a placeholder as the operator's primary safety evidence when the server supplied real evidence."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "Re-reproduced in a real browser after this round's edits to the same sort key: a descending latency sort, its `aria-sort=descending` announcement, and the visible Reset control all survived a real 15-second automatic poll unchanged. `EXCEPTION_COPY` is untouched by this round's diff."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT let test scaffolding mutate process-global state so that suite greenness depends on execution order."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "Re-reproduced after ~665 new test lines landed. The one process-global the new tests replace (`worker_main._write_job_health_transition`) is restored by `addCleanup`; the clock patch still uses `mock.patch` + `addCleanup`. Ran the phase module alone (34 passed), with `test_runtime_ownership.py` in both orders (56 passed each), and with two real-clock modules in both orders (65 passed each). Latent shape noted, not a violation: the new `lease_lost` subtest reaches `stop_worker()`, which reads the module global `worker_main.scheduler`; `stop_worker` only reads it, so no mutation escapes."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT record a requirement, plan, or phase as complete on the strength of an implementation claim rather than independent verification -- the traceability table is the project's own memory of what is actually true."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: violated
    detail: "Was VIOLATED (DIA-03 stood at Complete while blocked). Now UPHELD and genuinely so: 03-14 promoted only the three requirements the previous report verified, left DIA-03 and TEL-06 open on the explicit ground that a plan closing its own gap is an implementation claim, and deferred promotion to this pass. ROADMAP still shows Phase 3 `In Progress`. The record under-credits rather than over-credits, which is the correct failure direction. DIA-03 is promoted here, by this verifier, on reproduced evidence."
---

# Phase 3: Advanced Current Diagnosis Verification Report

**Phase Goal:** The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.

**Verified:** 2026-08-19T06:54:41Z
**Status:** gaps_found
**Re-verification:** Yes — round 3, after gap-closure plans 03-11, 03-12, 03-13, 03-14.

Nothing below is taken from a SUMMARY. Every claim is either a line of code I read or a command I ran. Where a claim contradicts 03-REVIEW.md or a SUMMARY, my reproduction is stated so it can be re-run.

## Gap-Closure Outcome (03-11 / 03-12 / 03-13 / 03-14)

| Prior gap | Claimed | Verifier result | How I established it |
| --- | --- | --- | --- |
| **A** — Services surface fabricates evidence (`failed`) | Closed by 03-11 + 03-13 | ✓ **CLOSED** | Built a real SQLite database, served it through the production Flask app, opened `/advanced` in real Chromium, and read the rendered cells. Every one of the previous report's four reproduction shapes now renders correctly, and a genuine `0` still renders `0 ms`. |
| **B** — Background-job health misreports success as failure (`partial`) | Closed by 03-12 | ⚠️ **HALF CLOSED, HALF REGRESSED** | Fault-injected six outcome paths through the real `dispatch_callback` against a real database. The previous report's exact shape is fixed. The mirror shape — work fails *and* the outcome write fails — erases the genuine failure from every channel, and the erasure is a regression this round introduced. |
| **C** — REQUIREMENTS.md record (`failed`) | Closed by 03-14 | ✓ **CLOSED** | Read both halves of the file. They agree. Nothing is recorded Complete ahead of its evidence. The prior self-contradiction is resolved below. |

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Operator can open the dedicated advanced page from the dashboard and return without losing theme. | ✓ VERIFIED | Not touched by this round's diff (`app.js`, `app.py` unchanged). Behavioral re-check executed: `test_theme_or_return_round_trip_preserves_theme_and_consumes_scroll_once` and `test_production_routes_serve_the_advanced_document_bundle` passed. |
| 2 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, and host freshness. | ✓ VERIFIED | Untouched by this round; full suite green. Host projection re-exercised incidentally by every reproduction below (the payloads carried a live `host` block). |
| 3 | Operator can inspect every current service's status, **latency or failure class**, **state duration**, criticality, tags, and effective health rule. | ✓ **VERIFIED** *(was FAILED)* | Full-stack browser reproduction, field by field. See the reproduction section — every field in the criterion's own enumeration renders from the durable payload, and the `03-UI-SPEC.md:118` contract ("latency when healthy or failure class when not") is now honoured. |
| 4 | Operator can view truthful retention, resolution, database pressure, worker freshness, **collection gaps**, and **background-job health**, and change presentation/refresh/filtering preferences without remote controls. | ✗ **FAILED** *(was VERIFIED)* | Five of the six enumerated clauses re-reproduced truthful, including all six collection-gap shapes from the previous report. **Background-job health is not truthful**: a genuinely failed job is durably recorded as `running`, promoted as nothing, and its cause erased from the exception chain and the log. Reproduced. |

**Score:** 3/4 roadmap success criteria verified (0 present-but-behavior-unverified).

> **On Success Criterion 4's movement.** This is the second consecutive round in which a criterion moved from VERIFIED to FAILED because the previous report credited it over its own contrary evidence. Last round it was SC3, credited on "unchanged and not regressed by 03-07" without ever rendering an offline row. This round it is SC4, credited VERIFIED while the same report filed Gap B against the background-job-health clause SC4 enumerates and called it "a warning, not an absence of the capability". A criterion that names six things is not satisfied when one of them lies. I am not repeating that reasoning, and the finding is stated at the severity the reproduction supports rather than at the severity that would let the phase pass.

### Reproduction Evidence (verifier-executed)

Every block below is output I produced, not narration.

#### Services surface — real database, production Flask route, real Chromium

Server payload from `GET /api/advanced/current`:

```
HTTP 200  Cache-Control: no-store   schema_version 3
  port= 9090 avail=offline  latency_ms=None  failure_class='ConnectionRefused'  state_duration_seconds=None  collection_gaps={"count":0,"evidence":"absent","items":[],"open_count":0}
  port= 7070 avail=unknown  latency_ms=None  failure_class=None                 state_duration_seconds=None  collection_gaps={"count":1,"evidence":"complete",...}
  port= 6060 avail=online   latency_ms=0.0   failure_class=None                 state_duration_seconds=600   collection_gaps={"count":0,"evidence":"complete",...}
  port= 8080 avail=online   latency_ms=12.0  failure_class=None                 state_duration_seconds=3600  collection_gaps={"count":1,"evidence":"complete","items":[{...,"open":true}]}
```

Rendered by real Chromium at the production `/advanced` route:

```
=== DEFAULT ORDER ===          [name:port | status | LATENCY/FAILURE | DURATION]
  Broken service:9090   ● offline   ConnectionRefused   Unknown duration      <- was '0 ms' / '0 seconds'
  Unknown service:7070  ● unknown   Unknown             Unknown duration      <- was '0 ms' / '0 seconds'
  Zero service:6060     ● online    0 ms                10 minutes            <- a genuine zero still reads as a measurement
  Fast service:8080     ● online    12 ms               1 hours

=== ASCENDING LATENCY SORT (aria-sort=ascending) ===
  ['Zero service:6060', 'Fast service:8080', 'Broken service:9090', 'Unknown service:7070']   <- unmeasured LAST
=== DESCENDING (aria-sort=descending) ===
  ['Broken service:9090', 'Unknown service:7070', 'Fast service:8080', 'Zero service:6060']   <- unmeasured FIRST, deliberately extreme

=== SORT SURVIVES A REAL 15-SECOND AUTOMATIC POLL ===
  order identical, aria-sort still 'descending', Reset control still visible
```

DIA-03 field by field, offline critical service `:9090`:

```
  status               = '● offline'
  latency_or_failure   = 'ConnectionRefused'
  state_duration       = 'Unknown duration'
  criticality          = 'Critical'
  freshness            = '● fresh — 6 seconds ago'
  detail: Tags: lan, critical-path
  detail: Effective health rule: 200-299
  detail: Failure class: ConnectionRefused
  detail: Exact probe timestamp / Selected cadence / TLS trust annotation / Last error / Freshness  — all present
```

Expanded rows, gap-evidence copy:

```
  service-detail-9090   'Collection-gap evidence: No gap evidence'     (server said evidence='absent')
  service-detail-7070   'Collection-gap evidence: 1 gap (0 open)'
  service-detail-6060   'Collection-gap evidence: No gap evidence'     (server said evidence='complete', count=0)
  service-detail-8080   'Collection-gap evidence: 1 gap (1 open)'

  serialized-container scan over every rendered node in the services table -> []
```

The `JSON.stringify` defect is gone and the join is real. The two rows marked above are the newly found conflation: the server distinguished them and the client did not.

#### Collection-gap projection — regression re-check of all six prior shapes

```
Shape 1  open gap + resolved-30d + retention-expired on the SAME stream
    collection_gap open=True  actionable=True  /  collection_gap open=False  /  expired open=False
    gaps.count=3 truncated=False   EXCEPTIONS: ['host_freshness','worker_freshness','collection_gap']   <- exactly one
Shape 2  single reason='unknown'      -> [('unknown', False, True)]   EXCEPTIONS include 'coverage_unknown'
Shape 3  'expired' + 'not_yet_monitored' -> both open=False actionable=False; promoted as nothing
Shape 4  65 open-gap streams, 0 coverage rows      -> count=48 truncated=True  all open
Shape 5  64 open-gap streams + 60 coverage rows    -> count=48 truncated=True  all open
Shape 6  MIRROR: 65 streams, only 2 open, +5 cov   -> count=7 truncated=False, streams.truncated=True
```

Identical to the previous report's verified-closed results. No regression from 03-13's `SCHEMA_VERSION` 2 → 3 or from the new join.

#### Background-job health — fault injection through the real `dispatch_callback`

```
B1  work SUCCEEDS, `succeeded` write fails      (the previous report's exact shape)
    writes attempted : [('started',None), ('succeeded',None)]
    durable row      : state='running'  error_class=None            <- was ('failed','OperationalError')
    operator exception: []                                          <- was a job_failed card
    GAP B PRIMARY DEFECT: FIXED

B2  work SUCCEEDS, writes fine   -> row ('succeeded', last_success_ts=100), no exception     control OK
B3  work returns False           -> row ('failed','CallbackReturnedFalse'), job_failed card  control OK
B4  work RAISES, writes fine     -> row ('failed','WorkBlewUp'), job_failed card, WorkBlewUp re-raised  control OK

B5  work RAISES *and* the `failed` write fails      <- 03-REVIEW CR-01
    writes attempted : [('started',None), ('failed','WorkBlewUp')]
    raised           : JobHealthBookkeepingError  "... transition=failed error_class=OperationalError"
    __cause__        : OperationalError            __context__ : OperationalError
    full chain       : JobHealthBookkeepingError <- OperationalError
    WorkBlewUp anywhere in chain or message : False
    durable row      : state='running'  error_class=None
    operator exception: []
    THE GENUINE FAILURE IS GONE FROM EVERY CHANNEL

B6  `started` write fails (work never runs)
    durable row: none    pipeline job state: 'unknown'    raised JobHealthBookkeepingError    no operator signal
```

That B5 is a **regression**, not a pre-existing condition, is provable by construction rather than by argument:

```
PRE-03-12  structure (raise inside the except handler)   chain: OperationalError <- WorkBlewUp   retained: True
POST-03-12 structure (work error stashed in a variable)  chain: BookkeepingError <- OperationalError  retained: False
```

Python sets `__context__` to the active exception when you raise inside an `except` block. 03-12 moved the work error into a local variable, so no implicit chaining occurs, and the explicit `from exc` binds the *write* error. The channel that previously carried the real cause into the container log through APScheduler's `exc_info=True` was removed by the edit that fixed B1.

#### Test-scaffolding isolation (prohibition 4, re-tested after ~665 new test lines)

```
tests/test_advanced_diagnosis_api.py alone                                    34 passed, 78 subtests
+ tests/test_runtime_ownership.py            (both orders)                    56 passed, 139 subtests each
+ tests/test_telemetry_retention.py + tests/test_durable_queues.py (both)     65 passed, 94 subtests each
```

### Deferred Items

| # | Item | Addressed In | Evidence |
| --- | --- | --- | --- |
| 1 | The `range` clause of Success Criterion 4 and of DIA-08's requirement text. | Phase 4 | Phase 4 success criterion 1 names shared preset and validated custom ranges. `advanced.html` exposes refresh interval, density, pause, filters, and sort only. This is a deferral, not a gap — no closure plan should be written for it. |

Neither Phase 03.1 (MNT-01..04) nor Phase 4 owns worker job bookkeeping or per-service gap-evidence copy. Both open gaps are Phase 3's own contract and are reported as gaps, not deferrals.

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/advanced.js` | Truthful services rendering, preferences, refresh safety | ✓ VERIFIED | `finiteMeasurement` (71-75) is wired into all three former coercion sites — latency cell (660), latency sort key (531), `serviceDuration` (484). `formatServiceGapEvidence` (261-275) replaced the `JSON.stringify`. Diff is 45 lines, scoped, with no collateral edits; `EXCEPTION_COPY`, the guarded `selectSection`, and the refresh generation guard are untouched. One residual: line 266 collapses two server states (gap 2). |
| `dashboard/beacon/diagnosis.py` | Truthful bounded composition + per-service gap join | ✓ VERIFIED | `attach_service_collection_gaps` (360-393) joins on `('service', str(port))` with both sides `str()`-normalised; `_service_gap_evidence_state` (343-357) resolves from a durable truncation flag and only a literal `False` yields `absent`. `count`, `open_count` and `items` all derive from one list, so the Gap-3 defect cannot recur inside the block. The former hardcoded `collection_gaps: []` is gone. |
| `dashboard/beacon/worker_main.py` | Durable authority-fenced job health | ⚠️ PARTIAL | The three-scope split is real and the `succeeded` write is genuinely outside the work's `except Exception`. `JobHealthBookkeepingError` (240-256) leaks no message. But the compound path erases the work error, four paths leave the row wedged at `running`, and the named condition has no handler anywhere in `dashboard/`. |
| `tests/test_advanced_ui.py` | Browser regressions through the production route | ⚠️ PARTIAL | `test_unmeasured_service_shows_its_failure_class_instead_of_a_fabricated_latency` and `test_unmeasured_latency_and_duration_never_rank_or_read_as_zero` are substantive — they assert `ConnectionRefused`, `Unknown` with `assertNotRegex(r'\d')`, `0 ms` for a genuine zero, both sort directions, and sort survival across a poll. `test_service_detail_gap_evidence_reads_as_operator_copy` asserts eight ports and forbids `[]{}"` in the copy. It also pins the absent/complete conflation shut. |
| `tests/test_advanced_diagnosis_api.py` | Worker + composition regressions, no global-clock leak | ⚠️ PARTIAL | `test_a_succeeded_callback_never_records_durable_failed_evidence` proves B1 including the composed exception list. `test_outcome_paths_survive_the_bookkeeping_split` covers four outcomes — but never a raising callback together with a failing outcome write, which is why B5 survived the round that created it. |
| `.planning/REQUIREMENTS.md` | Record matching independent verification | ✓ VERIFIED | Traceability rows and body checklist agree for all six Phase 3 IDs. Nothing recorded Complete ahead of evidence. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| server `service.failure_class` | Services table latency/failure-class column | fallback reachable once absent is rejected before coercion | ✓ **WIRED** *(was NOT WIRED)* | Rendered `ConnectionRefused` in a real browser from a real payload. |
| server `service.latency_ms` absent | latency sort rank | `finiteMeasurement` → `POSITIVE_INFINITY` branch | ✓ **WIRED** *(was dead code)* | Ascending puts unmeasured last, descending puts them first — both observed. |
| server `state_duration_seconds` absent | `Unknown duration` | `serviceDuration` returns null → `formatDuration` | ✓ **WIRED** *(was dead code)* | Observed. |
| composed pipeline gap items | `service.collection_gaps` | per-service stream join | ✓ **WIRED** *(was NOT WIRED)* | `1 gap (1 open)` on the open-gap stream, `1 gap (0 open)` on the closed one. |
| `service.collection_gaps` | operator copy | `formatServiceGapEvidence` | ⚠️ PARTIAL | Real copy, no serialized container — but `absent` and `complete`-with-zero produce the same string. |
| `_invoke_callback` outcome | durable `background_job_health` transition | outcome decided outside the recording scope | ✓ WIRED | B1-B4 confirm the four ordinary outcomes. |
| work error on the compound path | any operator- or operator-reachable channel | — | ✗ **NOT WIRED** | Not the durable row, not `__cause__`, not `__context__`, not a log. |
| durable `state='running'` | Overview safety surface | `compose_active_exceptions` | ✗ NOT WIRED | Only `failed` is promoted; a wedged job reaches the Pipeline card but never the safety surface. |
| `JobHealthBookkeepingError` | any handler in `dashboard/` | — | ✗ NOT WIRED | Three references repo-wide: the class and two raises. |
| gap row `reason` → exception kind; per-row `open`; one bounded population | pipeline gaps projection | unchanged from round 2 | ✓ WIRED | All six shapes re-reproduced. |

### Data-Flow Trace (Level 4)

| Artifact | Data variable | Source | Produces real data | Status |
| --- | --- | --- | --- | --- |
| Services table — latency cell | `service.latency_ms` | `probe_latency_ms` when online, `None` otherwise | Renders the failure class when absent | ✓ **FLOWING** *(was FABRICATED)* |
| Services table — state duration | `service.state_duration_seconds` | `now - state_since`, `None` when unknown | Renders `Unknown duration` when absent | ✓ **FLOWING** *(was FABRICATED)* |
| Service detail — collection-gap evidence | `service.collection_gaps` | joined from the matching `('service', port)` stream's own gaps | Yes | ✓ **FLOWING** *(was HOLLOW_PROP)* — with the state conflation noted |
| Services table — status / criticality / tags / health rule | `snapshot.services[*]` | services + meta + latest checks | Yes | ✓ FLOWING |
| Host renderer, exception cards, streams/pending/gaps regions | — | unchanged | Yes | ✓ FLOWING |
| Pipeline job health | `pipeline.jobs[*].state` | `background_job_health` durable rows | The row itself is false on the compound path | ✗ **FALSE AT SOURCE** |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Full workspace suite (run once) | `uv run --project dashboard python -m pytest -q` | 288 passed, 395 subtests passed in 85.86s | ✓ PASS |
| Offline service renders its failure class | real browser, production route, real DB | `ConnectionRefused` | ✓ PASS |
| Unknown service renders no number | real browser | `Unknown`, matches no digit | ✓ PASS |
| A genuine `0` latency still renders `0 ms` | real browser | `0 ms` | ✓ PASS |
| Unknown state duration renders `Unknown duration` | real browser | `Unknown duration` | ✓ PASS |
| Ascending latency sort ranks unmeasured last | real browser | `6060, 8080, 9090, 7070` | ✓ PASS |
| No serialized container in operator copy | real browser, whole services table | `[]` (no matches) | ✓ PASS |
| Per-service gap evidence is real | real browser | `1 gap (1 open)` / `1 gap (0 open)` | ✓ PASS |
| `absent` distinguishable from clean | real browser | both render `No gap evidence` | ✗ FAIL |
| Sort + aria-sort survive a real automatic poll | real browser, 15 s wait | unchanged | ✓ PASS |
| All six prior gap shapes | production route repro | identical to round 2 | ✓ PASS |
| Succeeded callback never records durable `failed` | fault injection | row `running`, no exception | ✓ PASS |
| Failed callback's cause survives a failing outcome write | fault injection | erased from every channel | ✗ FAIL |
| Named phase regressions | `pytest -k` (8 browser, 2 worker) | 8 + 2 passed, 55 subtests | ✓ PASS |
| Module-order independence (5 permutations) | `pytest` module pairs | all green in both orders | ✓ PASS |
| `finiteMeasurement` against non-numeric inputs | `node -e` on the shipped implementation | `' '`, `[]`, `false` → `0` | ⚠️ WARNING (unreachable from this server) |

### Probe Execution

No `scripts/` directory exists in this repository and no plan declares a probe path. Step 7c: SKIPPED (no probes declared or conventional).

### Requirements Coverage

All six phase requirement IDs are claimed by at least one plan. This round: 03-11 (DIA-03), 03-12 (TEL-06), 03-13 (TEL-06, DIA-03), 03-14 (all six as a record action). No orphaned Phase 3 requirements in REQUIREMENTS.md — `grep '| Phase 3 |'` returns exactly six rows.

| Requirement | Status | Recorded now | Should stand at | Evidence |
| --- | --- | --- | --- | --- |
| TEL-06 | ✗ BLOCKED | `Gaps Found` | **`Gaps Found`** — correct, do not promote | Retention, resolution, pressure, worker freshness and collection gaps all re-reproduced truthful. **Background-job health is not**: B5 leaves a genuinely failed job durably recorded as `running` with its cause erased. Two clauses of TEL-06's own text (collection gaps, background-job health) carry open defects. |
| DIA-01 | ✓ SATISFIED | `Complete` | **`Complete`** — correct | Production asset routes plus theme continuity; named tests executed and passed. |
| DIA-02 | ✓ SATISFIED | `Complete` | **`Complete`** — correct | Full host projection with its own freshness exception; untouched this round; suite green. |
| DIA-03 | ✓ **SATISFIED** | `Gaps Found` | **`Complete`** — **promote** | Every field the requirement enumerates — status, latency *or* failure class, state duration, criticality, tags, effective health rule — reproduced rendering from the durable payload in a real browser through the production route. The `03-UI-SPEC.md:118` contract is honoured. Per-service gap evidence is **not** part of DIA-03's enumerated text; gap 2 lands on TEL-06. |
| DIA-08 | ⚠️ PARTIALLY SATISFIED | `Gaps Found` | **open — but as a *deferral*, not a gap** | Everything Phase 3 owns is verified: effective settings project real values, presentation/refresh/filter preferences are local-only and survive refresh, the endpoint is GET-only and effect-free. The `range` clause of the requirement's own text is undelivered and belongs to Phase 4. `Gaps Found` is not false, but it mislabels a deferral; the table has no `Deferred` value, so leave the cell and rely on this row. **Do not write a Phase 3 closure plan for DIA-08.** |
| UX-02 | ✓ SATISFIED | `Complete` | **`Complete`** — correct | `beacon-theme` persisted, scroll consumed exactly once, behaviorally tested. |

#### Resolving the previous report's self-contradiction (as 03-14 requested)

03-14's `<attribution_audit>` correctly identified that the previous VERIFICATION.md said two different things. Its frontmatter `missing` list specified "TEL-06, DIA-03, DIA-08 unchecked"; its closing narrative said "TEL-06 / DIA-01 / DIA-02 / DIA-08 / UX-02 satisfied, DIA-03 blocked". 03-14 resolved in favour of the frontmatter and was right to, but the deeper resolution is that the two statements were on **different axes** and the report never said so:

- **TEL-06.** No genuine ambiguity — the narrative was simply wrong. It recorded TEL-06 satisfied while the same report filed a `partial` gap against background-job health, a clause TEL-06's own text enumerates, and dismissed it as "a warning, not an absence of the capability". A requirement is not satisfied because one of its clauses fails only sometimes. TEL-06 was open then and is open now, for a reason that has since become sharper.
- **DIA-08.** Genuine ambiguity, both halves true on different axes. *Capability axis:* everything Phase 3 owns is delivered and verified — the narrative was right. *Record axis:* the requirement's text names a `range` clause that Phase 3 does not deliver — the frontmatter was right. The record status must stay open; the reason is deferral to Phase 4, not a Phase 3 defect.

For the next round, unambiguously: **TEL-06 open (gaps). DIA-03 promote to Complete. DIA-08 open (deferral, Phase 4 — not a gap, no closure plan). DIA-01, DIA-02, UX-02 Complete.**

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `dashboard/beacon/worker_main.py` | 335-341 | Error swallowed by variable shadowing; `raise ... from exc` binds the wrong exception | 🛑 BLOCKER | A genuine callback failure is erased from the durable row, the exception chain and the log at once. |
| `dashboard/beacon/worker_main.py` | 240-256, 444-486 | A named, documented exception with zero handlers, escaping a `try` that catches only `KeyboardInterrupt`/`SystemExit` | ⚠️ WARNING | A transient lock on the S1/S2/S3 bookkeeping write terminates the worker before the scheduler is built. Not a regression. |
| `dashboard/beacon/worker_main.py` | 296-302 | The `started` write gates the work; a bookkeeping failure vetoes the callback | ⚠️ WARNING | Under sustained write contention, bookkeeping alone can starve the heartbeat that holds the lease. Carried from round 1, unfixed, now commented. |
| `dashboard/beacon/worker_main.py` | 330 | Log message asserts "recording callback failure" on a branch now reached for `succeeded` | ⚠️ WARNING | An operator-facing claim contradicted by the transition being written — the phase's own defect class, one layer down. |
| `dashboard/advanced.js` | 266 | Two distinct server states collapsed into one operator string | ⚠️ WARNING | An unmonitored service reads as a clean bill of health. Filed as gap 2. |
| `dashboard/advanced.js` | 71-75 | `finiteMeasurement` treats `' '`, `[]` and `false` as the measurement `0` | ⚠️ WARNING | Verified in node against the shipped implementation. Unreachable from this server (`latency_ms`, `state_duration_seconds`, `count`, `open_count` are `int` or `None`), so latent — but this helper is now the single absent-value rule for the whole surface. |
| `dashboard/beacon/diagnosis.py` | 384 | `item.get('open')` without an `isinstance` guard, inside an otherwise fully defensive normaliser | ⚠️ WARNING | A non-dict item would `AttributeError` into the request path, which catches only `MaintenanceBusy` and `OperationalError` → unparseable HTML 500. Not reachable from the composer, which builds only dicts. |
| `tests/test_advanced_diagnosis_api.py` | `test_outcome_paths_survive_the_bookkeeping_split` | Four outcomes covered independently, never in combination | ⚠️ WARNING | The exact reason the compound erasure survived the round that created it. |
| `tests/test_advanced_ui.py` | gap-evidence `expected` map | A test that pins a defect shut | ⚠️ WARNING | Ports 9002 (`absent`) and 9003 (`complete`) assert the same literal. |

**Debt-marker gate: PASS.** No `TBD`, `FIXME`, `XXX`, `HACK`, `TODO` or `PLACEHOLDER` in any of the five files this round modified. All DOM writes remain `textContent`/`replaceChildren`; no mutation or remote-control affordance was introduced; `JobHealthBookkeepingError`'s message carries only a fixed callback id, a literal transition, and `type(exc).__name__[:96]`.

**Acknowledged plan defect, not a code defect:** 03-13's acceptance criterion `grep -c 'gap_evidence_truncated' == 1` is unsatisfiable given the wiring the same plan requires (one producer at `diagnosis.py:316`, one consumer at `diagnosis.py:352` = 2). The executor left the code correct and reported it. Confirmed and not counted against the phase.

### Unverified Prohibitions (human review recommended)

Five judgment-tier prohibitions, no automated enforcement wired for any of them. The verdicts below are **non-authoritative LLM-judge assessments**, flagged for human review rather than counted as green. Two changed verdict this round — one in each direction.

| Source | Prohibition (abbreviated) | Round 2 | Round 3 | Basis |
| --- | --- | --- | --- | --- |
| 03-08 | Every operator-facing label derivable from its durable row | ⚠️ VIOLATED | ✓ **UPHELD** | The `0 ms` / `0 seconds` fabrications are gone at all three sites; gap evidence is joined from durable rows. Reproduced. |
| 03-08 | Narrowing false positives must never suppress a genuine failure | ✓ UPHELD | ⚠️ **VIOLATED** | Upheld on collection gaps (re-reproduced). Violated on job health: 03-12 narrowed the false positive and removed the last channel carrying a real failure, proven by construction. |
| 03-09 | Refresh must not override an operator choice; no placeholder as primary safety evidence | ✓ UPHELD | ✓ UPHELD | Re-reproduced in a real browser after this round edited the same sort key. |
| 03-10 | Test scaffolding must not make greenness order-dependent | ✓ UPHELD | ✓ UPHELD | Re-tested across five module permutations after ~665 new test lines. |
| 03-10 | Never record complete on an implementation claim | ⚠️ VIOLATED | ✓ **UPHELD** | 03-14 promoted only what was verified and explicitly deferred DIA-03/TEL-06 to this pass. The record now under-credits. |

### Human Verification Required

#### 1. Real-hardware collection-health trust

**Test:** On the target Pi, open `/advanced` while a real collection gap is active and while host evidence is stale.
**Expected:** The workspace shows the open gap and the stale host as real, correctly labelled exceptions — and shows no resolved or retention-expired interval as an open actionable gap.
**Why human:** Carried forward from both previous reports and re-declared by 03-14-PLAN.md's own human-check block. The synthetic reproductions above establish the server contract; only a person on the hardware can establish that it reads correctly to them.

### Gaps Summary

Two of the three gaps are genuinely closed, and the first is closed thoroughly. The Services surface no longer invents measurements: I built a real database, served it through the production Flask app, and read the rendered cells out of real Chromium. An offline service shows `ConnectionRefused` where it used to show `0 ms`; an unknown service shows `Unknown` and matches no digit; a state duration the server never established shows `Unknown duration`; an ascending latency sort ranks unmeasured services last and a descending one ranks them first; and — the detail that shows the fix was made to a rule rather than to a symptom — a service with a genuine `0 ms` measurement still reads `0 ms`. Per-service collection-gap evidence is now joined from each service's own durable stream and rendered as a sentence, and a scan of every node in the services table for a serialized container returns nothing. The record in REQUIREMENTS.md is reconciled, under-credits rather than over-credits, and 03-14 correctly refused to promote its own work. All six collection-gap shapes from round 2 re-reproduce unchanged, so nothing in the round broke what the round before it fixed.

Gap B is the exception, and it did what the orchestrator suspected: it moved. The half the plan was written against is really fixed — with the work returning True and the `succeeded` write raising, the durable row is now `running` instead of `failed` and no `job_failed` card is composed. But the same restructuring created the mirror defect on the adjacent path. When the callback raises *and* the outcome write then fails, the genuine error is stashed in `work_error`, the write error is raised in its place, `from exc` binds the write error to both `__cause__` and `__context__`, no durable row is written, and nothing logs it. I confirmed the work error is absent from every one of those channels, and — because this determines whether it is a defect or a regression — I confirmed the mechanism: before 03-12 the `failed` write happened *inside* an `except` block, so Python's implicit chaining kept the real cause in `__context__`, where APScheduler's `exc_info=True` would have printed it. Moving the error into a local variable removed that. The edit that stopped a bookkeeping failure from masquerading as a work failure also stopped a work failure from being visible at all. That is the phase's own standing prohibition — *do not suppress a genuine failure while narrowing false positives* — and it is the second time in this phase that a correct narrowing has produced a silent surface.

The second gap is smaller and newer. 03-13's server work is careful: four completeness literals, each derived from a durable truncation flag, with only a literal `False` allowed to produce `absent`. The client then throws one of those distinctions away. `absent` means the stream list is complete and contains no stream for this service — the pipeline has no record of ever observing it, which happens to a newly discovered service before its first persisted probe and to any service probed while storage pressure suppresses persistence. That service and a fully collected, genuinely clean one produce the identical string `No gap evidence`, and the round's own browser regression asserts both, pinning the conflation shut. On the one surface this phase exists to make honest, an absence of collection should not read as a clean bill of health.

Neither remaining gap is large. The first is a chained exception, a log line, and one promotion rule; the second is one string and one split assertion. What they have in common is the pattern this phase keeps producing: a fix is made correctly at the site it was aimed at, and the same edit leaves an adjacent path quieter than it found it. The closure worth asking for is not more code but the missing test — a raising callback whose outcome write also fails, and an `absent` service asserted separately from a clean one.

On promotion, which the code plans deliberately left to this pass: **DIA-03 is satisfied and should move to `Complete`** — every field its text enumerates was reproduced rendering from a durable payload in a real browser. **TEL-06 is not** — two clauses of its own text still carry open defects. **DIA-08 stays open as a deferral to Phase 4, not as a gap**, and no closure plan should be written for it.

---

_Verified: 2026-08-19T06:54:41Z_
_Verifier: Claude (gsd-verifier)_
