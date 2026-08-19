---
phase: 03-advanced-current-diagnosis
verified: 2026-08-19T10:03:43Z
status: gaps_found
score: 3/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
unverified_prohibitions: 5
re_verification:
  round: 4
  previous_status: gaps_found
  previous_score: 3/4
  gaps_closed:
    - "Round-3 Gap 2 — Per-service collection-gap evidence. Closed and independently reproduced closed: `advanced.js:291-292` now gives `absent` its own sentence ('No collection stream established for this service') while `complete`-with-zero keeps 'No gap evidence', and `test_service_detail_gap_evidence_reads_as_operator_copy` asserts the two as unequal by port with a dedicated `assertNotEqual(rendered[9002], rendered[9003])` rather than pinning them equal. Run by this verifier: 2 passed, 8 subtests."
  gaps_partially_closed:
    - "Round-3 Gap 1 — Background-job health. Four of its six `missing` items are genuinely closed and were reproduced closed. The remaining two were implemented in a shape that introduces new operator-facing untruths, so the gap stays open in a different form."
  regressions:
    - "dashboard/beacon/diagnosis.py:425-443 — 03-15's new `job_outcome_unrecorded` promotion derives an expected *duration* from a poll *interval*. Reproduced end-to-end through the real `dispatch_callback`: a J6 preview still running nine seconds into its own work is promoted to the operator as `job_outcome_unrecorded`. J6's shipped cadence is 2 s, so its threshold is 8 s; a Chromium screenshot on Pi hardware routinely exceeds that. J1's threshold is 20 s, shorter than the 30 s `flock` wait `connect_db` is allowed to block for (`db.py:76`). This defect did not exist before this round."
  newly_found:
    - "dashboard/beacon/worker_main.py:324-327 — `dispatch_callback` maps a callback's `False` return to durable `state='failed'`, `error_class='CallbackReturnedFalse'`, but the two production queue pollers return `False` as their *normal idle* result. Reproduced against the real `worker_process_scan_requests` / `worker_process_preview_requests` adapters: an idle Pi permanently shows two fabricated `Background job failed` cards. NOT a round-4 regression — `git log -S 'result is False'` dates the mapping to `7044313 feat(03-02): persist worker callback outcomes`. It has been reachable in production through all three previous verification rounds and was missed by each."
  over_credit_corrected:
    - "The round-3 report reproduced this exact shape as `B3  work returns False -> row ('failed','CallbackReturnedFalse'), job_failed card  control OK` and recorded it as a passing control. The mapping was only ever exercised against a synthetic callback, never against what the two real queue pollers return, so the reproduction confirmed the code did what the code says rather than whether what it says is true. `test_callback_outcome_false_and_exception_never_claim_success` pins the same mapping and passes. The defect is stated here at the severity the reproduction supports."
gaps:
  - truth: "Background-job health reported to the operator reflects what the job actually did."
    status: failed
    reason: "Three independently reproduced operator-facing untruths on the background-job-health surface, two of them reachable on a healthy idle Pi within seconds of worker start. (1) FABRICATED FAILURE: driving the real `appmod.worker_process_scan_requests` and `worker_process_preview_requests` against an empty durable queue yields `DURABLE ROWS: {'J5': ('failed','CallbackReturnedFalse',None), 'J6': ('failed','CallbackReturnedFalse',None)}` and `OPERATOR EXCEPTIONS: [job_failed J5, job_failed J6]`. Both pollers return `False` to mean 'the queue was empty', which is a completed poll, not a fault. `advanced.js:221-236` renders every exception with a count, so an idle Pi permanently reads '2 active exceptions — Background job failed — J5 / — J6', `last_success_ts` stays NULL forever, and the cards never clear because the next tick rewrites the same row. (2) FABRICATED IN-PROGRESS FAULT: reproduced through the real `dispatch_callback` with the work still executing — the durable row reads `('running', 1700000000)` and `compose_active_exceptions` at start+9 emits `[{'kind':'job_outcome_unrecorded','job_id':'J6'}]`. The `started` transition commits in its own `write_transaction` before the work runs, so the row genuinely reads `running` for the whole duration, and `4 * cadence` resolves to 8 s for J5/J6 and 20 s for J1 against a 180 s discovery timeout and a 30 s `connect_db` flock wait. (3) INVISIBLE GENUINE FAILURE: reproduced through the real `run_worker` — S1's `recover_worker_state` raising while its `failed` write also raises leaves `durable rows: {'S1': ('running', None)}`, `operator exceptions for S1: []`, the scheduler built and started, and the catch-site warning naming only `error_class=OperationalError`. `callback_schedule_evidence` returns `cadence_seconds=None` for every non-`interval` trigger, so S1/S2/S3/J9 can never be promoted by the new kind — the promotion 03-15 added covers everything except the paths the same round's handler swallows."
    artifacts:
      - path: "dashboard/beacon/worker_main.py"
        issue: "Lines 324-327: `if result is False: transition, error_class = 'failed', 'CallbackReturnedFalse'` infers a verdict from a return value that already means 'no work available' for the two callbacks dispatched every 2 seconds. Origin `7044313 feat(03-02)`; not new this round."
      - path: "dashboard/app.py"
        issue: "Lines 1803-1804 and 1959-1960: `if not claim: return False` in `worker_process_scan_requests` and `worker_process_preview_requests` — the normal idle result. `worker.py:34-35` wires exactly these two adapters into production. `_legacy_do_uptime_check` adds a third reachable case when `_uptime_lock` is held and J3/J4 overlap on `ThreadPoolExecutor(2)`."
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Lines 425-443: `max(0, now - job['last_started_ts']) > 4 * job['cadence_seconds']` treats a poll interval as an upper bound on run duration. Resolved thresholds printed from the shipped inventory: J5 8 s, J6 8 s, J1 20 s, J2 20 s, J4 240 s, J3 1200 s, J8 14400 s, J7 345600 s."
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Lines 180-198: `callback_schedule_evidence` returns `cadence_seconds=None` for every non-`interval` trigger, so `type(job.get('cadence_seconds')) is int` is False for S1, S2, S3 and J9. Verified against the shipped inventory: an S1 wedged at `running` for 24 hours promotes nothing."
      - path: "dashboard/beacon/worker_main.py"
        issue: "Lines 499-514: the startup handler catches `JobHealthBookkeepingError` from both raise sites but reads only `bookkeeping_error.error_class`. It ignores `work_error_class` — the field 03-15 added in the same round specifically so a genuine work failure would remain recoverable at the catch site — and continues to `build_scheduler`. The work error is logged at ERROR by `dispatch_callback:355-361`, so the log channel is intact; the operator-facing surface shows nothing."
      - path: "tests/test_advanced_diagnosis_api.py"
        issue: "`test_callback_outcome_false_and_exception_never_claim_success` pins the `False -> failed` mapping against a synthetic `collect_system_stats`, never against the real queue pollers. `test_a_job_stuck_without_an_outcome_becomes_an_operator_exception` asserts `running_inside_its_cadence_window_promotes_nothing` only at `cadence=60`, never at a cadence smaller than the work it gates, and pins `absent_cadence_promotes_nothing` without recording that it exempts the swallowed startup paths. `test_startup_survives_a_bookkeeping_failure` covers only the `started`-write failure, where the work is skipped. All four run green while all three defects are live."
    missing:
      - "Stop overloading `False`. Give an empty durable queue its own outcome vocabulary — have `worker_process_scan_requests` and `worker_process_preview_requests` return `None` or a sentinel for 'no work available' and reserve `False` for a genuine refusal — so an idle poll records `succeeded`, not `failed`."
      - "Add a regression that drives the REAL adapters against an empty queue and asserts `compose_active_exceptions` emits no `job_failed` for J5 or J6. The existing synthetic-callback test is what let this survive three verification rounds."
      - "Replace `4 * cadence_seconds` with a boundary no legitimate run can plausibly cross, floored above the lock waits the callback may block on (`connect_db` holds a 30 s flock wait and a 30 s busy_timeout; discovery has a 180 s timeout): `> max(UNRECORDED_OUTCOME_FLOOR_SECONDS, 4 * cadence)`."
      - "Add subtests for `cadence_seconds=2` with a nine-second-old start (must promote nothing) and a heartbeat blocked 25 s behind the maintenance lock (must promote nothing)."
      - "Give startup callbacks a promotable boundary so a wedged S1/S2/S3/J9 is actionable rather than merely readable — a `None` cadence must not silently exempt a job from the promotion built to catch it."
      - "Distinguish the two conditions at the `run_worker` catch site: when `bookkeeping_error.work_error_class is not None` the startup work itself failed and its outcome could not be recorded, so continuing runs Beacon on state nothing confirmed. Re-raise, or surface it durably; do not downgrade it to a warning that does not name it."
      - "Add a compound startup regression: an S1 whose work raises AND whose `failed` write raises must not reach `build_scheduler` unnoticed."
deferred:
  - truth: "Operator can change supported *range* preferences in the advanced workspace (the `range` clause of Success Criterion 4 and of DIA-08's requirement text)."
    addressed_in: "Phase 4"
    evidence: "Phase 4 success criterion 1: 'Operator can choose shared ranges from one hour through 90 days or a validated custom range within retained history.' Re-confirmed against ROADMAP.md this round. No range control exists in advanced.html; the preference controls present are refresh interval (line 17), pause/refresh (18-19), search and four filters (52-57), clear filters, reset order and collapse details (57-59). Phase 3 is scoped to current diagnosis. Carried forward from round 3 unchanged — a deferral, not a gap, and no closure plan should be written for it."
human_verification:
  - test: "On the target Pi, open /advanced while a real collection gap is active and while host evidence is stale."
    expected: "The workspace shows the open gap and the stale host as real, correctly labelled exceptions — and shows no resolved or retention-expired interval as an open actionable gap."
    why_human: "Carried forward from all three previous reports and re-declared as human judgment in 03-08-SUMMARY.md and in 03-14-PLAN.md's own human-check block. Operator trust in the rendered snapshot on real hardware cannot be asserted programmatically. Collected at the end-of-phase human checkpoint."
  - test: "On the target Pi, start the worker and leave the system idle for one minute, then open /advanced and read the Overview 'Active exceptions' region."
    expected: "No 'Background job failed' card for J5 or J6. An idle system has no failed background jobs."
    why_human: "The synthetic reproduction below establishes this on a real database through the real production adapters; this confirms it on the operator's actual hardware once the fix lands. Recorded so the gap-closure round cannot declare success without it."
prohibitions:
  - source: "03-08-PLAN.md"
    statement: "MUST NOT present resolved, retention-expired, or otherwise inferred evidence to the operator as a current, open, actionable fault -- every operator-facing open/actionable/kind label must be derivable from the durable row it describes, never from a neighbouring row or a stream-level fact."
    verification: judgment
    llm_judge_verdict: violated
    flagged: true
    previous_verdict: upheld
    detail: "Still UPHELD on the two surfaces it was written for — the collection-gap projection and the services surface were re-checked and are unchanged (7 gap/vocabulary tests, 25 subtests, green; the round's only edits to `advanced.js` are `finiteMeasurement` and the gap-evidence copy, both covered by named browser regressions run here). VIOLATED on background-job health, on both new counts. `Background job failed — J5` is a fault inferred from a return value that means 'no work available'; `Background job outcome not recorded — J6` is a fault inferred from a poll interval while the work is legitimately still executing. Both reproduced."
  - source: "03-08-PLAN.md"
    statement: "MUST NOT suppress a genuine collection failure while narrowing false positives -- restricting promotion by reason must never cause a real collection_gap, or a reason value the code does not recognise, to go unreported to the operator."
    verification: judgment
    llm_judge_verdict: violated
    flagged: true
    previous_verdict: violated
    detail: "UPHELD on the collection-gap surface (re-checked green). The round-3 erasure is genuinely CLOSED and was reproduced closed: `worker_main.py:335-361` carries `work_error_class`, chains `from work_error`, and logs the work failure at ERROR before raising — my run shows `work_error_class=StartupWorkBlewUp write_error_class=OperationalError`. But a genuine startup work failure still reaches the operator as nothing at all: durable row `running`, zero promoted exceptions, scheduler started. The erasure moved from the exception chain to the operator surface rather than being removed."
  - source: "03-09-PLAN.md"
    statement: "MUST NOT let automatic background refresh silently override an operator's explicit presentation choice, and MUST NOT present a machine identifier or a placeholder as the operator's primary safety evidence when the server supplied real evidence."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "This round's `advanced.js` diff is 30 lines confined to `finiteMeasurement` and `formatServiceGapEvidence`, plus one new `EXCEPTION_COPY` entry for `job_outcome_unrecorded` that is real operator copy, not a placeholder or an identifier. Sort persistence and the refresh loop are untouched. `test_unmeasured_latency_and_duration_never_rank_or_read_as_zero` and the gap-evidence browser regression both pass here."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT let test scaffolding mutate process-global state so that suite greenness depends on execution order."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "~440 new test lines this round. Every replacement of `worker_main._write_job_health_transition` is paired with an `addCleanup(setattr, worker_main, '_write_job_health_transition', real_write)` registered before the assignment; the four worker module globals are reset through `_reset_worker_globals` registered via `addCleanup`; the scheduler is replaced with `mock.patch.object`. Full suite measured green by the orchestrator (294 passed / 406 subtests) and the prior-phase regression subset green (221 passed / 254 subtests)."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT record a requirement, plan, or phase as complete on the strength of an implementation claim rather than independent verification -- the traceability table is the project's own memory of what is actually true."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "Verified independently: `git log -3 -- .planning/REQUIREMENTS.md` shows the file last touched by `b3879f3`, before this run. Neither 03-15 nor 03-16 promoted TEL-06, and both summaries stop short of claiming it. ROADMAP.md still shows Phase 3 unchecked. The record under-credits rather than over-credits, which remains the correct failure direction. TEL-06 is NOT promoted here either — see Requirements Coverage."
---

# Phase 3: Advanced Current Diagnosis Verification Report

**Phase Goal:** The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.

**Verified:** 2026-08-19T10:03:43Z
**Status:** gaps_found
**Re-verification:** Yes — round 4, after gap-closure plans 03-15 and 03-16.

This report supersedes the round-3 `03-VERIFICATION.md` and preserves the requirement-status history it
established. Nothing below is taken from a SUMMARY or from `03-REVIEW.md`. Every claim is either a line
of code I read or a command I ran in my own process. The review's three blockers were re-derived from
the shipped code independently; where my finding differs from the reviewer's, the difference is stated.

## Gap-Closure Outcome (03-15 / 03-16)

| Round-3 gap | Claimed | Verifier result | How I established it |
| --- | --- | --- | --- |
| **1** — Background-job health (`partial`) | Closed by 03-15 | ✗ **STILL OPEN, AND WORSE** | Ran the real production adapters and the real `run_worker` against a real SQLite database. Four of six `missing` items are genuinely closed. The two that were not produced one new reachable false positive and left the swallowed path unpromotable. A third, older defect on the same surface surfaced during the check. |
| **2** — `absent` vs collected-and-clean (`partial`) | Closed by 03-16 | ✓ **CLOSED** | Read `advanced.js:264-292` and ran the browser regression myself. The two states now carry two sentences and the test asserts them unequal by port rather than pinning them equal. |

### Round-3 Gap 1, item by item

| `missing` item | Status | Evidence |
| --- | --- | --- |
| Carry `work_error_class` and chain from the work error | ✓ CLOSED | `worker_main.py:352-361`. My `run_worker` reproduction raised the condition carrying `work_error_class=StartupWorkBlewUp`. |
| Log the work error at error level, class only | ✓ CLOSED | `worker_main.py:355-361`. Captured line: `Beacon worker could not record a callback failure; reporting the work failure here: callback=S1 transition=failed work_error_class=StartupWorkBlewUp write_error_class=OperationalError`. No message text leaks. *(The reviewer's CR-03 states the work failure has no channel at all; that half is overstated — the log channel is intact. The operator-facing half of CR-03 holds.)* |
| Correct the lease-loss log line | ✓ CLOSED | `worker_main.py:329-334` now names the transition instead of asserting a failure. |
| Add the compound regression | ✓ CLOSED | `test_a_failed_callback_survives_a_failing_outcome_write` exists, asserts on the object graph via a `reachable()` chain walk, and passes here. |
| Promote a job whose outcome was never recorded | ✗ DEFECTIVE | Present as `job_outcome_unrecorded`, but fires on work that is merely still running and cannot fire for the startup callbacks at all. Reproduced both ways. |
| Decide what `run_worker` does with `JobHealthBookkeepingError` | ✗ WRONG DECISION | A handler exists and swallows a compound work-plus-write failure, ignoring the `work_error_class` the same round added for exactly this catch site. Reproduced. |

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Operator can open the dedicated advanced page from the dashboard and return without losing theme. | ✓ VERIFIED | Untouched by this round — `git diff b3879f3..HEAD -- dashboard/` covers only `advanced.js`, `diagnosis.py`, `worker_main.py`. Behavior-dependent (a state transition), so proven by named test rather than presence: `test_theme_or_return_round_trip_preserves_theme_and_consumes_scroll_once` and `test_production_routes_serve_the_advanced_document_bundle` run green here. |
| 2 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, and host freshness. | ✓ VERIFIED | Untouched. `renderHost` (`advanced.js:303-318`) reads all eight fields from the server payload; `test_host_tracer_returns_one_current_snapshot_with_server_freshness` green here. Host block carried live evidence in every reproduction below. |
| 3 | Operator can inspect every current service's status, latency or failure class, state duration, criticality, tags, and effective health rule. | ✓ VERIFIED | Round-3's full-stack browser reproduction stands; this round's only edits to the surface are `finiteMeasurement` (now a type rule) and the gap-evidence copy. Both are covered by named browser regressions I ran: `test_unmeasured_latency_and_duration_never_rank_or_read_as_zero` and `test_service_detail_gap_evidence_reads_as_operator_copy` (2 passed, 8 subtests). A genuine `0` still renders `0 ms`; no serialized container reaches the operator. |
| 4 | Operator can view truthful retention, resolution, database pressure, worker freshness, **collection gaps**, and **background-job health**, and change presentation/refresh/filtering preferences without remote controls. | ✗ **FAILED** | Five of six clauses re-checked truthful, including all collection-gap shapes (7 tests / 25 subtests green) and the no-remote-controls clause (`advanced.js` makes exactly one network call: `fetch('/api/advanced/current', {cache:'no-store'})` — a GET). **Background-job health is not truthful, on three counts, all reproduced below.** |

**Score:** 3/4 roadmap success criteria verified (0 present-but-behavior-unverified).

> **On Success Criterion 4.** This is the third consecutive round in which the background-job-health
> clause of SC4 has not held. It is not the same defect each time: round 3 found a genuine failure
> erased from the exception chain, and that erasure is now genuinely fixed. What round 4 finds is that
> the remedy introduced a new false positive, and that the oldest defect on this surface — one that has
> been live in production since 03-02 and that the round-3 report explicitly recorded as a passing
> control — makes an idle Pi permanently report two failed jobs. A criterion that names six things is
> not satisfied when one of them lies, and it is not satisfied more the fourth time.

### Reproduction Evidence (verifier-executed)

Every block below is output from a command I ran, against a real SQLite database created by the
project's own `tests.helpers.load_app`, through production code paths. Scripts are re-runnable.

#### 1. An idle Pi permanently reports two background jobs as failed

Driving the **real** production adapters (`appmod.worker_process_scan_requests`,
`appmod.worker_process_preview_requests`, the exact two `dashboard/worker.py:34-35` wires in) through
the **real** `dispatch_callback` against an **empty** durable queue:

```
J5 real adapter return on empty queue: False
J6 real adapter return on empty queue: False
DURABLE ROWS: {'J5': ('failed', 'CallbackReturnedFalse', None),
               'J6': ('failed', 'CallbackReturnedFalse', None)}
OPERATOR EXCEPTIONS: [{'kind': 'job_failed', 'section': 'pipeline', 'priority': 6, 'job_id': 'J5'},
                      {'kind': 'job_failed', 'section': 'pipeline', 'priority': 6, 'job_id': 'J6'}]
```

`app.py:1803-1804` and `1959-1960` are both `if not claim: return False` — the empty-queue result.
J5 and J6 are `interval` jobs at 2 seconds, so this state is re-established every 2 seconds for as long
as the Pi is idle. `advanced.js:221-236` renders every exception plus a count, so the Overview reads
`2 active exceptions` / `Background job failed — J5` / `Background job failed — J6`, permanently, with
`last_success_ts` NULL forever.

**Provenance.** `git log -S "result is False" -- dashboard/beacon/worker_main.py` returns exactly one
commit: `7044313 feat(03-02): persist worker callback outcomes`. This is not a round-4 regression. It
has been reachable through three verification rounds, and round 3 reproduced the same shape and filed it
as `B3 ... control OK` because the reproduction used a synthetic callback rather than the real pollers.

#### 2. The new promotion fires on work that is legitimately still running

Resolved thresholds, printed from the shipped `WORKER_CALLBACK_INVENTORY` through the shipped
`callback_schedule_evidence`:

```
J1  trigger=interval  cadence=5      threshold=20
J2  trigger=interval  cadence=5      threshold=20
J3  trigger=interval  cadence=300    threshold=1200
J4  trigger=interval  cadence=60     threshold=240
J5  trigger=interval  cadence=2      threshold=8
J6  trigger=interval  cadence=2      threshold=8
J8  trigger=interval  cadence=3600   threshold=14400
S1  trigger=None      cadence=None   threshold=NEVER PROMOTED
S2  trigger=None      cadence=None   threshold=NEVER PROMOTED
S3  trigger=None      cadence=None   threshold=NEVER PROMOTED
J9  trigger=date      cadence=None   threshold=NEVER PROMOTED
```

End-to-end through the real `dispatch_callback`, reading the durable row and composing exceptions from
**inside** the still-executing work:

```
J6 durable row while its work is still running : ('running', 1700000000)
Operator exceptions 9s into a 2s-cadence J6 run: [{'kind': 'job_outcome_unrecorded', 'job_id': 'J6'}]
```

The `started` transition commits in its own `write_transaction` before the work is invoked, so the row
genuinely reads `running` for the entire duration. J6 drives Chromium through `_refresh_service_preview`;
J5 runs a claimed discovery scan with a `DISCOVERY_TIMEOUT_SECONDS` default of **180**. Both routinely
exceed an 8-second threshold whenever they find work. Direct projection checks:

```
J6 running  9s, cadence 2    -> [{'kind': 'job_outcome_unrecorded', 'job_id': 'J6'}]
J1 running 25s, cadence 5    -> [{'kind': 'job_outcome_unrecorded', 'job_id': 'J1'}]
S1 wedged  24h, cadence None -> []
```

The J1 line matters because `connect_db` (`db.py:76-81`) holds a shared `flock` wait of **30 s** and a
`busy_timeout` of **30 s**. Any maintenance window longer than 20 s promotes the heartbeat as
"outcome not recorded" while it is simply waiting for a lock.

#### 3. A genuine startup work failure reaches the operator as nothing

Through the real `run_worker`, with S1's `recover_worker_state` raising **and** the `failed` write
raising:

```
writes attempted            : [('S1','started',None), ('S1','failed','StartupWorkBlewUp'),
                               ('S2','started',None), ('S2','succeeded',None),
                               ('S3','started',None), ('S3','succeeded',None)]
exception escaped run_worker: None
scheduler built+started     : True
later startup work ran      : ['heartbeat', 'metrics']
worker log lines mentioning S1:
   [ERROR]   ... reporting the work failure here: callback=S1 transition=failed
             work_error_class=StartupWorkBlewUp write_error_class=OperationalError
   [WARNING] Beacon worker could not record a startup job; continuing startup:
             callback=S1 error_class=OperationalError
durable rows                : {'S1': ('running', None), 'S2': ('succeeded', None), 'S3': ('succeeded', None)}
operator exceptions for S1  : []
S1 pipeline job row         : {... 'cadence_seconds': None, 'state': 'running',
                                'last_success_ts': None, 'error_class': None ...}
```

`recover_worker_state` failing means stale scan and preview requests were never reclaimed and the
monitoring gap was never logged — and Beacon starts the scheduler anyway. The ERROR line shows 03-15's
log channel is genuinely intact (correcting `03-REVIEW.md` CR-03 on that point). The operator-facing
channel is not: the row reads `running` indefinitely and `job_outcome_unrecorded` cannot promote it,
because a `None` cadence exempts every startup callback from the very promotion built to catch a job
whose outcome was never recorded.

#### 4. Round-3 Gap 2 — closed

`advanced.js:290-292`:

```javascript
if (state === 'absent') return 'No collection stream established for this service';
if (state === 'complete' && count === 0) return 'No gap evidence';
```

`test_service_detail_gap_evidence_reads_as_operator_copy` now expects `9002` (`absent`) →
`No collection stream established for this service` and `9003` (`complete`, count 0) → `No gap evidence`,
and adds `self.assertNotEqual(rendered[9002], rendered[9003])` so a future edit that rewords both map
entries together cannot re-collapse the distinction and stay green. Run here: **2 passed, 8 subtests**.
The reviewer's claim that `absent` is truthful was independently checked — nothing in the codebase
deletes a `('service', port)` row from `telemetry_streams`, so a missing stream in a complete stream list
really is a service the pipeline has never recorded.

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/advanced.html` | Advanced workspace document with preference controls, no remote-control actions | ✓ VERIFIED | 82 lines. Refresh interval select (17), pause/refresh (18-19), search + four filters (52-56), clear/reset/collapse (57-59). No mutation control. Served by `app.py:2096`. |
| `dashboard/advanced.js` | Renders host, services, pipeline, settings, exceptions from the server payload | ✓ VERIFIED | 826 lines. Single network call is a GET to `/api/advanced/current`. Every insertion is `textContent`. Wired via `app.py:2116`. |
| `dashboard/advanced.css` | Workspace presentation in both themes | ✓ VERIFIED | 58 lines, served by `app.py:2106`. |
| `dashboard/beacon/diagnosis.py` | Read-only current-diagnosis composition | ⚠️ HOLLOW on the job-health branch | 507 lines, wired through `app.py:2121`. Host, services, gap and settings composition verified truthful. `compose_active_exceptions` lines 425-443 emit a fault from a poll interval; lines 180-198 exempt every non-interval callback from that same promotion. |
| `dashboard/beacon/worker_main.py` | Worker composition root publishing durable job health | ⚠️ HOLLOW on the outcome mapping | 529 lines, wired via `dashboard/worker.py:26`. `started`/`succeeded`/`failed`/lease-loss/compound paths all verified reachable and correct except the `False → failed` mapping (324-327) and the startup catch site (499-514). |
| `dashboard/beacon/repositories.py` | Bounded durable job-health writes | ✓ VERIFIED | `_safe_job_error_class` strips to `[A-Za-z0-9_.]` and truncates at 96 — independently confirmed no message can reach `background_job_health.error_class`. |
| `.planning/REQUIREMENTS.md` | Traceability record matching verified reality | ✓ VERIFIED | Byte-unchanged since `b3879f3`, before this run. Both halves agree. Nothing recorded Complete ahead of verification. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `dashboard/index.html` / `app.js` | `/advanced` | Link + theme round trip | ✓ WIRED | Named round-trip test green. |
| `dashboard/advanced.js` | `/api/advanced/current` | `fetch(..., {cache:'no-store'})` | ✓ WIRED | Line 58; the only network call on the page. |
| `app.py:2121` | `beacon_diagnosis.get_current_diagnosis` | Route → composition | ✓ WIRED | Exercised in every reproduction above. |
| `diagnosis.get_current_diagnosis` | `background_job_health` table | `compose_pipeline_diagnosis` → `pipeline['jobs']` | ✓ WIRED | Real rows read in reproductions 1 and 3. |
| `worker.py:34-35` | `dispatch_callback` J5/J6 | `WorkerOperations.process_*_requests` | ✓ WIRED — **and that is the problem** | The wiring is real; what travels it is a fabricated verdict. |
| `dispatch_callback` compound path | `run_worker` startup handler | `JobHealthBookkeepingError.work_error_class` | ✗ NOT WIRED | The field is set at the raise site and never read at the only catch site. |
| `compose_active_exceptions` `job_outcome_unrecorded` | S1/S2/S3/J9 | `cadence_seconds` from `callback_schedule_evidence` | ✗ NOT WIRED | `None` for every non-interval trigger; the branch is unreachable for those four jobs. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| --- | --- | --- | --- | --- |
| `advanced.js` `renderHost` | `host.metrics.*`, `sample_ts`, `freshness` | `system_stats` via `compose_host_diagnosis` | Yes | ✓ FLOWING |
| `advanced.js` `renderServices` | `latency_ms`, `failure_class`, `state_duration_seconds`, tags, health rule | `services` / `service_checks` durable rows | Yes | ✓ FLOWING |
| `advanced.js` `formatServiceGapEvidence` | `collection_gaps` | `telemetry_streams` ⋈ `telemetry_coverage` per service | Yes | ✓ FLOWING |
| `advanced.js` exceptions region | `snapshot.exceptions` `job_failed` | `background_job_health.state` | Row is real; **the value written into it is fabricated** for J5/J6 | ⚠️ HOLLOW |
| `advanced.js` exceptions region | `snapshot.exceptions` `job_outcome_unrecorded` | `last_started_ts` + `cadence_seconds` | Derived from a poll interval, not from an outcome | ⚠️ HOLLOW |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Idle production pollers do not record a failure | real adapters → `dispatch_callback` → `get_current_diagnosis` | two `job_failed` cards | ✗ FAIL |
| Running work inside its own cadence promotes nothing | real `dispatch_callback`, read from inside the work at start+9 | `job_outcome_unrecorded` J6 | ✗ FAIL |
| A wedged startup job is promotable | `S1 running 24h, cadence None` → `compose_active_exceptions` | `[]` | ✗ FAIL |
| Compound work+write failure is not swallowed at startup | real `run_worker`, S1 work raises and `failed` write raises | scheduler built and started, no exception escaped | ✗ FAIL |
| `absent` reads differently from collected-and-clean | `pytest -k test_service_detail_gap_evidence_reads_as_operator_copy` | 2 passed, 8 subtests | ✓ PASS |
| Theme survives the advanced round trip | `pytest -k theme_or_return_round_trip` | 4 passed, 3 subtests | ✓ PASS |
| Collection-gap projection and wire vocabulary | `pytest -k "open_stream_gap... or gap_evidence_vocabulary..."` (7 tests) | 7 passed, 25 subtests | ✓ PASS |
| Round-3's own new job-health regressions | 4 named tests run individually | 4 passed, 7 subtests | ✓ PASS — **while all four failures above are live** |

### Probe Execution

No `scripts/*/tests/probe-*.sh` exist in this repository and no PLAN declares a probe path. Probe
execution is **N/A** for this phase; the project's verification surface is the pytest suite, exercised
above by named test and by direct reproduction.

### Requirements Coverage

Statuses established by rounds 1-3 are preserved. Only evidence found this round can move one.

| Requirement | Source Plan | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| DIA-01 | 03-01, 03-05 | Open a dedicated advanced page from either theme | ✓ SATISFIED (Complete — established round 3) | SC1 verified; untouched this round; named route and round-trip tests green. |
| DIA-02 | 03-02, 03-06 | Inspect current CPU, memory, disk, temperature, identity, sample time, freshness | ✓ SATISFIED (Complete — established round 3) | SC2 verified; untouched this round. |
| DIA-03 | 03-04, 03-11, 03-13 | Inspect every service's status, latency or failure class, state duration, criticality, tags, health rule | ✓ SATISFIED (Complete — established round 3) | SC3 verified; this round's edits to the surface covered by named browser regressions run here. |
| UX-02 | 03-05, 03-07 | Move between dashboard and advanced without losing theme | ✓ SATISFIED (Complete — established round 3) | SC1 evidence. |
| DIA-08 | 03-03, 03-09 | Effective monitoring settings and supported presentation/refresh/range/filtering preferences without remote controls | ⏸ DEFERRED to Phase 4 (established round 3) | Settings, refresh, presentation and filtering all present and read-only; `range` is Phase 4 SC1. Unchanged. |
| TEL-06 | 03-03, 03-08, 03-12, 03-15 | Effective retention, displayed resolution, database pressure, worker freshness, collection gaps, **and background-job health** | ✗ BLOCKED — **not promoted** | Five of six clauses verified truthful. Background-job health is not: an idle Pi reports two fabricated failures, in-progress work is reported as an unrecorded outcome, and a genuine startup failure is reported as nothing. `.planning/REQUIREMENTS.md` correctly still records `[ ]` / `Gaps Found`; no change is warranted. |

**Orphaned requirements: none.** All six IDs ROADMAP.md maps to Phase 3 are claimed by at least one
plan's `requirements` frontmatter. The `UI-01`…`UI-36` identifiers appearing in plan frontmatter are
`03-UI-SPEC.md` contract IDs, not REQUIREMENTS.md requirements, and are correctly absent from the
traceability table.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| — | — | `TBD` / `FIXME` / `XXX` debt markers | — | **None found** across all nine phase source files. |
| — | — | `TODO` / `HACK` / `PLACEHOLDER` / "not yet implemented" | — | **None found**. |
| `dashboard/beacon/worker_main.py` | 324-327 | Verdict inferred from an overloaded return value | 🛑 Blocker | Fabricated operator-facing failure — see Gap. |
| `dashboard/beacon/diagnosis.py` | 425-443 | Duration inferred from a schedule interval | 🛑 Blocker | Fabricated operator-facing fault — see Gap. |
| `dashboard/beacon/worker_main.py` | 499-514 | Catch site discards a field added for it | 🛑 Blocker | Genuine failure invisible to the operator — see Gap. |
| `dashboard/beacon/repositories.py` | 142-148 | Global unscoped `LIMIT 49` read backing a per-service number | ⚠️ Warning | `03-REVIEW.md` WR-02. One chatty stream degrades every other service's gap evidence to `possibly_incomplete` with a count that is an artifact of the global budget. Disclosed, so not an untruth — recorded, not filed as a gap. |
| `dashboard/advanced.js` | 182-186 | `job_outcome_unrecorded` copy says "longer than its own configured cadence allows" | ℹ️ Info | `03-REVIEW.md` WR-06. Copy overstates the rule; moot once the boundary is fixed. |
| `dashboard/beacon/diagnosis.py` | 12 | Read-only composition imports the worker composition root | ℹ️ Info | `03-REVIEW.md` WR-03. The Flask process transitively imports APScheduler to read one tuple. No operator-facing effect. |

Items 5-7 are recorded for the next round rather than filed as gaps: none of them produces an untruthful
operator-facing claim, which is the bar this phase's prohibitions set. Everything in
`deferred-items.md` was read first and is **not** re-argued here — rows 2-6 and the seventeen
carried-forward round-1 findings remain dispositioned as recorded.

### Human Verification Required

#### 1. Real collection gap and stale host on the target Pi

**Test:** On the target Pi, open `/advanced` while a real collection gap is active and while host
evidence is stale.
**Expected:** The workspace shows the open gap and the stale host as real, correctly labelled
exceptions — and shows no resolved or retention-expired interval as an open actionable gap.
**Why human:** Carried forward from all three previous reports and re-declared as human judgment in
`03-08-SUMMARY.md` and in `03-14-PLAN.md`'s own human-check block. The synthetic reproductions establish
the server contract; only a person on the hardware can establish that it reads correctly.

#### 2. Idle-Pi Overview after the fix

**Test:** Start the worker on the target Pi, leave the system idle for one minute, then open `/advanced`
and read the Overview "Active exceptions" region.
**Expected:** No `Background job failed` card for J5 or J6, and no `Background job outcome not recorded`
card for any job that is simply working.
**Why human:** The reproductions below prove this on a real database through the real production
adapters, but the operator's own idle Pi is the surface the criterion is written about. Recorded so the
next gap-closure round cannot declare success without it.

### Gaps Summary

One gap, on one clause of one criterion, for the third round running — but not the same defect, and the
direction of travel this round is mixed rather than simply forward.

**What genuinely improved.** 03-16 closed its gap cleanly and completely: a service the pipeline has
never observed now says so, in its own words, protected by a test that asserts the two sentences are
different rather than pinning them the same. 03-15 closed four of its six items, including the one that
mattered most — a genuine work failure now survives a failing outcome write in the raised condition, in
the exception chain, and in the log. I re-derived all of that from the code and reproduced it running.

**What did not.** The two remaining items were implemented in shapes that do not do what they were
written to do. The promotion meant to make a wedged job actionable derives an expected *duration* from a
poll *interval*, so it fires on a J6 preview nine seconds into legitimate work (threshold: 8 seconds) and
on a heartbeat waiting behind a maintenance lock the database itself allows 30 seconds for (threshold:
20 seconds) — while being structurally unable to fire for S1, S2, S3 or J9, whose cadence is `None`.
Those four are exactly the callbacks the other unclosed item concerns: the new `run_worker` handler
catches a compound work-plus-write failure, ignores the `work_error_class` this very round added so the
work failure would remain recoverable at the catch site, and starts Beacon anyway. A startup job that
failed to reclaim stale work reads `running` forever and promotes nothing.

**What was there all along.** While checking the promotion I drove the real queue pollers instead of a
synthetic callback, and found that `dispatch_callback` maps their normal idle result — `False`, meaning
"the queue was empty" — to a durable `failed` state. An idle Pi therefore shows two permanent
`Background job failed` cards within two seconds of worker start, and they never clear. This dates to
03-02 and has been reachable in production through every round of this phase. Round 3 reproduced the
same shape and recorded it as a passing control, because the reproduction asked whether the code did
what the code says rather than whether what it says is true. That is the failure mode worth naming: two
green tests (`test_callback_outcome_false_and_exception_never_claim_success`,
`test_a_job_stuck_without_an_outcome_becomes_an_operator_exception`) pin all three defects in place, and
the full suite is green with every one of them live.

**Consequence.** Success Criterion 4 is FAILED and TEL-06 stays BLOCKED. Four of the phase's six
requirements are satisfied and one is a legitimate Phase 4 deferral; the phase's other three criteria
hold and were re-checked, not assumed. The remaining work is narrow and well-specified — give an empty
queue its own vocabulary, floor the unrecorded-outcome boundary above the lock waits the callback can
block on, give startup callbacks a promotable boundary, and make the startup catch site read the field
that was added for it — and each fix needs a regression driven by the *real* collaborator, because a
synthetic one is what let all three of these through.

---

_Verified: 2026-08-19T10:03:43Z_
_Verifier: Claude (gsd-verifier), re-verification round 4_
