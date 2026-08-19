---
phase: 03-advanced-current-diagnosis
verified: 2026-08-19T11:44:11Z
status: gaps_found
score: 3/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
unverified_prohibitions: 5
re_verification:
  round: 5
  previous_status: gaps_found
  previous_score: 3/4
  gaps_closed:
    - "Round-4 `missing` 1 — Stop overloading `False`. Closed and independently reproduced closed: `app.py:1810` and `app.py:1968` now `return None` on an empty claim. Driving the REAL `appmod.worker_process_scan_requests` / `worker_process_preview_requests` through the REAL `dispatch_callback` against a genuinely empty queue on a real SQLite database returns `None` / `None` and writes `{'J5': ('succeeded', None, 100), 'J6': ('succeeded', None, 100)}`. `get_current_diagnosis` emits zero `job_failed`. The two permanent idle-Pi cards are gone."
    - "Round-4 `missing` 2 — A regression driven by the REAL adapters. `test_the_real_scan_and_preview_pollers_record_an_idle_queue_as_success` binds `self.appmod.worker_process_scan_requests` / `worker_process_preview_requests` — the exact two callables `dashboard/worker.py:34-35` wires in — seeds nothing, and asserts `assertIsNone` plus `state='succeeded'`. Run here: green."
    - "Round-4 `missing` 3 — Floor-clamped boundary. `diagnosis.py:40` `UNRECORDED_OUTCOME_FLOOR_SECONDS = 900`; `_unrecorded_outcome_boundary` returns `max(floor, 4 * cadence)` for a strict positive `int` cadence and the floor for everything else. 900 clears both of `connect_db`'s 30 s waits and discovery's 180 s timeout. Reproduced by direct probe."
    - "Round-4 `missing` 4 — The two false positives round 4 reproduced are gone. My own probe through `compose_active_exceptions`: `J6 running 9s cadence 2 -> []`, `J1 running 25s cadence 5 -> []`, and additionally `J5 running 179s cadence 2 -> []` and `J9 running 180s cadence None -> []` (a full discovery timeout). Strict at the boundary: 900 s -> `[]`, 901 s -> one promotion."
    - "Round-4 `missing` 5 — The `None`-cadence exemption is gone. `S1 wedged 24h cadence None -> [{'kind': 'job_outcome_unrecorded', 'job_id': 'S1'}]`. The two cadence-type guards were removed from the branch, not merely bypassed."
    - "Round-4 `missing` 6 — The catch site reads the field added for it. `worker_main.py:505-512` re-raises when `bookkeeping_error.work_error_class is not None`. Reproduced through the REAL `run_worker`: `JobHealthBookkeepingError | work_error_class = RecoverBlewUp` escapes, `build_scheduler called: False`, `_worker_started: False`, `calls == ['prepare','recover','shutdown_browser']` (S2/S3 never dispatched), and the `worker_owner` lease row is gone — no stranded state. Round 4 offered `Re-raise, OR surface it durably`; re-raise was chosen, so the item is closed as commissioned. See `gaps` count 2 for the operator-surface half that re-raise does not deliver."
    - "Round-4 `missing` 7 — `test_a_compound_startup_failure_reaches_the_operator_instead_of_continuing` exists and asserts `work_error_class == 'RecoverBlewUp'`, `build_scheduler.assert_not_called()`, `attempted == [('S1','started'),('S1','failed')]`, and that `'heartbeat'`/`'metrics'` never ran. Green here."
    - "Round-4 `regressions` (03-15's poll-interval promotion) — genuinely closed, reproduced closed. Round-4 `newly_found` (03-02's `False` overloading) — genuinely closed, reproduced closed."
  gaps_remaining:
    - "The failed truth. `Background-job health reported to the operator reflects what the job actually did` is STILL FALSE, now in the opposite direction: a genuine work failure in J5, J6, J7 and J9 is recorded and shown to the operator as `succeeded`."
  regressions: []
  newly_found:
    - "dashboard/app.py:1847 and dashboard/app.py:2004 — `worker_process_scan_requests` and `worker_process_preview_requests` compute a real failure verdict (`status='failed'`), durably record it in `scan_requests` / `preview_requests`, and then `return True` unconditionally. `dispatch_callback` maps anything that is not literal `False` to `succeeded`. Reproduced end to end on a real database through the real adapters: `scan_requests.status='failed' error='discovery hit a real error'` and `preview_requests.status='failed' error='preview capture failed'`, while `background_job_health` reads `{'J5': ('succeeded', None, 100), 'J6': ('succeeded', None, 100)}` and the pipeline row rendered to the operator reads `state=succeeded error_class=null last_success_ts=100`. NOT a round-5 regression — `git log -L 1847,1847:dashboard/app.py` returns `82e3eaa 2026-08-06 feat(01-22)`. Flagged as WR-05 by `03-17-REVIEW.md`; independently confirmed here."
    - "dashboard/beacon/worker_main.py:188-202 — BROADER THAN THE REVIEW REPORTED. `_run_scheduled_discovery` (J7) and `_run_startup_discovery` (J9) discard `services.run_discovery(...)`'s return entirely and fall off the end returning `None`, so `run_discovery` returning the literal `'failed'` also records `succeeded`. Reproduced: with `run_discovery` returning `'failed'`, `{'J7': ('succeeded', None, 100), 'J9': ('succeeded', None, 100)}` and zero operator exceptions. The failure-direction defect therefore covers four of the eleven promotable jobs, not the two `03-17-REVIEW.md` WR-05 names."
  over_credit_corrected:
    - "The round-5 plan, summary and review all frame the truth as closed in the direction round 4 commissioned. It is. The plan's own `objective` states the goal as `Make background-job health reported to the operator reflect what the job actually did -- for real, this time`, and `03-17-SUMMARY.md` records all three `coverage` items as `pass`. Neither is wrong about what it built; both are silent on the symmetric half. A surface that reports `succeeded` for a run the same transaction recorded as `failed` does not reflect what the job did, and crediting the truth on the commissioned direction alone would repeat the round-3 error at the opposite polarity."
gaps:
  - truth: "Background-job health reported to the operator reflects what the job actually did."
    status: failed
    reason: "The fabricated-FAILURE direction is genuinely closed and was reproduced closed on every count round 4 raised. The fabricated-SUCCESS direction is live and was reproduced here on a real SQLite database through the real production adapters. (1) FABRICATED SUCCESS, four jobs. `worker_process_scan_requests` computes `status = 'failed' if outcome == 'failed' or state.get('last_error') else 'completed'` (app.py:1825), calls `fail_scan_for_worker`, and then `return True` at app.py:1847; `worker_process_preview_requests` computes `status='failed' if warning else 'completed'` (app.py:1990) and `return True` at app.py:2004. `_run_scheduled_discovery` / `_run_startup_discovery` (worker_main.py:188-202) discard `run_discovery`'s `'failed'` return and fall off the end as `None`. `dispatch_callback` maps every non-`False` result to `succeeded`. Reproduced: a discovery that raised and a preview capture that failed both left `scan_requests.status='failed'` / `preview_requests.status='failed'` with their error text, while `background_job_health` read `{'J5': ('succeeded', None, 100), 'J6': ('succeeded', None, 100)}`, the pipeline rows shown to the operator read `state=succeeded, error_class=null, last_success_ts=100`, and `get_current_diagnosis` emitted zero job exceptions. Separately reproduced for J7/J9 with `run_discovery` returning `'failed'`: `{'J7': ('succeeded', None, 100), 'J9': ('succeeded', None, 100)}`. The system knows the work failed, records that it failed, and tells the operator it succeeded. Pre-existing (`82e3eaa`, 2026-08-06), not a round-5 regression — but the truth is symmetric, and round 4 set the precedent that provenance does not exempt a live untruth from this truth (it credited 03-02's `False` mapping as keeping the truth false). (2) COMPOUND STARTUP FAILURE STILL ABSENT FROM THE WORKSPACE. Reproduced through the real `run_worker`: the re-raise works exactly as commissioned — condition escapes carrying `work_error_class='RecoverBlewUp'`, `build_scheduler` never called, S2/S3 never dispatched, lease released — but the durable row is left at `('running', None)` and `operator exceptions for S1: []`. `job_outcome_unrecorded` cannot fire for at least 900 s, and the worker container's `restart: unless-stopped` re-dispatches S1 and rewrites `started` on each restart, so under a sub-900 s restart loop the promotion never fires. Round-4 `missing` 6 offered `Re-raise, OR surface it durably`, so this item IS closed as commissioned; it is recorded here because it is a second live instance of the same failed truth, at materially lower severity than count 1 (the process exits loudly, the ERROR log names the work failure, and `worker_freshness` correctly goes stale). (3) TRANSIENT FABRICATED FAILURES REMAIN, DEFERRED. `worker_process_scan_requests`'s discovery-busy `return False` (app.py:1822) and `_legacy_do_uptime_check`'s `return False` under `_uptime_lock` contention (app.py:1333-1334, wired to production through `_monitoring_operations().do_uptime_check` at app.py:1475) still map to `('failed','CallbackReturnedFalse')` and a `Background job failed` card for a job that merely lost a lock. Recorded in `deferred-items.md` row 8 with a defensible reason (transient, self-clearing on the next tick) and NOT commissioned by any round-4 `missing` bullet. Recorded, not filed as the blocker."
    artifacts:
      - path: "dashboard/app.py"
        issue: "Line 1847: `return True` after a branch that already resolved `status='failed'` and called `fail_scan_for_worker`. Line 2004: `return True` after `status='failed' if warning else 'completed'`. Both discard a verdict the function itself computed. The `except Exception as exc: status, error = 'failed', str(exc)[:240]` at 1828-1829 also swallows a raised scan failure into the same `return True`, so an exception in a manual scan reaches job health as `succeeded` too."
      - path: "dashboard/beacon/worker_main.py"
        issue: "Lines 188-202: `_run_scheduled_discovery` and `_run_startup_discovery` call `services.run_discovery(...)` as a statement and return `None` implicitly on both the skip path and the work path, so `run_discovery`'s documented `'failed'` return (app.py:1327) is discarded. `None` therefore carries at least three meanings on the dispatch boundary, contradicting the return-value vocabulary `03-17-SUMMARY.md` records as established (`None` = no work available)."
      - path: "dashboard/beacon/worker_main.py"
        issue: "Lines 505-512: the new re-raise delivers the compound failure on the process/log channel only. Nothing writes a durable `failed` row before re-raising, so `background_job_health` is left at `running` and the /advanced workspace names nothing. Confirmed by reproduction."
      - path: "tests/test_advanced_diagnosis_api.py"
        issue: "No test in this round or any prior round drives either poller against work that genuinely fails. Every J5/J6 outcome test covers the empty-queue path or a synthetic callback. This is the same test-scaffolding shape round 4 named as what let three rounds pass green, applied to the opposite polarity."
      - path: "tests/test_advanced_diagnosis_api.py"
        issue: "Lines 1222, 1288-1305: `floor = diagnosis.UNRECORDED_OUTCOME_FLOOR_SECONDS` and every absent-cadence expectation derived from it (`now - floor + 1`, `now - floor - 1`) are self-referential and cannot fail for any value. Independently confirmed: I set the constant to 30 in a throwaway copy of HEAD and ran the full suite — 296 passed / 413 subtests, byte-identical to HEAD's result. Recorded as a WARNING, not part of this gap: the shipped value 900 satisfies round-4 `missing` 3 and the boundary was reproduced behaving correctly."
    missing:
      - "Return the verdict the poller already computed instead of a constant: `return status == 'completed'` in `worker_process_scan_requests` and `return not warning` in `worker_process_preview_requests`, so `dispatch_callback`'s unchanged mapping records `failed` for a run the same call already recorded as failed. Decide explicitly what the `except Exception` path at app.py:1828 should record — swallowing it into `succeeded` is the same defect by another route."
      - "Make J7/J9 honour the vocabulary this round declared: `_run_scheduled_discovery` and `_run_startup_discovery` must return the discovery outcome on the work path (`return outcome != 'failed'`) and `None` only on the genuine skip path. Until then `None` means three different things at the dispatch boundary and the recorded pattern is not true of production."
      - "Add a regression that drives the REAL `worker_process_scan_requests` and `worker_process_preview_requests` against work that GENUINELY FAILS — a queued scan whose `worker_run_discovery` raises, and a queued preview whose capture returns a warning — and asserts the durable J5/J6 rows read `failed` and that `compose_active_exceptions` emits `job_failed` for each. The empty-queue regression this round added is necessary and is not sufficient; only the failure case closes the symmetric half."
      - "Leave durable evidence before the compound-startup re-raise, or record explicitly that the compound path is a journal-and-exit channel only and that the /advanced workspace is not expected to name it. Today the round's own completeness claim is met on the log, not on the workspace this phase is about."
      - "Pin `UNRECORDED_OUTCOME_FLOOR_SECONDS` against the external facts its own comment cites rather than against itself — `assertGreater(floor, 30 + 30)` for `connect_db`'s two waits and `assertGreater(floor, DISCOVERY_TIMEOUT_SECONDS)` — plus a `J9 running 180s, cadence None` subtest. Without this the value is correct today and unenforced tomorrow, which is the exact shape of hole that let three rounds pass green."
      - "Either close the two deferred transient `False`-on-contention sites (`worker_process_scan_requests`'s busy branch, `_legacy_do_uptime_check` under `_uptime_lock`) or restate `deferred-items.md` row 8 to say plainly that a J3/J4 lock overlap shows the operator a `Background job failed` card for up to one minute. `Another run already owns this work` is not a fault."
deferred:
  - truth: "Operator can change supported *range* preferences in the advanced workspace (the `range` clause of Success Criterion 4 and of DIA-08's requirement text)."
    addressed_in: "Phase 4"
    evidence: "Re-confirmed against ROADMAP.md this round: Phase 4 success criterion 1 is 'Operator can choose shared ranges from one hour through 90 days or a validated custom range within retained history.' No range control exists in `advanced.html`; the preference controls present are refresh interval, pause/refresh, search, four filters, clear filters, reset order and collapse details. Carried forward from rounds 3 and 4 unchanged — a deferral, not a gap, and no closure plan should be written for it. DIA-08 stays DEFERRED."
human_verification:
  - test: "On the target Pi, open /advanced while a real collection gap is active and while host evidence is stale."
    expected: "The workspace shows the open gap and the stale host as real, correctly labelled exceptions — and shows no resolved or retention-expired interval as an open actionable gap."
    why_human: "Carried forward from all four previous reports and re-declared as human judgment in 03-08-SUMMARY.md, 03-14-PLAN.md and 03-17-PLAN.md's own human-check blocks. Still NOT performed on real hardware. Operator trust in the rendered snapshot cannot be asserted programmatically."
  - test: "On the target Pi, start the worker and leave the system idle for one minute, then open /advanced and read the Overview 'Active exceptions' region."
    expected: "No 'Background job failed' card for J5 or J6, and no 'Background job outcome not recorded' card for any job that is simply working."
    why_human: "Recorded by round 4 specifically so a gap-closure round could not declare success without it. Still NOT performed on real hardware. My reproduction establishes it on a real SQLite database through the real production adapters and it now passes there; the operator's own idle Pi is the surface the criterion is written about. Carried forward unchanged."
prohibitions:
  - source: "03-08-PLAN.md"
    statement: "MUST NOT present resolved, retention-expired, or otherwise inferred evidence to the operator as a current, open, actionable fault -- every operator-facing open/actionable/kind label must be derivable from the durable row it describes, never from a neighbouring row or a stream-level fact."
    verification: judgment
    llm_judge_verdict: violated
    flagged: true
    previous_verdict: violated
    detail: "MATERIALLY IMPROVED but not clean. Both round-4 counts are closed and were reproduced closed: an idle poll no longer infers a fault from `False`, and an in-progress run no longer infers a fault from a poll interval (`J6 9s cadence 2 -> []`, `J1 25s cadence 5 -> []`, `J5 179s cadence 2 -> []`). UPHELD unchanged on the collection-gap and services surfaces, which this round did not touch. Still VIOLATED, at much reduced severity, on two transient paths: `worker_process_scan_requests`'s discovery-busy `return False` and `_legacy_do_uptime_check`'s `return False` under `_uptime_lock` contention both still infer `Background job failed` from 'another run already owns this work'. Both are reachable in production (`_legacy_do_uptime_check` is the wired implementation via `_monitoring_operations()` at app.py:1475) and both are self-clearing on the next successful tick. Deliberately deferred in `deferred-items.md` row 8 with a reason I judge defensible; disclosure in a planning file the operator never reads does not make the card truthful."
  - source: "03-08-PLAN.md"
    statement: "MUST NOT suppress a genuine collection failure while narrowing false positives -- restricting promotion by reason must never cause a real collection_gap, or a reason value the code does not recognise, to go unreported to the operator."
    verification: judgment
    llm_judge_verdict: violated
    flagged: true
    previous_verdict: violated
    detail: "UPHELD on the collection-gap surface (re-checked, unchanged and green). VIOLATED on background-job health, and this round the violation is the phase's central finding rather than a side effect. A genuine J5 scan failure, a genuine J6 preview failure and a genuine J7/J9 discovery failure are all suppressed into `state='succeeded', error_class=null` — reproduced on a real database with the failure simultaneously and durably recorded in `scan_requests` / `preview_requests`. Separately, the compound startup work failure now escapes `run_worker` loudly (genuine progress, reproduced) but still reaches the operator surface as `running`, never `failed`. This is precisely the narrowing-false-positives-into-suppression shape the prohibition names: the round removed two fabricated alarms and left the mirror suppression untouched."
  - source: "03-09-PLAN.md"
    statement: "MUST NOT let automatic background refresh silently override an operator's explicit presentation choice, and MUST NOT present a machine identifier or a placeholder as the operator's primary safety evidence when the server supplied real evidence."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "This round's entire `advanced.js` diff is one line: the `job_outcome_unrecorded` `evidence` sentence. Sort persistence, the refresh loop and every `textContent` insertion are untouched. `test_every_emitted_exception_kind_renders_operator_copy` and the gap-evidence browser regression both pass here. `03-17-REVIEW.md` WR-04 is confirmed at the code level — the sentence still says 'See Pipeline for ... configured cadence' while `advanced.js:433` renders `Not scheduled` for S1/S2/S3 and `expected every —` for J9, which are exactly the jobs Task 2 newly made promotable — but this is a stale pointer, not a placeholder standing in for real evidence the server supplied: the server genuinely has no cadence for those triggers and the placeholder correctly reads as absence. Recorded as a Warning anti-pattern, not a violation."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT let test scaffolding mutate process-global state so that suite greenness depends on execution order."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "Verified by running both cross-module orders myself: `test_runtime_ownership.py test_advanced_diagnosis_api.py` and the reverse each give 62 passed / 153 subtests. Every new monkeypatch is paired with an `addCleanup` restore and `mock.patch.object` context managers unwind on the raising path. `03-17-REVIEW.md` IN-03 is confirmed — `tests/test_advanced_diagnosis_api.py:706` assigns before `707-709` registers the restore, contrary to `03-17-PLAN.md`'s own stricter restatement — but no statement between them can raise and the cleanup does run, so the prohibition as written holds. Recorded as Info, together with the fact that `03-17-SUMMARY.md:176` 'Total deviations: 0' is inaccurate on this point."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT record a requirement, plan, or phase as complete on the strength of an implementation claim rather than independent verification -- the traceability table is the project's own memory of what is actually true."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "Verified independently: `git diff 43c3727 HEAD -- .planning/REQUIREMENTS.md` is empty; line 25 still reads `- [ ] **TEL-06**` and line 123 still reads `| TEL-06 | Phase 3 | Gaps Found |`. The executor deliberately left the promotion decision to this round and said so. TEL-06 is NOT promoted here either — my own reproduction does not support it. The record continues to under-credit rather than over-credit, which remains the correct failure direction."
---

# Phase 3: Advanced Current Diagnosis Verification Report

**Phase Goal:** The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.

**Verified:** 2026-08-19T11:44:11Z
**Status:** gaps_found
**Re-verification:** Yes — round 5, after gap-closure plan 03-17.

This report supersedes the round-4 `03-VERIFICATION.md` and preserves the requirement-status history
rounds 1-4 established. Nothing below is taken from `03-17-SUMMARY.md` or from `03-17-REVIEW.md`.
Every claim is a line of code I read or a command I ran in my own process against a real SQLite
database created by the project's own `tests.helpers.load_app`. Where my finding differs from the
reviewer's, or extends it, the difference is stated.

## The short version

**Plan 03-17 did what it was commissioned to do.** All seven of round-4's `missing` items are closed,
and I reproduced each one closed rather than reading the summary. The two permanent fabricated
`Background job failed` cards on an idle Pi are gone. The promotion that fired on a J6 preview nine
seconds into legitimate work no longer fires. A wedged startup job with no cadence is now promotable.
A compound startup failure escapes `run_worker` and never reaches `build_scheduler`. This is real
progress and it is the largest single-round improvement this surface has had.

**The truth is still false.** It is false in the other direction. A manual scan that fails, a preview
capture that fails, and a discovery that returns `'failed'` are all recorded — in the very same
dispatch that durably writes `status='failed'` into `scan_requests` / `preview_requests` — as
`state='succeeded'`, `error_class=null`, `last_success_ts` set. The operator's Pipeline reads
`J5 — succeeded` for a scan the system just recorded as failed. "Background-job health reported to the
operator reflects what the job actually did" is violated by a fabricated success exactly as it is by a
fabricated failure, and the fabricated success is the quieter of the two.

## Gap-Closure Outcome (03-17), item by item

Every row was established by a command I ran, not by reading the summary.

| Round-4 `missing` item | Status | How I established it |
| --- | --- | --- |
| 1 — Stop overloading `False`; an empty poll records `succeeded` | ✓ CLOSED | Drove the REAL `appmod.worker_process_scan_requests` / `worker_process_preview_requests` through the REAL `dispatch_callback` against a genuinely empty queue. |
| 2 — A regression driven by the REAL adapters | ✓ CLOSED | Read the test; it binds `self.appmod.*`, seeds nothing, asserts `assertIsNone`. Ran it: green. |
| 3 — Floor-clamped boundary above the lock waits | ✓ CLOSED | `UNRECORDED_OUTCOME_FLOOR_SECONDS = 900`; probed `_unrecorded_outcome_boundary` across 12 cadence values. |
| 4 — Subtests at cadence 2 / 9 s and cadence 5 / 25 s | ✓ CLOSED | Probed the projection directly; both promote nothing, plus two harder cases I added myself. |
| 5 — Startup callbacks get a promotable boundary | ✓ CLOSED | `S1 wedged 24h, cadence None` now promotes; the two cadence-type guards are removed, not bypassed. |
| 6 — Distinguish the two conditions at the `run_worker` catch site | ✓ CLOSED as commissioned | Reproduced through the real `run_worker`. Round 4 offered "Re-raise, **or** surface it durably"; re-raise was chosen. The operator-surface half is recorded separately below. |
| 7 — Compound startup regression | ✓ CLOSED | Test exists, asserts the object graph and the halt, runs green. |
| `newly_found` — 03-02's `False` mapping | ✓ CLOSED | Same reproduction as item 1. |
| `regressions` — 03-15's poll-interval promotion | ✓ CLOSED | Same probe as items 3-5. |

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Operator can open the dedicated advanced page from the dashboard and return without losing theme. | ✓ VERIFIED | Untouched this round — `git diff e12cada..HEAD -- dashboard/` covers only `advanced.js` (one string), `app.py` (two returns), `diagnosis.py`, `worker_main.py`. Behavior-dependent, so proven by named test rather than presence: `test_theme_or_return_round_trip_preserves_theme_and_consumes_scroll_once` and `test_production_routes_serve_the_advanced_document_bundle` run green here. |
| 2 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, and host freshness. | ✓ VERIFIED | Untouched. `test_host_tracer_returns_one_current_snapshot_with_server_freshness` green here. The host block carried live evidence in every reproduction below. |
| 3 | Operator can inspect every current service's status, latency or failure class, state duration, criticality, tags, and effective health rule. | ✓ VERIFIED | Untouched. `test_unmeasured_latency_and_duration_never_rank_or_read_as_zero` and `test_service_detail_gap_evidence_reads_as_operator_copy` green here (6 tests / 55 subtests across the SC1-3 set). |
| 4 | Operator can view truthful retention, resolution, database pressure, worker freshness, **collection gaps**, and **background-job health**, and change presentation/refresh/filtering preferences without remote controls. | ✗ **FAILED** | Five of six clauses re-checked truthful, including all collection-gap shapes and the no-remote-controls clause (`advanced.js` still makes exactly one network call, a GET to `/api/advanced/current`). **Background-job health is not truthful.** The fabricated-failure direction is closed; the fabricated-success direction is live and reproduced below. |

**Score:** 3/4 roadmap success criteria verified (0 present-but-behavior-unverified — every truth above was
exercised by a named test or a direct reproduction, not by symbol presence).

> **On Success Criterion 4, fifth round.** The pattern is worth naming precisely, because it is not
> repetition. Round 3 found a genuine failure erased from the exception chain; round 4 found the remedy
> introduced a false positive and that an older false positive had been live all along; round 5 finds
> both false positives genuinely gone and the mirror suppression still standing. Each round has closed
> what it was asked to close. What has never happened is a round that asked the whole question in both
> directions at once. A criterion that names six things is not satisfied when one of them lies, and it
> does not matter which way the lie points.

### Reproduction Evidence (verifier-executed)

Every block below is output from a command I ran, against a real SQLite database created by the
project's own `tests.helpers.load_app`, through production code paths. Scripts are re-runnable.

#### 1. The idle Pi is genuinely fixed

Driving the **real** production adapters — the exact two `dashboard/worker.py:34-35` wires in —
through the **real** `dispatch_callback` against an **empty** durable queue:

```
J5 real adapter return on empty queue: None
J6 real adapter return on empty queue: None
DURABLE ROWS: {'J5': ('succeeded', None, 100), 'J6': ('succeeded', None, 100)}
OPERATOR EXCEPTIONS: [{'kind': 'host_freshness', ...}, {'kind': 'worker_freshness', ...}]
```

Zero `job_failed`. Round 4's reproduction of the same fixture produced
`{'J5': ('failed','CallbackReturnedFalse',None), 'J6': ('failed','CallbackReturnedFalse',None)}` and two
`job_failed` cards. This defect is closed.

#### 2. The promotion boundary is genuinely fixed

Probing `_unrecorded_outcome_boundary` and then `compose_active_exceptions` directly:

```
FLOOR = 900
  cadence=None -> 900     cadence=2   -> 900     cadence=5    -> 900
  cadence=60   -> 900     cadence=300 -> 1200    cadence=3600 -> 14400
  cadence=0/-1/True/2.0/'2' -> 900   (strict `type(x) is int`, bool excluded)

  J6 running   9s, cadence 2    (legit preview work)     -> []
  J1 running  25s, cadence 5    (behind the flock wait)  -> []
  J5 running 179s, cadence 2    (discovery in flight)    -> []
  J9 running 180s, cadence None (startup discovery)      -> []
  J9 running 899s, cadence None                          -> []
  J9 running 900s, cadence None (exactly at boundary)    -> []
  J9 running 901s, cadence None (past the boundary)      -> [job_outcome_unrecorded J9]
  S1 wedged   24h, cadence None                          -> [job_outcome_unrecorded S1]
  J8 running 14400s, cadence 3600 (4*c dominates)        -> []
  J8 running 14401s, cadence 3600                        -> [job_outcome_unrecorded J8]
  failed job control (J5 failed)                         -> [job_failed J5]
```

Round 4's two reproduced false positives (`J6 9s -> job_outcome_unrecorded`,
`J1 25s -> job_outcome_unrecorded`) are gone, and I added two harder cases of my own (a full 179 s
discovery, a full 180 s startup discovery) which also promote nothing. The `None`-cadence exemption is
gone: S1 and J9 are promotable. The comparison is strict at the boundary. `max`, not `min`.

#### 3. The compound startup failure is loud on the process channel and silent on the workspace

Through the real `run_worker`, with S1's `recover_worker_state` raising **and** the `failed` write
raising:

```
exception escaped run_worker : JobHealthBookkeepingError | work_error_class = RecoverBlewUp
build_scheduler called       : False
_worker_started              : False
calls                        : ['prepare', 'recover', 'shutdown_browser']
writes attempted             : [('S1','started',None), ('S1','failed','RecoverBlewUp')]
durable rows                 : {'S1': ('running', None)}
worker_owner lease row       : None
operator exceptions naming S1: []
all operator exceptions      : ['host_freshness', 'worker_freshness']
   [ERROR] Beacon worker could not record a callback failure; reporting the work failure here:
           callback=S1 transition=failed work_error_class=RecoverBlewUp write_error_class=OperationalError
```

The commissioned behaviour is exactly right: the condition escapes carrying the work error, the
scheduler is never built, S2 and S3 are never dispatched, and — checking the reviewer's own claim
independently — **no worker state is stranded**: the `worker_owner` lease row is gone because the
re-raise sits inside the outer `try` and `finally: _finalize_worker_lifecycle(services)` still runs.
(My first run of this reproduction showed the lease still held; that was my own fixture binding
`release_worker_lease=queues.release_worker_lease` where production binds
`queues.release_worker_authority`. Corrected, the lease releases.)

What does **not** happen: the durable row stays `running`, and `/advanced` names nothing about S1.
Round-4 `missing` item 6 offered "Re-raise, **or** surface it durably", so the item is closed as
written. I record it because it is a second live instance of the failed truth — at materially lower
severity than the finding below, since the process exits loudly, the ERROR log names the work failure,
and `worker_freshness` correctly goes stale.

#### 4. A genuinely FAILED scan and a genuinely FAILED preview are reported as succeeded

**This is the finding that keeps Success Criterion 4 failed.** Driving the same two real production
adapters through the same real `dispatch_callback`, this time with a queued scan whose
`worker_run_discovery` raises and a queued preview whose capture returns a warning:

```
J5 real adapter return on a FAILED scan   : True
J6 real adapter return on a FAILED preview: True

DURABLE JOB-HEALTH ROWS  : {'J5': ('succeeded', None, 100), 'J6': ('succeeded', None, 100)}

scan_requests    : [{... 'status': 'failed', 'error': 'discovery hit a real error', ...}]
preview_requests : [{... 'status': 'failed', 'error': 'preview capture failed', ...}]

OPERATOR EXCEPTIONS      : []
PIPELINE JOB ROW SHOWN TO OPERATOR:
  {"job_id":"J5", "state":"succeeded", "error_class":null, "last_success_ts":100, ...}
  {"job_id":"J6", "state":"succeeded", "error_class":null, "last_success_ts":100, ...}
```

The same dispatch that wrote `status='failed'` with the error text into the queue table wrote
`state='succeeded'` into `background_job_health`. `worker_process_scan_requests` computes
`status = 'failed' if outcome == 'failed' or state.get('last_error') else 'completed'` (app.py:1825),
calls `fail_scan_for_worker`, and then `return True` at app.py:1847.
`worker_process_preview_requests` computes `status='failed' if warning else 'completed'` (app.py:1990)
and `return True` at app.py:2004. `dispatch_callback` maps everything that is not literal `False` to
`succeeded`.

**Provenance.** `git log -L 1847,1847:dashboard/app.py` and `-L 2004,2004:dashboard/app.py` both return
`82e3eaa 2026-08-06 feat(01-22): fence worker database callback adapters`. Pre-existing, not a round-5
regression, and not named in round-4's `missing` list. It is nonetheless a live operator-facing untruth
on the exact clause the failed truth is about, and round 4 established the precedent that provenance
does not exempt (it credited 03-02's `False` mapping as keeping this same truth false).

#### 5. The same defect is broader than the review reported — J7 and J9 too

`03-17-REVIEW.md` WR-05 names two functions. It is four jobs. `_run_scheduled_discovery` (J7) and
`_run_startup_discovery` (J9) at `worker_main.py:188-202` call `services.run_discovery(...)` as a
statement and fall off the end returning `None`, discarding a return that `app.py:1327` documents as
`'completed' | 'failed' | 'busy'`:

```
J7 dispatch return on a FAILED discovery: None
J9 dispatch return on a FAILED discovery: None
DURABLE JOB-HEALTH ROWS: {'J7': ('succeeded', None, 100), 'J9': ('succeeded', None, 100)}
OPERATOR EXCEPTIONS    : []
PIPELINE ROW SHOWN: J7 state= succeeded error_class= None last_success_ts= 100
PIPELINE ROW SHOWN: J9 state= succeeded error_class= None last_success_ts= 100
```

This also bounds a claim `03-17-SUMMARY.md` records as an established pattern: "None means 'no work was
available', False means 'the work refused', an exception means 'the work failed'." Four of the eleven
promotable jobs return `None` for a failure. The vocabulary the round declared is not yet true of
production.

#### 6. The floor's value is pinned by nothing (adjudicating WR-01)

I set `UNRECORDED_OUTCOME_FLOOR_SECONDS = 30` in a throwaway copy of HEAD (`rsync` of the tree minus
`.git`/`.planning`, one `sed`) and ran the entire suite:

```
296 passed, 413 subtests passed in 92.46s
```

Byte-identical to HEAD's result. **WR-01 is confirmed as stated.** The absent-cadence subtests read
`floor = diagnosis.UNRECORDED_OUTCOME_FLOOR_SECONDS` and derive their fixtures from it
(`now - floor + 1`, `now - floor - 1`), so they cannot fail for any value; the only absolute-value
constraints are the 9 s and 25 s cases, which together require only `floor >= 25`. A 30-second floor
sits below `connect_db`'s own 30 s `flock` wait and far below the 180 s discovery timeout — I verified
by direct probe that a `J9 running 180s, cadence None` would promote under it.

**Adjudication: WARNING, not a gap.** Round-4 `missing` item 3 asked for "a boundary no legitimate run
can plausibly cross, floored above the lock waits". The shipped value 900 satisfies that, and I
reproduced the boundary behaving correctly at 900 across ten cases. The item is closed behaviourally.
What is missing is enforcement, and that is the same shape of hole that let three rounds pass green —
so it is recorded in `missing` for the next round rather than dismissed.

### Adjudication of the five review warnings

Each judged on my own evidence, not deferred to the reviewer.

| Finding | Verdict | Basis |
| --- | --- | --- |
| **WR-01** floor pinned by nothing | **CONFIRMED**, WARNING | Reproduced the 30-second mutation myself: full suite green, 296/413. Behaviourally correct today, unenforced tomorrow. Not a live untruth, so not the blocker. |
| **WR-02** startup `False` + failed write misclassified as bookkeeping-only | **CONFIRMED but latent**, WARNING | Read all three startup handlers: `worker_recover_worker_state`, `worker_update_worker_heartbeat` and `worker_collect_system_stats` all return truthy, so no startup dispatch can produce `transition='failed', work_error=None` today. The classification hole is real and the new code owns it; it is unreachable, so it is not a gap. |
| **WR-03** compound failure never reaches the workspace | **CONFIRMED**, folded into the gap as count 2 | Reproduced: `{'S1': ('running', None)}`, `operator exceptions for S1: []`. Round-4 `missing` 6 permitted re-raise as an alternative to durable surfacing, so the commissioned item IS closed; the residual is recorded, at lower severity. |
| **WR-04** copy points at a cadence the newly-promotable jobs do not have | **CONFIRMED**, Warning, not a prohibition violation | `advanced.js:184` still says "See Pipeline for ... configured cadence"; `advanced.js:433` renders `Not scheduled` for S1/S2/S3 and `expected every —` for J9. A stale pointer, not a placeholder standing in for evidence the server supplied. |
| **WR-05** pollers report `succeeded` for a genuine failure | **CONFIRMED AND BROADENED — this is the blocker** | Reproduced end to end on a real database with the failure durably recorded in the queue table in the same transaction. Extends to J7 and J9, which the review did not cover. The truth is symmetric; a fabricated success falsifies it exactly as a fabricated failure does. |

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/advanced.html` | Advanced workspace with preference controls, no remote-control actions | ✓ VERIFIED | Untouched this round. No mutation control. |
| `dashboard/advanced.js` | Renders host, services, pipeline, settings, exceptions from the server payload | ✓ VERIFIED | One-line diff (the `job_outcome_unrecorded` evidence sentence). Single network call remains a GET to `/api/advanced/current`. Every insertion is `textContent`. |
| `dashboard/advanced.css` | Workspace presentation in both themes | ✓ VERIFIED | Untouched. |
| `dashboard/beacon/diagnosis.py` | Read-only current-diagnosis composition | ✓ VERIFIED | `UNRECORDED_OUTCOME_FLOOR_SECONDS` and `_unrecorded_outcome_boundary` present, substantive, wired into the single `job_outcome_unrecorded` emission site, and reproduced behaving correctly across ten cases. The round-4 HOLLOW rating on this file is lifted. |
| `dashboard/beacon/worker_main.py` | Worker composition root publishing durable job health | ⚠️ HOLLOW on the outcome mapping | The `False → failed` mapping and the new re-raise are both correct and reproduced. `_run_scheduled_discovery` / `_run_startup_discovery` (188-202) discard a genuine `'failed'` discovery outcome, so J7/J9 job health is fabricated. |
| `dashboard/app.py` | Production callback adapters reporting what the work did | ⚠️ HOLLOW on the failure direction | The empty-queue fix (1810, 1968) is correct and reproduced. `return True` at 1847 and 2004 discards a failure verdict the same function computed. |
| `tests/test_advanced_diagnosis_api.py` | Regressions driven by real collaborators | ⚠️ PARTIAL | 40 test methods; the three new/rewritten ones bind the real adapters and the real `run_worker` and are genuine (independently corroborated: they fail against the pre-change tree). No test drives either poller against work that genuinely fails; the floor's value is pinned by nothing. |
| `dashboard/beacon/repositories.py` | Bounded durable job-health writes | ✓ VERIFIED | Untouched. `_safe_job_error_class` still strips and truncates. |
| `.planning/REQUIREMENTS.md` | Traceability record matching verified reality | ✓ VERIFIED | Byte-unchanged since `b3879f3`. TEL-06 open in both halves. Nothing recorded Complete ahead of verification. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `dashboard/index.html` / `app.js` | `/advanced` | Link + theme round trip | ✓ WIRED | Named round-trip test green. |
| `dashboard/advanced.js` | `/api/advanced/current` | `fetch(..., {cache:'no-store'})` | ✓ WIRED | The only network call on the page. |
| real empty-queue path | durable `succeeded` row for J5/J6 | `return None` → `dispatch_callback`'s unchanged `if result is False:` | ✓ WIRED | Reproduction 1. |
| job's own recorded start | `job_outcome_unrecorded` promotion | `_unrecorded_outcome_boundary`, floor-clamped, cadence-agnostic | ✓ WIRED | Reproduction 2. Single call site, single emission site. |
| compound bookkeeping failure | `run_worker` control flow | `bookkeeping_error.work_error_class is not None` → bare `raise` | ✓ WIRED | Reproduction 3. Round 4's `NOT WIRED` is lifted. |
| a genuinely FAILED scan/preview verdict | durable `failed` row for J5/J6 | *nothing* — `return True` at app.py:1847 / 2004 discards it | ✗ **NOT WIRED** | Reproduction 4. The verdict is computed, durably written to the queue table, and then thrown away before job health sees it. |
| a genuinely FAILED discovery outcome | durable `failed` row for J7/J9 | *nothing* — `run_discovery`'s return discarded at worker_main.py:192 / 202 | ✗ **NOT WIRED** | Reproduction 5. |
| compound startup failure | the `/advanced` exceptions region | *nothing* — the row is left at `running` | ✗ NOT WIRED | Reproduction 3. Permitted by round-4 `missing` 6's "re-raise **or** surface"; recorded, not filed as the blocker. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| --- | --- | --- | --- | --- |
| `advanced.js` `renderHost` | `host.metrics.*`, `sample_ts`, `freshness` | `system_stats` via `compose_host_diagnosis` | Yes | ✓ FLOWING |
| `advanced.js` `renderServices` | `latency_ms`, `failure_class`, `state_duration_seconds`, tags, health rule | `services` / `service_checks` durable rows | Yes | ✓ FLOWING |
| `advanced.js` `formatServiceGapEvidence` | `collection_gaps` | `telemetry_streams` ⋈ `telemetry_coverage` | Yes | ✓ FLOWING |
| `advanced.js` exceptions region | `job_outcome_unrecorded` | `last_started_ts` + floor-clamped boundary | Yes — derived from the job's own start against a duration floor | ✓ FLOWING (round-4 HOLLOW lifted) |
| `advanced.js` exceptions region | `job_failed` on an idle poll | `background_job_health.state` | Yes — an idle poll now writes `succeeded` | ✓ FLOWING (round-4 HOLLOW lifted) |
| `advanced.js` Pipeline "Background jobs" | `job.state` / `job.error_class` for J5, J6, J7, J9 | `background_job_health` | **Row is real; the value written into it is fabricated on every failure path** | ⚠️ **HOLLOW** |
| `advanced.js` Pipeline "Background jobs" | `job.state` for S1 after a compound startup failure | `background_job_health` | Left at `running` for a job whose work failed | ⚠️ HOLLOW |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Idle production pollers record success | real adapters → `dispatch_callback` → `get_current_diagnosis` | `succeeded` ×2, zero `job_failed` | ✓ PASS |
| Running work inside a plausible duration promotes nothing | direct probe, 10 boundary cases | all correct, strict at 900 | ✓ PASS |
| A wedged cadence-less startup job is promotable | `S1 running 24h, cadence None` | one `job_outcome_unrecorded` | ✓ PASS |
| Compound work+write failure halts startup | real `run_worker` | condition escapes, `build_scheduler` never called, lease released | ✓ PASS |
| **A genuinely failed scan records a failure** | real adapter, queued scan, `worker_run_discovery` raises | `('succeeded', None, 100)` | ✗ **FAIL** |
| **A genuinely failed preview records a failure** | real adapter, queued preview, capture warns | `('succeeded', None, 100)` | ✗ **FAIL** |
| **A genuinely failed discovery records a failure (J7/J9)** | real `dispatch_callback`, `run_discovery → 'failed'` | `('succeeded', None, 100)` ×2 | ✗ **FAIL** |
| Compound startup failure names S1 on the workspace | real `run_worker` → `get_current_diagnosis` | `[]` | ✗ FAIL (permitted alternative; see gap count 2) |
| The floor's value is enforced by a test | mutate constant to 30, full suite | 296 passed / 413 subtests — unchanged | ✗ FAIL (WARNING) |
| Round-5's own new regressions | 5 named tests run together | 5 passed, 13 subtests | ✓ PASS |
| SC1-3 named regressions | 6 named tests | 6 passed, 55 subtests | ✓ PASS |
| Cross-module order independence | both orders of the two modules | 62 passed / 153 subtests each | ✓ PASS |

### Probe Execution

No `scripts/*/tests/probe-*.sh` exist in this repository and no PLAN declares a probe path. Probe
execution is **N/A** for this phase; the verification surface is the pytest suite plus the direct
reproductions above.

### Requirements Coverage

Statuses established by rounds 1-4 are preserved. Only evidence found this round can move one.

| Requirement | Source Plan | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| DIA-01 | 03-01, 03-05 | Open a dedicated advanced page from either theme | ✓ SATISFIED (Complete — established round 3) | SC1 verified; untouched this round; named route and round-trip tests green here. |
| DIA-02 | 03-02, 03-06 | Inspect current CPU, memory, disk, temperature, identity, sample time, freshness | ✓ SATISFIED (Complete — established round 3) | SC2 verified; untouched this round. |
| DIA-03 | 03-04, 03-11, 03-13 | Inspect every service's status, latency or failure class, state duration, criticality, tags, health rule | ✓ SATISFIED (Complete — established round 3) | SC3 verified; untouched this round; named browser regressions green here. |
| UX-02 | 03-05, 03-07 | Move between dashboard and advanced without losing theme | ✓ SATISFIED (Complete — established round 3) | SC1 evidence. |
| DIA-08 | 03-03, 03-09 | Effective monitoring settings and supported presentation/refresh/range/filtering preferences without remote controls | ⏸ DEFERRED to Phase 4 (established round 3) | Settings, refresh, presentation and filtering all present and read-only; the `range` clause is Phase 4 SC1, re-confirmed against ROADMAP.md this round. Unchanged. |
| TEL-06 | 03-03, 03-08, 03-12, 03-15, 03-17 | Effective retention, displayed resolution, database pressure, worker freshness, collection gaps, **and background-job health** | ✗ BLOCKED — **not promoted** | Five of six clauses verified truthful. Background-job health is not: J5, J6, J7 and J9 report `succeeded` for genuine work failures, reproduced on a real database with the failure durably recorded in the same dispatch. `.planning/REQUIREMENTS.md` correctly still records `[ ]` / `Gaps Found`; no change is warranted, and I am not making one. |

**Orphaned requirements: none.** All six IDs ROADMAP.md maps to Phase 3 are claimed by at least one
plan's `requirements` frontmatter. The `UI-01`…`UI-36` identifiers in plan frontmatter are
`03-UI-SPEC.md` contract IDs, not REQUIREMENTS.md requirements, and are correctly absent here.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| — | — | `TBD` / `FIXME` / `XXX` debt markers | — | **None found** across all five source files this round modified. |
| — | — | `TODO` / `HACK` / `PLACEHOLDER` / "not yet implemented" | — | **None found**. |
| `dashboard/app.py` | 1847, 2004 | Computed failure verdict discarded by an unconditional `return True` | 🛑 Blocker | Fabricated operator-facing success — see Gap count 1. |
| `dashboard/beacon/worker_main.py` | 188-202 | Callback outcome discarded; `None` returned from both the skip and the failure path | 🛑 Blocker | Fabricated operator-facing success for J7/J9 — see Gap count 1. |
| `tests/test_advanced_diagnosis_api.py` | 1222, 1288-1305 | Expectations derived from the constant under test | ⚠️ Warning | WR-01, reproduced. The floor is correct today and enforced by nothing. |
| `dashboard/beacon/worker_main.py` | 502-521 | Two-way classification of a three-way condition (`transition='failed'` with `work_error=None`) | ⚠️ Warning | WR-02. Latent only — all three startup handlers return truthy today. |
| `dashboard/advanced.js` | 184 | Copy directs the operator to a "configured cadence" that reads `Not scheduled` / `—` for the newly promotable jobs | ⚠️ Warning | WR-04, confirmed at `advanced.js:433`. A stale pointer, not a fabricated value. |
| `dashboard/app.py` | 1822; 1333-1334 | Lock/busy contention inferred as a job failure | ⚠️ Warning | Deferred-items row 8. Transient (self-clears next tick) but a real `Background job failed` card for a job that merely lost a lock. |
| `dashboard/app.py` | 1803-1810 | Comment says "empty durable queue" where `claim_scan` also returns `None` on a lost claim race and after an expiry sweep | ℹ️ Info | Review IN-01. `succeeded` is defensible for all three; the comment describes one. |
| `dashboard/app.py` | 1808-1809 | Shipped source comment references `deferred-items.md`, which the Dockerfile does not copy | ℹ️ Info | Review IN-02. Unresolvable for a maintainer reading inside the container. |
| `tests/test_advanced_diagnosis_api.py` | 706-709 | `addCleanup` registered after the assignment, contrary to `03-17-PLAN.md`'s own restatement | ℹ️ Info | Review IN-03, confirmed. Practical risk nil; `03-17-SUMMARY.md:176` "Total deviations: 0" is inaccurate on this point. |
| `tests/test_advanced_diagnosis_api.py` | 726 | `assertFalse(worker_main._worker_started)` cannot fail given the preceding assertion and the cleanup | ℹ️ Info | Review IN-04. I independently confirmed the lease *is* released on the re-raise path, but no test would catch a regression that stranded it. |
| `dashboard/beacon/repositories.py` | 142-148 | Global unscoped `LIMIT 49` behind a per-service number | ⚠️ Warning | Carried unchanged from round 4. Disclosed, so not an untruth. |

Everything in `deferred-items.md` was read first and is not re-argued here; rows 1-8 and the seventeen
carried-forward round-1 findings remain dispositioned as recorded.

### Human Verification Required

Both items are carried forward unchanged. **Neither has been performed on real hardware**, through five
rounds. Item 2 was recorded by round 4 specifically so a gap-closure round could not declare success
without it, and that condition is still unmet.

#### 1. Real collection gap and stale host on the target Pi

**Test:** On the target Pi, open `/advanced` while a real collection gap is active and while host
evidence is stale.
**Expected:** The workspace shows the open gap and the stale host as real, correctly labelled
exceptions — and shows no resolved or retention-expired interval as an open actionable gap.
**Why human:** Re-declared as human judgment in `03-08-SUMMARY.md`, `03-14-PLAN.md` and
`03-17-PLAN.md`'s own human-check blocks. The synthetic reproductions establish the server contract;
only a person on the hardware can establish that it reads correctly.

#### 2. Idle-Pi Overview after the fix

**Test:** Start the worker on the target Pi, leave the system idle for one minute, then open
`/advanced` and read the Overview "Active exceptions" region.
**Expected:** No `Background job failed` card for J5 or J6, and no `Background job outcome not recorded`
card for any job that is simply working.
**Why human:** Reproduction 1 proves this on a real SQLite database through the real production
adapters and it now passes there. The operator's own idle Pi is the surface the criterion is written
about.

### Gaps Summary

**This round genuinely closed what it was asked to close.** All seven of round-4's `missing` items are
shut, and I established each one by running production code against a real database rather than by
reading `03-17-SUMMARY.md`. The two permanent `Background job failed` cards an idle Pi displayed are
gone. The promotion that fired on a J6 preview nine seconds into legitimate work no longer fires — nor
does it fire on a 179-second discovery or a 180-second startup scan, two harder cases I added myself. A
wedged S1 is promotable for the first time. A compound startup failure escapes `run_worker`, never
reaches `build_scheduler`, and strands no worker state. Both round-4 defects that were reachable in
production are dead. That is the largest single-round improvement this surface has had, and the new
tests are genuine regressions rather than tautologies.

**And the truth is still false, in the direction nobody asked about.** `worker_process_scan_requests`
decides a scan failed, writes `status='failed'` and the error text into `scan_requests`, and then
returns `True`. `worker_process_preview_requests` does the same for a failed capture.
`_run_scheduled_discovery` and `_run_startup_discovery` throw away a `run_discovery` result that
literally reads `'failed'`. `dispatch_callback` maps all four to `succeeded`. I reproduced every one on
a real database: the queue tables record the failure and the operator's Pipeline reads
`J5 — succeeded`, `J6 — succeeded`, `J7 — succeeded`, `J9 — succeeded`, `error_class` null,
`last_success_ts` set, zero exceptions. Four of the eleven promotable jobs — both queue pollers and
both discovery jobs — cannot report a failure at all.

**Why this is a gap and not a scoping note.** It is pre-existing (`82e3eaa`, 2026-08-06) and it is not
in round-4's `missing` list, so plan 03-17 was not commissioned to fix it and did not fail to. But the
failed truth is *"Background-job health reported to the operator reflects what the job actually did"*,
and it is symmetric. Round 4 established the precedent directly: it credited 03-02's pre-existing
`False` mapping as keeping this same truth false. A fabricated success falsifies the truth exactly as a
fabricated failure does, and it is the quieter of the two — a false alarm is noisy and gets
investigated; a false all-clear is silent. An operator who triggers a manual scan that fails is told it
succeeded.

**What I did not treat as blocking.** WR-01 is real and I reproduced it — a 30-second floor leaves the
suite at exactly 296/413 — but the shipped value is 900 and I verified the boundary behaves correctly
at that value, so it is an enforcement hole recorded in `missing`, not a live untruth. WR-02 is a real
classification hole that no shipped startup handler can reach. WR-03 is a genuine residual, but round-4
`missing` item 6 explicitly permitted re-raise *or* durable surfacing, so the commissioned item is
closed. The two transient contention-as-failure paths are deliberately and defensibly deferred in row 8.

**Consequence.** Success Criterion 4 is FAILED and TEL-06 stays BLOCKED and unpromoted. Four of the
phase's six requirements are satisfied and one is a legitimate Phase 4 deferral; the phase's other three
criteria hold and were re-checked, not assumed. The remaining work is narrow — return the verdict each
poller already computed instead of a constant, make the two discovery handlers honour the vocabulary
this round declared, and add a regression that drives the real adapters against work that genuinely
fails. That last one is the point: this phase has now been passed green four times by tests that
exercised only the half of the behaviour someone thought to ask about.

---

_Verified: 2026-08-19T11:44:11Z_
_Verifier: Claude (gsd-verifier), re-verification round 5_
