---
phase: 03-advanced-current-diagnosis
verified: 2026-08-19T15:50:55Z
status: gaps_found
score: 3/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
unverified_prohibitions: 5
re_verification:
  round: 7
  previous_status: gaps_found
  previous_score: 3/4
  gaps_closed:
    - "Round-5 `missing` 1 — Return the verdict the poller already computed. CLOSED and independently reproduced closed. `worker_process_scan_requests` now ends `return status == 'completed'` (app.py:1868). Driving the REAL `appmod.worker_process_scan_requests` through the REAL `dispatch_callback` on a real SQLite database: `run_discovery` RAISING -> dispatch `False`, J5 durable health `{'state': 'failed', 'last_success_ts': None, 'error_class': 'CallbackReturnedFalse'}`, `scan_requests` row `{'status': 'failed', 'error': 'boom'}`. `run_discovery` returning the literal `'failed'` -> the same durable `failed` J5 row. The `except Exception` path the round-5 gap named explicitly is the one exercised in the first case."
    - "Round-5 `missing` 2 — J7/J9 honour the vocabulary. CLOSED and reproduced closed, now by MEMBERSHIP rather than by exclusion. `_discovery_outcome_verdict` (worker_main.py:189-206) returns True for `'completed'|'busy'`, False for `'failed'`, and raises `ValueError` otherwise. Reproduced through the real `dispatch_callback`: `'failed'` -> `{'J7': failed/CallbackReturnedFalse}` and `{'J9': failed/CallbackReturnedFalse}`; `'busy'` -> both `succeeded`; an unrecognised literal -> `ValueError: run_discovery returned an unknown outcome: 'an_unrecognised_literal'`. The genuine-skip path still returns `None` without calling `run_discovery`."
    - "Round-5 `missing` 3 — A regression driven by work that GENUINELY FAILS. CLOSED. `test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed` (tests/test_advanced_diagnosis_api.py:307) binds `self.appmod.worker_process_scan_requests` / `worker_process_preview_requests` — the exact two callables `dashboard/worker.py:34-35` wires in — makes `run_discovery` actually raise, and asserts the durable J5 row reads `failed`. Ran green here. Its J6 half asserts `succeeded` by design (the user's round-6 decision), which is where gap 1 below now lands."
    - "Round-5 `missing` 6 — the two deferred transient contention sites. CLOSED. `worker_process_scan_requests`'s discovery-busy branch now `return None` (app.py:1837) and `_legacy_do_uptime_check` under `_uptime_lock` contention now `return None` (app.py:1343). `dispatch_callback`'s unchanged `if result is False:` mapping therefore records `succeeded`, not a fabricated `('failed','CallbackReturnedFalse')` card. `deferred-items.md` row 9 records the closure and names the two pinning regressions."
    - "Round-6 WR-04 — a lost lease on the discovery-busy branch. CLOSED at the site named. `raise beacon_queues.LeaseLost('worker scan lease was lost')` is the first statement in the busy branch (app.py:1831), precedes `requeue_scan_for_worker` (app.py:1834-1836), and sits inside the outer `try` so `finally: heartbeat.stop()` still runs."
    - "Round-6 CR-01 (`return not warning`) — the conflation is gone. Confirmed by reading the code: an ordinary per-service capture condition no longer produces a J6 `job_failed`. The per-request verdict is intact — `finish_preview_for_worker_in_transaction(..., status='failed' if warning else 'completed', error=warning)` at app.py:2010-2013 and `preview_complete` carrying `'success': not bool(warning)` at app.py:2018-2021. Reproduced: a broken capture still writes `preview_requests {'status': 'failed', ...}`. This closure is what gap 1 below finds went one step too far."
  gaps_remaining:
    - "The failed truth is STILL the background-job-health clause of Success Criterion 4, for the sixth consecutive round — now narrowed to exactly one job. J5, J7 and J9 are genuinely correct in both directions and I reproduced each. J6 is the sole remaining hole: no fault of the capture machinery J6 itself owns can ever produce a `failed` J6 row."
  regressions:
    - "dashboard/app.py:2038 — INTRODUCED BY THIS PHASE'S OWN ROUND-6 FIX (commit 8320366, `fix(03-20): decouple J6's job outcome from the per-service preview warning`). `worker_process_preview_requests` now returns `True` unconditionally. Reproduced by me on a real SQLite database through the real production adapter and the real `dispatch_callback`, by BOTH the reviewer's injected path and the fully realistic production path — see gap 1."
    - "dashboard/beacon/diagnosis.py:56 — INTRODUCED BY THIS ROUND (commit df6f947). The widened `_unrecorded_outcome_boundary` floor is global, so raising `DISCOVERY_TIMEOUT_SECONDS` lengthens the wedged-job blind window for jobs that never run discovery. Measured directly: `f(5, 3600) -> 3660` for J1's 5-second heartbeat, against the 900 the constant guarantees. See gap 2."
  newly_found:
    - "CR-01 is BROADER than 03-21-REVIEW.md reported. The reviewer reproduced it by forcing the `fetch_thumbnail` collaborator to raise, reaching `_legacy_refresh_service_preview`'s blanket `except Exception` (app.py:982). I reproduced the identical outcome WITHOUT that blanket handler, on the ordinary already-caught production path: `_legacy_screenshot_service`'s own `except Exception as exc: return None, None, _thumb_error(exc)` (app.py:930-932) converts a `_get_browser()` failure — Chromium missing, OOM-killed, `/dev/shm` exhausted — into `thumb_error`, which becomes the warning `'thumbnail refresh failed'`. J6 records `succeeded` either way. Narrowing the blanket handler at app.py:982, which the review offers as the less invasive of its two fixes, would therefore NOT close this. Any fix must be made at the `worker_process_preview_requests` return site or by giving the browser lifecycle its own signal."
  over_credit_corrected:
    - "03-20-SUMMARY.md and 03-21-SUMMARY.md are each accurate about what they built, and both correctly declined to promote TEL-06. But the ROADMAP entry for 03-20 describes it as closing CR-01 'per the user's decision', and the user's decision as recorded in 03-19-REVIEW.md CR-01 was that a PER-SERVICE capture condition must not become J6's verdict. The implementation discarded EVERY warning, including the class describing J6's own machinery, which the decision did not authorise. Crediting the truth on the decision's wording rather than on the code's reach would repeat the exact error rounds 3-6 each made at a different polarity."
    - "03-21-REVIEW.md IN-04 is confirmed independently: of the round's five new assertions, `a_busy_discovery_lock_is_recorded_as_succeeded` and the `last_uptime_check` assertion both pass against the pre-fix tree, so the round added four genuine regressions, not five. Recorded so the coverage claim is not overcounted."
gaps:
  - truth: "Background-job health reported to the operator reflects what the job actually did — specifically for J6, the preview poller."
    status: failed
    reason: "J6's durable `background_job_health` row cannot report a fault of the capture machinery J6 itself owns. `worker_process_preview_requests` ends in an unconditional `return True` (app.py:2038), and every fault in the capture path is converted to the `warning` string that `return True` discards — either by `_legacy_screenshot_service`'s own `except Exception` (app.py:930-932) or by `_legacy_refresh_service_preview`'s blanket `except Exception` (app.py:982-984). REPRODUCED BY ME on a real SQLite database created by the project's own `tests.helpers.load_app`, through the real `appmod.worker_process_preview_requests` and the real `worker_main.dispatch_callback`, in two independent ways. CASE A (the reviewer's path, `fetch_thumbnail` raising `ImportError(\"Playwright's browser executable doesn't exist\")`): dispatch `True`; J6 durable health `{'state': 'succeeded', 'last_success_ts': 100, 'error_class': None}`; `preview_requests` `{'status': 'failed', 'error': 'title refresh failed (exception); thumbnail refresh skipped'}`. CASE B (the ordinary production path, `_get_browser()` raising `RuntimeError('chromium not installed')`, caught by the screenshot function's OWN handler and never reaching the blanket one): dispatch `True`; J6 durable health `{'state': 'succeeded', 'last_success_ts': 100, 'error_class': None}`; `preview_requests` `{'status': 'failed', 'error': 'thumbnail refresh failed'}`. In both cases `get_current_diagnosis` emitted `['host_freshness', 'worker_freshness']` and ZERO `job_failed` — nothing names J6. J6 declares `browser_resource_lifecycle` in its `effect_surfaces` and is the sole occupant of the `screenshots` executor (worker_main.py:89, worker_main.py:461), so the browser is unambiguously the job's own machinery. Enumerating the function, the only reachable `failed` transitions left for J6 are a SQLite error inside `_worker_write_transaction` or inside `claim_preview_for_worker`. A permanently dead browser reads `succeeded` at 0.5 Hz forever. This is the same fabricated-success class TEL-06 exists to remove, relocated rather than removed, and it was introduced by this phase's own round-6 fix (commit 8320366). SECOND, LOWER-SEVERITY COUNT — J5 still decides the discovery outcome by exclusion. `worker_process_scan_requests` computes `status = 'failed' if outcome == 'failed' or state.get('last_error') else 'completed'` (app.py:1844); the legacy `process_scan_requests` repeats it at app.py:1906. Reproduced with `run_discovery` returning `'an_unrecognised_literal'`: dispatch `True`, J5 durable health `{'state': 'succeeded', 'last_success_ts': 100, 'error_class': None}`, `scan_requests` `{'status': 'completed', 'error': None}` — the operator's own manual scan reported completed having done nothing, on two durable surfaces. `_legacy_run_discovery` returns only the three contract literals today (app.py:1325, app.py:1327), so this is a latent contract inconsistency rather than a live untruth; it is recorded inside this gap because it is the identical fail-open shape J7/J9 were converted away from in the same round, leaving one of the three consumers behind."
    artifacts:
      - path: "dashboard/app.py"
        issue: "Line 2038: `return True` is unconditional, and the comment above it at lines 2028-2037 asserts a safety property the code does not have — 'A genuine J6 job fault ... already propagates as LeaseLost above or as an uncaught exception dispatch_callback converts to a real failed row.' Reproduced false: a `_get_browser()` failure is caught at app.py:930-932 and a raise anywhere else in the capture path is caught at app.py:982, so neither ever reaches `worker_process_preview_requests` as an exception."
      - path: "dashboard/app.py"
        issue: "Lines 930-932 and 982-984: two independent blanket `except Exception` handlers each convert a fault of the browser subsystem into the same `warning` string the previewed service's own unhealthiness produces. Because both exist, narrowing only line 982 (the less invasive of 03-21-REVIEW.md's two proposed fixes) would leave the defect fully live via line 930."
      - path: "dashboard/app.py"
        issue: "Lines 1844 and 1906: the discovery outcome is resolved by exclusion in both scan pollers, so any literal outside `'busy'|'completed'|'failed'` takes the `'completed'` branch. `worker_main._discovery_outcome_verdict` (worker_main.py:189) exists and does exactly the right thing by membership, but is not reachable from `dashboard/app.py`."
      - path: "tests/test_advanced_diagnosis_api.py"
        issue: "No test drives the preview poller against a failure of the CAPTURE MACHINERY as distinct from a failure of the previewed service. `test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed` (line 307) and `test_a_titleless_service_never_fails_j6s_job_health` (line 389) both assert J6 `succeeded` for a warning, which is correct for the service-condition case and is exactly what pins the machinery case shut. `test_the_real_discovery_dispatch_honours_the_return_value_vocabulary` loops `for job_id in ('J7', 'J9')` and therefore cannot see the J5 fail-open path."
    missing:
      - "Give J6 a job-owned failure signal that `warning` cannot erase. Keep `return True` for every per-service condition (the user's round-6 decision stands), and make a fault of the capture machinery a distinct fact. Because BOTH app.py:930-932 and app.py:982-984 erase it, the fix must either raise a dedicated condition (e.g. `PreviewCaptureUnavailable`) from `worker_process_preview_requests` when the capture path reports a machinery-class error, or have `_refresh_service_preview` return that class as a seventh value separate from `warning`. Narrowing app.py:982 alone is NOT sufficient — verified."
      - "Add a regression that drives the REAL `worker_process_preview_requests` through the REAL `dispatch_callback` with `_get_browser` raising (not `fetch_thumbnail`, and not `_legacy_refresh_service_preview` stubbed), asserting J6's durable `background_job_health` row reads `failed` while `preview_requests` still reads `failed` with its own text — so the distinction the comment at app.py:2028-2037 asserts is enforced rather than described. A second subtest must keep the titleless/offline-service case at `succeeded`, so the two directions are pinned together and neither can be closed by breaking the other."
      - "Route J5 through the same membership check the same round gave J7/J9: move `_discovery_outcome_verdict` somewhere both `dashboard/app.py` and `dashboard/beacon/worker_main.py` can import, and apply it at app.py:1844 (and at the legacy sibling app.py:1906). Extend the vocabulary regression with a J5 unknown-literal subtest asserting `scan_requests.status == 'failed'` and a `failed` J5 durable row."
  - truth: "The `job_outcome_unrecorded` promotion floor — the only remaining signal for a permanently wedged `_scan_lock` / `_uptime_lock` — is not lengthened by a setting unrelated to the wedged job."
    status: failed
    reason: "`_unrecorded_outcome_boundary` computes `floor = max(UNRECORDED_OUTCOME_FLOOR_SECONDS, int(discovery_timeout_seconds) + 60)` once (diagnosis.py:56) and `compose_active_exceptions` applies it to EVERY job in `pipeline['jobs']` (diagnosis.py:479-484), not only to the jobs that run under the discovery budget. `DISCOVERY_TIMEOUT_SECONDS` is `_positive_int(..., 180)` with no upper bound (config.py:205). MEASURED DIRECTLY against the live function: `f(5, 180) -> 900`, `f(5, 1200) -> 1260`, `f(5, 3600) -> 3660`; `f(2, 3600) -> 3660`; `f(None, 3600) -> 3660`. So an operator who raises the discovery timeout to an hour silently extends the blind window for a WEDGED HEARTBEAT (J1, 5 s cadence) from 15 minutes to 61 minutes, and equally for J2/J3/J4/J5/J6 and every startup callback. Round 5 established `job_outcome_unrecorded` as the only remaining signal for those wedges; this round lengthened it by a knob whose name has nothing to do with them. The new subtests exercise only J9, so nothing in the suite detects the collateral. SECOND COUNT, same line — the new input both coerces and can raise, breaking the module's own stated strict-integer discipline. Measured: `f(5, None) -> TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'`; `f(5, 900.9) -> 960` (silently truncated); `f(5, True) -> 900` (bool accepted); `f(5, '900') -> 960` (string accepted). The `TypeError` is raised inside `compose_active_exceptions`, i.e. inside `get_current_diagnosis`, so one malformed value would take out the ENTIRE `/advanced` payload — `recovery_required`, host freshness and every unrelated exception — rather than degrading one promotion. Production `Settings` always yields an int (`_positive_int` falls back to its default on `TypeError`/`ValueError`, confirmed at config.py:205), so this half is a robustness and consistency defect today, not a live crash. It is recorded because this is now the only input to a module documented as a 'safety-first deterministic exception projection' that can abort it, and because the sibling line 57 in the very same function uses `type(cadence_seconds) is int` and the comment beneath it calls that discipline 'reused rather than a second convention'."
    artifacts:
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Line 56: the widened floor is computed unconditionally and line 479-484 applies it to every job id. There is no notion of which jobs actually run discovery, so J1's guarantee is now a function of `DISCOVERY_TIMEOUT_SECONDS`."
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Line 56: `int(discovery_timeout_seconds)` coerces where every other numeric input in the module guards (`type(job.get('last_started_ts')) is int`, `type(now) is int` at lines 478-480; `type(cadence_seconds) is int` at line 57). It accepts `float`, `bool` and `str`, and raises `TypeError` on `None` from inside `get_current_diagnosis`."
      - path: "tests/test_advanced_diagnosis_api.py"
        issue: "The new widened-floor subtests cover J9 only. No assertion pins a J1 (or any non-discovery) row against the constant, so the collateral widening is invisible to the suite; and no assertion covers a malformed `discovery_timeout_seconds`."
    missing:
      - "Apply the widened floor only to the jobs that actually run under the operator's discovery budget (J5, J7, J9), and leave every other job on `UNRECORDED_OUTCOME_FLOOR_SECONDS`. Pass the job id into `_unrecorded_outcome_boundary` or select the floor at the call site."
      - "Guard instead of coerce, and pick the safe direction on malformed input: `floor = UNRECORDED_OUTCOME_FLOOR_SECONDS` then widen only `if type(discovery_timeout_seconds) is int and discovery_timeout_seconds > 0`. This restores the module's single stated convention and removes its only input that can abort the whole diagnosis payload."
      - "Add a subtest asserting a J1 row aged past 900 s still promotes at `discovery_timeout_seconds=3600`, and a subtest asserting a malformed `discovery_timeout_seconds` degrades one promotion rather than raising out of `get_current_diagnosis`."
deferred:
  - truth: "Operator can change supported *range* preferences in the advanced workspace (the `range` clause of Success Criterion 4 and of DIA-08's requirement text)."
    addressed_in: "Phase 4"
    evidence: "Re-confirmed against ROADMAP.md this round: Phase 4 success criterion 1 is 'Operator can choose shared ranges from one hour through 90 days or a validated custom range within retained history.' Re-confirmed against the markup this round: `dashboard/advanced.html` exposes refresh interval, refresh-now, service search, four service filters, clear-all-filters, reset order and collapse details — no range control. Carried forward unchanged from rounds 3, 4 and 5. A deferral, not a gap; no closure plan should be written for it. DIA-08 stays DEFERRED."
  - truth: "The five Info findings 03-19-REVIEW.md raised in round 6, plus the six 03-21-REVIEW.md raised in round 7."
    addressed_in: "deferred-items.md"
    evidence: "None is named by any gap above and none is an operator-facing untruth. 03-21-REVIEW.md IN-06 correctly observes that round 6's Info set is unchanged in the diff. These belong in `deferred-items.md` as explicit carry-forward rows rather than lapsing silently between rounds — recorded here so the next planner files them, not so a closure plan is written for them."
human_verification:
  - test: "On the target Pi, open /advanced while a real collection gap is active and while host evidence is stale."
    expected: "The workspace shows the open gap and the stale host as real, correctly labelled exceptions — and shows no resolved or retention-expired interval as an open actionable gap."
    why_human: "Carried forward from all six previous reports and re-declared as human judgment in 03-08-SUMMARY.md, 03-14-PLAN.md and 03-17-PLAN.md's own human-check blocks. Still NOT performed on real hardware. Operator trust in the rendered snapshot cannot be asserted programmatically."
  - test: "On the target Pi, start the worker and leave the system idle for one minute, then open /advanced and read the Overview 'Active exceptions' region."
    expected: "No 'Background job failed' card for J5 or J6, and no 'Background job outcome not recorded' card for any job that is simply working."
    why_human: "Recorded by round 4 specifically so a gap-closure round could not declare success without it. Still NOT performed on real hardware. My reproductions establish it on a real SQLite database through the real production adapters and it passes there; the operator's own idle Pi is the surface the criterion is written about. Carried forward unchanged."
  - test: "On the target Pi with Chromium/Playwright deliberately unavailable (rename the browser executable, or unset the download path), leave the worker running for two minutes, then open /advanced and read the Pipeline region."
    expected: "Something in the workspace tells the operator the preview subsystem is broken. Today J6 reads 'succeeded' and only the per-service preview cells carry the evidence — the operator's judgement on whether that is sufficient disclosure is the decision this gap turns on."
    why_human: "New this round. Gap 1 is a judgement about how much of J6's own machinery must be visible on the job-health surface versus on the per-service surface. My reproduction establishes the FACTS (J6 reads succeeded, zero job exceptions name J6, preview_requests reads failed); whether the operator considers the per-service evidence adequate disclosure is not programmatically decidable, and the same user decision already redirected this behaviour once in round 6."
prohibitions:
  - source: "03-08-PLAN.md"
    statement: "MUST NOT present resolved, retention-expired, or otherwise inferred evidence to the operator as a current, open, actionable fault -- every operator-facing open/actionable/kind label must be derivable from the durable row it describes, never from a neighbouring row or a stream-level fact."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: violated
    detail: "PROMOTED FROM VIOLATED TO UPHELD this round, on my own reproduction. Round 5's two remaining violations were the two transient contention sites, and both are closed: `worker_process_scan_requests`'s discovery-busy branch returns `None` (app.py:1837) and `_legacy_do_uptime_check` returns `None` under `_uptime_lock` contention (app.py:1343), so `dispatch_callback`'s unchanged `if result is False:` mapping records `succeeded` rather than a `Background job failed` card for a run that merely lost a lock. Reproduced on the empty-queue path (`J5 -> None/succeeded`, `J6 -> None/succeeded`) and confirmed by reading both sites. The idle-Pi and in-progress-run inferences closed in earlier rounds remain closed. This prohibition is about presenting an inferred fault the durable row does not support; nothing in either gap above does that. NOT a green light for the phase — gap 1 is the OPPOSITE failure (a real fault suppressed), which is the next prohibition's territory."
  - source: "03-08-PLAN.md"
    statement: "MUST NOT suppress a genuine collection failure while narrowing false positives -- restricting promotion by reason must never cause a real collection_gap, or a reason value the code does not recognise, to go unreported to the operator."
    verification: judgment
    llm_judge_verdict: violated
    flagged: true
    previous_verdict: violated
    detail: "STILL VIOLATED, and the violation is now precisely the phrase 'while narrowing false positives'. UPHELD on the collection-gap surface (re-checked, unchanged, `test_service_detail_gap_evidence_reads_as_operator_copy` green here). UPHELD on background-job health for J5, J7 and J9 — all four directions reproduced correct this round. VIOLATED for J6: round 6 narrowed a genuine false positive (a per-service warning failing J6) and in doing so suppressed a genuine job failure (a total failure of the capture machinery J6 owns), reproduced twice on a real database with `preview_requests.status='failed'` written in the very same dispatch that records J6 `succeeded`. Also violated in the latent direction at J5's `app.py:1844`, where 'a reason value the code does not recognise' — an outcome literal outside the contract — is reported as `completed`, the exact fail-open shape the sibling `_discovery_outcome_verdict` was written to remove. This is the fourth consecutive round in which the remedy for one polarity of this prohibition created the other polarity somewhere adjacent."
  - source: "03-09-PLAN.md"
    statement: "MUST NOT let automatic background refresh silently override an operator's explicit presentation choice, and MUST NOT present a machine identifier or a placeholder as the operator's primary safety evidence when the server supplied real evidence."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "`git diff 1272951..HEAD -- dashboard/` touches only `app.py`, `beacon/diagnosis.py` and `beacon/worker_main.py`; `dashboard/advanced.js` is byte-unchanged across both rounds 6 and 7, so sort persistence, the refresh loop and every `textContent` insertion are untouched. `test_every_emitted_exception_kind_renders_operator_copy`, `test_unmeasured_latency_and_duration_never_rank_or_read_as_zero` and `test_service_detail_gap_evidence_reads_as_operator_copy` all pass here (5 tests / 55 subtests green). `advanced.js` still makes exactly one network call — `fetch('/api/advanced/current', {cache: 'no-store'})` at line 58 — so the no-remote-controls clause of SC4 holds. The stale `job_outcome_unrecorded` evidence pointer noted in round 5 is unchanged and remains a Warning, not a violation."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT let test scaffolding mutate process-global state so that suite greenness depends on execution order."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UPHELD. Every new patch in both rounds is a `mock.patch.object` context manager that unwinds on the raising path, and `test_a_busy_discovery_lock_with_a_lost_lease_does_not_report_success` registers `self.addCleanup(self._reset_worker_globals)` (tests/test_advanced_diagnosis_api.py:656) because the path it drives reaches `stop_worker`. That cleanup is necessary and correct — but see the WARNING recorded below: the need for it is itself evidence of a new failure mode, which is a design concern rather than a scaffolding one. The orchestrator's cross-file run (303 passed / 426 subtests, plus a 16-file prior-phase regression gate at 221 passed / 254 subtests) shows no order dependency."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT record a requirement, plan, or phase as complete on the strength of an implementation claim rather than independent verification -- the traceability table is the project's own memory of what is actually true."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UPHELD, and the correct decision was made twice. `git diff 43c3727 HEAD -- .planning/REQUIREMENTS.md` is empty: line 25 still reads `- [ ] **TEL-06**` and line 123 still reads `| TEL-06 | Phase 3 | Gaps Found |`. Both 03-20 and 03-21 declared in their own frontmatter that they MUST NOT promote TEL-06 and left the decision to this verifier. I am that verifier and I am NOT promoting it: my own reproduction of gap 1 does not support the claim that the operator can see truthful background-job health. The record continues to under-credit rather than over-credit, which remains the correct failure direction."
---

# Phase 3: Advanced Current Diagnosis Verification Report

**Phase Goal:** The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.

**Verified:** 2026-08-19T15:50:55Z
**Status:** gaps_found
**Re-verification:** Yes — round 7, after gap-closure plans 03-20 and 03-21.

This report supersedes the round-5 `03-VERIFICATION.md` and preserves the requirement-status history
rounds 1-5 established. Nothing below is taken from `03-20-SUMMARY.md`, `03-21-SUMMARY.md`, or
`03-21-REVIEW.md`. Every claim is a line of code I read or a command I ran in my own process against a
real SQLite database created by the project's own `tests.helpers.load_app`. Where my finding differs
from the reviewer's, or extends it, the difference is stated explicitly.

## The short version

**Both plans did what they were commissioned to do, and I reproduced each closure rather than reading
the summaries.** A genuine J5 discovery failure — raised or returned — now reaches the operator as a
durable `failed` row. J7 and J9 decide by membership against the documented contract and raise loudly on
an unrecognised literal. The two transient lock-contention sites that showed a `Background job failed`
card for a run that merely lost a lock are closed. A lost lease on the discovery-busy branch raises
instead of reporting a clean poll. Five of round 5's six commissioned items, and four of round 6's five
review findings, are genuinely closed at the sites they name.

**The truth is still false, and for the sixth consecutive round it is false in the direction the
previous round's own remedy created.** Round 6 was asked to stop a per-service preview warning from
becoming J6's job verdict. It did — by discarding the warning entirely. Since `_legacy_screenshot_service`
and `_legacy_refresh_service_preview` each convert every fault of the browser subsystem into that same
warning string, J6 can no longer report any fault of the machinery it owns. I reproduced a totally broken
browser recording J6 `succeeded` on a real database through the real adapters, twice, by two different
routes — one of which the review did not identify and which its own less-invasive proposed fix would not
close.

**The scope of the failure has narrowed sharply and this is worth stating plainly.** Round 5 found four
of eleven promotable jobs fabricating success. Round 7 finds one. Three of the four are genuinely and
verifiably fixed. But Success Criterion 4 names background-job health as one of six things the operator
must be able to view truthfully, and a surface that reports `succeeded` at 0.5 Hz forever while the
subsystem it owns is dead is not truthful about that job.

## Independent confirmation of 03-21-REVIEW.md

The task asked me to confirm or refute the review's CR-01 against the live source before letting it drive
the verdict. I ran my own reproductions.

| Review finding | My verdict | How I established it |
| --- | --- | --- |
| **CR-01** — `return True` leaves J6 with no job-health signal for a total capture failure | ✓ **CONFIRMED, and broader than reported** | Reproduced twice on a real DB through the real adapter and the real `dispatch_callback`. The review's route (`fetch_thumbnail` raising → blanket handler at app.py:982) reproduces. So does a route the review did not name: `_get_browser()` raising, caught by `_legacy_screenshot_service`'s OWN handler at app.py:930-932, which never touches the blanket one. The review's less-invasive proposed fix (narrowing app.py:982) would therefore leave the defect fully live. |
| **WR-01** — J5 still decides discovery outcome by exclusion | ✓ **CONFIRMED, severity qualified** | Reproduced: `run_discovery` returning an unrecognised literal gives `J5 -> succeeded` and `scan_requests -> completed`. But `_legacy_run_discovery` returns only the three contract literals (app.py:1325, 1327), so this is a latent contract inconsistency, not a live untruth. Recorded inside gap 1 rather than as its own blocker. |
| **WR-02** — the widened floor is global | ✓ **CONFIRMED** | Measured directly: `f(5, 3600) -> 3660` for J1's 5-second heartbeat, `f(2, 3600) -> 3660` for the pollers, against the 900 the constant guarantees. This is a behavioural regression introduced by this round. Raised to its own gap. |
| **WR-03** — the busy-branch `LeaseLost` escalates a per-request condition to a worker shutdown | ⚠️ **CONFIRMED as a design concern, not a gap** | Confirmed by reading `dispatch_callback` (worker_main.py:353-357) and `renew_scan_lease`'s `WHERE ... deadline_ts > ?` (queues.py:464-466). A request-level deadline expiry does reach `stop_worker()`. Recorded as a Warning: reachability requires a sub-millisecond busy return racing a ≥1 s first renewal, and the previous behaviour (`return None`) was itself the fabricated success round 6 asked to remove. Not a blocker, but it is a new failure mode on a path that previously could not stop the worker. |
| **WR-04** — `int(discovery_timeout_seconds)` breaks the module's type discipline | ✓ **CONFIRMED, live-crash risk refuted** | Measured: `f(5, None) -> TypeError`, `f(5, 900.9) -> 960`, `f(5, True) -> 900`, `f(5, '900') -> 960`. Confirmed at config.py:205 that `_positive_int` always yields an int in production, so this is robustness/consistency, not a live crash. Folded into gap 2 as its second count. |
| **WR-05** — the compensating uptime disclosure needs an exact 600 s boundary | ⚠️ **PLAUSIBLE, not independently reproduced** | Confirmed the code facts (`>=` at telemetry.py:683, `cadence_seconds=300` at app.py:1416, `misfire_grace_time=60`). Whether scheduler jitter actually swallows a single skipped J3 sweep depends on live executor contention I did not reproduce. Recorded as a Warning; the comment at app.py:1334-1343 should state the narrower true claim. |
| **IN-04** — the round's regression coverage is 4 new pins, not 5 | ✓ **CONFIRMED** | The `busy` subtest passes under the old `return outcome != 'failed'` (`'busy' != 'failed'` is `True`), and the `last_uptime_check` assertion accompanies a comment-only change. Recorded in `over_credit_corrected`. |

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Operator can open the dedicated advanced page from the dashboard and return without losing theme. | ✓ VERIFIED | Behavior-dependent (a navigation round-trip with state), so proven by named test rather than presence: `test_theme_or_return_round_trip_preserves_theme_and_consumes_scroll_once` and `test_production_routes_serve_the_advanced_document_bundle` run green here. `git diff 1272951..HEAD -- dashboard/` shows `advanced.js`, `advanced.html` and `advanced.css` untouched across both rounds. |
| 2 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, and host freshness. | ✓ VERIFIED | Untouched this round. `test_host_tracer_returns_one_current_snapshot_with_server_freshness` green here. `GET /api/advanced/current` served a live `host` block carrying identity, all four metrics, `sample_ts` and `freshness` in my own probe. |
| 3 | Operator can inspect every current service's status, latency or failure class, state duration, criticality, tags, and effective health rule. | ✓ VERIFIED | Untouched this round. `test_unmeasured_latency_and_duration_never_rank_or_read_as_zero` and `test_service_detail_gap_evidence_reads_as_operator_copy` green here (5 tests / 55 subtests across the SC1-3 set). |
| 4 | Operator can view truthful retention, resolution, database pressure, worker freshness, collection gaps, and **background-job health**, and change presentation/refresh/filtering preferences without remote controls. | ✗ **FAILED** | Five of six clauses re-checked truthful against a live payload: `retention {'five_minute_days': 30, 'point_budget': 2048, 'raw_days': 7, 'retention_days': 90}`, `resolution_policy`, `database_pressure {'state': 'normal', ...}`, `worker {'expected_cadence_seconds': 5, 'freshness': ..., 'heartbeat_ts': ..., 'lease_until': ...}`, `gaps {'count': 0, 'truncated': False}`. The no-remote-controls clause holds — `advanced.js` still makes exactly one network call, a GET. **Background-job health is not truthful for J6**, reproduced below. |

**Score:** 3/4 roadmap success criteria verified (0 present-but-behavior-unverified — every truth above was
exercised by a named test or by a direct reproduction, never by symbol presence).

> **On Success Criterion 4, sixth round.** The scope has genuinely collapsed: round 5 found four of
> eleven promotable jobs fabricating success; this round finds one. But the *shape* has not changed once
> in four rounds. Each round closes the polarity it was commissioned to close and creates or leaves the
> mirror polarity somewhere adjacent — round 3 erased a genuine failure; round 4 found the remedy
> fabricated a failure; round 5 found both false positives gone and the mirror suppression standing;
> round 6 removed a fabricated failure at J6 and, in the same edit, removed J6's only reachable genuine
> one. The recurring cause is that these fixes are made at the *return statement* while the fault
> classes are merged upstream, inside two blanket `except Exception` handlers neither round touched. Any
> next round that edits only the return will produce the seventh instance of this pattern.

### Gap-Closure Outcome (03-20 and 03-21), item by item

Every row was established by a command I ran or a line I read, not by reading a summary.

| Commissioned item | Status | How I established it |
| --- | --- | --- |
| Round-5 `missing` 1 — pollers return their own computed verdict | ✓ CLOSED | Drove the REAL `worker_process_scan_requests` through the REAL `dispatch_callback` with `run_discovery` raising: `False` / `J5 failed / CallbackReturnedFalse` / `scan_requests failed`. Same for the literal `'failed'`. |
| Round-5 `missing` 2 — J7/J9 honour the vocabulary | ✓ CLOSED, and improved | Reproduced both directions: `'failed'` → both `failed`; `'busy'` → both `succeeded`. Now decided by MEMBERSHIP, with an unrecognised literal raising `ValueError`. |
| Round-5 `missing` 3 — a regression against work that genuinely fails | ✓ CLOSED | Read `test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed`; it binds the two production callables and makes `run_discovery` actually raise. Ran it: green. |
| Round-5 `missing` 4 — durable evidence before the compound-startup re-raise | ✓ CLOSED as commissioned | Round 5 offered "leave durable evidence, OR record explicitly that it is a journal-and-exit channel". 03-19 chose to leave durable evidence on the best-effort-retry path. Not re-litigated here. |
| Round-5 `missing` 5 — pin the floor against external facts | ✓ CLOSED, then partly undone | The self-referential pin is replaced and a J9/cadence-`None` subtest exists. But the same change introduced gap 2 — the floor is now widened globally by a discovery-only knob. |
| Round-5 `missing` 6 — the two deferred transient contention sites | ✓ CLOSED | Both now `return None` (app.py:1837, app.py:1343). `deferred-items.md` row 9 records the closure and names both pinning regressions. |
| Round-6 CR-01 — decouple J6 from the per-service warning | ⚠️ CLOSED, OVERSHOT | `return not warning` is gone and the per-request verdict is intact. But the decoupling discards every warning, including the class that describes J6's own machinery. See gap 1. |
| Round-6 WR-04 — lost lease on the busy branch | ✓ CLOSED at the site | The raise is the first statement in the busy branch, inside the outer `try`, before the requeue. See the WR-03 Warning below for the consequence it introduces. |
| Round-6 WR-01 — discovery vocabulary fails closed | ⚠️ CLOSED at 2 of 3 consumers | J7 and J9 converted and pinned. J5 (app.py:1844) and its legacy sibling (app.py:1906) still decide by exclusion. Folded into gap 1. |
| Round-6 WR-02 — the uptime-contention comment states the true asymmetry | ✓ CLOSED as a comment change | The comment at app.py:1334-1343 now names the J3/J4 asymmetry explicitly. Behaviour is byte-identical, which the plan intended. Whether the compensating disclosure it relies on always fires is 03-21-REVIEW.md WR-05, recorded as a Warning. |
| Round-6 WR-03 — the floor derives from the configured timeout | ✓ CLOSED, with collateral | It does derive from `settings.discovery_timeout_seconds`. The collateral is gap 2. |

### Reproduction Evidence (verifier-executed)

Every block below is output from a command I ran, against a real SQLite database created by the
project's own `tests.helpers.load_app`, through production code paths.

#### 1. CR-01 — J6 reports success while the browser is dead (BOTH routes)

Driving the **real** `appmod.worker_process_preview_requests` — the exact callable `dashboard/worker.py:35`
wires in — through the **real** `worker_main.dispatch_callback`:

```
=== CASE A: fetch_thumbnail raises (playwright binding not installed) ===
  J6 dispatch result   -> True
  J6 durable health    -> {'state': 'succeeded', 'last_success_ts': 100, 'error_class': None}
  preview_requests row -> {'status': 'failed', 'error': 'title refresh failed (exception); thumbnail refresh skipped'}

=== CASE B: browser machinery broken via the REAL caught path (_get_browser raises) ===
  J6 dispatch result   -> True
  J6 durable health    -> {'state': 'succeeded', 'last_success_ts': 100, 'error_class': None}
  preview_requests row -> {'status': 'failed', 'error': 'thumbnail refresh failed'}

  operator exception kinds -> ['host_freshness', 'worker_freshness']
  job_failed job_ids       -> []
```

Case A is the reviewer's reproduction, reaching `_legacy_refresh_service_preview`'s blanket handler at
app.py:982. **Case B is mine and is the ordinary production path**: `_get_browser()` raising is caught by
`_legacy_screenshot_service`'s own `except Exception` at app.py:930-932 and converted to `thumb_error`
before the blanket handler is ever in play. Both record J6 `succeeded`. Narrowing app.py:982 alone —
03-21-REVIEW.md's less-invasive proposed fix — would not close this.

#### 2. WR-01 — J5 fabricates a completed manual scan on an unrecognised literal

```
=== J5 (worker_process_scan_requests) with an unrecognised run_discovery literal ===
  J5 dispatch result   -> True
  J5 durable health    -> {'state': 'succeeded', 'last_success_ts': 100, 'error_class': None}
  scan_requests row    -> {'status': 'completed', 'error': None}

=== J7/J9 (converted dispatchers) with the same literal ===
  J7 helper -> ValueError: run_discovery returned an unknown outcome: 'an_unrecognised_literal'
```

The same input, at two consumers of the same contract, gives opposite answers. Reachability is bounded:
`_legacy_run_discovery` returns only `'busy'` (app.py:1325) and `'completed'|'failed'` (app.py:1327).

#### 3. The commissioned closures genuinely hold

```
[A] J5 with run_discovery RAISING
   dispatch-> False  health-> {'state': 'failed', 'error_class': 'CallbackReturnedFalse'}  queue-> {'status': 'failed', 'error': 'boom'}
[B] J5 with run_discovery returning "failed"
   dispatch-> False  health-> {'state': 'failed', 'error_class': 'CallbackReturnedFalse'}  queue-> {'status': 'failed', 'error': 'scan failed'}
[C] J5/J6 on an EMPTY queue
   J5-> None {'state': 'succeeded', 'last_success_ts': 100}   J6-> None {'state': 'succeeded', 'last_success_ts': 100}
[D] J7/J9 with run_discovery returning "failed"
   J7 dispatch-> False  health-> {'state': 'failed', 'error_class': 'CallbackReturnedFalse'}
   J9 dispatch-> False  health-> {'state': 'failed', 'error_class': 'CallbackReturnedFalse'}
[E] J7/J9 with "busy"
   J7 dispatch-> True  health-> {'state': 'succeeded'}   J9 dispatch-> True  health-> {'state': 'succeeded'}
   job_failed ids -> []
```

Both directions correct at J5, J7 and J9, and the idle-Pi fix from round 4 has not regressed.

#### 4. WR-02 — the widened floor is global

```
FLOOR = 900
  cadence=5    (J1 heartbeat ) timeout=  180 -> 900
  cadence=5    (J1 heartbeat ) timeout= 1200 -> 1260
  cadence=5    (J1 heartbeat ) timeout= 3600 -> 3660
  cadence=2    (J5/J6 pollers) timeout= 3600 -> 3660
  cadence=None (J9 startup   ) timeout= 3600 -> 3660
```

`compose_active_exceptions` computes this once and applies it to every job in `pipeline['jobs']`
(diagnosis.py:479-484). J1 is a 5-second heartbeat that never runs discovery.

#### 5. WR-04 — type discipline of the new input

```
  f(5, None)   -> TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'
  f(5, 900.9)  -> 960     # silently truncated
  f(5, True)   -> 900     # bool accepted
  f(5, '900')  -> 960     # str accepted
```

Sibling line 57 in the same function uses `type(cadence_seconds) is int`. Production is safe today
because `_positive_int` (config.py:205) always yields an int.

#### 6. SC4's other five clauses, served live

```
top keys      -> ['exceptions', 'generated_ts', 'host', 'pipeline', 'safety', 'schema_version', 'services', 'settings']
pipeline keys -> ['aggregation_pending', 'database_pressure', 'gaps', 'jobs', 'resolution_policy', 'retention', 'streams', 'worker']
retention     -> {'five_minute_days': 30, 'point_budget': 2048, 'raw_days': 7, 'retention_days': 90}
db pressure   -> {'pressure_gaps': {}, 'reason': None, 'snapshot': None, 'state': 'normal'}
worker        -> {'expected_cadence_seconds': 5, 'freshness': {...}, 'heartbeat_ts': None, 'lease_until': None}
gaps          -> {'count': 0, 'truncated': False}
jobs (n)      -> 14 ['P0','S1','S2','S3','J1','J2','J3','J4','J5','J6','J7','J8','J9','L1']
```

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/app.py` | J6's job outcome decoupled from the per-service warning; busy-branch lease guard | ⚠️ **PARTIAL** | Decoupling present at line 2038 and lease guard present at line 1831. But the decoupling discards every fault class, including J6's own — gap 1. |
| `dashboard/app.py` | J5's poller returns its own computed verdict | ✓ VERIFIED | Line 1868 `return status == 'completed'`, reproduced correct in both directions. |
| `dashboard/beacon/worker_main.py` | `_discovery_outcome_verdict` fails closed on an unrecognised literal | ✓ VERIFIED | Lines 189-206. Wired into both `_run_scheduled_discovery` and `_run_startup_discovery`; raise reproduced. |
| `dashboard/beacon/diagnosis.py` | Floor derives from the configured `DISCOVERY_TIMEOUT_SECONDS` | ⚠️ **PARTIAL** | Present at line 56 and threaded from `settings.discovery_timeout_seconds` at line 545. Applied globally rather than to discovery jobs, and coerces rather than guards — gap 2. |
| `tests/test_advanced_diagnosis_api.py` | Regressions for CR-01, WR-04, WR-01, WR-02, WR-03 | ⚠️ **PARTIAL** | `test_a_titleless_service_never_fails_j6s_job_health` (:389), `test_a_busy_discovery_lock_with_a_lost_lease_does_not_report_success` (:639) and `test_the_real_discovery_dispatch_honours_the_return_value_vocabulary` (:476) all exist and are green. Four of five new assertions are genuine regressions (IN-04 confirmed). No test covers the capture-machinery class, the J5 fail-open path, or a non-J9 row against the widened floor. |
| `dashboard/advanced.js` / `advanced.html` / `advanced.css` | Unchanged this round | ✓ VERIFIED | `git diff 1272951..HEAD -- dashboard/` lists only `app.py`, `beacon/diagnosis.py`, `beacon/worker_main.py`. |
| `.planning/REQUIREMENTS.md` | Not promoted on an implementation claim | ✓ VERIFIED | `git diff 43c3727 HEAD -- .planning/REQUIREMENTS.md` is empty. Both plans declined promotion by design. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `worker_process_preview_requests`'s committed transaction | J6's durable `background_job_health` row | unconditional `return True` after commit | ⚠️ **WIRED, SEMANTICALLY WRONG** | The link works exactly as the plan specifies. The plan's specification is what gap 1 rejects: it carries no J6-owned fault. |
| `heartbeat.lost` in the discovery-busy branch | a raised `LeaseLost` | raise before `requeue_scan_for_worker` | ✓ WIRED | app.py:1831 precedes app.py:1834-1836; reproduced by `test_a_busy_discovery_lock_with_a_lost_lease_does_not_report_success`. |
| `services.run_discovery`'s three-literal contract | membership check | `_discovery_outcome_verdict`, shared by both discovery dispatchers | ⚠️ **PARTIALLY WIRED** | Wired at J7/J9 (worker_main.py:216, :229). NOT wired at J5 (app.py:1844) or the legacy sibling (app.py:1906) — the helper lives in a module `dashboard/app.py` does not import from for this purpose. |
| `settings.discovery_timeout_seconds` | the `job_outcome_unrecorded` boundary | `get_current_diagnosis` → `compose_active_exceptions` → `_unrecorded_outcome_boundary` | ✓ WIRED (over-broadly) | diagnosis.py:545 → :433 → :482. Reaches every job, not only the discovery jobs — gap 2. |
| `J3` losing `_uptime_lock` to a concurrent `J4` | `last_uptime_check` staying unadvanced | `return None` on contention | ✓ WIRED | app.py:1343. Pinned, though the pin asserts a fresh-DB default rather than an unadvanced seeded value (03-21-REVIEW.md IN-05, confirmed). |
| `advanced.js` | the server | one `fetch('/api/advanced/current', {cache: 'no-store'})` | ✓ WIRED | Line 58; the only network call in the file. No remote controls. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| --- | --- | --- | --- | --- |
| `/api/advanced/current` | `pipeline.retention` | `settings` + durable retention policy | ✓ | ✓ FLOWING |
| `/api/advanced/current` | `pipeline.database_pressure` | `beacon_telemetry.measure_storage` snapshot | ✓ | ✓ FLOWING |
| `/api/advanced/current` | `pipeline.worker` | `worker_heartbeat` / `worker_owner` rows | ✓ | ✓ FLOWING |
| `/api/advanced/current` | `pipeline.gaps` | durable coverage rows, bounded population | ✓ | ✓ FLOWING |
| `/api/advanced/current` | `pipeline.jobs` | `background_job_health` rows (14 job ids returned) | Rows flow; **J6's `state` value is fabricated on a capture-machinery fault** | ⚠️ **HOLLOW for J6** |
| `/api/advanced/current` | `exceptions[].job_failed` | `compose_active_exceptions` over `pipeline.jobs` | Emits correctly for J5/J7/J9; **structurally cannot emit for a J6 machinery fault** | ⚠️ **HOLLOW for J6** |
| `/api/advanced/current` | `host.*`, `services[].*` | `system_stats`, `services`, `service_checks`, `service_meta` | ✓ | ✓ FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| SC1 theme round-trip survives navigation | `pytest tests/test_advanced_ui.py -k "theme_or_return_round_trip or production_routes_serve"` | passed | ✓ PASS |
| SC2/SC3 host + service surfaces | `pytest -k "host_tracer_returns_one_current or unmeasured_latency or service_detail_gap_evidence or every_emitted_exception_kind"` | 5 passed, 55 subtests | ✓ PASS |
| J5 records a genuine failure as failed | verifier probe, real adapter + real `dispatch_callback` | `False` / `failed` / `CallbackReturnedFalse` | ✓ PASS |
| J7/J9 honour the outcome vocabulary in both directions | verifier probe | `'failed'`→`failed`, `'busy'`→`succeeded`, unknown→`ValueError` | ✓ PASS |
| Idle J5/J6 poll records success (round-4 guard) | verifier probe on an empty queue | `None` / `succeeded` for both | ✓ PASS |
| **J6 records a capture-machinery failure as failed** | verifier probe, `_get_browser` raising | `True` / **`succeeded`** / zero `job_failed` | ✗ **FAIL** |
| **J5 rejects an unrecognised discovery literal** | verifier probe | `True` / **`succeeded`** / `scan_requests completed` | ✗ **FAIL** |
| **J1's wedge boundary is independent of the discovery timeout** | direct probe of `_unrecorded_outcome_boundary` | `f(5, 3600) -> 3660`, not 900 | ✗ **FAIL** |
| SC4's other five clauses served live | `GET /api/advanced/current` via test client | all five blocks populated | ✓ PASS |
| Full suite (run once by the orchestrator) | `pytest` | 303 passed, 426 subtests, 0 failures | ✓ PASS |
| Prior-phase regression gate (16 files, phases 01-02) | `pytest` | 221 passed, 254 subtests | ✓ PASS |

### Probe Execution

| Probe | Command | Result | Status |
| --- | --- | --- | --- |
| — | `find scripts -path '*/tests/probe-*.sh'` | no matches | ? SKIP (project defines no probe scripts; no PLAN or SUMMARY in this phase declares one) |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| **TEL-06** | 03-01…03-21 | Operator can see effective retention, displayed resolution, database pressure, worker freshness, collection gaps, and background-job health. | ✗ **GAPS FOUND — NOT PROMOTED** | Five of six clauses verified truthful against a live payload. Background-job health is untruthful for J6, reproduced twice on a real database. Both 03-20 and 03-21 explicitly left this decision to this verifier; the evidence does not support promotion. `.planning/REQUIREMENTS.md` line 25 and line 123 stay unchanged — no edit required. |
| **DIA-01** | 03-01 | Operator can open a dedicated advanced page from either theme. | ✓ SATISFIED | SC1 verified. Table already reads `Complete`. |
| **DIA-02** | 03-02 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, freshness. | ✓ SATISFIED | SC2 verified. Table already reads `Complete`. |
| **DIA-03** | 03-03, 03-11, 03-16 | Operator can inspect every service's status, latency/failure class, duration, criticality, tags, health rule. | ✓ SATISFIED | SC3 verified. Table already reads `Complete`. |
| **DIA-08** | 03-04 | Operator can view effective monitoring settings and change presentation, refresh, **range**, and filtering preferences without remote-control actions. | ⏸ **DEFERRED to Phase 4** | Settings, refresh interval, search and four filters all present in `advanced.html`; no range control exists, and Phase 4 SC1 owns range selection. Table already reads `Deferred to Phase 4`. Unchanged from rounds 3-5. |
| **UX-02** | 03-01, 03-05 | Operator can move between dashboard and advanced without losing theme choice. | ✓ SATISFIED | SC1's named round-trip test green. Table already reads `Complete`. |

**Orphaned requirements:** none. `grep -E "Phase 3" .planning/REQUIREMENTS.md` maps exactly the six IDs
the ROADMAP phase entry declares, and every one is claimed by at least one plan's `requirements`
frontmatter.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `dashboard/app.py` | 2028-2037 | A comment asserting a safety property the code does not have ("A genuine J6 job fault ... already propagates as LeaseLost above or as an uncaught exception") | 🛑 Blocker | Reproduced false by two independent routes. A future maintainer reading this comment will believe J6's health is covered. Part of gap 1. |
| `dashboard/app.py` | 930-932, 982-984 | Two blanket `except Exception` handlers merging distinct fault classes into one string | 🛑 Blocker | The structural cause of gap 1 and of four rounds of oscillation on this surface. Neither is on the diff of any round. |
| `dashboard/app.py` | 1844, 1906 | Outcome decided by exclusion where a membership helper already exists elsewhere | ⚠️ Warning | Latent fail-open; folded into gap 1. |
| `dashboard/beacon/diagnosis.py` | 56 | Coercion (`int(...)`) inside a module whose every other numeric input is type-guarded, and whose comment on the adjacent line calls that discipline "reused rather than a second convention" | ⚠️ Warning | Gap 2's second count. |
| `dashboard/app.py` | 1831 → `worker_main.py:353-357` | A request-level condition raising a class the dispatcher treats as worker-level, reaching `close_admission()` + `stop_worker()` | ⚠️ Warning | 03-21-REVIEW.md WR-03, confirmed by reading both sites. A manual scan whose 900 s deadline expires during a busy discovery would tear down the whole worker on a healthy epoch. Reachability requires a sub-millisecond busy return racing a ≥1 s first renewal, so unlikely rather than impossible. A follow-up should distinguish `ScanClaimLost` from `LeaseLost`. |
| `dashboard/app.py` | 1334-1343 | A comment relying on a compensating disclosure (`detect_collection_gaps`) that needs an exact `>= 2 * 300` boundary a single skipped J3 tick barely reaches under executor jitter | ⚠️ Warning | 03-21-REVIEW.md WR-05. Code facts confirmed (telemetry.py:683, app.py:1416, `misfire_grace_time=60`); the jitter interaction was not reproduced. The comment should state the narrower true claim. |
| `tests/test_advanced_diagnosis_api.py` | 389, 639 | Two new methods with no blank line before `def` (PEP 8 E301) | ℹ️ Info | 03-21-REVIEW.md IN-01, confirmed. Cosmetic. |
| `dashboard/beacon/worker_main.py` | 206 | Bare `ValueError` for the unknown-outcome condition, indistinguishable on the durable surface from three other `ValueError`s the same dispatcher raises; and an unbounded `{outcome!r}` next to neighbours capped at `[:96]` / `[:240]` | ℹ️ Info | 03-21-REVIEW.md IN-02 and IN-03, confirmed by reading `_job_error_class` (worker_main.py:266-268). Define `UnknownDiscoveryOutcome(ValueError)` and cap the interpolation. |
| `tests/test_advanced_diagnosis_api.py` | 746 | `assertIsNone(state['last_uptime_check'])` pins a fresh-database default rather than a surviving seeded value | ℹ️ Info | 03-21-REVIEW.md IN-05, confirmed. A regression that *cleared* the value would pass. |

**Debt-marker gate:** PASSED. `grep -n -E "\bTBD\b|\bFIXME\b|\bXXX\b|\bTODO\b|\bHACK\b|PLACEHOLDER"` over
`dashboard/app.py`, `dashboard/beacon/diagnosis.py`, `dashboard/beacon/worker_main.py`,
`dashboard/advanced.js`, `dashboard/advanced.html`, `tests/test_advanced_diagnosis_api.py` and
`tests/test_advanced_ui.py` returns zero matches. No unreferenced debt markers were introduced.

### Human Verification Required

#### 1. Real collection gap and stale host on the target Pi

**Test:** Open `/advanced` on the Pi while a real collection gap is active and while host evidence is stale.
**Expected:** The workspace shows the open gap and the stale host as real, correctly labelled exceptions, and shows no resolved or retention-expired interval as an open actionable gap.
**Why human:** Carried forward from all six previous reports and re-declared as human judgment in three separate plans' own `human-check` blocks. Still not performed on real hardware. Operator trust in the rendered snapshot cannot be asserted programmatically.

#### 2. Idle Pi, one minute, Active exceptions region

**Test:** Start the worker on the Pi, leave the system idle for one minute, open `/advanced` and read the Overview "Active exceptions" region.
**Expected:** No "Background job failed" card for J5 or J6, and no "Background job outcome not recorded" card for any job that is simply working.
**Why human:** Recorded by round 4 specifically so a gap-closure round could not declare success without it. Still not performed on real hardware. My reproductions establish it on a real SQLite database through the real production adapters and it passes there; the operator's own idle Pi is the surface the criterion is written about.

#### 3. Deliberately broken browser, two minutes, Pipeline region — NEW

**Test:** With Chromium/Playwright deliberately unavailable on the Pi (rename the browser executable, or unset the download path), leave the worker running for two minutes, then open `/advanced` and read the Pipeline region and the per-service preview cells.
**Expected:** Something in the workspace tells the operator the preview subsystem is broken. Today J6 reads `succeeded` and only the per-service preview cells carry the evidence.
**Why human:** Gap 1 turns on a judgement about how much of J6's own machinery must be visible on the job-health surface versus on the per-service surface. My reproduction establishes the facts — J6 reads `succeeded`, zero job exceptions name J6, `preview_requests` reads `failed` — but whether the operator considers the per-service evidence adequate disclosure is not programmatically decidable, and the same user decision already redirected this behaviour once in round 6. **If the operator judges the per-service evidence sufficient, gap 1's first count should be closed by an override rather than by a code change** (see the override note below).

### Gaps Summary

Two gaps, both on Success Criterion 4's background-job-health clause, both narrower than any previous
round's.

**Gap 1 — J6 cannot report a fault of the machinery it owns.** `worker_process_preview_requests` returns
`True` unconditionally, and every fault of the browser subsystem is converted into the same `warning`
string a merely-unhealthy monitored service produces, by two independent blanket `except Exception`
handlers. A permanently dead browser records J6 `succeeded` at 0.5 Hz forever with no operator exception
naming J6. I reproduced this by two routes, one of which 03-21-REVIEW.md did not identify and which its
own less-invasive proposed fix would not close. Folded into the same gap at much lower severity: J5 still
decides the discovery outcome by exclusion, so an unrecognised literal fabricates both a `succeeded` J5
row and a `completed` manual scan — latent today, because `_legacy_run_discovery` returns only the three
contract literals, but it is the identical fail-open shape J7/J9 were converted away from in the very
same round.

**Gap 2 — the widened `job_outcome_unrecorded` floor is global.** Raising `DISCOVERY_TIMEOUT_SECONDS`
to an hour extends the blind window for a wedged 5-second heartbeat from 15 to 61 minutes. Round 5
established `job_outcome_unrecorded` as the only remaining signal for a permanently wedged
`_scan_lock`/`_uptime_lock`; this round lengthened it with a knob whose name has nothing to do with those
jobs. Same line, second count: the input coerces where the module's every other numeric input guards, and
raises `TypeError` from inside `get_current_diagnosis` on `None` — robustness only today, because
`_positive_int` always yields an int in production.

**Root cause worth naming for the next planner.** Four consecutive rounds have edited the *return
statement* while the fault classes stay merged upstream inside `_legacy_screenshot_service`'s and
`_legacy_refresh_service_preview`'s blanket handlers. That is why each round's fix produces the mirror
defect. A fix at the return site alone will produce a seventh instance. The distinction must be made
where the classes are still distinguishable.

### Override Suggestion (gap 1, first count only)

Gap 1's J6 count may be an intentional deviation rather than a defect. Round 6 recorded a user decision
that a per-service capture condition must not become J6's verdict, and the implementation honoured that
decision — it simply reached further than the decision's wording, because the code cannot tell a broken
service from a broken browser. If the operator, after human-verification item 3 above, judges the
per-service preview evidence to be sufficient disclosure for a dead browser, add to this file's
frontmatter and re-run verification:

```yaml
overrides:
  - must_have: "J6's background-job health reports a fault of the capture machinery it owns"
    reason: "The user's round-6 decision stands as implemented: J6's contract is claim-capture-record, and a dead browser is disclosed on every per-service preview cell. Accepting the false-negative in exchange for eliminating the high-frequency false positive."
    accepted_by: "{your name}"
    accepted_at: "{ISO timestamp}"
```

Gap 1's J5 count and gap 2 are **not** override candidates — both are unambiguous defects with
unambiguous fixes and neither reflects any recorded decision.

---

_Verified: 2026-08-19T15:50:55Z_
_Verifier: Claude (gsd-verifier), round 7, adversarial goal-backward_
_All reproductions run against a real SQLite database via `tests.helpers.load_app`, through the real production adapters and the real `worker_main.dispatch_callback`. No claim below is taken from a SUMMARY or REVIEW without independent confirmation._
