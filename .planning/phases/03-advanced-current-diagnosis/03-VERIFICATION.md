---
phase: 03-advanced-current-diagnosis
verified: 2026-08-19T21:35:00Z
status: human_needed
score: 4/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
overrides: []
re_verification:
  round: 8
  previous_status: gaps_found
  previous_score: 3/4
  gaps_closed:
    - "Round-7 gap 1, primary count — J6 could not report a fault of the capture machinery it owns. CLOSED and independently reproduced closed by TWO routes. `_get_browser()` raising inside `_legacy_screenshot_service` (currently line 913) and `context.new_page()` raising (currently line 924) both now return `(None, None, THUMB_ERROR_BROWSER_UNAVAILABLE)` immediately, before either of app.py's two blanket `except Exception` handlers (930/932 no longer reachable for this fault; the second inner try/except at 924-926 sits inside the `with` body, upstream of the original 982-line blanket handler's now-relocated equivalent) is ever reached. I reproduced the `_get_browser()` route via the plan's own named test (green here) AND independently reproduced the `context.new_page()` route myself with a fake context object the plan's own test does not exercise: `dispatch_callback(services, 'J6')` raised `PreviewCaptureUnavailable`; J6 durable row `{'state': 'failed', 'error_class': 'PreviewCaptureUnavailable'}`; `preview_requests` row `{'status': 'failed', 'error': 'thumbnail refresh failed'}`; `job_failed` exceptions `['J6']` exactly. The overclaiming trailing comment at the old app.py:2028-2037 site (\"already propagates as LeaseLost above or as an uncaught exception\") is gone, replaced with an accurate statement; confirmed by grep (`propagates as LeaseLost above or as an uncaught exception` count = 0, was 1)."
    - "Round-7 gap 1, secondary count — J5 decided the discovery outcome by exclusion at app.py:1844 (now 1862) and the legacy `process_scan_requests` at app.py:1906 (now 1937). CLOSED at BOTH sites. Both now call `beacon_worker_main._discovery_outcome_verdict(outcome)` — the identical membership check J7/J9 already used — immediately after `run_discovery`/`worker_run_discovery` returns, before the busy-branch handling. I reproduced both directions myself and via the plan's own two new named tests (both green here): an unrecognised literal now raises `ValueError` inside the helper, caught by each function's own pre-existing `except Exception as exc: status, error = 'failed', str(exc)[:240]` handler, durably recording J5 `failed`/`CallbackReturnedFalse` and `scan_requests.status='failed'` with 'unknown outcome' in the error text (both `worker_process_scan_requests`, reachable from `dispatch_callback`/`background_job_health` in production, and the legacy `process_scan_requests`, which the plan correctly documents as unreachable from `background_job_health` and therefore does not assert a return value for)."
    - "Round-7 gap 2, both counts — the widened `job_outcome_unrecorded` floor was global and coerced its input. CLOSED. `_unrecorded_outcome_boundary` now takes a `job_id` parameter and widens the floor above the constant `UNRECORDED_OUTCOME_FLOOR_SECONDS` (900) only `if job_id in DISCOVERY_JOB_IDS` (`{'J5','J7','J9'}`) `and type(discovery_timeout_seconds) is int and discovery_timeout_seconds > 0`. I reproduced directly against the live function AND against `compose_active_exceptions` called with a real one-job pipeline: `f(5, 3600, 'J1') -> 900` (was 3660 pre-fix — a J1-shaped 901-second-old row now correctly still promotes `job_outcome_unrecorded` at a widened discovery timeout, where pre-fix it promoted nothing); `f(5, 3600, 'J5') -> 3660` (discovery job still correctly widened); `f(5, 3600, 'J2') -> 900` (another non-discovery job also correctly unaffected). The coercion is replaced by a type guard: `f(5, None, 'J1') -> 900` (no raise, was `TypeError`), and I additionally probed the full malformed-input matrix round 7 named — `f(5, 900.9, 'J5') -> 900` (float rejected), `f(5, True, 'J5') -> 900` (bool rejected, `type(True) is int` is `False` in Python), `f(5, '900', 'J5') -> 900` (string rejected) — all degrade to the constant rather than coercing, and `diagnosis.compose_active_exceptions(..., discovery_timeout_seconds=None)` against a stuck J9 row returns `['J9']` without raising, confirming `get_current_diagnosis` no longer aborts the whole `/advanced` payload on a malformed setting."
  gaps_remaining: []
  regressions: []
  newly_found: []
  over_credit_corrected: []
  red_proof_independently_confirmed:
    - "Task 1: reverted dashboard/app.py and dashboard/beacon/previews.py to commit b73ec1e~1 and re-ran the new test. Both subTests failed exactly as SUMMARY.md claimed: subTest 1 raised `AttributeError: module 'dashboard.beacon.previews' has no attribute 'PreviewCaptureUnavailable'` at the `assertRaises` line; subTest 2 failed `queue_row['status']` `'queued' != 'failed'` as a documented collateral of subTest 1's precondition never executing. Genuine RED proof, not over-claimed."
    - "Task 2: reverted dashboard/app.py to commit c2aa34c~1 (Task 1's fix still in place) and re-ran both new tests. `test_the_real_manual_scan_poller_fails_closed_on_an_unrecognised_discovery_outcome` failed `AssertionError: True is not False` exactly as claimed. `test_the_legacy_manual_scan_poller_also_fails_closed_on_an_unrecognised_discovery_outcome` failed `AssertionError: 'completed' != 'failed'` exactly as claimed. Genuine RED proof."
    - "Task 3: reverted dashboard/beacon/diagnosis.py to commit e574f72~1 and re-ran the widened-floor subtests. `the_widened_floor_never_reaches_a_job_that_does_not_run_discovery` failed `Lists differ: [] != ['J1']` exactly as claimed. `a_malformed_discovery_timeout_degrades_one_promotion_instead_of_aborting_the_payload` failed with an uncaught `TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'` raised from inside `_unrecorded_outcome_boundary`, exactly as claimed. Genuine RED proof — unlike round 7's IN-04 finding (two of five prior-round assertions over-claimed), all five of this round's new assertions genuinely discriminate."
    - "Working tree fully restored after each revert; `git diff --stat` and `git status --short` confirmed clean (only pre-existing untracked `.gsd/` and `.planning/debug/` remain) before writing this report."
  rounds_1_through_7_summary:
    - "Rounds 1-2: initial phase build (03-01 through 03-19 gap-closure lineage). See prior VERIFICATION.md revisions in git history for full detail; not restated here per the cumulative-history instruction — round 7's own frontmatter (preserved verbatim below) is the authoritative prior record."
    - "Round 5 (previous_status carried in round 7's own record): four of eleven promotable jobs fabricating success. Six `missing` items opened."
    - "Round 6: closed round-5 missing items 1, 2, 3, 6, and WR-04; introduced gap 1 (commit 8320366, `worker_process_preview_requests` returns `True` unconditionally, discarding every warning including J6's own machinery fault)."
    - "Round 7 (full record preserved verbatim in `round_7_record` below): closed round-6's WR-01/WR-02/WR-03/WR-04 for J7/J9, but confirmed gap 1 live via two independent reproduction routes and introduced gap 2 (commit df6f947, the widened `job_outcome_unrecorded` floor applied globally and coerced its input). Root cause named: four consecutive rounds edited the return statement while the fault classes stayed merged upstream inside two blanket `except Exception` handlers."
    - "Round 8 (this report): 03-22-PLAN.md closed both of round 7's gaps by making the fault-class distinction at the collaborator boundary (`_get_browser()`/`context.new_page()`), upstream of both blanket handlers, per round 7's own root-cause finding — the first round in this phase's eight-round history to do so. No new regression found despite deliberate adversarial reproduction beyond the plan's own test coverage (the untested `context.new_page()` route, the full four-variant malformed-input matrix, and a direct probe of the disclosed `browser.new_context()` residual)."
  round_7_record:
    previous_status: gaps_found
    previous_score: 3/4
    gaps_closed:
      - "Round-5 `missing` 1 — Return the verdict the poller already computed. CLOSED and independently reproduced closed."
      - "Round-5 `missing` 2 — J7/J9 honour the vocabulary. CLOSED and reproduced closed, now by MEMBERSHIP rather than by exclusion."
      - "Round-5 `missing` 3 — A regression driven by work that GENUINELY FAILS. CLOSED."
      - "Round-5 `missing` 6 — the two deferred transient contention sites. CLOSED."
      - "Round-6 WR-04 — a lost lease on the discovery-busy branch. CLOSED at the site named."
      - "Round-6 CR-01 (`return not warning`) — the conflation is gone... This closure is what gap 1 below finds went one step too far."
    gaps_remaining:
      - "The failed truth is STILL the background-job-health clause of Success Criterion 4, for the sixth consecutive round — now narrowed to exactly one job (J6)."
    regressions:
      - "dashboard/app.py:2038 — INTRODUCED BY THIS PHASE'S OWN ROUND-6 FIX (commit 8320366). worker_process_preview_requests now returns True unconditionally."
      - "dashboard/beacon/diagnosis.py:56 — INTRODUCED BY THIS ROUND (commit df6f947). The widened _unrecorded_outcome_boundary floor is global."
    newly_found:
      - "CR-01 is BROADER than 03-21-REVIEW.md reported — reproduced via the _get_browser() route, not only the fetch_thumbnail route the review named."
    over_credit_corrected:
      - "The ROADMAP entry for 03-20 over-described CR-01's closure; the implementation discarded every warning, not only per-service ones."
      - "03-21-REVIEW.md IN-04 confirmed: of the round's five new assertions, two pass against the pre-fix tree — four genuine regressions, not five."
    note: "Full round-7 narrative, reproduction transcripts, and the complete gaps/deferred/human_verification/prohibitions blocks are preserved in this file's git history at commit 2633b9e and earlier; condensed here per the cumulative-history instruction to keep this file's active frontmatter legible. Nothing in the condensed form above contradicts or narrows the original round-7 findings."
gaps: []
deferred:
  - truth: "Operator can change supported *range* preferences in the advanced workspace (the `range` clause of Success Criterion 4 and of DIA-08's requirement text)."
    addressed_in: "Phase 4"
    evidence: "Re-confirmed against ROADMAP.md this round: Phase 4 success criterion 1 is 'Operator can choose shared ranges from one hour through 90 days or a validated custom range within retained history.' Re-confirmed against dashboard/advanced.html this round: still no range control. Carried forward unchanged from rounds 3, 4, 5 and 7. A deferral, not a gap; no closure plan should be written for it. DIA-08 stays DEFERRED."
  - truth: "Design-concern residuals from prior rounds' reviews (WR-03 lease-loss-on-busy-branch escalation, WR-05 uptime-disclosure boundary jitter, the seventeen carried-forward CF-* findings, the browser.new_context() residual)."
    addressed_in: "deferred-items.md"
    evidence: "None appears in either round-7 gap or is reintroduced by round 8's fix. The browser.new_context() residual is newly re-confirmed this round: I reproduced it directly (a FakeBrowser.new_context() raising RuntimeError still falls through to the per-service classification, J6 records succeeded, preview_requests records its own failed text) — exactly as 03-22-PLAN.md's comment discloses, honestly and accurately. Not a concealed gap; a recorded, correctly-scoped-out residual."
human_verification:
  - test: "On the target Pi, open /advanced while a real collection gap is active and while host evidence is stale."
    expected: "The workspace shows the open gap and the stale host as real, correctly labelled exceptions — and shows no resolved or retention-expired interval as an open actionable gap."
    why_human: "Carried forward from all seven previous reports. Still NOT performed on real hardware through eight rounds of automated reproduction. Operator trust in the rendered snapshot cannot be asserted programmatically. NOTE: this same item remains open for DIA-01/DIA-02/DIA-03/UX-02, all of which this project's own REQUIREMENTS.md already records as Complete — this project's established convention is that this class of hardware check is a standing human-verification item, not a promotion blocker, once the code-level truth is independently reproduced."
  - test: "On the target Pi, start the worker and leave the system idle for one minute, then open /advanced and read the Overview 'Active exceptions' region."
    expected: "No 'Background job failed' card for J5 or J6, and no 'Background job outcome not recorded' card for any job that is simply working."
    why_human: "Recorded by round 4 specifically so a gap-closure round could not declare success without it. Still NOT performed on real hardware. My reproductions establish it on a real SQLite database through the real production adapters and it passes there for every job including J6 (now correctly succeeded on an idle/ordinary poll and correctly failed on a genuine machinery fault)."
  - test: "On the target Pi with Chromium/Playwright deliberately unavailable (rename the browser executable, or unset the download path), leave the worker running for two minutes, then open /advanced and read the Pipeline region."
    expected: "A 'Background job failed' card names J6 — the new operator-facing signal this round's Task 1 adds."
    why_human: "New in round 7, carried forward. My reproduction establishes the FACTS on a real database through the real production adapters and the real dispatch_callback: J6's durable row now reads failed/PreviewCaptureUnavailable, exactly one job_failed names J6, and preview_requests independently keeps its own failed text. Confirming this renders correctly in the actual browser-served Pipeline region on real hardware is the one remaining step outside this verifier's reach."
prohibitions:
  - source: "03-08-PLAN.md"
    statement: "MUST NOT present resolved, retention-expired, or otherwise inferred evidence to the operator as a current, open, actionable fault -- every operator-facing open/actionable/kind label must be derivable from the durable row it describes, never from a neighbouring row or a stream-level fact."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UNCHANGED this round. No task in 03-22 touches gap/inference logic; re-confirmed by reading compose_active_exceptions and by the fact that dashboard/advanced.js is byte-unchanged since round 7 (git diff 2633b9e..865508c -- dashboard/ shows only app.py, beacon/diagnosis.py, beacon/previews.py)."
  - source: "03-08-PLAN.md"
    statement: "MUST NOT suppress a genuine collection failure while narrowing false positives -- restricting promotion by reason must never cause a real collection_gap, or a reason value the code does not recognise, to go unreported to the operator."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: violated
    detail: "PROMOTED FROM VIOLATED TO UPHELD this round, on my own reproduction. This is the first round in the phase's history in which this prohibition is genuinely satisfied on ALL directions I could reproduce: the collection-gap surface (untouched, unchanged), J5/J7/J9's discovery vocabulary (all fail closed by membership at every consumer, both routes), and J6's capture-machinery fault (now durably recorded as a genuine job_failed, both via the browser-cannot-launch route and the browser-cannot-open-a-page route I reproduced independently). The four-consecutive-round oscillation this prohibition tracked is broken this round because the fix was made at the collaborator boundary, upstream of the blanket handlers that previously erased the distinction, not at the return statement alone."
  - source: "03-09-PLAN.md"
    statement: "MUST NOT let automatic background refresh silently override an operator's explicit presentation choice, and MUST NOT present a machine identifier or a placeholder as the operator's primary safety evidence when the server supplied real evidence."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UNCHANGED. dashboard/advanced.js is byte-unchanged across rounds 6, 7 and 8 (git diff 2633b9e..865508c -- dashboard/ touches only app.py, beacon/diagnosis.py, beacon/previews.py)."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT let test scaffolding mutate process-global state so that suite greenness depends on execution order."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UPHELD. Every new mock in 03-22 is a mock.patch.object context manager that unwinds automatically. I independently ran tests/test_advanced_diagnosis_api.py against tests/test_runtime_ownership.py in both module orders; both passed identically (72 passed, 170 subtests, both orders)."
  - source: "03-10-PLAN.md"
    statement: "MUST NOT record a requirement, plan, or phase as complete on the strength of an implementation claim rather than independent verification -- the traceability table is the project's own memory of what is actually true."
    verification: judgment
    llm_judge_verdict: upheld
    flagged: true
    previous_verdict: upheld
    detail: "UPHELD, and correctly deferred a third time. 03-22-SUMMARY.md and 03-22-PLAN.md both explicitly decline to promote TEL-06 or edit REQUIREMENTS.md, leaving the decision to this independent re-verification round -- exactly the discipline this prohibition requires. `git diff 2633b9e..865508c -- .planning/REQUIREMENTS.md` is empty: line 25 still reads `- [ ] **TEL-06**` and line 123 still reads `| TEL-06 | Phase 3 | Gaps Found |`. This report's own Requirements Coverage section below records my independent determination that TEL-06 is now SATISFIED; the frontmatter edit to promote it is left for the orchestrator's downstream reconciliation step (the project's established `docs(phase-03): record requirement statuses established by re-verification round N` commit pattern), not made by this verification report itself."
---

# Phase 3: Advanced Current Diagnosis Verification Report — Round 8

**Phase Goal:** The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.

**Verified:** 2026-08-19T21:35:00Z
**Status:** human_needed
**Re-verification:** Yes — round 8, after gap-closure plan 03-22 (the only plan new since round 7).

This report supersedes round 7's `03-VERIFICATION.md` for status/score purposes while preserving its full
cumulative record (condensed in `re_verification.round_7_record` above; the complete original text remains
recoverable from this file's git history at commit `2633b9e` and earlier). Nothing below is taken from
`03-22-SUMMARY.md` without independent reproduction. Every reproduction below is a command I ran myself
against a real SQLite database created by the project's own `tests.helpers.load_app`, through the real
production adapters and the real `worker_main.dispatch_callback` — including scenarios `03-22-SUMMARY.md`'s
own tests do not cover.

## The short version

**For the first time in this phase's eight-round history, both gaps closed and no new one appeared.**
Round 7 named the root cause precisely: four consecutive rounds (3, 4, 6, 7) each edited the *return
statement* of `worker_process_preview_requests` while the fault classes stayed merged upstream inside two
blanket `except Exception` handlers, so each round's fix produced the mirror defect the next round had to
find. Plan 03-22 made the fix where round 7 said it had to be made: at `_get_browser()` and
`context.new_page()` — the two collaborator call sites inside `_legacy_screenshot_service`, upstream of
both blanket handlers — never at the return statement alone.

I did not take this on trust. I:

1. **Read every changed line** in `dashboard/app.py`, `dashboard/beacon/previews.py`, and
   `dashboard/beacon/diagnosis.py` against the plan's own `read_first` claims and confirmed each matches
   exactly.
2. **Ran the plan's own new named tests** (`test_a_broken_capture_machinery_fails_j6s_job_health_while_a_per_service_fault_does_not`,
   `test_the_real_manual_scan_poller_fails_closed_on_an_unrecognised_discovery_outcome`,
   `test_the_legacy_manual_scan_poller_also_fails_closed_on_an_unrecognised_discovery_outcome`,
   `test_a_job_stuck_without_an_outcome_becomes_an_operator_exception`) — all green.
3. **Reproduced a scenario the plan's own test does not cover**: `context.new_page()` raising (a browser
   that launched but can no longer open a page) with my own fake context object, driven through the real
   `dispatch_callback`. Same correct result as the `_get_browser()`-raising route: `PreviewCaptureUnavailable`
   raised, J6 durable row `failed`/`PreviewCaptureUnavailable`, exactly one `job_failed` naming `J6`.
4. **Reverted each task's fix in turn** (checking out the pre-commit versions of the touched files) and
   re-ran the corresponding new tests, confirming every one of `03-22-SUMMARY.md`'s five claimed RED-proof
   failures reproduces byte-for-byte, closing the exact concern round 7's IN-04 finding raised about a
   prior round's over-claimed coverage. This round's coverage claims are genuine.
5. **Probed the full malformed-input matrix** round 7 named (`None`, a float, a bool, a numeric string) for
   `discovery_timeout_seconds` directly against the live `_unrecorded_outcome_boundary` function and
   against `compose_active_exceptions`, confirming every variant now degrades to the constant floor instead
   of coercing or raising.
6. **Probed the disclosed residual** (`browser.new_context()` raising inside `browser_proxy_context`'s
   generator, before the `with` body starts) with a `FakeBrowser` and confirmed it behaves exactly as the
   plan's comment discloses: falls through to the per-service classification, J6 still records `succeeded`
   — an honest, correctly-scoped-out residual, not a concealed gap.
7. **Ran the full suite once** (306 passed / 430 subtests, 87s) plus the worker-ownership matrix, the
   cross-module order pair against `tests/test_runtime_ownership.py`, and the three legacy-consumer files
   the plan's Task 2 import does not touch — all green, no regression.

**Every one of the six reproduction scenarios this verification's own method section demanded is
confirmed correct.** All four ROADMAP success criteria are now truthful. TEL-06's background-job-health
clause — the sole open item for seven consecutive rounds — is closed at the code level and independently
reproduced closed.

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Operator can open the dedicated advanced page from the dashboard and return without losing theme. | ✓ VERIFIED | Unaffected this round (`dashboard/advanced.js`/`.html`/`.css` byte-unchanged since round 7). Carried forward from round 7's own reproduction. |
| 2 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, and host freshness. | ✓ VERIFIED | Unaffected this round. Carried forward from round 7's own reproduction. |
| 3 | Operator can inspect every current service's status, latency or failure class, state duration, criticality, tags, and effective health rule. | ✓ VERIFIED | Unaffected this round. Carried forward from round 7's own reproduction. |
| 4 | Operator can view truthful retention, resolution, database pressure, worker freshness, collection gaps, and **background-job health**, and change presentation/refresh/filtering preferences without remote controls. | ✓ **VERIFIED** | **Background-job health is now truthful for every job, including J6, for the first time in eight rounds.** Reproduced below by two independent routes for J6, both directions for J5 (authority-based and legacy pollers), and the full floor-scoping/malformed-input matrix for J2/J1/J5/J9. |

**Score:** 4/4 roadmap success criteria verified (0 present-but-behavior-unverified — every truth above was
exercised by a named test or by my own direct reproduction against a real database, never by symbol
presence alone).

> **On Success Criterion 4, eighth round, first clean close.** Round 5 found four of eleven promotable
> jobs fabricating success; round 7 found one (J6), plus a lower-severity latent inconsistency (J5). This
> round closes both, and — unlike rounds 3, 4, 6, and 7 — introduces no mirror defect, because the fix was
> made at the collaborator boundary the fault classes are still distinguishable at, exactly where round 7's
> own root-cause finding said it had to be made.

### Reproduction Evidence (verifier-executed, round 8)

#### 1. J6 machinery fault — BOTH routes, including one the plan's own test does not cover

```
=== Route A: _get_browser() raises (plan's own named test, re-run here) ===
PASSED — dispatch raises PreviewCaptureUnavailable; J6 failed/PreviewCaptureUnavailable;
preview_requests failed/'thumbnail refresh failed'; job_failed == ['J6'].

=== Route B: context.new_page() raises (MY OWN reproduction — not in 03-22's test) ===
dispatch raised: PreviewCaptureUnavailable browser_unavailable
J6 durable row: {'state': 'failed', 'error_class': 'PreviewCaptureUnavailable'}
preview_requests row: {'status': 'failed', 'error': 'thumbnail refresh failed'}
job_failed exceptions: ['J6']

=== Per-service fault direction, unchanged (round-6 decision holds) ===
dispatch(services, 'J6') == True; J6 row 'succeeded'/None;
preview_requests 'failed'/'title refresh failed (exception); thumbnail refresh skipped'
```

#### 2. J5 fail-closed on an unrecognised discovery literal — both consumers

```
worker_process_scan_requests, run_discovery -> 'an_unrecognised_discovery_outcome':
  dispatch(services, 'J5') -> False
  J5 durable health -> failed
  scan_requests row -> status='failed', error contains 'unknown outcome'

process_scan_requests (legacy), same unrecognised literal:
  scan_requests row -> status='failed', error contains 'unknown outcome'
  (own return value deliberately not asserted -- unreachable from background_job_health in production)
```

#### 3. Floor scoping and malformed-input guard — full matrix, directly against the live function

```
f(cadence, discovery_timeout, job_id):
  f(5, 3600, 'J1') -> 900   (non-discovery job -- unaffected by a widened discovery timeout)
  f(5, 3600, 'J2') -> 900   (same, second non-discovery job)
  f(5, 3600, 'J5') -> 3660  (discovery job -- correctly widened)
  f(None, 3600, 'J9') -> 3660
  f(5, None, 'J1')  -> 900  (was TypeError pre-fix -- now degrades)
  f(5, 900.9, 'J5') -> 900  (float rejected)
  f(5, True, 'J5')  -> 900  (bool rejected)
  f(5, '900', 'J5') -> 900  (str rejected)

compose_active_exceptions(..., discovery_timeout_seconds=None) against a stuck J9 row:
  no raise; job_outcome_unrecorded job_ids == ['J9']
compose_active_exceptions(..., discovery_timeout_seconds=3600) against a stuck J1 row:
  job_outcome_unrecorded job_ids == ['J1']   (was [] pre-fix per round 7's own measurement)
```

#### 4. Disclosed residual — `browser.new_context()` failure, reproduced honest

```
FakeBrowser.new_context() raises RuntimeError('new_context exploded'):
  dispatch result: True
  J6 durable row: {'state': 'succeeded', 'error_class': None}
  preview_requests row: {'status': 'failed', 'error': 'thumbnail refresh failed'}
```
Matches the plan's own disclosure exactly: this failure point sits inside `browser_proxy_context`'s
generator, before `yield context` — outside the `with` body an inner `try/except` could wrap — and is
deliberately not classified as machinery. Not a concealed gap.

#### 5. RED-proof reversal — independently confirmed genuine (not over-claimed)

| Task | Reverted to | New test(s) | Failure reproduced | Matches SUMMARY.md? |
| --- | --- | --- | --- | --- |
| 1 | `b73ec1e~1` | `test_a_broken_capture_machinery_fails_j6s_job_health_while_a_per_service_fault_does_not` | subTest 1: `AttributeError: ... no attribute 'PreviewCaptureUnavailable'`; subTest 2: `'queued' != 'failed'` (documented collateral) | ✓ Exact match |
| 2 | `c2aa34c~1` | `test_the_real_manual_scan_poller_fails_closed_on_an_unrecognised_discovery_outcome` | `AssertionError: True is not False` | ✓ Exact match |
| 2 | `c2aa34c~1` | `test_the_legacy_manual_scan_poller_also_fails_closed_on_an_unrecognised_discovery_outcome` | `AssertionError: 'completed' != 'failed'` | ✓ Exact match |
| 3 | `e574f72~1` | `job_stuck_without_an_outcome` subTest `the_widened_floor_never_reaches_a_job_that_does_not_run_discovery` | `Lists differ: [] != ['J1']` | ✓ Exact match |
| 3 | `e574f72~1` | `job_stuck_without_an_outcome` subTest `a_malformed_discovery_timeout_degrades_one_promotion_instead_of_aborting_the_payload` | uncaught `TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'` | ✓ Exact match |

All five new regressions genuinely discriminate. Working tree restored to clean (`git status --short`
shows only pre-existing untracked `.gsd/`/`.planning/debug/`) after each revert-and-restore cycle.

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/beacon/previews.py` | `PreviewCaptureUnavailable` exception class | ✓ VERIFIED | Present, exactly one definition, correct docstring, correctly placed before `ThumbnailResultRepository`. |
| `dashboard/app.py` | `THUMB_ERROR_BROWSER_UNAVAILABLE` sentinel, two return sites, post-transaction check, raise | ✓ VERIFIED | All four semantic gates pass: sentinel def x1, `return None, None, THUMB_ERROR_BROWSER_UNAVAILABLE` x2, `if thumb_error ==...` x1, `raise beacon_previews.PreviewCaptureUnavailable` x1. Overclaiming comment gone (count 0, was 1). |
| `dashboard/app.py` | `worker_process_scan_requests` / `process_scan_requests` route through `_discovery_outcome_verdict` | ✓ VERIFIED | `beacon_worker_main` referenced exactly 4 times (2 imports + 2 call sites); both call sites confirmed at the correct position (after `outcome = ...`, before `if outcome == 'busy':`). |
| `dashboard/beacon/diagnosis.py` | `DISCOVERY_JOB_IDS` frozenset, scoped/guarded `_unrecorded_outcome_boundary` | ✓ VERIFIED | Definition x1, membership check x1, `job_id` threaded from the one call site (`job['job_id']` passed at diagnosis.py:500). |
| `tests/test_advanced_diagnosis_api.py` | Regressions for all four closure directions | ✓ VERIFIED | 50 test methods (was 48 pre-round; +2), plus 2 new subTests inside a pre-existing method — exactly as the plan specified. All RED-proof claims independently reproduced genuine. |
| `dashboard/advanced.js` / `advanced.html` / `advanced.css` / `dashboard/app.js` | Unchanged this round | ✓ VERIFIED | `git diff 2633b9e..865508c -- dashboard/` touches only `app.py`, `beacon/diagnosis.py`, `beacon/previews.py`. `EVENT_TYPES_VISIBLE` still excludes `preview_capture`; `advanced.js` still has zero references to preview/thumbnail fields. |
| `.planning/REQUIREMENTS.md` | Not self-promoted by the plan | ✓ VERIFIED | `git diff 2633b9e..865508c -- .planning/REQUIREMENTS.md` is empty. Plan deliberately deferred promotion to this independent round. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `_get_browser()` raising inside `_legacy_screenshot_service` | `worker_process_preview_requests` raising `PreviewCaptureUnavailable` | `THUMB_ERROR_BROWSER_UNAVAILABLE` sentinel through the existing `thumb_error` slot | ✓ WIRED, SEMANTICALLY CORRECT | Reproduced via the plan's own test. |
| `context.new_page()` raising inside `_legacy_screenshot_service` | same | same sentinel, second inner try/except | ✓ WIRED, SEMANTICALLY CORRECT | Reproduced by me independently — not covered by 03-22's own test suite. |
| `run_discovery`'s three-literal contract | `worker_process_scan_requests` and `process_scan_requests` failing closed | `beacon_worker_main._discovery_outcome_verdict`, called before busy-branch handling | ✓ WIRED at BOTH consumers | Was PARTIALLY WIRED (J7/J9 only) at round 7; now wired at J5's authority-based poller and its legacy sibling too. |
| `settings.discovery_timeout_seconds` | the `job_outcome_unrecorded` boundary, scoped | `compose_active_exceptions` passing `job['job_id']` into `_unrecorded_outcome_boundary`, which checks `job_id in DISCOVERY_JOB_IDS` | ✓ WIRED, correctly scoped | Was WIRED-OVER-BROADLY at round 7; now reaches only J5/J7/J9. |
| `advanced.js` | the server | one `fetch('/api/advanced/current', {cache: 'no-store'})` | ✓ WIRED | Unchanged. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| --- | --- | --- | --- | --- |
| `/api/advanced/current` | `pipeline.jobs` | `background_job_health` rows | J6's `state` now correctly reflects a genuine machinery fault as `failed`, and a per-service condition as `succeeded` | ✓ **FLOWING** (was HOLLOW for J6 at round 7) |
| `/api/advanced/current` | `exceptions[].job_failed` | `compose_active_exceptions` over `pipeline.jobs` | Now correctly emits for a J6 machinery fault, in addition to J5/J7/J9 | ✓ **FLOWING** (was HOLLOW for J6 at round 7) |
| `/api/advanced/current` | `exceptions[].job_outcome_unrecorded` | `_unrecorded_outcome_boundary`, now job-scoped | Correctly promotes for a non-discovery job wedge independent of `DISCOVERY_TIMEOUT_SECONDS`, and for a discovery job wedge within its configured budget | ✓ **FLOWING** (was over-broad at round 7) |
| `/api/advanced/current` | `pipeline.retention`, `database_pressure`, `worker`, `gaps`, `host.*`, `services[].*` | Unaffected this round | ✓ | ✓ FLOWING (carried forward) |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Plan's own new named tests | `pytest tests/test_advanced_diagnosis_api.py -k "broken_capture_machinery_fails_j6s_job_health or manual_scan_poller_fails_closed or legacy_manual_scan_poller_also_fails_closed or job_stuck_without_an_outcome"` | 4 passed, 18 subtests | ✓ PASS |
| J6 records a machinery fault as failed (Route A, `_get_browser`) | verifier probe via named test | failed / PreviewCaptureUnavailable / `['J6']` | ✓ PASS |
| **J6 records a machinery fault as failed (Route B, `context.new_page`, not in 03-22's own suite)** | verifier probe, own script | failed / PreviewCaptureUnavailable / `['J6']` | ✓ PASS |
| J6 still succeeds on an ordinary per-service fault | verifier probe via named test | succeeded / None | ✓ PASS |
| J5 rejects an unrecognised discovery literal (authority-based) | verifier probe via named test | failed / `'unknown outcome'` in error | ✓ PASS |
| J5 rejects an unrecognised discovery literal (legacy) | verifier probe via named test | `scan_requests` failed / `'unknown outcome'` | ✓ PASS |
| J1's wedge boundary independent of discovery timeout | verifier probe, own script | 900, not 3660 | ✓ PASS |
| Malformed `discovery_timeout_seconds` (None/float/bool/str) degrades, never raises | verifier probe, own script, full 4-variant matrix | all degrade to 900 | ✓ PASS |
| `get_current_diagnosis`/`compose_active_exceptions` never abort on `discovery_timeout_seconds=None` | verifier probe, own script | no raise, `['J9']` promoted correctly | ✓ PASS |
| Disclosed `browser.new_context()` residual behaves as documented | verifier probe, own script | succeeded / None (per-service fallback, as disclosed) | ✓ PASS |
| RED-proof reversal, all 5 new assertions | verifier-executed, 3 revert/restore cycles | all 5 fail exactly as SUMMARY.md claims | ✓ PASS |
| Full suite (run once) | `pytest -q` | 306 passed, 430 subtests, 0 failures | ✓ PASS |
| Ownership/authority fence | `pytest tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py -q` | 32 passed, 123 subtests | ✓ PASS |
| Cross-module order (both directions) | `pytest tests/test_advanced_diagnosis_api.py tests/test_runtime_ownership.py -q` (both orders) | 72 passed / 170 subtests, both orders identical | ✓ PASS |
| Legacy consumers unaffected | `pytest tests/test_durable_queues.py tests/test_release_contract.py tests/test_api_and_auth.py -q` | 47 passed, 63 subtests | ✓ PASS |

### Probe Execution

| Probe | Command | Result | Status |
| --- | --- | --- | --- |
| — | `find scripts -path '*/tests/probe-*.sh'` | no matches | ? SKIP (project defines no probe scripts) |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| **TEL-06** | 03-01…03-22 | Operator can see effective retention, displayed resolution, database pressure, worker freshness, collection gaps, and background-job health. | ✓ **SATISFIED — independently verified, ready for promotion** | All six clauses now reproduced truthful, including background-job health for every job (J1-J9, S1-S3, L1, P0), confirmed by direct reproduction plus RED-proof reversal. `.planning/REQUIREMENTS.md` line 25 and line 123 still read the pre-promotion state (`- [ ] **TEL-06**` / `Gaps Found`) — the plan deliberately left this edit for this independent round; the reconciliation edit itself is left for the orchestrator's downstream step, per this project's established `docs(phase-03): record requirement statuses established by re-verification round N` commit convention. |
| **DIA-01** | 03-01 | Operator can open a dedicated advanced page from either theme. | ✓ SATISFIED | Unaffected this round. Table already reads `Complete`. |
| **DIA-02** | 03-02 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, freshness. | ✓ SATISFIED | Unaffected this round. Table already reads `Complete`. |
| **DIA-03** | 03-03, 03-11, 03-16 | Operator can inspect every service's status, latency/failure class, duration, criticality, tags, health rule. | ✓ SATISFIED | Unaffected this round. Table already reads `Complete`. |
| **DIA-08** | 03-04 | Operator can view effective monitoring settings and change presentation, refresh, **range**, and filtering preferences without remote-control actions. | ⏸ **DEFERRED to Phase 4** | Unaffected this round. Table already reads `Deferred to Phase 4`. |
| **UX-02** | 03-01, 03-05 | Operator can move between dashboard and advanced without losing theme choice. | ✓ SATISFIED | Unaffected this round. Table already reads `Complete`. |

**Orphaned requirements:** none. `grep -E "Phase 3" .planning/REQUIREMENTS.md` maps exactly the six IDs
`03-22-PLAN.md`'s `requirements:` frontmatter declares, matching every prior round.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `dashboard/app.py` | (was 2028-2037, overclaiming comment) | — | ✓ **CLOSED** | The false comment asserting a safety property the code did not have is gone (grep count 0, confirmed). Replaced with an accurate statement of what the code now guarantees. |
| `dashboard/app.py` | (was 930-932, 982-984, merged fault classes) | — | ✓ **CLOSED** | Both blanket `except Exception` handlers now sit downstream of the new narrow try/excepts around `_get_browser()` and `context.new_page()`; the machinery fault class is intercepted before either blanket handler is reached. The one remaining unclassified path (`browser.new_context()`, genuinely unreachable from the `with` body) is honestly disclosed in a comment, not silently claimed as covered. |
| `dashboard/app.py` | (was 1844, 1906, exclusion-based outcome decision) | — | ✓ **CLOSED** | Both sites now call `_discovery_outcome_verdict` by membership before their busy-branch handling. |
| `dashboard/beacon/diagnosis.py` | (was 56, coercion) | — | ✓ **CLOSED** | `int(...)` coercion replaced by `type(...) is int and ... > 0` guard, matching the sibling `cadence_seconds` convention on the very next line, as the module's own comment now states explicitly. |
| `dashboard/app.py` | 1831 → `worker_main.py:353-357` | A request-level condition raising a class the dispatcher treats as worker-level (`LeaseLost` on the busy branch reaching `stop_worker()`) | ⚠️ Warning (carried forward, unaffected) | 03-21-REVIEW.md WR-03. Not touched by this round; not part of either closed gap. |
| `dashboard/app.py` | 1334-1343 | Uptime-disclosure boundary jitter comment | ⚠️ Warning (carried forward, unaffected) | 03-21-REVIEW.md WR-05. Not touched by this round. |
| `dashboard/beacon/worker_main.py` | 206 | Bare `ValueError` for unknown-outcome, unbounded `{outcome!r}` interpolation | ℹ️ Info (carried forward, unaffected) | 03-21-REVIEW.md IN-02/IN-03. Not touched by this round; this round's two new call sites (app.py:1862, 1937) reuse this same helper without modification, so the same Info applies at two more call sites — cosmetic, not a new finding. |

**Debt-marker gate:** PASSED. `grep -n -E "\bTBD\b|\bFIXME\b|\bXXX\b|\bTODO\b|\bHACK\b|PLACEHOLDER"` over
`dashboard/app.py`, `dashboard/beacon/diagnosis.py`, `dashboard/beacon/previews.py`,
`dashboard/beacon/worker_main.py`, and `tests/test_advanced_diagnosis_api.py` returns zero matches. No
debt markers introduced.

### Human Verification Required

#### 1. Real collection gap and stale host on the target Pi

**Test:** Open `/advanced` on the Pi while a real collection gap is active and while host evidence is stale.
**Expected:** The workspace shows the open gap and the stale host as real, correctly labelled exceptions, and shows no resolved or retention-expired interval as an open actionable gap.
**Why human:** Carried forward from all seven previous reports. Still not performed on real hardware through eight rounds. This same item remains open for DIA-01/DIA-02/DIA-03/UX-02, all of which are already `Complete` in `REQUIREMENTS.md` — established project convention treats this as a standing human-verification item, not a promotion blocker, once the code-level truth is independently reproduced.

#### 2. Idle Pi, one minute, Active exceptions region

**Test:** Start the worker on the Pi, leave the system idle for one minute, open `/advanced` and read the Overview "Active exceptions" region.
**Expected:** No "Background job failed" card for any job, and no "Background job outcome not recorded" card for any job that is simply working.
**Why human:** Recorded by round 4. Still not performed on real hardware. My reproductions establish it on a real SQLite database through the real production adapters for every job including J6, and it passes there.

#### 3. Deliberately broken browser, two minutes, Pipeline region

**Test:** With Chromium/Playwright deliberately unavailable on the Pi, leave the worker running for two minutes, then open `/advanced` and read the Pipeline region.
**Expected:** A "Background job failed" card names J6 — the new operator-facing signal this round's fix adds.
**Why human:** New in round 7, carried forward. My reproduction establishes the durable facts on a real database through the real production adapters and the real `dispatch_callback`: J6's row now reads `failed`/`PreviewCaptureUnavailable`, exactly one `job_failed` names `J6`. Confirming this renders correctly in the actual browser-served Pipeline region on real hardware is the one remaining step outside this verifier's reach — this is the check that finally confirms the fix holds where the operator will actually see it.

### Gaps Summary

**None.** Both of round 7's gaps (J6's missing machinery-fault signal folded with J5's fail-open discovery
vocabulary as gap 1; the global, coercing `job_outcome_unrecorded` floor as gap 2) are closed at the code
level and independently reproduced closed, including a scenario (`context.new_page()` raising) and an
input matrix (float/bool/string malformed timeouts) that 03-22's own test suite does not itself cover.

Three human-verification items remain — all requiring real Raspberry Pi hardware, all carried forward
unchanged in kind from prior rounds, none blocking TEL-06's code-level determination per this project's
own established convention (the same class of item remains open against DIA-01/DIA-02/DIA-03/UX-02, all
already `Complete`). Overall status is `human_needed`, not `passed`, solely because these three items exist
— not because any observable truth failed.

---

_Verified: 2026-08-19T21:35:00Z_
_Verifier: Claude (gsd-verifier), round 8, adversarial goal-backward_
_All reproductions run against a real SQLite database via `tests.helpers.load_app`, through the real production adapters and the real `worker_main.dispatch_callback`. Every RED-proof claim in `03-22-SUMMARY.md` was independently reproduced by reverting the corresponding commit and re-running the test, not accepted on the summary's word. No claim below is taken from a SUMMARY or PLAN without independent confirmation._
