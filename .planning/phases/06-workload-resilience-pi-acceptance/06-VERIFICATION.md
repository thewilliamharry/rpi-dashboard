---
phase: 06-workload-resilience-pi-acceptance
verified: 2026-09-07T08:03:39Z
status: gaps_found
score: 4/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
prohibitions:
  - statement: "PROH-OPS-07-01 — a route budget may never be tuned so that a failing measurement passes"
    status: verified
    verification: test
    evidence: "`ROUTE_BUDGETS_MS` (tests/pi_load_acceptance.py:103) is BYTE-IDENTICAL to its introduction in `807776a` (06-06, 2026-09-01). Verified by extracting the dict block at `807776a`, at `32781e5` (06-07) and at HEAD and diffing all three: no difference. `git log -L '/^ROUTE_BUDGETS_MS = {/,/^}/'` names exactly one commit in the block's entire history."
  - statement: "PROH-OPS-07-10 — a success criterion may never be weakened because the code could not meet it"
    status: verified
    verification: test
    evidence: "The criterion-5 amendment is commit `63db9ef` (2026-09-04). `git show --stat 63db9ef` touches THREE files, all planning Markdown: `.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md`, `06-DEBT.md`. Zero lines of `dashboard/` or `tests/`. Independently confirmed that `assert_response_times`, `assert_resource_budget`, `assert_cadence` and `_routes_for_ports` are untouched since 06-06 (`807776a`) and `_load_worker` since 06-07 (`5e29ab3`) — all five predate the amendment. Harness defaults remain `--concurrency 8` (line 1792) and `--duration 600` (line 1781); the gating run passes `--concurrency 3` explicitly on the command line, exactly as the amendment note claims."
  - statement: "The criterion-5 amendment's justification is usage, not difficulty"
    status: verified
    verification: test
    evidence: "Every claim in the ROADMAP block quote checked against source. `dashboard/app.js:795` is `Promise.allSettled([loadStats(), loadHistory(), loadScan(), loadServices(), loadEvents()])` — five parallel calls at page load. `setInterval` at :796 (5000ms, loadStats+loadScan), :797 (15000ms, loadServices+loadEvents), :798 (60000ms, loadHistory). That is 33 requests per 60s = 0.55 req/s per tab, matching the note's 'roughly 0.5 requests per second'. `/api/services` specifically: 1/15s = 0.067 req/s. The gating harness drove it at 1381 requests / 601s = 2.298 req/s = 34.5x. The amendment describes the deployment accurately and the resulting gate is still ~34x conservative."
  - statement: "PROH-OPS-07-11 — an instrumented run may never be presented as acceptance evidence"
    status: verified
    verification: test
    evidence: "Parsed `beacon-c3-run3.json` directly: `run_kind: 'acceptance'`, `lock_profile: {}` (empty), `scenario.self_test: false`, `scenario.concurrency: 3`, `scenario.duration_seconds: 600`, `host_machine: aarch64`, `host_node: raspi`, elapsed `1788708625 - 1788708024 = 601s`. All gating properties as declared."
  - statement: "PROH-OPS-07-08 — OPS-07 may not be promoted by a plan in its own round"
    status: verified
    verification: judgment
    evidence: "`.planning/REQUIREMENTS.md:73` still carries `- [ ]` (unchecked) for OPS-07 and the traceability row at :158 reads `Accepted with deviation`, not `Complete`. `06-27-SUMMARY.md` states in `key-decisions` that it 'does not mark OPS-07 anything but Pending'. The promotion decision was taken separately by the operator in `1f0ce4b`."
  - statement: "PROH-OPS-07-28 — a NULL `online` row is never coalesced away by the strip input reduction"
    status: unverified
    flagged: true
    verification: test
    evidence: "The branch IS PRESENT and correct at `dashboard/app.py:2969-2978`. But it is NOT ENFORCED on the shipping route: this verification collapsed the NULL branch on the real route (mutation M2) and the ENTIRE 993-test suite stayed green. See gap 2. No live exposure — no writer produces a NULL — so this is flagged, not blocking."
re_verification:
  previous_status: gaps_found
  previous_score: 4/5
  gaps_closed:
    - "The `/api/services` uptime-truncation regression (round-3 gap 2; `D-DEBT-06-10`) is CLOSED and the closure is independently reproduced. `dashboard/app.py:2928`'s `all_checks` query carries no `LIMIT` clause and is preceded by a 40-line comment marking it deliberately unbounded and naming `D-DEBT-06-10`. The row cap is applied in Python at :2939/:2979-2981 against `points_by_port` only, so it reaches the offline-interval reconstruction and never `_uptime_summary`. Not accepted on prose: this verification re-applied the exact defect (mutation M1 — push `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` back into the SQL, with a truncating cap) and confirmed BOTH phase guards fire (`test_the_route_does_not_bound_the_uptime_read_with_the_interval_row_cap`, `test_uptime_pct_is_not_affected_by_the_offline_interval_row_cap`) AND an independently-written end-to-end differential fires, catching a service reporting 6.563% uptime against a true 87.194%. The guard is diagnostic, not decorative — which is precisely what the round-3 report found the ORIGINAL guard was not."
    - "The round-3 gap item 'instrument `_db_lock` directly under load and report wait-vs-hold per route' is discharged as an activity — rounds 4 and 5 performed it (`06-LOCK-DIAGNOSTIC.md`, `-R5A`, `-R5B`) and the round-3 report's `_db_lock` attribution was confirmed rather than refuted. The consequent FIX is not landed: `ea8689e` reverted 06-20's narrowing and it was never re-landed, so `api_services` still holds the process-wide lock across its entire handler body at HEAD (`dashboard/app.py:2875` to first dedent at :3076)."
    - "The round-3 gap item 'measure how much of `/api/services`' critical section is actually database work' and 'reduce that residual cost' are discharged. Rounds 6/6.5/7 cut per-request cost substantially: `06-PROFILE-5.md` measured 34.927ms against the pre-06-25 56.820ms bar on the dev host (-38.53%, first round of the phase to beat the baseline), and `06-PI-PROFILE-C.md` reproduced it on the Pi at 77.081ms vs 140.323ms (-45.07%). Both verified against the committed `beacon-pi-profile-{before,after}-{1,2,3}.json`."
    - "The round-3 gap item 'a fourth hardware acceptance run after a fix' is discharged as an activity, THREE times, under the amended criterion — `06-ACCEPTANCE-C3.md` (2026-09-04, `a33af15`), `06-ACCEPTANCE-C3-RUN2.md` (2026-09-05, `82801cb`) and `06-ACCEPTANCE-C3-RUN3.md` (2026-09-06, `a7c3ef1`). Run 3's build is code-identical to HEAD (`git diff --stat a7c3ef1..HEAD -- dashboard/ tests/` is empty). All three results are failing, so the underlying truth does not close."
    - "The security-boundary re-close that `PROH-OPS-04-05` had required since round 5 is performed — `06-SECURITY.md` now carries 88 threat rows at HEAD (independently counted), matching 06-28's claimed 42→88 expansion."
  gaps_remaining:
    - "Criterion 5: `/api/services` p95 exceeds its 500ms budget on all three concurrency-3 hardware runs (635.6 / 679.3 / 662.3ms). The failure has NARROWED — from five routes over budget in round 1, to three in round 3 at concurrency 8, to exactly one at concurrency 3 — but it has not closed, and run 3 measures HEAD's own code."
  regressions:
    - "None. The `/api/services` uptime regression that round 3 recorded as a `regressions:` entry is closed and re-proved closed by mutation. No new correctness regression found. The full suite is independently confirmed green at HEAD: 993 passed, 593 subtests, 0 failures, 5m36s (`cd dashboard && uv run --frozen pytest -q`)."
gaps:
  - truth: "A Raspberry Pi-class run at single-operator load — concurrency 3, 600s, every declared route budget unchanged — demonstrates responsive interaction, resource-budget compliance, recovery, and uninterrupted essential sampling"
    status: failed
    reason: "The gating run WAS performed on real Pi-class hardware (aarch64/raspi) and returned `overall_passed: false`. Three independent runs, all failing, all on the same single route: `/api/services` p95 635.6ms (run 1), 679.3ms (run 2), 662.3ms (run 3) against a 500ms budget. Run 3's build `a7c3ef1` is code-identical to HEAD, so this is HEAD's measured result, not a stale build's. Three of the criterion's four clauses PASS outright — resource-budget compliance (worker RSS 553.6MB < 1GiB, web 117.1MB < 256MiB), recovery (all 12 `background_job_health` rows `succeeded`, no `error_class`) and uninterrupted essential sampling (`assertions.cadence` `{passed: true, failures: []}`, J1-J4 all `fresh`). ONLY the 'responsive interaction' clause fails, and only on one of six exercised routes. Independently recomputed p50/p95 from the raw 16,547 latency samples in `beacon-c3-run3.json` rather than trusting the report's table: `/api/services` p95 = 662.3ms, confirming every figure. SEPARATELY: the operator recorded decision (a) 'accept the deviation' on 2026-09-06 (`1f0ce4b`), and `.planning/REQUIREMENTS.md:158` reads `Accepted with deviation` — NOT `Complete`. That acceptance is legitimate and well-documented but it is not a measurement, and it has not been entered into this file's `overrides:` channel, so this truth is scored as measured: FAILED. See 'Suggested override' in the body."
    artifacts:
      - path: ".planning/phases/06-workload-resilience-pi-acceptance/beacon-c3-run3.json"
        issue: "`overall_passed: false`; `failure_reasons: ['/api/services: p95 662.3ms exceeds budget 500ms']`. Admissible as OPS-07 evidence on every gating property (`run_kind: acceptance`, `lock_profile: {}`, `concurrency: 3`, `duration_seconds: 600`, `self_test: false`, `host_machine: aarch64`, `host_node: raspi`, 601s elapsed) — which is what makes the failure count."
      - path: "dashboard/app.py"
        issue: "The mechanism the round-3 report attributed and rounds 4-5 measured is STILL PRESENT at HEAD and unfixed. `api_services` takes the process-wide `_db_lock` (declared line 139) at line 2875 and the first dedent back to function level is line 3076 — the lock spans the entire handler body, including all the Python computation. 06-20 narrowed this to database reads only; `ea8689e` reverted that narrowing and it was never re-landed. `D-DEBT-06-27`'s round-7 finding (two routes inflating 6.9x under concurrency 3 while four are unaffected, 'consistent with lock contention') is recorded as an untested hypothesis. This is the honest reason the route still misses, and it is disclosed rather than hidden."
      - path: ".planning/phases/06-workload-resilience-pi-acceptance/06-PI-PROFILE-C.md"
        issue: "Not a defect in the artifact — a gap in the ACCEPTANCE'S EVIDENCE CHAIN. The operator's stated reasoning is 'at the real rate the route's measured cost is segment A's 77.1ms'. That 77.081ms figure is real, Pi-class, and on the correct build — but it is `wall_ms_unprofiled` from a cProfile-instrumented IN-PROCESS measurement, not an HTTP p95 through gunicorn at any concurrency. No concurrency-1 HTTP control run exists on the accepted build `a7c3ef1`; the most recent c1 HTTP evidence is 289.0ms p50 / 300.1ms p95 from round 5, on the older build segment A measures at 140.323ms. Both numbers are comfortably inside 500ms so the conclusion is very likely right, but 'meets its budget at real usage' currently rests on an inferential step rather than a direct measurement."
    missing:
      - "EITHER accept the deviation formally in this file's `overrides:` frontmatter (block ready to paste in the body below), which converts this truth to `PASSED (override)` and makes the operator's already-recorded decision a first-class part of the verification verdict — OR close the gap by measurement."
      - "One `--concurrency 1 --duration 600` acceptance run on the Pi against `a7c3ef1`/HEAD. This is the cheapest item on this list and it converts the acceptance's central claim from inference to direct HTTP measurement at single-operator load. `06-ACCEPTANCE-RUNBOOK.md` already documents the exact invocation, including the sqlite3-CLI-not-installed detail. Prediction to falsify: `/api/services` p95 lands between 77ms and 300ms, well inside budget."
      - "OPTIONAL, and explicitly NOT required to close this gap: option (b) from `06-ACCEPTANCE-C3-RUN3.md` — re-derive the harness's load model to a think-time-bearing client shape calibrated against `app.js`'s actual polling rate. The record already warns that this and the forbidden move look identical from outside; if pursued it must be documented at least as carefully as `D-DEBT-06-20`'s amendment was."
      - "OPTIONAL: option (c) — a round 8 attributing `D-DEBT-06-27`'s selective 6.9x inflation. The structural candidate is already named and confirmed present at HEAD: `api_services` holds `_db_lock` across 200 lines of mostly-Python work (app.py:2875-3075). Four of this phase's seven rounds already chased a hypothesis that did not fully explain the result; scope it to confirm-or-refute a named mechanism, not to search."
  - truth: "A NULL `online` row is never coalesced away by 06-31's input reduction: the producer still refuses the same inputs it refuses at HEAD, with the same exception type (`PROH-OPS-07-28`, `06-31-PLAN.md` must_haves)"
    status: partial
    reason: "The CODE is correct — `dashboard/app.py:2969-2978` appends every NULL row unconditionally and resets `last_state_by_port[port] = None` so the row following a NULL is also always appended. The PROOF does not exist on the shipping path. This verification collapsed the NULL branch on the real route (mutation M2: replace the two-branch body with `state = 1 if online else 0` so `None` is treated as merely falsy) and the ENTIRE 993-test suite stayed green — the only failure was the separately-disclosed `(function, line)` lock-audit line-shift, which my edit triggered incidentally and which `D-DEBT-06-25` documents as expected. Root cause: `UptimeStripCoalescingDifferentialTests` asserts NULL preservation against `_reduce_to_state_changes`, a MIRROR copy that lives in the test file; the single test that binds the mirror to the real route (`test_mirror_agrees_with_the_route_on_its_own_loop`) seeds a fixture of only 0/1 rows and contains no NULL. So the mirror is NULL-tested and the route is not. This is the same shape as `D-DEBT-06-10` and `D-DEBT-06-22`: a green gate over an unexercised path. Severity is WARNING, not blocker — `service_checks.online` is nullable in schema (`migrations.py:120`, no `NOT NULL`), but both writers (`app.py:1468` and `:1665`) bind 0/1 integers, so no shipping code path currently produces a NULL. This is an unguarded defensive invariant with no live exposure."
    artifacts:
      - path: "tests/test_services_route_scaling.py"
        issue: "`test_mirror_agrees_with_the_route_on_its_own_loop` (the one test that binds the test-file mirror to the real route) uses `rows = [(now-6000,1),(now-5900,1),(now-5800,1),(now-5000,0),(now-4900,0),(now-4000,1),(now-2000,0),(now-1900,0)]` — every value is 0 or 1. `UptimeStripCoalescingDifferentialTests` does exercise NULLs, but only against `_reduce_to_state_changes`, the mirror function defined at line 1852 of this same test file, not against `dashboard/app.py`."
    missing:
      - "Add one NULL row to `test_mirror_agrees_with_the_route_on_its_own_loop`'s fixture, positioned immediately after an offline run (the exact case `PROH-OPS-07-28` names — the divergence the phase measured on 39 of 1,802 randomized cases). The test already captures what the route hands `_uptime_summary` via its `spy`, so no new machinery is needed; the mirror already handles NULL correctly, so the assertion will pass at HEAD and fail against mutation M2. Roughly a two-line change."
deferred: []
human_verification:
  - test: "Run the acceptance harness on the Pi at single-operator concurrency against HEAD's build: `--concurrency 1 --duration 600`, uninstrumented (confirm `/api/diagnostics/lock-profile` returns 404 before starting), `run_kind: acceptance`, `self_test: false`. `06-ACCEPTANCE-RUNBOOK.md` carries the exact invocation and the three invocations that silently produce inadmissible results."
    expected: "`/api/services` p95 comfortably inside its 500ms budget — predicted between 77ms and 300ms. This is the single measurement that would convert the operator's acceptance rationale from an inferential step (a cProfile in-process 77.1ms) into a direct HTTP measurement at the rate the deployment actually generates."
    why_human: "Requires real Raspberry Pi-class hardware with the live Docker deployment. `PROH-OPS-07-02` forbids treating anything but a genuine hardware run as OPS-07 evidence, and no CI or dev-host substitute is admissible."
  - test: "Decide the disposition of criterion 5 in this file's `overrides:` channel. The operator's 'accept the deviation' decision of 2026-09-06 is recorded in `.planning/REQUIREMENTS.md`, `.planning/STATE.md` and `06-ACCEPTANCE-C3-RUN3.md`, but not here — so this verification scores the truth as measured (FAILED) rather than accepted."
    expected: "Either the ready-to-paste `overrides:` block in the body is added to this frontmatter (making the score 5/5 with `overrides_applied: 1`), or the deviation is left unaccepted at the verification layer and the gap stands as written."
    why_human: "A verifier cannot grant its own override. Accepting a measured failure is a governance decision reserved to the operator, and `PROH-OPS-07-08` scopes OPS-07's promotion to an independent round — this one — precisely so the acceptance is visible rather than absorbed."
---

> ## Superseded rounds — condensed 2026-09-07
>
> Following this phase's convention that no measurement is superseded, only added to. The prior
> report's findings are preserved below in compressed form; every one of them has since been
> discharged or carried forward into this round's `re_verification` block.
>
> **Round 1 (2026-09-01, `gaps_found` 4/5).** OPS-07's first hardware run failed with ALL FIVE
> exercised routes over budget (`/api/services` p95 10010.9ms). Surfaced two blocking defects —
> `/api/services` costing ~2.5s CPU per request, and a harness resource oracle sampling an unrelated
> application on the same host. Recorded as `06-UAT.md` gap `G-06-1`.
>
> **Round 2 (2026-09-02, `gaps_found` 4/5).** Recorded the harness CPU column as a structural `0.0`
> (✗ STUB) and asked for the residual per-request cost to be profiled and reduced.
>
> **Round 3 (2026-09-02, `gaps_found` 4/5).** Confirmed the CPU-sampling fix behaviourally on
> hardware (594 non-zero web samples, `all_samples_zero: false`). Confirmed `06-13`'s memoization as
> substantive with `/api/services` control p50 down 27.6% (289.0 → 209.355ms). Third hardware run
> still failed with three routes over budget at concurrency 8. Its two load-bearing contributions:
>
> 1. **It named the serialization mechanism as `_db_lock`** from evidence already in the repository,
>    against `D-DEBT-06-09`'s position that the mechanism was unattributable. The chain: the lock is
>    a single process-wide `threading.Lock` taken by 5 of 6 exercised routes; `api_services` holds it
>    across its entire handler body of which only ~18% is SQL; the harness's rotation puts
>    `/api/scan-status` immediately after `/api/services`; and `/api/scan-status`' excess wait
>    (239.333ms) is 1.143x one `/api/services` critical section. It also showed
>    `D-DEBT-06-01`'s reopening test was non-diagnostic and that the "165.504% CPU weakens the
>    one-interpreter hypothesis" inference was unsound. **Rounds 4 and 5's instrumented Pi passes
>    confirmed this attribution rather than refuting it.** It remains structurally true at HEAD.
> 2. **It caught a data-correctness regression that the entire green test suite could not see** —
>    `06-13` had extended `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` onto the uptime path, so a service with
>    a real outage reported 100.0% uptime behind a fully-populated 168-hour bar. Fixed in `bcad398`,
>    recorded as `D-DEBT-06-10`, and **re-proved closed by mutation in this round.**
>
> **Orchestrator addendum (2026-09-02).** Recorded that the uptime regression was closed in `bcad398`
> with a mutation-verified output-level guard replacing the SQL-shape-only one; that
> `06-REVIEW-ROUND3.md`'s CR-02 (`_window_from_row_cached` keyed on `id(row)`) and CR-03
> (`--self-test` reporting `primed_pid_count: 0`) were fixed in `631381f`; and that the `_db_lock`
> attribution was accepted, with `D-DEBT-06-09` updated to carry it.
>
> **Rounds 4-7 (2026-09-03 → 2026-09-06), not previously verified.** Round 4's diagnostic returned
> INCONCLUSIVE; the operator chose `fix-now`. Round 5 landed the lock narrowing (`06-20`) and then
> **reverted it in `ea8689e`**, superseding `06-23`/`06-24`. Criterion 5 was amended on 2026-09-04.
> Round 6 (`06-25`/`06-26`) moved the uptime strip to bulk SQL and was **REFUTED** at +315.8%.
> Round 6.5 (`06-29`/`06-30`) reshaped the join to -70.71%, still 21.8% over the bar, and decided
> `revert-route-wiring`. Round 7 (`06-31`/`06-32`) reverted `06-25`'s wiring and reduced the strip's
> input to state-change points only: **34.927ms against the 56.820ms bar, the first round of the
> phase to beat the pre-`06-25` baseline.** `06-27` then measured that build on the Pi (-45.07% per
> request) and ran the third gating acceptance run, which failed. `06-28` re-closed the security
> boundary (42 → 88 threat rows).

---

# Phase 6: Workload Resilience & Pi Acceptance Verification Report

**Phase Goal:** Beacon keeps essential monitoring reliable while discovery and previews operate as bounded, recoverable best-effort work on Raspberry Pi-class hardware.

**Verified:** 2026-09-07T08:03:39Z
**Status:** gaps_found
**Score:** 4/5
**Re-verification:** Yes — **round 4 of verification**, after plans `06-15` through `06-32` (the prior report predates `06-15`). Supersedes the 2026-09-02 report, condensed above.

**Verified against the AMENDED criterion 5** as it reads in `.planning/ROADMAP.md` today
(amended `63db9ef`, 2026-09-04), not the original "representative load" wording the prior report used.

## The headline answer

**Criterion 5 is FAILED as measured, and separately Accepted-with-deviation as dispositioned. Both
are true and they are not in conflict.**

- The gating concurrency-3 acceptance run **was** performed on real Pi-class hardware — three times.
- All three returned `overall_passed: false`, failing on the same single route.
- Run 3's build is **code-identical to HEAD**, so the failure is the current code's failure.
- The operator accepted the deviation on usage grounds on 2026-09-06. That acceptance is legitimate,
  well-reasoned, and correctly recorded — but it is a governance act, not a measurement, and it has
  not been entered into this file's `overrides:` channel.

`.planning/STATE.md`'s two claims are both **accurate at HEAD**: OPS-07 is recorded as accepted with
deviation on usage grounds rather than passed, and all three failing runs stand unsuperseded.

## Goal Achievement

### Observable Truths

| # | Truth (ROADMAP Success Criterion) | Status | Evidence |
|---|------|--------|----------|
| 1 | Metric sampling and service checks remain within their accepted cadence while discovery, previews, cleanup, and analytics queries are active | ✓ VERIFIED | Lane split intact at HEAD: `dashboard/beacon/worker_main.py:465-466` declares separate `ThreadPoolExecutor(1)` for `'metrics'` and `'cleanup'`, with J1/J2 pinned to `executor='metrics'` (:84-85) and J8's hourly retention pass to `executor='cleanup'` (:91) — the comment at :457-459 states the OPS-01 intent explicitly. `CadenceUnderContentionTests` present at `tests/test_workload_resilience.py:524` and passing in this verification's own clean full-suite run. **Backed by the amended criterion's own hardware run**, parsed from raw JSON not from the report: `assertions.cadence` = `{"failures": [], "passed": true}`, all four `freshness_by_job` states `fresh` (J1 0s, J2 0s, J3 200s, J4 20s), across the full 601s window at concurrency 3. Cadence has now held on **every** hardware run this phase has produced, including all six that failed on latency. |
| 2 | Preview work has one serialized browser owner, bounded deadlines and retries, and a visible non-fatal degraded state instead of blocking core monitoring | ✓ VERIFIED | No regression. `dashboard/beacon/queues.py:28` `PREVIEW_STATUS_DEGRADED = 'degraded'`; bounded deadlines throughout (`deadline_ts` at :55, :347, :369, :373, :415-420) with lease-based serialized ownership (`lease_owner`/`lease_until` at :475, :500). WR-02's precedence fix survives every subsequent edit — now at `dashboard/app.py:3282-3286`, with the rationale ("a servable stored thumbnail outranks a degraded latest preview request") intact. `queues.py` untouched since round 3. |
| 3 | Thumbnail data expires within a bounded managed store and no longer puts large preview blobs on Beacon's primary telemetry path | ✓ VERIFIED | No regression. Migration 10 (`dashboard/beacon/migrations.py:604-624`) creates `thumbnails(port, data, mime, captured_ts, source, expires_ts)` with `idx_thumbnails_expires`, backfills every existing blob, and `UPDATE services SET thumb_data=NULL, thumb_mime=NULL` — the whole sequence inside the migration's `BEGIN IMMEDIATE` per `PROH-OPS-03-01`. `ThumbnailStoreRepository` at `repositories.py:709`. **Confirmed on hardware at concurrency 3**: `assertions.resources.passed: true`, worker RSS 553,615,360 B against a 1 GiB limit, web RSS 117,129,216 B against 256 MiB. |
| 4 | Beacon recovers predictably from restarts, concurrent web/worker database activity, and failed background jobs, as proven by automated runtime and persistence coverage | ✓ VERIFIED | No regression. WAL in force: `dashboard/beacon/db.py:27` `JOURNAL_MODE = 'WAL'`, applied per connection at :201, with `configured_journal_mode` at :209 for verification. `WalModeTests` (:690), `ConcurrentAccessTests` (:749) and `NarrowedShapeConcurrentAccessTests` (:945) all present in `tests/test_workload_resilience.py` and passing. **Confirmed on hardware**: all 12 `background_job_health` rows read `state: succeeded` with no `error_class`. Note the same non-conflict the round-3 report identified: `_db_lock` is doing its correctness job here, and expensively — truth 5's finding is the same lock's performance consequence, not a contradiction of this one. |
| 5 | A Raspberry Pi-class run at single-operator load — concurrency 3, 600s, every declared route budget unchanged — demonstrates responsive interaction, resource-budget compliance, recovery, and uninterrupted essential sampling | ✗ FAILED | `overall_passed: false` on real hardware (`host_machine: aarch64`, `host_node: raspi`) against `a7c3ef1`, **independently confirmed code-identical to HEAD** (`git diff --stat a7c3ef1..HEAD -- dashboard/ tests/` → empty). Three of four clauses PASS. The fourth — responsive interaction — fails on exactly one of six routes: `/api/services` p95 662.3ms vs a 500ms budget, the third consecutive independent miss (635.6 / 679.3 / 662.3). Separately **Accepted with deviation** by recorded operator decision, which this report does not treat as a pass. |

**Score:** 4/5 truths verified. 0 present-but-behavior-unverified. 0 overrides applied.

---

## Truth 5, settled

### The open question: was the gating run ever performed, and what did it return?

**Yes — three times, all on real Pi-class hardware, all failing.** This was verified from the raw
committed artifacts, not from SUMMARY prose.

| Run | Date | Build | Build vs HEAD | `/api/services` p95 | Result |
|---|---|---|---|---|---|
| 1 (`06-ACCEPTANCE-C3.md`) | 2026-09-04 | `a33af15` | 5 files differ | 635.6ms | FAIL +27% |
| 2 (`06-ACCEPTANCE-C3-RUN2.md`) | 2026-09-05 | `82801cb` | 5 files differ | 679.3ms | FAIL +36% |
| 3 (`06-ACCEPTANCE-C3-RUN3.md`) | 2026-09-06 | `a7c3ef1` | **identical** | **662.3ms** | **FAIL +32.5%** |

Run 3 is the one that matters for this verification, because it is the only one measuring the code
that is actually in the tree.

**Admissibility, parsed directly from `beacon-c3-run3.json`:**

| Property | Value | Required |
|---|---|---|
| `run_kind` | `acceptance` | ✓ |
| `scenario.concurrency` | `3` | ✓ |
| `scenario.duration_seconds` | `600` (601s elapsed) | ✓ |
| `scenario.self_test` | `false` | ✓ |
| `lock_profile` | `{}` (uninstrumented) | ✓ `PROH-OPS-07-11` |
| `host_machine` / `host_node` | `aarch64` / `raspi` | ✓ `PROH-OPS-07-02` |

**Percentiles recomputed from the raw samples, not read from the report's table.** The JSON carries
`route_latencies_ms` — 16,547 individual measurements. Recomputing p50/p95 independently:

| route | n | p50 | p95 | budget | result |
|---|---:|---:|---:|---:|---|
| `/api/services` | 1381 | 530.1 | **662.3** | 500 | **FAIL** |
| `/api/advanced/current` | 1380 | 508.1 | 549.6 | 2000 | pass |
| `/api/scan-status` | 1380 | 8.1 | 192.1 | 500 | pass |
| `/api/thumbnail/<port>` | 9646 | 7.8 | 204.5 | 1500 | pass |
| `/api/history` | 1380 | 17.6 | 38.4 | 2000 | pass |
| `/api/thumbnail-status` | 1380 | 8.5 | 11.8 | 750 | pass |

Every figure reproduces. The reports are accurate.

**The failure has narrowed monotonically across the phase** — five routes over budget in round 1,
three in round 3 at concurrency 8, exactly one at concurrency 3 — but it has not closed.

### Is the criterion met, failed, or accepted-with-deviation?

**Plainly: FAILED as measured; Accepted-with-deviation as dispositioned.**

The criterion's own text requires the run to *demonstrate responsive interaction*. It did not, on the
route whose budget rationale is specifically "a slow response here is a slow-feeling UI". No reading
of the amended text makes 662.3ms against 500ms a pass.

The operator's acceptance (recorded 2026-09-06 in `1f0ce4b`, present at HEAD in
`.planning/REQUIREMENTS.md:74`, `.planning/STATE.md` and `06-ACCEPTANCE-C3-RUN3.md`) is a separate
and legitimate act. Its arithmetic was checked and holds exactly:

- `dashboard/app.js:797` polls `loadServices` every 15,000ms → **0.067 req/s**. ✓
- The harness drove `/api/services` at 1381 / 601s = **2.298 req/s** inside a 16,547 / 601 = **27.5
  req/s** total offered load, closed-loop with zero think time. ✓ (report says 2.30 and 27.6)
- 2.298 / 0.067 = **34.5x** the real per-route rate. ✓

The record is also unusually candid about its own limits: it states the decision "is not a claim that
the route passes its budget", that all three failing runs stand unsuperseded, that option (b) remains
unexercised, and that `D-DEBT-06-27`'s untested contention finding is the condition under which the
acceptance should be revisited.

**Why this report still scores it FAILED.** `PROH-OPS-07-08` reserves OPS-07's promotion to an
independent verification round — this one. The mechanism by which an operator decision enters a
verification verdict is the `overrides:` frontmatter channel, and no such entry exists in this file.
Scoring the truth as passed on the strength of a decision recorded elsewhere would do exactly what
`PROH-OPS-07-08` exists to prevent: make the acceptance invisible in the verdict. So the measurement
stands as the score, and the acceptance is surfaced as a decision awaiting its channel.

### Suggested override

**This looks intentional.** The deviation is a documented, dated, reasoned operator decision, and this
is the correct channel for it. To make the acceptance a first-class part of the verification verdict,
add to this file's frontmatter:

```yaml
overrides:
  - must_have: "A Raspberry Pi-class run at single-operator load — concurrency 3, 600s, every declared route budget unchanged — demonstrates responsive interaction, resource-budget compliance, recovery, and uninterrupted essential sampling"
    reason: "Accepted with deviation on usage grounds, per the operator decision of 2026-09-06 recorded in 06-ACCEPTANCE-C3-RUN3.md, .planning/REQUIREMENTS.md:74 and .planning/STATE.md. Cadence, resources and recovery all PASS. /api/services misses its 500ms p95 (662.3ms) only under a closed-loop harness load measured at 34.5x the deployment's real 0.067 req/s per-route rate. No budget, criterion, assertion or harness default was moved — verified independently this round (PROH-OPS-07-01 and PROH-OPS-07-10 intact). OPS-07 stays 'Accepted with deviation', never 'Complete', per PROH-OPS-07-08. Revisit if the real request rate rises or services are added — see D-DEBT-06-27."
    accepted_by: "thewilliamharry"
    accepted_at: "2026-09-06T16:21:50Z"
```

Adding this makes the score **5/5** with `overrides_applied: 1` and the status `human_needed` (the
concurrency-1 confirmation run would remain outstanding). Leaving it out keeps the gap as written.
Either is defensible; the choice is the operator's, not the verifier's.

---

## The amendment audit

The ROADMAP block quote makes four checkable claims about criterion 5's 2026-09-04 amendment. **All
four hold**, verified against source and git history rather than against the note itself.

| Claim | Status | Evidence |
|---|---|---|
| Every route budget unchanged | ✓ VERIFIED | `ROUTE_BUDGETS_MS` (`tests/pi_load_acceptance.py:103`, not 102 — a one-line drift from edits above it) extracted at `807776a` (06-06), at `32781e5` (06-07) and at HEAD: **byte-identical across all three**. `git log -L` over the exact dict block returns ONE commit in its entire history — its introduction on 2026-09-01. Never touched. |
| `assert_response_times`, `assert_resource_budget`, `assert_cadence`, `_routes_for_ports`, `_load_worker` untouched | ✓ VERIFIED | Per-function `git log -L`: the first four last changed in `807776a` (06-06, 2026-09-01); `_load_worker` in `5e29ab3` (06-07, 2026-09-01). All five predate the 2026-09-04 amendment by three days. |
| Harness defaults untouched; the gating run passes `--concurrency 3` explicitly | ✓ VERIFIED | `tests/pi_load_acceptance.py:1792` still declares `'--concurrency', type=int, default=8`; :1781 `'--duration', type=int, default=600`. The default was NOT quietly moved to 3. `beacon-c3-run3.json`'s `scenario.concurrency: 3` came from the command line. |
| The justification is usage, not difficulty | ✓ VERIFIED | Every source claim in the note reproduces. `dashboard/app.js:795` is `Promise.allSettled([loadStats(), loadHistory(), loadScan(), loadServices(), loadEvents()])` — five parallel calls (the note cites line 784; phase 7's comments shifted it by 11). `setInterval` at :796/:797/:798 = 5s/15s/60s exactly as described. Arithmetic: 33 requests per 60s = 0.55 req/s per tab, matching "roughly 0.5". The resulting gate is still ~34.5x the real per-route rate — conservative, not lenient. |
| The amendment itself moved no code | ✓ VERIFIED | `git show --stat 63db9ef` → three files, all planning Markdown (`REQUIREMENTS.md`, `ROADMAP.md`, `06-DEBT.md`), 76 insertions, 2 deletions. **Zero lines under `dashboard/` or `tests/`.** |

**Conclusion: the amendment is legitimate.** Nothing that could turn a failing measurement into a
passing one moved with it. `PROH-OPS-07-01` and `PROH-OPS-07-10` are structurally intact. The
criterion was narrowed because the load model was wrong about the deployment — and the deployment's
actual behaviour, read out of `app.js`, confirms it was.

---

## The data-correctness regression: closed, and re-proved closed

The prior report's second failed truth — `06-13` extending `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` onto
the uptime path, so a service with a real outage reported 100.0% — is **CLOSED**. Not accepted on
prose; reproduced.

**Static evidence.** `dashboard/app.py:2928`'s `all_checks` query is
`SELECT ts, port, online FROM service_checks WHERE port IN (...) AND ts >= ? ORDER BY port ASC, ts ASC`
— **no `LIMIT` clause**. It is preceded by a 40-line comment beginning `DELIBERATELY UNBOUNDED`,
which names both consumers, states that dropping rows here "does not degrade the metric, it falsifies
it", and cites `D-DEBT-06-10`. The cap survives as a Python budget (`offline_points_budget`,
:2939) decremented only inside the `points_by_port` branch (:2979-2981), after the `ts <= now`
filter — so it reaches the offline-interval reconstruction and never `_uptime_summary`.

**Behavioural evidence (mutation M1).** This verification re-applied the exact defect — pushed the
cap back into the SQL with a truncating value — and confirmed the guards fire:

| Guard | Under M1 |
|---|---|
| `test_the_route_does_not_bound_the_uptime_read_with_the_interval_row_cap` | ✗ FAILED (correctly) |
| `test_uptime_pct_is_not_affected_by_the_offline_interval_row_cap` | ✗ FAILED (correctly) |
| This verification's own independent end-to-end differential | ✗ FAILED (correctly) — `6.563 != 87.194` |

`tests/test_services_route_scaling.py:439` asserts the **output** (`uptime_pct` equality between a
full and a capped read) and carries its own fixture guard (`assertLess(full, 99.0)`) so it cannot go
vacuous. This is the direct inverse of the guard the prior report found defective, which asserted
only SQL shape and a `200`. The lesson took.

## 06-31's input reduction: exact, and no truncation reintroduced

`06-31` reverted `06-25`'s bulk-SQL wiring and put the strip back on the Python producer
`_uptime_summary`, but fed a **reduced, state-change-only** subset. The concern is whether that
reduction is exactly equal, or a second silent truncation wearing different clothes.

**It is exact.** Verified by an independently-written end-to-end differential — own seed (777001),
own fixture strategy, deliberately unlike the phase's own mirror-based test — which drove the **real**
`/api/services` route against a **real** SQLite database and compared its **actual** `uptime_pct` and
all 168 `uptime_buckets` against `_reference_uptime_summary`, the verbatim pre-optimization
O(buckets x intervals) oracle, computed over the **full, unreduced** row stream:

```
[VERIFIER] 12 services, 4012 raw rows -> 1581 state-change points (39.4%);
           uptime_pct range 5.292..98.262
1 passed
```

- **39.4% retained** — the reduction is genuinely shedding 60.6% of input, so the test is not
  trivially comparing an unreduced stream against itself.
- **uptime_pct range 5.292–98.262** — real, observable downtime; the fixture is not vacuous.
- **Every `uptime_pct` and every 168-element bucket array matched the unreduced reference exactly**
  for all 12 services.

Structurally, `checks_by_port` carries **no budget of any kind** — only `points_by_port` is bounded —
so the reduction cannot truncate. It sheds only rows that repeat the preceding state.

**The reduction's presence is also guarded.** Mutation m3 (remove the reduction entirely) fails three
tests: `test_mirror_agrees_with_the_route_on_its_own_loop`,
`test_reduced_input_count_tracks_transitions_not_stored_volume` and
`test_reduced_input_count_holds_on_a_mostly_unobserved_window`. Note that this verification's own
correctness differential **passes** under m3 — confirming the phase's own stated insight
(`PROH-OPS-07-28`) that a correctness differential can never detect a reduction's absence.

## New finding: the NULL rule is correct in code but unproven on the shipping path

Recorded as gap 2 and as a flagged prohibition. In brief: mutation M2 collapsed the NULL branch on
the **real route**, and all 993 tests stayed green. The NULL assertion lives against
`_reduce_to_state_changes`, a mirror in the test file; the one test binding that mirror to the route
uses a fixture containing no NULL. No live exposure — both `service_checks` writers
(`app.py:1468`, `:1665`) bind 0/1 integers — so this is a warning, closable by adding one NULL row to
an existing fixture.

This is the third instance in this phase of the same pattern the user flagged (`D-DEBT-06-10`,
`D-DEBT-06-22`): a green gate over a path nothing exercises. It is worth naming as a pattern rather
than only as an item.

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `tests/pi_load_acceptance.py` (`ROUTE_BUDGETS_MS`) | Unchanged — no budget tuning | ✓ VERIFIED | Line 103. Byte-identical at `807776a`, `32781e5` and HEAD. One commit in its whole history. `PROH-OPS-07-01` intact. |
| `tests/pi_load_acceptance.py` (assertions + load generator) | Unchanged across the amendment | ✓ VERIFIED | `assert_response_times`/`assert_resource_budget`/`assert_cadence`/`_routes_for_ports` last touched `807776a`; `_load_worker` `5e29ab3`. Both 2026-09-01, three days before the amendment. |
| `tests/pi_load_acceptance.py` (defaults) | `--concurrency` default not moved to 3 | ✓ VERIFIED | :1792 `default=8`; :1781 `default=600`. The gating run supplies `3` explicitly. |
| `beacon-c3-run3.json` | Admissible, uninstrumented, Pi-class acceptance evidence at c3/600s | ✓ VERIFIED (result FAILING) | All six gating properties confirmed by direct parse. 16,547 raw latency samples present and independently re-percentiled. |
| `dashboard/app.py` (`all_checks`) | Unbounded uptime read | ✓ VERIFIED | :2928, no `LIMIT`. Cap applied in Python to `points_by_port` only. Mutation-verified. |
| `dashboard/app.py` (strip input reduction) | Exact state-change reduction, NULL-preserving | ⚠️ PARTIAL | Reduction exact (end-to-end differential, 12 services, all buckets matched) and present (m3 caught by 3 tests). NULL branch present at :2969-2978 but **unguarded on the route** (M2 undetected). |
| `dashboard/beacon/worker_main.py` | Metrics/cleanup lane separation | ✓ VERIFIED | :465-466 two `ThreadPoolExecutor(1)`; J1/J2 `executor='metrics'`, J8 `executor='cleanup'`. |
| `dashboard/beacon/migrations.py` (migration 10) | Bounded TTL thumbnail store, blobs off `services` | ✓ VERIFIED | :604-624. Table + `idx_thumbnails_expires` + backfill + `UPDATE services SET thumb_data=NULL, thumb_mime=NULL`, all inside the migration transaction. |
| `dashboard/beacon/db.py` | WAL in force | ✓ VERIFIED | :27 `JOURNAL_MODE = 'WAL'`, applied :201, verifiable via `configured_journal_mode` :209. |
| `dashboard/beacon/queues.py` | Bounded preview deadlines/retries + degraded state | ✓ VERIFIED | :28 `PREVIEW_STATUS_DEGRADED`; `deadline_ts` and `lease_owner`/`lease_until` throughout. |
| `dashboard/beacon/repositories.py` (`read_uptime_strips_by_port`) | Retained, unreferenced by production | ⚠️ ORPHANED — **disclosed** | Zero production callers (`grep` across the tree returns only `tests/`). Explicitly recorded as `D-DEBT-06-24` with the retention rationale, "not left to be rediscovered as dead code". Correctly disclosed; not a finding. |
| `06-SECURITY.md` | Boundary re-closed against HEAD | ✓ VERIFIED | 88 threat rows independently counted, matching 06-28's claimed 42 → 88. |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `dashboard/app.py::api_services` | `service_checks` (unbounded read) | `conn.execute` at :2928 | ✓ WIRED | No `LIMIT`. Feeds `checks_by_port` -> `_uptime_summary`. |
| `checks_by_port` | `_uptime_summary` | :3024 onward | ✓ WIRED, ✓ DATA FLOWS | Real query -> real reduction -> real rendered `uptime_pct`/`uptime_buckets`. Proved end-to-end against an independent oracle, not by inspection. |
| `points_by_port` | offline-interval reconstruction | `offline_points_budget` :2939, :2979-2981 | ✓ WIRED | Cap correctly isolated to this consumer only. |
| `api_services` | `_db_lock` | `with _db_lock, database_access(...)` :2875 | ⚠️ WIRED — **whole-body scope** | First dedent at :3076. 200 lines of mostly-Python work under a process-wide mutex. 06-20's narrowing reverted by `ea8689e`, never re-landed. Correct, and the standing performance mechanism behind truth 5. |
| `worker_main` J8 (`cleanup_history`) | `'cleanup'` executor | `executor='cleanup'` :91 | ✓ WIRED | Off the metrics lane, as OPS-01 requires. |
| `06-31` reduction | `tests/test_services_route_scaling.py` guards | m3 mutation | ✓ WIRED | 3 tests fire on removal. |
| `06-31` NULL branch | any test | M2 mutation | ✗ NOT WIRED | 993/993 green under mutation. Gap 2. |

### Behavioural Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Full suite green at HEAD, clean tree | `cd dashboard && uv run --frozen pytest -q` | `993 passed, 593 subtests passed in 336.88s`, exit 0 | ✓ PASS |
| Uptime output survives the row cap (D-DEBT-06-10) | mutation M1 + `pytest -k` | 2 phase guards + 1 independent differential all FAIL correctly | ✓ PASS |
| Strip reduction is exactly equal end-to-end | independent differential vs `_reference_uptime_summary` over unreduced input | 12/12 services, all `uptime_pct` and all 168 buckets identical; 4012 -> 1581 points | ✓ PASS |
| Strip reduction is detectably present | mutation m3 + `pytest -k` | 3 tests FAIL correctly | ✓ PASS |
| NULL row is never coalesced away | mutation M2 + full suite | `993 passed` — **undetected** | ✗ FAIL |
| Acceptance run percentiles reproduce from raw samples | recompute p50/p95 over `route_latencies_ms` | `/api/services` p95 662.3ms — matches report exactly | ✓ PASS |
| Run-3 build equals HEAD | `git diff --stat a7c3ef1..HEAD -- dashboard/ tests/` | empty | ✓ PASS |
| Criterion-5 amendment moved no code | `git show --stat 63db9ef` | 3 planning `.md` files only | ✓ PASS |

*Note: the tree was fully restored after every mutation; `git diff` against HEAD is empty and the
verifier's scratch test file was removed.*

### Probe Execution

| Probe | Command | Result | Status |
|---|---|---|---|
| — | `find scripts -path '*/tests/probe-*.sh'` | no matches | SKIPPED — this project uses a pytest suite and the checked-in `tests/pi_load_acceptance.py` harness rather than shell probes |

### Requirements Coverage

| Requirement | Description | Status | Evidence |
|---|---|---|---|
| OPS-01 | Metric sampling and service checks continue within cadence while discovery, previews, cleanup and analytics are active | ✓ SATISFIED | Truth 1. Lane split in code, `CadenceUnderContentionTests` green, and `assertions.cadence.passed: true` with J1-J4 all `fresh` on hardware at concurrency 3. `REQUIREMENTS.md:152` `Complete`. |
| OPS-02 | Serialized browser ownership, bounded deadlines/retries, visible non-fatal degraded state | ✓ SATISFIED | Truth 2. `REQUIREMENTS.md:153` `Complete`. |
| OPS-03 | Thumbnail storage/expiry bounded, no large blobs on the primary telemetry path | ✓ SATISFIED | Truth 3. Migration 10 + hardware RSS well inside budget. `REQUIREMENTS.md:154` `Complete`. |
| OPS-04 | Automated tests cover migrations, restart recovery, concurrent access, scheduler ownership, failed jobs | ✓ SATISFIED | Truth 4. 993 tests green; 12/12 hardware job rows `succeeded`. `REQUIREMENTS.md:155` `Complete`. |
| OPS-07 | Pi-class acceptance run at concurrency 3 verifies responsiveness, resource budgets, recovery and sampling continuity | ✗ BLOCKED (accepted with deviation) | Truth 5. Run performed three times, failing each time on `/api/services` p95. `REQUIREMENTS.md:73` still `- [ ]`; :158 reads `Accepted with deviation`, correctly NOT `Complete` per `PROH-OPS-07-08`. |

**Orphaned requirements:** none. `grep` over `REQUIREMENTS.md` maps exactly OPS-01/02/03/04/07 to
Phase 6, and all five are claimed and addressed.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| `dashboard/app.py`, `dashboard/beacon/repositories.py`, `dashboard/beacon/worker_main.py`, `tests/pi_load_acceptance.py`, `tests/test_services_route_scaling.py` | — | `TBD` / `FIXME` / `XXX` | — | **None found.** Debt-marker gate passes; all deferred work carries a `D-DEBT-06-NN` ID in `06-DEBT.md` (27 entries, `D-DEBT-06-01` through `-27`, count independently confirmed). |
| `tests/test_lock_profile.py` | 2244-2262 | `(function, line)` pinning of the lock audit | ℹ️ INFO | Observed firsthand: an unrelated edit to `app.py` shifted 9 lock sites and failed `test_every_db_lock_site_is_covered_by_the_audit`. This is exactly the brittleness `D-DEBT-06-25` documents, and the decision to retain `(function, line)` over `(function, ordinal)` was taken explicitly and recorded (Option A, `06-32`). **Behaves as documented — disclosed, not a defect.** |
| `dashboard/beacon/repositories.py` | `UPTIME_STRIP_QUERY`, `read_uptime_strips_by_port` | Production function with zero production callers | ℹ️ INFO | Referenced only from `tests/`. Fully and accurately disclosed as `D-DEBT-06-24` with the retention rationale. |
| `.planning/.../06-UAT.md` | frontmatter + `## Gaps` | Record staleness | ⚠️ WARNING | `status: complete` while carrying unresolved gap `G-06-1` whose numbers (`/api/services` p95 10010.9ms etc.) are from 2026-09-01 and **two load models out of date** — they predate both the harness CPU-sampling fix and the concurrency-8 → 3 amendment. Not a code defect, but a future reader could take those figures as current. Worth a one-line pointer to `06-ACCEPTANCE-C3-RUN3.md`. |

### Human Verification Required

#### 1. Concurrency-1 acceptance run on the Pi against HEAD

**Test:** Run the harness at `--concurrency 1 --duration 600`, uninstrumented (confirm
`/api/diagnostics/lock-profile` returns 404 first), `run_kind: acceptance`, `self_test: false`.
`06-ACCEPTANCE-RUNBOOK.md` carries the exact invocation and the three that silently produce
inadmissible results.
**Expected:** `/api/services` p95 comfortably inside 500ms — predicted 77–300ms.
**Why human:** Requires real Pi-class hardware with the live Docker deployment; `PROH-OPS-07-02`
admits no substitute. **Why it matters:** this is the single cheapest measurement that would convert
the acceptance decision's central claim from an inferential step (a cProfile in-process 77.1ms, plus
an HTTP c1 figure from a superseded build) into a direct HTTP measurement at single-operator load on
the shipped build.

#### 2. Decide criterion 5's disposition in this file's `overrides:` channel

**Test:** Either paste the ready-made `overrides:` block (body, "Suggested override") into this
frontmatter, or leave the gap standing.
**Expected:** With the override → 5/5, `overrides_applied: 1`, status `human_needed`. Without →
4/5, status `gaps_found`, as written.
**Why human:** A verifier cannot grant its own override. `PROH-OPS-07-08` reserves this decision to an
independent round precisely so the acceptance is visible rather than silently absorbed.

### Gaps Summary

**One criterion fails, and it fails honestly.** Beacon's essential-monitoring half of the phase goal
is delivered and holds under exactly the load the amended criterion specifies: cadence, resources,
recovery and sampling continuity all pass on real Pi hardware at concurrency 3. Discovery and
previews are bounded, recoverable and non-blocking. Four of five success criteria are verified
without reservation.

What does not close is responsiveness on one route. `/api/services` has missed its 500ms p95 on three
independent hardware runs spanning builds whose per-request cost differs by 45% — and the p95 moved
2.5% between the last two. That is itself the finding: **the residual gap is not per-request cost.**
Round 7 cut the route's cost nearly in half and the p95 barely noticed. The structural candidate is
still sitting in the code and was confirmed present at HEAD — `api_services` holds a process-wide
mutex across 200 lines of predominantly Python work (`app.py:2875-3075`), the narrowing that would
have addressed it having been reverted in `ea8689e` and never re-landed. `D-DEBT-06-27` records the
selective 6.9x inflation consistent with that mechanism as untested.

The phase's response was to accept the deviation on usage grounds, and that response is defensible:
the harness load is 34.5x the deployment's real per-route rate, the arithmetic checks out against
`app.js`, and — this is the part worth crediting — **nothing was tuned to make the failure go away.**
Every budget, every assertion, every harness default and the load generator itself are byte-identical
to their 2026-09-01 originals. The criterion amendment moved three Markdown files and zero lines of
code. Three failing runs stand unsuperseded. `PROH-OPS-07-01` and `PROH-OPS-07-10` were not merely
respected in letter; the phase went out of its way to make the distinction auditable.

Two things are still owed. First, the acceptance's own supporting number is a profiled in-process
cost, not an HTTP measurement — one concurrency-1 run would close that, cheaply. Second, this
verification found a fresh instance of the phase's own recurring failure mode: `06-31`'s
NULL-preservation rule is asserted against a mirror in the test file, and mutating it away on the
real route leaves all 993 tests green. It has no live exposure and is a two-line fix, but it is the
third time in this phase a green gate has covered an unexercised path, and that pattern deserves
naming more than this particular instance deserves alarm.

---

_Verified: 2026-09-07T08:03:39Z_
_Verifier: Claude (gsd-verifier) — round 4, goal-backward against the amended criterion 5_
