---
phase: 06-workload-resilience-pi-acceptance
verified: 2026-09-02T15:30:00Z
status: gaps_found
score: 4/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: human_needed
  previous_score: 4/5
  gaps_closed:
    - "06-REVIEW.md WR-01 (read-only inspection fallback fails on locked-down WAL copies) — closed by 06-09, dashboard/beacon/inventory.py now reaches a third mode=ro&immutable=1 attempt, proven by tests/test_migrations.py::InventoryTests"
    - "06-REVIEW.md WR-02 (thumb_state could report degraded while a valid thumbnail was servable) — closed by 06-09, dashboard/app.py:3100-3116 now checks has_thumb before preview_status"
    - "The previously-outstanding human-verification item (a real Raspberry Pi acceptance run) has now been performed, twice, on real hardware — it is no longer an open human-verification item, it is a measured, failing result"
  gaps_remaining:
    - "Truth 5 / OPS-07: the Pi-class acceptance run's own overall_passed is false — three routes exceed their declared p95 budgets under representative concurrent load"
  regressions: []
gaps:
  - truth: "A Raspberry Pi-class representative-load run demonstrates responsive interaction, resource-budget compliance, recovery, and uninterrupted essential sampling"
    status: failed
    reason: "The acceptance run was executed on real Pi-class hardware (aarch64/raspi) against this round's build (commit e46a044 and later) and returned overall_passed: false. Three of six exercised routes exceeded their declared p95 budgets under concurrency 8 / 600s: /api/services (p95 2465.9ms vs 500ms budget), /api/scan-status (p95 1797.4ms vs 500ms budget), and /api/advanced/current (p95 2742.1ms vs 2000ms budget). Cadence (OPS-01) and RSS-based resource budgets passed cleanly on the same run; the failure is specifically the responsiveness/latency clause of this success criterion."
    artifacts:
      - path: "dashboard/app.py"
        issue: "api_services (line 2781) calls _uptime_summary once per service inside its result loop (dashboard/app.py:2834). 06-08 already fixed the O(buckets x intervals) rescan inside _uptime_summary itself (now a linear sweep, dashboard/app.py:1156-1246, confirmed present in the codebase), but the operator's own control-pass measurement (concurrency 1, zero contention) still shows /api/services at 289.0ms p50 -- an 8.7x improvement over the pre-fix 2504.6ms, but still 58% of the route's own 500ms budget consumed with nothing else running. The residual cost is the per-service _uptime_summary sweep plus the attributed_downtime_seconds/offline-interval computation still running proportional to stored check count for every service in every request, not the now-fixed O(buckets x intervals) term."
      - path: "dashboard/Dockerfile"
        issue: "Line 27: gunicorn runs `--workers 1 --threads 8` -- one Python interpreter, one GIL, eight HTTP threads. D-DEBT-06-01's own hardware evidence (06-DEBT.md) shows /api/advanced/current, which takes no lock at all (dashboard/beacon/diagnosis.py holds none; this is the pre-existing AR-03-01 accepted-risk route), still degraded 29x (80.7ms control p50 to 2344.0ms acceptance p50) under concurrency 8 -- a result a process-wide lock cannot produce on a caller that never acquires it. The single-worker/multi-thread GIL configuration is the evidence-backed live suspect for the acceptance run's remaining over-budget routes, per the phase's own D-DEBT-06-01 analysis."
      - path: "tests/pi_load_acceptance.py"
        issue: "_live_role_processes (line 498) constructs a brand-new psutil.Process(target.root_pid) object on every sampling tick rather than reusing a cached Process handle across ticks. psutil.Process.cpu_percent(interval=None) computes its delta against state stored on that specific Process instance; because a fresh instance is created every tick, every single cpu_percent(interval=None) call is effectively psutil's meaningless first call and returns 0.0. _prime_cpu_percent (line 519) primes a different, run-start-only set of Process objects that _sample_resources_tick never reuses, so the priming is discarded. This is confirmed as the root cause of D-DEBT-06-06 (peak_cpu_percent/mean_cpu_percent reading exactly 0.0 for both roles on both hardware runs despite plausible, load-correlated RSS figures on the same runs) by direct code read, not merely reported by 06-DEBT.md. Consequence: the CPU half of this success criterion's 'resource-budget compliance' clause has never actually been measured by any run this phase has produced -- only RSS has. D-DEBT-06-02's own revisit trigger ('sustained CPU percent that starves the host') has now failed to be evaluable for two consecutive rounds because of this defect."
    missing:
      - "A profile of api_services' residual per-request cost at concurrency 1 (289ms) to identify what beyond the now-fixed bucket sweep is proportional to stored check count -- likely the per-service attributed_downtime_seconds computation and/or the offline-interval reconstruction, not yet reduced by 06-08"
      - "A decision, informed by that profile plus the GIL-contention evidence already gathered in D-DEBT-06-01, on whether the fix path is further per-request cost reduction in dashboard/app.py, a gunicorn worker/thread reconfiguration, or (per D-DEBT-06-01's own reopening test) narrowing _db_lock -- the phase's own evidence currently rules out _db_lock as sufficient on its own"
      - "A fix to tests/pi_load_acceptance.py's process-handle caching (reuse one psutil.Process object per PID across the sampling loop's lifetime, priming it once, instead of re-instantiating per tick) so peak_cpu_percent/mean_cpu_percent produce a real reading and D-DEBT-06-02's revisit trigger can finally be evaluated on usable evidence"
      - "A third, passing hardware acceptance run against whatever fix is chosen, since PROH-OPS-07-01/PROH-OPS-07-02 forbid tuning the harness's budgets to manufacture a pass and forbid treating anything but a genuine hardware run as evidence"
---

# Phase 6: Workload Resilience & Pi Acceptance Verification Report

**Phase Goal:** Beacon keeps essential monitoring reliable while discovery and previews operate as bounded, recoverable best-effort work on Raspberry Pi-class hardware.

**Verified:** 2026-09-02T15:30:00Z
**Status:** gaps_found
**Re-verification:** Yes — after gap-closure round (06-07..06-10), following a prior `human_needed` verification whose single outstanding item (a real Pi acceptance run) has now been performed and returned a measured, failing result.

## Goal Achievement

### Observable Truths

| # | Truth (mapped to ROADMAP Success Criterion) | Status | Evidence |
|---|------|--------|----------|
| 1 | Metric sampling and service checks remain within accepted cadence while discovery, previews, cleanup, and analytics queries are active | ✓ VERIFIED | Unchanged code path from the prior verification (`worker_main.py`'s `'metrics'`/`'cleanup'` lane split, confirmed still present by direct read), now additionally proven on **real Pi-class hardware twice** in this round: `assertions.cadence.passed: true` with J1-J4 never `stale` on both the 120s concurrency-1 control run and the 600s concurrency-8 acceptance run (`06-DEBT.md` D-DEBT-06-04, `06-UAT.md`). `tests/test_workload_resilience.py::CadenceUnderContentionTests` still present and passing in the full-suite re-run (below). This truth now has both automated and hardware evidence, superseding the prior verification's automated-only evidence. |
| 2 | Preview work has one serialized browser owner, bounded deadlines and retries, and a visible non-fatal degraded state instead of blocking core monitoring | ✓ VERIFIED | Unchanged core mechanism (`queues.py` retry/backoff, `app.js`/`style.css` degraded badge) plus this round's fix: `06-REVIEW.md` WR-02 — `/api/thumbnail-status`'s `thumb_state` could report `"degraded"` while a valid thumbnail was still servable — is now closed. Confirmed by direct read of `dashboard/app.py:3100-3116`: `has_thumb` is checked before `preview_status`, so `thumb_state` is `'ok'` whenever a servable thumbnail exists regardless of the latest preview attempt's outcome. `tests/test_api_and_auth.py::ApiAndAuthTests::test_thumb_state_precedence_across_the_four_has_thumb_and_preview_status_combinations` (06-09) covers this directly and passes in the full-suite re-run. |
| 3 | Thumbnail data expires within a bounded managed store and no longer puts large preview blobs on Beacon's primary telemetry path | ✓ VERIFIED | Unchanged from the prior verification (migration 10, `ThumbnailStoreRepository`, TTL/budget reap) — untouched by this round's plans, still passing in the full-suite re-run. |
| 4 | Beacon recovers predictably from restarts, concurrent web/worker database activity, and failed background jobs, as proven by automated runtime and persistence coverage | ✓ VERIFIED | Unchanged core mechanism (WAL, `ConcurrentAccessTests`, restart-fencing test) plus this round's fix: `06-REVIEW.md` WR-01 — the read-only inspection fallback needed write access to create the `-shm` sidecar, defeating the phase's own documented copy-then-lock-down workflow — is now closed. `dashboard/beacon/inventory.py`'s `_readonly_connection` now reaches a third `mode=ro&immutable=1` attempt after both write-requiring attempts fail, with a validating probe added to all three attempts (discovered necessary because this environment's SQLite build defers `-shm` failures to first-statement execution). `tests/test_migrations.py::InventoryTests` (three new tests) covers this and passes in the full-suite re-run. `_db_lock`'s scope was deliberately re-examined this round against real hardware evidence (`06-10-PLAN.md` Task 2, a blocking one-way-door checkpoint) and the user chose `defer-again` — no line touching the lock changed, `T-06-24`'s closure evidence in `06-SECURITY.md` remains valid by the plan's own verification gate (`git diff` shows zero `_db_lock`-touching lines), confirmed by direct read of `06-SECURITY.md` line 68. |
| 5 | A Raspberry Pi-class representative-load run demonstrates responsive interaction, resource-budget compliance, recovery, and uninterrupted essential sampling | ✗ FAILED | The run that the prior verification correctly routed to human verification **has now been performed, twice, on real hardware** (`aarch64`/`raspi`), against this round's build. Cadence and RSS-based resource budgets pass. But the run's own `overall_passed` is **`false`**: `/api/services` p95 2465.9ms (budget 500ms), `/api/scan-status` p95 1797.4ms (budget 500ms), `/api/advanced/current` p95 2742.1ms (budget 2000ms) — three of six exercised routes over their declared budgets under concurrency 8 / 600s. This is a measured, code-level shortfall in the "responsive interaction" clause of the success criterion, not an untested item. Separately, direct code read of `tests/pi_load_acceptance.py:498-535` confirms the root cause of `D-DEBT-06-06`: `_live_role_processes` constructs a fresh `psutil.Process()` object every sampling tick, so `cpu_percent(interval=None)` never has a prior-tick baseline to diff against and reads `0.0` on every call regardless of actual load — meaning the "resource-budget compliance" clause's CPU half has never actually been measured by any run this phase has produced, only RSS has. |

**Score:** 4/5 truths verified; 1 failed (measured, not untested).

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dashboard/beacon/inventory.py` | Third `mode=ro&immutable=1` fallback attempt, closing AR-06-02/WR-01 | ✓ VERIFIED | Confirmed by direct read; `06-SECURITY.md` AR-06-02 records the closure |
| `dashboard/app.py` (thumb_state) | `has_thumb` checked before `preview_status` | ✓ VERIFIED | Confirmed by direct read of lines 3100-3116 |
| `dashboard/app.py` (`_legacy_uptime_summary`) | Linear-cost sweep replacing the O(buckets x intervals) rescan | ✓ VERIFIED (present and correct) | Confirmed by direct read of lines 1156-1246, including the sweep's `head`-pointer advancement and the code's own correctness argument; still the identified residual-cost source at truth 5 |
| `dashboard/app.py` (`api_services`) | Bulk offline-interval read replacing a per-service N+1 | ✓ VERIFIED | Confirmed by direct read: `read_service_offline_intervals_by_port` (line 2814-ish, bulk) called once, mirroring the existing `read_maintenance_windows_by_port` bulk pattern |
| `tests/pi_load_acceptance.py` | Container-derived resource-target resolution (`docker_container_tree`) | ✓ VERIFIED | Confirmed by direct read of `resolve_container_process_tree`, `_container_root_pid`; independently cross-checked by the operator's own `docker inspect` against the hardware report's sampled PIDs — exact match |
| `tests/pi_load_acceptance.py` | Working CPU sampling | ✗ STUB (present but non-functional) | `_live_role_processes` re-instantiates `psutil.Process()` every tick, discarding `_prime_cpu_percent`'s baseline; `peak_cpu_percent`/`mean_cpu_percent` always read `0.0`. Root-caused by direct code read this verification, matching `D-DEBT-06-06`'s description exactly |
| `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` | Updated dispositions after hardware run | ✓ VERIFIED | Present, reorganized into Deferred/Decided/Discharged sections; D-DEBT-06-04 discharged, D-DEBT-06-01 re-decided with hardware evidence, D-DEBT-06-06 newly filed, D-DEBT-06-05 (flaky test) newly filed |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `tests/pi_load_acceptance.py` (`resource_targets`) | `docker inspect` (live containers) | PID cross-check | ✓ WIRED (per operator's independent confirmation) | Operator's own `docker inspect --format '{{.State.Pid}}' beacon-web beacon-worker'` returned exactly the PIDs the report sampled (`1745069`/`1745146` web, `1745076` worker) |
| `dashboard/app.py` `api_services` | `beacon_repositories.read_service_offline_intervals_by_port` | bulk read call site | ✓ WIRED | Confirmed by direct read; called once per request, outside the per-service loop |
| `06-10-PLAN.md` Task 2 decision | `06-SECURITY.md` T-06-24 | "no line touching `_db_lock` changed" verification gate | ✓ WIRED | `defer-again` chosen; `git log` shows `06-10`'s only commit (`32781e5`) touches `06-DEBT.md` only, no `app.py` changes |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full suite green, no regressions (re-run independently, once, this verification) | `time uv run --project dashboard python -m pytest -q` | `837 passed, 561 subtests passed in 242.80s (0:04:02)` | ✓ PASS |
| `_legacy_uptime_summary` sweep present and matches its own correctness argument | Direct read of `dashboard/app.py:1156-1246` | Sweep pointer (`head`) only ever advances; matches the code's own inline proof of equivalence to the nested-loop version | ✓ PASS |
| `Dockerfile` threading config matches the GIL-contention hypothesis in `D-DEBT-06-01` | `grep -n "workers\|threads" dashboard/Dockerfile` | `--workers 1 --threads 8` | ✓ CONFIRMED (matches 06-DEBT.md's own claim) |
| `thumb_state` precedence fix (WR-02) | Direct read of `dashboard/app.py:3100-3116` | `has_thumb` branch checked before `preview_status`/degraded branch | ✓ CONFIRMED |
| `_readonly_connection` third-attempt fix (WR-01) | `grep -n "immutable=1" dashboard/beacon/inventory.py` | Present | ✓ CONFIRMED |
| Harness CPU-sampling root cause (D-DEBT-06-06) | Direct read of `tests/pi_load_acceptance.py:498-535` | `_live_role_processes` calls `psutil.Process(target.root_pid)` fresh every tick; `_prime_cpu_percent` primes a different, discarded set of objects | ✓ CONFIRMED DEFECT — root cause located, not previously identified in 06-DEBT.md beyond symptom description |

### Probe Execution

| Probe | Command | Result | Status |
|-------|---------|--------|--------|
| Real Pi-class acceptance run (the phase's actual OPS-07 probe — `tests/pi_load_acceptance.py`, non-self-test) | Performed by the operator on real hardware twice this round, per `06-DEBT.md`/`06-UAT.md`; not re-executable from this verification environment (no Pi access) | Control pass: `overall_passed: true`. Acceptance pass: `overall_passed: false`, 3 routes over budget (see Truth 5) | FAILED (acceptance pass is the authoritative result; treated as measured evidence per this run's instructions, not re-run) |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|--------------|--------|----------|
| OPS-01 | 06-04, 06-07, 06-08, 06-10 | Cadence holds under contention | ✓ SATISFIED | Held on two real-hardware runs this round in addition to automated coverage; `REQUIREMENTS.md` traceability row already reads "Complete" |
| OPS-02 | 06-03, 06-09 | Bounded preview retry, degraded state | ✓ SATISFIED | WR-02 closed this round; `REQUIREMENTS.md` traceability row already reads "Complete" |
| OPS-03 | 06-01, 06-02 | Bounded thumbnail store off primary telemetry path | ✓ SATISFIED | Unchanged, untouched this round; `REQUIREMENTS.md` traceability row already reads "Complete" |
| OPS-04 | 06-05, 06-09, 06-10 | Restart/concurrency/failed-job automated coverage | ✓ SATISFIED | WR-01 closed this round; `_db_lock` deferral re-examined and upheld on hardware evidence; `REQUIREMENTS.md` traceability row already reads "Complete" |
| OPS-07 | 06-06, 06-07, 06-08, 06-10 | Pi-class acceptance run | ✗ BLOCKED | The run happened, on real hardware, twice — and its own result is `overall_passed: false`. `REQUIREMENTS.md` line 155 correctly still reads "Pending", consistent with this finding; do not promote it |

No orphaned requirements — all 5 phase requirement IDs (OPS-01, OPS-02, OPS-03, OPS-04, OPS-07) declared across this phase's plan frontmatter and present in `REQUIREMENTS.md`'s Phase 6 mapping. `REQUIREMENTS.md`'s own traceability table (lines 149-155) already correctly reflects this verification's findings (OPS-01/02/03/04 Complete, OPS-07 Pending) — no update needed there.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `tests/pi_load_acceptance.py` | 498-535 | CPU-percent sampling reads a structurally-guaranteed `0.0` regardless of load — fresh `psutil.Process()` per tick discards the primed baseline | 🛑 Blocker (for the resource-compliance half of Truth 5's evidence, not for Truths 1-4) | The harness's own resource assertion (`assertions.resources.passed`) is only ever checking RSS; the CPU figures it prints have never been true, on any run to date, and `D-DEBT-06-02`'s revisit trigger cannot be evaluated until this is fixed |
| `dashboard/app.py` | 2781-2870 (`api_services`) | Residual per-request cost (289ms at zero contention, post-06-08) not yet attributed to a specific sub-computation | ⚠️ Warning | Consumes 58% of the route's own 500ms budget before any concurrency is applied; the largest remaining contributor to Truth 5's failure alongside GIL contention |
| `dashboard/Dockerfile` | 27 | `--workers 1 --threads 8` — single-interpreter, GIL-serialized concurrency | ⚠️ Warning (deployment configuration, not a code defect) | The phase's own `D-DEBT-06-01` evidence (the unlocked `/api/advanced/current` route's 29x regression under load) implicates this configuration, not `_db_lock`, as the live amplifier |

No debt-marker anti-patterns (`TBD`/`FIXME`/`XXX`) found in any file modified by this round's plans (`dashboard/beacon/inventory.py`, `dashboard/app.py`, `tests/pi_load_acceptance.py`, `tests/test_migrations.py`, `tests/test_api_and_auth.py`, `tests/test_workload_resilience.py`, `dashboard/beacon/repositories.py`). No stub patterns (empty returns, hardcoded empty data flowing to render) found in this round's new/modified code, with the sole exception of the CPU-sampling defect above, which is a functional bug rather than an unimplemented stub.

### Human Verification Required

None. The one item the prior verification routed to human verification (the real Pi acceptance run) has been performed and its result is now measured, authoritative evidence — a `gaps_found` status, not `human_needed`, per this run's explicit instructions.

## Gaps Summary

Four of five phase success criteria hold, two of them (Truths 2 and 4) newly strengthened this round by closing `06-REVIEW.md`'s two carried-forward warnings (WR-01, WR-02), and Truth 1 additionally now proven on real hardware rather than automated tests alone. The full regression suite is green: 837 passed, 561 subtests, 0 failures, independently re-run in full during this verification (242.80s).

The fifth criterion — **OPS-07's Raspberry Pi-class acceptance run** — is not met. This is not an untested item: the run has now been executed on real hardware twice this round, and its own second, corrected-build result is `overall_passed: false`, with three of six exercised routes (`/api/services`, `/api/scan-status`, `/api/advanced/current`) exceeding their declared p95 latency budgets under representative concurrent load (concurrency 8, 600s). Cadence (OPS-01) held throughout, and RSS-based resource budgets passed — but the "responsive interaction" clause of the success criterion is measurably unmet, and a second defect (the acceptance harness's CPU sampling, root-caused during this verification to a `psutil.Process()` re-instantiation bug in `tests/pi_load_acceptance.py`) means the "resource-budget compliance" clause has never actually had its CPU half measured on any run this phase has produced.

The phase's own `06-08` fix reduced `/api/services`'s per-request cost 8.7x (2504.6ms to 289.0ms at zero contention) but left a residual cost the plan's own prediction ("tens of milliseconds") did not anticipate, and the phase's own `06-10` decision checkpoint (the user, on measured hardware evidence) found that the deferred `_db_lock` narrowing is *not sufficient* to explain the remaining failure — the unlocked `/api/advanced/current` route degraded 29x under the same load. The evidence the phase itself gathered points at `dashboard/Dockerfile`'s `--workers 1 --threads 8` GIL-serialized configuration combined with `/api/services`'s residual Python-side cost as the live, unresolved mechanism.

This phase cannot seal on this evidence. A gap-closure plan is needed to: (1) profile and reduce `/api/services`' residual per-request cost below its 06-08 checkpoint; (2) evaluate the GIL/threading configuration implicated by the phase's own `D-DEBT-06-01` analysis; (3) fix `tests/pi_load_acceptance.py`'s CPU-sampling defect so the resource-compliance clause can finally be measured; and (4) re-run the acceptance harness on real Pi-class hardware a third time to confirm `overall_passed: true` before OPS-07 can be promoted to Complete in `REQUIREMENTS.md`.

---

_Verified: 2026-09-02T15:30:00Z_
_Verifier: Claude (gsd-verifier)_
