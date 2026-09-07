---
phase: 06-workload-resilience-pi-acceptance
plan: 06
subsystem: testing
tags: [load-testing, acceptance-harness, freshness_state, background_job_health, docker-compose, ops-07]

# Dependency graph
requires:
  - phase: 06-04
    provides: "The dedicated 'cleanup' executor lane and the CadenceUnderContentionTests essential-job set (J1-J4) this harness's cadence oracle re-asserts under real load"
  - phase: 06-05
    provides: "WAL-mode connect_db/database_access, the read-side this harness's cadence oracle opens the live database through"
provides:
  - "tests/pi_load_acceptance.py -- a standalone, checked-in, repeatable Pi-class load acceptance harness (--duration/--base-url/--db/--concurrency/--output/--self-test) whose cadence, resource, and response-time oracles all delegate to evidence the product already produces (freshness_state, read_background_job_health, docker-compose.yml mem_limit)"
  - "An automated --self-test smoke path proving the harness end-to-end with no Pi required"
  - "D-DEBT-06-02 -- the recorded, reasoned decision not to add a cpus: cgroup cap this phase"
  - "D-DEBT-06-04 -- the recorded, honest gap that real Raspberry Pi-class execution did not happen in this environment"
affects: [any future load-testing or resource-budget work, the next real-Pi deployment cycle]

actuals:
  tokens: 9800
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "A load-generation harness whose pass/fail oracle is the product's own durable evidence (freshness_state, background_job_health) rather than thresholds invented for the harness"
    - "run_kind derived strictly from the invocation (--self-test vs not), never from a flag the runner sets independently, so a convenience run can never be mistaken for hardware evidence"
    - "mem_limit budgets parsed from docker-compose.yml at run time rather than duplicated as constants"

key-files:
  created:
    - tests/pi_load_acceptance.py
  modified:
    - tests/test_workload_resilience.py
    - README.md
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md

key-decisions:
  - "D-DEBT-06-02: no cpus: cgroup cap is added this phase -- it would throttle Chromium against the already-bounded PREVIEW_BROWSER_BUDGET_MS deadline, trading a solved OPS-01 contention problem for an unsolved one. CPU compliance is instead evidenced by the harness's own peak/mean CPU sampling."
  - "No real Raspberry Pi was deployed to or confirmed reachable from this execution environment. A read-only mDNS/ping check found raspi.local (this repo's own documented deployment hostname) answering on the sandbox's local network, but with no deployment access to confirm this phase's build (or any build) is actually running there, treating it as a verified acceptance target was rejected -- running a sustained real-load pass against an unconfirmed host would risk unauthorized load and would misrepresent unverified evidence as Pi-class acceptance (PROH-OPS-07-02). The harness's --self-test smoke path was run instead, and the real-hardware run is recorded as D-DEBT-06-04, an open item for the next confirmed Pi deployment."

requirements-completed: [OPS-07]

coverage:
  - id: D1
    description: "A checked-in, repeatable load harness generates representative concurrent load against the dashboard's own routes and emits a machine-readable pass/fail JSON report"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#PiLoadAcceptanceHarnessTests::test_pi_load_acceptance_oracles_are_the_products_own"
        status: pass
      - kind: e2e
        ref: "python tests/pi_load_acceptance.py --self-test (smoke run, overall_passed: true)"
        status: pass
    human_judgment: false
  - id: D2
    description: "The harness's cadence oracle delegates entirely to freshness_state and read_background_job_health -- never a parallel threshold"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#PiLoadAcceptanceHarnessTests::test_pi_load_acceptance_oracles_are_the_products_own"
        status: pass
    human_judgment: false
  - id: D3
    description: "Worker/web resident memory is asserted against mem_limit values parsed from docker-compose.yml, not duplicated as constants"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#PiLoadAcceptanceHarnessTests::test_pi_load_acceptance_oracles_are_the_products_own"
        status: pass
    human_judgment: false
  - id: D4
    description: "The harness reports failure honestly: an unreachable target, an unopenable database, or a missing oracle all exit non-zero with the reason named in the report"
    requirement: "OPS-07"
    verification:
      - kind: e2e
        ref: "python tests/pi_load_acceptance.py --duration 5 --base-url http://127.0.0.1:1 (exit 1, failure_reasons names the unreachable target)"
        status: pass
    human_judgment: false
  - id: D5
    description: "The absence of a CPU cgroup limit is an explicitly recorded decision with rationale (D-DEBT-06-02), not a silent omission"
    requirement: "OPS-07"
    verification:
      - kind: manual_procedural
        ref: ".planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md#D-DEBT-06-02"
        status: pass
    human_judgment: false
  - id: D6
    description: "A Raspberry Pi-class acceptance run demonstrates responsive interaction, resource-budget compliance, and uninterrupted essential sampling under representative load"
    verification: []
    human_judgment: true
    rationale: "No confirmed, deployed Raspberry Pi target was reachable from this execution environment (D-DEBT-06-04); real-hardware execution requires an operator to deploy this phase's build via docker compose up -d --build and run the harness per README.md's new 'Raspberry Pi-class load acceptance run' subsection. This is a genuine, environment-imposed gap, not a skipped automation opportunity -- the harness itself is complete and proven by D1-D5 above."

duration: ~35min
completed: 2026-09-01
status: complete
---

# Phase 06 Plan 06: Pi-Class Load Acceptance Harness Summary

**A standalone, checked-in `tests/pi_load_acceptance.py` load-acceptance harness whose cadence, resource, and response-time oracles all delegate to evidence Beacon already trusts (`freshness_state`, `background_job_health`, `docker-compose.yml` `mem_limit`); its `--self-test` smoke path is proven green end-to-end, and the real Raspberry Pi run is honestly recorded as an open item rather than fabricated.**

## Performance

- **Duration:** ~35 min
- **Tasks:** 2
- **Files modified:** 3 (2 source/test + README.md), 1 file created (`tests/pi_load_acceptance.py`), plus `06-DEBT.md` extended with two new entries

## Accomplishments

- **Built the OPS-07 acceptance harness (Task 1).** `tests/pi_load_acceptance.py` is a standalone script (deliberately not `test_*.py`-named, so pytest never collects it) with a `--duration`/`--base-url`/`--db`/`--concurrency`/`--output`/`--self-test` CLI. It drives `--concurrency` threads issuing rotating GETs against `/api/services`, `/api/scan-status`, `/api/thumbnail-status`, `/api/thumbnail/<port>` (one per discovered service), `/api/history`, and `/api/advanced/current` for the run duration, recording per-route latency. Three oracle functions never restate a threshold the product doesn't already own: `assert_cadence` classifies J1-J4 via `freshness_state` fed each job's own cadence (`callback_schedule_evidence` over `WORKER_CALLBACK_INVENTORY`, with `Settings.metric_sample_seconds` for J2) and fails on any `background_job_health.state == 'failed'`; `assert_resource_budget` compares sampled worker/web RSS (matched by command line -- `worker.py`/`gunicorn` -- in a real run, or the current process in `--self-test`) against limits from `parse_compose_memory_limits`, a small line-oriented parser that reads `docker-compose.yml`'s `mem_limit` values directly (`1g` -> 1073741824, `256m` -> 268435456, verified against the real file); `assert_response_times` fails when any exercised route's p95 exceeds a declared, reasoned budget (tightest for the interactively-polled routes, loosest for operator-initiated analytics routes). The `AcceptanceReport` JSON carries the host (`platform.machine()`/`platform.node()`), `run_kind` (`acceptance` only when invoked without `--self-test`; `smoke` always for `--self-test`, per PROH-OPS-07-02), full `background_job_health`, per-job `freshness_by_job`, and one boolean per assertion. Every failure path -- unreachable target, unopenable database, a missing resource-oracle process -- names its reason and exits non-zero; the harness never exits 0 with missing evidence.
- **Proved the harness without hardware.** `python tests/pi_load_acceptance.py --self-test` starts a real local Beacon instance on a threaded `werkzeug` dev server, seeds one service and fresh `J1`-`J4` job-health rows, runs a 5-second bounded load pass, and completed in ~5.8s wall-clock with `overall_passed: true` and `run_kind: smoke`. `python tests/pi_load_acceptance.py --duration 5 --base-url http://127.0.0.1:1` (an unreachable target) exited non-zero in ~0.17s with the unreachable host named in `failure_reasons`. `tests/test_workload_resilience.py::PiLoadAcceptanceHarnessTests::test_pi_load_acceptance_oracles_are_the_products_own` proves the three oracle functions directly: `parse_compose_memory_limits` against the real `docker-compose.yml`, `assert_cadence`'s exact-boundary pass/one-second-past-boundary fail delegation to `freshness_state`, and `assert_resource_budget`'s over/at-budget behavior.
- **Recorded the CPU-limit decision and documented the run (Task 2).** `06-DEBT.md` gained `D-DEBT-06-02`: no `cpus:` cgroup cap is added this phase, because it would throttle Chromium against `PREVIEW_BROWSER_BUDGET_MS` -- exactly the contention class OPS-01/06-04 just finished eliminating -- with CPU compliance instead evidenced by the harness's own peak/mean CPU sampling. `README.md` gained a "Raspberry Pi-class load acceptance run" subsection under `## Data and operations` documenting the exact invocation, what a pass means, the `--self-test` smoke path, and the honesty contract around `run_kind`.
- **Ran the harness and recorded the honest outcome.** No confirmed, deployed Raspberry Pi target was reachable from this execution environment. A read-only check found `raspi.local` (this repository's own documented deployment hostname) answering a single ICMP ping on the sandbox's local network, but with no deployment access to confirm this phase's build -- or any build -- is actually running there. Per this plan's own `<precondition>` fallback and `06-RESEARCH.md` § Environment Availability, the harness's `--self-test` path was run instead and labelled honestly as `smoke`; the real-hardware run is recorded as `D-DEBT-06-04`, a new, non-blocking open item for the next confirmed Pi deployment.

## Task Commits

1. **Task 1: Build the checked-in Pi-class load acceptance harness** — `807776a` (feat)
2. **Task 2: Record the CPU-budget decision and run the acceptance harness** — `f8c3560` (docs)

**Plan metadata:** this commit (docs: complete plan)

## Files Created/Modified

- `tests/pi_load_acceptance.py` — new; the standalone OPS-07 harness (`main`, `run_acceptance`, `run_self_test`, `LoadScenario`, `AcceptanceReport`, `assert_cadence`, `assert_resource_budget`, `assert_response_times`, `parse_compose_memory_limits`)
- `tests/test_workload_resilience.py` — `PiLoadAcceptanceHarnessTests::test_pi_load_acceptance_oracles_are_the_products_own`
- `README.md` — new "Raspberry Pi-class load acceptance run" subsection under `## Data and operations`
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — `D-DEBT-06-02` (CPU decision) and `D-DEBT-06-04` (Pi-evidence gap), appended after the existing `D-DEBT-06-01`/`D-DEBT-06-03` entries

## Decisions Made

- **No `cpus:` cgroup cap this phase (`D-DEBT-06-02`).** A CPU cap on `worker` would throttle Chromium mid-capture against the already-bounded `PREVIEW_BROWSER_BUDGET_MS = 27_000` deadline -- trading a solved OPS-01 contention problem for an unsolved one. CPU compliance is instead evidenced by observation (peak/mean CPU percent sampled and reported by the harness), not enforced by a limit.
- **Declined to treat a coincidentally-reachable `raspi.local` as a verified acceptance target.** A read-only ping check found this hostname answering on the sandbox's local network, but this task has no deployment access to that host and no way to confirm this phase's build runs there. Running the harness's sustained real-load mode against it would risk generating load against a host outside this task's authority, and reporting the result as `run_kind: acceptance` would misrepresent unverified evidence as Pi-class acceptance per `PROH-OPS-07-02`. The `--self-test` smoke path was run instead and the real-hardware run recorded as `D-DEBT-06-04`.
- **`run_kind` is derived purely from the `--self-test` flag, never from hardware auto-detection.** The harness has no way to detect whether it is running against real Pi-class hardware; the honesty guarantee (PROH-OPS-07-02) instead comes from the report always carrying `host_machine`/`host_node`, so a reviewer auditing an `acceptance`-labelled report against a non-Pi host can catch a misrepresented run. This mirrors the threat model's own T-06-26 mitigation description.
- **Resource-oracle self-test fallback samples the current process for both roles, clearly comment-labelled as smoke-only.** `--self-test` has no separate worker/web containers; sampling the current process (rather than skipping the resource oracle) keeps the harness's "never exit 0 with missing evidence" guarantee true even in the smoke path, while the fallback is explicitly restricted to `self_test=True` and never substitutes for real per-process evidence in an acceptance run.

## Deviations from Plan

None — plan executed as written. The `<precondition>`'s own documented fallback (no Pi reachable -> run `--self-test`, carry the real run forward as an open item) applied exactly as specified; this is not a deviation but the plan's designed behavior for this scenario, consistent with `06-RESEARCH.md` § Environment Availability calling this out in advance.

## Issues Encountered

None. The one notable finding during Task 2's precondition check -- `raspi.local` answering a ping in this sandbox despite no real Pi deployment being possible from here -- was investigated (see Decisions Made above) and resolved by declining to treat it as a verified target, not by working around it.

## User Setup Required

**External hardware requires manual action.** Per `06-DEBT.md` `D-DEBT-06-04` and this plan's `user_setup` block:

1. Deploy this phase's build to the target Raspberry Pi: `docker compose up -d --build` (on the Pi host running Beacon).
2. Run the acceptance harness on the Pi and attach its JSON report as phase evidence:
   ```bash
   python tests/pi_load_acceptance.py --duration 600 --base-url http://127.0.0.1 \
     --db /data/dashboard.db --output beacon-acceptance.json
   ```
3. Confirm the report shows `"run_kind": "acceptance"`, a genuinely Pi-class host, `overall_passed: true`, no `failed` `background_job_health` rows, `J1`-`J4` classified `fresh`/`aging` (never `stale`), worker/web RSS within their declared `mem_limit`, and every route's p95 within budget. See `README.md`'s new "Raspberry Pi-class load acceptance run" subsection for full instructions.

## Verified Smoke Evidence (this environment)

Captured verbatim from `python tests/pi_load_acceptance.py --self-test --output <path>` on this environment (host: `arm64` / `Williams-MacBook-Pro-635.local` — explicitly NOT Pi-class, hence `run_kind: smoke`):

```json
"run_kind": "smoke",
"overall_passed": true,
"failure_reasons": [],
"assertions": {
  "cadence": { "passed": true, "failures": [] },
  "resources": {
    "passed": true,
    "results": [
      {"role": "worker", "passed": true, "rss_bytes": 56344576, "limit_bytes": 1073741824},
      {"role": "web", "passed": true, "rss_bytes": 56344576, "limit_bytes": 268435456}
    ]
  },
  "response_times": { "passed": true, "failures": [] }
},
"freshness_by_job": {
  "J1": {"state": "fresh", "age_seconds": 5},
  "J2": {"state": "fresh", "age_seconds": 5},
  "J3": {"state": "fresh", "age_seconds": 5},
  "J4": {"state": "fresh", "age_seconds": 5}
}
```

This is smoke evidence only — proof the harness works end-to-end, not Pi-class acceptance evidence (see User Setup Required above).

## Next Phase Readiness

This is the phase's final plan (wave 6). All five phase requirements have automated harness/test coverage checked in and green (`uv run --project dashboard python -m pytest -q`: 795 passed, 561 subtests passed). The one remaining open item across the whole phase is real Raspberry Pi-class execution of this harness (`D-DEBT-06-04`), consistent with the pattern this project already used for `03-UAT.md`/`03.1-UAT.md`'s real-Pi checks. Phase verification should treat `D-DEBT-06-04` as a known, honestly-recorded gap rather than a defect to chase further in this execution environment.

## Self-Check: PASSED

- `tests/pi_load_acceptance.py` — FOUND, contains `def main(`, `def assert_cadence(`, `def assert_resource_budget(`, `def assert_response_times(`, `def parse_compose_memory_limits(`
- `tests/test_workload_resilience.py` — FOUND, contains `PiLoadAcceptanceHarnessTests`
- `README.md` — FOUND, contains `pi_load_acceptance.py`
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — FOUND, contains `D-DEBT-06-02` and `D-DEBT-06-04`
- Commit `807776a` — FOUND in `git log --oneline`
- Commit `f8c3560` — FOUND in `git log --oneline`
- Full suite: `uv run --project dashboard python -m pytest -q` — 795 passed, 561 subtests passed in 225.94s
