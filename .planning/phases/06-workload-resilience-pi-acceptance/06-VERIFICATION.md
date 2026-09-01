---
phase: 06-workload-resilience-pi-acceptance
verified: 2026-09-01T05:10:00Z
status: human_needed
score: 4/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
human_verification:
  - test: "Deploy this phase's build to a confirmed Raspberry Pi (or Pi-class ARM SBC) target with `docker compose up -d --build`, then run `python tests/pi_load_acceptance.py --duration 600 --base-url http://127.0.0.1 --db /data/dashboard.db --output beacon-acceptance.json` against it."
    expected: "The emitted report shows `\"run_kind\": \"acceptance\"`, a host that is genuinely Pi-class (`platform.machine()`/`platform.node()`), `overall_passed: true`, no `background_job_health` row in state `failed`, every essential job (J1-J4) classified `fresh` or `aging` (never `stale`), worker RSS at or under 1 GiB, web RSS at or under 256 MiB, every route's p95 within its declared budget, and the dashboard subjectively responsive in a browser during the run."
    why_human: "The success criterion explicitly names Raspberry Pi-class hardware. This execution environment has no confirmed, reachable Raspberry Pi (D-DEBT-06-04): a coincidental `raspi.local` mDNS/ping reply was found but could not be confirmed to be running this build, and no deployment access (SSH, `docker compose up -d`) exists to it. Running the harness's real-load mode against an unconfirmed host was correctly declined per PROH-OPS-07-02 (a report from an unverified host must not be labelled `acceptance`). The harness itself is built, checked in, and proven end-to-end by its `--self-test` smoke path (re-run independently during this verification: `overall_passed: true`, `run_kind: smoke`) and by `tests/test_workload_resilience.py::PiLoadAcceptanceHarnessTests`, which is not in question — only the real-hardware execution is missing."
gaps: []
deferred: []
---

# Phase 6: Workload Resilience & Pi Acceptance Verification Report

**Phase Goal:** Beacon keeps essential monitoring reliable while discovery and previews operate as bounded, recoverable best-effort work on Raspberry Pi-class hardware.

**Verified:** 2026-09-01T05:10:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth (mapped to ROADMAP Success Criterion) | Status | Evidence |
|---|------|--------|----------|
| 1 | Metric sampling and service checks remain within accepted cadence while discovery, previews, cleanup, and analytics queries are active | ✓ VERIFIED | `dashboard/beacon/worker_main.py:463-469` — dedicated `'cleanup': ThreadPoolExecutor(1)` lane; `'metrics'` lane (lines 84-85) is claimed by exactly J1/J2, everything else confirmed disjoint by direct grep. `tests/test_worker_ownership_matrix.py::test_every_scheduled_callback_declares_its_expected_executor_lane` asserts the `EXPECTED_EXECUTOR_LANES` map against the built scheduler. `tests/test_workload_resilience.py::CadenceUnderContentionTests::test_essential_cadence_under_contention` drives J1/J2/J3/J4/J5/J6/J7/J8-shaped work concurrently against a real temp SQLite DB and asserts `freshness_state` (the product's own classifier, not a hand-rolled threshold) returns `fresh`/`aging`, never `stale`, for J1 and J2. Re-run independently: `tests/test_workload_resilience.py` — 11/11 passed in 11.88s. Full suite green (795 passed / 561 subtests, 221.41s, re-run independently during this verification). |
| 2 | Preview work has one serialized browser owner, bounded deadlines and retries, and a visible non-fatal degraded state instead of blocking core monitoring | ✓ VERIFIED (see WARNING below) | `dashboard/beacon/queues.py` — `PREVIEW_STATUS_DEGRADED`, `preview_retry_decision` (doubling-with-cap, returns `None` at `attempt_count >= max_attempts`), `schedule_preview_retry_in_transaction`/`_for_worker_in_transaction`, `next_attempt_ts`-gated `claim_preview`, all confirmed present by direct code read. `dashboard/app.js:231,296-303` — the operator-visible degraded state (`◈ Preview capture failing — retries exhausted`) is keyed off `service.preview_status`, rendered in `.svc-meta` (not hidden by light theme) and the dark-mode fallback badge; both theme-parity CSS rules present in `style.css`. Single-owner browser and 27s capture deadline were pre-existing and unchanged. `tests/test_durable_queues.py` and `tests/test_workload_resilience.py::PreviewRetryTests` prove the bounded retry reaches `degraded` after exactly `PREVIEW_MAX_ATTEMPTS` claims without blocking J1-J4. **WARNING:** `06-REVIEW.md` WR-02 (independently confirmed by direct code read of `dashboard/app.py:3055-3062`) — the *separate*, unused `/api/thumbnail-status` `thumb_state` field can report `"degraded"` while a valid, unexpired thumbnail is still being served, because it checks `preview_status == degraded` before `has_thumb`. This field has zero frontend consumers (`grep -rn thumb_state dashboard/app.js` returns nothing) and zero test coverage, so it does not affect the dashboard's actual degraded-state signal (which correctly uses `preview_status` alone) — but it is a real, shipped inconsistency against `06-03-SUMMARY.md`'s own documented contract for that field. |
| 3 | Thumbnail data expires within a bounded managed store and no longer puts large preview blobs on Beacon's primary telemetry path | ✓ VERIFIED | Migration 10 (`dashboard/beacon/migrations.py:581-`) creates `thumbnails`, backfills, and empties `services.thumb_data`/`thumb_mime` in one transaction — confirmed by direct read. `ThumbnailStoreRepository`, `read_thumbnail`, `delete_expired_thumbnails`, `evict_thumbnails_over_budget`, `thumbnail_store_bytes`, `THUMBNAIL_EVICTION_SCAN_LIMIT` all present in `dashboard/beacon/repositories.py` (confirmed by grep). `Settings.thumbnail_ttl_days`/`thumbnail_store_max_bytes` present in `config.py` with fail-closed `_positive_int` fallback. J8's `database_surfaces` declares `'thumbnails'` (`worker_main.py:91`). Old `ThumbnailRepository` write path fully retired (`grep -rn "ThumbnailRepository\b"` outside `ThumbnailStoreRepository`/`ThumbnailResultRepository` returns nothing). Full suite green, and `tests/test_workload_resilience.py::ThumbnailRelocationTests/ThumbnailMigrationTests/ThumbnailBudgetTests` all pass. **NOTE:** `.planning/REQUIREMENTS.md` still lists OPS-03 as `[ ]`/"Pending" in both the checklist and traceability table (lines 68, 151) despite the code fully implementing it — a stale bookkeeping entry, not a code gap (06-01/06-02-SUMMARY.md both claim `requirements-completed: [OPS-03]`, but neither plan's `files_modified` includes `.planning/REQUIREMENTS.md`, unlike 06-04/06-05 which did update it for OPS-01/OPS-04). |
| 4 | Beacon recovers predictably from restarts, concurrent web/worker database activity, and failed background jobs, as proven by automated runtime and persistence coverage | ✓ VERIFIED (see WARNING below) | `dashboard/beacon/db.py:22,96,104-111` — `JOURNAL_MODE='WAL'`, PRAGMA set in `connect_db`, `configured_journal_mode` read-back, confirmed by direct read. `tests/test_workload_resilience.py::ConcurrentAccessTests::test_concurrent_web_and_worker_writers_are_corruption_free` and `::test_worker_restart_recovery_fences_the_dead_epoch` are genuine behavior-dependent (concurrency/fencing) tests and both pass — re-run independently as part of the full suite. `_db_lock` scope confirmed byte-identical across the phase's commits by the plan's own `git diff` acceptance criterion (independently spot-checked: `_db_lock` call-site count and usages unchanged). **WARNING:** `06-REVIEW.md` WR-01 (independently confirmed by direct code read of `dashboard/beacon/inventory.py:29-56`) — the WAL read-only-inspection fallback opens a normal *writable* connection and only forbids writes at the SQL level (`PRAGMA query_only=ON`), so it still requires write access to the source directory to create the `-shm` file. This defeats the fallback specifically for the workflow this phase's own README now documents (copy the 3 files, lock the copy down, then inspect) — a functional regression versus pre-WAL behavior for that documented operator path. No test in the suite exercises inspection from a genuinely read-only directory, so this gap is real and untested, not merely theoretical. It does not affect the live, writable `/data` deployment path, migrations, backups, or the concurrent-access/restart-recovery guarantees that are the substance of this truth — all of those are proven by passing tests. |
| 5 | A Raspberry Pi-class representative-load run demonstrates responsive interaction, resource-budget compliance, recovery, and uninterrupted essential sampling | ? UNCERTAIN — routed to human verification | `tests/pi_load_acceptance.py` is built, checked in, and its three oracles delegate correctly to `freshness_state`/`read_background_job_health`/`docker-compose.yml` `mem_limit` values (confirmed by direct code read and by independently re-running `python tests/pi_load_acceptance.py --self-test`: exit 0, `overall_passed: true`, `run_kind: "smoke"`, `host_machine: "arm64"`, `host_node: "Williams-MacBook-Pro-635.local"` — explicitly not Pi-class). No real Raspberry Pi-class hardware run has ever been executed against this build (`D-DEBT-06-04`). A working, smoke-tested harness is necessary but not sufficient evidence for this truth — the truth asserts an actual representative-load run *on Pi-class hardware*, which by definition cannot be produced or judged from this execution environment. |

**Score:** 4/5 truths verified programmatically; 1 truth requires human/hardware action to close (not failed, not fabricatable).

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dashboard/beacon/migrations.py` | `_migration_10_bounded_thumbnail_store`, `THUMBNAIL_BACKFILL_TTL_SECONDS` | ✓ VERIFIED | Present, registered as `Migration(10, ...)`, confirmed by direct read |
| `dashboard/beacon/repositories.py` | `ThumbnailStoreRepository`, `read_thumbnail`, `delete_expired_thumbnails`, `evict_thumbnails_over_budget`, `thumbnail_store_bytes` | ✓ VERIFIED | All present; old `ThumbnailRepository` retired |
| `dashboard/beacon/support_floor.json` / `tests/fixtures/legacy/support-floor.json` | v9 lineage entries, `target_version: 10` everywhere | ✓ VERIFIED (via green full suite; support-floor equality and version-agnostic tail assertions all pass) | |
| `dashboard/beacon/queues.py` | `PREVIEW_STATUS_DEGRADED`, `preview_retry_decision`, `schedule_preview_retry_in_transaction(_for_worker)` | ✓ VERIFIED | Present, confirmed by grep and read |
| `dashboard/beacon/config.py` | 5 new Settings fields (thumbnail TTL/budget, preview retry x3) | ✓ VERIFIED | Present with fail-closed `_positive_int` loading |
| `dashboard/beacon/worker_main.py` | `'cleanup'` executor lane, J8 reassigned | ✓ VERIFIED | Confirmed: `'metrics'` claimed by exactly J1/J2; `'cleanup'` claimed by exactly J8 |
| `dashboard/beacon/db.py` | `JOURNAL_MODE`, `configured_journal_mode` | ✓ VERIFIED | Present |
| `dashboard/beacon/inventory.py` | WAL-tolerant `_readonly_connection` fallback | ⚠️ VERIFIED-WITH-DEFECT | Present and wired, but fails on a genuinely read-only source (WR-01) — see truth 4 |
| `tests/pi_load_acceptance.py` | Standalone harness, `main`/`assert_cadence`/`assert_resource_budget`/`assert_response_times`/`parse_compose_memory_limits` | ✓ VERIFIED | Present (>150 lines), all functions confirmed by grep, `--self-test` independently re-run and passed |
| `tests/test_workload_resilience.py` | Phase 6 OPS-01..04/07 integration suite | ✓ VERIFIED | 11 tests, all pass independently re-run |
| `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` | D-DEBT-06-01 through 06-04 | ✓ VERIFIED | Present, all four entries read in full |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `dashboard/app.py` | `dashboard/beacon/repositories.py` | `_store_thumbnail_result` → `ThumbnailStoreRepository` | ✓ WIRED | Confirmed via composition-root read and passing tracer test |
| `dashboard/app.py` | `dashboard/beacon/migrations.py` (thumbnails table) | `read_thumbnail`, 3x `has_thumb` EXISTS subquery | ✓ WIRED | `grep -c "FROM thumbnails" dashboard/app.py` matches plan's acceptance criterion |
| `dashboard/beacon/worker_main.py` | `tests/worker_ownership_contract.py` | `database_surfaces` declarations (`thumbnails`, `cleanup` lane) | ✓ WIRED | Ownership-matrix tests pass |
| `dashboard/app.py` | `dashboard/beacon/queues.py` | `worker_process_preview_requests` → `preview_retry_decision` branch | ✓ WIRED | Confirmed by grep + passing `PreviewRetryTests` |
| `dashboard/app.js` | `dashboard/app.py` | `service.preview_status` → degraded copy/badge | ✓ WIRED | Confirmed by direct read of both files |
| `tests/pi_load_acceptance.py` | `dashboard/beacon/diagnosis.py` | `freshness_state` | ✓ WIRED | Confirmed by grep; no parallel threshold found in harness |
| `tests/pi_load_acceptance.py` | `docker-compose.yml` | `parse_compose_memory_limits` | ✓ WIRED | Confirmed against real file: 1g→1073741824, 256m→268435456 |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full suite green, no regressions | `time uv run --project dashboard python -m pytest -q` (run independently in full, once) | `795 passed, 561 subtests passed in 221.41s` | ✓ PASS |
| Phase 6 integration suite green | `uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py -v` | `11 passed in 11.88s` | ✓ PASS |
| Harness smoke path | `python tests/pi_load_acceptance.py --self-test --output <path>` (re-run independently) | Exit 0; `overall_passed: true`, `run_kind: "smoke"`, cadence/resources/response_times all `passed: true` | ✓ PASS |
| `'metrics'` lane exclusivity | `grep -c "executor='metrics'" dashboard/beacon/worker_main.py` | `2` | ✓ PASS |
| `'cleanup'` lane exclusivity | `grep -c "executor='cleanup'" dashboard/beacon/worker_main.py` | `1` | ✓ PASS |
| Old `ThumbnailRepository` fully retired | `grep -rn "ThumbnailRepository\b" dashboard/ tests/` excluding Store/Result variants | No hits | ✓ PASS |
| WR-01 reproduction (read-only inspection fallback) | Direct read of `_readonly_connection`/`_query_only` | Fallback opens a writable `sqlite3.connect()`, only gates writes via `PRAGMA query_only=ON` post-connect | ✓ CONFIRMED DEFECT (matches 06-REVIEW.md WR-01) |
| WR-02 reproduction (`thumb_state` precedence) | Direct read of `dashboard/app.py:3055-3062` | `degraded` branch checked before `has_thumb` branch, exactly as described | ✓ CONFIRMED DEFECT (matches 06-REVIEW.md WR-02); confirmed no frontend consumer of `thumb_state` |

### Probe Execution

| Probe | Command | Result | Status |
|-------|---------|--------|--------|
| `tests/pi_load_acceptance.py --self-test` (harness self-test, the phase's own "probe") | `python tests/pi_load_acceptance.py --self-test --output <path>` | Exit 0; JSON report `overall_passed: true`, `run_kind: "smoke"` | PASS (smoke only — not the OPS-07 acceptance run itself; see truth 5) |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|--------------|--------|----------|
| OPS-01 | 06-04 | Cadence holds under contention | ✓ SATISFIED | `worker_main.py` lane split, `test_essential_cadence_under_contention` passing |
| OPS-02 | 06-03 | Bounded preview retry, degraded state | ✓ SATISFIED | `queues.py`, `app.js`/`style.css`, passing tests; WR-02 noted as a narrow, unconsumed-field defect, not blocking |
| OPS-03 | 06-01, 06-02 | Bounded thumbnail store off primary telemetry path | ✓ SATISFIED (code); ⚠️ REQUIREMENTS.md traceability stale — still marked "Pending" | Migration 10, `ThumbnailStoreRepository`, TTL/budget reap, all passing; REQUIREMENTS.md not updated (bookkeeping only) |
| OPS-04 | 06-05 | Restart/concurrency/failed-job automated coverage | ✓ SATISFIED | WAL rollout, `ConcurrentAccessTests`, restart-fencing test, all passing; WR-01 noted as a narrow, untested inspection-fallback defect on read-only media, not blocking |
| OPS-07 | 06-06 | Pi-class acceptance run | ? NEEDS HUMAN | Harness built and smoke-proven; real hardware run never executed (`D-DEBT-06-04`) |

No orphaned requirements — all 5 phase requirement IDs (OPS-01, OPS-02, OPS-03, OPS-04, OPS-07) declared in plan frontmatter and present in REQUIREMENTS.md's Phase 6 mapping.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `dashboard/beacon/inventory.py` | 41-56 | Read-only inspection fallback is not actually read-only on a read-only filesystem (WR-01, `06-REVIEW.md`) | ⚠️ Warning | Regresses a documented operator workflow (copy-then-lock-down-then-inspect); untested; does not affect live deployment or the automated OPS-04 evidence |
| `dashboard/app.py` | 3054-3062 | `/api/thumbnail-status`'s `thumb_state` can report `degraded` while a valid thumbnail is servable (WR-02, `06-REVIEW.md`) | ⚠️ Warning | Field has zero consumers and zero test coverage; does not affect the dashboard's actual (and correct) `preview_status`-driven degraded UI |
| `dashboard/beacon/migrations.py` | 617-621 | Backfill's `expires_ts` computation relies on an unenforced schema invariant (`thumb_ts` non-NULL whenever `thumb_data` is non-NULL) — IN-01, `06-REVIEW.md` | ℹ️ Info | Not reachable under any current write path; flagged only for future-proofing |
| `.planning/REQUIREMENTS.md` | 68, 151 | OPS-03 still marked `[ ]`/"Pending" despite full implementation | ⚠️ Warning (bookkeeping) | No functional impact; traceability doc drift |
| `.planning/phases/.../06-VALIDATION.md` | 6, 107, 109 | `status: planned`, `nyquist_compliant: false`, `Approval: pending` left unclosed despite the phase's plans all executing against it | ℹ️ Info | No functional impact; validation-artifact bookkeeping not closed out |

No debt-marker anti-patterns (`TBD`/`FIXME`/`XXX`) found in any phase-modified file. No stub patterns (empty returns, hardcoded empty data flowing to render) found in the phase's new/modified code.

### Human Verification Required

### 1. Real Raspberry Pi-class acceptance run

**Test:** Deploy this phase's build to a confirmed Raspberry Pi (or genuinely Pi-class ARM SBC) with `docker compose up -d --build`, then run:
```
python tests/pi_load_acceptance.py --duration 600 --base-url http://127.0.0.1 --db /data/dashboard.db --output beacon-acceptance.json
```
**Expected:** Report shows `"run_kind": "acceptance"`, a genuinely Pi-class host, `overall_passed: true`, no `background_job_health` row in state `failed`, J1-J4 classified `fresh`/`aging` (never `stale`), worker RSS ≤ 1 GiB, web RSS ≤ 256 MiB, every route's p95 within its declared budget, and the dashboard subjectively responsive in a browser during the run.
**Why human:** Requires physical/target Raspberry Pi hardware this execution environment does not have confirmed access to. This is the one success criterion (5 of 5) that cannot be closed by any amount of additional code inspection — the harness that produces the evidence is itself already built and proven (see truth 5's evidence column).

## Gaps Summary

No blocking gaps. All four code-level success criteria (cadence isolation, bounded preview retry with visible degraded state, bounded thumbnail store, and automated restart/concurrency/failed-job coverage) are implemented, wired, and independently proven by a from-scratch re-run of the full test suite (795 passed / 561 subtests, 221.41s — matching the phase's own claimed baseline exactly) plus a from-scratch re-run of the phase's own integration suite (11/11) and the harness's `--self-test` smoke path.

The fifth criterion — a representative-load run on Raspberry Pi-class hardware — cannot be satisfied from this execution environment. The phase's own artifacts (`06-DEBT.md` D-DEBT-06-04, `06-RESEARCH.md` § Environment Availability, this project's precedent in `03-UAT.md`/`03.1-UAT.md`) already document this honestly rather than fabricating hardware evidence, and the harness that would produce that evidence is itself complete and independently re-verified as working. This is an environment-imposed gap, not a defect, and is routed to human verification rather than `passed` or `gaps_found`.

Two code-review Warnings (WR-01, WR-02) were independently reproduced by direct code inspection during this verification and are real, but narrow: WR-01 regresses an operator-documented but untested inspection workflow on read-only media; WR-02 affects an API field (`thumb_state`) with no frontend consumer and no test coverage, while the dashboard's actual (and correct) degraded-state signal is unaffected. Neither breaks a stated must-have truth or an automated test. They are carried forward here as WARNINGs for a human decision (fix now vs. accept as scoped follow-up), consistent with how `06-REVIEW.md` already flagged them.

One documentation-bookkeeping gap was found independently: `.planning/REQUIREMENTS.md` still marks OPS-03 as `[ ]`/"Pending" even though the code fully implements it (verified above) — likely because neither 06-01-SUMMARY.md nor 06-02-SUMMARY.md's `files_modified` included `.planning/REQUIREMENTS.md`, unlike 06-04/06-05 which did update it for their own requirements. Recommend updating REQUIREMENTS.md's OPS-03 checkbox and traceability row to Complete once this verification is accepted.

---

_Verified: 2026-09-01T05:10:00Z_
_Verifier: Claude (gsd-verifier)_
