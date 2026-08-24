---
phase: 03
slug: advanced-current-diagnosis
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-08-12
validated: 2026-08-24
---

# Phase 03 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest >=9,<10 with `unittest`-style Flask, SQLite, worker-ownership, and real-Chromium Playwright suites |
| **Config file** | `dashboard/pyproject.toml` (`testpaths = ["../tests"]`, `pythonpath = [".."]`) |
| **Working directory** | Pinned by `tests/conftest.py` (added by the Phase 01 validation audit, 2026-08-24) — the suite is green from any invocation directory |
| **Quick run command** | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py` |
| **Full suite command** | `uv run --project dashboard python -m pytest -q` |
| **Measured runtime** | Quick run 32.8s (119 tests, 200 subtests) — API file 2.4s, Playwright UI file 29.7s. Full suite ~149s (561 tests, 470 subtests) |

`dashboard/.venv/bin/python -m pytest` is an equivalent invocation and is what Phase 01's contract uses; both were re-run green on 2026-08-24.

---

## Sampling Rate

- **After every task commit:** Run the quick run command above (32.8s, both Phase 3 files in full)
- **After every plan wave:** Run the full suite
- **Before `$gsd-verify-work`:** Full suite plus the dark/light and desktop/narrow Playwright flows must be green
- **Max feedback latency:** 60 seconds for task-level automated feedback — met at 32.8s

---

## Per-Task Verification Map

| Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TEL-06 | T-03 / T-04 | One bounded GET snapshot exposes retention, pressure, worker, gap, aggregation, and durable job evidence without thumbnail/history scans | API + worker integration | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py` | ✅ | ✅ COVERED — 66 passed, 109 subtests (includes all 21 background-job-health tests) |
| DIA-01 | T-01 | `/advanced` and same-origin static assets are GET-only and preserve existing request middleware | Route + Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py` | ✅ | ✅ COVERED — 53 passed, 91 subtests |
| DIA-02 | T-04 | Host metrics, identity, sample timestamp, cadence, and four-state freshness are separate observable facts | API unit | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py` | ✅ | ✅ COVERED — 66 passed, 109 subtests |
| DIA-03 | T-04 | Every service exposes required evidence while TLS posture, availability, freshness, gaps, and failures remain distinct | API + Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py` | ✅ | ✅ COVERED — 119 passed, 200 subtests |
| DIA-08 | T-01 / T-02 | Effective settings are read-only; advanced UI contains no monitoring mutation or remote-control fetch and persists only local presentation preferences | Source contract + Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py` | ✅ | ⚠️ PARTIAL BY DESIGN — read-only/no-remote-control clause covered (53 passed). The **range** clause is not, and cannot be: `dashboard/advanced.html` has no range control. `03-VERIFICATION.md:160` records DIA-08 as ⏸ DEFERRED to Phase 4; `REQUIREMENTS.md` agrees. No test can gate a control that does not exist. |
| UX-02 | — | Theme, return-scroll state, route focus, and all advanced capabilities survive dashboard round trips and supported widths | Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py` | ✅ | ✅ COVERED — 53 passed, 91 subtests |

All commands re-run green on 2026-08-24. Counts are from that run, not from SUMMARY.md prose.

---

## Wave 0 Requirements

- [x] `tests/test_advanced_diagnosis_api.py` — deterministic temporary-SQLite seeds for host/service freshness, retention, gaps, pressure, settings, job success/failure, bounded reads, and the GET-only route contract (3025 lines, 66 tests)
- [x] `tests/test_advanced_ui.py` — fixture-routed Playwright coverage for navigation, theme/scroll return, refresh pause/error retention, keyboard sorting/disclosure, filters, state copy, and desktop/narrow behavior (2158 lines, 53 tests)
- [x] Worker callback coverage — `tests/test_worker_ownership_matrix.py` (10 passed, 62 subtests) plus the 21 job-health tests in `tests/test_advanced_diagnosis_api.py`: durable job health is authority-fenced, records failure without false success, and cannot create duplicate scheduled work

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Status | Test Instructions |
|----------|-------------|------------|--------|-------------------|
| Representative Raspberry Pi polling and SQLite-read overhead | TEL-06 | Target hardware load, WAL behavior, and real service count cannot be established by repository fixtures alone | ⬜ **Never performed.** Overlaps Phase 6 / OPS-07 ("a Raspberry Pi-class acceptance run verifies responsiveness, resource budgets, recovery, and sampling continuity under representative load"), which owns this measurement for the milestone. Deliberately left open here and cross-referenced rather than duplicated. | Run the advanced workspace with representative services for 15 minutes at the 5-second interval; confirm no visible sampling gaps, UI stalls, or sustained database contention and record CPU/RAM/read latency |
| Five hardware perception/behavior checks | TEL-06, DIA-03, UX-02 | Display perception and live Pi collection state are outside `getComputedStyle` and fixture reach | ✅ **All 5 passed** — recorded in `03-UAT.md` (`status: complete`, total 5 / passed 5 / pending 0), on real hardware 2026-08-20 | See `03-UAT.md` tests 1–5: `Refresh now` accent treatment, workspace-wide hover perceptibility, real collection gap + stale host, idle-Pi job health, deliberately-broken-browser J6 fault |

All UI states, freshness boundaries, read-only constraints, navigation, accessibility interactions, and failure fallbacks are automated; only target-hardware capacity and display perception are manual.

---

## Validation Sign-Off

- [x] All tasks have automated verification or explicit Manual-Only entries
- [x] Sampling continuity: no three consecutive tasks without automated verification
- [x] Wave 0 covers all missing references
- [x] No watch-mode flags
- [x] Feedback latency remains below 60 seconds for focused task checks (32.8s)
- [x] `nyquist_compliant: true` set in frontmatter after validation

**Approval:** validated 2026-08-24

---

## Validation Audit 2026-08-24

Run by `/gsd-validate-phase 03`. This file was a plan-time seed dated 2026-08-12 — every row read `⬜ pending` and every Wave 0 reference `❌ W0`, because none of the tests existed yet. Phase 3 has since executed all 23 plans and passed verification at round 9. This audit reconciled the contract against the tree.

| Metric | Count |
|--------|-------|
| Requirements audited | 6 |
| COVERED | 5 |
| PARTIAL (by design — deferred clause) | 1 |
| MISSING | 0 |
| Gaps found | 4 |
| Resolved | 4 |
| Escalated | 0 |

### Gap 1 — The gates sampled 12 of 119 tests (RESOLVED)

Every documented command was green, and nearly meaningless. The six `-k` substring filters selected **12 of the 119 tests** in the phase's own two test files:

| Requirement | Filter | Selected | Deselected |
|-------------|--------|---------:|-----------:|
| TEL-06 | `-k pipeline` | 1 | 65 |
| DIA-01 | `-k navigation` | 1 | 52 |
| DIA-02 | `-k host` | 4 | 62 |
| DIA-03 | `-k services` | 4 | 115 |
| DIA-08 | `-k settings` | 1 | 52 |
| UX-02 | `-k theme_or_return` | 1 | 52 |

The worst case is TEL-06, the requirement that took nine verification rounds and seven consecutive rounds of background-job-health gap closure. Its entire automated gate was one test — `test_services_pipeline_and_settings_are_present_in_one_current_snapshot` — which asserts that keys are *present* in the snapshot. It selects **none** of the 21 job-health tests those rounds produced (`test_a_broken_capture_machinery_fails_j6s_job_health`, `test_callback_outcome_false_and_exception_never_claim_success`, `test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed`, and 18 more). The gate could not fail for any reason those rounds cared about.

The filters bought nothing. The whole API file runs in **2.4 seconds**; `-k pipeline` saved 2.1 seconds and forfeited 65 tests.

**Fix:** every requirement now gates on its full relevant file(s). Measured 2026-08-24: 119 passed, 200 subtests, **32.8s** — comfortably inside the contract's own 60-second task-level budget.

### Gap 2 — Wave 0 boxes unchecked (RESOLVED)

All three Wave 0 artifacts exist and pass; the boxes were never reconciled after execution. Checked off with file sizes, test counts and the specific worker-callback coverage named.

### Gap 3 — DIA-08 row overstated its coverage (RESOLVED)

The row carried a passing gate with no qualification. The gate genuinely covers the read-only / no-remote-control clause, but DIA-08 also requires the operator to change the **range**, and `dashboard/advanced.html` has no range control — `03-VERIFICATION.md:160` records the requirement as deferred to Phase 4 and `REQUIREMENTS.md` agrees. A green row implying full coverage of a deferred requirement is precisely the kind of false signal this contract exists to prevent. Row now reads PARTIAL BY DESIGN with the deferred clause named.

### Gap 4 — Manual-Only item never performed, and duplicated (RESOLVED)

The 15-minute representative-load Pi polling check was never run. It also restates what Phase 6 / OPS-07 owns for the whole milestone. Left explicitly open, marked `⬜ Never performed`, and cross-referenced to OPS-07 rather than silently carried as satisfied or duplicated as separate work.

### Correction to `v1.0-MILESTONE-AUDIT.md`

That audit (written earlier today) listed Phase 3 human-verification items 1 and 2 as outstanding tech debt, citing `03-VERIFICATION.md`. That was true when the verification report was written at 22:50 on 2026-08-20, but `03-UAT.md` was updated at 23:14 the same evening and records **all five items passed, 0 pending** — including the git-tracked artifact the verifier said was missing. The milestone audit's entries are stale and are corrected there.
