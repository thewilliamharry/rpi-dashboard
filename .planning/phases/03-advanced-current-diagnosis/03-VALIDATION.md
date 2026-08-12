---
phase: 03
slug: advanced-current-diagnosis
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-12
---

# Phase 03 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest >=9,<10 with existing `unittest`-style Flask, SQLite, worker-ownership, and Playwright fixture suites |
| **Config file** | `dashboard/pyproject.toml` |
| **Quick run command** | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py` |
| **Full suite command** | `uv run --project dashboard python -m pytest -q` |
| **Estimated runtime** | <60 seconds for focused Phase 3 tests; full suite sampled after every wave |

---

## Sampling Rate

- **After every task commit:** Run `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py`
- **After every plan wave:** Run `uv run --project dashboard python -m pytest -q`
- **Before `$gsd-verify-work`:** Full suite plus desktop/narrow and dark/light Playwright fixture flows must be green
- **Max feedback latency:** 60 seconds for task-level automated feedback

---

## Per-Task Verification Map

Plan and task IDs are assigned during planning. Every resulting task must map to one or more rows below.

| Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TEL-06 | T-03 / T-04 | One bounded GET snapshot exposes retention, pressure, worker, gap, aggregation, and durable job evidence without thumbnail/history scans | API + worker integration | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py -k pipeline` | ❌ W0 | ⬜ pending |
| DIA-01 | T-01 | `/advanced` and same-origin static assets are GET-only and preserve existing request middleware | Route + Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py -k navigation` | ❌ W0 | ⬜ pending |
| DIA-02 | T-04 | Host metrics, identity, sample timestamp, cadence, and four-state freshness are separate observable facts | API unit | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py -k host` | ❌ W0 | ⬜ pending |
| DIA-03 | T-04 | Every service exposes required evidence while TLS posture, availability, freshness, gaps, and failures remain distinct | API + Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py -k services` | ❌ W0 | ⬜ pending |
| DIA-08 | T-01 / T-02 | Effective settings are read-only; advanced UI contains no monitoring mutation or remote-control fetch and persists only local presentation preferences | Source contract + Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py -k settings` | ❌ W0 | ⬜ pending |
| UX-02 | — | Theme, return-scroll state, route focus, and all advanced capabilities survive dashboard round trips and supported widths | Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py -k theme_or_return` | ❌ W0 | ⬜ pending |

---

## Wave 0 Requirements

- [ ] `tests/test_advanced_diagnosis_api.py` — deterministic temporary-SQLite seeds for host/service freshness, retention, gaps, pressure, settings, job success/failure, bounded reads, and the GET-only route contract
- [ ] `tests/test_advanced_ui.py` — fixture-routed Playwright coverage for navigation, theme/scroll return, refresh pause/error retention, keyboard sorting/disclosure, filters, state copy, and desktop/narrow behavior
- [ ] Worker callback coverage — durable job health is authority-fenced, records failure without false success, and cannot create duplicate scheduled work

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Representative Raspberry Pi polling and SQLite-read overhead | TEL-06 | Target hardware load, WAL behavior, and real service count cannot be established by repository fixtures alone | Run the advanced workspace with representative services for 15 minutes at the 5-second interval; confirm no visible sampling gaps, UI stalls, or sustained database contention and record CPU/RAM/read latency |

All UI states, freshness boundaries, read-only constraints, navigation, accessibility interactions, and failure fallbacks remain automated; only target-hardware capacity is manual.

---

## Validation Sign-Off

- [ ] All tasks have automated verification or explicit Wave 0 dependencies
- [ ] Sampling continuity: no three consecutive tasks without automated verification
- [ ] Wave 0 covers all missing references
- [ ] No watch-mode flags
- [ ] Feedback latency remains below 60 seconds for focused task checks
- [ ] `nyquist_compliant: true` set in frontmatter after validation

**Approval:** pending
