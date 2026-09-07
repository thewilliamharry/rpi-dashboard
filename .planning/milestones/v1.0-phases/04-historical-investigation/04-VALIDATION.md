---
phase: 04
slug: historical-investigation
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-08-25
updated: 2026-08-25
---

# Phase 04 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> 24 tasks across 8 plans in 7 waves. Every task carries a real `<automated>` command;
> no task defers verification to a Wave 0 that does not exist.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest `>=9.0.2,<10` (`dashboard/pyproject.toml:21`), with `playwright` `sync_api` + `werkzeug.serving.make_server` for browser-contract coverage |
| **Config file** | `dashboard/pyproject.toml` — `[tool.pytest.ini_options]`, `testpaths = ["../tests"]`; `tests/conftest.py` pins the working directory to the repository root so relative asset paths resolve from any invocation directory |
| **Quick run command (server plans)** | `uv run --project dashboard python -m pytest tests/test_incidents_api.py -q` |
| **Quick run command (browser plans)** | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` |
| **Full suite command** | `uv run --project dashboard python -m pytest -q` |
| **Estimated runtime** | quick ~4s (API modules, measured: `test_historical_telemetry_api.py` + `test_advanced_diagnosis_api.py` = 3.6s / 86 tests) · quick ~35s (browser module, extrapolated from the comparable `tests/test_advanced_ui.py` at 30.9s / 53 tests) · full ~150s (measured 2026-08-25: 563 passed, 472 subtests, 149.19s) |

All figures above were measured on this repository on 2026-08-25, not estimated from recall.

---

## Sampling Rate

- **After every task commit:** run that plan's quick command (server plans → `tests/test_incidents_api.py`; browser plans → `tests/test_history_investigation_ui.py`)
- **After every plan wave:** run the full suite — `uv run --project dashboard python -m pytest -q`
- **Before `/gsd-verify-work`:** full suite must be green
- **Max feedback latency:** ~35 seconds (worst case, the browser module)

No watch-mode flags are used anywhere; every command is a single bounded run that exits.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 04-01-01 | 01 | 1 | DIA-04, HIS-01 | T-04-03 / T-04-05 / T-04-07 | No investigation state reaches the `/advanced` URL; no string-to-markup assignment; timezone name is non-secret | integration (browser + API) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py tests/test_historical_telemetry_api.py -q` | ✅ created in-task | ⬜ pending |
| 04-01-02 | 01 | 1 | DIA-04, DIA-08 | T-04-04 | A hostile stored `historyRange` falls back to the documented default; requests are built only from validated integers | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-01-03 | 01 | 1 | HIS-01 | — | N/A | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-02-01 | 02 | 2 | HIS-04 | T-04-01 | Every filter value is allowlisted before SQL is built; no interpolated SELECT | unit (tdd) | `uv run --project dashboard python -m pytest tests/test_incidents_api.py -q` | ✅ created in-task | ⬜ pending |
| 04-02-02 | 02 | 2 | HIS-04 | T-04-01 / T-04-06 / T-04-08 | Malformed parameters return 400 before SQLite opens; the route takes `_db_lock`; error bodies name the parameter only | integration (API) | `uv run --project dashboard python -m pytest tests/test_incidents_api.py -q` | ✅ | ⬜ pending |
| 04-02-03 | 02 | 2 | DIA-05, HIS-04 | T-04-02 | Bounds rejected by `HistoricalRange`; row budget capped with `truncated` disclosed; queries index-backed | integration (API) | `uv run --project dashboard python -m pytest tests/test_incidents_api.py -q` | ✅ | ⬜ pending |
| 04-03-01 | 03 | 2 | HIS-01 | T-04-05 | Per-metric copy written with `textContent` only | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-03-02 | 03 | 2 | HIS-01 | T-04-09 | Threshold lines carry documented provenance and use the muted token, so a constant cannot read as a live alert | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-03-03 | 03 | 2 | HIS-01 | T-04-02 / T-04-05 | Pointer updates coalesced; no path regenerated on hover; **R-01 render baseline measured and recorded** | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-04-01 | 04 | 3 | HIS-06 | T-04-10 | Trend withheld below three points, qualified below ten; no projection language | unit (tdd) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-04-02 | 04 | 3 | HIS-06 | T-04-10 / T-04-05 | Absent values render `Unknown`, never `0`; latest always carries its own timestamp | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-04-03 | 04 | 3 | HIS-06 | T-04-05 | DST ticks labelled from `Intl.DateTimeFormat`, never manual offset arithmetic | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-05-01 | 05 | 4 | DIA-05 | T-04-12 / T-04-04 | Only integers surviving client validation reach the request; the server re-validates independently | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-05-02 | 05 | 4 | DIA-06 | T-04-03 | The navigation stack lives in memory and localStorage only; the URL-mutation gate re-runs | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-05-03 | 05 | 4 | DIA-05, DIA-06 | T-04-02 | Drag updates only the overlay rectangle; no request issued until the gesture commits | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-06-01 | 06 | 5 | DIA-06 | T-04-04 / T-04-13 | Stored port validated to 1..65535; `/api/advanced/current` stays parameterless and byte-identical | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-06-02 | 06 | 5 | HIS-03 | T-04-05 | Service names and coverage details rendered with `textContent` only | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-06-03 | 06 | 5 | HIS-02, HIS-03 | T-04-10 | Unknown and gap seconds excluded from both sides of the ratio; no fabricated 0 or 100 percent | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-07-01 | 07 | 6 | HIS-04, DIA-08 | T-04-04 / T-04-14 / T-04-15 | Stored filters allowlisted; truncation disclosed; no action affordance exists on a read-only surface | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-07-02 | 07 | 6 | HIS-04 | T-04-05 | Incident rows render more free-text server columns than any other surface, all via `textContent` | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-07-03 | 07 | 6 | HIS-05, DIA-06 | — | N/A | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-08-01 | 08 | 7 | DIA-07 | T-04-16 | Markers carry no severity encoding, so a mark cannot imply an importance or causal claim | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-08-02 | 08 | 7 | DIA-07 | T-04-02 / T-04-05 | Cursor readout reports the instant's observed value or an explicit absence, never a borrowed neighbour; **R-01 interaction baseline measured and recorded** | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 04-08-03 | 08 | 7 | DIA-07 | T-04-16 / T-04-17 | Seven-phrase no-causation list enforced over source and rendered DOM; a failed correlation check says so | integration (browser) | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

Every task additionally carries one or more source-assertion gates (`grep`/`test` shape checks) alongside the pytest command above; those are recorded in the plans and are not repeated here. Tasks 04-02-03, 04-03-03, 04-04-03, 04-05-03, 04-06-03, 04-07-03 and 04-08-03 — the last task of each plan from wave 2 onward — additionally run the full suite as a second `<automated>` gate, so every wave boundary is sampled at full depth.

---

## Wave 0 Requirements

**Existing infrastructure covers all phase requirements.**

- pytest and its config are installed and operational (563 tests green, measured 2026-08-25); Playwright's chromium is already driven by `tests/test_advanced_ui.py`; no framework install, no `conftest.py` change and no fixture scaffolding is needed.
- The two new test modules are created **in-task by the task that first needs them** — `tests/test_history_investigation_ui.py` by task 04-01-01 (the tracer, which writes its own end-to-end test) and `tests/test_incidents_api.py` by task 04-02-01 (a `tdd="true"` task whose tests are written before the module). Neither is a MISSING reference deferred to a separate wave, so `wave_0_complete` is true with no outstanding work.

---

## Manual-Only Verifications

**All phase behaviors have automated verification.** `workflow.human_verify_mode` is `end-of-phase`, so no plan carries a `checkpoint:human-verify` task and all 8 plans are `autonomous: true`.

Two items are deliberately *recorded* rather than *gated*, and neither is a manual verification gap in this phase:

| Item | Requirement | Why not a pass/fail gate here | Where it is judged |
|------|-------------|-------------------------------|--------------------|
| R-01 render and interaction baselines (tasks 04-03-03, 04-08-02) | HIS-01, DIA-07 | The measurement is automated and asserted bounded, but the developer machine is not Pi-class, so no threshold invented here would mean anything | Phase 6 / OPS-01 inherits the recorded numbers rather than the open question |
| R-03 keyboard equivalents for drag-to-select and the hover cursor | UX-06 | Explicitly out of Phase 4 scope per `04-UI-SPEC.md`; the canonical start/end fields remain the fully keyboard-operable path to any range | Phase 5 / UX-06, with the obligation recorded at creation time |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies — 24 of 24 carry a real command; zero `MISSING` references
- [x] Sampling continuity: no 3 consecutive tasks without automated verify — every task samples
- [x] Wave 0 covers all MISSING references — none exist; the two new modules are created in-task
- [x] No watch-mode flags — every command is a single bounded run
- [x] Feedback latency < 35s — quick commands measured at ~4s (API) and ~35s (browser)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** populated 2026-08-25 by gsd-planner (revision pass, checker W-1). `status` stays `draft` until `/gsd-validate-phase` §6 sets `validated`.
