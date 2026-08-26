---
phase: 5
slug: theme-parity-analytics-experience
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: true
created: 2026-08-26
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest (`pytest>=9.0.2,<10`) with `playwright.sync_api` driving a real Chromium against a real Flask server |
| **Config file** | `dashboard/pyproject.toml` (`[tool.pytest.ini_options]`, `testpaths = ["../tests"]`) |
| **Quick run command** | `uv run --project dashboard python -m pytest tests/test_advanced_ui.py tests/test_ui_states.py tests/test_ui_contract.py -q` |
| **Full suite command** | `uv run --project dashboard python -m pytest -q` |
| **Estimated runtime** | quick run: seconds; full suite: minutes (browser-driven) |

---

## Sampling Rate

- **After every task commit:** the task's own `<automated>` command (each task carries at least one, scoped to the module it changed)
- **After every plan wave:** `uv run --project dashboard python -m pytest -q`
- **Before `/gsd-verify-work`:** full suite must be green
- **Max feedback latency:** the per-task scoped command, seconds for source-level modules and under a minute for a single browser module

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 5-01-01 | 01 | 1 | UX-07 | T-05-01 / T-05-02 / T-05-03 | degraded is emitted only from durable evidence via one shared classifier, and never together with stale | integration (API) | `uv run --project dashboard python -m pytest tests/test_advanced_diagnosis_api.py tests/test_api_and_auth.py -q` | ✅ | ⬜ pending |
| 5-01-02 | 01 | 1 | UX-07 | T-05-04 | banner copy is static markup; JS toggles only `hidden`; no HTML sink introduced | contract (source + browser) | `uv run --project dashboard python -m pytest tests/test_ui_contract.py tests/test_ui_states.py tests/test_advanced_ui.py -q` | ✅ | ⬜ pending |
| 5-01-03 | 01 | 1 | UX-07, OPS-06 | T-05-01 / T-05-02 | an unstubbed aging heartbeat raises exactly one banner in both themes on both documents | browser end-to-end | `uv run --project dashboard python -m pytest tests/test_ui_safety_integration.py -q` | ✅ | ⬜ pending |
| 5-02-01 | 02 | 2 | UX-07, UX-06 | T-05-06 / T-05-09 | unrecognised freshness literals fail closed to Unknown; all new text via `textContent` | browser/UI-contract | `uv run --project dashboard python -m pytest tests/test_advanced_ui.py tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 5-02-02 | 02 | 2 | UX-07 | T-05-06 | every freshness reading is keyed off a server literal, never a client age comparison | browser/UI-contract | `uv run --project dashboard python -m pytest tests/test_advanced_ui.py tests/test_advanced_diagnosis_api.py tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 5-02-03 | 02 | 2 | UX-07, OPS-06 | T-05-07 | boxed error and inline degraded stay distinguishable by shape in each theme | browser/UI-contract, dual-theme | `uv run --project dashboard python -m pytest tests/test_advanced_ui.py -q` | ✅ | ⬜ pending |
| 5-03-01 | 03 | 2 | UX-01, UX-03 | T-05-10 | the theme-gated visibility surface cannot grow without classification | source-level contract | `uv run --project dashboard python -m pytest tests/test_ui_contract.py -q` | ✅ | ⬜ pending |
| 5-03-02 | 03 | 2 | UX-01, OPS-06 | T-05-11 | shared capability is proven present and displayed in both themes, never inferred from colour | browser/UI-contract, dual-theme | `uv run --project dashboard python -m pytest tests/test_ui_states.py -q` | ✅ | ⬜ pending |
| 5-03-03 | 03 | 2 | UX-01 | T-05-12 | deliberate calm is CSS over a complete document, with a recorded substitute or a recorded exception | browser/UI-contract, dual-theme | `uv run --project dashboard python -m pytest tests/test_ui_states.py -q` | ✅ | ⬜ pending |
| 5-04-01 | 04 | 3 | UX-06 | T-05-15 / T-05-17 | actionable elements announce as actionable; accessible names carry no HTML sink | browser/accessibility | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py tests/test_ui_states.py -q` | ✅ | ⬜ pending |
| 5-04-02 | 04 | 3 | UX-06, OPS-06 | T-05-15 / T-05-16 | focus disclosure reuses the existing coalesced tooltip and cursor mechanisms | browser/accessibility | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py tests/test_advanced_ui.py -q` | ✅ | ⬜ pending |
| 5-04-03 | 04 | 3 | UX-06 | T-05-13 / T-05-14 | one range-apply function serves both gestures; the server re-validates bounds unchanged | browser/keyboard | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 5-05-01 | 05 | 4 | UX-04 | T-05-18 / T-05-19 | the density preference keeps its strict allowlist; the override record stays bounded | browser/UI-contract | `uv run --project dashboard python -m pytest tests/test_advanced_ui.py tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 5-05-02 | 05 | 4 | UX-03, UX-04, OPS-06 | T-05-20 | density never makes a control unreachable, asserted by equal control sets across themes | browser/UI-contract, dual-theme | `uv run --project dashboard python -m pytest tests/test_advanced_ui.py -q` | ✅ | ⬜ pending |
| 5-05-03 | 05 | 4 | UX-07 | T-05-21 / T-05-22 | a failed read never leaves a number it did not produce | browser/UI-contract | `uv run --project dashboard python -m pytest tests/test_history_investigation_ui.py -q` | ✅ | ⬜ pending |
| 5-06-01 | 06 | 4 | UX-05 | T-05-23 | the two stylesheets cannot drift apart on the narrow boundary | source-level contract | `uv run --project dashboard python -m pytest tests/test_theme_parity_ui.py tests/test_advanced_ui.py tests/test_history_investigation_ui.py -q` | ❌ created by 5-06-01 | ⬜ pending |
| 5-06-02 | 06 | 4 | UX-05, OPS-06 | T-05-24 / T-05-26 | the boundary is asserted from both sides and the light run is proven to have applied | browser/UI-contract, dual-theme | `uv run --project dashboard python -m pytest tests/test_theme_parity_ui.py -q` | ✅ after 5-06-01 | ⬜ pending |
| 5-06-03 | 06 | 4 | UX-05, OPS-06 | T-05-25 / T-05-27 | narrow layouts scroll rather than hide, and no pixel baseline is introduced | browser/UI-contract, dual-theme | `uv run --project dashboard python -m pytest -q` | ✅ after 5-06-01 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. pytest, Playwright 1.61.0 and the Chromium
binary are already present and working (`05-RESEARCH.md` "Environment Availability"), and every
module this phase extends already exists — with one intra-plan exception:

- [x] `tests/test_theme_parity_ui.py` — the phase's new cross-surface dual-theme module is created
      by plan 05-06 Task 1, which is the first task of that plan; Tasks 2 and 3 extend it. This is
      an intra-plan ordering dependency, not a cross-wave gap, so no Wave 0 scaffold is required.
- [x] Framework install: none needed.

---

## Manual-Only Verifications

`workflow.human_verify_mode` is `end-of-phase`, so these are checked once at the end of the phase
rather than by a blocking checkpoint mid-execution.

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| The four glyphs (`●` `◈` `◐` `○`) are legible and distinguishable at 12px on the Raspberry Pi's actual display and font stack | UX-07 | Glyph rendering depends on the installed font fallback chain; a computed-style assertion proves the character is present, not that it is distinguishable to a human at that size | On the Pi, open `/advanced` → Services in both themes with services at all four freshness tiers and confirm the four badges are told apart at a normal viewing distance |
| Light mode still reads as calmer than dark after the disclosure defaults land | UX-04 | "Calm" is a subjective product-intent judgement no assertion can make; the tests prove reachability and default state, not the felt result | Open `/advanced` in light with no density preference, walk History and Incidents, and confirm the reduced simultaneous content reads as calmer rather than as missing |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [ ] Feedback latency < 5s — the quick run is seconds for source-level modules; browser-driven modules exceed 5s by nature of launching Chromium, which is this project's established and accepted cost
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
