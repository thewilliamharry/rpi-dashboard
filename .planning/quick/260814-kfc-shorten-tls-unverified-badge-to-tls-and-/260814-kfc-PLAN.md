---
phase: quick
plan: 260814-kfc
type: execute
wave: 1
depends_on: []
files_modified:
  - dashboard/app.js
  - tests/test_ui_contract.py
  - tests/test_ui_states.py
autonomous: true
requirements:
  - FND-07
must_haves:
  truths:
    - "A service with unverified trusted-LAN TLS shows the compact visible badge text `TLS` while retaining the existing descriptive title and accessible label."
    - "Each service card shows the visible action label `Edit`, exposes the accessible name `Edit service`, and opens the same metadata editor when activated."
    - "The copy-only change does not alter TLS posture, service availability, service-card rendering conditions, editor behavior, or either theme's DOM hooks."
  artifacts:
    - path: "dashboard/app.js"
      provides: "Compact service-card labels with preserved TLS and edit accessibility semantics"
      contains: "textContent: 'TLS'"
    - path: "tests/test_ui_contract.py"
      provides: "Static copy and accessibility contract for the service-card controls"
    - path: "tests/test_ui_states.py"
      provides: "Browser proof of visible copy, accessible descriptions, and unchanged edit activation"
  key_links:
    - from: "dashboard/app.js::buildServiceCard"
      to: ".svc-tls-unverified"
      via: "service.tls_unverified condition creates the compact badge and attaches the existing descriptive title/ARIA label"
      pattern: "service\\.tls_unverified"
    - from: "dashboard/app.js::.svc-edit"
      to: "openMetaEditor"
      via: "the unchanged click listener passes the service and edit button as the focus target"
      pattern: "openMetaEditor\\(service, edit\\)"
---

<objective>
Shorten the two main-dashboard service-card labels without weakening their behavior or accessibility contract.

Purpose: Save horizontal space in service-card action rows while preserving the established separation between TLS posture and availability and retaining a descriptive accessible name for the edit control.
Output: Updated vanilla-JavaScript service-card copy plus focused source and Playwright regression expectations.
</objective>

<execution_context>
@/Users/william/.codex/gsd-core/workflows/execute-plan.md
@/Users/william/.codex/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/STATE.md
@.planning/phases/01-behavioral-safety-runtime-ownership/01-08-SUMMARY.md
@.planning/phases/01-behavioral-safety-runtime-ownership/01-14-SUMMARY.md
@.planning/phases/03-advanced-current-diagnosis/03-VERIFICATION.md
@dashboard/app.js
@tests/test_ui_contract.py
@tests/test_ui_states.py

Phase 3 currently has separate verified gaps in advanced stylesheet delivery and advanced safety/freshness evidence. This quick task changes only main-dashboard service-card copy and its direct regression contracts; it must neither modify advanced-workspace files nor claim to close any Phase 3 verification gap.
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Compact service-card copy while preserving accessible meaning</name>
  <files>dashboard/app.js, tests/test_ui_contract.py, tests/test_ui_states.py</files>
  <behavior>
    - Source contract: `buildServiceCard()` renders visible TLS badge text exactly `TLS` only when `service.tls_unverified` is true, while its current full certificate-warning title and ARIA label remain unchanged.
    - Source contract: the service edit button renders visible text exactly `Edit` and has the explicit accessible name `Edit service`.
    - Browser contract: a TLS-unverified card exposes visible text `TLS`, the existing full title and accessible description, and an edit control whose visible text is `Edit` and accessible name is `Edit service`.
    - Interaction contract: activating the shortened edit control still opens the existing metadata editor and preserves the existing focus-target path.
  </behavior>
  <action>Update the focused assertions first so they express the requested visible copy and preserved accessibility contract, confirm the focused test run fails for the old copy, then update `buildServiceCard()` in `dashboard/app.js`. Change only the TLS badge's visible `textContent` to `TLS`; retain its `.svc-tls-unverified` class, conditional rendering, full `title`, and full `aria-label`. Change only the edit button's visible `textContent` to `Edit`, and set an explicit `aria-label` of `Edit service` so shortening the rendered text does not shorten the established accessible name. Retain `.svc-edit`, `type="button"`, `data-port`, the `openMetaEditor(service, edit)` click listener, and focus behavior. In `tests/test_ui_contract.py`, replace the obsolete visible-copy assertions and add a source assertion for the edit ARIA label. In `tests/test_ui_states.py`, update both source and browser expectations, assert the TLS badge's visible text and existing ARIA description, assert the edit button's visible text and accessible name, and preserve the existing click-through coverage. Do not modify CSS, API payloads, outbound TLS policy, advanced-workspace assets, or Phase 3 gap-closure artifacts.</action>
  <verify>
    <automated>uv run --project dashboard python -m pytest -q tests/test_ui_contract.py tests/test_ui_states.py -x</automated>
  </verify>
  <done>The focused suites pass with visible `TLS` and `Edit` labels, the TLS title/ARIA warning and edit `Edit service` accessible name are asserted, clicking `.svc-edit` still opens the editor, and the diff is limited to the three declared files.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Service API evidence to dashboard DOM | Existing `tls_unverified` evidence controls whether the non-interactive warning badge is rendered; this task changes presentation copy only and retains text-only DOM construction. |
| Operator interaction to metadata editor | The service-card button remains the entry point to the existing editor and carries a descriptive accessible name independent of its compact visual label. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-QK-KFC-01 | Spoofing | `buildServiceCard()` TLS badge | medium | mitigate | Keep `.svc-tls-unverified`, the server-owned condition, and the full title/ARIA warning unchanged; prove compact visible text and descriptive assistive text together in source and browser tests. |
| T-QK-KFC-02 | Tampering | `.svc-edit` action semantics | low | mitigate | Preserve the button type, service port, click handler, and focus target while explicitly retaining `Edit service` as the accessible name; exercise the existing browser click path. |
</threat_model>

<verification>
- Run `uv run --project dashboard python -m pytest -q tests/test_ui_contract.py tests/test_ui_states.py -x` and require a zero exit code.
- Inspect `git diff -- dashboard/app.js tests/test_ui_contract.py tests/test_ui_states.py` to confirm only visible-copy/accessibility expectations and the corresponding DOM attributes changed.
- Confirm `.planning/phases/03-advanced-current-diagnosis/03-VERIFICATION.md` remains unchanged and its recorded gaps remain pending for the dedicated Phase 3 closure workflow.
</verification>

<success_criteria>
- TLS-unverified service cards visibly show `TLS`, not the longer mark, in both theme-independent rendering paths.
- Service-card edit buttons visibly show `Edit` while retaining the accessible name `Edit service`.
- TLS warning title/ARIA semantics, service-card DOM hooks, availability separation, and edit activation behavior remain intact.
- Focused static and Playwright UI regression tests pass without changes to CSS, backend, advanced-workspace, or Phase 3 gap artifacts.
</success_criteria>

## Source Coverage Audit

| Source | ID | Feature/Requirement | Plan | Status | Notes |
|--------|----|---------------------|------|--------|-------|
| GOAL | QK-GOAL | Shorten visible `TLS unverified` to `TLS` and visible `Edit service` to `Edit` while preserving behavior and accessibility | 260814-kfc | COVERED | Implemented and verified in the single atomic UI-copy task. |
| REQ | FND-07 | Preserve the established, independently rendered trusted-LAN TLS posture and its tested safety semantics | 260814-kfc | COVERED | Copy changes retain the server-owned condition, separate badge, and descriptive warning. |
| RESEARCH | — | No research artifact was requested or produced for this established vanilla-JavaScript copy pattern | — | EXCLUDED | Discovery Level 0: existing source and test patterns fully determine the change. |
| CONTEXT | — | No quick-task CONTEXT.md or locked D-XX decisions were supplied | — | EXCLUDED | The explicit task description is the governing copy/accessibility contract. |

<output>
Create `.planning/quick/260814-kfc-shorten-tls-unverified-badge-to-tls-and-/260814-kfc-SUMMARY.md` when done.
</output>
