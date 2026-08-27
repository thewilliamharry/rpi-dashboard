# Codebase Concerns

**Analysis Date:** 2026-08-27

## Tech Debt

**Deferred WCAG AA compliance decision:**
- Issue: Light-mode `--green` token fails WCAG AA for `.freshness-fresh` badge at 3.30:1 contrast ratio (4.5:1 required)
- Files: `dashboard/style.css:36`, `dashboard/advanced.css:213`, plus 7 other consumers
- Impact: The freshness badge for the "fresh" state is not accessible in light mode; retuning the token affects all success indicators across the light theme (text at two sizes, five fills)
- Fix approach: Requires a deliberate product decision: (a) darken light-mode `--green` to clear 4.5:1 across all text consumers, (b) introduce a separate text-only success token, or (c) accept 3.30:1 and record an exception. Recorded in `05-DEBT.md` D-DEBT-01 as deliberate deferral awaiting human decision. This is not an oversight — Task 3 of `05-02-PLAN.md` deliberately omits `.freshness-fresh` from its contrast assertions.

**Hand-written SQLite migrations:**
- Issue: Complex migration system with manual fallback and recovery paths
- Files: `dashboard/beacon/migrations.py` (818 lines)
- Impact: High implementation complexity requiring careful coordination between `migrate.py`, recovery snapshots, and the `RECOVERY_MARKER` file
- Current mitigation: Well-designed with verified recovery snapshots, contention budgeting (240-second wait), and atomic file operations; all tested by 67 assertions across `tests/test_migrations.py` and `tests/test_backup_recovery.py`
- Safe modification: Any change to migration logic must re-verify against the full test suite; the system is robust but intricate

**Large client-side module:**
- Issue: `dashboard/advanced.js` is 4,062 lines
- Files: `dashboard/advanced.js`
- Impact: Single-file size makes local function visibility and state tracking harder (though no global mutable state leaks between functions)
- Mitigation: Well-structured with clear sections and purpose comments; no dead code except one unreachable branch (IN-01, documented below)

---

## Known Bugs

### CR-01: Keyboard chart-range-selection anchor state leak (OPEN)

**Symptoms:** 
After holding a keyboard range anchor (Shift+Enter on a chart point), performing a mouse drag, and then pressing plain Enter on any chart point, a stale date range (built from the original anchor point, not the new point) applies silently with no visual warning.

**Files:** 
- `dashboard/advanced.js:2328` (`beginKeyboardRangeAnchor` sets `pendingRangeAnchor`)
- `dashboard/advanced.js:2251` (`beginDragSelect` starts mouse drag)
- `dashboard/advanced.js:2238-2312` (`beginDragSelect`, `updateDragSelect`, `commitDragSelect`, `cancelDragSelect`)
- `dashboard/advanced.js:2350` (`cancelKeyboardRangeAnchor` exists but is never called during drag)

**Trigger:**
1. Focus a chart point and press Shift+Enter (arming `pendingRangeAnchor`)
2. Perform an ordinary mouse drag on any chart instead (or click an unrelated preset)
3. Tab to a different chart point and press Enter (plain Enter, no Shift)
4. Result: A range built from step 1's timestamp fires, silently overwriting step 3's intended action

**Workaround:** 
Press Escape to clear the pending anchor before interacting with mouse controls, or press Shift+Enter again to complete or clear the anchor intentionally.

**Direct code evidence:** 
`commitDragSelect` (line ~2313) calls `cancelDragSelect`, which clears `dragState` but never calls `cancelKeyboardRangeAnchor()`. The mouse drag lifecycle is independent and does not know about `pendingRangeAnchor`.

**Why this blocks Phase 5:** Directly contradicts 05-04-PLAN.md's declared must-have truth: *"A pending keyboard range anchor can always be abandoned without applying anything, and abandoning it leaves the current range untouched."* A mouse drag is not a documented abandon path, so the anchor is never abandoned. Confirmed untested: no regression test exercises the "keyboard-anchor, then mouse-drag, then plain Enter" sequence.

**Fix approach:** 
Call `cancelKeyboardRangeAnchor()` at the start of `beginDragSelect()` (to clear any stale anchor before starting a new drag) and/or at the end of `commitDragSelect()` for defense-in-depth. Add a regression test in `tests/test_history_investigation_ui.py` exercising the full sequence.

---

### WR-01: Degraded and recovery safety banners can render simultaneously with contradictory copy (OPEN)

**Symptoms:** 
When a recovery-marker file exists on disk AND the worker heartbeat is aging (but not yet stale), both `#degraded-warning` ("Degraded — Beacon's worker heartbeat is aging. Monitoring continues; this is not a failure.") and `#recovery-warning` ("Upgrade recovery is required. Monitoring is paused. Follow the documented recovery command...") render side-by-side with directly contradictory claims about monitoring status.

**Files:**
- `dashboard/app.py:3047` (computes `state['worker_degraded']`)
- `dashboard/app.py:3051` (computes `state['recovery_required']`)
- `dashboard/beacon/diagnosis.py:676` (computes `safety['worker_degraded']`)
- `dashboard/beacon/diagnosis.py:666` (computes `recovery_required`)
- `dashboard/app.js:150-151` (toggles both banners from `updateScanStatus`)
- `dashboard/advanced.js:3178-3180` (toggles both banners from `renderSafety`)

**Trigger:**
1. Place an on-disk recovery-marker file (e.g., `recovery-required.json`)
2. Allow the worker heartbeat to age (time passes, no heartbeat renewal) but NOT reach the `worker_stale` threshold
3. Result: Both banners render, with contradictory "monitoring paused" vs. "monitoring continues" claims

**Why this is reachable:** 
- `worker_degraded` is computed as `(not worker_stale) and state['worker_freshness']['state'] == 'aging'` (app.py:3047, diagnosis.py:676)
- `recovery_required` is computed independently as `worker_stale or (Path(DB_PATH).parent / RECOVERY_MARKER).is_file()` (app.py:3051, diagnosis.py:666)
- Both are guarded against `worker_stale`, but `worker_degraded` is NOT guarded against `recovery_required`
- These two booleans are **orthogonal**: a recovery marker file and an aging heartbeat are both independent conditions; one does not imply the other

**Current test coverage gap:** 
No test in `tests/test_ui_safety_integration.py` seeds a recovery-marker file alongside an aging (not stale) heartbeat. Grepped the file for `RECOVERY_MARKER`/`recovery_required` — zero matches.

**Why this blocks Phase 5:** Directly contradicts UX-07 success criterion: *"Loading, empty, stale, unknown, degraded, and error states are visibly and meaningfully distinct in both themes."* The safety-banner cluster is not meaningfully distinct when both states render together with contradictory messaging.

**Fix approach:** 
Gate `worker_degraded` on `not recovery_required` as well as `not worker_stale` in both `dashboard/app.py:3047` and `dashboard/beacon/diagnosis.py:676`. Add a regression test in `tests/test_ui_safety_integration.py` seeding a recovery-marker file alongside an aging (not stale) heartbeat, asserting that `#degraded-warning` and `#recovery-warning` never both render.

---

## Security Considerations

**Database recovery marker file handling:**
- Risk: The recovery marker file (`recovery-required.json`) is checked via `.is_file()` on every `/api/scan-status` request and every diagnosis computation
- Files: `dashboard/app.py:3051`, `dashboard/beacon/diagnosis.py:666`, `dashboard/beacon/recovery.py:336-337`
- Current mitigation: File is created atomically using a temporary file + rename pattern (recovery.py:337), and cleaned up with `unlink(missing_ok=True)` for race-safe cleanup. The file itself contains immutable JSON data. The marker is checked only for existence, never parsed during the fast path.
- Status: Solid design; no immediate concerns

**Outbound request policy:**
- Risk: This is a monitoring dashboard making requests to user-configured services — probes, previews, webhooks
- Files: `dashboard/beacon/outbound.py` (592 lines), `dashboard/beacon/config.py` (277 lines)
- Current mitigation: Strict `OutboundPolicy` with DNS resolution, redirect budgets (5 for services/previews, 0 for webhooks), timeout enforcement, and TLS posture tracking. Service purpose is validated before each connection. Webhook delivery is guarded against redirects entirely.
- Status: Mature; no immediate concerns

**SQL construction in repositories:**
- Risk: Dynamic query building in `read_maintenance_windows_for_ports` (repositories.py:938-940) uses f-strings
- Files: `dashboard/beacon/repositories.py:938-940`
- Current mitigation: The f-string constructs only the placeholders (question marks) via `','.join('?' * len(ports))` from a **count**, not the actual port values. Port values are passed separately in the parameterized tuple, so there is no SQL injection vector.
- Status: Safe; false positive for injection concerns

---

## Performance Bottlenecks

**Worker heartbeat cadence + stale/aging thresholds:**
- Problem: Two independently-configured cadences affect freshness state machine: `WORKER_READY_SECONDS` (app-configurable, env var) and `METRIC_SAMPLE_SECONDS` (service config). The 4x stale boundary is a fixed multiplier. Changes to either can shift when a heartbeat transitions from "fresh" → "aging" → "stale".
- Files: `dashboard/app.py:3041-3047`, `dashboard/beacon/worker_main.py:84`, `dashboard/beacon/config.py`
- Impact: Low risk in practice; thresholds have broad safety margins (default 20s ready + 80s stale boundary = 100s before failure), but coupling between two independently-configurable parameters is fragile
- Improvement path: Document the coupling in both `config.py` and the hearbeat detection code; consider moving WORKER_READY_SECONDS into service config as well for co-location

**Timing-sensitive intermittent test flake:**
- Problem: `tests/test_ui_safety_integration.py::test_stale_to_fresh_page_persists_actions_and_records_recovery` occasionally times out under full-suite resource contention
- Files: `tests/test_ui_safety_integration.py:82`
- Cause: Real wall-clock heartbeat aging + Playwright `wait_for(timeout=18_000)` polling for text; under contention the 18-second timeout is occasionally exceeded
- Current status: Intermittent (not deterministic), passes in isolation. Reproduced ~1 in 3 full-suite runs in past; requires baseline measurement to confirm pre-existing vs. introduced.
- Improvement path: Increase polling timeout or reduce real-world timing sensitivity by using a stubbed clock; recorded in `deferred-items.md` entry 2 as out-of-scope for phase 05 (the test file was not modified by that phase)

---

## Fragile Areas

**Test helper environment variable leakage:**
- Files: `tests/helpers.py:load_app`
- Why fragile: `load_app()` writes every `extra_env` key into `os.environ` but never restores it, causing cross-test contamination. One test's environment changes persist to all later test modules that reload `dashboard.app`.
- Safe modification: The pattern is already fixed for one instance in phase 05 (test now uses `addCleanup` to restore environment), but the helper itself remains unpatched. Fixing the helper changes shared behaviour for the whole suite — some tests may be depending on the leak. Wants its own scoped change with a full-suite run.
- Test coverage: Full-suite run required after fix to ensure no regressions. Previously caused one deterministic failure (`test_lease_takeover_records_one_monitoring_gap`), now fixed by the affected test's own cleanup.

**Wave grouping planning defect (non-code):**
- Issue: Phases 05-05 and 05-06 were grouped into the same parallel wave because their `files_modified` sets don't intersect, but they have a hidden **semantic dependency**: 05-06 changes the narrow breakpoint (719px → 720px) that two assertions inside 05-05's test file hardcode.
- Files: Affects `tests/test_advanced_ui.py` (assertions), `dashboard/advanced.css` (new value)
- Impact: 05-06 finished with 2 failing tests it could not legally fix and reported the exact reconciliation (commit 54ba02b)
- Mitigation: Not a code defect but a planning process gap. Future planning should declare `constants_changed` alongside `files_modified` and intersect that against a grep of the repo, or serialise constant-change-only phases into their own wave.

**Database migration system recovery mechanics:**
- Files: `dashboard/beacon/migrations.py` (818 lines), `dashboard/beacon/recovery.py` (500 lines)
- Why fragile: The recovery snapshot and contention budget interact in complex ways; any change to migration order or timing can affect the 240-second contention window calculation
- Safe modification: Changes must be verified against both `test_migrations.py` and `test_backup_recovery.py`; the system is robust but intricate

---

## Scaling Limits

**No identified hard scaling limits.**
- Database: SQLite with no reported capacity issues; tested against the full telemetry retention history
- Webhooks: Outbound delivery is queued and rate-limited per service
- Telemetry streams: Capped at Phase 2's retention tier boundaries and subject to aggressive rollup
- Browser resources: Screenshot/preview queue is semaphore-limited (one at a time, `_screenshot_sem`)

---

## Dependencies at Risk

**No high-risk dependencies identified.**
- Flask/Waitress: Standard web stack, tested and mature
- Playwright: Used for browser preview screenshots; optional, guarded by feature flag
- APScheduler: Scheduler for worker jobs; mature, well-tested
- SQLite: No external dependency; database is bundled

---

## Missing Critical Features

**None identified at this analysis stage.**
All planned phases (01-05) have been executed and verified. Phase 6 and beyond are not yet planned.

---

## Test Coverage Gaps

**Keyboard range-anchor + mouse-drag interaction (CR-01):**
- What's not tested: The sequence "keyboard-anchor a point (Shift+Enter) → perform a mouse drag elsewhere → plain Enter on an unrelated point"
- Files: `tests/test_history_investigation_ui.py`
- Risk: CR-01 defect can silently fire without detection
- Priority: **High** — blocks Phase 5 completion

**Recovery marker + aging heartbeat (WR-01):**
- What's not tested: Seeding a recovery-marker file alongside an aging (not stale) heartbeat
- Files: `tests/test_ui_safety_integration.py`
- Risk: WR-01 defect allows contradictory banners to render without detection
- Priority: **High** — blocks Phase 5 completion

**Intermittent load-dependent timeout (timing-sensitive):**
- What's not tested: Full-suite baseline run at the pre-phase commit to establish whether the flake is pre-existing
- Files: `tests/test_ui_safety_integration.py:82`
- Risk: Intermittent failures under resource contention mask underlying timing assumptions
- Priority: **Medium** — confirmed not deterministic and not caused by Phase 05; low operational risk but testing rigor gap

---

## Hygiene Issues

**macOS `.DS_Store` files tracked in git:**
- Files: `.DS_Store`, `dashboard/.DS_Store`, `tests/.DS_Store`
- Issue: System-generated directory index files should not be version-controlled
- Current status: All three are tracked in git history (confirmed via `git ls-files`)
- Coverage gap: `.gitignore` does not include `.DS_Store` entry
- Fix approach: Add `.DS_Store` to `.gitignore` and remove from git tracking with `git rm --cached .DS_Store dashboard/.DS_Store tests/.DS_Store`

---

## Anti-Patterns Found

### Unreachable code branch (INFO-ONLY)

**What happens:** 
`dashboard/advanced.js:369-371` — the `freshnessWord()` function has an `if (state === 'aging')` branch that returns `'degraded'`, but this branch is unreachable.

**Why it's not a bug:** 
`compose_active_exceptions` (the only caller's data source) never emits `state: 'aging'` for the exceptions that `freshnessWord()` serves. When the worker heartbeat enters "aging" state, it flows through the worker-freshness safety property, not through exception composition.

**Do nothing:** 
This is documented as IN-01 in 05-REVIEW.md and 05-VERIFICATION.md. No functional impact. No test gap — if the branch ever becomes reachable, its behavior is obvious and harmless (returns the same string the fallback would produce anyway).

---

*Concerns audit: 2026-08-27*
