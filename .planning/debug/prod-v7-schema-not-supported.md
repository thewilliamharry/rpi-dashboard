---
status: resolved
trigger: "Production Beacon database at migrations 1-7 is rejected as unsupported during the Migration 8 deployment after the data-init traversal issue is repaired."
created: 2026-08-14
updated: 2026-08-14
---

# Debug Session: production v7 schema rejected

## Symptoms

**Expected:** The operator-confirmed production database upgrades transactionally from Migration 7 to Migration 8, then worker and web become healthy.

**Actual:** `data-init` succeeds after adding `DAC_READ_SEARCH`, but the worker restart-loops with `UnsupportedSchemaError: unsupported Beacon database schema`; the UI displays stale data and unavailable-worker warnings.

**Errors:** The worker raises from `run_migrations()` before Migration 8. The sanitized Pi inventory reports fingerprint `3f88834a2cfacc2bbecac2424a3bc36955f7a81727132ba18cbc88c7bb85f7f7` and migration versions 1-7. Recovery status is `false` and `/data/recovery-required.json` is absent.

**Timeline:** Surfaced on the 2026-08-14 production rebuild after Phase 3/Migration 8 was deployed.

**Reproduction:** Start Beacon 2.0.1 against the existing Pi named volume after applying official migrations 1-7 along the operator-production upgrade path.

## Current Focus

hypothesis: confirmed — the exact operator-production-to-v7 fingerprint was absent from the support floor despite being deterministically produced by canonical migrations 2-7; the same deployment flow also exposed a missing read/search-only traversal capability and recovery commands that overrode the service entrypoint.
test: completed — reproduced fingerprint `3f88834a2cfacc2bbecac2424a3bc36955f7a81727132ba18cbc88c7bb85f7f7` from the sanitized operator fixture, then verified its admission and additive Migration 8 preservation contract.
expecting: observed — the RED contracts failed before the support-floor, Compose, and documentation changes; the bounded migration/recovery/deployment gates pass after commit `4af248a`.
next_action: resolved — deploy commit `4af248a` through the normal Pi Compose procedure and observe worker/web health; this remains an operator deployment check, not a repository test claim.
reasoning_checkpoint: The support-floor match remains exact and structural; no unknown schema acceptance or migration bypass was introduced.
tdd_checkpoint: RED observed (four focused contract failures before the fix); GREEN observed (focused gates pass after the fix).

## Evidence

- timestamp: 2026-08-14; source: Pi worker logs; observation: worker raises `UnsupportedSchemaError` before Migration 8 and restart-loops; action: stop web/worker and inventory the database read-only
- timestamp: 2026-08-14; source: Pi sanitized inventory; observation: database fingerprint is `3f88834a2cfacc2bbecac2424a3bc36955f7a81727132ba18cbc88c7bb85f7f7`, migration versions are 1-7, WAL bytes are zero, and no recovery marker exists; action: compare exact structure with supported fixtures
- timestamp: 2026-08-14; source: local deterministic reproduction; observation: applying canonical migrations 2-7 to `tests/fixtures/legacy/operator/production.db` yields the exact Pi fingerprint; action: treat this as a missing evidence-backed upgrade-path admission, not corruption
- timestamp: 2026-08-14; source: Pi data-init failure and constrained local reproduction; observation: CAP_CHOWN-only data-init cannot traverse the worker-owned mode-0700 backup catalog; action: add the narrow DAC_READ_SEARCH capability and regression coverage
- timestamp: 2026-08-14; source: Pi recovery invocation; observation: documented `docker compose run ... recovery status` replaces the Compose command and tries to execute `status`; action: document the explicit Python module entrypoint
- timestamp: 2026-08-14; source: commit 4af248a and focused regression run; observation: the support floor now admits only the exact canonical V7 fingerprint at minimum schema version 7, Migration 8 preserves inserted representative legacy rows, data-init has only CHOWN plus DAC_READ_SEARCH, and README invokes `python -m beacon.recovery` explicitly; action: resolve the repository fix while leaving actual Pi rollout observation to the operator

## Eliminated

- Database corruption: inventory completes read-only, WAL is empty, and the schema exactly matches a canonical repository migration path.
- Active recovery requirement: the marker is absent and the supported recovery CLI reports `{"recovery_required": false}`.
- Migration 8 partial application: recorded versions stop at 7 and the rejection occurs before pending migrations execute.

## Resolution

root_cause: The valid V7 schema produced by applying canonical migrations 2-7 to the operator fixture had fingerprint `3f88834a2cfacc2bbecac2424a3bc36955f7a81727132ba18cbc88c7bb85f7f7`, but that fingerprint was missing from the exact support floor, so Migration 8 rejected it before backup or write; the same production path also needed DAC_READ_SEARCH to traverse a worker-owned 0700 backup directory and explicit recovery module commands because Compose run arguments replace the service command.
fix: Commit `4af248a` adds the exact V7 support-floor evidence at minimum version 7 in the packaged and fixture manifests, adds the narrow `DAC_READ_SEARCH` data-init capability alongside CHOWN, corrects recovery commands to `python -m beacon.recovery`, and adds RED-to-GREEN regression coverage.
verification: Pre-fix focused RED run: 4 expected failures. Post-fix focused migration/UI run: 33 passed, 6 subtests passed. Dependent backup/recovery/advanced/release run: 49 passed, 28 subtests passed. Final bounded migration/UI/recovery run: 55 passed, 19 subtests passed. `docker compose config --quiet` passed. A final escalated complete suite passed: 244 tests and 269 subtests, with one pre-existing system-clock warning.
files_changed: README.md; docker-compose.yml; dashboard/beacon/support_floor.json; tests/fixtures/legacy/support-floor.json; tests/test_migrations.py; tests/test_ui_contract.py; commit 4af248a
