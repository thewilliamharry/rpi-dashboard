---
phase: 01
slug: behavioral-safety-runtime-ownership
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-24
---

# Phase 01 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.1.1 with `unittest.TestCase`, Flask test client, and temporary SQLite databases |
| **Config file** | `dashboard/pyproject.toml` |
| **Quick run command** | `dashboard/.venv/bin/python -m pytest -q` |
| **Full suite command** | `dashboard/.venv/bin/python -m pytest -q` plus Compose recovery smoke when Docker is available |
| **Estimated runtime** | ~1 second for the current 43-test suite; new migration/recovery tests may increase this |

---

## Sampling Rate

- **After every task commit:** Run `dashboard/.venv/bin/python -m pytest -q`
- **After every plan wave:** Run the full pytest suite plus the phase-specific migration, queue, runtime-ownership, and outbound-policy tests
- **Before `$gsd-verify-work`:** Full suite must be green; Compose recovery smoke must pass where Docker is available
- **Max feedback latency:** 60 seconds for task-level automated feedback

---

## Per-Task Verification Map

Plan and task IDs are assigned during planning. Every resulting task must map to one or more rows below.

| Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| FND-01 | — | Existing route, response, metadata, scan, preview, uptime, and event contracts remain compatible | API contract + integration | `dashboard/.venv/bin/python -m pytest -q tests/test_api_and_auth.py tests/test_uptime_integration.py tests/test_ui_contract.py` | ✅ expand | ⬜ pending |
| FND-02 | — | Runtime modules have explicit dependency direction without circular application imports | import-boundary unit | `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py` | ❌ W0 | ⬜ pending |
| FND-03 | — | Importing the web composition root starts no scheduler, browser, probe, migration, or network work | fresh-process import unit | `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py -k import` | ❌ W0 | ⬜ pending |
| FND-04 | T-01 | Only the worker owns scheduling and durable queue claims recover without duplicate execution | SQLite integration + process smoke | `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py tests/test_durable_queues.py` | ❌ W0 | ⬜ pending |
| FND-05 | T-02 | Each supported legacy schema upgrades atomically once and a forced failure leaves no partial version | migration fixtures | `dashboard/.venv/bin/python -m pytest -q tests/test_migrations.py` | ❌ W0 | ⬜ pending |
| FND-06 | T-02 | Pre-migration backup opens and passes integrity checks; retention keeps three; restore returns readable data | backup/restore integration | `dashboard/.venv/bin/python -m pytest -q tests/test_backup_recovery.py` | ❌ W0 | ⬜ pending |
| FND-07 | T-03 | Every outbound purpose uses the policy seam; LAN TLS exceptions remain visible and webhooks remain strict | policy unit + integration | `dashboard/.venv/bin/python -m pytest -q tests/test_outbound_policy.py` | ❌ W0 | ⬜ pending |
| OPS-05 | T-03 / T-04 | Invalid schemes, credentials, ports, resolved addresses, redirects, TLS modes, hosts, origins, and mutation headers fail safely | table-driven security | `dashboard/.venv/bin/python -m pytest -q tests/test_outbound_policy.py tests/test_security_and_scanning.py tests/test_release_contract.py` | ✅ expand | ⬜ pending |

---

## Wave 0 Requirements

- [ ] `tests/fixtures/legacy/` — sanitized SQLite fixture for each schema shape found in history and each production shape found during inventory
- [ ] `tests/test_migrations.py` — upgrade, idempotency, forced rollback, and schema-version tests
- [ ] `tests/test_backup_recovery.py` — verified online backup, three-backup retention, restore, and post-restore API-data tests
- [ ] `tests/test_runtime_ownership.py` — clean web import, sole scheduler owner, stale worker behavior, recovery gap event, and duplicate-start prevention
- [ ] `tests/test_durable_queues.py` — atomic claim, lease expiry, restart recovery, visible request expiry, and metadata persistence without worker
- [ ] `tests/test_outbound_policy.py` — outbound-purpose matrix, DNS A/AAAA handling, redirect chain, strict webhook TLS, and unverified-LAN-service indicator
- [ ] Stable Compose smoke harness for web/worker ownership and the supported recovery path

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Production database inventory and support-floor decision | FND-05 | The repository cannot reveal every database currently deployed on the operator's Pi | Copy metadata-only/schema snapshots or sanitized databases, classify each shape, and record which fixtures represent supported upgrades |
| Recovery clarity on the deployed Compose environment | FND-06 | Operator usability and volume ownership depend on the actual Raspberry Pi deployment | Force a migration failure on a disposable copy, confirm the worker does not operate, follow the supported recovery path, and verify services/metadata/events reappear |

---

## Validation Sign-Off

- [ ] All tasks have automated verification or explicit Wave 0 dependencies
- [ ] Sampling continuity: no three consecutive tasks without automated verification
- [ ] Wave 0 covers all missing references
- [ ] No watch-mode flags
- [ ] Feedback latency remains below 60 seconds for task-level checks
- [ ] `nyquist_compliant: true` set in frontmatter after validation

**Approval:** pending
