---
phase: 01
slug: behavioral-safety-runtime-ownership
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-24
validated: 2026-08-24
---

# Phase 01 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.x with `unittest.TestCase`, `pytest-subtests`, Flask test client, and temporary SQLite databases |
| **Config file** | `dashboard/pyproject.toml` (`testpaths = ["../tests"]`, `pythonpath = [".."]`) |
| **Working directory** | Pinned by `tests/conftest.py` — a session-scoped autouse fixture chdirs to the repository root, so the suite is green from any invocation directory |
| **Quick run command** | `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py tests/test_module_boundaries.py tests/test_durable_queues.py tests/test_migrations.py tests/test_backup_recovery.py tests/test_outbound_policy.py tests/test_worker_ownership_matrix.py` |
| **Full suite command** | `dashboard/.venv/bin/python -m pytest -q` |
| **Measured runtime** | Quick run 45s (149 tests, 200 subtests). Full suite ~149s (561 tests, 470 subtests), reproduced from both the repository root and `dashboard/` on 2026-08-24 |

---

## Sampling Rate

- **After every task commit:** Run the quick run command above (45s — the Phase 1 surface only)
- **After every plan wave:** Run the full suite
- **Before `$gsd-verify-work`:** Full suite must be green; the Compose recovery path must be exercised manually (see Manual-Only)
- **Max feedback latency:** 60 seconds for task-level automated feedback — met by the 45s quick run. The full suite at ~149s deliberately exceeds it and is a wave-level gate, not a task-level one.

---

## Per-Task Verification Map

| Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| FND-01 | — | Existing route, response, metadata, scan, preview, uptime, and event contracts remain compatible | API contract + integration | `dashboard/.venv/bin/python -m pytest -q tests/test_api_and_auth.py tests/test_uptime_integration.py tests/test_ui_contract.py` | ✅ | ✅ COVERED — 35 passed, 55 subtests |
| FND-02 | — | Runtime modules have explicit dependency direction without circular application imports | import-boundary unit | `dashboard/.venv/bin/python -m pytest -q tests/test_module_boundaries.py tests/test_runtime_ownership.py` | ✅ | ✅ COVERED — 17 passed / 22 subtests + 22 passed / 61 subtests |
| FND-03 | — | Importing the web composition root starts no scheduler, browser, probe, migration, or network work | fresh-process import unit | `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py -k import` | ✅ | ✅ COVERED — 2 passed, 45 subtests |
| FND-04 | T-01 | Only the worker owns scheduling and durable queue claims recover without duplicate execution | SQLite integration + process smoke | `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py tests/test_durable_queues.py tests/test_worker_ownership_matrix.py` | ✅ | ✅ COVERED — 36 passed / 71 subtests + 10 passed / 62 subtests |
| FND-05 | T-02 | Each supported legacy schema upgrades atomically once and a forced failure leaves no partial version | migration fixtures | `dashboard/.venv/bin/python -m pytest -q tests/test_migrations.py` | ✅ | ✅ COVERED — 40 passed, 6 subtests |
| FND-06 | T-02 | Pre-migration backup opens and passes integrity checks; retention keeps three; restore returns readable data | backup/restore integration | `dashboard/.venv/bin/python -m pytest -q tests/test_backup_recovery.py` | ✅ | ✅ COVERED — 22 passed, 13 subtests |
| FND-07 | T-03 | Every outbound purpose uses the policy seam; LAN TLS exceptions remain visible and webhooks remain strict | policy unit + integration | `dashboard/.venv/bin/python -m pytest -q tests/test_outbound_policy.py` | ✅ | ✅ COVERED — 24 passed, 26 subtests |
| OPS-05 | T-03 / T-04 | Invalid schemes, credentials, ports, resolved addresses, redirects, TLS modes, hosts, origins, and mutation headers fail safely | table-driven security | `dashboard/.venv/bin/python -m pytest -q tests/test_outbound_policy.py tests/test_security_and_scanning.py tests/test_release_contract.py` | ✅ | ✅ COVERED — 49 passed, 26 subtests |

All eight requirements independently re-run green on 2026-08-24. Counts above are from that run, not from SUMMARY.md prose.

---

## Wave 0 Requirements

- [x] `tests/fixtures/legacy/` — sanitized SQLite fixtures per schema shape: `initial-2026-04.db`, `metadata-events-2026-04.db`, `runtime-queues-2026-07.db`, `current-v4.db`, `current-v6.db`, plus `support-floor.json`
- [x] `tests/test_migrations.py` — upgrade, idempotency, forced rollback, and schema-version tests
- [x] `tests/test_backup_recovery.py` — verified online backup, three-backup retention, restore, and post-restore API-data tests
- [x] `tests/test_runtime_ownership.py` — clean web import, sole scheduler owner, stale worker behavior, recovery gap event, and duplicate-start prevention
- [x] `tests/test_durable_queues.py` — atomic claim, lease expiry, restart recovery, visible request expiry, and metadata persistence without worker
- [x] `tests/test_outbound_policy.py` — outbound-purpose matrix, DNS A/AAAA handling, redirect chain, strict webhook TLS, and unverified-LAN-service indicator
- [x] `tests/conftest.py` — working-directory pin (added 2026-08-24 by this audit; see Validation Audit below)
- [~] ~~Stable Compose smoke harness for web/worker ownership and the supported recovery path~~ — **never built; reclassified as Manual-Only.** Nothing in the suite invokes `docker compose`. Compose coverage is static text assertion against `docker-compose.yml` and `README.md` (`tests/test_ui_contract.py:90,104,169`, `tests/test_startup_ordering.py:134`), which pins the file's *contents* but never proves the stack *runs*.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Production database inventory and support-floor decision | FND-05 | The repository cannot reveal every database currently deployed on the operator's Pi | Copy metadata-only/schema snapshots or sanitized databases, classify each shape, and record which fixtures represent supported upgrades |
| Recovery clarity on the deployed Compose environment | FND-06 | Operator usability and volume ownership depend on the actual Raspberry Pi deployment | Force a migration failure on a disposable copy, confirm the worker does not operate, follow the supported recovery path, and verify services/metadata/events reappear |
| Compose stack actually starts with correct web/worker ownership | FND-03, FND-04 | Requires a Docker daemon and a real multi-container start; the suite asserts `docker-compose.yml` *content* but never runs it. Reclassified from Wave 0 on 2026-08-24 | On a machine with Docker: `docker compose up -d`, confirm the `migrate` one-shot completes before `web` and `worker` start, confirm exactly one worker claims the scheduler lease, and confirm `recovery` does not start without `--profile recovery` |

---

## Validation Sign-Off

- [x] All tasks have automated verification or explicit Manual-Only entries
- [x] Sampling continuity: no three consecutive tasks without automated verification
- [x] Wave 0 covers all missing references (one item reclassified to Manual-Only rather than left unchecked)
- [x] No watch-mode flags
- [x] Feedback latency remains below 60 seconds for task-level checks (45s quick run)
- [x] `nyquist_compliant: true` set in frontmatter after validation

**Approval:** validated 2026-08-24

---

## Validation Audit 2026-08-24

Run by `/gsd-validate-phase 01`. This file was a plan-time seed dated 2026-07-24 — every row read `⬜ pending` and every Wave 0 reference read `❌ W0`, because none of the tests existed yet. Phase 1 has since executed all 23 plans and passed verification. This audit reconciled the contract against what the tree actually contains.

| Metric | Count |
|--------|-------|
| Requirements audited | 8 |
| COVERED | 8 |
| PARTIAL | 0 |
| MISSING | 0 |
| Gaps found | 3 |
| Resolved | 3 |
| Escalated | 0 |

### Gap 1 — Working-directory fragility (RESOLVED, code change)

`tests/test_ui_contract.py` reads project files through bare relative paths in 17 places (`pathlib.Path('dashboard/app.js')`, `'docker-compose.yml'`, `'README.md'`), and no `conftest.py` pinned the working directory. Only 2 of 22 test files used the `PROJECT_ROOT = Path(__file__).resolve().parents[1]` idiom.

Because the pytest config lives in `dashboard/pyproject.toml` and sets `testpaths = ["../tests"]`, invoking `pytest` from `dashboard/` — the natural place, next to the config — collected the whole suite and then failed **39 tests** on missing files. Those failures were false alarms about paths, not defects. A sampling contract whose signal goes red for the wrong reason is worse than no signal.

**Fix:** added `tests/conftest.py`, a session-scoped autouse fixture that chdirs to the repository root and restores on teardown. Safe by inspection — no test changes its own working directory, and every subprocess in the suite already passes an explicit `cwd=`.

**Verified:** full suite run from both directories after the fix — `dashboard/`: 561 passed, 470 subtests (was 39 failed / 531 passed). Repository root: 561 passed, 470 subtests (unchanged). This also independently reproduces the count `03.1-VERIFICATION.md` claims.

### Gap 2 — Documented command drift (RESOLVED, doc change)

The FND-02 row named `tests/test_runtime_ownership.py`. The real module-boundary and connection-ownership gate tests live in `tests/test_module_boundaries.py`, which did not exist when this file was seeded. The row now names both files.

### Gap 3 — Wave 0 item 7 never built (RESOLVED, reclassified)

"Stable Compose smoke harness for web/worker ownership and the supported recovery path" sat as an unchecked Wave 0 box. Nothing in the suite invokes `docker compose`; the Compose surface is covered by static text assertions against `docker-compose.yml` and `README.md` only. Reclassified as a third Manual-Only entry with explicit instructions, rather than left as a permanently unchecked automation promise.
