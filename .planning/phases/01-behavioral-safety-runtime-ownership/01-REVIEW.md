---
phase: 01-behavioral-safety-runtime-ownership
reviewed: 2026-07-31T21:36:40Z
depth: standard
files_reviewed: 41
files_reviewed_list:
  - README.md
  - dashboard/Dockerfile
  - dashboard/app.js
  - dashboard/app.py
  - dashboard/beacon/__init__.py
  - dashboard/beacon/config.py
  - dashboard/beacon/db.py
  - dashboard/beacon/inventory.py
  - dashboard/beacon/migrations.py
  - dashboard/beacon/monitoring.py
  - dashboard/beacon/outbound.py
  - dashboard/beacon/previews.py
  - dashboard/beacon/queues.py
  - dashboard/beacon/recovery.py
  - dashboard/beacon/repositories.py
  - dashboard/beacon/support_floor.json
  - dashboard/beacon/web.py
  - dashboard/beacon/worker_main.py
  - dashboard/index.html
  - dashboard/style.css
  - dashboard/worker.py
  - docker-compose.yml
  - tests/fixtures/legacy/initial-2026-04.db
  - tests/fixtures/legacy/metadata-events-2026-04.db
  - tests/fixtures/legacy/operator/production.db
  - tests/fixtures/legacy/operator/production.json
  - tests/fixtures/legacy/runtime-queues-2026-07.db
  - tests/fixtures/legacy/support-floor.json
  - tests/helpers.py
  - tests/test_api_and_auth.py
  - tests/test_backup_recovery.py
  - tests/test_durable_queues.py
  - tests/test_migrations.py
  - tests/test_module_boundaries.py
  - tests/test_outbound_policy.py
  - tests/test_release_contract.py
  - tests/test_runtime_ownership.py
  - tests/test_security_and_scanning.py
  - tests/test_ui_contract.py
  - tests/test_ui_states.py
  - tests/test_uptime_integration.py
findings:
  critical: 4
  warning: 2
  info: 0
  total: 6
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-07-31T21:36:40Z
**Depth:** standard
**Files Reviewed:** 41
**Status:** issues_found

## Summary

The migration, queue, recovery, outbound, web, worker, UI, compatibility fixtures, and tests were reviewed at standard depth. `uv run --project dashboard python -m pytest -q` passes (`101 passed, 4 subtests passed`), and `docker compose config -q`/`git diff --check` pass. Those checks do not cover the failures below. Recovery can silently retain or lose data, manual scans can become permanently stuck, and the outbound policy validates DNS answers without binding the actual connection to them.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: Restore leaves the prior SQLite WAL and SHM beside the restored database

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/recovery.py:269`

**Issue:** `restore_backup()` atomically replaces only `dashboard.db`. It neither checkpoints nor removes `dashboard.db-wal` and `dashboard.db-shm`. SQLite can subsequently replay a still-present WAL produced after the backup, so a restore that reports `completed: true` can reintroduce the very writes it was meant to roll back. This was reproduced against a temporary copy of `initial-2026-04.db`: after a committed WAL-only title update, restore returned success but the next connection read `live-wal-state`, not the backup's `backup-state`.

**Fix:** With all writers proven stopped and while the upgrade lock is held, remove or quarantine the exact `-wal` and `-shm` sidecars before admitting the restored main database, fsync the directory after each durability boundary, and add a regression test that keeps a live WAL sidecar present during restore.

### CR-02: A valid manual discovery exceeds its own queue lease and is left running forever

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/app.py:1511-1535`

**Issue:** `process_scan_requests()` claims a scan with the queue's default 30-second lease, then runs discovery, whose configured deadline is 180 seconds (`dashboard/beacon/config.py:33`; `dashboard/app.py:1084-1086`). The code never calls the existing `renew_scan_lease()`. Once a scan runs past 30 seconds, `finish_scan()` rejects it as `LeaseLost`; the row remains `running` and `claim_scan()` only selects `queued` rows. Queue recovery runs only at worker startup, so the UI can remain stuck on a running request until another restart.

**Fix:** Renew the scan lease periodically for the entire discovery operation (and fail/requeue safely if renewal is lost), or make the lease cover the full bounded operation and schedule expired-lease recovery. Add an integration test with a discovery duration greater than 30 seconds that verifies a terminal queue status.

### CR-03: DNS policy validation is bypassed by a second, unvalidated resolver lookup

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/outbound.py:252-266`

**Issue:** The policy resolves and validates addresses in `plan()`, but the requester is called with `plan.url`, a hostname URL. `requests` performs a separate DNS lookup when it opens the socket and `resolved_addresses` is never used to pin or verify that socket. The same gap exists for Chromium after `route_browser_request()` calls `route.continue_()` (`dashboard/beacon/previews.py:62-69`). A DNS rebinding between policy validation and connection can therefore send a service/browser request or the strict webhook payload to an address the policy would reject, violating the stated per-connection destination boundary.

**Fix:** Use a transport that connects only to one of the just-validated addresses while preserving the original Host header/SNI, or add a connection adapter/resolver hook that validates the address selected for every socket. Do not use `route.continue_()` unless Chromium's resolved remote address can be checked or navigation is proxied through a pinned transport. Add a rebinding regression test that returns an allowed answer to policy resolution and a forbidden answer to the transport lookup.

### CR-04: Recovery proceeds while the web writer can still mutate the database

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/recovery.py:246-258`

**Issue:** The recovery guard checks only whether `worker_heartbeat` is stale. The web container deliberately remains available while the worker is stale and continues to write service metadata, scan requests, rate-limit rows, and events (`dashboard/app.py:1844-1938`, `dashboard/app.py:2026-2041`). It does not acquire the upgrade lock or publish a lease/heartbeat that recovery verifies. Thus a normal worker outage makes `restore_backup()` eligible while a live web process can commit concurrently, causing lost writes or WAL sidecar replay during restore.

**Fix:** Give every database writer a shared maintenance/read-write lease and have recovery refuse restoration until the web and worker writer leases are absent/stale under the same lock. Alternatively, make the supported command enforce exclusive volume access before starting recovery. Cover the case where the worker is stale but a web metadata mutation is active.

## Warnings

### WR-01: Malformed metadata JSON produces a 500 instead of a validation response

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/app.py:1855-1859`

**Issue:** `request.get_json(silent=True) or {}` is assumed to be a mapping and is immediately dereferenced with `.keys()`. A valid JSON array/string causes `AttributeError`; scalar values for `display_name` also reach `.strip()` at line 1878. An authenticated UI request with malformed input therefore receives a server error rather than the documented safe validation failure.

**Fix:** Reject non-object payloads before accessing keys and validate field types before normalization, e.g. `if not isinstance(payload, dict): return jsonify({'error': 'JSON object required'}), 400`. Add API tests for `[]`, a JSON string, and a numeric `display_name`.

### WR-02: Invalid integer environment values still crash application import

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/app.py:46-108`

**Issue:** The new `Settings` loader deliberately falls back safely for invalid positive integers, but the compatibility module parses the same deployment settings at import time with raw `int(os.environ[...])`. A malformed `EXPIRE_DAYS`, `METRIC_SAMPLE_SECONDS`, `WORKER_READY_SECONDS`, `DISCOVERY_TIMEOUT_SECONDS`, trigger limit/window, or alert cooldown raises `ValueError` before the worker or web server can start. This contradicts the new configuration boundary and turns a recoverable deployment typo into an outage.

**Fix:** Derive all compatibility constants from one validated `Settings` instance (or use the same guarded positive-integer parser) and add import/startup coverage with invalid values.

---

_Reviewed: 2026-07-31T21:36:40Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
