---
schema_version: 1
open_count: 8
waived_count: 0
fixed_count: 4
total_count: 12
last_updated: 2026-08-14T19:05:14.014Z
---

# Broken Windows Ledger

> Cross-phase defect register. `/gsd-ship` blocks while `open_count > 0`.
> Waive with `gsd-tools windows waive <id> "<reason>"` (reason required).
> Mark fixed with `gsd-tools windows fixed <id>`.

| id | phase | kind | file | line | description | status | reason | recorded_at | resolved_at |
|----|-------|------|------|------|-------------|--------|--------|-------------|-------------|
| 1 | 01 | deviation | dashboard/app.py |  | Compatibility adapter required direct outbound-policy integration until staged extraction completes. | open |  | 2026-07-31T20:51:51.317Z |  |
| 2 | 01 | deviation | dashboard/beacon/recovery.py |  | Verified intermediate automatic migration backups require catalog transition validation for restore --latest. | open |  | 2026-07-31T21:01:33.290Z |  |
| 3 | 01 | deviation | dashboard/beacon/recovery.py |  | Staging I/O errors are redacted as fixed recovery failures. | open |  | 2026-07-31T21:01:33.357Z |  |
| 4 | 01 | deviation | tests/test_outbound_policy.py |  | Added real Chromium main-frame, subresource, and CONNECT/SNI tests as required browser-boundary evidence. | open |  | 2026-08-01T06:46:19.283Z |  |
| 5 | 02 | deviation | tests/worker_ownership_contract.py |  | Added runtime_state to the frozen database-surface universe after inventory verification. | open |  | 2026-08-10T15:00:53.841Z |  |
| 6 | 02 | deviation | dashboard/beacon/migrations.py |  | Added latency_sample_count migration to preserve exact cross-tier latency averages. | fixed |  | 2026-08-10T15:24:57.532Z | 2026-08-10T15:25:37.783Z |
| 7 | 02 | deviation | dashboard/beacon/repositories.py |  | Corrected raw-host timestamp and service display-bucket query details. | fixed |  | 2026-08-10T15:24:57.593Z | 2026-08-10T15:25:37.844Z |
| 8 | 02 | deviation | dashboard/beacon/support_floor.json |  | Advanced migration support-floor metadata for additive migration 6. | fixed |  | 2026-08-10T15:24:57.655Z | 2026-08-10T15:25:37.905Z |
| 9 | 03 | unrun-verify | .planning/phases/03-advanced-current-diagnosis/03-04-SUMMARY.md |  | Raspberry Pi-class 15-minute refresh/load observation remains manual target-hardware validation | open |  | 2026-08-14T11:25:44.416Z |  |
| 10 | 03 | deviation | tests/test_advanced_diagnosis_api.py |  | Corrected the exact-cap fixture to use the schema-valid collection_gap reason. | fixed |  | 2026-08-14T15:25:01.736Z | 2026-08-14T15:25:18.072Z |
| 11 | 03 | deviation | .planning/phases/03-advanced-current-diagnosis/03-06-SUMMARY.md |  | Operator-approved combined 6/11/20-minute samples replace exact pre-start/midpoint/end timing after corrected host-port command. | open |  | 2026-08-14T19:05:13.868Z |  |
| 12 | 03 | deviation | .planning/phases/03-advanced-current-diagnosis/03-06-SUMMARY.md |  | Docker cgroup memory was unavailable (0B); recorded host-process RSS as the explicit RAM fallback. | open |  | 2026-08-14T19:05:14.014Z |  |

````json
[
  {
    "id": 1,
    "kind": "deviation",
    "phase": "01",
    "file": "dashboard/app.py",
    "line": null,
    "description": "Compatibility adapter required direct outbound-policy integration until staged extraction completes.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-07-31T20:51:51.317Z",
    "resolved_at": null
  },
  {
    "id": 2,
    "kind": "deviation",
    "phase": "01",
    "file": "dashboard/beacon/recovery.py",
    "line": null,
    "description": "Verified intermediate automatic migration backups require catalog transition validation for restore --latest.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-07-31T21:01:33.290Z",
    "resolved_at": null
  },
  {
    "id": 3,
    "kind": "deviation",
    "phase": "01",
    "file": "dashboard/beacon/recovery.py",
    "line": null,
    "description": "Staging I/O errors are redacted as fixed recovery failures.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-07-31T21:01:33.357Z",
    "resolved_at": null
  },
  {
    "id": 4,
    "kind": "deviation",
    "phase": "01",
    "file": "tests/test_outbound_policy.py",
    "line": null,
    "description": "Added real Chromium main-frame, subresource, and CONNECT/SNI tests as required browser-boundary evidence.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-01T06:46:19.283Z",
    "resolved_at": null
  },
  {
    "id": 5,
    "kind": "deviation",
    "phase": "02",
    "file": "tests/worker_ownership_contract.py",
    "line": null,
    "description": "Added runtime_state to the frozen database-surface universe after inventory verification.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-10T15:00:53.841Z",
    "resolved_at": null
  },
  {
    "id": 6,
    "kind": "deviation",
    "phase": "02",
    "file": "dashboard/beacon/migrations.py",
    "line": null,
    "description": "Added latency_sample_count migration to preserve exact cross-tier latency averages.",
    "status": "fixed",
    "reason": "",
    "recorded_at": "2026-08-10T15:24:57.532Z",
    "resolved_at": "2026-08-10T15:25:37.783Z"
  },
  {
    "id": 7,
    "kind": "deviation",
    "phase": "02",
    "file": "dashboard/beacon/repositories.py",
    "line": null,
    "description": "Corrected raw-host timestamp and service display-bucket query details.",
    "status": "fixed",
    "reason": "",
    "recorded_at": "2026-08-10T15:24:57.593Z",
    "resolved_at": "2026-08-10T15:25:37.844Z"
  },
  {
    "id": 8,
    "kind": "deviation",
    "phase": "02",
    "file": "dashboard/beacon/support_floor.json",
    "line": null,
    "description": "Advanced migration support-floor metadata for additive migration 6.",
    "status": "fixed",
    "reason": "",
    "recorded_at": "2026-08-10T15:24:57.655Z",
    "resolved_at": "2026-08-10T15:25:37.905Z"
  },
  {
    "id": 9,
    "kind": "unrun-verify",
    "phase": "03",
    "file": ".planning/phases/03-advanced-current-diagnosis/03-04-SUMMARY.md",
    "line": null,
    "description": "Raspberry Pi-class 15-minute refresh/load observation remains manual target-hardware validation",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-14T11:25:44.416Z",
    "resolved_at": null
  },
  {
    "id": 10,
    "kind": "deviation",
    "phase": "03",
    "file": "tests/test_advanced_diagnosis_api.py",
    "line": null,
    "description": "Corrected the exact-cap fixture to use the schema-valid collection_gap reason.",
    "status": "fixed",
    "reason": "",
    "recorded_at": "2026-08-14T15:25:01.736Z",
    "resolved_at": "2026-08-14T15:25:18.072Z"
  },
  {
    "id": 11,
    "kind": "deviation",
    "phase": "03",
    "file": ".planning/phases/03-advanced-current-diagnosis/03-06-SUMMARY.md",
    "line": null,
    "description": "Operator-approved combined 6/11/20-minute samples replace exact pre-start/midpoint/end timing after corrected host-port command.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-14T19:05:13.868Z",
    "resolved_at": null
  },
  {
    "id": 12,
    "kind": "deviation",
    "phase": "03",
    "file": ".planning/phases/03-advanced-current-diagnosis/03-06-SUMMARY.md",
    "line": null,
    "description": "Docker cgroup memory was unavailable (0B); recorded host-process RSS as the explicit RAM fallback.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-14T19:05:14.014Z",
    "resolved_at": null
  }
]
````
