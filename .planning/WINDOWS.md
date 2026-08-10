---
schema_version: 1
open_count: 5
waived_count: 0
fixed_count: 0
total_count: 5
last_updated: 2026-08-10T15:00:53.841Z
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
  }
]
````
