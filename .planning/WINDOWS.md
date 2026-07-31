---
schema_version: 1
open_count: 1
waived_count: 0
fixed_count: 0
total_count: 1
last_updated: 2026-07-31T20:51:51.317Z
---

# Broken Windows Ledger

> Cross-phase defect register. `/gsd-ship` blocks while `open_count > 0`.
> Waive with `gsd-tools windows waive <id> "<reason>"` (reason required).
> Mark fixed with `gsd-tools windows fixed <id>`.

| id | phase | kind | file | line | description | status | reason | recorded_at | resolved_at |
|----|-------|------|------|------|-------------|--------|--------|-------------|-------------|
| 1 | 01 | deviation | dashboard/app.py |  | Compatibility adapter required direct outbound-policy integration until staged extraction completes. | open |  | 2026-07-31T20:51:51.317Z |  |

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
  }
]
````
