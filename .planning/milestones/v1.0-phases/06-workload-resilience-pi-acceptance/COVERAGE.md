---
phase: 6
slug: workload-resilience-pi-acceptance
kind: api-coverage-declaration
created: 2026-08-28
detector: node gsd-core/bin/lib/api-coverage.cjs --json
detected: true
matrix_required: false
---

# Phase 6 — API Coverage Declaration

**No external API integration: the phase's only `detected` signal is the phrase "consuming `/api/thumbnail-status`", which is Beacon's own in-process Flask route, not a third-party service.**

## Detector output

```json
{"detected":true,"signals":[{"verb":"consuming","noun":"api","snippet":"…ded-state read at the dashboard layer consuming `/api/thumbnail-status` (or a new small endpoint that c…"}]}
```

## Why no capability matrix

The detector fired on a verb/noun pair (`consuming` + `api`) inside `06-RESEARCH.md` Architecture
Pattern 2. Re-reading the phase scope confirms every surface this phase touches is internal:

| Phase scope item | Surface | External? |
|---|---|---|
| OPS-01 executor lane split | `dashboard/beacon/worker_main.py` — in-process APScheduler executors | No |
| OPS-02 bounded preview retry + degraded state | `dashboard/beacon/queues.py` (SQLite), `dashboard/app.js` reading Beacon's own `/api/services` | No |
| OPS-03 bounded thumbnail store | SQLite `thumbnails` table, Beacon's own `/api/thumbnail/<port>` | No |
| OPS-04 WAL / concurrency / restart | Python stdlib `sqlite3` PRAGMAs against a local file | No |
| OPS-07 Pi-class load acceptance | `requests` against Beacon's own `127.0.0.1` HTTP surface | No |

`06-RESEARCH.md` § Standard Stack states explicitly: **"Installation: None. No new packages this
phase."** No third-party SDK, REST/GraphQL/gRPC client, OAuth flow, webhook receiver, or MCP server
is introduced. Beacon's only outbound HTTP is to operator-configured LAN services through the
already-shipped, already-covered outbound policy (OPS-05, Phase 1 — complete), which this phase does
not modify.

Fabricating INTEGRATE/OPT-OUT matrix rows for Beacon's own internal Flask routes would produce rows
with no external capability surface to reason about. This declaration is the correct output.
