# Phase 03 — Deferred Items

Out-of-scope discoveries found while executing this phase. Logged, not fixed.

| # | Found during | File | Issue | Why deferred |
|---|--------------|------|-------|--------------|
| 1 | 03-09 Task 2 | `dashboard/advanced.js` (`renderServices` latency cell, `stableServiceSort` latency branch) | A service whose `latency_ms` is `null` renders as `0 ms` and sorts as the fastest service, because `Number(null)` is `0` and therefore passes `Number.isFinite`. The failure class is available on the same row but is never shown. | Pre-existing behaviour in the services table; not caused by, and not in the file regions touched by, plan 03-09's exception-copy or sort-persistence changes. Belongs with the service-table presentation work (03-02/03-04), not with this gap-closure plan. |
