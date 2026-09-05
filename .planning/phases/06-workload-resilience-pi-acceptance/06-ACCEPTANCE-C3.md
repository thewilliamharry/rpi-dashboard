---
phase: 06-workload-resilience-pi-acceptance
kind: acceptance-evidence
build: a33af15
measured: 2026-09-04
criterion: amended (concurrency 3, D-DEBT-06-20)
outcome: failed — one route
---

# OPS-07 gating run under the amended criterion

First acceptance run against the single-operator criterion adopted in `D-DEBT-06-20`.
Supersedes no prior evidence: rounds 3-5's concurrency-8 results stand as recorded.

Build a33af15. Host aarch64/raspi, Pi 5, nproc 4. 2026-09-04.
Admissible: uninstrumented (lock_profile {}, endpoint 404 pre-run), advanced diagnostics ENABLED
(200 pre-run, PROH-DIA-09-01), run_kind acceptance, scenario concurrency 3 / duration 600 /
self_test false.
Dataset: 61,387 -> 61,502 rows. **services = 7** (every prior run had 8 — slightly LESS work
per /api/services request than rounds 3-5, and worth remembering when comparing).

## Result: overall_passed FALSE — one route, missing by 135ms

cadence PASSED | resources PASSED | response_times FAILED
failure_reasons: /api/services: p95 635.6ms exceeds budget 500ms

route                     p50      p95   budget   count
/api/services           577.3    635.6      500    1355   FAIL (+27%)
/api/advanced/current   442.6    482.6     2000    1353   pass
/api/scan-status          7.5    223.3      500    1354   pass
/api/thumbnail/<port>     7.8    237.0     1500    9465   pass
/api/history             17.3     37.9     2000    1353   pass
/api/thumbnail-status     8.5     13.3      750    1353   pass

## Comparison across concurrency, same build family
                      c1 (r5b)   c3 (this)   c8 (r5b)
/api/services p95        300.1       635.6      2917.3
/api/advanced/current    138.6       482.6      3291.9
routes failing               0           1           3

## CONFOUND — record before anyone reads 635.6 as this build's typical number
Worker resource profile is unlike every prior acceptance run:
  this run:     peak_cpu 71.0%   peak_rss 786.9 MB   mean_cpu 1.1%
  rounds 3-5:   peak_cpu  8.9%   peak_rss  54.9 MB   mean_cpu 0.7%
A 14x jump in worker RSS and 8x in peak CPU — almost certainly a Chromium preview job (J6)
running inside the measurement window. It passed the resource assertion (worker limit 1GB) so
nothing gated on it, but it plausibly inflated /api/services.

This does NOT make the run a pass. The run failed and the failure stands. It does mean 635.6ms
may not be representative, and a second run at the same settings would establish whether it is
stable. Do not re-run selectively hoping for a better number — record whatever the second run
gives, both runs, per PROH-OPS-07-01.

## What this bears on
/api/services is now the ONLY failing route, and it is precisely the route D-DEBT-06-19 identifies
as O(stored rows): it rebuilds 168 hourly buckets from ~8,700 raw rows per service per request,
while service_rollups already stores exactly those buckets and is already populated. That work
was shelved as future-proofing when the criterion was amended; this run is the first evidence it
may be load-bearing for OPS-07 rather than merely prudent.

OPS-07 remains Pending. This round does not promote it (PROH-OPS-07-08).

## Reading the p50, which is the part that matters

`/api/services` p50 is **577.3ms** — already above the 500ms budget the criterion applies to p95.
The spread is narrow (577.3 -> 635.6, 10%). A background job competing for CPU inflates a tail; it
does not move a median 77ms above a p95 budget. This is a uniformly slow route, not a route with
occasional slow requests, so the worker confound above most likely explains part of the tail and
none of the median.

Conclusion recorded deliberately: a second run at these settings would probably shave the p95 and
leave the median where it is. The route is structurally over budget at concurrency 3 by roughly 15%
at the median, and `D-DEBT-06-19`'s cost model is the reason.

## The 33x comparison, same run, same Pi, same ten minutes

`/api/history` reads `service_rollups`.  p50 **17.3ms**.
`/api/services` recomputes 168 hourly buckets from raw `service_checks`.  p50 **577.3ms**.

The same underlying data, served two ways, differing by 33x on the same hardware in the same
window. That is the case for the rollup work stated in one line.
