---
phase: 06-workload-resilience-pi-acceptance
kind: acceptance-evidence
build: 82801cb (docs-only ahead of a33af15; no code change)
measured: 2026-09-05
criterion: amended (concurrency 3, D-DEBT-06-20)
outcome: failed — one route
supersedes: nothing; pairs with 06-ACCEPTANCE-C3.md
---

# OPS-07 second gating run — option D, the unconfounded baseline

The run `06-ACCEPTANCE-C3.md` called for and `D-DEBT-06-21` recorded as option D. Committed to
before its result was seen, and recorded whether or not it helped (`PROH-OPS-07-01`).

Host aarch64/raspi. Admissible: uninstrumented (`lock_profile {}`), `run_kind acceptance`,
concurrency 3 / duration 600 / `self_test false`. Job health: no row in state `failed`.
**7 services** — the same shape as run 1 (thumbnail count 8929/1278 = 6.99 per rotation; run 1 was
9465/1355 = 6.98), so the two runs are directly comparable.

## Result: overall_passed FALSE — the same one route, missing by 179ms

cadence PASSED | resources PASSED | response_times FAILED
failure_reasons: `/api/services: p95 679.3ms exceeds budget 500ms`

route                     p50      p95      max   count
/api/services           618.8    679.3    716.0    1278   FAIL (+36%)
/api/advanced/current   468.6    511.6    559.7    1277   pass (budget 2000)
/api/thumbnail/<port>     7.8    247.5    483.2    8929   pass
/api/scan-status          7.5    237.6    456.8    1278   pass
/api/history             17.7     39.8    243.1    1278   pass
/api/thumbnail-status     8.5     12.3    267.1    1278   pass

## The confound is resolved, and it was not the explanation

                        run 1 (2026-09-04)   run 2 (this)   rounds 3-5
worker peak_cpu                      71.0%           9.9%         8.9%
worker peak_rss                    786.9 MB       513.0 MB      54.9 MB
/api/services p95                   635.6ms        679.3ms          n/a

Worker CPU is back in line with every prior acceptance run. The route did **not** improve — it
degraded by 43.7ms p95 and 41.5ms p50. **`/api/services` is structurally over budget at concurrency
3, now established by two independent runs rather than one confounded one.** The margin is 36%, not
the 27% run 1 suggested.

`D-DEBT-06-19`'s underlying claim — this route is the OPS-07 gap — stands. Only its *remediation*
was refuted (`D-DEBT-06-21`).

## Two observations the record did not previously hold

**1. A third distinct worker memory state.** Worker RSS is 513.0 MB peak against 512.9 MB mean —
flat across the whole 600s window, not a spike. That is unlike run 1 (786.9 MB *with* 71% CPU: an
active Chromium preview job) and unlike rounds 3-5 (54.9 MB: no browser resident). It reads as a
Chromium browser held alive between jobs. It passed the 1 GiB worker limit, so nothing gated on it
and no assertion covers it. Not investigated here; recorded so a later reader does not treat
54.9 MB as the only baseline.

**2. Web-tier CPU is 143.5% mean / 164.3% peak** across 593 samples on a 4-core Pi — roughly 1.4
cores sustained. RESOLVED, and it does NOT undercut `06-PROFILE.md`.

The sampled set is `web: n_pids=2 [3356456, 3356517]`, `sampled_set_changed=False` — a gunicorn
master plus one worker, stable for the whole run. A master is effectively idle, so nearly all of
that 143.5% belongs to the single worker process, which runs `--workers 1 --threads 8` behind one
GIL. A single Python process cannot exceed ~100% on bytecode, so roughly 43 points of it is in C
code with the GIL released.

**That is not attributable to `/api/services`.** The run issued **8,929 `/api/thumbnail/<port>`
requests** — each reading an image BLOB out of SQLite, precisely the GIL-released C work that pushes
a process past 100%, and unrelated to the route under investigation. The 143.5% figure is
container-wide across six route families and cannot be apportioned to any one of them.

`06-PROFILE.md` remains the better instrument here: it is route-scoped instrumentation of
`/api/services` itself, where this is a coarse whole-container aggregate. **Option C's target
stands.** Recorded because the raw number invites the opposite conclusion, and a later reader
should find the reasoning rather than repeat it.

The worker's `n_pids=7` (also `changed=False`) is consistent with observation 1 — a resident
Chromium process tree rather than a transient job.

## What this does to option C's arithmetic

C targets `uptime_sweep` (29.975%). Against 679.3ms, removing all of it lands at ~475ms — inside a
500ms budget by 25ms, with **no margin**, and only if the SQL path costs nothing. `06-PREMISE-C.md`
already corrected C's payoff from ~35% to ~30% and found the existing shape is not reusable as-is.

**CORRECTION — do not scope a round against `06-PROFILE.md`'s percentages.** They describe a build
that predates a landed optimization aimed at one of them.

`06-PROFILE.md` is plan 12, created 2026-09-02, profiling a 289.0ms route. The
`maintenance_occurrence_cache` memo that targets `maintenance_coverage` specifically landed in
**06-13** (`4352198`), after that profile, and **survives in HEAD** (`dashboard/app.py:2976`; the
round-5 revert `ea8689e` backed out a different memo, `afff388` on `get_current_diagnosis`).
The 679.3ms measured here therefore **already includes** that win.

Consequence in both directions:

- Scoping a round at "uptime_sweep 29.975% + maintenance_coverage 29.649% = ~60%" **double-counts an
  already-banked optimization**. That arithmetic was proposed in this session and is withdrawn.
- If `maintenance_coverage` is genuinely gone, `uptime_sweep`'s *share* of the remaining cost is
  larger than the profile states — roughly 29.975 / (100 - 29.649) = ~43%, which would put option C
  alone near 390ms with real margin.

Neither figure may be acted on: both are inferences over a stale profile, and the second repeats the
error of the first. **`06-PROFILE.md` must be re-run against the current build before any
optimization round is scoped.** That also answers a question nothing currently does — whether
06-13's memo banked what it was written to bank.
