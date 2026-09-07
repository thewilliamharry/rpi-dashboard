---
phase: 6
slug: workload-resilience-pi-acceptance
kind: hardware-evidence
created: 2026-09-02
---

# Third Raspberry Pi acceptance run — round 3

> Durable record of the two hardware reports Task 1 of `06-14-PLAN.md` produced, so a later reader
> is not dependent on chat history for the figures `06-DEBT.md`'s round-3 updates cite. Performed on
> real hardware by the operator (this plan's blocking `checkpoint:human-verify` was not automatable —
> `PROH-OPS-07-02`). **The acceptance pass FAILED.** `overall_passed: false`.

## Build under test

Pi `git log --oneline -1` = `b8ed60b`, matching `origin/main`. Both `beacon-web` and `beacon-worker`
up. Host: `aarch64` / `raspi`, Raspberry Pi 5 Model B Rev 1.0, `nproc` = 4. No budget in
`tests/pi_load_acceptance.py` was edited (`PROH-OPS-07-01` intact).

## Control pass — `beacon-control-c1-round3.json` — concurrency 1, 120s — `overall_passed: true`

| route | p50 ms | p95 ms | max ms | count |
|---|---:|---:|---:|---:|
| /api/services | 209.355 | 227.436 | 357.863 | 348 |
| /api/advanced/current | 82.281 | 107.196 | 159.240 | 347 |
| /api/history | 11.962 | 14.438 | 38.607 | 347 |
| /api/scan-status | 3.281 | 4.198 | 13.937 | 347 |
| /api/thumbnail-status | 4.235 | 5.395 | 12.056 | 347 |
| /api/thumbnail/<port> | 3.425 | 4.373 | 10.639 | 2776 |

`/api/services` p50: 289.0ms (round 2) → 209.355ms (round 3), a 27.6% reduction attributable to
`06-13`'s `reduce-request-cost` fix. `/api/advanced/current` at 82.281ms vs. round 2's 80.7ms —
essentially unchanged, as expected, since `06-13` did not touch it.

## Acceptance pass — `beacon-acceptance-round3.json` — concurrency 8, 600s — `overall_passed: FALSE`

`run_kind: acceptance`. `scenario`: `duration_seconds` 600, `concurrency` 8, `self_test` false —
unchanged from the failing round-2 run (`PROH-OPS-07-10` intact).

`failure_reasons`:
- `/api/services: p95 1732.3ms exceeds budget 500ms`
- `/api/scan-status: p95 656.5ms exceeds budget 500ms`
- `/api/advanced/current: p95 2382.2ms exceeds budget 2000ms`

| route | p50 ms | p95 ms | max ms | count |
|---|---:|---:|---:|---:|
| /api/services | 1228.811 | 1732.260 | 2856.046 | 1020 |
| /api/advanced/current | 1037.461 | 2382.219 | 3045.340 | 1017 |
| /api/scan-status | 242.614 | 656.483 | 1432.669 | 1017 |
| /api/history | 48.387 | 335.707 | 1753.851 | 1017 |
| /api/thumbnail-status | 22.041 | 35.715 | 1753.932 | 1017 |
| /api/thumbnail/<port> | 25.852 | 1402.228 | 2856.307 | 8111 |

Round-2 → round-3 p95 comparison: `/api/services` 2465.9 → 1732.3ms (−29.7%); `/api/scan-status`
1797.4 → 656.5ms (−63.5%); `/api/advanced/current` 2742.1 → 2382.2ms (−13.1%).

**Degradation factor, control p50 → acceptance p50 (round 3):** `/api/scan-status` **74x**
(3.281 → 242.614ms); `/api/advanced/current` 12.6x; `/api/thumbnail/<port>` 7.5x; `/api/services`
5.9x; `/api/thumbnail-status` 5.2x; `/api/history` 4.0x.

## Cadence — `assertions.cadence`

**`passed: true`, `failures: []`** — J1-J4 never stale. OPS-01 holds again on this run.

## Resources — `assertions.resources`

**`passed: true`**
- worker rss 54,919,168 B against limit 1,073,741,824 B — passed
- web rss 124,928,000 B against limit 268,435,456 B — passed
- `resource_targets`: both resolved by `docker_container_tree`. web `beacon-web` root_pid 1947963,
  sampled_pids `[1947963, 1948029]`, `sampled_set_changed: false`. worker `beacon-worker` root_pid
  1947970, sampled_pids `[1947970]`, `sampled_set_changed: false`.

## CPU sampling — `cpu_sampling` — the first real measurement this phase has produced

- **web:** `all_samples_zero: false`, `nonzero_sample_count: 594`, `zero_sample_count: 0`,
  `primed_pid_count: 2`, `handle_cache: "per_pid_run_lifetime"`. **mean_cpu_percent 165.504,
  peak_cpu_percent 233.6.** mean_rss 123,869,521 B, peak_rss 124,928,000 B, sample_count 594.
- **worker:** `all_samples_zero: false`, `nonzero_sample_count: 309`, `zero_sample_count: 285`,
  `primed_pid_count: 1`. mean_cpu_percent 0.698, peak_cpu_percent 8.9. mean_rss 54,876,856 B.

## Environmental fact surfaced by this round's build output

`docker compose up` emitted, for `migrate`, `web` and `worker`: "Your kernel does not support memory
limit capabilities or the cgroup is not mounted. Limitation discarded." **`mem_limit` is declared in
`docker-compose.yml` but NOT kernel-enforced on this host.** `tests/pi_load_acceptance.py`'s
`assert_resource_budget` parses the declared value out of `docker-compose.yml`, so the assertion
above remains a meaningful budget check and stays comparable across rounds — but the deployment
itself is not actually protected by it; a container exceeding its declared limit gets memory
pressure, not an OOM kill. This bears on `06-DEBT.md`'s `D-DEBT-06-07` `mem_limit` arithmetic.

## What this run does and does not establish

Per-request cost is no longer the dominant problem: the control pass passes cleanly on every route,
and `/api/services`'s control p50 improved 27.6% over round 2, attributable to `06-13`. But a 3.281ms
route (`/api/scan-status`) degrades 74x under concurrency 8 while the host has roughly 2.3 of 4 cores
idle (web mean_cpu_percent 165.504 of 400 available) — eight clients on four cores cannot make a 3ms
computation take 243ms on serialization grounds alone; the bottleneck is serialization, not
computation. The mechanism is now **measured to be serialization** but is **not yet attributed** to a
specific cause. `D-DEBT-06-01`'s own second reopening test — the unlocked `/api/advanced/current`
recovering while the locked routes stay over budget — did **not** fire: `/api/advanced/current`
improved only 13.1% and remains over its own 2000ms budget at 2382.2ms p95. `_db_lock` is therefore
**not** newly implicated by this run. The 165.504% mean CPU figure (a single Python process exceeding
one core) also shows real parallelism is occurring — SQLite's C code releases the GIL — so the
classic GIL-saturation signature (a hard pin near 100%) is not what this run shows; the
one-interpreter hypothesis is weakened, not confirmed, and not eliminated. The next round is a
diagnostic one, by the user's explicit choice, rather than a third inferred fix.
