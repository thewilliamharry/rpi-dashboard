---
phase: 06-workload-resilience-pi-acceptance
plan: 21
kind: hardware-evidence
created: 2026-09-03
---

# Round 5 attribution point 1 — real Raspberry Pi hardware, post-narrowing, instrumented

> Durable record of the two instrumented hardware passes Task 1 of `06-21-PLAN.md` produced, so a
> later reader is not dependent on chat history for the figures this artifact's verdict and
> `06-DEBT.md`'s round-5 updates cite. Performed on real hardware by the operator (this plan's
> blocking `checkpoint:human-verify`; `PROH-OPS-07-02`). **The measured result is a system
> regression under load. It is stated plainly below, not softened.**

## Provenance

| Field | Value |
|---|---|
| Pi `git log --oneline -1` | `cc87995` (matches `origin/main` HEAD under test; contains `06-20`'s narrowing) |
| Host | `aarch64` / `raspi`, Raspberry Pi 5, `nproc` = 4 |
| Endpoint pre-check | `enabled: true`, `schema_version: 2` — confirmed live before either pass |
| Endpoint post-check | `404` — confirmed restored after both passes (Step 7) |
| Control pass scenario | concurrency 1, duration 120s, `--lock-profile` |
| Acceptance-shape pass scenario | concurrency 8, duration 600s, `--lock-profile` |
| `service_checks` row count, before (step 3) | 57,944 |
| `service_checks` row count, after (step 6) | 58,000 |
| Row growth across this session's ~13-minute window | 56 rows (+0.097%) — not explanatory of anything below |
| Row count vs round 4's 56,828 (before this session) | 58,000 / 56,828 = 1.0206x — **+2.06% growth since round 4**, not the 2.24x jump round 3→round 4 carried |

**This is diagnostic evidence, not OPS-07 acceptance evidence.** Both passes ran with
`BEACON_LOCK_PROFILE=1` — an instrumented build — and `PROH-OPS-07-11` states plainly that an
instrumented run is never OPS-07 evidence, whichever way its numbers fall. `PROH-OPS-07-08` holds:
OPS-07 is not promoted by this round, and `.planning/REQUIREMENTS.md` is unedited by this artifact
(`git diff --quiet -- .planning/REQUIREMENTS.md`).

**`PROH-OPS-07-11` applies with extra force here, in the direction that matters least ambiguously:**
both passes are diagnostic regardless of outcome, and this round's outcome is a measured regression
— an instrumented build showing worse numbers is exactly as non-authoritative as one showing better
numbers.

---

## In-situ overhead check

The instrumented control pass's `/api/services` p50 measured **285.3ms**
(`route_latencies_ms['/api/services'].p50`, `beacon-r5a-c1.json`). Round 4's instrumented control
p50 was **257.6ms** (`06-LOCK-DIAGNOSTIC.md` Provenance) — the like-for-like, instrumented-to-
instrumented comparison. The gap is `(285.3 − 257.6) / 257.6 = 10.75%` — smaller than round 4's own
23.05% gap against round 3, and inside the 15% band that check calibrates against were it evaluated
against round 4 rather than round 3. Round 3's uninstrumented control p50 (`06-ACCEPTANCE-ROUND3.md`)
was **209.355ms**, noted here as before with the caveat that it is not like-for-like against an
instrumented build.

**This 10.75% rise at zero contention is itself worth flagging, not discarding.** The dataset grew
only 2.06% since round 4 — nowhere near enough to explain a 10.75% p50 increase on its own. The
narrowing's own required change (`PROH-OPS-04-06`/`T-06-102`, `06-20-SUMMARY.md`) is that every row
consumed after the lock closes is now materialized into a plain dict *inside* the lock first — a
small, real, uncontended-cost addition that this figure is the first hardware evidence to reflect.
The figure is recorded, not discarded, per this check's own instruction.

---

## Section 1 — the held region's composition

**The narrowing did what it was built to do, on both passes, measured directly.**

| Pass | connect / sql / python split (`lock_profile.routes['/api/services']`) | Python share | Round 4 same-pass split |
|---|---|---:|---|
| Control (c1) | `.001 / .645 / .353` | **0.3532** (`services_python_share_below_refutation_threshold`, `beacon-r5a-c1.json`) | `.001 / .423 / .576` |
| Loaded (c8) | `.044 / .844 / .112` | **0.1118** (`services_python_share_at_or_below_confirmation_threshold`, `beacon-r5a-c8.json`) | `.002 / .748 / .250` |

Python share of the held region fell from `.576 → .353` at concurrency 1 (a 38.7% relative
reduction) and from `.250 → .112` under load (a 55.2% relative reduction). Both are real, measured
reductions in the fraction of the critical section spent on Python work — the mechanism the
narrowing targeted moved, and moved by more than half under load.

**`clamped_python_count` is 0 on both passes** (`beacon-r5a-c1.json`, `beacon-r5a-c8.json`). The
derived `python_share` remainder is trustworthy on both passes, per `D-DEBT-06-10`'s own lesson
about a summing identity that can survive a corrupted remainder — the zero clamp count is the
mutation-verified signal that did not fire here.

---

## Section 2 — hold and utilisation

**Same-run figures, c8 (source: `beacon-r5a-c8.json`).**

- `total_hold_ns = 583,472,152,134ns`
- `window_ns = 602,010,575,569ns`
- `utilisation = 583,472,152,134 / 602,010,575,569 = 0.9692`
- `scan_status_median_hold_near_zero`: `/api/scan-status`'s hold median measured **3,415,058ns**
  (3.415ms).
- `services_hold_dominates_scan_status_hold`: ratio measured **180.76** against the 20.0 floor —
  **HELD**, comfortably above the floor.

**Derived, not directly reported — `/api/services`' own hold median, back-calculated from the two
figures above** (`180.76 × 3,415,058ns ≈ 617,306,000ns`, ≈617.3ms). This is arithmetic over two
named report fields, not a third field on its own; it is presented as derived so it is not mistaken
for a value the report states directly. Round 4's equivalent figure (`06-LOCK-DIAGNOSTIC.md` §Missing
item 1) was **596,245,129ns** (596.245ms) — this round's derived figure is **≈+3.5% higher**, not
lower, despite the Python share collapsing from 25.0% to 11.2% of the same hold.

**This is the central, load-bearing measurement of this artifact: `/api/services`' hold got
*longer*, not shorter, even as the work moved out of it.** The `sql_share` component rose from
`.748 → .844` (Section 1's table) while the hold's own duration stayed flat-to-up — the SQL
execution still running *inside* the lock got absolutely slower under this pass, consistent with
that SQL now competing for the GIL against the composition work that used to be serialized behind
it and now runs concurrently instead.

**Compared against the 0.745–0.82 estimate range (`D-DEBT-06-15`), arithmetic shown:**

- Estimate's predicted new total hold, low end (0.745 utilisation): `0.745 × 602,010,575.569ms(window in ms, i.e. 602,010.575569ms) ≈ 448,497.88ms`.
- Estimate's predicted new total hold, high end (0.82 utilisation): `0.82 × 602,010.575569ms ≈ 493,648.67ms`.
- **Measured total hold: 583,472.152134ms** — `+89,823.48ms` (+18.2%) above the high end of the
  estimated range, `+134,974.27ms` (+30.1%) above the low end.
- **Measured utilisation: 0.9692** — above both the 0.85 superlinear threshold the estimate itself
  used as its safety margin and above the 0.82 upper bound of the estimate range.
- **The estimate did not merely fall short of its target — total hold rose relative to round 4's own
  pre-narrowing baseline** (578,783,964,515ns → 583,472,152,134ns, +4,688,187,619ns, **+0.81%**),
  the opposite direction the estimate predicted (a ~15% *reduction*).

**Which of the estimate's two stated assumptions the measurement implicates.** `06-LOCK-DIAGNOSTIC.md`
§4 named two assumptions the 0.745–0.82 range rested on: (1) the 25% Python cut translates linearly
into hold-time reduction, and (2) all other routes' behavior holds constant. **Both are falsified by
this run, and the mechanism that falsifies them is the same one:**

1. **Assumption 1 is falsified directly.** A linear translation of the measured Python-share cut
   (25.0% → 11.2% under load, i.e. roughly the predicted magnitude of cut) predicts `/api/services`'
   own hold falling to roughly `596.245ms × 0.75 ≈ 447.2ms`. The measured hold instead *rose* to
   ≈617.3ms. The cut in Python's *share* of the hold did not translate into a cut in the hold's
   *absolute duration* at all — the SQL portion inside the lock absorbed the difference and then
   some.
2. **Assumption 2 is falsified directly.** `/api/advanced/current` — untouched by this narrowing,
   takes no lock — had its `other_off_cpu_ns_total` nearly double (Section 4). `/api/scan-status`'s
   own hold rose 34.9% (2,531,729ns → 3,415,058ns) and its lock-wait share and absolute wait both
   rose (Section 3). No route's behavior held constant.

Both falsifications trace to one mechanism, stated as the well-supported hypothesis it is: work
released from `_db_lock` now runs concurrently with everything else and contends for the GIL rather
than being serialized behind the lock. That contention slows down the SQL execution still inside the
lock (assumption 1's failure) and slows down every other CPU-bound route running at the same time
(assumption 2's failure). Lock contention was converted into GIL contention on this single-
interpreter deployment.

**A genuine, uncontended-load improvement worth stating alongside the loaded-pass regression.** At
concurrency 1 (no contention to convert into GIL contention), utilisation fell from **0.6653 to
0.4339** (`beacon-r5a-c1.json` vs `06-LOCK-DIAGNOSTIC.md`'s round-4 c1 figure) — a genuine 34.8%
reduction, the narrowing working exactly as designed when there is no queue for the freed time to
be reabsorbed into. **The estimate's failure is specific to load, not to the mechanism it targeted.**

---

## Section 3 — the queueing consequence

`/api/scan-status`'s lock-wait share of wall, c8: `453,401.2ms / 456,464.1ms = 0.9933`
(`scan_status_lock_wait_share_of_wall`, `beacon-r5a-c8.json`) — **up from round 4's 0.9902**
(99.0%), both essentially total. This is the route whose 74x round-3 degradation motivated the whole
attribution; its lock-wait share did not recover — if anything it inched up.

**Wall-clock consequence, c8.** `/api/scan-status`' p95 rose to **1,563.9ms** against its 500ms
budget (round 4: 853.0ms — a +83.3% increase). Mean wall per request:
`456,464.1ms / 784 = 582.2ms` (round 4: `272,392.5ms / 880 = 309.5ms`) — nearly double. Throughput
also fell: 880 → 784 completions in the same 600s window (round 4 → round 5), a route-level signature
matching `/api/services`' own throughput drop below.

**Control-pass value, this run.** `/api/scan-status`'s c1 p50/p95 measured **3.4/4.8ms**
(essentially unchanged from round 4's 3.4/4.2ms) — confirming, as expected, that this route's own
uncontended cost was never the problem; its degradation under load is entirely a queueing
consequence of `_db_lock`, and that queueing consequence is *worse*, not better, after the narrowing.

**This is the outcome the narrowing was for, and it did not recover.** `/api/scan-status` waits
behind `/api/services`' held lock essentially unchanged in mechanism and now measurably longer in
duration, because `/api/services`' own hold did not shrink (Section 2) — it grew.

---

## Section 4 — what the narrowing could not touch

`/api/advanced/current` takes **no lock** and was **not modified** by `06-20`'s narrowing.
Its full request accounting, c8 (`beacon-r5a-c8.json`, `requests['/api/advanced/current']`):

| Field | Round 5 (measured) | Round 4 |
|---|---:|---:|
| `n` | 784 | 882 |
| `wall_ns_total` | 1,579,129.8ms | 1,087,221.5ms |
| `cpu_ns_total` | 571,721.4ms | 536,241.0ms |
| `lock_wait_ns_total` | **0.0ms** | 0.0ms |
| `other_off_cpu_ns_total` | 1,007,408.3ms | 550,980.5ms |

`lock_wait_ns_total` is confirmed still exactly zero across all 784 requests — this route cannot be
touched by a lock it never takes, and this pass confirms that construction held.

**This route's off-lock, off-CPU time nearly doubled: 550,980.5ms → 1,007,408.3ms (+82.9%), despite
this route's own code being untouched by `06-20`.** Per-request: mean wall
`1,579,129.8 / 784 = 2,014.2ms` (round 4: `1,087,221.5 / 882 = 1,232.7ms`, +63.4%); mean CPU
`571,721.4 / 784 = 729.2ms` (round 4: `536,241.0 / 882 = 608.0ms`, +19.9%); mean other-off-CPU
`1,007,408.3 / 784 = 1,285.0ms` (round 4: `550,980.5 / 882 = 624.7ms`, **+105.7%**, genuinely
doubled). p95 rose from 2217.6ms to **2,799.3ms** against the unchanged 2000ms budget.

**This is the smoking gun for the GIL-contention mechanism, restated as evidence rather than
hypothesis.** A route that takes no lock, whose code did not change, saw its off-CPU time roughly
double in the identical pass in which the narrowing released `/api/services`' Python work to run
concurrently instead of serialized behind a lock. The only thing that changed in this route's
environment is what else is now runnable at the same time.

**Aggregate CPU across all routes, as a fraction of the Pi's four cores.** Summing every route's
`cpu_ns_total` from the c8 request-accounting table below: `571,721.4 + 330,587.8 + 12,207.1 +
1,594.5 + 29,710.5 + 2,286.5 + 109.4 = 948,217.2ms` total CPU time inside a `602,010.575569ms`
window — `948,217.2 / 602,010.575569 = 1.575` core-equivalents, **39.4% of the Pi's four cores**.
This is essentially unchanged from round 4's own estimate of roughly 942s of request CPU in a 600s
window (~1.57 cores, ~39.3% of four cores, `06-22-PLAN.md`'s objective). **Total requested CPU work
stayed flat while wall-clock and off-CPU time exploded** — the same total amount of work is taking
much longer to run, which is exactly the signature of increased scheduling contention rather than
increased work.

**`cpu_sampling` process-level figures (`mean_cpu_percent`, `peak_cpu_percent`) for the web and
worker roles were not captured in the operator's Task-1 transcript this artifact is compiled from.**
Per `06-LOCK-DIAGNOSTIC.md`'s own precedent for the same gap in round 4, this is recorded as missing
rather than inferred or assumed unchanged; a future reader wanting these figures must read them
directly from `beacon-r5a-c1.json` / `beacon-r5a-c8.json`'s `cpu_sampling` block on the Pi host, or
have a future round commit that block into a durable artifact.

### Decisive request-accounting table, concurrency-8 (source: `beacon-r5a-c8.json`, `requests[*]`; round 4 in parens)

| route | n | wall (ms) | cpu (ms) | lock_wait (ms) | other (ms) |
|---|---:|---:|---:|---:|---:|
| `/api/advanced/current` | 784 (882) | 1,579,129.8 (1,087,221.5) | 571,721.4 (536,241.0) | 0.0 (0.0) | 1,007,408.3 (550,980.5) |
| `/api/services` | 784 (882) | 1,490,711.6 (1,232,421.9) | 330,587.8 (365,245.9) | 903,325.4 (695,573.4) | 256,798.4 (171,602.6) |
| `/api/thumbnail/<port>` | 6,217 (7,007) | 1,026,242.8 (2,042,381.5) | 12,207.1 (n/a) | 984,592.1 (2,021,760.3) | 29,444.6 (n/a) |
| `/api/scan-status` | 784 (880) | 456,464.1 (272,392.5) | 1,594.5 (n/a) | 453,401.2 (269,736.4) | 1,468.4 (n/a) |
| `/api/history` | 784 (880) | 130,966.6 (86,896.3) | 29,710.5 (n/a) | 76,123.3 (51,916.1) | 25,132.7 (n/a) |
| `/api/thumbnail-status` | 784 (880) | 24,986.1 (22,937.3) | 2,286.5 (n/a) | 22,032.4 (19,579.4) | 667.3 (n/a) |
| `/healthz` | 49 (54) | 70,566.4 (25,562.3) | 109.4 (n/a) | 65,315.6 (25,432.7) | 5,141.3 (n/a) |

`/api/services`' own throughput fell 882 → 784 acquisitions (**−11.1%**) on **fewer** completions
while its lock-wait total rose (695,573.4ms → 903,325.4ms) — more waiting per request, on fewer
requests served, in the same 600s window.

**One improvement, stated plainly.** `/api/thumbnail/<port>` dropped out of the failure list
entirely this pass: p95 **1,023.0ms** against its 1500ms budget (round 4: **1,695.6ms**, over
budget). Its `lock_wait_ns_total` roughly halved: 2,021,760.3ms → 984,592.1ms. Round 4 had four
failing routes; round 5 has three.

---

## Section 5 — the narrowing-outcome verdict

**Transcribed verbatim from `narrowing_outcome` (`tests/pi_load_acceptance.py::evaluate_narrowing_outcome`).**

### Control pass (c1) — verdict **REFUTED**

`beacon-r5a-c1.json`, `narrowing_outcome.reason`: `/api/services`' python_share is 0.3532, at or
above the 0.2 refutation threshold — the narrowing did not move the Python-side work out of the
critical section (as measured **at concurrency 1, uncontended**).

| name | measured | threshold | held |
|---|---|---|---|
| `services_python_share_below_refutation_threshold` | 0.3532 | 0.2 | **FAILED** |

**This is not softened.** Read at concurrency 1 alone, the verdict is a flat refutation — 35.3%
Python share is well above the 20% line the harness set as the point below which "the narrowing did
something" can even be entertained. The narrowing's real, measured effect on this pass (a 38.7%
relative reduction from round 4's 57.6%) is not disputed; it is simply not enough to clear the
threshold this prediction set before the change was made.

### Loaded pass (c8) — verdict **INCONCLUSIVE**

`beacon-r5a-c8.json`, `narrowing_outcome.reason`: the refutation condition did not hold, but not
every confirmation prediction did either.

| name | measured | threshold | held |
|---|---|---|---|
| `services_python_share_below_refutation_threshold` | 0.1118 | 0.2 | **HELD** |
| `services_python_share_at_or_below_confirmation_threshold` | 0.1118 | 0.1 | **FAILED** |
| `services_sql_share_at_or_above_confirmation_threshold` | 0.8442 | 0.85 | **FAILED** |
| `utilisation_below_max_after_narrowing` | 0.9692 | 0.85 | **FAILED** |

**This is not softened either.** The refutation condition — the harness's minimum bar for "the
narrowing did something measurable" — did not fire under load: 11.2% Python share is inside the
threshold that would call the whole effort a refutation. But every one of the three confirmation
predictions failed, including the decisive `utilisation_below_max_after_narrowing` check, by a wide
margin (0.9692 against a 0.85 ceiling — 14.0 percentage points over, not a near-miss). **INCONCLUSIVE
here means "the narrowing moved the needle it was built to move, and the system is not better for
it" — not "undetermined."**

### The attribution verdict, for comparison (`evaluate_lock_attribution`)

- **c1:** `attribution.verdict = INCONCLUSIVE` — no route degraded slowly enough at concurrency 1 for
  the attribution checks to have anything to explain; this is expected shape for a control pass, not
  a finding.
- **c8:** all five `evaluate_lock_attribution` checks **HELD** —
  `scan_status_lock_wait_share_of_wall` (0.9933 vs 0.5), `scan_status_median_hold_near_zero`
  (3,415,058ns vs 5,000,000ns), `services_hold_dominates_scan_status_hold` (180.76 vs 20.0),
  `scan_status_wait_tracks_services_hold` (0.9368 vs 0.5), `utilisation_above_superlinear_threshold`
  (0.9692 vs 0.85). Round 4's equivalent run held 4 of 5 (INCONCLUSIVE). **This run holds 5 of 5 —
  the lock-serialization attribution reads more strongly confirmed after the narrowing than before
  it,** because `/api/services`' own hold did not shrink (Section 2) and `/api/scan-status`'s wait
  therefore did not either (Section 3). **A post-fix run reading the attribution as no longer
  strongly confirmed would have been the fix working; that is not what this run shows** — the lock
  is measured to be exactly as dominant a serializer as it was before the narrowing, on a hold that
  is if anything slightly larger.

**Neither verdict is an OPS-07 oracle** (`PROH-OPS-07-12`, `PROH-OPS-07-13`) — both are diagnostic
readings over an instrumented build, computed the same way regardless of which direction the numbers
fall.

---

## Section 6 — OPS-01 and resources

`assertions.cadence.passed` is **`true` on both passes** (`beacon-r5a-c1.json`,
`beacon-r5a-c8.json`) — J1–J4 did not go `stale` on either run. **OPS-01 has not regressed.** This is
now confirmed on five hardware runs (round 2's `06-10`, round 3's `06-14`, round 4's two `06-18`
passes, and this round's two `06-21` passes).

**Resource summary.** `clamped_python_count` is 0 on both passes (Section 1). `clamped_off_cpu_count`
is **1** on the c1 pass and **57** on the c8 pass. Total c8 requests across all routes sum to
`784 × 5 + 6,217 + 49 = 10,186`; `57 / 10,186 ≈ 0.56%` — consistent with `D-DEBT-06-13`'s documented
1–3% developer-machine characterisation of this clock-comparison artifact, reproducing on real
hardware at the low end of that range and not itself evidence of a defect. `route_overflow` is
`false` on both passes. Process-level `cpu_sampling` (`mean_cpu_percent`, `peak_cpu_percent`, RSS)
for the web and worker roles was not captured in the operator's transcript — recorded as missing,
per this section's opening note in Section 4, rather than assumed unchanged from round 4.

---

## Provenance guard, restated

`git diff --quiet -- .planning/REQUIREMENTS.md` — holds; this artifact and its plan do not edit
`.planning/REQUIREMENTS.md`. `git diff --quiet -- dashboard/` — holds; this plan writes no code.
Both hardware passes were instrumented (`BEACON_LOCK_PROFILE=1`) and are diagnostic evidence only
(`PROH-OPS-07-11`); OPS-07 stays Pending. The Pi's diagnostic endpoint returned `404` after Step 7,
confirming the deployment ends this plan uninstrumented.

## Summary of what this artifact establishes

**Establishes:** the narrowing moved the Python-share of `/api/services`' held region substantially
in both passes (measured, not inferred), and at concurrency 1 that translated into a genuine 34.8%
utilisation reduction. Under load (concurrency 8), the same held-region composition shift did **not**
translate into a smaller hold, a smaller total-hold figure, or a lower utilisation — all three moved
in the wrong direction relative to both the pre-narrowing baseline and the 0.745–0.82 estimate. Three
routes' p95 rose 26.2–83.3%; `/api/services`' own throughput fell 11.1%; a route that takes no lock
and was not touched by this change saw its off-CPU time nearly double in the same pass. One route,
`/api/thumbnail/<port>`, genuinely improved.

**Does not establish:** that the narrowing was a mistake in isolation, or that it should be reverted
without further evidence — `06-22`'s remedy for `/api/advanced/current` has not yet shipped, and the
mechanism identified here (GIL contention absorbing the freed lock time) is exactly the half
`D-DEBT-06-15` already flagged as untouched by any `_db_lock` change. Does not constitute OPS-07
evidence of any kind (`PROH-OPS-07-11`) — both passes were instrumented.
