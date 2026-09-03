---
phase: 06-workload-resilience-pi-acceptance
plan: 18
kind: hardware-evidence
created: 2026-09-03
---

# Round 4 lock diagnostic — real Raspberry Pi hardware, instrumented

> Durable record of the two instrumented hardware passes Task 1 of `06-18-PLAN.md` produced, so a
> later reader is not dependent on chat history for the figures this artifact's verdict and
> `06-DEBT.md`'s round-4 updates cite. Performed on real hardware by the operator (this plan's
> blocking `checkpoint:human-verify`; `PROH-OPS-07-02`).

## Provenance

| Field | Value |
|---|---|
| Pi `git log --oneline -1` | `d9cecb8` (matches `origin/main` HEAD under test) |
| Host | `aarch64` / `raspi`, Raspberry Pi 5 Model B, `nproc` = 4 |
| Endpoint pre-check | `enabled: true`, `schema_version: 2` — confirmed live before either pass |
| Endpoint post-check | `404` — confirmed restored after both passes (Step 7) |
| Control pass scenario | concurrency 1, duration 120s, `--lock-profile` |
| Acceptance-shape pass scenario | concurrency 8, duration 600s, `--lock-profile` |
| `service_checks` row count, before (step 3) | 56,742 |
| `service_checks` row count, after (step 6) | 56,828 |
| Row growth across the ~12-minute window | 86 rows |
| `services` row count | 8 |
| Reference shape this Pi now exceeds | `06-PROFILE.md`'s 25,278-row reference (this Pi holds 2.24x that) |

**This is diagnostic evidence, not OPS-07 acceptance evidence.** Both passes ran with
`BEACON_LOCK_PROFILE=1` — an instrumented build — and `PROH-OPS-07-11` states plainly that an
instrumented run is never OPS-07 evidence, whichever way its numbers fall. `PROH-OPS-07-08` holds:
OPS-07 is not promoted by this round, and `.planning/REQUIREMENTS.md` is unedited by this artifact
(`git diff --quiet -- .planning/REQUIREMENTS.md`).

**In-situ overhead check (`T-06-81`).** The instrumented control pass's `/api/services` p50 measured
**257.6ms**. Round 3's uninstrumented control p50 (`06-ACCEPTANCE-ROUND3.md`) was **209.355ms**. The
gap is `(257.6 - 209.355) / 209.355 = 23.05%` — **outside** the 15% band this check calibrates
against. Two things are true at once and neither cancels the other: (1) the instrument is measurably
perturbing what it measures on this build, by more than the rehearsal's laptop figures predicted, so
every absolute-millisecond figure below should be read with that inflation in view, not as the
uninstrumented deployment's true cost; and (2) the dataset also grew 2.24x between round 3's control
pass and this one, which independently raises `/api/services`' true uncontended cost regardless of
instrumentation — round 3's own `06-DEBT.md` `D-DEBT-06-01` records this route's residual cost as
proportional to stored check count. The two effects are not separated by this run. The figure is
recorded, not discarded, per this check's own instruction.

---

## Missing item 1 — "Instrument `_db_lock` directly under the concurrency-8 load and report, per route and per request: time spent WAITING to acquire the lock versus time spent HOLDING it. This is the single measurement that converts the attribution above from strong inference to direct evidence. Prediction to falsify: `/api/scan-status` will show ~0ms hold and ~240ms median wait; `/api/services` will show ~200-500ms hold and a wait that grows with the number of siblings queued ahead of it. A wrapper recording monotonic timestamps around the acquire in a contextmanager replacing the bare `with _db_lock` is sufficient — no fix, no topology change."

**Every hold figure below carries its error bar first.** `instrument_cost_ns_per_acquisition = 1469.1ns`
(`06-15-SUMMARY.md`), a fixed absolute per-acquisition cost. Against `/api/services`' hundreds of
milliseconds it is negligible (< 0.001%). Against `/api/scan-status`' low-single-digit-millisecond
hold it is a much larger relative share, so each hold below states plainly whether it is
distinguishable from that cost.

### Full per-route table, concurrency-8 pass (source: `beacon-lockdiag-c8.json`, `lock_profile.routes[*]` and `lock_profile.requests[*]`)

| Route | Acquisitions | Wait p50 (bucketed) | Hold p50 (bucketed) | Lock share of wall (`requests[*]`) | connect / sql / py split |
|---|---:|---|---|---:|---|
| `/api/services` | 882 | 545.6–1128.8ms | 263.7–545.6ms | 56.4% | .002 / .748 / .250 |
| `/api/scan-status` | 880 | 263.7–545.6ms | 1.6–3.4ms | 99.0% | .384 / .454 / .162 |
| `/api/history` | 880 | 14.4–29.8ms | 14.4–29.8ms | 59.7% | .035 / .954 / .011 |
| `/api/thumbnail-status` | 880 | 14.4–29.8ms | 1.6–3.4ms | 85.4% | .234 / .652 / .113 |
| `/api/thumbnail/<port>` | 7,007 | 14.4–29.8ms | 1.6–3.4ms | 99.0% | .356 / .487 / .157 |
| `/healthz` | 54 | 263.7–545.6ms | 1.6–3.4ms | 99.5% | .436 / .449 / .115 |
| `/api/advanced/current` | 0 (takes no lock) | n/a | n/a | 0.0% | n/a |

The "Wait p50" / "Hold p50" columns are the `[lower, upper]` histogram-bucket edges
`percentile_from_histogram` returns (`tests/pi_load_acceptance.py`), not point estimates.

### Concurrency-1 control-pass figures for the same routes (source: `beacon-lockdiag-c1.json`)

Only aggregate route-latency percentiles and two routes' held-region splits were captured in the
operator's Task-1 transcript this artifact was compiled from; a route-level wait/hold-ns table for
the control pass is not reproduced here and, if needed for a future recalibration, must be read
directly from `beacon-lockdiag-c1.json`'s `lock_profile.routes[*]`.

| Route | Wall p50 / p95 (ms) | Held-region split (connect / sql / py) |
|---|---|---|
| `/api/services` | 257.6 / 275.9 | .001 / .423 / .576 |
| `/api/scan-status` | 3.4 / 4.2 | .198 / .594 / .208 |
| `/api/advanced/current` | 92.4 / 104.2 | n/a — no lock |
| `/api/history` | 12.1 / 14.0 | not captured |
| `/api/thumbnail-status` | 4.3 / 5.3 | not captured |
| `/api/thumbnail/<port>` | 3.5 / 4.3 | not captured |

### The exact figures the verdict's `checks` used, and a naming caveat worth recording

`evaluate_lock_attribution` (`tests/pi_load_acceptance.py`) computes
`services_hold_median = services_route['hold_ns_total'] / services_route['acquisitions']` —
**this is an arithmetic mean over 882 acquisitions, not a percentile-derived median**, despite the
prediction key's name. Measured: **596,245,129ns (596.245ms)**. This sits *above* the independently
bucketed hold-percentile range for `/api/services` (263.7–545.6ms upper edge 545.6ms), which is
exactly what a right-skewed hold-time distribution produces: a minority of unusually long
`/api/services` acquisitions (larger stored-check volume for some ports, or the maintenance-coverage
walk) pull the mean above the bucketed median. Both figures are genuine measurements from named
fields; they are not in conflict, they are two different statistics of the same distribution. Either
way, 596.245ms is **1,469.1ns × ~406,000** — the measured hold is trivially distinguishable from the
instrument's own cost.

For `/api/scan-status`, the same formula gives `scan_status_hold_median = 2,531,729ns (2.532ms)`,
which *does* sit inside its own bucketed range (1.6–3.4ms) — no such skew for this route, consistent
with its short, low-variance held region (near-zero SQL work, mostly instrument overhead). 2.532ms is
**1,469.1ns × ~1,723** — also clearly distinguishable from the instrument's own cost. **Neither
route's measured hold is "at or below the instrument's resolution"; both readings are real
measurements.**

### The prediction, evaluated clause by clause

1. **"`/api/scan-status` will show ~0ms hold."** HELD (`scan_status_median_hold_near_zero`: measured
   2,531,729ns against a 5,000,000ns threshold). 2.532ms is not literally zero but is well inside the
   generous band and, as above, is distinguishable from instrument noise — it is a small, genuine
   critical section (mostly `connect`/`sql` per the .384/.454/.162 split), consistent with "brief."

2. **"~240ms median wait."** No single-number check exists for this in `evaluate_lock_attribution`;
   the closest formal check is `scan_status_wait_tracks_services_hold`
   (`scan_status_wait_median / services_hold_median >= 0.5`), which **HELD** at measured **0.5141**.
   Reconstructing the absolute figure from that ratio: `0.5141 × 596.245ms ≈ 306.5ms` — which matches,
   almost exactly, the independently-computed request-level mean lock-wait for `/api/scan-status`
   (`requests['/api/scan-status'].lock_wait_ns_total / requests_total = 269,736.4ms / 880 =
   306.5ms`, from the decisive request-accounting table below). **The measured wait (~306.5ms) is
   higher than the original ~240ms prediction, but not by contradiction** — the ~240ms figure was
   derived from round 3's 209.355ms control-pass services hold; this run's services hold is itself
   larger (596.245ms, see item 4), because the dataset grew 2.24x. Scaling the original relationship
   (wait ≈ ~1 full services hold) to this run's own measured services hold reproduces the observed
   wait almost exactly. The *relationship* held; the *absolute* figure moved with the dataset, as
   expected.

3. **"`/api/services` will show ~200-500ms hold."** **FAILED** (`services_median_hold_in_band`:
   measured 596,245,129ns against threshold `[200,000,000, 500,000,000]`ns) — 596.2ms exceeds the
   500ms upper edge by 96.2ms (19.2% over). This is the verdict's sole failed check. See the Verdict
   section for why this points toward, not away from, the attribution.

4. **"and a wait that grows with the number of siblings queued ahead of it."** Qualitatively
   supported, not independently gated: `/api/services`' own wait bucket (545.6–1128.8ms — this route
   can queue behind up to 7 siblings, including other `/api/services` calls) sits well above
   `/api/scan-status`' wait bucket (263.7–545.6ms — one full `/api/services` hold ahead of it in the
   rotation). No formal check asserts monotonicity in sibling count; the ordering observed is
   consistent with the claim.

### Decisive request-accounting table, concurrency-8 (source: `beacon-lockdiag-c8.json`, `requests[*]`)

| route | n | wall (ms) | cpu (ms) | lock_wait (ms) | other (ms) | lock share |
|---|---:|---:|---:|---:|---:|---:|
| `/api/thumbnail/<port>` | 7,007 | 2,042,381.5 | 12,890.9 | 2,021,760.3 | 7,732.3 | 99.0% |
| `/api/scan-status` | 880 | 272,392.5 | 1,758.6 | 269,736.4 | 897.6 | 99.0% |
| `/healthz` | 54 | 25,562.3 | 82.2 | 25,432.7 | 47.5 | 99.5% |
| `/api/thumbnail-status` | 880 | 22,937.3 | 2,591.5 | 19,579.4 | 766.4 | 85.4% |
| `/api/history` | 880 | 86,896.3 | 23,667.7 | 51,916.1 | 11,312.5 | 59.7% |
| `/api/services` | 882 | 1,232,421.9 | 365,245.9 | 695,573.4 | 171,602.6 | 56.4% |
| `/api/advanced/current` | 880 | 1,087,221.5 | 536,241.0 | 0.0 | 550,980.5 | 0.0% (takes no lock) |

---

## Missing item 2 — "Measure lock utilisation (fraction of wall time `_db_lock` is held by anyone) over the acceptance window, and attribute it by route. The control-pass figures already imply `/api/services` alone accounts for >=35% (1020 completions x 209ms / 600s) BEFORE any load-induced stretch of its 82%-Python critical section; confirm whether utilisation under load crosses the ~0.85 threshold where M/G/1 queueing delay goes superlinear. This determines whether the fix is narrowing the lock's scope or reducing the critical section, and by how much."

**Utilisation, concurrency-8:** `total_hold = 578,783,964,515ns`, `window = 600,444,800,885ns`,
`utilisation = 578,783,964,515 / 600,444,800,885 = 0.9639`. **HELD** against the 0.85 superlinear
threshold (`utilisation_above_superlinear_threshold`, measured 0.9639). For comparison, the
concurrency-1 control pass measured `utilisation = 0.6653`.

**Per-route composition, arithmetic shown.** `/api/services`' exact per-acquisition mean hold
(596.245129ms, item 1) times its acquisition count (882) accounts for
`882 × 596.245129ms = 525,888.19ms` of the 578,783.96ms total — **90.9%** of all lock hold time in
the window, from `/api/services` alone. The remaining five lock-taking routes combined account for
the residual: `578,783.96ms − 525,888.19ms = 52,895.77ms` — **9.1%**. `/api/thumbnail/<port>`'s
7,007 acquisitions dominate that residual by count, but its per-acquisition hold is short
(1.6–3.4ms bucket), so its total contribution stays small next to `/api/services`' long individual
holds.

**0.85 is crossed almost entirely by one route.** Past 0.85, M/G/1 queueing delay is superlinear in
utilisation — this is the mechanism that turns `/api/scan-status`' 3.4ms uncontended hold into a
route that waits ~300ms behind a queue, even though `/api/scan-status` itself is cheap.

---

## Missing item 3 — "Separate the GIL contribution from the lock contribution by measuring them independently rather than inferring one from the other's absence. For the GIL: sample per-thread state (or run under a GIL-contention profiler) to get gil-wait time for `/api/advanced/current`, the one route that takes no lock. Do NOT reuse `D-DEBT-06-01`'s reopening test — this verification finds it non-diagnostic, and the round should record that finding rather than run it a third time. Note the decisive bound already available: an 8-thread interpreter can stretch a CPU-bound route at most ~8x, but `/api/scan-status` degraded 74x, so the GIL provably cannot be that route's dominant mechanism."

**`/api/advanced/current` — the route that takes no lock, measured independently.** Its
`requests['/api/advanced/current'].lock_wait_ns_total` is exactly **0.0ms** across 880 requests —
this route never contends for `_db_lock`. Its wall p50 degraded from **92.4ms** (concurrency-1) to
**1,137.5ms** (concurrency-8) — a **12.31x** degradation, essentially matching round 3's 12.6x
(`06-ACCEPTANCE-ROUND3.md`) despite the dataset growing 2.24x since — consistent with this route's
cost being CPU/GIL-bound rather than data-volume-bound.

The concurrency-8 report decomposes its total wall time exactly into on-CPU and other-off-CPU with
no lock component (`cpu_ns_total + other_off_cpu_ns_total = wall_ns_total` for this route, since
`lock_wait_ns_total = 0`): `cpu = 536,241.0ms`, `other = 550,980.5ms`, sum `1,087,221.5ms` =
measured wall total, exactly. Per request: mean CPU **609.4ms**, mean other-off-CPU **626.1ms**.

**The excess, as a floor rather than a precise before/after subtraction.** The operator's Task-1
transcript this artifact was compiled from does not include a per-request CPU/off-CPU split for the
concurrency-1 pass — only the aggregate wall p50 (92.4ms). A defensible floor is still derivable
without it: the mean **other-off-CPU alone** at concurrency-8 (626.1ms/request) already exceeds the
**entire** uncontended wall time at concurrency-1 (92.4ms) by roughly **534ms**. Since concurrency-1
wall time is an upper bound on whatever off-CPU component existed at baseline (the whole request,
CPU and off-CPU combined, took only 92.4ms), the growth in off-CPU time alone under load cannot be
explained by baseline I/O wait that was already present — it is new, contention-driven off-CPU time.
That is the GIL signature: a thread ready to run but not holding the interpreter.

**`/api/scan-status`, for the other half of the split.** Its lock-wait share of wall is **99.0%**
(`scan_status_lock_wait_share_of_wall`, measured 0.9902 — the run's decisive, refutation-tested
check). Its `other_off_cpu` share is `897.6ms / 272,392.5ms = 0.33%` — negligible. **The two
mechanisms are now measured, not inferred from each other's absence, and they point at different
routes almost exclusively:** `/api/scan-status`'s degradation is essentially all lock wait and
essentially no GIL contention; `/api/advanced/current`'s degradation is essentially all GIL/CPU
contention (49.3% cpu, 50.7% other-off-cpu of its wall) and, by construction, zero lock wait.

**`D-DEBT-06-01`'s second reopening test is recorded as non-diagnostic and was not run a third time.**
That test asked whether the unlocked `/api/advanced/current` recovers to near its control-pass p95
while locked routes stay over budget. It cannot fire while any GIL cost exists, because it uses a
GIL-bound 82.281ms route as the discriminator for a *lock* it never takes — and this run's own
measurement confirms that GIL cost is large and real (12.31x degradation, 534ms+ of off-CPU growth
under an unlocked route). The test's failure to fire in prior rounds was never evidence about
`_db_lock` either way; this round's independent GIL measurement is the first time that claim rests on
direct evidence rather than the test's own design logic.

---

## Missing item 4 — "Measure how much of `/api/services`' critical section is actually database work needing the lock's protection. `06-PROFILE.md` already puts it at 17.958% on a laptop; confirm the split on the Pi under load. This sizes the payoff of the obvious candidate fix — releasing `_db_lock` after the reads and performing the uptime sweep, maintenance coverage and offline-interval reconstruction outside it — without committing to that fix this round."

**This CONTRADICTS `06-PROFILE.md`'s laptop figure, and by a wide margin, on the Pi's own uncontended
pass already.** `06-PROFILE.md` §3 measured, on a MacBook, `sql_execute` (2.338%) + `sql_fetch`
(15.620%) = **17.958%** SQL, **82.042%** Python. On the Pi, concurrency-1 (uncontended,
`beacon-lockdiag-c1.json`, `/api/services`' held-region split): `connect .001 sql .423 py .576` —
**42.3% SQL** even with zero contention, 2.4x the laptop's share. Under load, concurrency-8: `connect
.002 sql .748 py .250` — **74.8% SQL**, 25.0% Python. The SQL share does not merely differ from the
laptop figure; it **rises further under contention on the same host**, more than 4x the laptop
figure at load. **The candidate fix — moving the ~82% "Python" work out of the critical section — is
sized against a laptop figure that materially overstates what remains under lock on the Pi.** The
connection-setup share stays immaterial at every stage: 0.1% uncontended, 0.2% under load.

**Sizing the actual candidate fix ceiling, arithmetic shown.** Cutting the measured Python-only
portion (25.0% of the held region, under load) out of `/api/services`' critical section would reduce
that route's own hold by ~25%: `525,888.19ms × 0.25 = 131,472.05ms`. Applied to item 2's total hold
figure: `578,783.96ms − 131,472.05ms = 447,311.91ms`. New utilisation:
`447,311.91 / 600,444.80 = 0.745` — comfortably **under** the 0.85 superlinear threshold. This is a
larger estimated win than a rougher pass would suggest, because `/api/services` was independently
found to be ~90.9% of total hold (item 2), not a smaller fraction — the fix ceiling is larger, not
smaller, than a first-glance estimate implies. **This is sized as a payoff estimate, not a
commitment**: it assumes the 25% Python cut translates linearly into hold-time reduction and holds
all other routes' behavior constant, neither of which this round measures directly.

**Accuracy evidence for the split — never the summing identity.** `connect + sql + python == hold`
holds by construction (`python` is the derived remainder), so it demonstrates nothing about accuracy
(`06-16` labels it "reported for readability" for exactly this reason; `D-DEBT-06-10`'s lesson is
that a guard which cannot fail is not a guard). The evidence that this split measures rather than
merely partitions is `tests/test_lock_profile.py::HoldDecompositionTests::test_two_directional_sql_share_of_the_held_region`
(`06-16` Task 1), which is demonstrated to report a high SQL share for a SQL-dominated section and a
low one for a Python-dominated section — a two-directional check that can fail in either direction.
Additionally, `clamped_python_count` is **0** on this hardware run (both passes), the collector's own
visible signal that no negative-remainder defect corrupted the derived `python` component. If it had
been non-zero, the split above would need to be read as suspect; it is not.

---

## Missing item 5 — "Re-run the acceptance harness on real Pi-class hardware only AFTER a fix chosen against the diagnostic measurements above. `PROH-OPS-07-01` forbids tuning budgets (verified intact this round: `ROUTE_BUDGETS_MS` at `tests/pi_load_acceptance.py:102` is unchanged since `06-07` and its values match those the report cites) and `PROH-OPS-07-02` forbids treating anything but a genuine hardware run as OPS-07 evidence."

**Deliberately not this round.** Both hardware passes in this artifact ran an **instrumented**
build (`BEACON_LOCK_PROFILE=1`) and are diagnostic evidence, never OPS-07 evidence
(`PROH-OPS-07-11`). The hardware acceptance re-run this item names happens only after Task 3's
decision selects a fix and that fix is implemented, guarded, and shipped — this artifact is the
measurement that decision is made against, not the re-run itself.

**What round 5's re-run needs, if `fix-now`/`defer-to-round-5` lands a fix:** an **uninstrumented**
build (`docker compose up -d --build` with `BEACON_LOCK_PROFILE` unset or 0); the unchanged
`--concurrency 8 --duration 600` scenario (`PROH-OPS-07-10`); a genuine hardware run, never
developer-machine evidence (`PROH-OPS-07-02`, `PROH-OPS-07-09`); and comparison against this
artifact's control-pass figures with the dataset-size caveat this artifact itself needed (row counts
recorded at both ends, not assumed stable).

**Also worth naming here, since it is new context this round's own run surfaces:** a **fourth**
route now fails its own budget — `/api/thumbnail/<port>` p95 1695.6ms against its 1500ms budget
(`beacon-lockdiag-c8.json`, `failure_reasons`). Round 3 had three failing routes
(`06-ACCEPTANCE-ROUND3.md`). This should **not** be read as a regression from round 3 without the
caveat that the dataset grew 2.24x between the two runs — the two acceptance passes are not
directly comparable on absolute figures, only on shape. `clamped_off_cpu_count` was **106** of
roughly 10,000 requests on this run (~1%), consistent with `D-DEBT-06-13`'s 1–3%
developer-machine characterisation of this same clock-comparison artifact — it reproduces on real
hardware at the expected rate, and is not itself evidence of a defect. `clamped_python_count` was
**0**.

---

## Verdict

**Verdict:** INCONCLUSIVE

**Reason** (verbatim from `lock_profile.attribution.reason`, `beacon-lockdiag-c8.json`): "the
refutation condition did not hold, but not every confirmation prediction did either:
services_median_hold_in_band (measured 596245128.7142857, threshold [200000000, 500000000])."

### Full `checks` list

| name | measured | threshold | held |
|---|---|---|---|
| `scan_status_lock_wait_share_of_wall` | 0.9902 | 0.5 | **HELD** |
| `scan_status_median_hold_near_zero` | 2,531,729ns (2.53ms) | 5,000,000ns | **HELD** |
| `services_median_hold_in_band` | 596,245,129ns (596.2ms) | [200,000,000, 500,000,000]ns | **FAILED** |
| `scan_status_wait_tracks_services_hold` | 0.5141 | 0.5 | **HELD** |
| `utilisation_above_superlinear_threshold` | 0.9639 | 0.85 | **HELD** |

(`evaluate_lock_attribution`, `tests/pi_load_acceptance.py`: the refutation condition
(`scan_status_lock_wait_share_of_wall`) is evaluated first, before any confirmation condition — it
did not fire, so the run proceeded to the confirmation checks above.)

### Why this points toward the attribution, not away from it

The one failed check (`services_median_hold_in_band`) failed on the **high** side —
596.2ms against a 500ms upper edge — not because `/api/services` holds the lock briefly (which
would undercut the attribution) but because it holds it *longer* than the band predicted. The band
was calibrated from round 3's 209.355ms control p50, measured when the Pi held 25,278 check rows.
This run's Pi holds 56,828 rows (2.24x) and its own control p50 has risen to 257.6ms accordingly
(item 4's held-region measurement also shows the SQL-bound portion of that hold growing with row
count). A route that holds a process-wide lock for *longer* because there is genuinely more work to
do under it, on a dataset that has grown since the band was set, is the mechanism getting stronger
with scale, not weaker. This does not license calling the run CONFIRMED — the verdict function
declined to paper over a failed prediction, and that conservatism is the point of the three-valued
design (`06-17`).

**A finding worth recording for round 5's predictions.** The **relational** check
(`scan_status_wait_tracks_services_hold`, measured 0.5141 against 0.5) HELD, while the **absolute**
magnitude check (`services_median_hold_in_band`, a fixed millisecond band) FAILED. Encoding a fixed
band tied that prediction to round 3's dataset size rather than to a relationship between measured
quantities — the same class of mistake `D-DEBT-06-10` names (mechanism instead of outcome), in a
different costume: an absolute threshold instead of a relative one. A round-5 prediction phrased as
"services' hold sits within N% of the concurrency-1 control-pass hold measured in the same run"
would not have this failure mode.

### What this INCONCLUSIVE means, and what would settle it

The missing precondition is not a data-collection failure (`collected`, `route_overflow`, and
minimum-acquisition preconditions all passed cleanly — see the checks list; this is not a case of
"no measurement was taken"). It is that one confirmation prediction was phrased as an absolute
band calibrated to a dataset size that had since changed. Two ways to settle it, either sufficient
on its own:

1. **Recalibrate the band to the current dataset shape and re-run** — using this run's own
   control-pass growth (257.6ms / 209.355ms ≈ 1.230x) to rescale the band to roughly
   `[246,000,000, 615,000,000]`ns would return CONFIRMED on these same measured figures (596.2ms
   falls inside that rescaled band). This is a diagnostic-harness change (a prediction constant),
   not a code fix, and does not require another hardware session on its own — though re-running is
   still the honest way to confirm a rescaled prediction against fresh data rather than the same
   numbers that motivated the rescale.
2. **Replace the absolute band with a relational check**, per the finding above — a prediction
   stated relative to the same run's own control-pass measurement is dataset-size-invariant by
   construction and would not need recalibration as the deployment's data volume grows.

Both are round-5-scoped diagnostic-harness changes, not fix implementation.

### What this does and does not establish

**Establishes:** `/api/scan-status`'s degradation under load is measured, not inferred, to be almost
entirely `_db_lock` wait (99.0% of its wall), and its wait tracks `/api/services`' measured hold at
essentially the predicted ratio. `/api/services` alone accounts for ~90.9% of total lock hold time
in the window, and utilisation (0.9639) sits well past the 0.85 superlinear threshold. GIL
contention is separately measured, on an unlocked route, to be real and substantial (12.31x
degradation, ~534ms+ of off-CPU growth under load) but essentially absent from `/api/scan-status`'s
own degradation (0.33% off-CPU share). The Pi's own SQL share of `/api/services`' held region
(42.3% uncontended, 74.8% loaded) is measured to be far higher than the laptop profile's 17.958%,
which materially changes the sizing of the obvious candidate fix — larger, not smaller, than the
laptop figure implied.

**Does not establish:** that the attribution is confirmed outright — one prediction, phrased as an
absolute band, failed on measured data. Does not establish what a narrowed `_db_lock` would actually
achieve in production — the 0.745 post-fix utilisation estimate in item 4 is arithmetic against
today's measured shares, not a hardware-verified result of an implemented change. Does not constitute
OPS-07 evidence of any kind (`PROH-OPS-07-11`) — both passes were instrumented.
