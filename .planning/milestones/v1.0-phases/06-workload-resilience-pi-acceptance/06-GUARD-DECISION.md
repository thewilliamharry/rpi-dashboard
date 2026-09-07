---
phase: 06-workload-resilience-pi-acceptance
kind: decision-record
created: 2026-09-06
subject: UPTIME_STRIP_QUERY rounding guard
supersedes: nothing
---

# The rounding guard: what `06-25` left unmet, why `06-29` narrowed it, and what `06-27`/`06-28` now need

This record exists because three things happened in this round that a code commit cannot carry on
its own: an executed plan's acceptance criterion that was never implemented, a guard narrowing
whose legitimacy depends on a distinction that must be stated rather than assumed, and a cost fix
whose verdict changes what two already-written plans can safely say. Nothing here is absorbed
quietly into anything else.

## Section 1 — The unmet acceptance criterion, recorded as unmet against `06-25`

`06-25-PLAN.md` (lines 508–522) required, verbatim:

> **Rounding provably never entered SQL (`must_haves` truth 6).** A test reads the
> `UPTIME_STRIP_QUERY` constant's value and asserts both `'/' not in query` and
> `'round(' not in query.lower()` hold over it. The constant is a module-level string with no
> comment or docstring inside it, so the assertion is over executable SQL only. This is the static
> counterpart to Task 2's mutation (c), which is a manual observation recorded in prose and
> therefore cannot fail a future regression.
> <!-- planner-discipline-allow: ROUND( -->
> <!-- planner-discipline-allow: round( -->

That test was never written. The check that proves it:

```
grep -rn "UPTIME_STRIP_QUERY" tests/
```

returns **nothing** — at `9da5e5e` (the commit `06-25-SUMMARY.md` describes as landed) and again at
`8a84139~1` (`dcff587`, HEAD immediately before `06-29`'s Task 1 began). Both checks were run
directly against the git tree for this record, not inferred:

```
$ git show 9da5e5e:tests/test_services_route_scaling.py | grep -c "UPTIME_STRIP_QUERY"
0
$ git show dcff587:tests/test_services_route_scaling.py | grep -c "UPTIME_STRIP_QUERY"
0
```

`06-25-SUMMARY.md` reports three of three tasks complete, carries `status: complete`, carries
`Self-Check: PASSED`, and does not disclose the omission anywhere in its Deviations, Issues
Encountered, or Self-Check sections.

**This is an unmet acceptance criterion in an executed, merged and pushed plan** — a
verification-path gap in the execute-to-summary handoff, not a coding mistake. The executor
implemented the dynamic half of `must_haves` truth 6 (mutation (c)'s manual demonstration) and the
surrounding criteria in the same block (the retention floor, the route's floor-passing, the
duplicate-timestamp constraint, the NULL-refusal path) but not the static regression guard itself,
and nothing in the execute-to-summary path caught that one criterion among many was skipped.

Per `PROH-OPS-07-27`, this fact is recorded against `06-25`, and `06-25-PLAN.md` and
`06-25-SUMMARY.md` are deliberately left unedited so both the original specification and the
original omission stay legible:

```
$ git diff -- .planning/phases/06-workload-resilience-pi-acceptance/06-25-PLAN.md \
              .planning/phases/06-workload-resilience-pi-acceptance/06-25-SUMMARY.md
(no output)
```

## Section 2 — The hazard was real, and was demonstrated

`06-25-SUMMARY.md`'s mutation (c) — "Moved the division and rounding into SQL" — moved rounding and
division into the query and consumed the result directly in Python instead of computing
`round(online_seconds / observed, 3)`. The 400-trial randomized differential caught it at **trial
33, port 40331**: the mutated reader returned `0.063` (SQLite `ROUND()`, half-away-from-zero) where
the correct value was `0.062` (Python `round()`, half-to-even), on a ratio near one sixteenth
(`1/16 = 0.0625`). Confirmed independently both ways: `round(1/16, 3) == 0.062` in Python,
`SELECT ROUND(1.0*1/16, 3)` returns `0.063` in SQLite.

The hazard is real and was demonstrated dynamically. What was missing was the **standing** guard —
for the entire interval between `d127158` (`06-25`'s differential-oracle commit) and `06-29`, a
regression that reintroduced SQL-side rounding would have been caught only if someone happened to
re-run the differential against a seed that landed on a boundary like trial 33's. No regression test
existed to force that re-run.

## Section 3 — The criterion as written forbids the correct fix

`06-29`'s reshape derives each segment's first and last overlapping bucket index by **integer
division** against `bucket_seconds`, at `dashboard/beacon/repositories.py:1327-1328`:

```sql
(seg_start - ?) / ? AS first_idx,
(seg_end - 1 - ?) / ? AS last_idx
```

A blanket ban on the division character (`'/' not in query`) fails on any correct implementation of
this reshape — the reshape's entire cost saving comes from computing these two indices arithmetically
instead of joining on a range predicate SQLite cannot index-seek. The criterion as `06-25` wrote it
would reject the fix that closes `06-25`'s own regression.

## Section 4 — The narrowing, and the distinction it turns on

The criterion conflated two different things:

- *no SQLite rounding of a rendered value* — the real, demonstrated hazard (Section 2)
- *no division character anywhere in the query text* — an over-broad proxy for it, since not every
  division renders a value; bucket-index arithmetic divides to select an array position and that
  quotient is never rendered to the client

The resolution: the guard is narrowed to the actual hazard — no SQL rounding call, and every
division belongs to an enumerated `(first_idx, last_idx)` pair.

**The distinction that makes this narrowing legitimate, stated in its own sentence and unmissably:
the guard is narrowed because the original proxy was wrong about what it was protecting, NOT
because the code could not meet it.** `06-29`'s reshape did not fail to satisfy `'/' not in query`
because the reshape was somehow deficient — it failed because the proxy banned a syntactic character
rather than the semantic hazard (a rendered, rounded value) that character sometimes, but not always,
indicates.

This distinction is the one `PROH-OPS-07-01` and `PROH-OPS-07-10` exist to enforce: the acceptance
harness's thresholds and criteria must never be tuned to pass, and a criterion or budget may never be
amended because the code could not meet it — only because the criterion's own premise was shown
wrong. `PROH-OPS-07-23` (minted in `06-29`, referenced here by ID, not re-minted) states the same
rule specifically for this guard: a guard may be narrowed only when the original was wrong about what
it protected, never when the code cannot meet it, and never without proving the narrowed form still
fails the mutation the original existed to catch, in the same commit that narrows it.

This project has already drawn this exact line once before, in `.planning/ROADMAP.md`'s criterion-5
amendment note (2026-09-04): "Amending a criterion because the code could not meet it is exactly what
`PROH-OPS-07-01` and `PROH-OPS-07-10` forbid. This amendment is legitimate only because the load
model was wrong about the deployment, and it is recorded here so that distinction survives." This
record follows that precedent directly, for the same phase, on the same two prohibitions.

## Section 5 — Proof the narrowed guard is not weaker

This is not asserted; it is shown by `06-29` Task 2's recorded mutation results, reproduced verbatim
from `06-29-SUMMARY.md`.

**Mutation (c)** — the original injection, `ROUND(1.0 * bt.online_seconds / (bt.online_seconds +
bt.offline_seconds + 1), 3) AS bucket_fraction` added to the final `SELECT`. Fails **three**
independent assertions in the narrowed guard:

```
AssertionError: 3 != 2 : a division character exists in UPTIME_STRIP_QUERY outside the enumerated
first_idx/last_idx bucket-index pair -- a division added anywhere else (a projected column, a CASE
arm, a join predicate) must fail this assertion
```
```
AssertionError: <re.Match object; span=(2246, 2252), match='ROUND('> is not None : UPTIME_STRIP_QUERY
must contain no SQL rounding call -- rounding happens only in Python, over the integer second totals
this query returns (SQLite ROUND() rounds half away from zero; Python round() rounds half to even,
PROH-OPS-07-15/07-23)
```
```
AssertionError: Lists differ: ['port', 'idx', 'online_seconds', 'offline_seconds', 'null_count',
'bucket_fraction'] != ['port', 'idx', 'online_seconds', 'offline_seconds', 'null_count'] : the
projected column set must be exactly the five the reader consumes
```

**Shows:** the rounding-call test, the division-allowlist test, and the projected-column-name
assertion each independently catch the original hazard.

**Mutation (c-prime)** — the same ratio column, `1.0 * bt.online_seconds / (bt.online_seconds +
bt.offline_seconds + 1) AS bucket_fraction`, with the `ROUND()` call removed. Fails the
division-allowlist and column-name assertions, **passes** the rounding-call test:

```
AssertionError: 3 != 2 : a division character exists in UPTIME_STRIP_QUERY outside the enumerated
first_idx/last_idx bucket-index pair -- ...
```
```
AssertionError: Lists differ: [..., 'bucket_fraction'] != ['port', 'idx', 'online_seconds',
'offline_seconds', 'null_count'] : the projected column set must be exactly the five the reader
consumes
```

**Shows:** the asymmetry the plan asked to confirm — a projected column can divide without rounding,
and the allowlist (not the rounding check) is what still catches it. The allowlist is not redundant
with the rounding-call test; it earns its own place.

**Mutation (c-double-prime)** — a division inserted into an existing projected total with no new
column and no rounding call, `bt.online_seconds / 1 AS online_seconds`. Fails **only** the
division-allowlist test (rounding-call, column-name, and value-type assertions all pass unchanged):

```
AssertionError: 3 != 2 : a division character exists in UPTIME_STRIP_QUERY outside the enumerated
first_idx/last_idx bucket-index pair -- ...
```

**Shows:** this is the decisive case. A rounding-only ban would have missed this mutation entirely
(no `ROUND()` call, no new column, no changed column-name set) — and the *original* division ban
would have caught it (any `/` anywhere fails it). Because the narrowed allowlist form catches it too,
the narrowing opened no hole: the surface the original division-ban covered that the rounding-check
alone does not cover is still covered by the enumerated allowlist.

**Conclusion, on this evidence rather than on preference:** the narrowed guard's detection power over
the demonstrated hazard (mutation (c)) is not lower than the original's, and its detection power over
the projected-column surface (mutation (c-double-prime)) is exactly as high as the original's, which
covered that surface only by banning every division unconditionally. The narrowed guard is also
higher-resolution on a surface the original did not distinguish at all — bucket-index arithmetic
divisions versus rendered-value divisions — because it names the allowed pair explicitly rather than
banning the character wholesale.

## Section 6 — The alternatives that would avoid division, and why they were rejected

Two alternatives to narrowing the guard were considered and rejected on evidence, so the narrowing is
a considered choice rather than the only path anyone looked for.

**Compute bucket indices in Python and bind them.** Not possible: the segments are produced inside
SQL by a `LEAD` window function over the merged boundary-and-in-window point stream (the `spans` CTE
reads from `ordered_points`, which is built entirely in SQL) and never reach Python before the bucket
range is needed. Binding indices computed in Python would require materializing every segment into
Python first — the per-row materialization `PROH-OPS-07-24` and the boundedness guards
(`UptimeStripBoundednessTests`) exist specifically to prevent, since it would make the Python-side row
count a function of window coverage rather than a fixed bound.

**Expand by recursive increment rather than by division.** Start each segment at bucket zero and step
forward until the bucket containing `seg_start` is reached, instead of computing `first_idx`
arithmetically. Rejected: that walk is `O(UPTIME_BUCKETS)` per segment, which is the exact cost
dimension the reshape exists to remove (`06-PROFILE-3.md`'s root-cause finding was the unindexed range
join's `buckets x ports x segments_per_port` scaling) — taking this path would reproduce the
regression the reshape is fixing, just relocated from the join predicate into the recursion's
iteration count.

**Keep the division ban and accept the range join.** Rejected on measured evidence: `06-26` measured
that shape (the range join `06-25` shipped, unindexed) at **+315.8%** against the pre-`06-25`
baseline. Keeping the original guard at the cost of reverting to the shape it was written against is
not a live option; it is the regression this round exists to close.

## Section 7 — `06-27` and `06-28`: what each now needs

Neither `06-27-PLAN.md` nor `06-28-PLAN.md` is edited by this plan. This phase's append contract
forbids modifying an existing PLAN; the only way each is not silently left describing a build that no
longer exists is to enumerate here what a re-planning round must change in each.

### `06-27` needs

1. **Both build references in its `user_setup` segment A must be restated against the reshape's
   SHA.** `06-27-PLAN.md`'s `user_setup` describes segment A as profiling "the pre-`06-25` parent
   commit and HEAD" — after this round, HEAD is the reshaped build (`06-29`'s Task 1 commit,
   `8a84139`, or whatever commit results from Task 2's checkpoint decision), not the `06-25`-landed
   build (`9da5e5e`) segment A's Task 1 language was written against. Segment A's Task 1 (lines
   241-242 of `06-27-PLAN.md`) instructs finding "the parent of `06-25`'s first production commit" —
   that instruction is still correct for the "before" side, but the "after" (HEAD) side must be
   restated to name the actual current HEAD, whatever it is after this round's checkpoint resolves.

2. **`06-27`'s `PROH-OPS-07-20` gate now sits behind a second local predictor.** `06-27-PLAN.md`'s
   own Task 1 is itself a cheap local predictor gating segment B's Pi time (per `PROH-OPS-07-20`'s
   original purpose), but that gate was written assuming it would be the *only* pre-hardware
   measurement standing between `06-25`'s landed regression and a Pi acceptance run. `06-PROFILE-4.md`
   is now a second, already-measured, already-committed local predictor that sits in front of it. Any
   re-planning round must have segment A's decision gate reference `06-PROFILE-4.md`'s verdict rather
   than re-deriving a fresh before/after comparison as if no local measurement yet existed.

3. **`06-27` cannot run at all unless `06-PROFILE-4.md`'s verdict is PASS.** `06-PROFILE-4.md`'s
   verdict is **FAIL-BUT-IMPROVED** (69.191ms mean against a 56.820ms pass bar). Per `PROH-OPS-07-20`
   — "an acceptance run must never be spent on a build whose own cheap predictor measured worse" —
   `06-27` is **not unblocked** by this round. This is unaffected by which option Task 2's checkpoint
   selects among the ones that do not themselves clear the bar (`keep-reshape`, `keep-and-extend`,
   `revert-route-wiring` all leave the route at or below its pre-`06-25` baseline or exactly at it, not
   above it): only `unblock-27` requires a PASS, and no verdict recorded here is PASS.

### `06-28` needs

1. **A fourth threat, added to the enumerated list.** `06-28-PLAN.md`'s `must_haves` names "the
   threats `06-25` introduced (a dynamic `IN` list, a second producer of a rendered contract, an
   uncapped aggregation)" as three threats to register with severities and dispositions. The reshape
   adds a fourth: the recursive `expanded` CTE's intermediate row count is **data-dependent**, where
   the previous shape's intermediate (the `requested_ports CROSS JOIN buckets` scaffold) was fixed at
   `ports x UPTIME_BUCKETS` regardless of the underlying data. Its bound is
   `segments + len(ports) * (UPTIME_BUCKETS - 1)` — provable because a port's segments partition
   `[start, now]` contiguously, so each of a port's internal bucket boundaries splits exactly one
   segment, contributing at most one extra expanded row per boundary crossed. `06-29`'s own measured
   figure against this bound: **22,247 expanded rows against a computed bound of 23,583** (the
   8-service/8-day profiled shape), recorded so `06-28`'s register can carry the bound with evidence
   already measured rather than re-derive it.

2. **`06-28`'s `PROH-OPS-07-21` obligation extends to any `06-SECURITY.md` entry that cites
   `UPTIME_STRIP_QUERY`'s previous shape.** `PROH-OPS-07-21` states a security register entry may
   never cite evidence not in the tree it describes. Any `06-SECURITY.md` row whose evidence cites the
   pre-`06-29` range-join shape of `UPTIME_STRIP_QUERY` (rather than the current index-arithmetic plus
   recursive-expansion shape) must be re-closed on the current shape's evidence or reopened, the same
   treatment `06-28-PLAN.md` already applies to `T-06-24` and `T-06-101` for the `ea8689e` revert.

## Section 8 — The checkpoint outcome

**Selected option: `revert-route-wiring`.**

The operator's reasoning, recorded verbatim:

> Revert `/api/services` to the Python sweep. `06-29`'s reshape is proven output-identical and 3.4x
> better than `06-25` left the route, but 69.191ms against a 56.820ms bar is a measured regression
> against the code it replaced, and knowingly shipping one on a FAIL verdict is not acceptable. The
> route returns to its best known cost while the real remedy is scoped. `read_uptime_strips_by_port`,
> its 1,824-case differential, the three golden fixtures and the boundedness suite all STAY in the
> tree — they are a proven-correct implementation and the evidence base for the next round, not
> throwaway work.
>
> The decisive finding is the floor, not this implementation: `ordered_points`' LEAD window alone
> costs approximately what the entire Python sweep cost, so making the bucket aggregation nearly free
> — which `06-29` did — still loses. That is evidence about per-request computation as an approach.
> `keep-and-extend` was rejected for that reason: the held-in-reserve `ordered_points` restructure
> saves ~10ms against a ~13ms gap, so at best it buys another round for another FAIL, and it does so
> by restructuring the single `admitted` CTE that `06-25` chose specifically so the retention floor
> could not be applied to the in-window scan while silently missing the boundary lookup
> (`PROH-OPS-07-22`) — a correctness risk taken for a cost gain.
>
> Consequently OPS-07's remedy is re-scoped: the next round moves the 168-bucket strip OFF the
> request path entirely, precomputed by the worker on its existing cadence and read by
> `/api/services`, rather than continuing to make per-request computation cheaper. That is a separate
> plan and is not authorized by this decision beyond the re-scoping itself.

Per this plan's own context and its `files_modified`, **the revert itself is a separate plan**. No
`.py` file appears in this plan's diff, and no revert is executed here — Task 3 records this decision
alongside the debt entries it produces.

`.planning/REQUIREMENTS.md` is unedited by this plan: OPS-07 stays Pending in both halves
(`PROH-OPS-07-08`).
