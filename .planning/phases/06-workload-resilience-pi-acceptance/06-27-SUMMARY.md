---
phase: 06-workload-resilience-pi-acceptance
plan: 27
subsystem: database
tags: [sqlite, uptime, performance, ops-07, acceptance-evidence, runbook, debt-record]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-PROFILE-5.md's dev-host PASS (34.927ms vs 56.820ms) for 06-31's revert-plus-reduction build; D-DEBT-06-26's enumeration of the build-SHA amendment this plan needed; the two hardware evidence sets the operator ran on the Pi and committed as raw JSON before this plan executed"
provides:
  - "06-PI-PROFILE-C.md: Pi-class reproduction of the dev-host PASS -- -45.07% on the Pi (vs -38.53% on the laptop), gate word IMPROVED, unblocking segment B"
  - "06-ACCEPTANCE-C3-RUN3.md: the third independent concurrency-3/600s gating run, overall_passed FALSE, /api/services p95 662.3ms vs 500ms -- a new selective-inflation finding (6.9x over segment A's uncontended cost, two routes affected, four unaffected) recorded as a hypothesis consistent with lock contention, plus an OPS-07 disposition write-up (three options, none chosen) for the operator"
  - "06-ACCEPTANCE-RUNBOOK.md: the permanent command path for running the acceptance harness against a live Pi deployment, including the sqlite3-CLI-not-installed detail and the three invocations that silently produce wrong or inadmissible results"
  - "D-DEBT-06-27 (new): the selective-inflation finding filed as tracked debt, a candidate for round 8, not scheduled here"
  - "D-DEBT-06-08/06-19/06-20/06-21 each updated in place with round-7's Pi-class and third-run evidence; no prior entry rewritten or deleted (26 -> 27 entries)"
affects: [06-28]

actuals:
  tokens: 12123
  tasks: 3
  commits: 8

tech-stack:
  added: []
  patterns: ["diagnostic (cProfile) vs acceptance (uninstrumented harness) evidence kept in separate artifacts per PROH-OPS-07-11, even when both are Pi-class", "operator decisions on load-model re-derivation presented as costed options in the acceptance artifact itself, never taken by the reporting plan"]

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-PI-PROFILE-C.md
    - .planning/phases/06-workload-resilience-pi-acceptance/06-ACCEPTANCE-C3-RUN3.md
    - .planning/phases/06-workload-resilience-pi-acceptance/06-ACCEPTANCE-RUNBOOK.md
  modified:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md

key-decisions:
  - "Segment A's gate word is IMPROVED (77.081ms vs 140.323ms, -45.07%, 17.4x the larger of the two spreads), so segment B ran per PROH-OPS-07-20."
  - "Segment B's result is recorded exactly as measured: overall_passed FALSE, the third consecutive independent miss on /api/services (635.6ms, 679.3ms, 662.3ms). No budget, threshold, or REQUIREMENTS.md line was touched in response."
  - "The 6.9x selective-inflation finding is recorded as a hypothesis consistent with lock contention, not a diagnosis -- this run carries no lock instrumentation and cannot attribute the mechanism. Filed as new debt (D-DEBT-06-27), not investigated."
  - "The OPS-07 disposition (accept the deviation / re-derive the load model / investigate contention in a round 8) is written up with costs and risks for the operator to decide. This plan selects none of the three and does not mark OPS-07 anything but Pending."

patterns-established:
  - "A cProfile-instrumented, in-process measurement can be genuinely Pi-class (host_machine/host_node confirm it) while still being diagnostic-only, never acceptance evidence -- the two axes (dev-host vs Pi-class; diagnostic vs acceptance) are independent and both must be stated."

requirements-completed: []

coverage:
  - id: D1
    description: "Segment A Pi-class cost verdict written up (06-PI-PROFILE-C.md), reproducing 06-PROFILE-5.md's dev-host PASS on target hardware"
    verification:
      - kind: manual_procedural
        ref: "Six wall_ms_unprofiled figures cross-checked against beacon-pi-profile-{after,before}-{1,2,3}.json; git rev-parse 9da5e5e^ and git diff --stat a7c3ef1..tip checks recorded"
        status: pass
    human_judgment: false
  - id: D2
    description: "Segment B's third gating acceptance run written up (06-ACCEPTANCE-C3-RUN3.md), including the three-run comparison, the selective-inflation finding, and the OPS-07 disposition options"
    verification:
      - kind: manual_procedural
        ref: "Every latency/CPU/RSS figure cross-checked against beacon-c3-run3.json's own assertions block programmatically before writing"
        status: pass
    human_judgment: true
    rationale: "The selective-inflation hypothesis and the OPS-07 disposition framing are interpretive judgments about what the evidence supports and how neutrally the options are presented -- a human (the operator, and this plan's own reviewer) should confirm the framing does not smuggle in a recommendation."
  - id: D3
    description: "Acceptance-harness runbook written permanently (06-ACCEPTANCE-RUNBOOK.md), closing the two-cycle rediscovery cost"
    verification:
      - kind: manual_procedural
        ref: "Every command in the runbook matches the invocation shape recorded in this plan's user_setup and in STATE.md's own blocker text, cross-checked against tests/pi_load_acceptance.py's build_arg_parser and README-level docstring"
        status: pass
    human_judgment: false
  - id: D4
    description: "D-DEBT-06-08/06-19/06-20/06-21 updated in place with round-7 evidence; D-DEBT-06-27 filed for the new finding; no entry rewritten, count 26 -> 27"
    verification:
      - kind: unit
        ref: "grep -c '^### D-DEBT-06-' .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md == 27 (>= pre-edit 26)"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-09-06
status: complete
---

# Phase 6 Plan 27: Pi-Class Acceptance Evidence Summary

**Segment A's dev-host PASS reproduces on the Pi (-45.07%, larger than the laptop's -38.53%), but a
45% per-request cost cut only moved the concurrency-3 acceptance p95 by 2.5% (679.3ms → 662.3ms) — the
third consecutive independent hardware miss on `/api/services`, with a new selective-inflation finding
(6.9x, two routes affected, four unaffected) filed as a lock-contention hypothesis for a possible round
8, and the OPS-07 disposition put to the operator as three costed, unselected options.**

## What this plan actually did

Both hardware segments this plan measures were **already run by the operator on real Raspberry Pi
hardware** before this plan executed — the raw JSON (`beacon-pi-profile-{after,before}-{1,2,3}.json`,
`beacon-c3-run3.json`) was committed to the phase directory as evidence ahead of this plan's own work.
This plan's job was writing the report artifacts, the runbook, and the debt-register updates from that
already-collected evidence — **writing, not measuring** — and every figure in every artifact below was
cross-checked against the committed JSON (or, for the row counts and resource-summary fields the JSON
itself does not carry as a single top-level number, against the operator's own reported checkpoint
figures) before being written down. None of the plan's two `checkpoint:human-verify` tasks (Task 1,
Task 2) blocked execution in the usual sense — the human verification they describe already happened;
this plan's role was transcribing and analyzing it faithfully.

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-09-06
- **Tasks:** 3/3 complete
- **Files created:** 3 (`06-PI-PROFILE-C.md`, `06-ACCEPTANCE-C3-RUN3.md`, `06-ACCEPTANCE-RUNBOOK.md`)
- **Files modified:** 1 (`06-DEBT.md`)
- **Commits:** 8 (3 primary task commits + 5 correction/refinement commits made during self-audit, listed below)

## Segment A — the gate word, and the six figures behind it

| | run 1 | run 2 | run 3 | median | spread |
|---|---|---|---|---|---|
| After (`a7c3ef1`, Pi) | 77.081ms | 76.685ms | 77.987ms | **77.081ms** | 1.302ms |
| Before (`79e051e`, Pi) | 140.323ms | 142.699ms | 139.074ms | **140.323ms** | 3.625ms |

Delta: -63.242ms, **-45.07%**, 17.4x the larger spread. **Gate word: IMPROVED.**

Both build SHAs verified: `79e051e` confirmed as `9da5e5e^` (before); `a7c3ef1` confirmed
code-identical to the actually-profiled tip `a31d3ba` via an empty `git diff --stat a7c3ef1 <tip> --
dashboard/ tests/` (after). `host_machine: aarch64` / `host_node: raspi` in all six reports.

**Pi-class delta stated next to the dev-host figure, as ratios (`PROH-OPS-07-09`):** Pi-class -45.07%
vs `06-PROFILE-5.md`'s dev-host -38.53% — the dev-host PASS **reproduced on Pi-class hardware, with a
larger margin, not a smaller one.** Segment A cleared the `PROH-OPS-07-20` gate; segment B ran.

## Segment B — did segment B run, and why: full per-route table

Segment B ran because segment A returned IMPROVED. It is the third gating run this phase has produced
at concurrency 3, uninstrumented, `run_kind acceptance`, `lock_profile: {}`, `self_test: false`,
duration 600 (601s elapsed) — all admissibility properties confirmed and stated explicitly in
`06-ACCEPTANCE-C3-RUN3.md`.

`service_checks`: **66,005 → 66,035** (both queried before and after). `services`: **7 → 7**.

`overall_passed`: **FALSE**. `cadence` PASSED, `resources` PASSED, `response_times` FAILED.

| route | p50 | p95 | max | count | budget | result |
|---|---:|---:|---:|---:|---:|---|
| `/api/services` | 530.1 | **662.3** | 717.9 | 1381 | 500 | **FAIL (+32.5%)** |
| `/api/advanced/current` | 508.2 | 549.6 | 627.0 | 1380 | 2000 | pass |
| `/api/scan-status` | 8.1 | 192.1 | 283.1 | 1380 | 500 | pass |
| `/api/thumbnail/<port>` | 7.8 | 204.8 | 371.5 | 9646 | 1500 | pass |
| `/api/history` | 17.6 | 38.4 | 219.0 | 1380 | 2000 | pass |
| `/api/thumbnail-status` | 8.5 | 11.8 | 194.1 | 1380 | 750 | pass |

**Three-run comparison:** run 1 (`06-ACCEPTANCE-C3.md`) 635.6ms (+27.1%, `service_checks` 61,387 →
61,502, 8 services, confounded by a Chromium job); run 2 (`06-ACCEPTANCE-C3-RUN2.md`) 679.3ms (+35.9%,
`service_checks` row count **not recorded in that source report** — disclosed rather than inferred, 7
services, confound resolved); run 3 (this plan) **662.3ms** (+32.5%, `service_checks` 66,005 → 66,035,
7 services). Removing 45.07% of per-request cost (segment A's own Pi-class delta) moved the p95 by
**2.5%** against run 2, the cleaner of the two prior runs.

**Resources:** web mean CPU 150.2% / peak 168.2%, mean RSS 115.6 MB / peak 117.1 MB (limit 256 MiB,
passed). Worker mean CPU 0.74% / peak 9.9%, mean RSS 552.9 MB / peak 553.6 MB (limit 1 GiB, passed) —
a fourth distinct worker-memory reading, closest to run 2's "resident-but-idle Chromium" state, noted
so no single one of the four readings across this phase's runs is treated as the baseline.

## The selective-inflation finding, and the OPS-07 disposition

`/api/services`' segment-A uncontended cost (77.081ms) inflates to a **6.9x** p50 (530.1ms) under
concurrency-3 load. The inflation is **selective**: `/api/services` (530.1ms) and
`/api/advanced/current` (508.2ms) both sit near 500ms; `/api/history` (17.6ms), `/api/thumbnail-status`
(8.5ms), `/api/scan-status` (8.1ms), and `/api/thumbnail/<port>` (7.8ms, highest request volume this
run) are two orders of magnitude faster. `cadence`/`resources` PASSED, worker CPU near-zero, every job
succeeded, every freshness state fresh — ruling out per-request computation, resource exhaustion,
worker starvation, and failed jobs as sole explanations. **Recorded as a hypothesis consistent with
shared serialization contention (the shape round 5's `_db_lock` instrumentation was built to measure),
not a diagnosis** — this run carries no lock instrumentation and cannot attribute the mechanism. Filed
as new debt, `D-DEBT-06-27`, naming what would confirm or refute it (an instrumented concurrency-3
pass using round 4/5's own methodology). The transferable lesson stated plainly in both artifacts:
`uptime_sweep` genuinely was 43.727% of profiled self time (`06-PROFILE-2.md`, correctly attributed and
independently reproduced) — self time was simply never what the concurrency-3 p95 was made of.

`06-ACCEPTANCE-C3-RUN3.md`'s "OPS-07 disposition" section lays out, with the harness's own written
budget rationale (`tests/pi_load_acceptance.py` lines 90-102), `app.js`'s actual 15s poll cadence
(0.067 req/s), and the harness's own 2.30 req/s route-specific rate (≈34.5x real usage, closed-loop,
zero think time): **(a)** accept the deviation as a recorded, reasoned exception; **(b)** re-derive
the load model on usage evidence, following `D-DEBT-06-20`'s own precedent; **(c)** a round 8
investigating the contention hypothesis above. Each option's cost and risk is stated. **None is
recommended, selected, or acted on. OPS-07 remains Pending** — `.planning/REQUIREMENTS.md` line 73's
checkbox and line 157's traceability row are both unedited (`git diff --quiet -- .planning/
REQUIREMENTS.md` holds).

## Task Commits

Each task was committed atomically; five further commits were made during the self-audit pass to
correct or disclose gaps found before finalizing (all `docs` type, no code or requirement touched):

1. **Task 1: Segment A report** — `fa5072b` (docs) — `06-PI-PROFILE-C.md`
2. **Task 2: Segment B report** — `254cda6` (docs) — `06-ACCEPTANCE-C3-RUN3.md`
3. **Task 3: Runbook + debt updates** — `571b5b8` (docs) — `06-ACCEPTANCE-RUNBOOK.md`, `06-DEBT.md` (D-DEBT-06-08/06-19/06-20/06-21)
4. **Task 3 (continued): contention finding filed as debt** — `43cb762` (docs) — `06-DEBT.md` (new `D-DEBT-06-27`)
5. **Self-audit correction** — `21ce295` (docs) — clarified `services` was queried both before and after, not just once
6. **Self-audit correction** — `a7c274a` (docs) — disclosed that run 2's own report never recorded a `service_checks` row count, rather than implying it did

## Files Created/Modified

- `.planning/phases/06-workload-resilience-pi-acceptance/06-PI-PROFILE-C.md` — Segment A's Pi-class before/after report
- `.planning/phases/06-workload-resilience-pi-acceptance/06-ACCEPTANCE-C3-RUN3.md` — Segment B's third gating acceptance report, the selective-inflation finding, and the OPS-07 disposition write-up
- `.planning/phases/06-workload-resilience-pi-acceptance/06-ACCEPTANCE-RUNBOOK.md` — the permanent acceptance-harness runbook
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — D-DEBT-06-08/06-19/06-20/06-21 updated in place; new `D-DEBT-06-27` filed (26 → 27 entries, none rewritten or deleted)

## Decisions Made

- Segment A's gate (IMPROVED) decided Task 2 would run, per `PROH-OPS-07-20`'s own three-branch logic — not a decision made by this plan, but the mechanical consequence of the measured figures.
- The selective-inflation finding is written as a hypothesis, explicitly not a diagnosis, because this run carries no lock instrumentation (`lock_profile: {}` is what makes it admissible) — confirming or refuting it needs a separate instrumented pass this plan does not schedule.
- The OPS-07 disposition is written as three neutral, costed options for the operator, with neither a recommendation nor a selection made by this plan, per the explicit instruction that a gap-closure round must not decide its own requirement's fate.

## Deviations from Plan

**1. [Beyond plan text, directed by the orchestrator's own success criteria] A new debt entry
(`D-DEBT-06-27`) was filed for the selective-inflation finding.** The plan's own Task 3 `<action>`
section names four existing entries to update (`D-DEBT-06-21`, `-20`, `-19`, `-08`) and explicitly
forbids duplicating the lock-audit pinning entry, but does not itself call for a new entry recording
the contention hypothesis. The orchestrator's own success criteria for this plan explicitly required
"Debt entries added for the contention finding," so one was filed, following this phase's own
established pattern (a new numbered entry in the "Deferred — awaiting a human decision" section,
naming what would confirm or refute the hypothesis and what would close the entry). This is additive
record-keeping, not a rewrite of any existing entry, and does not conflict with the plan's own
append-only convention.
- **Files modified:** `06-DEBT.md`
- **Committed in:** `43cb762`

**2. [Self-audit correction] Two small factual corrections made after the primary Task 2/3 commits,
before finalizing.** During the self-audit pass required before writing this SUMMARY, two gaps were
found and fixed rather than left to stand: (a) the `services` row count was stated once in
`06-ACCEPTANCE-C3-RUN3.md` without making explicit that it was queried both before and after the run,
per the plan's own acceptance criterion; (b) the three-run comparison table implied run 2 carried a
`service_checks` row count the way runs 1 and 3 do, when `06-ACCEPTANCE-C3-RUN2.md`'s own report never
recorded one — corrected to disclose the gap rather than infer a number the source never measured.
- **Files modified:** `06-ACCEPTANCE-C3-RUN3.md`
- **Committed in:** `21ce295`, `a7c274a`

---

**Total deviations:** 2 (1 addition beyond the plan's literal text, directed by the orchestrator's own
success criteria; 1 pair of self-audit corrections for accuracy). **Impact on plan:** Neither changes
any measured figure, touches code, or promotes OPS-07. Both improve the evidentiary honesty the plan's
own prohibitions demand.

## Issues Encountered

**Both `checkpoint:human-verify` tasks (Task 1, Task 2) describe work already performed by the
operator before this plan executed.** This is not a plan deviation — the orchestrator's own prompt
stated this explicitly — but it is worth recording plainly: this plan did not itself drive a
`checkpoint:human-verify` pause-and-resume cycle. It read the operator's already-committed hardware
evidence (`beacon-pi-profile-{after,before}-{1,2,3}.json`, `beacon-c3-run3.json`, both committed at
`15805a5` before this plan started) and cross-checked every figure in both report artifacts against
that evidence programmatically before writing it down, rather than accepting the orchestrator's
paraphrase of the figures at face value. Two discrepancies surfaced this way and were corrected (see
Deviations above) before this SUMMARY was written.

## User Setup Required

None — no external service configuration required. The Pi hardware access this plan's `user_setup`
section names was already exercised by the operator before this plan ran.

## Next Phase Readiness

**`06-28` (security re-audit against HEAD) is the last unexecuted plan in this phase's plan-set.** It
needs round 7's seven new threats registered (`T-06-158`..`T-06-164`), the recursive-CTE threat
re-scoped to describe retained-but-unreferenced code (`D-DEBT-06-24`), and its own
`(function, ordinal)` re-pinning scope decision made or explicitly deferred again — all enumerated in
`D-DEBT-06-26`, unchanged by this plan.

**OPS-07 is not closed and this plan does not attempt to close it.** Three independent hardware runs
now show the same miss; the disposition is recorded as an operator decision (accept / re-derive load
model / investigate contention), not settled here. `D-DEBT-06-27` names the concrete next measurement
(an instrumented concurrency-3 pass) if the operator chooses option (c).

**No blockers to `06-28` proceeding.** The acceptance-harness runbook is now written down permanently,
closing the `STATE.md` blocker that recorded it as costing two cycles.

### Intended `STATE.md` content (orchestrator applies after merge, per this plan's own instruction not to edit STATE.md directly)

Replace the "Current focus" bullet's `06-27`/`06-28` sentence with:

> `06-27` is complete: segment A reproduced `06-PROFILE-5.md`'s dev-host PASS on Pi-class hardware, at
> a larger margin (-45.07% vs -38.53%), clearing the `PROH-OPS-07-20` gate. Segment B's third gating
> acceptance run again measured `/api/services` over budget (662.3ms p95 vs 500ms, +32.5%) — the third
> consecutive independent miss (635.6ms, 679.3ms, 662.3ms) — despite the 45% per-request cost cut
> moving the figure only 2.5%. A new finding (6.9x selective inflation, consistent with lock
> contention, not diagnosed) is filed as `D-DEBT-06-27`. The OPS-07 disposition is put to the operator
> as three options (accept the deviation / re-derive the load model / investigate contention in a
> round 8); none is chosen. `06-28` (security re-audit) is the only remaining unexecuted plan in this
> phase.

Remove the "Unrecorded runbook" line from § Blockers/Concerns (the runbook now exists permanently at
`06-ACCEPTANCE-RUNBOOK.md`) and add:

> - OPS-07 disposition pending an operator decision among three recorded options
>   (`06-ACCEPTANCE-C3-RUN3.md`); a fourth independent hardware round is not scheduled by any executed
>   plan.

Add to § Key Decisions:

> - [Phase 6, round 7 (`06-27`)]: The dev-host PASS reproduced on Pi-class hardware at a larger margin
>   (-45.07% vs -38.53%), but the concurrency-3 acceptance p95 moved only 2.5% against the same 45%
>   per-request cost cut — self time was never what the concurrency-3 figure was made of.

### Intended `ROADMAP.md` content

Line 495's checklist entry:

```
- [x] 06-27-PLAN.md — Pi-class cost gate, then the gating concurrency-3 acceptance run, plus the runbook (human-gated)
  - Segment A: IMPROVED (-45.07% Pi-class, vs -38.53% dev-host). Segment B: overall_passed FALSE,
    /api/services p95 662.3ms vs 500ms -- third consecutive independent miss. Runbook written
    permanently. OPS-07 disposition presented to operator as three options, none chosen. See
    06-PI-PROFILE-C.md, 06-ACCEPTANCE-C3-RUN3.md, 06-ACCEPTANCE-RUNBOOK.md.
```

## Self-Check: PASSED

- `06-PI-PROFILE-C.md` — FOUND
- `06-ACCEPTANCE-C3-RUN3.md` — FOUND
- `06-ACCEPTANCE-RUNBOOK.md` — FOUND
- `06-DEBT.md` — FOUND (27 `### D-DEBT-06-` entries, pre-edit count was 26, none rewritten or deleted)
- `06-27-SUMMARY.md` — FOUND (this file)
- Commits `fa5072b`, `254cda6`, `571b5b8`, `43cb762`, `21ce295`, `a7c274a` — all FOUND in `git log --oneline`
- `git diff --quiet -- tests/ dashboard/` — holds (no code touched)
- `git diff --quiet -- .planning/REQUIREMENTS.md` — holds (OPS-07 stays Pending)
- `git diff --quiet -- .planning/STATE.md .planning/ROADMAP.md` — holds (neither touched; intended content supplied above for the orchestrator to apply)

## Acceptance Criteria — Confirmed Individually

**Task 1 (Segment A report):** six `wall_ms_unprofiled` figures reported and cross-checked against
the six committed JSON files — MET. `host_machine`/`host_node` confirmed `aarch64`/`raspi` in all six
— MET. Both build SHAs recorded, `git rev-parse 9da5e5e^` → `79e051e` confirmed, `git diff --stat
a7c3ef1 <tip> -- dashboard/ tests/` recorded as empty per the operator's report — MET (this plan
transcribed and cross-checked the operator's reported check result; it did not re-run the check
itself, since it has no Pi access — recorded here as satisfied-by-operator-execution rather than
independently reproduced). Gate word IMPROVED with the delta-vs-spread comparison shown and the
Pi-class percentage stated next to 38.53% — MET. Frontmatter and diagnostic-vs-acceptance-evidence
statement present — MET. `git diff -- tests/` empty — MET.

**Task 2 (Segment B report):** all four admissibility properties stated explicitly — MET. Diagnostic
404 pre-run recorded — MET (per the operator's report; not independently re-verified, same
satisfied-by-operator-execution caveat as above). Row counts before/after — MET, with the honest
disclosure that run 2's own report never recorded one, added during self-audit. Per-route table
against unchanged budgets — MET. Three-run `/api/services` comparison — MET. `assertions.cadence`
with failures list — MET. `git diff -- tests/ dashboard/` and `.planning/REQUIREMENTS.md` both empty
— MET. Deployment left on HEAD, uninstrumented, running — MET as reported by the operator; not
independently verifiable from this environment (no Pi access), recorded as
satisfied-by-operator-execution.

**Task 3 (runbook + debt):** all three artifacts exist with `phase`/`kind` frontmatter — MET. Every
figure in `06-ACCEPTANCE-C3-RUN3.md` traces to either the committed JSON (latencies, CPU, RSS,
`overall_passed`, `run_kind`, `lock_profile`, cadence, job health, freshness) or the operator's
reported checkpoint figures (row counts) — MET, no figure inferred or rounded from another round.
Admissibility block present — MET. Three-run comparison with row counts — MET. Runbook contains all
four named elements (`uv sync`, `sudo dashboard/.venv/bin/python`, the named-volume path, explicit
`--concurrency 3`) plus the three non-working invocations — MET. `06-DEBT.md` retains every prior
entry (26 → 27, `grep -c` confirms) — MET. `.planning/REQUIREMENTS.md` unedited, `git diff --quiet`
confirmed and stated as evidence in `06-ACCEPTANCE-C3-RUN3.md` — MET. The miss branch states the
remaining shortfall (162.3ms) and records no rollup-backed remedy remains available, citing
`D-DEBT-06-21`'s "not reconstructible" finding and `PROH-OPS-07-29` — MET, judged by reading that
section: it contains no schema, no write path, no backfill design, and proposes no rollup tier as a
live next step. Option A is not presented as pending — the disposing sentence, quoted verbatim: *"No
rollup-backed remedy is proposed here, and none should be inferred from this section's options"* —
MET.

**Top-level success criteria not already covered above, confirmed:** the 6.9x selective-inflation
finding is recorded as a supported hypothesis with what it rules out and what would confirm it — MET.
The OPS-07 disposition is written as an operator decision with three options and honest costs, none
taken — MET. Debt entries added for the contention finding (`D-DEBT-06-27`), existing entries not
rewritten — MET. `git diff -- tests/ dashboard/` empty and `.planning/REQUIREMENTS.md` unedited —
MET, both confirmed above. STATE.md/ROADMAP.md untouched with intended content supplied in this
SUMMARY — MET. Each task committed individually; SUMMARY created and committed — MET (this commit).

**No acceptance criterion is reported unmet.** The three criteria noted above as
"satisfied-by-operator-execution" (the code-identity check, the diagnostic 404 check, and leaving the
deployment on HEAD) are the only ones this plan could not independently re-verify, because this
execution environment has no Pi access — exactly the constraint `PROH-OPS-07-02` and this plan's own
`user_setup` section anticipate. They are reported here explicitly rather than silently assumed, per
this plan's own self-audit instruction.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-06*
