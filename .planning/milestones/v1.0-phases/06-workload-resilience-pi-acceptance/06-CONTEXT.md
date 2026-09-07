# Phase 6 Context: Workload Resilience & Pi Acceptance

**Captured:** 2026-08-28
**Source:** Targeted decisions captured during `/gsd-plan-phase 6`, after `06-RESEARCH.md` surfaced
open questions that had no code precedent and no artifact to settle them.

> **Provenance note — read this before treating the file as a normal CONTEXT.md.**
> A full `/gsd-discuss-phase` pass was deliberately declined for this phase. This file is NOT the
> output of that workflow and does not carry its breadth. It records exactly two decisions the user
> answered directly. Everything else in this phase remained an open planner decision and was
> validated by `gsd-plan-checker` — absence of a decision here means "not decided", never
> "planner's discretion, unrecorded". (Same pattern as `05-CONTEXT.md`.)

---

## Decisions

<decisions>
- **D-01 — WAL only; `_db_lock`'s scope is not narrowed in this phase** Enable WAL + `busy_timeout`
  and prove concurrent web/worker access is corruption-free, but leave `_db_lock`'s scope unchanged.
  Narrowing it becomes the `D-DEBT-06-01` follow-up, citing this phase's evidence. Full rationale
  and scope fence below.
- **D-02 — preview retry budget and thumbnail TTL are the planner's, but must be documented** No
  code precedent fixes them; the user asked for defensible, env-configurable defaults with recorded
  rationale rather than hand-specifying the numbers. Chosen values below.
</decisions>

The two sections that follow carry each decision's full rationale and scope fences. They are the
authoritative statement; the block above exists so the decision-coverage gate can enumerate them.

### D-01 — WAL only; `_db_lock`'s scope is not narrowed in this phase

**Decision:** Enable WAL + `busy_timeout` on the SQLite connection path and prove concurrent
web/worker access is corruption-free under a bounded stress run. Do **not** change `_db_lock`'s
scope.

**Rationale:** The web process serializes all DB access behind one process-global `_db_lock`
because gunicorn runs `--workers 1 --threads 8`. `06-RESEARCH.md` Pitfall 4 rates narrowing it a
real risk, and `AR-03-01` is an existing accepted-risk note covering a narrow exception.
`PROJECT.md` grouped the `_db_lock` question with the WAL decision for Phase 6; offered the choice,
the user took the smaller blast radius. WAL is separately verified as never set anywhere in the
codebase today — `journal_mode` is only ever read, at `inventory.py:134,147`.

**Scope fence:**
- `_db_lock` may be read and exercised to the extent OPS-04's concurrency testing needs to *prove*
  current behavior correct — never to change its scope.
- The narrowing is recorded as `D-DEBT-06-01` in `06-DEBT.md`, citing the evidence this phase
  produces, and is explicitly out of scope here.
- An acceptance criterion requires a scoped `git diff` proving `_db_lock` is unchanged.

**Where it lands:** `06-01-PLAN.md`, `06-05-PLAN.md` (incl. `PROH-OPS-04-02` and `D-DEBT-06-01`).

### D-02 — preview retry budget and thumbnail TTL are the planner's, but must be documented

**Decision:** The preview retry count, backoff shape, and thumbnail TTL are the planner's to choose.
Each must be specified, exposed as an env-configurable knob, and carry recorded rationale.

**Rationale:** No existing convention fixes any of the three. `THUMB_REFRESH_DAYS=1` is a *refresh*
cadence, not a retry budget or a storage TTL, so it cannot be borrowed as a precedent. Offered the
choice between specifying the numbers personally and delegating with a documentation requirement,
the user delegated — so the obligation shifts to rationale that survives review.

**Values chosen and their justification:**

| Knob | Value | Rationale |
|---|---|---|
| `PREVIEW_MAX_ATTEMPTS` | 3 | 3 × the 27s browser capture budget stays well inside the 1800s request deadline |
| `PREVIEW_RETRY_BASE_SECONDS` | 60 | mirrors the existing `telemetry_retry_*` doubling precedent |
| `PREVIEW_RETRY_MAX_SECONDS` | 600 | backoff cap for the same doubling curve |
| `THUMBNAIL_TTL_DAYS` | 7 | set equal to `EXPIRE_DAYS`, so a thumbnail never outlives its service |
| `THUMBNAIL_STORE_MAX_BYTES` | 67108864 (64 MiB) | total-store byte budget sized for Pi-class hardware |

**Constraint:** all five land in `config.py` via `_positive_int` with documented fallback behavior,
and in `docker-compose.yml`'s shared `x-beacon-common` environment anchor.

**Where it lands:** `06-01-PLAN.md`, `06-02-PLAN.md`, `06-03-PLAN.md`.

---

## Claude's Discretion

Task slicing, wave assignment, test structure, migration mechanics, and the shape of the Pi load
harness were left to the planner and validated by `gsd-plan-checker` across three verification
rounds.

## Not asked, not decided

The user was not asked about, and this file claims no decision on: the eventual `_db_lock`
narrowing (deferred as `D-DEBT-06-01`); whether the deployed production database is already in WAL
mode (handled as non-blocking evidence capture in `06-05` Task 1, with an `unverified` fallback
recorded as `D-DEBT-06-03`); and whether real Pi hardware is reachable at execution time (OPS-07's
harness is built and checked in regardless; the hardware run is human-gated per
`06-VALIDATION.md` § Manual-Only Verifications).
