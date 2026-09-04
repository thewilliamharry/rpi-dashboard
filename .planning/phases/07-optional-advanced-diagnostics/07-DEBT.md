---
phase: 7
slug: optional-advanced-diagnostics
kind: debt-and-dispositions
created: 2026-09-04
---

# Phase 7 — Tracked Debt & Revision Dispositions

> A later verifier must read this before re-litigating anything in this phase: what was deliberately
> **not** done, why, and what evidence this phase already produced for the next evaluation to start from.

---

## D-DEBT-07-01 — the acceptance harness cannot see a 404; `_load_worker` records it as a fast success

| Field | Value |
|---|---|
| **Raised by** | `07-03-PLAN.md`'s objective, `PROH-DIA-09-01` |
| **Status** | **Recorded — measured evidence, not fixed. This phase is forbidden from modifying `tests/pi_load_acceptance.py`.** |
| **Owner** | The next OPS-07 round in Phase 6. |

**What it is.** `tests/pi_load_acceptance.py::_load_worker` (lines 425-446) issues each request via
`session.get(url, timeout=10)` and discards the result entirely — it records only `elapsed_ms`, never
`response.status_code`. `assert_response_times` (lines 373-401), the oracle that turns those latencies
into a pass/fail, receives only the `latencies_by_route` dict it built — it has no status-code
information to inspect even in principle. A 404 answered in under a millisecond is therefore recorded
as a fast, budget-clearing **success**, indistinguishable in the recorded evidence from a real 200.

**Why this matters for `PROH-DIA-09-01`.** `/api/advanced/current` is the single most expensive route
in Phase 6's own acceptance mix (584s CPU / 1,090,992ms off-CPU across 750 requests in round 5b,
`06-DEBT.md`). An operator (or a shortcut-seeking acceptance run) that disables
`ENABLE_ADVANCED_DIAGNOSTICS` before running OPS-07 would not merely make the run easier — every
`/api/advanced/current` sample in that run would be a near-instant 404, and the harness's own oracle
would report the route's 2000ms budget cleared with no indication anywhere in the report that the
route measured was never actually exercised. `07-03`'s `AcceptanceConfigurationGuardTests` guards the
**shipped default** through the real parser; it does not and cannot guard against an operator
exporting a disabling shell variable immediately before running an acceptance round by hand. This
entry records the second half of that gap honestly rather than implying the compose-default guard
closes it.

**MEASURED — one-time reproduction, 2026-09-04.** Run against a disabled application
(`ENABLE_ADVANCED_DIAGNOSTICS=0`) served under `werkzeug.serving.make_server`, using the harness's own
`_load_worker`, `_routes_for_ports([])`, `assert_response_times` and `ROUTE_BUDGETS_MS` — a 3-second
bounded window, single worker thread, no thumbnail ports (no seeded services). This reproduction is
**one-time recorded evidence**, deliberately not left as a standing test: a standing test asserts what
must remain true, and "the harness cannot see a 404" is a defect this repository wants fixed, not
pinned.

| Quantity | Value | Produced by |
|---|---|---|
| Samples collected for `/api/advanced/current` | 389 (3s window) | the harness's own `_load_worker` |
| p50 latency | 0.927ms | the harness's own `_load_worker` |
| **p95 latency** | **1.225ms** | **the harness's own `_load_worker`** |
| max latency | 4.467ms | the harness's own `_load_worker` |
| `assert_response_times` result for this route | `{'passed': True, 'failures': []}` | **the harness's own oracle, `assert_response_times`** |
| Route budget (`ROUTE_BUDGETS_MS['/api/advanced/current']`) | 2000ms | declared constant, unmodified |
| **Observed HTTP status** | **404** | **a separate direct probe (`requests.get`), issued OUTSIDE the harness — `_load_worker` never inspects this** |

**Which of these the harness itself produced, stated explicitly per the plan's own instruction:** the
p50/p95/max latencies and the `assert_response_times` pass verdict were all produced by the harness's
own code paths, unmodified. The **status code was not** — it could not be, because `_load_worker`
discards `session.get`'s return value; that discarding is the finding itself. The 404 above came from
one ordinary `GET` issued directly against the same running server, outside `_load_worker`, immediately
after the harness's own 3-second window closed against the same disabled application. Recording the two
side by side is the point: a latency set the harness produced (and passed, comfortably, at 1.225ms
against a 2000ms budget), and a status the harness never looked at (404 — the very failure mode this
entry names).

**What this does not do.** It does not close the hole. The fix — `_load_worker` treating a non-2xx
response as a failed (or at minimum status-tagged) sample rather than a fast one — requires editing
`tests/pi_load_acceptance.py`, which this phase's scope fence forbids
(`git status --porcelain tests/pi_load_acceptance.py` must report nothing at the end of this phase).
This entry exists so the hole is on the record with numbers behind it, not left implicit inside
`PROH-DIA-09-01`'s prose.

**What would need to be true to close this entry.** The next OPS-07 round in Phase 6 (the only party
with standing to modify `tests/pi_load_acceptance.py`) changes `_load_worker` to record each sample's
response status alongside its latency, and `assert_response_times` (or a sibling oracle) to fail a
route whose samples include a non-2xx status the route's own contract does not expect — closing the gap
this entry measures rather than merely re-measuring it in a future round.
