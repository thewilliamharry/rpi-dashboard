---
phase: 01
slug: behavioral-safety-runtime-ownership
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
block_on: high
created: 2026-08-24
verified: 2026-08-24
register_authored_at_plan_time: true
threats_total: 106
threats_closed: 106
distinct_threat_ids: 106
retroactive_audit: true
---

# Phase 01 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

This file was written retroactively on 2026-08-24. Phase 1 executed and passed verification before the security capability existed in this project, so it never had a SECURITY.md — it was the only one of the four built phases without one, and it owns the outbound-target, TLS, redirect, webhook and mutation-protection surface. The threat register itself is **not** retroactive: all 23 PLAN.md files carry a `<threat_model>` block and a full STRIDE register table authored at plan time.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Browser → Flask web process | Trusted-LAN operator UI; no accounts, no auth | Service metadata edits, scan/preview triggers, presentation preferences |
| Flask web process → SQLite | Shared WAL database, concurrent with the worker | Metadata, events, telemetry, queue rows, runtime state |
| Worker process → SQLite | Sole scheduler owner; all writes epoch-fenced | Scheduled mutations, heartbeat, lease, job outcomes |
| Beacon → monitored LAN services | Probes, HTML fetches, browser previews | Outbound HTTP(S) requests, TLS handshakes |
| Beacon → operator webhook | Strict verified-TLS outbound notification | Alert payloads |
| Compose `migrate` / `recovery` one-shots → data volume | Exclusive, pre-service database access | Schema migrations, backup restore |

---

## Threat Register

The full 106-row register lives in the per-plan `<threat_model>` STRIDE tables across `01-01-PLAN.md` … `01-23-PLAN.md`. Summarized here by outcome; every row was individually verified against source on 2026-08-24.

| Severity × Disposition | Count | Status |
|------------------------|------:|--------|
| high / mitigate | 52 | 52 closed |
| medium / mitigate | 39 | 39 closed |
| low / mitigate | 6 | 6 closed |
| low / accept | 9 | 9 closed (rationale re-confirmed true of current code) |
| **Total** | **106** | **106 closed** |

All 52 high-severity threats were verified individually with file:line evidence or a re-run of the pytest command the plan's `verification_evidence` names. Medium and low threats were verified by component group (runtime ownership & lifecycle, module boundaries & repositories, browser/preview lifecycle, migrations/backup/recovery, outbound policy & transport, durable queues, UI safety, input validation & error envelopes, lifecycle cleanup).

### Threats found OPEN by this audit, and closed by it

| Threat ID | Category | Component | Severity | Finding | Resolution |
|-----------|----------|-----------|----------|---------|------------|
| T-01-14 | Denial of service | Playwright lifecycle (`dashboard/app.py`) | medium | **Real defect.** `_legacy_screenshot_service` took `_screenshot_sem.acquire()` at line 1006, but the `finally: _screenshot_sem.release()` at line 1082 belonged to a *second* `try` opened at line 1020. The `except OutboundPolicyError: return` at line 1013 returned between them, leaking the permit. `_screenshot_sem = threading.Semaphore(1)`, so a single refusal permanently wedged every later preview in the process. Three of the four declared mitigation clauses (lazy worker-only construction, serialized ownership, deadline budgets) were present; the `finally` cleanup clause was not. | **FIXED** — `dashboard/app.py`: the acquisition moved below the planning block so no path can return between `acquire()` and its `finally`, and kept above `started` so the browser budget still excludes queue wait. Regression: `tests/test_outbound_policy.py::test_a_refused_preview_target_releases_the_screenshot_permit` (both refusal reasons) and `::test_repeated_refused_preview_targets_leave_capacity_for_a_real_capture`. |
| T-01-88 | Denial of service | APScheduler/Chromium shutdown | medium | Declared mitigation's third clause — "closes Chromium after preview count reaches zero" — was unreachable once T-01-14 fired. A blocked `acquire()` is not an exception, so `admit()`'s `finally` never ran, `_active['preview']` never decremented, and `WorkerAdmission.drain()` (`worker_main.py:136-139`, an untimed `Condition.wait()`) never returned — leaving `_finalize_worker_lifecycle` unable to reach `shutdown_browser()` or `release_worker_lease()`. J1's heartbeat kept renewing the lease on a separate executor, so no successor could take over. | **CLOSED by removing the trigger** (T-01-14's fix). See Recommended Follow-Up below for the defence-in-depth item deliberately not taken here. |
| T-01-111 | Tampering / DoS | Worker admission & drain | **high** | The auditor classified this CLOSED on its declared clauses — all four are present and correct in `worker_main.py` — while flagging that the threat's *named outcome*, "partial admission closure **or drain deadlock**", was demonstrably reachable through T-01-14 in a different component (`dashboard/app.py`), and explicitly surfaced the classification as a judgment call rather than deciding it silently. | **Adjudicated OPEN at high severity**, then closed by the T-01-14 fix. A threat register names outcomes to prevent, not patterns to find; marking this closed while its named outcome was reachable would verify the pattern rather than the property. This is the same failure mode the Phase 03 validation audit corrected on the same day. With T-01-14 fixed the deadlock is unreachable and T-01-111 is genuinely closed. |

---

## Accepted Risks Log

All nine are `low / accept` and were authored at plan time. Each stated rationale was re-checked against the current code on 2026-08-24 — not assumed.

| Risk ID | Threat Ref | Rationale | Still true? | Accepted By | Date |
|---------|------------|-----------|-------------|-------------|------|
| R-01 | T-01-05 | Browser warnings expose only freshness and recovery state; no internal addresses, exceptions, or secrets | ✅ `/api/scan-status` (`app.py:2887-2921`) emits heartbeat/lease/recovery fields only, never `owner_token`; `error_class` is a fixed vocabulary (`app.py:649-662`) | Operator (plan-time) | 2026-08-24 |
| R-02 | T-01-15 | Existing event/alert rows are the local audit evidence; no multi-user attribution in scope | ✅ `events` has no principal column; product is single-operator, no accounts | Operator (plan-time) | 2026-08-24 |
| R-03 | T-01-25 | Recovery messages disclose only fixed `/data` concepts and catalog IDs; raw rows and exceptions redacted | ✅ every `RecoveryError` is one of 7 fixed literals; `main()` prints only `str(exc)` (`recovery.py:494`) | Operator (plan-time) | 2026-08-24 |
| R-04 | T-01-41 | Bounded API fields plus wrapping/ellipsis and layout tests keep the dashboard usable under hostile strings | ✅ `test_ui_states.py:874-988` renders a 130-char IPv6 URL and unbroken names, asserting `scrollWidth ≤ 360` in both themes | Operator (plan-time) | 2026-08-24 |
| R-05 | T-01-90 | Worker epoch stays in internal runtime JSON and process calls; exceptions generic; no token exposure | ✅ `owner_token` appears in no log/jsonify/f-string across `dashboard/`; `WorkerAuthority.owner_token` is `field(repr=False, compare=False)` (`worker_authority.py:20`) | Operator (plan-time) | 2026-08-24 |
| R-06 | T-01-104 | Failure labels use stable row IDs and redacted identity roles; tokens never in messages or fixtures | ✅ `test_worker_ownership_matrix.py:207` explicitly asserts the token is absent from the test id | Operator (plan-time) | 2026-08-24 |
| R-07 | T-01-109 | Authority repr and assertion errors redacted; tokens absent from logs, events, JSON, exception strings | ✅ same `repr=False` field plus codebase-wide grep; `LeaseLost('worker lease was lost')` is generic | Operator (plan-time) | 2026-08-24 |
| R-08 | T-01-115 | Tokens never enter delivery keys, logs, events or API; webhook errors remain destination-free | ✅ `app.py:1848-1849` key material is `now:port:prev:online` only; errors are `'policy_'+reason` / `'delivery_error'` | Operator (plan-time) | 2026-08-24 |
| R-09 | T-01-SC | No npm/pip/cargo install; no dependency or lockfile change in this phase | ✅ no Phase-01 commit touches `dashboard/uv.lock` or `dashboard/pyproject.toml` | Operator (plan-time) | 2026-08-24 |

---

## ASVS L1 Coverage

| Chapter | Exercised | Basis |
|---------|-----------|-------|
| V1 Architecture, Design & Threat Modeling | Yes | Import-side-effect freedom (AST + subprocess), single-composition-root dispatch, enforced dependency direction |
| V4 Access Control | Yes | Global `before_request` host/UI-header/origin gate; durable epoch fencing after `BEGIN IMMEDIATE`; marker-authorized restore |
| V5 Validation, Sanitization & Encoding | Yes | Exact-type JSON validation, field allowlist, URL parse/port/credential rejection, `textContent`-only rendering (zero `innerHTML`) |
| V7 Error Handling & Logging | Yes | Fixed error vocabularies at every boundary |
| V8 Data Protection | Yes | Inventory report allowlisted to structure; opaque epoch never logged or serialized |
| V9 Communications | Yes | Socket pinned to validated numeric address with SNI/`assert_hostname` preserved; redirects disabled and re-planned; strict verified webhook |
| V11 Business Logic | Yes | Row leases, deadlines, attempt counts, supersession, conditional terminal writes |
| V12 Files & Resources | Yes (was Partial) | Path/symlink/inode/`O_NOFOLLOW` hardening and fsync boundaries were already strong. The process-resource half is exactly where T-01-14 sat — `_screenshot_sem` was the one resource acquisition in the codebase without a `finally`, and it had no release-discipline test. Both are now closed. |
| V13 API / Service Boundaries | Yes | Owner-free web writes vs owner-gated worker writes proven separately |
| V14 Configuration | Yes | Bounded env parsing with subprocess matrix; Compose hardening asserted by tests |
| V6 Stored Cryptography | Named but not applicable | Cited in `01-07-PLAN.md` for T-01-33. Phase 1 stores no cryptographic material; TLS verification posture is a V9 concern. A mis-citation, not a gap. |

---

## Register Discrepancies Found

Recorded so future tooling does not silently mis-count.

1. **Threat IDs are not contiguous.** `T-01-91` … `T-01-100` do not exist anywhere in the repository; plans 01-21 → 01-23 restart at `T-01-101`. The total (106) is correct and nothing was dropped, but any tool that walks the ID range will under- or over-count.
2. **`T-01-SC` breaks the `T-NN-NN` ID convention.** The supply-chain threat is declared in plans 01-20 → 01-23 and tabled in each, but its non-numeric suffix means naive extraction misses it. This audit's first extraction pass did exactly that and produced 105 instead of 106; the auditor caught it.
3. **No `## Threat Flags` section exists in any of the 23 SUMMARY.md files.** These plans predate the security capability, so the executor-side new-attack-surface channel produced no signal at all. Its silence is not evidence that no new surface appeared — T-01-14 is precisely the kind of finding that channel exists to raise.

---

## Recommended Follow-Up (not blocking)

**Bound `WorkerAdmission.drain()`.** `worker_main.py:136-139` is an untimed `Condition.wait()`. T-01-88's trigger is now removed, so no known path wedges it — but any future job that blocks rather than raises would hang worker shutdown and lease handoff with no timeout and no log. A bounded `drain(timeout)` that degrades to a logged forced shutdown would make the class unreachable rather than the instance. Deliberately not changed here: altering worker shutdown semantics is a behavioral change beyond the scope of a security audit, and is better done as planned work with its own verification.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-08-24 | 106 | 106 | 0 | `/gsd-secure-phase 01` — gsd-security-auditor (opus), findings independently reproduced by the orchestrator |

**Verification basis:** full suite re-run green before and after the fix — 561 passed / 470 subtests before, **563 passed / 472 subtests** after (the two new regression tests). The T-01-14 defect was independently reproduced by the orchestrator before the fix (permits 1 → 0, subsequent acquire blocked), and the new regression tests were confirmed to fail against the unfixed tree and pass against the fixed one — they are real gates, not green-by-construction.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log, each rationale re-confirmed against current code
- [x] `threats_open: 0` confirmed
- [x] One real defect found, fixed, and pinned by a regression proven to fail without the fix
