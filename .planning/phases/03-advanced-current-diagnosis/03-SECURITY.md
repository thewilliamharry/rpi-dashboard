---
phase: 03
slug: advanced-current-diagnosis
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
block_on: high
created: 2026-08-20
register_authored_at_plan_time: true
threats_total: 142
threats_closed: 142
distinct_threat_ids: 128
---

# Phase 03 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

**Register key convention:** `{plan}/{threat_id}`, not `{threat_id}` alone. The 142 register rows
use only 128 distinct Threat IDs — fourteen IDs are reused across plans (`T-03-80`–`T-03-87` in
both 03-13 and 03-15; `T-03-88`–`T-03-89` in both 03-14 and 03-15; `T-03-90`–`T-03-93` in both
03-14 and 03-16). The colliding pairs describe genuinely different threats — `T-03-80` is the
hollow `collection_gaps` property in 03-13 but the `dispatch_callback` outcome-write failure
branch in 03-15 — so a register keyed on ID alone would silently merge or overwrite 14 rows.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Browser → `/api/advanced/current` | GET-only, parameterless read surface. The advanced workspace performs no mutation request of any kind. | Diagnosis snapshot JSON (host, service, settings, pipeline evidence) |
| SQLite durable rows → diagnosis composer | Each `telemetry_coverage` and `telemetry_streams` row carries a distinct bounded fact; the composer must never transfer a fact from one row onto another. | Per-row collection evidence |
| Diagnosis composer → browser JSON | The payload is the operator's sole basis for trusting current collection health; a wrong `open`, `actionable`, or `kind` becomes an operator-visible false claim. | Exception kinds, freshness verdicts, gap intervals |
| Worker authority → job outcome writers | Only the current lease-holding worker may mutate a job health row; a stale worker must be fenced. | `WorkerAuthority` fence, job health transitions |
| Web process → worker process | The Flask diagnosis path must stay effect-free: reads only, no scheduler, probe, or preview operation reachable. | Read-only repository access |
| Bounded read cap → completeness disclosure | Any list the composer caps must disclose truncation over the same population its count describes. | `truncated` flags, `count` fields |

---

## Threat Register

142 threats across 23 plans. **All 142 closed.** The register itself lives in each plan's
`<threat_model>` block (`.planning/phases/03-advanced-current-diagnosis/*-PLAN.md`, section
"STRIDE Threat Register (ASVS L1)") and is not duplicated row-by-row here; this file records
disposition, verification status, and residual risk.

### Summary

| Disposition | Severity | Count | Status |
|-------------|----------|-------|--------|
| mitigate | critical | 2 | closed — mitigation verified in code |
| mitigate | high | 44 | closed — mitigation verified in code |
| mitigate | medium | 53 | closed — mitigation verified in code |
| mitigate | low | 12 | closed — mitigation verified in code |
| accept | medium | 2 | closed — documented accepted risk |
| accept | low | 11 | closed — documented accepted risk |
| accept | n/a | 18 | closed — documented accepted risk |
| **Total** | | **142** | **142 closed, 0 open** |

**Blocking set** (at or above `block_on: high`): 46 threats — 2 critical + 44 high, all
`mitigate`. STRIDE split: Tampering 14, Spoofing 13, Repudiation 12, Denial of Service 4,
Elevation of Privilege 2, Information Disclosure 1. **All 46 verified individually**, each with a
named file:line control and, where the mitigation plan specified one, a named passing test.

The two `critical` threats and their controls:

| Key | Category | Component | Control verified |
|-----|----------|-----------|------------------|
| 03-17/T-03-107 | Repudiation | scan/preview poller outcome | `dashboard/app.py:1905` returns `status == 'completed'`, not a constant — `test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed` |
| 03-19/T-03-119 | Repudiation | preview job success signal | `dashboard/app.py:2089` `return True` fully decoupled from `warning`; `:2077-2078` raises on machinery fault instead |

The 65 medium/low `mitigate` threats were **all** verified, not sampled.

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above `block_on` count toward `threats_open`*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-03-01 | 03-12/T-03-62 (DoS, medium) | **Live residual risk — see below.** `api_advanced_current` deliberately does not acquire the process-global `_db_lock` every other DB route uses. | william | 2026-08-20 |
| AR-03-02 | 17 supply-chain rows, disposition `accept`, severity `n/a` (T-03-46, -56, -66, -72, -79, -87, -89, -93, -98, -106, -111, -118, -123, -129, -134, -143, -144) | No package-manager install task exists in any Phase 03 plan; no dependency added, removed, or upgraded. Verified empirically: `git log --since=2026-08-11 -- dashboard/pyproject.toml dashboard/uv.lock` returns nothing. | william | 2026-08-20 |
| AR-03-03 | 13 remaining `accept` rows (T-03-05, -20, -27, -30, -36, -44, -71, -92, -116, -127, -131, -142, and 03-18/T-03-110) | Proportionate for a trusted-LAN, single-operator product. Auditor found none mis-dispositioned. | william | 2026-08-20 |

### AR-03-01 — the one accepted risk with live residual exposure

`api_advanced_current` (`dashboard/app.py:2214-2234`, confirmed lock-free) does not take the
process-global `_db_lock`. The deferral rationale is sound: a 30 s maintenance flock wait held
inside a global lock, on a route polled as often as every 5 s, is worse than the read
inconsistency it would remove. Residual exposure is bounded by `MaintenanceBusy` fail-fast,
`read_transaction`, and `busy_timeout`. **Revisit in Phase 6 alongside the WAL decision.**

### Note on 03-18/T-03-110 — accepted-then-closed, not standing

Recorded as accepted in 03-18, but superseded one plan later: the two transient paths it scoped
out were actually mitigated by 03-19/T-03-115. It carries no standing residual risk.

*Accepted risks do not resurface in future audit runs.*

---

## Verified Controls Lacking a Durable Regression Gate

**These are not open threats.** In every case below the protective control is present in code and
was verified directly by reading it. What is missing is the *test* the mitigation plan named, so
the control could regress silently in future work. Recorded here so the gap is visible rather
than implied-covered.

| Key | Sev | Control — verified present | Named guard that does not exist |
|-----|-----|---------------------------|--------------------------------|
| 03-02/T-03-09 | high | `repositories.py:110-170` one txn, normalized caps, sentinel+1; `diagnosis.py:544` active-service cutoff; no BLOB or history scan | "query instrumentation in the API suite" — no `set_trace_callback`, query counter, or statement-count assertion exists in `tests/`. Caps are behaviourally pinned by the three sentinel truncation tests, so the DoS vector itself is covered. |
| 03-02/T-03-08 | high | Route body calls only `beacon_diagnosis.get_current_diagnosis`; `app.py:2216-2217` rejects `request.args` before the `try`/SQLite | "source-test absence of worker operations" — no such source test. |
| 03-01/T-03-02 | high | `diagnosis.py:3-12` Flask-free; single `read_transaction` at `:540`; three repository reads only | "test that no worker/scheduler/probe/preview symbol is reached" — no such source test. Also note `diagnosis.py:12` *does* import `WORKER_CALLBACK_INVENTORY` from `worker_main` — immutable metadata only, and required by T-03-23 — so the stated invariant is narrower than its wording. |
| 03-07/T-03-54 | medium | Zero `innerHTML` anywhere in the bundle (grep-verified) | The mitigation claims "the existing regression continues to assert no `innerHTML` path exists". It does not — `test_advanced_controller_tracer_is_same_origin_get_only_and_text_safe` forbids `POST/PUT/PATCH/DELETE/thumbnail/history/http://` but never `innerHTML`. |
| 03-12/T-03-77, 03-15/T-03-87 | medium | No corrective-write property holds, pinned behaviourally at `test_advanced_diagnosis_api.py:981` (asserts exactly `['started','succeeded']`) | "a call-site count gate pins the module to exactly one started write and one outcome write" — no source-count gate exists, and `_write_job_health_transition` now has **three** call sites (`worker_main.py:336`, `:369`, `:546`), the third being the deliberate 03-19/T-03-113 best-effort retry. |

---

## Unregistered Threat Flags

None. Eleven SUMMARY files (03-01, 03-07 through 03-13, 03-15, 03-16, 03-17) carry a
`## Threat Flags` section; all eleven report "None" with specific justification. The other twelve
carry no such section — informational, not a finding.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-08-20 | 142 | 142 | 0 | gsd-security-auditor (opus, ASVS L1, block_on high) |

### Audit method

Not documentation-only. The auditor independently re-extracted the register from all 23
`<threat_model>` blocks (arriving at the same 142/111/31 split), verified each blocking threat
against a named file:line control, and ran four suites read-only — all green:

- `test_advanced_diagnosis_api.py`, `test_module_boundaries.py`, `test_worker_ownership_matrix.py`, `test_runtime_ownership.py` — 89 passed, 242 subtests
- `test_advanced_ui.py` (real Chromium against the production route) — 36 passed, 91 subtests
- `test_api_and_auth.py`, `test_outbound_policy.py`, `test_security_and_scanning.py` — 48 passed, 79 subtests

No implementation file was modified.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-08-20
