---
phase: 03-advanced-current-diagnosis
verified: 2026-08-18T17:01:11Z
status: gaps_found
score: 3/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 3/4
  gaps_closed:
    - "The Overview never declares all systems normal while current host evidence is stale or unknown. (prior CR-02)"
    - "Pending aggregation lists report truncation only when additional rows were omitted. (prior CR-03)"
    - "The bounded stream projection discloses incomplete stream evidence rather than silently hiding streams after its cap. (prior CR-04)"
    - "A late response from an older scheduled/manual refresh cannot replace newer current diagnosis evidence. (prior WR-01)"
  gaps_remaining:
    - "Current collection health truthfully exposes an active collection gap and promotes it as an actionable exception. (prior CR-01 — synthesis landed, but the gap projection it plugs into is untruthful)"
  regressions: []
gaps:
  - truth: "Current collection health truthfully reports collection gaps and promotes only real collection failures as actionable exceptions."
    status: failed
    reason: "`open` is derived from the stream's open_gap_start_ts rather than the gap row, so every durable coverage row on a stream with any open gap is relabelled open+actionable and promoted as a separate exception. Reproduced through GET /api/advanced/current."
    artifacts:
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Line 208 `open_gap = bool(stream and stream.get('open_gap_start_ts') is not None)` applies a stream-level fact to every row; line 211 makes `actionable` inherit it."
      - path: "dashboard/advanced.js"
        issue: "Line 280 renders a 30-day-old resolved interval as `Open actionable gap`."
      - path: "tests/test_advanced_diagnosis_api.py"
        issue: "Lines 487-506 assert `len(collection_gaps) == 1 + len(coverage)`, locking the defect in as expected behaviour and omitting `open`/`actionable` from the historical assertion."
    missing:
      - "Decide `open` per coverage row (a persisted telemetry_coverage row is a closed interval by construction), leaving synthesis as the only producer of open items."
      - "Update the WR-06 test to assert `open is False` / `actionable is False` on the historical row and `len(collection_gaps) == 1`."
  - truth: "Only genuine collection failures are promoted as collection_gap exceptions; other coverage reasons keep their own meaning."
    status: failed
    reason: "compose_active_exceptions hard-codes `kind: 'collection_gap'` and discards `gap['reason']`. A `reason='unknown'` interval (written for any permanently unreadable metric, e.g. a host with no thermal sensor) is permanently actionable and reported as a collection gap, so such a host can never legitimately show 'reporting normally'. Reproduced with no open gap present."
    artifacts:
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Lines 308-310 promote every actionable gap as `collection_gap` regardless of the constrained `reason` enum (collection_gap | unknown | expired | not_yet_monitored, migrations.py:260-262)."
    missing:
      - "Map `reason` to a distinct exception kind, and stop promoting `expired` / `not_yet_monitored` lifecycle evidence at all."
      - "Add coverage asserting each `reason` value maps to its own kind or to no exception."
  - truth: "The bounded gap projection discloses incomplete gap evidence rather than presenting a capped list as complete."
    status: failed
    reason: "Synthesized open gaps come only from the already-capped 64-row stream read, but `gaps.truncated` is sourced solely from the telemetry_coverage read. With 65 open-gap streams and no coverage rows the API returns gaps.count=64, gaps.truncated=False — the same false-completeness claim prior CR-04 was raised to eliminate, relocated to `gaps`."
    artifacts:
      - path: "dashboard/beacon/diagnosis.py"
        issue: "Lines 273-277 ignore `streams_truncated`; `count` is len(gaps) which reached 112 against a documented 48-row cap in reproduction, so count and truncated describe two different populations."
    missing:
      - "Propagate `streams_truncated` into the gaps disclosure, and bound or separately type the combined gap list so count and truncated describe the same population."
deferred: []
human_verification:
  - test: "On the target Pi, open /advanced while a real collection gap is active and while host evidence is stale."
    expected: "The workspace shows the open gap and the stale host as real, correctly labelled exceptions — and shows no resolved or retention-expired interval as an open actionable gap."
    why_human: "03-07 coverage item D6 is declared human_judgment: true with no automated verification. Operator trust in the snapshot cannot be asserted programmatically."
  - test: "Run the full suite with tests/test_advanced_diagnosis_api.py deselected, and again in isolation, and compare results."
    expected: "Identical results in both orders."
    why_human: "The phase test module permanently replaces the process-global time.time; deciding whether to accept order-dependent suite evidence is a maintainer call."
---

# Phase 3: Advanced Current Diagnosis Verification Report

**Phase Goal:** The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.

**Verified:** 2026-08-18T17:01:11Z
**Status:** gaps_found
**Re-verification:** Yes — after the 03-07 gap-closure plan (prior gaps CR-01..CR-04, WR-01).

## Gap-Closure Outcome (03-07)

Four of the five prior gaps are genuinely closed, each confirmed by independent reproduction rather than by SUMMARY claim.

| Prior gap | Claimed | Verifier result | Evidence |
| --- | --- | --- | --- |
| CR-01 open stream gap absent | Closed | ⚠️ PARTIAL | The synthesized item is correct (`diagnosis.py:218-233`), but the projection it plugs into is untruthful — see Gap 1. |
| CR-02 stale/unknown host reported normal | Closed | ✓ CLOSED | `compose_active_exceptions` takes `host` and emits `host_freshness` (`diagnosis.py:299-300`); repro shows `host_freshness` present with no host row. `renderOverview` emits normal copy only when `exceptions.length === 0` (`advanced.js:128-133`). |
| CR-03 pending exact-cap misclassified | Closed | ✓ CLOSED | Sentinel `cap+1` fetch with slice-back (`repositories.py:143-149`). Reproduced through the HTTP route: 0→False, 31→False, 32→False, 33→True. |
| CR-04 streams silently capped | Closed | ✓ CLOSED | Sentinel fetch plus open-gap/stale-first `ORDER BY` (`repositories.py:126-135`). Reproduced: 0→False, 64→False, 65→True with count capped at 64. |
| WR-01 old refresh overwrites new | Closed | ✓ CLOSED | `state.requestGeneration` incremented before the await and checked on **both** the success and failure branches (`advanced.js:622,625,634`). Behavioural Playwright tests executed and passed, not merely present. |

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Operator can open the dedicated advanced page from the dashboard and return without losing theme. | ✓ VERIFIED | Flask serves `advanced.html`/`.js`/`.css` via `send_file` (`app.py:2096-2118`); `beacon-theme` persisted and restored, scroll captured on the advanced link (`app.js:418-444`). |
| 2 | Operator can inspect current CPU, memory, disk, temperature, identity, sample time, and host freshness. | ✓ VERIFIED | `_host_payload` + `freshness_state` project every field from `system_stats` (`diagnosis.py:36-87`); stale/unknown host now raises its own `host_freshness` exception, closing the prior false-normal path. |
| 3 | Operator can inspect every current service's status, latency/failure class, duration, criticality, tags, and effective health rule. | ✓ VERIFIED | `read_current_services` → `compose_service_diagnosis` → semantic table with expandable detail rows; unchanged and not regressed by 03-07. |
| 4 | Operator can view truthful retention, resolution, database pressure, worker freshness, **collection gaps**, and background-job health without remote controls. | ✗ FAILED | Retention, resolution, pressure, worker freshness and job health are real and GET-only, but the collection-gap projection misreports resolved, retention-expired, and indeterminate evidence as open actionable collection gaps, and still claims completeness while dropping open gaps. |

**Score:** 3/4 roadmap success criteria verified (0 present-but-behavior-unverified).

### Reproduction Evidence (verifier-executed, production route)

Both critical review claims were independently reproduced through `GET /api/advanced/current` — they are not review speculation.

```
--- one open gap + two unrelated historical rows on the SAME stream ---
  GAP resolved-30-days-ago   reason=collection_gap  open=True actionable=True
  GAP retention-deleted      reason=expired         open=True actionable=True
  GAP (synthesized)          reason=collection_gap  open=True actionable=True
  EXCEPTION KINDS: ['host_freshness','worker_freshness','collection_gap','collection_gap','collection_gap']

--- single reason='unknown' interval, NO open gap on the stream ---
  GAP reason=unknown open=False actionable=True
  EXCEPTION KINDS: ['host_freshness','worker_freshness','collection_gap']

--- 65 streams all carrying an open gap, zero coverage rows ---
  gaps.count=64  gaps.truncated=False   (65 open gaps exist)
  streams.count=64 streams.truncated=True

--- 64 open-gap streams + 60 coverage rows (durable read capped at 48) ---
  gaps.count=112  gaps.truncated=True
```

The UI consequence is direct: `advanced.js:280` renders `${gap.open ? 'Open' : 'Resolved'} ${gap.actionable ? 'actionable' : 'historical'} gap`, so a gap that closed a month ago is displayed to the operator as "Open actionable gap".

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/app.py` | Asset routes + GET-only current endpoint | ⚠️ PARTIAL | Routes and `no-store` are correct, but `api_advanced_current` (2121-2132) has no exception handling and is the only read route bypassing `_db_lock`; `MaintenanceBusy` escapes as an HTML 500 the client cannot parse. |
| `dashboard/advanced.html` / `advanced.css` | Semantic responsive workspace | ✓ VERIFIED | Non-empty, served through the real WSGI app and asserted by browser regressions. |
| `dashboard/advanced.js` | Snapshot rendering, preferences, refresh safety | ⚠️ PARTIAL | Generation guard and streams disclosure are correctly wired; `state.serviceSort = null` on every poll (line 628) discards the operator's chosen sort every 5-15 s, and exception cards fall through dead `label`/`evidence` fields to raw kinds + "Unknown evidence". |
| `dashboard/beacon/diagnosis.py` | Truthful bounded composition | ✗ STUB-EQUIVALENT (untruthful) | Host, service, worker, jobs, settings and synthesis are substantive; the gap `open`/`actionable` derivation and `reason`-discarding promotion are wrong. |
| `dashboard/beacon/repositories.py` | Parameterized bounded readers with completeness metadata | ✓ VERIFIED | Sentinel truncation applied uniformly to streams, gaps and pending; priority `ORDER BY` keeps actionable evidence inside the cap. |
| `dashboard/beacon/migrations.py` / `worker_main.py` | Durable authority-fenced job health | ✓ VERIFIED | Unchanged since prior verification. |
| Phase 3 tests | Current-diagnosis regressions | ⚠️ PARTIAL | Boundary coverage for CR-02/03/04 and WR-01 is genuine; `tests/test_advanced_diagnosis_api.py:487-506` asserts the CR-01 defect, and the module leaks a frozen global clock. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `advanced.js` | `/api/advanced/current` | cache-disabled same-origin GET | ✓ WIRED | Sole browser fetch; parameterless and effect-free. |
| Flask adapter | diagnosis composer | no-store JSON response | ✓ WIRED | Confirmed at `app.py:2121-2132`. |
| composer | current SQLite readers | one `read_transaction` | ✓ WIRED | Single bounded short read. |
| stream open-gap state | synthesized gap item | second synthesis pass | ✓ WIRED | `diagnosis.py:218-233` emits exactly one open item per open stream. |
| gap row `reason` | exception kind | reason→kind mapping | ✗ NOT WIRED | `reason` is discarded; kind is hard-coded `collection_gap`. |
| per-row gap state | `open` / `actionable` flags | row-level derivation | ✗ NOT WIRED | Derived from the stream, not the row. |
| `streams_truncated` | `gaps.truncated` | completeness propagation | ✗ NOT WIRED | Open gaps dropped by the stream cap are undisclosed. |
| refresh controller | newest response only | generation guard | ✓ WIRED | Guard on both branches, behaviourally tested. |

### Data-Flow Trace (Level 4)

| Artifact | Data variable | Source | Produces real data | Status |
| --- | --- | --- | --- | --- |
| Host renderer | `snapshot.host` | `system_stats` via `read_current_host` | Yes | ✓ FLOWING |
| Services table | `snapshot.services` | services/meta/latest checks | Yes | ✓ FLOWING |
| Streams / pending regions | `pipeline.streams` / `.aggregation_pending` | sentinel-measured bounded reads | Yes | ✓ FLOWING |
| Collection gaps region | `pipeline.gaps.items` | telemetry_coverage + stream synthesis | Values real, **labels false** | ⚠️ MISLEADING — `open`/`actionable`/`kind` do not describe the underlying row. |
| Exception cards | `item.label` / `item.evidence` | never emitted by the server | No | ✗ HOLLOW_PROP — both branches dead; cards read raw kinds + "Unknown evidence". |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Reverse-order refresh ordering invariant | `pytest tests/test_advanced_ui.py -k reverse_order -v` | 2 passed | ✓ PASS |
| Pending truncation boundary 0/31/32/33 | verifier repro via HTTP route | False/False/False/True | ✓ PASS |
| Stream truncation boundary 0/64/65 | verifier repro via HTTP route | False/False/True | ✓ PASS |
| Gap truthfulness under mixed history | verifier repro via HTTP route | resolved + expired rows returned open/actionable | ✗ FAIL |
| Non-gap `reason` promotion | verifier repro via HTTP route | `unknown` promoted as `collection_gap` | ✗ FAIL |
| Gap completeness disclosure at 65 open gaps | verifier repro via HTTP route | count=64, truncated=False | ✗ FAIL |
| Global clock isolation across modules | `pytest tests/test_advanced_diagnosis_api.py tests/test_zz_leak.py` | `time.time()=1700000121` leaked into the next module | ✗ FAIL |

Note on the green suite: `pytest -q` passes (263 passed), but the phase module permanently rebinds `time.time` on the stdlib module object — `tearDown` and `importlib.reload` do not restore it. Suite greenness is therefore order-dependent and is **not** accepted here as evidence for any must-have; every truth above rests on direct reproduction instead.

### Requirements Coverage

All six phase requirement IDs are claimed by at least one plan (03-01 DIA-01/02; 03-02 TEL-06, DIA-02/03/08; 03-03 TEL-06, DIA-01/02/08; 03-04 DIA-01/03/08, UX-02; 03-06 TEL-06, DIA-02/03/08; 03-07 TEL-06, DIA-02/03/08). No orphaned Phase 3 requirements.

| Requirement | Description | Status | Evidence |
| --- | --- | --- | --- |
| TEL-06 | Effective retention, resolution, pressure, worker freshness, collection gaps, background-job health | ✗ BLOCKED | Collection-gap evidence is mislabelled and its completeness claim is false. |
| DIA-01 | Open dedicated advanced page from either theme | ✓ SATISFIED | Production asset routes + theme continuity wired and tested. |
| DIA-02 | Current host metrics, identity, sample time, freshness | ✓ SATISFIED | Full projection plus the new `host_freshness` exception. |
| DIA-03 | Every service's status, latency/failure, duration, criticality, tags, health rule | ✓ SATISFIED | Service composition and table detail rows intact. |
| DIA-08 | Effective settings + presentation/refresh/filter preferences, no remote control | ✗ BLOCKED | Controls are correctly local-only and GET-only, but the collection-health view they present is untruthful; the auto-refresh sort reset also defeats a supported presentation preference. |
| UX-02 | Move between dashboard and advanced without losing theme | ✓ SATISFIED | `beacon-theme` persisted; one-shot scroll restoration. |

REQUIREMENTS.md traceability is stale relative to this result: it marks TEL-06/DIA-02/DIA-03/DIA-08 `Complete` and DIA-01/UX-02 `Gaps Found`, which is close to the inverse of the verified state. Correct after gap closure.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `dashboard/beacon/diagnosis.py` | 205-217 | Stream-level fact applied per row | 🛑 BLOCKER | Historical and retention-expired intervals reported as open actionable gaps. |
| `dashboard/beacon/diagnosis.py` | 308-310 | Discarded discriminator, hard-coded kind | 🛑 BLOCKER | Indeterminate and lifecycle evidence mislabelled as collection failure. |
| `dashboard/beacon/diagnosis.py` | 273-277 | Completeness claim over the wrong population | 🛑 BLOCKER | `count` and `truncated` describe different sets; open gaps silently dropped. |
| `tests/test_advanced_diagnosis_api.py` | 487-506 | Test asserts the defect | ⚠️ WARNING | Protects the CR-01 bug; will fail correctly once fixed. |
| `tests/test_advanced_diagnosis_api.py` | 18-19 et al. | Global stdlib monkey-patch without teardown | ⚠️ WARNING | Frozen Nov-2023 clock leaks into every later module; masks real regressions. |
| `dashboard/advanced.js` | 628 | State reset on every poll | ⚠️ WARNING | Operator's service sort silently reverts within seconds. |
| `dashboard/advanced.js` | 138 | Dead fallback fields | ⚠️ WARNING | Primary safety surface reads raw kinds + "Unknown evidence". |
| `dashboard/advanced.js` | 602-612 | Unguarded dereference after mutation | ⚠️ WARNING | Unknown `section` hides every section then throws on `null.focus()`. |
| `dashboard/app.py` | 2121-2132 | Unhandled errors + lock-discipline bypass | ⚠️ WARNING | Maintenance window surfaces as an unparseable 500; only read route outside `_db_lock`. |
| `dashboard/beacon/diagnosis.py` | 15 | Contract change without version bump | ⚠️ WARNING | `pipeline.streams` shape changed while `SCHEMA_VERSION` stays 1. |

No unreferenced `TBD`, `FIXME`, or `XXX` markers were found. No mutation or remote-control request exists in the browser bundle; all DOM writes use `textContent`, all SQL is parameterized, and `alert_webhook_url` is correctly reduced to a boolean.

### Deferred Items

None. Phase 03.1 (planned maintenance suppression) and Phase 4 (historical investigation) do not own the per-row gap derivation, gap-reason classification, or gap completeness disclosure. These are Phase 3's own current-diagnosis contract.

### Gaps Summary

03-07 did real work: the sentinel-truncation pattern (CR-03, CR-04), the `host_freshness` exception (CR-02), and the refresh generation guard (WR-01) are all correctly implemented and independently confirmed at their boundaries — the guard with genuine behavioural evidence rather than symbol presence.

The phase still cannot pass because the one gap 03-07 was primarily created to close is only half-closed. Synthesizing the open gap was the easy half; the projection that item was appended to remains untruthful, and 03-07 explicitly recorded the per-row `open` mislabel as "out of scope" while its own test asserts that mislabel as expected behaviour. The result is that the Active Exceptions list — the single operator-facing safety surface of this phase — inflates with month-old resolved gaps and retention-deleted intervals the moment one real gap opens, labels a host with no thermal sensor as suffering a permanent collection gap, and can still hide 65 open gaps behind a `truncated: false`. For a phase whose goal is that the operator can *quickly diagnose collection health*, evidence that cries wolf on resolved history is a direct failure of the contract, not a cosmetic defect.

Three fixes close this: derive `open` per row, map `reason` to its own exception kind, and propagate stream truncation into the gaps disclosure. All three are localized to `compose_pipeline_diagnosis` and `compose_active_exceptions`. Fix the CR-01 test alongside the first — it will fail, and that failure is the correct signal.

Two adjacent issues should ride along in the same closure plan: the global `time.time` leak (which makes the whole suite's evidence order-dependent) and the auto-refresh sort reset (which defeats a DIA-08 presentation preference every poll).

---

_Verified: 2026-08-18T17:01:11Z_
_Verifier: Claude (gsd-verifier)_
