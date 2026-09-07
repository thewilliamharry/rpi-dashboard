---
phase: 07-optional-advanced-diagnostics
verified: 2026-09-07T11:30:00Z
status: gaps_found
score: 5/5 must-haves verified (ROADMAP success criteria 1-5, all mutation-confirmed)
behavior_unverified: 0
overrides_applied: 0
overrides: []
prohibitions:
  - statement: "PROH-DIA-09-01 — every OPS-07 acceptance run measures the fully-enabled configuration; the advanced-diagnostics toggle is a deployment mode, never a test knob. No OPS-07 pass may be reached with it off, and the shipped deployment default must resolve to enabled."
    status: partially_enforced
    flagged: true
    verification: test
    evidence: "The shipped-default half is REAL and independently mutation-confirmed twice. `AcceptanceConfigurationGuardTests` scans `docker-compose.yml`'s `environment: &beacon-environment` anchor with its own line scanner, resolves `${BEACON_ADVANCED_DIAGNOSTICS:-1}` for the operator-sets-nothing case, and feeds the result through the real `load_settings` — not a text comparison. Mutation M6 (flip the shipped default to `:-0}`) FAILED `test_the_shipped_default_resolves_to_enabled_through_the_real_parser`. Mutation M6b (delete the compose line entirely) FAILED BOTH guard tests, so a scan that finds nothing cannot report a pass over nothing. The anchor is genuinely load-bearing: `web` and `worker` both carry `<<: *beacon-common`, whose `environment:` IS that anchor. TWO holes remain: (a) the one 07-DECISIONS.md records honestly — an operator exporting a disabling shell variable by hand before a round; (b) one it does NOT record, found this round by mutation M8 — adding `ENABLE_ADVANCED_DIAGNOSTICS: \"0\"` to the `web` service's own `environment:` block (which already exists at docker-compose.yml:110-112, merging the anchor and adding `TZ`) disables the toggle on the actual web container and BOTH guard tests still PASS. Docker Compose gives the per-service key precedence over the merged anchor. See gap 2."
  - statement: "D-DEBT-07-01 — `tests/pi_load_acceptance.py::_load_worker` records a 404 as a fast, budget-clearing success"
    status: acknowledged_deferred
    flagged: false
    verification: judgment
    evidence: "Independently confirmed present at HEAD and NOT re-raised as a Phase 7 defect, per 07-DEBT.md's opening instruction. `_load_worker` (tests/pi_load_acceptance.py:425-446) discards `session.get`'s return value and records only `elapsed_ms`; `assert_response_times` (:373-401) receives only `latencies_by_route` and has no status information even in principle. `ROUTE_BUDGETS_MS` (:103-110) declares `/api/advanced/current: 2000`. Phase 7's scope fence forbade editing that file and `git status --porcelain tests/pi_load_acceptance.py` is clean. Owner named: the next OPS-07 round in Phase 6. Recorded here for continuity only."
gaps:
  - truth: "DIA-09 — the operator can disable advanced diagnostics ... hiding the page and its entry point and SERVING NONE OF ITS ROUTES, while the services front page keeps working unchanged"
    status: failed
    reason: "Two API routes that exist solely to serve the advanced workspace are not gated by the toggle. With ENABLE_ADVANCED_DIAGNOSTICS=0 they answer 200 and do real database work. This is a gap against the REQUIREMENT's wording, not against ROADMAP success criterion 2, which enumerates exactly four paths and is literally satisfied. It is not covered by 07-DEBT.md, 07-DECISIONS.md, or any 07-0x PLAN/SUMMARY: `grep -rn 'telemetry/history|events/history' .planning/phases/07-optional-advanced-diagnostics/` returns ZERO hits, so this is not a documented scope-out being re-litigated."
    artifacts:
      - path: "dashboard/app.py:2672 (api_telemetry_history)"
        issue: "No `if not ENABLE_ADVANCED_DIAGNOSTICS: return '', 404` guard. Measured disabled: HTTP 200, 1 connection, 6 SQLite statements, 308-byte JSON body."
      - path: "dashboard/app.py (api_events_history)"
        issue: "No gate. Measured disabled: HTTP 200, 1 connection, 3 SQLite statements, 274-byte JSON body."
      - path: "dashboard/advanced.js"
        issue: "The ONLY production consumer of both routes. `grep -ln` across dashboard/*.js and dashboard/*.html returns advanced.js alone for each; dashboard/app.js and dashboard/index.html reference neither. Their UI (advanced.html:99-106, the History section serving HIS-01..HIS-05) is 404 when the toggle is off, so in a disabled deployment these are unreachable-by-UI but openly-served data APIs."
    missing:
      - "Gate `/api/telemetry/history` and `/api/events/history` with D-07-02's exact shape (handler-first-statement `return '', 404`), OR record an explicit, reasoned decision that they are shared-surface routes outside DIA-09's 'its routes' — with the DIA-09 wording amended to match."
      - "Extend the disabled-route subtest table in `DisabledAdvancedAssetTests::test_the_disabled_toggle_gates_only_the_advanced_bundle` to cover both paths, so the decision (whichever way) is pinned."
  - truth: "PROH-DIA-09-01's automated guard detects an attempt to disable advanced diagnostics in the shipped deployment file"
    status: partial
    reason: "The guard scans ONLY the `environment: &beacon-environment` anchor. A per-service `environment:` override under `services:` — the pattern docker-compose.yml already uses at :110-112 and :96-98 — wins in Docker Compose and is invisible to the guard. This is a mutation of a TRACKED file (visible in review), so it is a narrowing of the guard's reach, not an open door; but 07-DECISIONS.md names only the shell-export escape as the residual, and a later reader would over-trust the guard."
    artifacts:
      - path: "tests/test_optional_advanced_diagnostics.py:260-281 (_scan_beacon_environment_anchor)"
        issue: "`break`s at the first line that does not start with four spaces, so it never reads below `services:`. Mutation M8 (add `ENABLE_ADVANCED_DIAGNOSTICS: \"0\"` to the `web` service's own environment block) left both AcceptanceConfigurationGuardTests PASSING."
    missing:
      - "Either widen the scan to fail when ANY `ENABLE_ADVANCED_DIAGNOSTICS` entry appears outside the anchor, or record the per-service-override escape alongside the shell-export escape in 07-DECISIONS.md's PROH-DIA-09-01 section."
  - truth: "The golden comparison's result can never move because an unrelated module ran first (tests/test_optional_advanced_diagnostics.py:104-116, module docstring claim)"
    status: partial
    reason: "The claim is false for `TZ`. `_DEFAULT_SETTINGS_PAYLOAD_ENV` pins every key `_settings_payload` reads, but the golden body ALSO depends on maintenance-window evaluation, which is timezone-dependent, and `TZ` is not pinned. `tests/test_history_investigation_ui.py:48` calls `load_app({'TZ': 'Australia/Sydney'})`, which `load_app` never clears. Reproduced: `cd dashboard && uv run --frozen pytest -q -k \"Toggle or EnabledResponseGolden\"` (8 tests) FAILS both golden assertions — the seeded 20002 maintenance window is not active outside UTC, so the exceptions block reorders. The full suite is green only because of which TZ-setting class in that module happens to run last under alphabetical class ordering. This fails LOUDLY and can never produce a silent vacuous pass, which is why it is partial and not a blocker."
    artifacts:
      - path: "tests/test_optional_advanced_diagnostics.py:110-131"
        issue: "`_DEFAULT_SETTINGS_PAYLOAD_ENV` omits `TZ`; `EnabledResponseGoldenTests.setUp` and `ToggleReversibilityTests` both inherit whatever `TZ` an earlier module left in `os.environ`."
    missing:
      - "Add `'TZ': 'UTC'` to `_DEFAULT_SETTINGS_PAYLOAD_ENV` (one line), restoring the docstring's stated property."
deferred:
  - truth: "`resolution_policy` is emitted as a hardcoded literal `{60, 300, 3600}` rather than derived from `telemetry.py:11 RESOLUTION_LADDER_SECONDS` (a ten-step ladder)"
    addressed_in: "Phase 3 (Advanced Current Diagnosis) — dashboard/beacon/diagnosis.py:448 is the origin, not a Phase 7 edit"
    evidence: "Confirmed frozen at `pipeline.resolution_policy` in 07's golden. Phase 7 is the THIRD pin site, not the first: `tests/fixtures/advanced_current_pre_remedy_golden.json` (Phase 3) and `tests/test_advanced_ui.py:867` already pin the same literal. The marginal cost of the new pin is one fixture regeneration, and `generate_enabled_response_golden()` (tests/test_optional_advanced_diagnostics.py:400-437) exists for exactly that. Mutation M5a (3600 -> 7200) FAILED the golden loudly with a self-explanatory message naming the referent commit, so the pin is a signpost to the fix, not a silent obstacle."
  - truth: "`_load_worker` must record each sample's response status so a 404 cannot be scored as a fast success"
    addressed_in: "The next OPS-07 round in Phase 6"
    evidence: "07-DEBT.md D-DEBT-07-01, with a one-time measured reproduction (389 samples, p95 1.225ms against a 2000ms budget, `assert_response_times` returning `{'passed': True}`, actual status 404). Phase 7 was forbidden from editing tests/pi_load_acceptance.py; that file is unmodified at HEAD."
human_verification:
  - test: "Before the next Pi OPS-07 acceptance round, confirm on the running deployment that advanced diagnostics is ENABLED — e.g. `curl -s -o /dev/null -w '%{http_code}' http://raspi.local/advanced` returns 200, and `docker compose config | grep ENABLE_ADVANCED_DIAGNOSTICS` resolves to a value in {1,true,yes,on}."
    expected: "200 from /advanced, and a resolved compose value that `load_settings` parses as enabled."
    why_human: "PROH-DIA-09-01 constrains the RUNTIME environment of a hand-run acceptance round. No test in this repository can observe the shell an operator exports before invoking the harness, and D-DEBT-07-01 establishes that the harness itself would score the resulting 404s as fast successes. This is the residual the compose-default guard explicitly does not close."
  - test: "Decide whether `/api/telemetry/history` and `/api/events/history` are 'its routes' under DIA-09 (gap 1) — gate them, or amend DIA-09's wording."
    expected: "A recorded decision. If gated, DIA-09 is promotable; if the wording is amended, the amendment must be justified by usage rather than by difficulty (PROH-OPS-07-10's standard, applied by analogy)."
    why_human: "This is a scope judgement about what the advanced workspace IS, not a defect with a mechanically correct answer. It also decides whether DIA-09 moves to Complete this round."
  - test: "Decide whether PROH-DIA-09-01's guard should also refuse a per-service compose override (gap 2)."
    expected: "Either a widened scan, or the escape recorded in 07-DECISIONS.md next to the shell-export escape."
    why_human: "Prohibition-scope decision. Judgment-tier: how hard the fence should be is an operator call, not a test outcome."
---

# Phase 7: Optional Advanced Diagnostics — Verification Report

**Phase Goal:** Beacon runs as a services-only dashboard on hosts that already have monitoring, with advanced diagnostics off by configuration and costing nothing when off.
**Requirements:** DIA-09
**Verified:** 2026-09-07T11:30:00Z at HEAD `dc8626a`
**Status:** gaps_found
**Re-verification:** No — this is the first verification of Phase 7, and the independent round ROADMAP.md reserved DIA-09's promotion for.

---

## Headline: can DIA-09 be promoted?

**No — not yet, and for one specific, small, evidenced reason.**

All five of ROADMAP's Phase 7 success criteria are verified, and every one of them was confirmed by
mutating the production code it rests on and watching the guard fail. That part of the phase is
sound, and unusually so: this is not a phase where a green suite was taken at its word.

DIA-09's own wording is wider than criterion 2's. The criterion enumerates four paths
(`/advanced`, `/advanced.css`, `/advanced.js`, `/api/advanced/current`) and all four 404 correctly.
The requirement says the operator can disable advanced diagnostics **"serving none of its routes."**
Two further routes — `/api/telemetry/history` and `/api/events/history` — exist solely to feed
`dashboard/advanced.js`, have no other production consumer anywhere in `dashboard/`, and are **not
gated**. Measured on a disabled build this round:

```
ENABLE_ADVANCED_DIAGNOSTICS=0
  /advanced                        -> 404   (0 conn, 0 stmt)
  /advanced.css                    -> 404
  /advanced.js                     -> 404
  /api/advanced/current            -> 404   (0 conn, 0 stmt)
  /api/telemetry/history?kind=host&metric=cpu&start_ts=..&end_ts=..  -> 200   1 conn, 6 stmts, 308 bytes
  /api/events/history?kind=host&metric=cpu&start_ts=..&end_ts=..     -> 200   1 conn, 3 stmts, 274 bytes
```

That is a disabled deployment still serving the advanced workspace's data APIs. Their UI (the
History section of `advanced.html`, serving HIS-01..HIS-05) is 404, so nothing a user can click
reaches them — but "unreachable from the UI" is exactly the "hidden rather than absent" shape
criterion 2 was written to reject, applied one layer down.

This is **not** something the phase deliberately scoped out. `grep -rn 'telemetry/history|events/history'`
over the entire Phase 7 directory returns **zero hits** — no PLAN, no SUMMARY, no 07-DEBT.md entry,
no 07-DECISIONS.md decision. It was not considered, so raising it is not re-litigating a settled
call, which is the one thing 07-DEBT.md asks a later verifier not to do.

**What promotion needs:** two more gates in `dashboard/app.py`, mirroring D-07-02's shape exactly
(the same one-line early return, four of which already exist), plus two rows added to
`DisabledAdvancedAssetTests`' subtest table. That is a small, mechanical change — or, alternatively,
a recorded decision that these are shared-surface routes and an amendment to DIA-09's wording. Either
resolution is legitimate; leaving the requirement's wording and the code disagreeing is not.

Until then, `.planning/REQUIREMENTS.md:44` should stay `- [ ]` and the traceability row at `:139`
should stay `Pending`. **Do not promote DIA-09 this round.**

---

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A single configuration toggle, defaulting to enabled, controls whether advanced diagnostics is available; an existing deployment that sets nothing keeps the page it has today | VERIFIED | One toggle end to end: `ENABLE_ADVANCED_DIAGNOSTICS` -> `config.py:281` `_enabled(source.get(..., '1'))` -> `Settings.enable_advanced_diagnostics` -> `app.py:105` module constant -> five handler gates. No second source of truth. **Mutation M1b** (`'1'` -> `'0'` at the effective parse site) FAILED `test_an_unset_value_defaults_to_enabled`. Independently reproduced: `load_app({'ENABLE_ADVANCED_DIAGNOSTICS':'1'})` serves all four surfaces 200. Documented for the operator at README.md:49. Deployment default `${BEACON_ADVANCED_DIAGNOSTICS:-1}` at docker-compose.yml:35, inside the anchor both `web` and `worker` merge. |
| 2 | With the toggle off, `/advanced`, `/advanced.css`, `/advanced.js` and `/api/advanced/current` all serve 404 and the front page's entry point is absent rather than merely hidden by styling | VERIFIED | **Reproduced independently of the phase's own tests** (see Behavioural Spot-Checks): all four return 404 with a zero-byte body, including `/api/advanced/current?x=1` — the gate really is ahead of the `request.args` 400 branch, so a disabled route is not probeable for its own existence. The served disabled `/` body contains none of `advanced-diagnosis-link`, `href="/advanced"`, `Advanced diagnosis`, and carries no `display:none` — the anchor is 97 bytes shorter and line 24 is empty in a unified diff against `index.html`. **Mutation M2** (delete the `/advanced.css` gate) and **Mutation M3** (make `without_advanced_entry_point` return the document unchanged) both FAILED their guards; M3 additionally failed the real-Chromium boot test in both themes. |
| 3 | With the toggle off, a request to the services front page performs none of the work advanced diagnostics would have required, demonstrated by measurement rather than by inspection | VERIFIED | Measured, not inspected, and the instrument was checked rather than trusted — see "Is the cost measurement real?" below. Baseline this round: the six-request front-page boot set costs **5 connections / 14 statements with the toggle OFF and 5 connections / 14 statements with it ON**, over the same seeded database, with `(off, on)` settings read as `(False, True)` immediately at each build. **Mutation M4** (one extra `SELECT 1` on the disabled `/` branch) FAILED the equality at `15 != 14` — one statement of granularity. Both sides are non-zero, so this is an equality between two live measurements, never `0 == 0`. |
| 4 | With the toggle on, behaviour is byte-identical to today's, proven against a captured response golden | VERIFIED | Three independent proofs, not one. (a) The golden's referent is genuine: all four `asset_sha256` digests match `git show ceef6da:dashboard/<file>` **exactly**, and match HEAD, so no served asset moved across the phase. (b) The golden constrains the response: **Mutation M5a** (`hourly_seconds` 3600 -> 7200) FAILED it. It also survived an unrelated 276-line `repositories.py` change landed by Phase 6 after capture — a live net, not a dead snapshot. (c) Byte-identity is a code-shape property (D-07-03): the enabled branches are untouched `send_file` calls, and `test_enabled_advanced_surfaces_are_byte_identical_to_disk` asserts served bytes == file bytes as an invariant. Independently reproduced: enabled `GET /` is byte-equal to `dashboard/index.html`. Residual on the golden's fixture recorded below. |
| 5 | Turning the toggle off changes no stored data and is reversible by restarting with it on — no migration, no destructive step | VERIFIED | `ToggleReversibilityTests` exercises the full boot set plus all four gated routes on a disabled build, compares `iterdump()` sha256 and `_recorded_version` before/after, then reopens the SAME file enabled and recovers 07-01's golden byte-for-byte. **Mutation M7** (a `CREATE TABLE` on the disabled `/advanced` branch) FAILED the digest comparison with both hashes printed — the oracle is sensitive to any logical write. D-07-08's choice of `iterdump` over file bytes is correct for a WAL deployment and is the property criterion 5 actually names. No migration, no schema change, no worker change anywhere in the phase's diff. |

**Score: 5/5 truths verified. 0 present-but-behaviour-unverified.** Every one was confirmed by a
mutation of the production code the guard protects, not by reading a SUMMARY.

---

## Scrutiny of the two instruments the brief flagged

### Does the golden actually constrain the response, or is the fixture degenerate?

**Both, honestly.** It constrains real behaviour, and it has a measurable blind spot.

The fixture is **not** uniformly degenerate. Its `services` array carries three genuinely distinct
states — `online`/`aging`, `maintenance`/`stale` with a live window (`covered_until_ts`,
`attributed_seconds: 5400`), and `offline`/`stale` unattributed — and a four-entry `exceptions` list
with a real priority ordering across three sections. `settings`, `safety`, `schema_version` and the
whole `pipeline` static shape are pinned. Mutation M5a proves a single changed integer three levels
deep fails it.

Its blind spot is real and worth recording: **42.9% of the body's 324 leaf values are `null` (121)
or the string `"unknown"` (18)**, because no `system_stats` row and no scheduler state are seeded.
Concretely, `_host_payload`'s entire `row is not None` branch (`diagnosis.py:166-188`) is never
executed by this golden. Demonstrated: **Mutation M5b** swapped `row['ram_used']` and
`row['ram_available']` — a genuine host-metrics defect — and the Phase 7 golden **PASSED**. Phase 3's
own `test_host_tracer_returns_one_current_snapshot_with_server_freshness` caught it immediately.

**Verdict:** adequate for what criterion 4 asks of it. Criterion 4 is a *no-change* proof for a phase
that edited zero lines of `diagnosis.py`, and it rests on three legs, of which the golden is one — the
`ceef6da` asset digests and the served-bytes-equal-disk-bytes invariant carry the other two, and
D-07-03's code-shape argument means the enabled path cannot drift without a visible edit. It is
**not** a general regression net for the diagnosis payload, and nobody should later cite it as one.
It is worth knowing that a future host-metrics regression would be caught in Phase 3's tests, not here.

### Does the cost-equality measurement count what it claims to count?

**Yes, at one-statement granularity, and both sides are live.**

- The instrument patches `connect_db` at **both** bindings — `dashboard.beacon.db`'s module attribute
  (which `database_access` resolves by name at call time, confirmed at `db.py:222`) and
  `dashboard.app`'s independent import alias (which `get_db()` and every direct call site use).
  `dashboard/app.py` contains **zero** direct `sqlite3.connect` calls, so no request path escapes the
  seam.
- It counts statements with `conn.set_trace_callback`, i.e. what SQLite actually executed, not what a
  reader was expected to call.
- Its own sensitivity is checked on an ungated route (`/api/stats` must be `> 0`), so an inert
  instrument cannot masquerade as a zero result.
- **The measured baseline is 14 statements / 5 connections on each side.** This is the strongest single
  fact about criterion 3: the equality is not `0 == 0`. Both sides do substantial, identical work, and
  M4 showed a one-statement delta breaks it.
- The `(False, True)` settings-pair assertion runs at build time, before any request, and its failure
  message names the exact vacuous-pass it exists to refuse. Given `dashboard.app` is a singleton module
  whose globals are rebound in place by every `importlib.reload`, this ordering discipline is genuinely
  load-bearing, and the test does it correctly (disabled requests complete BEFORE the enabled reload).

**Scope limit, recorded rather than hidden:** the instrument counts SQLite connections and statements
only. A toggle-delivery mechanism that cost the front page CPU or file I/O rather than database work
would not move this equality. The phase covers that specific hole separately with
`test_the_transform_runs_at_most_once_per_process_across_five_disabled_requests`, which is the right
guard for the mechanism actually chosen (D-07-05's cached server-side transform). Direct
`sqlite3.connect` users (`recovery.py`, `inventory.py`, `migrations.py`) are invisible to the counter,
but none of them is on a request path.

07-03's objective is also right that criterion 3 read literally is close to vacuous against a static
`send_file` front page, and D-07-07's re-reading — *whatever tells the front page about the toggle must
cost the front page nothing* — is the honest operative content. I agree with that narrowing and record
it as accepted rather than as a weakening.

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `dashboard/beacon/config.py:71,281` | `Settings.enable_advanced_diagnostics`, default True, parsed via `_enabled` | VERIFIED | Field at :71, parse at :281. Note: the **effective** default is the `'1'` literal at :281; the dataclass field default is decorative (only `load_settings` constructs `Settings`). See Observations. |
| `dashboard/app.py:105` | Module constant from `SETTINGS` | VERIFIED | Sits alongside `ENABLE_PROMETHEUS`/`ENABLE_LOCK_PROFILE`, same shape. |
| `dashboard/app.py:2535,2544,2557,2570,2581` | Five gates, each the handler's first statement | VERIFIED | Read directly. Four are `return '', 404`; `index()`'s is the transform branch. Gate precedes `request.args` in `api_advanced_current`, confirmed behaviourally by the `?x=1` -> 404 probe. |
| `dashboard/beacon/frontpage.py` | Pure transform raising rather than no-oping | VERIFIED | 74 lines, stdlib-only (`re`), imports nothing from `dashboard.app`. Raises `AdvancedEntryPointNotFound` on any match count != 1. Mutation M3 confirms the no-op is caught. |
| `dashboard/app.js:766,782` | Two independently guarded `advanced-diagnosis-link` lookups | VERIFIED | Both resolve into a local and branch on truthiness. Both failure paths exercised by separate Playwright subtests (ordinary load; seeded `sessionStorage` scroll), so either guard can be removed independently and be caught. |
| `tests/fixtures/07_advanced_current_enabled_response_golden.json` | Pre-change response + four asset digests + referent commit | VERIFIED | Digests match `ceef6da` blobs exactly. `captured_at_commit: ceef6da`, `captured_at_head: 2026cb14`. Fixture added in `62e041c` ("capture the enabled golden before any edit"). Degeneracy residual recorded above. |
| `tests/test_optional_advanced_diagnostics.py` | All nine phase test classes | VERIFIED | 1,269 lines, 27 tests + 29 subtests, all passing in isolation and inside the full suite. |
| `docker-compose.yml:35` | Deployment default resolving to enabled | VERIFIED | `ENABLE_ADVANCED_DIAGNOSTICS: "${BEACON_ADVANCED_DIAGNOSTICS:-1}"` inside `environment: &beacon-environment`, merged by `web` and `worker`. |
| `README.md:49` | Operator documentation | VERIFIED | Configuration row present and accurate about the four surfaces it removes. |
| `07-DECISIONS.md` / `07-DEBT.md` | D-07-01..D-07-09, PROH-DIA-09-01, D-DEBT-07-01 | VERIFIED | All present; D-DEBT-07-01 carries measured numbers and a named owner, exactly as 07-03's must-have required. |

## Key Link Verification

| From | To | Via | Status |
|---|---|---|---|
| `ENABLE_ADVANCED_DIAGNOSTICS` env | `Settings.enable_advanced_diagnostics` | `config.py:281` `_enabled(...)` | WIRED — mutation M1b kills it |
| `Settings` | `app.py:105` constant | module-level read of `SETTINGS` | WIRED |
| `app.py:105` | five handler gates | `if not ENABLE_ADVANCED_DIAGNOSTICS` read via `__globals__` at call time | WIRED — mutation M2 kills it |
| `index.html:24` anchor | served `/` bytes | `frontpage._ENTRY_POINT_PATTERN` -> `_index_document_without_advanced_entry_point` cache | WIRED — mutation M3 kills it; markup tripwire pins the coupling |
| `docker-compose.yml` anchor | `load_settings` | `_scan_beacon_environment_anchor` + `_resolve_unset_default` | WIRED but NARROW — mutations M6/M6b kill it, M8 escapes it (gap 2) |
| `advanced.js` | `/api/telemetry/history`, `/api/events/history` | `fetch` | **WIRED BUT UNGATED** — gap 1 |

## Behavioural Spot-Checks (run this round, independent of the phase's test module)

| Behaviour | Command | Result | Status |
|---|---|---|---|
| Full suite green at HEAD | `cd dashboard && uv run --frozen pytest -q` | 993 passed, 593 subtests, 1 failed | PASS — the single failure is `test_lock_profile.py::LockProfileInertnessTests::test_disabled_wrapper_path_costs_nothing_measurable` at ratio 1.0233 vs a 1.02 ceiling: the known timing-flake set of 06-DEBT.md D-DEBT-06-13's 2026-09-07 addendum (three tests, three files). Green in isolation. |
| Phase 7 module in isolation | `pytest -q -k "<the nine phase classes>"` | 27 passed, 29 subtests, 5.8s | PASS |
| Four gated routes disabled | direct `test_client` GETs on a `load_app({'ENABLE_ADVANCED_DIAGNOSTICS':'0'})` build | all 404, zero-byte bodies, incl. `?x=1` | PASS |
| Entry point absent, not hidden | token scan + unified diff of served `/` vs `index.html` | 6/6 advanced tokens absent, no `display:none`, exactly line 24 removed, `services-grid` retained | PASS |
| Enabled `/` byte-identical to disk | byte comparison | True | PASS |
| Front-page boot cost | live `DatabaseWorkCounter` over both builds | OFF 5 conn/14 stmt, ON 5 conn/14 stmt, `(False, True)` | PASS |
| Ungated advanced-only routes while disabled | direct GETs | `/api/telemetry/history` 200 (1 conn, 6 stmt); `/api/events/history` 200 (1 conn, 3 stmt) | **FAIL — gap 1** |
| Golden referent authenticity | `git show ceef6da:dashboard/<asset> \| shasum -a 256` x4 | all four match the fixture and HEAD | PASS |

## Mutation Testing

This project's history (D-DEBT-06-10, D-DEBT-06-22, PROH-OPS-07-28) records three cases where a fully
green suite concealed a real defect, so no must-have here was accepted on a passing test alone. Every
mutation below was applied to production code and reverted; `git diff --stat` and `git status --porcelain`
confirm the tree is byte-identical to `dc8626a` afterwards (only the untracked `.gsd/` remains), and the
phase module was re-run green after restoration.

| # | Mutation | Guard expected to fire | Result |
|---|---|---|---|
| M1 | `config.py:71` field default `True` -> `False` | `test_an_unset_value_defaults_to_enabled` | **SURVIVED — correctly.** The field default is not the effective default; `load_settings` uses the `'1'` literal at :281. Behaviourally inert mutation, so survival is right. See Observations. |
| M1b | `config.py:281` `source.get(..., '1')` -> `'0'` | same | KILLED |
| M2 | Delete `/advanced.css`'s 404 gate | `DisabledAdvancedAssetTests` subtest | KILLED (`200 != 404`, path named) |
| M3 | `without_advanced_entry_point` returns the document unchanged | entry-point + Chromium boot tests | KILLED (3 failures, both themes) |
| M4 | Disabled `/` branch performs one `SELECT 1` | `FrontPageCostEqualityTests` + zero-work guard | KILLED (`15 != 14`) |
| M5a | `resolution_policy.hourly_seconds` 3600 -> 7200 | `EnabledResponseGoldenTests` | KILLED |
| M5b | Swap `ram_used`/`ram_available` in `_host_payload`'s populated branch | `EnabledResponseGoldenTests` | **SURVIVED** — golden's host block is all-null. Caught by Phase 3's `test_host_tracer_...` instead. Blind spot, recorded. |
| M6 | compose default `:-1}` -> `:-0}` | `AcceptanceConfigurationGuardTests` | KILLED |
| M6b | Delete the compose line entirely | both guard tests | KILLED (scan-count guard fires first) |
| M7 | Disabled `/advanced` writes a table | `ToggleReversibilityTests` iterdump digest | KILLED (both hashes reported) |
| M8 | `ENABLE_ADVANCED_DIAGNOSTICS: "0"` added to the `web` service's own `environment:` | `AcceptanceConfigurationGuardTests` | **SURVIVED** — gap 2 |

## Requirements Coverage

| Requirement | Source Plans | Status | Evidence |
|---|---|---|---|
| DIA-09 | 07-01, 07-02, 07-03 | **BLOCKED (partial)** | Everything except "serving none of its routes" is verified and mutation-confirmed. Two advanced-workspace-only routes remain ungated (gap 1). Keep `- [ ]` at REQUIREMENTS.md:44 and `Pending` at :139 until gap 1 is resolved. |

No orphaned requirements: `grep -E "Phase 7" .planning/REQUIREMENTS.md` maps DIA-09 alone to this phase.

## Anti-Patterns Found

| File | Pattern | Severity | Impact |
|---|---|---|---|
| — | `TBD` / `FIXME` / `XXX` / `HACK` / `PLACEHOLDER` | none | Scanned all six phase-modified files. Zero markers. No unreferenced debt. |

## Observations (not gaps)

1. **The dataclass default is decorative.** `Settings.enable_advanced_diagnostics: bool = True`
   (config.py:71) is never the value a deployment gets — `load_settings` is the only constructor and it
   passes `_enabled(source.get('ENABLE_ADVANCED_DIAGNOSTICS', '1'))` explicitly. Mutation M1 confirms
   changing :71 alone changes nothing and fails nothing. The two literals agree today; a future editor
   changing :71 believing it controls the default would get silence. Harmless now, a drift hazard later.
2. **Disabled `/` omits the charset.** The disabled branch returns `{'Content-Type': 'text/html'}`,
   while `send_file` on the enabled branch sends `text/html; charset=utf-8`. `index.html` contains
   non-ASCII characters (`—`, `…`, `↻`), so this would matter — except `<meta charset="utf-8">` sits at
   `index.html:4`, well inside the first 1024 bytes, so browsers decode correctly. Cosmetic, untested,
   and worth one line if the disabled branch is ever touched again.
3. **The `_enabled` asymmetry is correctly pinned.** A typo (`'enabled'`) resolves a default-ON toggle to
   OFF — the opposite of its default. D-07-DECISIONS records this as accepted and
   `test_an_out_of_vocabulary_value_is_treated_as_disabled` pins it. Confirmed present; not re-litigated.
4. **The scope fence held.** `tests/pi_load_acceptance.py` is unmodified at HEAD, as 07-03's fence
   required, and `ROUTE_BUDGETS_MS` is untouched.

## Gaps Summary

The phase built what it said it built, and — unusually — proved it. Five for five on the ROADMAP
criteria, each confirmed by breaking the code and watching the guard catch it. The cost measurement
counts real statements on both sides at one-statement granularity, and the golden's referent is
authentic against `ceef6da`'s blobs.

Three things stand between here and a clean DIA-09 promotion, in descending order of weight:

1. **Two ungated advanced-workspace routes** (`/api/telemetry/history`, `/api/events/history`) leave a
   "disabled" deployment serving the advanced surface's data APIs, against DIA-09's "serving none of its
   routes". Small fix, real gap, entirely unconsidered by the phase.
2. **PROH-DIA-09-01's compose guard is narrower than its own record claims** — a per-service
   `environment:` override walks past it, and only the shell-export escape is documented.
3. **The golden comparison is not hermetic against `TZ`**, contradicting the module docstring's explicit
   claim. It fails loudly rather than passing silently, and the fix is one line.

Two items already owned elsewhere are recorded and deliberately **not** re-raised as Phase 7 defects,
per 07-DEBT.md's opening request: D-DEBT-07-01's acceptance-harness blindness to a 404 (Phase 6's next
OPS-07 round) and the `resolution_policy` literal drift (Phase 3). On the latter, the brief's question
was whether Phase 7's golden makes the drift harder to fix: **marginally, and not materially** — the
same literal is already frozen in a Phase 3 fixture and asserted in `test_advanced_ui.py:867`, this is
the third pin site rather than the first, the failure it would produce is loud and names its referent,
and `generate_enabled_response_golden()` exists to regenerate it.

---

_Verified: 2026-09-07T11:30:00Z at HEAD `dc8626a`_
_Verifier: Claude (gsd-verifier) — goal-backward, mutation-confirmed_
