---
phase: 7
slug: optional-advanced-diagnostics
kind: decisions-and-prohibitions
created: 2026-09-04
---

# Phase 7 — Decisions & Prohibitions

> Consolidates the decisions made across `07-01`, `07-02` and `07-03` into one canonical record, plus
> `PROH-DIA-09-01`, minted by `07-03` to fence the shortcut this phase's own toggle creates against
> Phase 6's OPS-07 acceptance gate.

---

## D-07-01 — the toggle defaults enabled

**Decision.** `Settings.enable_advanced_diagnostics: bool = True` — the only one of this phase's (and
`06-15`'s) three optional-surface toggles that defaults **on**, rather than off like
`enable_prometheus`/`enable_lock_profile`.

**Why.** Existing deployments already have the advanced-diagnosis workspace today. A default-off
toggle would mean an upgrade that sets no new environment variable silently removes a page the
operator already relies on. Silent removal on upgrade is worse than the (measured, in `07-03`, to be
zero — see D-07-07) cost of leaving it on.

**Rejected alternative.** Default off, matching the other two toggles' shape for consistency. Rejected
because consistency with a sibling toggle's default does not outweigh silently regressing an existing
deployment's functionality on upgrade.

---

## D-07-02 — gating is a handler-level 404, first statement, mirroring the two existing gates exactly

**Decision.** Every gated route (`api_advanced_current`, `advanced_index`, `serve_advanced_css`,
`serve_advanced_js`) opens with `if not ENABLE_ADVANCED_DIAGNOSTICS: return '', 404` as its literal
first statement, ahead of any other check (e.g. `request.args`) — mirroring `prometheus_metrics` and
`lock_profile_snapshot`'s existing gate shape exactly, four times over.

**Why gate-first.** A disabled route must not be probeable for the difference between a 400 (bad
request, route exists) and a 404 (route absent) to learn the route exists at all.

**Rejected alternative.** Conditional route registration (only calling `@app.route(...)` when the
toggle is on, so Flask itself returns 404 for an unregistered route). Rejected because it would put
route registration behind a runtime branch of the toggle across the whole module, a larger and more
diffuse change than one early-return per handler, for a behaviorally identical outcome. Consistency
with the two existing gates (D-07-02's driving reason) also favored the same mechanism already proven
in this codebase.

---

## D-07-03 — the enabled path is left textually unchanged

**Decision.** Every gated handler's enabled branch (`return send_file(...)`) is left byte-for-byte as
it was before this phase, below the new guard. `index()`'s enabled branch (`send_file("index.html",
...)`) is likewise untouched; only the disabled branch is new.

**Why.** Byte-identity between the enabled behavior and the pre-phase behavior (criterion 4) becomes a
property of the **code shape** — the enabled path literally cannot diverge because no phase-7 edit
touches it — rather than a property that only a test happens to currently confirm. This is also what
makes `07-01`'s pre-change golden fixture a durable, structural guarantee rather than a snapshot that
could quietly rot if the enabled path were later refactored.

---

## D-07-04 — all four routes gated; static assets deliberately kept in the production image

**Decision.** All four advanced surfaces (`/advanced`, `/advanced.css`, `/advanced.js`,
`/api/advanced/current`) are gated identically (D-07-02's shape). The underlying asset files
(`advanced.html`, `advanced.css`, `advanced.js`) are **not** removed from the production image or
conditionally excluded from the build — they simply become unreachable when the toggle is off.

**Why.** Removing the files from the image would require a build-time toggle (baked in at image build,
not runtime), which contradicts the toggle's runtime-configurable nature (D-07-01) and would make
flipping the toggle require a rebuild rather than a restart (which criterion 5 and D-07-09 require it
not to).

---

## D-07-05 — server-side, once-per-process removal of the front page's entry point

**Decision.** `dashboard/beacon/frontpage.py`'s `without_advanced_entry_point` excises the front page's
advanced-diagnosis anchor server-side, computed at most once per process via
`dashboard/app.py`'s `_index_document_without_advanced_entry_point` cache, on the disabled branch only.

**Rejected alternatives** (all three considered and rejected):

1. **Client-side fetch-then-remove** (ship the link in every response, have `app.js` hide/remove it
   after a config fetch). Rejected: the link is still present in the served bytes, violating
   criterion 2's "absent, not hidden" requirement outright — a client that doesn't run the removal
   script (or inspects the raw response) still sees the link.
2. **A toggled wrapper element added to `index.html` itself** (e.g. wrap the anchor in a
   server-conditional template block evaluated on every request, enabled or not). Rejected: this moves
   the *enabled* path's served bytes away from the raw file on disk, which is exactly what criterion 4
   and `07-01`'s captured golden forbid — the enabled path must stay byte-identical to `index.html`,
   and any templating mechanism touching that file changes what the enabled path serves even though
   its *behavior* wouldn't change.
3. **A second front-page file** (`index-disabled.html`, served instead of `index.html` when the toggle
   is off). Rejected: doubles the front-page markup as a maintenance burden (every future front-page
   edit must be made in two places, and the two can silently drift), for no benefit `without_advanced_
   entry_point`'s single-source transform doesn't already provide more cheaply.

**Never no-ops.** The transform raises `AdvancedEntryPointNotFound` on anything other than exactly one
regex match — a silent no-op would serve the link on a deployment that turned the feature off, the
exact failure criterion 2 forbids.

---

## D-07-06 — the front page's script must tolerate the absent anchor

**Decision.** `dashboard/app.js`'s two `advanced-diagnosis-link` element lookups (the `DOMContentLoaded`
click-listener registration and `restoreDashboardScroll`'s focus call) are each guarded independently
(resolve into a local, branch on truthiness) rather than consolidated into one shared check.

**What breaks if unguarded.** Site 772 (`DOMContentLoaded`)'s unguarded lookup throws synchronously and
kills the rest of `DOMContentLoaded` — the services grid never populates, on *every* load, not only one
touching the advanced link. Site 762 (`restoreDashboardScroll`)'s unguarded lookup throws only when a
scroll position was seeded in `sessionStorage`, asynchronously, two animation frames after boot — a
narrower, easy-to-miss failure mode that an ordinary Playwright load never reaches.

**Why independent guards, not one consolidated check.** The two sites fail on different code paths
reached under different conditions (07-02's own mutation-verified asymmetry: reverting only the
line-762 guard leaves ordinary loads passing while breaking only the seeded-scroll subtest).
Consolidating them into one shared guard would have hidden that asymmetry rather than proven it, and
`07-02`'s own acceptance criteria required proving both failure modes independently.

---

## D-07-07 — the front-page cost property is an equality between measured counts, never a threshold

**Decision.** `07-03`'s `FrontPageCostEqualityTests` asserts the front-page boot request set's total
measured SQLite statement count and total connection count are **equal** with the toggle off versus on
— never compared against a literal, a ratio, or a duration ceiling for either side.

**Why equality, not a threshold.** Both terms are measured in the same run, over the same seeded
database. A threshold would tie the guard to the seeded dataset's size and the executing machine —
`D-DEBT-06-14` (Phase 6) records exactly this defect class: an absolute-millisecond band calibrated to
one dataset size failed the moment the Pi's dataset grew, for a reason unrelated to whether the
attributed mechanism was real. An equality between two same-run measurements moves both sides together
as the dataset grows and keeps meaning what it meant.

**Why this gives criterion 3 real content.** Read literally, criterion 3 ("a request to the services
front page performs none of the work advanced diagnostics would have required") is close to vacuous
against today's code: `/` is a static `send_file` that performs no diagnosis work today even with the
feature fully enabled. The property this equality actually protects is that *whatever mechanism tells
the front page about the toggle* (D-07-05's server-side transform) costs the front page nothing — the
one way this phase's own implementation could have made criterion 3 false.

---

## D-07-08 and D-07-09 — no-stored-change and restart-reversibility, and why `iterdump` rather than file bytes

**D-07-08 (no stored change).** `07-03`'s `ToggleReversibilityTests` asserts a disabled session's
database — after exercising the full front-page boot set plus all four gated routes — has an unchanged
`iterdump()` sha256 digest and an unchanged applied schema version (read via
`dashboard.beacon.migrations._recorded_version`, the same query the migration runner itself uses).

**D-07-09 (restart reversibility).** The same database file, reopened by a fresh process build with the
toggle back on, serves `07-01`'s captured golden again on `/api/advanced/current` — proving the round
trip is a restart, nothing more: no migration, no destructive step, nothing to undo.

**Why `iterdump`'s logical content, not the file's bytes, is the oracle.** The deployment runs SQLite
in WAL mode, so even purely read-only traffic can move the `-wal`/`-shm` sidecar files without changing
any row's content. A file-bytes comparison would fail for a reason **unrelated** to stored data —
and a guard that fails for reasons unrelated to what it's supposed to protect is a guard that gets
disabled by whoever hits that false failure first, which is worse than no guard at all. `iterdump()`'s
logical content is the property criterion 5 actually names.

---

## The inherited `_enabled` behaviour: an out-of-vocabulary value resolves to disabled

**Decision (pinned, accepted).** `enable_advanced_diagnostics` is parsed through the same `_enabled`
helper `enable_prometheus`/`enable_lock_profile` already use. That helper's vocabulary treats
`{'1', 'true', 'yes', 'on'}` (case-insensitive) as enabling and **everything else** — including a typo
like `'enabled'` — as disabling.

**The asymmetry this creates.** For the two existing toggles (default **off**), an out-of-vocabulary
value degrades to the *default* — off stays off. For `enable_advanced_diagnostics` (default **on**), an
out-of-vocabulary value degrades to **disabled**, the *opposite* of the default. This is the one respect
in which this phase's default-on toggle behaves differently from its two default-off siblings sharing
the same parse helper.

**Why accepted rather than special-cased.** Consistency with the two existing toggles' parsing
mechanism (one helper, one vocabulary, no bespoke third parser) was preferred over inventing a
default-aware parse behavior solely for this one field. The alternative — an out-of-vocabulary value
resolving to the field's own default rather than to `_enabled`'s fixed "everything else is falsy"
behavior — would need a second, bespoke parsing function used nowhere else in `config.py`, for a
narrower and more surprising contract (the same string could parse to a different boolean depending on
which field it's assigned to).

**Pinned by test.** `tests/test_optional_advanced_diagnostics.py::SettingsAdvancedDiagnosticsTests::
test_an_out_of_vocabulary_value_is_treated_as_disabled` — a typo (`'enabled'`) resolves to `False`,
not to the field's own `True` default. This is recorded here as a deliberate, accepted property, not an
accident a later reader has to rediscover.

---

## PROH-DIA-09-01

> **Every OPS-07 acceptance run measures the fully-enabled configuration. The advanced-diagnostics
> toggle is a deployment mode, never a test knob. No OPS-07 pass may be reached with it off, and the
> shipped deployment default must resolve to enabled.**

**What it specializes.** `PROH-OPS-07-01` and `PROH-OPS-07-10` (Phase 6) already forbid reaching an
OPS-07 pass by asking less of the deployment than a real deployment would face. `PROH-DIA-09-01` states
the specific instance this phase's own toggle creates: `/api/advanced/current` is one of the routes
currently failing Phase 6's Pi acceptance budgets, and by a wide distance the most expensive route in
the mix (584s CPU / 1,090,992ms off-CPU across 750 requests in round 5b, per `06-DEBT.md`). Turning the
toggle off makes an acceptance run dramatically easier to pass — and would report a pass while
measuring a deployment configuration no real operator running OPS-07's own intended workload would
ship.

**What guards it, and what does not close it.** `07-03`'s `AcceptanceConfigurationGuardTests` proves
the *shipped default* resolves to enabled by feeding `docker-compose.yml`'s own
`ENABLE_ADVANCED_DIAGNOSTICS` value, resolved for the operator-sets-nothing case, through the real
`load_settings` parser. This raises the cost of using the toggle to buy a pass; it does **not** make it
impossible — it detects one specific act (flipping the shipped compose default) and would not detect an
operator exporting a disabling shell variable immediately before running an acceptance round by hand.
`D-DEBT-07-01` (`07-DEBT.md`) records the deeper, structural reason a determined misuse could still slip
through undetected by the acceptance harness itself: `tests/pi_load_acceptance.py`'s own `_load_worker`
never inspects response status, so a 404 from a disabled route is recorded as a fast success. This
phase is forbidden from modifying that file, so it records the hole rather than closing it.
