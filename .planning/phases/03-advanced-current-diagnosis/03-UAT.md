---
status: complete
phase: 03-advanced-current-diagnosis
source: [03-VERIFICATION.md]
started: 2026-08-19T21:35:00Z
updated: 2026-08-20T21:50:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Real collection gap and stale host on the target Pi
expected: Open `/advanced` on the Pi while a real collection gap is active and while host evidence is stale. The workspace shows the open gap and the stale host as real, correctly labelled exceptions, and shows no resolved or retention-expired interval as an open actionable gap.
result: pass
evidence: |
  Staged on real hardware 2026-08-20 ~13:00 by stopping the worker (genuine stale
  host + stale worker heartbeat) and seeding open_gap_start_ts on host/cpu only.
  Overview "Active exceptions" showed exactly 3 cards: "Host evidence is stale",
  "Worker heartbeat is stale", and "Open collection gap - host: cpu" with interval
  12:54:47 PM to 1:00:14 PM (matches the seeded open_gap_start_ts and the
  max(now, open_gap_start_ts) end bound at diagnosis.py:305).
  Pipeline "Collection gaps (48 gaps, truncated)" listed "host: cpu - Open
  actionable gap." at the TOP, above 47 "Resolved historical gap" entries -
  confirming the open-first priority sort at diagnosis.py:316 survives the
  gap_limit slice in production, not just in analysis.
  Discriminating evidence for the 03-08-PLAN.md prohibition: host disk/ram/temp
  were equally stale (stream-level fact, 9 minutes) but correctly produced NO
  open actionable gap, because only host/cpu carried a durable open_gap_start_ts.
  The open/actionable label was derived from the durable row it describes, never
  from a neighbouring row or a stream-level fact.
  Zero resolved or retention-expired intervals appeared as open actionable.

### 2. Idle Pi, one minute, Active exceptions region
expected: Start the worker on the Pi, leave the system idle for one minute, open `/advanced` and read the Overview "Active exceptions" region. No "Background job failed" card for any job, and no "Background job outcome not recorded" card for any job that is simply working.
result: pass
evidence: |
  Observed 2026-08-20 13:03, ~2 minutes after worker restart following an
  8m44s induced outage. Overview "Active exceptions" held 4 cards, ALL of kind
  "Recently resolved collection gap" (host cpu/ram/disk/temp). Zero
  "Background job failed" cards and zero "Background job outcome not recorded"
  cards - including none for P0, the non-schedulable prepare callback that
  renders as state=unknown / Not scheduled and was the specific false-positive
  risk. J5 and J6 both simply working, neither promoted.
  Stronger than plain idle: this was the post-outage restart path (S1/S2/S3
  startup callbacks plus J9 startup discovery all ran) and still produced no
  spurious job promotion.
  NOTE: this test is the NEGATIVE half only. Absence of a job card cannot by
  itself distinguish "jobs healthy" from "promotion broken"; test 3 is the
  discriminating positive counterpart.

### 3. Deliberately broken browser, two minutes, Pipeline region
expected: With Chromium/Playwright deliberately unavailable on the Pi, leave the worker running for two minutes, then open `/advanced` and read the Pipeline region. A "Background job failed" card names J6 — the new operator-facing signal round 8's fix adds.
result: pass
evidence: |
  Staged 2026-08-20 21:43 local by overriding PLAYWRIGHT_BROWSERS_PATH to a
  nonexistent path via a compose override (the container is read_only:true, so
  the filesystem cannot be altered), recreating the worker, and clearing all 8
  service thumbnails so J6 had queued work. Both enqueue sites are gated on
  has_thumb (app.py:1310 discovery, app.py:1458 uptime), so a phase with valid
  screenshots can never hand J6 work - this is why the first two attempts were
  inconclusive rather than failing.
  DIRECTLY OBSERVED on real hardware, polling background_job_health at 0.25s:
    21:43:31 ('failed', 'PreviewCaptureUnavailable')
    ... 8 consecutive failure cycles, one per cleared thumbnail ...
    21:43:45 ('failed', 'PreviewCaptureUnavailable')
    21:43:46 ('succeeded', None)
  Corroborated durably in events: preview_capture / preview_complete for port
  4500 both carry error_class='browser_unavailable', exactly
  THUMB_ERROR_BROWSER_UNAVAILABLE (app.py:68), proving app.py:2077 was reached
  and PreviewCaptureUnavailable was raised - the machinery fault correctly
  distinguished from a per-service fault. J5 stayed 'succeeded' throughout.
  CAVEAT - the render itself was NOT visually captured. The Pipeline screenshot
  was taken at 21:44:04, 19 seconds after the failed window closed. Promotion at
  diagnosis.py:484 is an unconditional `if job['state'] == 'failed'`, and the
  state was directly observed, so the card is a deterministic consequence; but
  the browser-served render of it remains unphotographed.
  SIGNAL DURATION: the failed state is transient. An empty queue returns None =
  "a completed poll, not a failure" (app.py:2036) and background_job_health keeps
  only the latest outcome per job, so J6's 2-second cadence overwrites `failed`
  with `succeeded` on the next poll. Window length scales with queue depth: ~15s
  for 8 queued requests, ~2s for a single one, against a 15s page refresh. See
  Deferred Follow-Ups.

### 4. Advanced workspace control affordance
expected: Interactive controls in the `/advanced` workspace read as interactive - pointer cursor and a hover state - and `Refresh now` carries the accent treatment 03-UI-SPEC.md reserves for it.
result: issue
reported: "Also the refresh now button doesn't feel like it's a button, doesn't react to hover and doesn't show a click pointer when hovering over it"
severity: cosmetic

## Summary

total: 4
passed: 3
issues: 1
pending: 0
skipped: 0
blocked: 0

## Gaps

- gap_id: G-03-4
  truth: "Interactive controls in the /advanced workspace read as interactive (pointer cursor, hover state), and `Refresh now` carries the accent treatment 03-UI-SPEC.md reserves for it."
  status: failed
  reason: "User reported: Also the refresh now button doesn't feel like it's a button, doesn't react to hover and doesn't show a click pointer when hovering over it"
  severity: cosmetic
  test: 4
  root_cause: "dashboard/advanced.css contains zero `cursor` declarations and zero `:hover` rules for the entire advanced workspace. #advanced-refresh inherits only the neutral `.advanced-header-controls button` rule (advanced.css:9, `color: var(--text); background: var(--bg3)`), so it has no pointer cursor, no hover feedback, and none of the accent 03-UI-SPEC.md:76 reserves for the `Refresh now` action. Only `button:focus-visible` (advanced.css:56) exists, which covers keyboard focus but gives mouse users no affordance at all. dashboard/style.css on the main dashboard defines both cursor and :hover throughout, so /advanced is inconsistent with the rest of the app."
  artifacts:
    - path: "dashboard/advanced.css"
      issue: "No cursor:pointer and no :hover rules anywhere; Refresh now lacks the UI-SPEC-reserved accent"
  missing:
    - "Add `cursor: pointer` to interactive controls: .advanced-header-controls button/select, .section-navigation button, .service-filters button, .service-details-toggle, #services-table th button"
    - "Add :hover states consistent with style.css conventions on the main dashboard"
    - "Give #advanced-refresh the accent treatment per 03-UI-SPEC.md:76, which reserves accent for the `Refresh now` action"
  debug_session: ""

## Deferred Follow-Ups

- test: 3
  idea: "J6's operator-facing failure signal is transient by construction. background_job_health retains only the latest outcome per job, and J6 polls every 2 seconds, so a `failed` state is overwritten by the next empty-queue poll (app.py:2036 returns None = completed poll). Observed window was ~15s with 8 queued requests and ~2s with one, against a 15s /advanced refresh interval. A genuinely broken Chromium is therefore visible to an operator only if a refresh happens to land inside a short window. Worth considering a sticky or last-failure-retaining representation so a real machinery fault is not missed. NOT a defect in round 8's fix, which was directly confirmed to fire correctly."
  deferred_at: 2026-08-20
