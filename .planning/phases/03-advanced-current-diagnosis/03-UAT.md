---
status: testing
phase: 03-advanced-current-diagnosis
source: [03-VERIFICATION.md]
started: 2026-08-19T21:35:00Z
updated: 2026-08-19T21:35:00Z
---

## Current Test

number: 1
name: Real collection gap and stale host on the target Pi
expected: |
  The workspace shows the open gap and the stale host as real, correctly labelled
  exceptions, and shows no resolved or retention-expired interval as an open
  actionable gap.
awaiting: user response

## Tests

### 1. Real collection gap and stale host on the target Pi
expected: Open `/advanced` on the Pi while a real collection gap is active and while host evidence is stale. The workspace shows the open gap and the stale host as real, correctly labelled exceptions, and shows no resolved or retention-expired interval as an open actionable gap.
result: [pending]

### 2. Idle Pi, one minute, Active exceptions region
expected: Start the worker on the Pi, leave the system idle for one minute, open `/advanced` and read the Overview "Active exceptions" region. No "Background job failed" card for any job, and no "Background job outcome not recorded" card for any job that is simply working.
result: [pending]

### 3. Deliberately broken browser, two minutes, Pipeline region
expected: With Chromium/Playwright deliberately unavailable on the Pi, leave the worker running for two minutes, then open `/advanced` and read the Pipeline region. A "Background job failed" card names J6 — the new operator-facing signal round 8's fix adds.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
