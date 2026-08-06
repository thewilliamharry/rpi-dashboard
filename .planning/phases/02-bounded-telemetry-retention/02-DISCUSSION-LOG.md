# Phase 2: Bounded Telemetry & Retention - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-07
**Phase:** 2-bounded-telemetry-retention
**Areas discussed:** Detail over 90 days, Missing-data meaning, Pressure and failed rollups

---

## Detail Over 90 Days

### Raw-detail window

| Option | Description | Selected |
|--------|-------------|----------|
| 7 days raw | Keep raw host metrics and service checks for 7 days, then aggregate through day 90. | ✓ |
| 24 hours raw | Minimize storage at the cost of multi-day detail. | |
| 30 days raw | Preserve substantially more raw detail with greater SQLite cost. | |
| Different windows | Give host metrics, service checks, and events separate raw windows. | |

**User's choice:** 7 days raw.
**Notes:** The user asked whether data remains after day 90. The fixed Phase 2 contract expires it after 90 days.

### Aggregate tiers

| Option | Description | Selected |
|--------|-------------|----------|
| Two tiers | Five-minute aggregates for days 8-30, then hourly aggregates for days 31-90. | ✓ |
| 15 minutes throughout | One aggregate resolution from day 8 through day 90. | |
| Hourly throughout | Smallest aggregate footprint with lower incident detail. | |
| Different telemetry tiers | Separate resolutions for host and service observations. | |

**User's choice:** Two tiers.
**Notes:** The user proposed extending hourly aggregates to day 365; this was deferred because the roadmap and TEL-01 fix this phase at 90 days.

### Event retention

| Option | Description | Selected |
|--------|-------------|----------|
| Full events for 90 days | Preserve each individual event throughout retained history. | ✓ |
| Full for 30 days, summaries afterward | Replace older individual events with daily summaries. | |
| Critical events for 90 days | Expire routine events earlier. | |
| Observation-style tiers | Replace older events with bucketed counts. | |

**User's choice:** Full events for 90 days.

### Aggregate evidence

| Option | Description | Selected |
|--------|-------------|----------|
| Diagnostic summary | Preserve host min/max/average/latest/count and service coverage, latency, check, and failure-class evidence. | ✓ |
| Compact summary | Preserve averages, availability, and counts only. | |
| Range-focused summary | Preserve range statistics without latest values or failure breakdowns. | |
| Agent discretion | Let research choose the minimum Phase 4-compatible schema. | |

**User's choice:** Diagnostic summary.

---

## Missing-Data Meaning

### Missing interval vocabulary

| Option | Description | Selected |
|--------|-------------|----------|
| Explicit reason for every interval | Distinguish collection gaps, unknown values, expired history, and time before monitoring began. | ✓ |
| Three reasons | Combine expired and not-yet-monitored history. | |
| Gap versus unavailable | Collapse all non-gap missing history together. | |
| Agent discretion | Let planning choose a TEL-04-compliant vocabulary. | |

**User's choice:** Explicit reason for every interval.

### Gap threshold

| Option | Description | Selected |
|--------|-------------|----------|
| Two missed observations | Confirm after two expected samples, beginning the gap at the first missed boundary. | ✓ |
| One missed observation | Classify every missed expected sample as a gap. | |
| Three missed observations | Tolerate two missed samples before classification. | |
| Different threshold by stream | Give host and service streams separate thresholds. | |

**User's choice:** Two missed observations.

### Mixed-coverage buckets

| Option | Description | Selected |
|--------|-------------|----------|
| Preserve coverage separately | Compute only from observed values and report gap/unknown coverage without interpolation. | ✓ |
| Mark whole bucket unknown | Hide all bucket values when any coverage is missing. | |
| Interpolate short gaps | Fill missing values for smoother history. | |
| Coverage threshold | Show values only above a configured observed percentage. | |

**User's choice:** Preserve coverage separately.

### Partially unavailable ranges

| Option | Description | Selected |
|--------|-------------|----------|
| Full requested range | Preserve requested bounds and encode expired/not-yet-monitored intervals with coverage metadata. | ✓ |
| Clamp with notice | Return only available time and disclose effective bounds. | |
| Reject request | Require the entire request to fall inside retained history. | |
| Partial data with warning | Return available rows without structured unavailable segments. | |

**User's choice:** Full requested range with coverage metadata.

---

## Pressure and Failed Rollups

### Rollup failure

| Option | Description | Selected |
|--------|-------------|----------|
| Keep raw data and retry | Preserve source evidence, record pending aggregation, and retry with bounded backoff. | ✓ |
| Retry then expire | Delete raw data after a fixed retry count. | |
| Stop collection | Halt telemetry until rollups recover. | |
| Require intervention | Preserve raw data and wait for manual recovery. | |

**User's choice:** Keep raw data and retry automatically.

### Exhausted storage reserve

| Option | Description | Selected |
|--------|-------------|----------|
| Keep monitoring, pause history | Continue current state, suspend historical persistence, and record a storage-pressure gap. | ✓ |
| Delete oldest unaggregated data | Preserve new history by discarding source evidence. | Initially selected, then rejected |
| Exceed storage limit | Preserve all writes beyond the configured boundary. | |
| Stop monitoring | Halt all collection and allow current state to become stale. | |

**User's choice:** The user initially chose deleting unaggregated observations. That conflicts with locked TEL-03, so the compliant alternatives were presented; the user selected continued live monitoring with paused historical persistence.

### Storage boundary

| Option | Description | Selected |
|--------|-------------|----------|
| Dual guardrail | Enforce a configurable telemetry allocation and a minimum free-disk reserve. | ✓ |
| Fixed database cap | Enforce database size without considering filesystem pressure. | |
| Disk percentage | Let the allocation move with available disk. | |
| Free-space reserve only | Protect the disk without a dedicated telemetry allocation. | |

**User's choice:** Dual guardrail.

### Pressure recovery

| Option | Description | Selected |
|--------|-------------|----------|
| Automatic with hysteresis | Resume below a lower threshold, preserve the gap, and never invent missed history. | ✓ |
| Resume at the limit | Resume immediately when storage reaches the pressure threshold. | |
| Manual resume | Require the operator to restart persistence. | |
| Reconstruct history | Derive missed observations after recovery. | |

**User's choice:** Automatic recovery with hysteresis.

---

## the Agent's Discretion

- Exact storage cap and free-space reserve defaults.
- Warning, pressure, recovery, hysteresis, and emergency-reserve thresholds.
- Retry/backoff timing and internal schema/module design.
- Bounded historical response-point budget and deterministic range-to-resolution thresholds.

## Deferred Ideas

- Consider retaining hourly telemetry aggregates through day 365 in a future phase.
