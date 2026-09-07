---
phase: 1
slug: behavioral-safety-runtime-ownership
status: draft
shadcn_initialized: false
preset: none
created: 2026-07-24
---

# Phase 1 — UI Design Contract

> Visual and interaction contract for the safety and compatibility surfaces introduced in Phase 1. Preserve the dashboard's existing information architecture, compact analytics, service cards, event panel, and theme toggle.

---

## Design System

| Property | Value |
|----------|-------|
| Tool | none — retain dependency-free HTML, CSS, and vanilla JavaScript |
| Preset | not applicable; `components.json` is absent and this is not a React/Next/Vite project |
| Component library | none |
| Icon library | none; retain existing text labels and the `↻` scan glyph |
| Font | Existing system sans (`--font-sans`) and monospace (`--font-mono`) stacks |

Use the existing CSS custom properties; do not introduce a framework, font download, icon package, route, sidebar, or advanced-workspace navigation in this phase. Light mode remains calm and sparse; dark mode retains the existing dense instrumentation treatment. Both expose the same Phase 1 safety information.

---

## Spacing Scale

Declared values (must be multiples of 4):

| Token | Value | Usage |
|-------|-------|-------|
| xs | 4px | Status-dot and icon gaps; badge internal separation |
| sm | 8px | Inline warning/badge padding and service-card subrows |
| md | 16px | Banner and modal content padding; default control separation |
| lg | 24px | Section and empty-state padding |
| xl | 32px | Desktop page and topbar inset |
| 2xl | 48px | Existing major section break and empty state |
| 3xl | 64px | No new Phase 1 surface; reserved page-level break |

Do not add new icon-only actions in this phase. At a narrow viewport (720px or less), any Phase 1 action presented in the metadata modal remains full-width and at least 44px tall; no safety state may depend on hover.

---

## Legacy Compatibility Dimensions

Preserve the existing 1px borders, 5–6px state-pip diameters, and current compact desktop controls unchanged for compatibility. These are inherited visual dimensions, not spacing tokens; no new Phase 1 layout, alignment, gap, padding, or action sizing may depend on them.

---

## Typography

Apply these values to Phase 1 additions. Existing unrelated typography remains unchanged.

| Role | Size | Weight | Line Height |
|------|------|--------|-------------|
| Body / feedback | 12px | 400 regular | 1.5 |
| Label / badge | 10px | 600 semibold | 1.4 |
| Heading / modal status | 14px | 600 semibold | 1.2 |
| Display | 16px | 600 semibold | 1.2 |

Use only the two declared weights for new safety content. Use sentence case in light mode; retain the existing compact uppercase label treatment in dark mode only where it already appears. Do not convey status through a glyph or colour without its text label.

---

## Color

| Role | Value | Usage |
|------|-------|-------|
| Dominant (60%) | dark `#010a14`; light `#ffffff` | Page background and the primary surface behind the dashboard |
| Secondary (30%) | dark `#030f1e` / `#041525`; light `#f7f7f7` | Existing cards, modal fields, topbar, and safety-status container |
| Accent (10%) | dark `#00d4ff`; light `#0066cc` | Existing keyboard focus ring, scan action, active scan progress, and primary Save affordance only |
| Warning / degraded | dark `#ffab00`; light `#b45309` | Stale-worker, queued/expired work, and `TLS unverified` notice; never a downtime state by itself |
| Destructive | not used by a Phase 1 control | No delete, restore, backup-removal, or migration-retry action is exposed in the browser |

Accent reserved for: the scan action, queued/running scan progress, metadata Save, and keyboard focus. Do not use accent to mark stale monitoring, TLS posture, expiry, recovery, or availability.

All status text must retain a 4.5:1 contrast ratio against its container in each theme. Retain the existing green/red availability colours only alongside the explicit `ONLINE`/`OFFLINE` text; this legacy availability treatment is separate from the unused destructive-control colour. Use the warning colour only alongside an explicit warning label.

---

## Visual Hierarchy

- **Primary focal point when a safety condition is present:** the safety-warning cluster is the first content block below the topbar and the page's primary visual anchor. Its stale-worker or migration/recovery warning precedes all existing dashboard content, stays full width, and cannot be displaced by scan status, cards, or events. When the existing browser/API connection alert and a stale-worker warning are both known, preserve their locked order within this cluster: connection alert first, stale-worker warning second. A migration/recovery warning remains within the same cluster rather than competing with dashboard content.
- **Default content order when no stale-worker or migration/recovery warning is present:** existing system-health metrics lead; scan status follows; service cards come next; the event panel follows service cards. Do not elevate a queued scan, preview status, or `TLS unverified` badge above system-health metrics.
- **Theme expression:** light mode presents this order with the existing calm, spacious surfaces; dark mode preserves its denser instrumentation and compact labels. Both modes retain the same focal-point rule, content order, controls, and information.

---

## Interaction and State Contract

### Monitoring ownership and stale worker

- Add one persistent, full-width warning immediately below the topbar and above the existing dashboard content whenever the worker heartbeat is stale. It must be visually distinct from a browser/API connection failure.
- Worker stale copy: **“Monitoring paused — worker unavailable. Dashboard data may be stale; service settings changes are still saved.”** Render it as a polite live status, not a modal and not an overlay. The page, service links, metadata editor, scan action, theme toggle, and already loaded data remain interactive.
- Browser/API connection failure retains the existing alert treatment and copy: **“Beacon is disconnected. Displayed data may be stale.”** Do not replace it with the worker-stale warning. If both conditions are known, show the connection alert first and the worker-stale warning second.
- When the worker heartbeat becomes fresh, remove the stale-worker warning automatically. Announce **“Monitoring resumed. The outage was recorded in Events.”** once through the existing feedback region, then show the persisted monitoring-gap event in the event panel. Do not require a page refresh or user acknowledgement.
- The monitoring-gap event row is sentence case in light mode and may use the existing compact dark label treatment. Its title is **“Monitoring gap recorded”** and its secondary text is **“Worker unavailable for {duration}.”** It is informational/warning, not an outage for any monitored service.

### Scan and preview queues

- Keep the existing topbar scan control labelled **“↻ scan now.”** When the worker is stale, it remains enabled except while its HTTP submission is in flight. Clicking it creates a durable request; it must never imply that the scan has already run.
- Topbar scan states use text plus the existing status pip: `Scan queued — runs when monitoring resumes`; `{stage} {percent}% · {found} found`; `{found} found · {relative time}`; and `Scan request expired — it was not run. Scan again.` An expired request returns the button to enabled without automatic retry.
- Do not disable the scan control simply because a request is queued. Disable only during a submission or while one scan is actively running; expose its queued/running state in the adjacent `role="status"` text.
- Add a per-service, non-interactive preview status line directly below existing service detail/tags when applicable: `Preview refresh queued`, `Refreshing preview`, `Preview refresh failed — saved settings are unaffected`, or `Preview refresh expired — save service details to request a new preview.` This line is separate from `ONLINE`/`OFFLINE` and does not alter service availability styling.
- Queued work has bounded age: manual scans expire after 15 minutes and previews after 30 minutes. Render expiry as a warning with the explicit word `expired`; recovery may run only still-relevant work. A recovered request transitions through the same queued/running text rather than creating a second UI flow.

### Metadata edits while the worker is unavailable

- Preserve the existing modal, keyboard focus trap, Escape/cancel behaviour, validation location, and post-save service-card refresh. The web process saves validated metadata immediately; it must not wait for a worker heartbeat.
- When stale monitoring is known, show a compact warning above the modal actions before submit: **“Monitoring is paused. Your service details will be saved now; preview refresh will run after recovery.”**
- On a successful save, update the affected card before closing the modal, return focus to its `edit` button, and announce through the page-level polite feedback region: **“Service details saved. Preview refresh queued.”** If no preview work is required, announce **“Service details saved.”**
- On validation or safe-outbound-policy failure, keep the modal open, preserve entered values, focus the inline error region, and show the API-safe message followed by: **“Review the service details and try again.”** Do not expose internal addresses, certificate details, stack traces, or raw redirect URLs.

### TLS posture and safe outbound failures

- For every service monitored with the narrow trusted-LAN certificate exception, render a persistent outlined warning badge reading **“TLS unverified.”** Place it in the service title/action row after the port badge and before `edit`; at narrow widths it may wrap below the title row but must not cover the title or edit control.
- The badge remains visible whether the service is online or offline. It is a trust-posture label, never the availability label, does not turn the card red, and does not change uptime buckets.
- Give the badge an accessible name/title: **“TLS certificate is not verified for this trusted local service.”** It is informational, not a button.
- For a blocked URL, redirect, DNS target, webhook, or TLS-policy failure, use the existing inline error/banner pattern and concise safe reason: **“Beacon could not use that destination. Review the service details and try again.”** Do not provide an override/“proceed anyway” action in the browser.

### Migration backup and recovery

- Phase 1 uses one documented, offline Compose recovery command as the supported restore path; do not add an in-browser restore, backup deletion, or migration retry control. This avoids a destructive browser workflow while the web/worker processes may be unsafe to run.
- If the web surface can read recovery status, show a non-dismissable warning: **“Upgrade recovery is required. Monitoring is paused. Follow the documented recovery command before restarting Beacon.”** Keep previous readable dashboard data visible where compatible, but do not claim that monitoring is current.
- Automatic verified migration backups and their retention are operational data, not a dashboard list in this phase. Do not show a backup count, path, or restore selector until a later, deliberately designed recovery surface is approved.

---

## Copywriting Contract

| Element | Copy |
|---------|------|
| Primary CTA | `↻ scan now` |
| Stale worker warning | `Monitoring paused — worker unavailable. Dashboard data may be stale; service settings changes are still saved.` |
| Queue success | `Scan queued — runs when monitoring resumes.` / `Service details saved. Preview refresh queued.` |
| Queue expiry | `Scan request expired — it was not run. Scan again.` / `Preview refresh expired — save service details to request a new preview.` |
| Worker recovery | `Monitoring resumed. The outage was recorded in Events.` |
| Empty state heading | `No HTTP services discovered` |
| Empty state body | `Run a scan to look for configured services.` |
| Error state | `Beacon could not use that destination. Review the service details and try again.` |
| Migration recovery notice | `Upgrade recovery is required. Monitoring is paused. Follow the documented recovery command before restarting Beacon.` |
| Destructive confirmation | Not applicable — this phase provides no destructive browser action; restore remains the documented offline recovery command. |

---

## UI Considerations

Applicable state considerations resolved: 7 covered, 1 backstop, 0 unresolved. Element-kind classifications and consolidated resolutions confirmed by the operator on 2026-07-24.

| Category | Element(s) | Status | Resolution / Reason |
|----------|------------|--------|---------------------|
| empty | Services collection; preview media; event collection | ✅ covered | Services render `No HTTP services discovered` and an actionable scan next step; a missing preview retains the existing labelled fallback; no events renders `no recent incidents`. |
| loading | Scan status; service collection; preview refresh; metadata form | ✅ covered | Initial status says `connecting`/`waiting for worker`; requests use explicit queued/running copy; Save disables only while submitting and preserves the modal. |
| error | Connection banner; stale-worker warning; metadata form; per-service preview state | ✅ covered | Browser disconnect, worker stale, blocked destination, save failure, preview failure, and expiry have distinct text, colour, and recovery path. |
| populated | Service cards; event panel | ✅ covered | Cards retain availability, latency, uptime, metadata, and independent TLS/preview state; Events includes the monitoring-gap row. |
| partial | Stale dashboard data; worker recovery; service availability with TLS warning | ✅ covered | Last readable data remains visible with a stale warning; a TLS warning never overwrites `ONLINE`/`OFFLINE`; recovered monitoring creates a bounded gap event. |
| overflow | Warning/banner copy; service labels and badges; event details | ✅ covered | Banners wrap within the page inset; service titles/event detail use existing ellipsis; `TLS unverified` may wrap below the action row without obscuring controls. |
| zero-one-many | Services and events collections | 🧪 backstop | Visual UI-state tests verify zero, one, and several services/events preserve readable cards, labels, and grid spacing in dark and light modes. |
| long-text | Service names, tags, safe errors, and event details | ✅ covered | Service names/tags/event detail truncate with ellipsis; safe errors wrap in the modal and never expose raw internal target data. |

---

## Registry Safety

| Registry | Blocks Used | Safety Gate |
|----------|-------------|-------------|
| none | none | not applicable — no shadcn initialization and no third-party registry declared (2026-07-24) |

---

## Checker Sign-Off

- [x] Dimension 1 Copywriting: PASS with advisory — use `Edit service` if Phase 1 touches the existing `edit` control
- [x] Dimension 2 Visuals: PASS
- [x] Dimension 3 Color: PASS
- [x] Dimension 4 Typography: PASS
- [x] Dimension 5 Spacing: PASS
- [x] Dimension 6 Registry Safety: PASS

**Approval:** approved 2026-07-24
