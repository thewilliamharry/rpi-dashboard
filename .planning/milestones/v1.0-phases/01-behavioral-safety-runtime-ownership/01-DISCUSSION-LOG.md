# Phase 1: Behavioral Safety & Runtime Ownership - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-24
**Phase:** 1-Behavioral Safety & Runtime Ownership
**Areas discussed:** Compatibility boundary, Upgrade and recovery experience, Local HTTPS policy, Worker failure behavior

---

## Compatibility Boundary

| Decision | Options considered | Selected |
|----------|--------------------|----------|
| Existing browser/API contracts | Preserve all contracts; preserve UI only; allow documented breaks; builder decides | Preserve all contracts |
| Confirmed bugs | Safety/correctness only; any confirmed bug; freeze quirks; builder decides | Any confirmed bug |
| Visible UI change | Minimal; small cohesion changes; open redesign; builder decides | Open redesign, constrained to phase-related work |
| Legacy database support | All repository variants; latest deployed; best effort; decide after inventory | Decide after inventory |

**Notes:** Compatibility adapters should protect current routes, response fields, and browser behavior. General visual redesign remains Phase 5 work. The user also proposed broader port discovery; it was deferred because it changes discovery capability.

---

## Upgrade and Recovery Experience

| Decision | Options considered | Selected |
|----------|--------------------|----------|
| Pre-migration protection | Automatic verified backup; prompted backup; manual backup; builder decides | Automatic verified backup |
| Backup retention | Latest three; latest one; 30 days; never delete | Latest three |
| Migration failure | Recovery screen; fail completely; automatic restore; builder decides | Builder decides |
| Restore interface | Supported command; manual commands; recovery UI; builder decides | Builder decides |

**Notes:** Any chosen failure path must prevent operation on a partial migration and provide a clear supported recovery mechanism.

---

## Local HTTPS Policy

| Decision | Options considered | Selected |
|----------|--------------------|----------|
| Untrusted LAN certificates | Per-service exception; strict everywhere; local CA; permissive LAN TLS | Permissive LAN TLS |
| Exception scope | Approved LAN only; every monitored service; all outbound HTTPS; builder decides | Builder decides narrowest scope |
| Redirects | Revalidate every redirect; same host only; follow freely; do not follow | Revalidate every redirect |
| Visibility | Persistent warning; event only; settings only; no warning | Persistent warning |

**Notes:** The user does not consider certificate verification important for trusted-LAN service monitoring. External destinations should not automatically inherit the LAN exception.

---

## Worker Failure Behavior

| Decision | Options considered | Selected |
|----------|--------------------|----------|
| Stale worker dashboard | Usable with disabled mutations; fully interactive; outage screen; builder decides | Fully interactive |
| Queued work recovery | Run recent/expire old; run all; discard all; builder decides | Run recent, expire old |
| Metadata edits | Save immediately; queue; disable; builder decides | Save immediately |
| Recovery record | Monitoring-gap event; clear only; acknowledgement; builder decides | Monitoring-gap event |

**Notes:** Cached state must be clearly labeled stale. Recovery automatically clears the warning while retaining the observation gap in history.

## the agent's Discretion

- Legacy schema compatibility floor after database inventory.
- Exact migration-failure UI and restore mechanism.
- Queue expiry durations by request type.
- Narrow scope of permissive LAN TLS.
- Internal architecture and module extraction mechanics.

## Deferred Ideas

- Expand discovery to every tenth port plus an explicit list of common service ports.
