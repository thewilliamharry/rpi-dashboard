---
title: Optional cron and systemd maintenance evidence
trigger_condition: "When Beacon gains an explicitly configured, read-only host integration that can safely enumerate schedules and map them to monitored services"
planted_date: 2026-08-14
status: seed
---

# Optional cron and systemd maintenance evidence

Explore read-only inspection of host cron jobs and systemd timers as supporting evidence for proposed service maintenance windows.

This must remain optional. Beacon runs in Docker and monitors services primarily by port or URL, so it cannot assume access to host schedules or reliably infer which job controls a service. Historical restart-pattern detection and operator confirmation remain the canonical Phase 03.1 path.

If activated, the integration must use an explicit allowlisted host boundary, expose provenance and uncertainty, never execute or modify schedules, and never enable event suppression without operator confirmation.
