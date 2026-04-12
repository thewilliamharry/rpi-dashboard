# Beacon

A self-hosted monitoring dashboard for Raspberry Pi. Runs as a single Docker container — no cloud, no accounts, no dependencies beyond Docker.

![Dark mode](https://github.com/user-attachments/assets/dark-mode-placeholder)

## Features

- **System metrics** — live CPU, RAM, and disk gauges with 24-hour sparkline history and CPU temperature
- **Service discovery** — automatically finds HTTP services running on the Pi by scanning ports 2000–9900 (plus common ports like 8080, 8443, 8888, 9090)
- **Uptime tracking** — 7-day bucketed uptime history per service, checks every 5 minutes (plus 60-second checks for currently-down services)
- **Latency + error telemetry** — stores latest response latency and probe error class per service
- **Transition events + webhook alerts** — records down/recovery events and can post alert payloads to a webhook with cooldowns
- **Service metadata** — editable display name, path/URL override, critical flag, pin order, and tags per service
- **Manual scan trigger** — `/api/trigger-scan` is rate limited
- **Live thumbnails** — headless Chromium screenshots of each service homepage, refreshed daily; falls back to localhost `og:image` when available
- **Status favicon** — browser tab icon is a live color-coded bulb (green / amber / red) reflecting service state and CPU load
- **Dark / light theme** — two distinct visual styles with a smooth radial-wipe transition

## Requirements

- Docker and Docker Compose
- Raspberry Pi 4 or 5 running a **64-bit OS** (Raspberry Pi OS Lite 64-bit or Ubuntu Server)

> Playwright's Chromium binary requires ARM64. 32-bit Pi OS is not supported.

## Quick start

```bash
git clone https://github.com/your-username/rpi-dashboard.git
cd rpi-dashboard
docker compose up -d
```

Open `http://<your-pi-ip>` in a browser. The first port scan runs automatically within a few seconds of startup and takes 1–2 minutes to complete.

## How it works

```
┌─────────────────────────────────────────────┐
│               Docker container               │
│                                              │
│  Gunicorn + Flask (port 80)                  │
│    ├── serves index.html + style.css         │
│    └── REST API  /api/stats                  │
│                  /api/history                │
│                  /api/services               │
│                  /api/events                 │
│                  /api/config                 │
│                  /api/service-meta/<port>    │
│                  /api/thumbnail/<port>       │
│                  /api/scan-status            │
│                  /api/trigger-scan           │
│                                              │
│  Background threads                          │
│    ├── stats_loop   — metrics every 60s      │
│    └── scan_loop    — discovery every 24h    │
│                       uptime check every 5m  │
│                       down check every 60s   │
│                                              │
│  SQLite  /data/dashboard.db  (persisted)     │
└─────────────────────────────────────────────┘
```

### Service discovery

On startup (and every 24 hours), the scanner:

1. Checks every port from 2000–9900 in steps of 100, plus a curated list of common self-hosted service ports (3001, 8080, 8443, 8888, 9090), for an open TCP connection
2. Makes an HTTP request to each open port and reads the page `<title>`
3. Takes a headless Chromium screenshot of the homepage and caches it

Services that have been offline for longer than `EXPIRE_DAYS` are removed automatically.

### Uptime checks

- **Full check** (all services) — every 5 minutes
- **Down-only check** — every 60 seconds for services currently marked offline, so recovery is detected quickly
- Each check updates the 7-day uptime strip shown on the service card

### Thumbnails

Screenshots are taken with Playwright (headless Chromium) and stored as PNG blobs in SQLite. They are refreshed once per day. If a service has a localhost-hosted `og:image` meta tag, that image is used instead of a screenshot.

### Status favicon

The browser tab icon is a canvas-drawn colour bulb that updates in real time:

- 🟢 **Green** — all services online, CPU normal
- 🟡 **Amber** — one or more services offline, or CPU above 80 %
- 🔴 **Red** — all services offline, or CPU above 90 %

The page title also updates to show the offline count when things go wrong (e.g., `Beacon — 2 offline`). An Apple touch icon (180×180) is generated alongside the standard favicon for home-screen shortcuts on iOS/macOS.

## Configuration

Environment variables can be set in `docker-compose.yml`:

| Variable | Default | Description |
|---|---|---|
| `EXPIRE_DAYS` | `7` | Days before an offline service is removed from the dashboard |
| `TRIGGER_SCAN_RATE_LIMIT` | `4` | Max manual scan trigger requests per rate-limit window per client IP |
| `TRIGGER_SCAN_WINDOW_SECONDS` | `60` | Rate-limit window for manual scan trigger requests |
| `ALERT_WEBHOOK_URL` | empty | Optional webhook target for up/down transition alerts |
| `ALERT_COOLDOWN_SECONDS` | `300` | Minimum seconds between repeated alert sends for the same port/state |
| `ALERT_ONLY_CRITICAL` | `0` | If `1`, only send webhook alerts for services marked `critical` |

## Project structure

```
rpi-dashboard/
├── docker-compose.yml
└── dashboard/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py          # Flask backend + background threads
    ├── index.html      # Single-page frontend (vanilla JS)
    └── style.css       # Dark + light theme styles
```

## Data persistence

Service history and thumbnails are stored in a named Docker volume (`dashboard-data`) mounted at `/data/dashboard.db` inside the container. The volume survives container restarts and image rebuilds.

To reset all data:

```bash
docker compose down -v
docker compose up -d
```

## Rebuilding after an update

```bash
docker compose build && docker compose up -d
```
