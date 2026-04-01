# Beacon

A self-hosted monitoring dashboard for Raspberry Pi. Runs as a single Docker container — no cloud, no accounts, no dependencies beyond Docker.

![Dark mode](https://github.com/user-attachments/assets/dark-mode-placeholder)

## Features

- **System metrics** — live CPU, RAM, and disk gauges with 24-hour sparkline history and CPU temperature
- **Service discovery** — automatically finds every HTTP service running on the Pi by scanning ports 2000–9900
- **Uptime tracking** — 7-day visual uptime history per service, checks every 5 minutes (every 60 seconds for services that are currently down)
- **Live thumbnails** — headless Chromium screenshots of each service's homepage, refreshed daily
- **Dark / light theme** — with a smooth radial wipe transition
- **Zero configuration** — discovers services automatically; no manifest or config file to maintain

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
│  Flask (port 80)                             │
│    ├── serves index.html + style.css         │
│    └── REST API  /api/stats                  │
│                  /api/history                │
│                  /api/services               │
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

1. Checks every port from 2000–9900 in steps of 100 for an open TCP connection
2. Makes an HTTP request to each open port and reads the page `<title>`
3. Takes a headless Chromium screenshot of the homepage and caches it

Services that have been offline for longer than `EXPIRE_DAYS` are removed automatically.

### Uptime checks

- **Full check** (all services) — every 5 minutes
- **Down-only check** — every 60 seconds for services currently marked offline, so recovery is detected quickly
- Each check updates the 7-day uptime strip shown on the service card

### Thumbnails

Screenshots are taken with Playwright (headless Chromium) and stored as PNG blobs in SQLite. They are refreshed once per day. If a service has an `og:image` meta tag, that image is used instead of a screenshot.

## Configuration

Environment variables can be set in `docker-compose.yml`:

| Variable | Default | Description |
|---|---|---|
| `EXPIRE_DAYS` | `7` | Days before an offline service is removed from the dashboard |

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
