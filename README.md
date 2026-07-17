# Beacon

Beacon is a self-contained Raspberry Pi dashboard for system pressure, HTTP-service discovery, time-weighted availability, screenshots, and service events on a trusted LAN. It does not require an account or an external monitoring backend.

## Architecture

Compose runs one immutable image as two non-root services sharing `/data/dashboard.db`:

- `data-init` is a one-shot, network-isolated ownership migration. It receives only `CAP_CHOWN`, repairs legacy `/data` ownership for UID 10001, and exits before the worker starts.
- `web` uses bridge networking and exposes container port 8080 on host port 80. It serves cached data and queues mutations.
- `worker` uses host networking so it can probe the Pi. APScheduler collects metrics, checks uptime, discovers services, captures previews, cleans history, and sends alerts.

Metrics, probes, and screenshots use separate executors. A slow Chromium preview cannot block the five-second system sampler. SQLite migrations are additive and versioned.

## Quick start

Requirements: Docker Compose and a Raspberry Pi 4/5 running a 64-bit OS.

```bash
git clone git@github.com:thewilliamharry/rpi-dashboard.git
cd rpi-dashboard
docker compose up -d --build --force-recreate --remove-orphans --wait --wait-timeout 180
```

Open `http://raspi.local`. BlueMap is discovered as an ordinary HTTP service because port 8100 is included through `EXTRA_SCAN_PORTS`.

Check health:

```bash
curl http://raspi.local/healthz
curl http://raspi.local/readyz
docker compose ps
```

## Configuration

Edit `docker-compose.yml` or supply equivalent environment values.

| Variable | Default | Purpose |
| --- | --- | --- |
| `EXTRA_SCAN_PORTS` | `8100` | Additional comma-separated HTTP ports. |
| `TRUSTED_HOSTS` | local aliases | Accepted HTTP Host/Origin aliases for the UI. Add the Pi's IP if accessing Beacon by IP. |
| `LOCAL_SERVICE_HOSTS` | `raspi.local` | Aliases service URLs may target; they are stored canonically as loopback. |
| `METRIC_SAMPLE_SECONDS` | `5` | Cached metric collection cadence. |
| `METRIC_HISTORY_SECONDS` | `60` | Persistent history cadence. |
| `DISCOVERY_TIMEOUT_SECONDS` | `180` | Full discovery deadline. |
| `WORKER_READY_SECONDS` | `20` | Maximum heartbeat age for readiness. |
| `ENABLE_PROMETHEUS` | `0` | Enables the optional `/metrics` endpoint. |
| `THUMB_REFRESH_DAYS` | `1` | Successful screenshot refresh interval. |
| `EXPIRE_DAYS` | `7` | Remove long-unseen services. |
| `ALERT_WEBHOOK_URL` | empty | Optional transition webhook. |
| `ALERT_COOLDOWN_SECONDS` | `300` | Persistent per-state alert cooldown. |
| `ALERT_ONLY_CRITICAL` | `0` | Limit alerts to critical services. |

Service health defaults to HTTP 200–399. The editor accepts exceptional codes/ranges such as `200-399,401` for authenticated endpoints. Targets, redirects, and userinfo URLs outside loopback or configured Pi aliases are rejected.

## Data and operations

The named volume stores metrics, services, checks, events, runtime state, queued work, rate limits, and screenshots. Back it up before a release:

```bash
docker compose stop
docker run --rm -v rpi-dashboard_dashboard-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/beacon-data.tgz -C /data .
docker compose start
```

Record the running image, deploy, then observe two uptime cycles and one discovery. `--force-recreate` reruns the one-shot ownership migration, `--remove-orphans` removes containers from older Compose definitions, and `--wait` avoids smoke requests while Gunicorn is still starting:

```bash
docker compose images
docker compose build --pull
docker compose up -d --build --force-recreate --remove-orphans --wait --wait-timeout 180
docker compose ps --all
curl -f http://raspi.local/healthz
curl -f http://raspi.local/readyz
docker compose logs -f worker web
```

`data-init` should show `Exited (0)`, while `worker` and `web` should show `healthy`. If Docker reports that the kernel does not support memory-limit capabilities or that the memory cgroup is not mounted, Beacon can still run but the configured container memory limits are not enforced. Keep the limits in Compose and enable the host memory controller before relying on them as a hard boundary.

For rollback, restore the previous Compose/image definition. Schema changes are additive, so the prior application can keep using the upgraded database. Restore the backup only if validation finds corrupted data.

Thumbnail diagnostics:

```bash
curl http://raspi.local/api/thumbnail-status
docker compose logs worker | grep -i preview
docker compose exec worker playwright --version
```

## Development and security gates

Dependencies are declared in `dashboard/pyproject.toml` and frozen in `dashboard/uv.lock`.

```bash
uv sync --project dashboard --frozen
uv run --project dashboard python -m pytest -q
uv run --project dashboard pip-audit
docker compose config -q
docker compose build
```

CI runs tests, `pip-audit`, and a Trivy image scan. Dependabot covers Python, Docker, and GitHub Actions. A release requires no unreviewed fixable high/critical vulnerabilities. Raspberry Pi acceptance must also confirm the Chromium sandbox starts without `--no-sandbox`, containers run as UID 10001, filesystems remain read-only except `/data` and tmpfs `/tmp`, and metrics show no gap longer than two collection intervals during discovery.
