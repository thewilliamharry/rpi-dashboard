# Beacon

Beacon is a self-contained Raspberry Pi dashboard for system pressure, HTTP-service discovery, time-weighted availability, screenshots, and service events on a trusted LAN. It does not require an account or an external monitoring backend.

## Architecture

Compose runs one immutable image as two non-root services sharing `/data/dashboard.db`:

- `data-init` is a one-shot, network-isolated ownership migration. It receives only `CAP_CHOWN` and `CAP_DAC_READ_SEARCH`, so it can traverse legacy worker-owned 0700 backup directories while repairing `/data` ownership for UID 10001, then exits before the worker starts.
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
| `TRUSTED_HOSTS` | Pi aliases and private LAN CIDRs | Accepted HTTP Host/Origin aliases or IP ranges for the UI. Defaults include RFC 1918 IPv4 and IPv6 ULA networks so LAN clients can use the Pi's IP. |
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

The named volume stores metrics, services, checks, events, runtime state, queued work, rate limits, and screenshots. Beacon creates verified automatic pre-migration backups during supported schema upgrades.

### Failed-upgrade recovery

If an upgrade reports that recovery is required, use this single supported offline procedure. Do not run recovery while web or worker could write `/data/dashboard.db`.

1. Stop the writers:

   ```bash
   docker compose stop web worker
   ```

2. Inspect the safe recovery status:

   ```bash
   docker compose run --rm --no-deps recovery python -m beacon.recovery status
   ```

3. Restore the newest verified automatic backup:

   ```bash
   docker compose run --rm --no-deps recovery python -m beacon.recovery restore --latest
   ```

4. Confirm the command reports `"completed": true`, then start only the compatible web service to inspect the restored data. Restart worker only after deploying a migration-fixed or prior compatible image.

The restore command refuses a fresh worker and never accepts a backup path. There is no browser restore action, backup deletion command, or migration-retry control. In addition to stopping the Compose writers, recovery takes the upgrade lock followed by the exclusive database-maintenance barrier, so a managed web or worker SQLite connection cannot overlap the replacement. While that barrier is held, it proves the target WAL checkpoint is not busy, fsyncs durability boundaries, and removes only the exact dashboard.db-wal and dashboard.db-shm sidecars before installing the verified catalog backup.

#### External operator verification: deployed and retained Pi databases

This is a human-only, fail-closed compatibility check. Before an upgrade, run `beacon.inventory` read-only against every database currently deployed or retained on the Pi, compare each sanitized fingerprint with `tests/fixtures/legacy/operator/` and the packaged support floor, and stop the upgrade for an unknown fingerprint. The repository automation cannot establish the set of databases held outside the repository, and it must not copy an external database into this repository.

For each local operator-owned database, save only the sanitized inventory report outside the checkout for comparison:

```bash
PYTHONPATH=dashboard dashboard/.venv/bin/python -m beacon.inventory \
  --db /absolute/path/to/deployed/dashboard.db \
  --output /tmp/beacon-inventory.json
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

For rollback, restore the previous Compose/image definition. Schema changes are additive, so the prior application can keep using the upgraded database.

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
