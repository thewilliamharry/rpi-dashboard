---
phase: 06-workload-resilience-pi-acceptance
kind: runbook
created: 2026-09-06
---

# Acceptance-harness runbook — reaching the live database from the Pi host

`.planning/STATE.md` § Blockers/Concerns has recorded, since round 4, that the exact command path for
running `tests/pi_load_acceptance.py` against a live deployment on the Pi was never written down —
"cost two cycles to rediscover." This is that record, written once so a third cycle is never spent on
it. Every command below was exercised against a real deployment as part of `06-27`'s segment B
(`06-ACCEPTANCE-C3-RUN3.md`).

## The shape of the problem, stated first

The harness must run **outside** any container, **under `sudo`**, with **its own dependencies synced
as a normal user**, against a database path that lives **inside a Docker named volume's `_data`
directory on the host filesystem** — four constraints that do not look like they belong together
until you have hit the failure mode each one prevents.

## Step-by-step

**1. Sync dependencies as the `pi` user — never under `sudo`.**

```bash
cd ~/projects/rpi-dashboard
uv sync --project dashboard
```

Run this as `pi`. Running it under `sudo` creates or updates the virtualenv with a different
effective `HOME`/cache path than the one the harness invocation below actually uses, which is the
specific mistake that has cost two cycles to rediscover.

**2. Bring up the deployment, uninstrumented, and confirm it.**

```bash
docker compose up -d --build
docker compose ps
```

No `BEACON_LOCK_PROFILE=1` prefix for an acceptance run. Confirm both `beacon-web` and `beacon-worker`
are up.

**3. Confirm the deployment is uninstrumented before spending any run time on it.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1/api/diagnostics/lock-profile
```

Must print `404`. Anything else means `BEACON_LOCK_PROFILE` reached the container; the resulting run
would be inadmissible as OPS-07 acceptance evidence (`PROH-OPS-07-11`). Bring the stack down and back
up without the prefix, and re-check.

**4. Record the stored-data shape before the run**, using Python's stdlib `sqlite3` module under
`sudo` — **not** the `sqlite3` CLI binary, which is not installed on the Pi:

```bash
sudo dashboard/.venv/bin/python -c "
import sqlite3
conn = sqlite3.connect('/var/lib/docker/volumes/rpi-dashboard_dashboard-data/_data/dashboard.db')
cur = conn.cursor()
cur.execute('SELECT COUNT(*) FROM service_checks')
print('service_checks:', cur.fetchone()[0])
cur.execute('SELECT COUNT(*) FROM services')
print('services:', cur.fetchone()[0])
"
```

**The `sqlite3` command-line binary is not installed on this Pi.** A command of the shape
`sqlite3 /var/lib/docker/volumes/.../dashboard.db 'SELECT COUNT(*) ...'` will fail with a "command not
found" error, not a permissions error — do not spend time troubleshooting file permissions on that
failure; the binary simply is not there. Python's `sqlite3` module is part of the standard library and
is always available inside the harness's own venv, which is why the row-count query above goes through
`dashboard/.venv/bin/python` rather than a separate CLI tool.

**5. Let the deployment settle.** Wait at least five minutes after `docker compose up` before starting
the run, so a cold cache or a startup discovery pass is not measured as steady-state behaviour.

**6. Run the harness.**

```bash
uv sync --project dashboard
sudo dashboard/.venv/bin/python tests/pi_load_acceptance.py \
    --base-url http://127.0.0.1 \
    --db /var/lib/docker/volumes/rpi-dashboard_dashboard-data/_data/dashboard.db \
    --concurrency 3 --duration 600 \
    --output ~/beacon-acceptance.json
```

Roughly eleven minutes for a 600s run plus startup/shutdown overhead. `--concurrency 3` must be
**passed explicitly** — the harness's own default is 8, which produces a non-gating run under the
amended criterion (`D-DEBT-06-20`) without any error or warning that the wrong scenario ran.

**7. Record the stored-data shape after the run**, with the same query as step 4.

**8. Read the result.**

```bash
sudo dashboard/.venv/bin/python -c "
import json
r = json.load(open('/home/pi/beacon-acceptance.json'))
print(r['overall_passed'], r['run_kind'], r.get('lock_profile'))
"
```

Then read `assertions.cadence`, `assertions.resources`, `assertions.response_times`, and any
`failure_reasons`.

**9. Leave the deployment on HEAD, uninstrumented, and running.**

## The instrumented variant, for a diagnostic (never acceptance) run

To collect lock-profile diagnostic evidence instead of acceptance evidence, prefix step 2's
`docker compose up` with the environment variable:

```bash
BEACON_LOCK_PROFILE=1 docker compose up -d --build
```

Then confirm the diagnostic endpoint returns a live snapshot (not `404`) before running the harness
with `--lock-profile` added to the invocation in step 6. **A run started this way is diagnostic
evidence only and must never be recorded as OPS-07 acceptance evidence** (`PROH-OPS-07-11`) — bring
the stack back down and up without the prefix, and re-confirm the `404`, before running anything meant
to gate the criterion.

## Three invocations that do NOT work, and why

Knowing the failure modes is what actually saves the next reader — each of these has been tried and
has failed, in earlier rounds of this phase, for a non-obvious reason.

**1. Running the harness inside a container.** The harness's resource oracle
(`tests/pi_load_acceptance.py`'s resolution of `beacon-web`/`beacon-worker` CPU and memory) resolves
**host-namespace PIDs** through `docker inspect`, run as a host-level subprocess. Invoked from inside
a container, `docker inspect` either is not available or resolves the wrong PID namespace entirely,
and the resource assertions silently read garbage or fail to resolve a role at all
(`resolution_reason` in the report names the failure rather than crashing, but the run is not
admissible evidence at that point).

**2. Running the harness under `sudo uv run` instead of `sudo dashboard/.venv/bin/python`.** `sudo uv`
does not resolve the same Python environment `uv sync` (run as `pi`, step 1) actually populated —
`sudo`'s environment does not inherit the calling user's `uv`-managed virtualenv activation, and the
invocation either fails to find the harness's dependencies or silently falls back to a different
interpreter. Invoke the venv's own interpreter directly under `sudo` instead:
`sudo dashboard/.venv/bin/python tests/pi_load_acceptance.py ...`.

**3. Omitting `--concurrency 3`.** The harness's own default is 8 (`build_arg_parser`). A run without
the flag completes normally, produces a fully-formed report, and prints no warning — but it is the
**optional**, non-gating concurrency-8 shape under the amended criterion (`D-DEBT-06-20`), not the
gating concurrency-3 run. The report will look complete and admissible by every other property
(`run_kind acceptance`, `lock_profile {}`, `self_test false`) while silently measuring the wrong
scenario. Always pass `--concurrency 3` explicitly for a gating run.

## Pre-run checks, consolidated

Before starting the timed run itself:

1. `docker compose ps` — both `beacon-web` and `beacon-worker` up.
2. `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1/api/diagnostics/lock-profile` — must
   read `404` for an acceptance run.
3. The row-count query (step 4 above), via Python's stdlib `sqlite3`, under `sudo`, against the venv
   interpreter — never the `sqlite3` CLI, which is not installed on this Pi.
4. A minimum five-minute settle wait after `docker compose up` before the harness starts.
