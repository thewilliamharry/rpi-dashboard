#!/usr/bin/env python3
"""Standalone, checked-in Raspberry Pi-class load acceptance harness (OPS-07).

Not a pytest module -- the ``pi_load_acceptance.py`` name deliberately does
not match pytest's ``test_*.py`` collection pattern, so it is never collected
by the suite; ``06-VALIDATION.md`` invokes it directly. Run it against a live
Beacon deployment::

    python tests/pi_load_acceptance.py --duration 600 \\
        --base-url http://127.0.0.1 --db /data/dashboard.db \\
        --output beacon-acceptance.json

Or run its short, bounded smoke pass against a locally-started app -- no Pi
and no live deployment required::

    python tests/pi_load_acceptance.py --self-test

Every oracle this harness asserts against is evidence the product already
produces and already trusts, never a parallel rule invented for this file
(PROH-OPS-07-01, 06-RESEARCH.md "Don't Hand-Roll"):

- Cadence: ``dashboard.beacon.diagnosis.freshness_state`` fed each essential
  job's own cadence (via ``callback_schedule_evidence`` over
  ``WORKER_CALLBACK_INVENTORY``, the same function
  ``dashboard/beacon/diagnosis.py`` itself uses), and
  ``dashboard.beacon.repositories.read_background_job_health`` for durable
  job outcomes.
- Resources: the ``mem_limit`` values declared in ``docker-compose.yml``,
  parsed from that file rather than duplicated as constants. The processes
  sampled against those limits are resolved from the Beacon containers
  themselves -- the ``worker``/``web`` ``container_name`` values pinned in
  ``docker-compose.yml`` (``beacon-worker``, ``beacon-web``), overridable
  via ``--worker-container``/``--web-container`` for an operator running a
  modified compose file -- never by host-wide process matching, which on
  real hardware sampled an unrelated co-tenant application sharing a
  command-line substring with Beacon's own (PROH-OPS-07-02, T-06-33).
- Response times: the dashboard's own routes, sampled under real concurrent
  HTTP load, judged against budgets declared (and reasoned about) below --
  never derived from a run this harness already made.

``run_kind`` is derived from the invocation, not from any flag the runner
controls independently: a ``--self-test`` run is always ``smoke``; a real
run without ``--self-test`` is ``acceptance`` -- so a convenience run can
never be mistaken for hardware evidence (PROH-OPS-07-02, T-06-26). Every
run reports failure honestly: an unreachable target, a database that could
not be opened, or an oracle that could not be sampled all produce a
non-zero exit with the reason named in the report -- never a pass with
missing evidence.
"""

import argparse
import json
import math
import os
import platform
import re
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import psutil
import requests

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dashboard.beacon import lockprofile as beacon_lockprofile  # noqa: E402
from dashboard.beacon import repositories as beacon_repositories  # noqa: E402
from dashboard.beacon.config import load_settings  # noqa: E402
from dashboard.beacon.db import database_access  # noqa: E402
from dashboard.beacon.diagnosis import callback_schedule_evidence, freshness_state  # noqa: E402
from dashboard.beacon.worker_main import WORKER_CALLBACK_INVENTORY  # noqa: E402


DEFAULT_COMPOSE_PATH = _REPO_ROOT / 'docker-compose.yml'

# OPS-01/OPS-07: the four callbacks every freshness surface in the product
# depends on -- J1 (heartbeat), J2 (metric sampling), J3 (full uptime
# sweep), J4 (down-only uptime sweep). This is the same essential set
# 06-04's CadenceUnderContentionTests proves holds cadence under contention;
# this harness re-asserts it under real, sustained concurrent load.
ESSENTIAL_JOB_IDS = ('J1', 'J2', 'J3', 'J4')

_CALLBACKS_BY_ID = {callback.identifier: callback for callback in WORKER_CALLBACK_INVENTORY}

# Response-time budgets in milliseconds, one per exercised route family.
# Declared here with written reasoning, never derived from a run this
# harness has already made (PROH-OPS-07-01):
#   - /api/services and /api/scan-status are polled by the dashboard on an
#     interactive cadence (app.js's own poll loop), so a slow response here
#     is a slow-feeling UI -- tightest budget.
#   - /api/thumbnail-status is also polled but composes more rows per
#     request, so it gets a slightly looser budget.
#   - /api/thumbnail/<port> serves up to THUMB_MAX_BYTES (2 MiB) of BLOB
#     data over a LAN connection, so it gets a looser budget still.
#   - /api/history and /api/advanced/current are operator-initiated (a
#     person opened a chart or the advanced workspace), not continuously
#     polled, so they get the loosest budget.
ROUTE_BUDGETS_MS = {
    '/api/services': 500,
    '/api/scan-status': 500,
    '/api/thumbnail-status': 750,
    '/api/thumbnail/<port>': 1_500,
    '/api/history': 2_000,
    '/api/advanced/current': 2_000,
}

SAMPLE_INTERVAL_SECONDS = 1.0
SELF_TEST_DURATION_SECONDS = 5
SELF_TEST_CONCURRENCY = 4

# 06-17: the round-4 diagnostic collection this harness adds on top of the
# round-1 acceptance oracles above. `/api/diagnostics/lock-profile` is
# appended to the run's own `--base-url` so there is no second URL to keep
# in sync with a live deployment.
LOCK_PROFILE_PATH = '/api/diagnostics/lock-profile'

# The snapshot shape this harness understands. A live snapshot reporting a
# different `schema_version` is an honest `collected: False` reason, never a
# crash -- see `_collect_lock_profile`. Matches
# `dashboard/beacon/lockprofile.SNAPSHOT_SCHEMA_VERSION` at the time this was
# written; deliberately a literal, not an import binding, so a future bump
# to that module does not silently widen what this harness claims to
# understand without a person choosing to update this constant too.
LOCK_PROFILE_SCHEMA_VERSION = 2

# Generous next to 06-16-SUMMARY.md's measured serialized snapshot size
# (6315 bytes for a 3-service, 8-thread, 3s rehearsal) -- a fetch this small
# has no reason to approach this ceiling; it exists so a hung diagnostic
# endpoint degrades to `collected: False` (T-06-90) rather than stalling a
# 600s hardware run.
LOCK_PROFILE_FETCH_TIMEOUT_SECONDS = 10

# Bounded so an unresponsive docker daemon produces a named, unresolved-role
# failure rather than a hung run (T-06-34); 10s is generous next to a local
# `docker inspect` call, which normally completes in well under a second.
DOCKER_INSPECT_TIMEOUT_SECONDS = 10

# Docker's own container-name grammar. Validating against it before any
# subprocess call removes argument-injection as a concern outright rather
# than merely sanitizing it (T-06-31).
_CONTAINER_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')

_MEM_UNIT_MULTIPLIERS = {'': 1, 'b': 1, 'k': 1024, 'm': 1024 ** 2, 'g': 1024 ** 3}


@dataclass
class LoadScenario:
    """One acceptance (or smoke) run's fixed parameters."""

    duration_seconds: int
    base_url: str
    db_path: str
    concurrency: int
    self_test: bool
    compose_path: str = str(DEFAULT_COMPOSE_PATH)
    worker_container: str = 'beacon-worker'
    web_container: str = 'beacon-web'
    # 06-17: requests the lock-profile snapshot pair around the load window.
    # Off by default -- production behaviour (and every prior round's
    # scenario shape) is untouched when this stays False.
    collect_lock_profile: bool = False
    # 06-17 T-06-86: an optional callable(failure_reasons_copy, overall_passed_copy)
    # `run_acceptance` invokes immediately before and immediately after the
    # lock-profile collection block, so a test can prove the block never
    # moves either value without restructuring `run_acceptance` itself.
    # `None` in every real invocation -- this field exists for
    # `LockProfileCollectionTests`' deterministic arm only.
    observer: object = None


@dataclass
class AcceptanceReport:
    """The harness's full, JSON-serializable verdict.

    Every field is present on every run regardless of outcome -- an early,
    unreachable-target failure still reports run_kind/host/scenario, just
    with empty evidence sections and the reason in ``failure_reasons``. This
    keeps the report's shape stable across runs (OPS-07 backstop:
    re-running the same scenario against the same build produces a report
    with the same shape and the same assertion set).
    """

    run_kind: str
    host_machine: str
    host_node: str
    scenario: dict
    started_at_epoch: int
    finished_at_epoch: int
    route_latencies_ms: dict = field(default_factory=dict)
    resource_samples: dict = field(default_factory=dict)
    background_job_health: list = field(default_factory=list)
    freshness_by_job: dict = field(default_factory=dict)
    assertions: dict = field(default_factory=dict)
    failure_reasons: list = field(default_factory=list)
    overall_passed: bool = False
    # 06-17: diagnostic-only. `{}` when collection was not requested, and
    # `{'collected': False, 'reason': ...}` when it was requested but
    # failed. Never read by any assertion above and never contributes to
    # `overall_passed` or `failure_reasons` (PROH-OPS-07-12).
    lock_profile: dict = field(default_factory=dict)

    def to_json(self):
        return json.dumps(asdict(self), indent=2, sort_keys=True, default=str)


@dataclass
class ResourceTarget:
    """One role's resolved (or unresolved) resource-sampling target.

    ``processes`` is the role's process set at resolution time -- non-empty
    on success. ``root_pid`` is held separately (rather than only the
    initial ``processes`` list) because a container-resolved role's child
    set is re-derived from this PID on every sampling tick, not fixed at
    run start (PROH-OPS-07-06): gunicorn recycles workers on timeout,
    ``max_requests``, or crash, and a 600s run is long enough for that to
    happen. ``reason`` is ``None`` only when resolution succeeded; a role
    with a reason is never sampled and always fails the run for an
    acceptance-shaped resolution.

    ``handles`` is a run-lifetime cache of ``psutil.Process`` objects keyed
    by PID, so ``cpu_percent(interval=None)`` -- which diffs against state
    stored on the specific object it was last called on -- has a real
    prior-tick baseline instead of the structural ``0.0`` produced by
    re-instantiating ``psutil.Process`` on every tick (D-DEBT-06-06). This
    is explicitly a cache of *objects*, never a cache of the process *set*:
    the set is still re-derived from the container on every tick
    (PROH-OPS-07-06) -- that distinction is precisely what the previous
    shape got wrong in the other direction.
    """

    role: str
    container: object  # str for a container-resolved role, None for self_test
    method: str  # 'docker_container_tree' or 'self_test'
    root_pid: object = None  # int once resolved, else None
    processes: list = field(default_factory=list)
    reason: object = None  # str once unresolved, else None
    handles: dict = field(default_factory=dict)  # PID -> held psutil.Process, run-lifetime


def _parse_mem_limit_value(raw):
    cleaned = raw.strip().strip('"\'')
    match = re.fullmatch(r'(\d+(?:\.\d+)?)\s*([bBkKmMgG]?)', cleaned)
    if not match:
        raise ValueError(f'unparseable mem_limit value: {raw!r}')
    number, unit = match.groups()
    return int(float(number) * _MEM_UNIT_MULTIPLIERS[unit.lower()])


def parse_compose_memory_limits(compose_path):
    """Parse the declared ``mem_limit`` values straight out of docker-compose.yml.

    No YAML dependency is introduced -- 06-RESEARCH.md keeps this phase
    dependency-free -- so this is a small, line-oriented scan over the
    ``services:`` block's two-space service-name / four-space-property
    structure, stable in this repository since Phase 1. Returns a dict of
    service name -> byte count (e.g. ``{'worker': 1073741824, 'web':
    268435456}``), reading the budget the resource oracle asserts against
    from the same file the deployment itself is configured by, rather than
    duplicating it as a constant here.
    """
    text = Path(compose_path).read_text()
    limits = {}
    current_service = None
    in_services = False
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped == 'services:':
            in_services = True
            current_service = None
            continue
        if not in_services:
            continue
        if stripped and not line.startswith(' '):
            # A new top-level key (e.g. ``volumes:``) ends the services block.
            break
        service_match = re.match(r'^ {2}([A-Za-z][\w-]*):\s*$', line)
        if service_match:
            current_service = service_match.group(1)
            continue
        if current_service is None:
            continue
        limit_match = re.match(r'^\s{4,}mem_limit:\s*(\S+)\s*$', line)
        if limit_match:
            limits[current_service] = _parse_mem_limit_value(limit_match.group(1))
    return limits


def assert_cadence(job_health_by_id, settings, *, now, required_job_ids=ESSENTIAL_JOB_IDS):
    """Classify each required essential job with the product's own oracle.

    Delegates every boundary to ``freshness_state`` fed each job's own
    cadence from ``WORKER_CALLBACK_INVENTORY`` (and
    ``Settings.metric_sample_seconds`` for J2, via
    ``callback_schedule_evidence`` -- the same function
    ``dashboard/beacon/diagnosis.py`` itself uses). This file never restates
    the fresh/aging/stale boundary (PROH-OPS-07-01). Fails when any required
    job classifies ``stale``, has no recorded evidence at all, or carries a
    ``background_job_health.state`` of ``failed``.
    """
    failures = []
    freshness_by_job = {}
    for job_id in required_job_ids:
        callback = _CALLBACKS_BY_ID.get(job_id)
        if callback is None:
            failures.append(f'{job_id}: not found in WORKER_CALLBACK_INVENTORY')
            continue
        health = job_health_by_id.get(job_id)
        if health is None:
            failures.append(f'{job_id}: no background_job_health evidence recorded')
            continue
        if health.get('state') == 'failed':
            failures.append(f"{job_id}: background_job_health.state is 'failed'")
        cadence_seconds = callback_schedule_evidence(callback, settings)['cadence_seconds']
        last_success_ts = health.get('last_success_ts')
        if cadence_seconds is None or last_success_ts is None:
            failures.append(f'{job_id}: missing cadence_seconds or last_success_ts evidence')
            continue
        classification = freshness_state(now, last_success_ts, cadence_seconds)
        freshness_by_job[job_id] = classification
        if classification['state'] == 'stale':
            failures.append(
                f"{job_id}: freshness_state classified 'stale' "
                f"(age={classification['age_seconds']}s, cadence={cadence_seconds}s)"
            )
    return {
        'passed': not failures,
        'failures': failures,
        'freshness_by_job': freshness_by_job,
    }


def assert_resource_budget(rss_bytes, limit_bytes, *, role):
    """Fail when a sampled resident-memory reading exceeds its declared mem_limit.

    Also fails honestly (never silently passes) when either the sample or
    the declared limit is missing -- a resource oracle that could not be
    sampled must never read as a pass with missing evidence.
    """
    if rss_bytes is None or limit_bytes is None:
        return {
            'role': role, 'passed': False, 'rss_bytes': rss_bytes, 'limit_bytes': limit_bytes,
            'reason': f'{role}: no RSS sample or no declared mem_limit to compare against',
        }
    passed = rss_bytes <= limit_bytes
    result = {'role': role, 'passed': passed, 'rss_bytes': rss_bytes, 'limit_bytes': limit_bytes}
    if not passed:
        result['reason'] = (
            f'{role}: peak RSS {rss_bytes} bytes exceeds declared mem_limit {limit_bytes} bytes'
        )
    return result


def _percentile(sorted_samples, pct):
    if not sorted_samples:
        return None
    if len(sorted_samples) == 1:
        return sorted_samples[0]
    rank = (len(sorted_samples) - 1) * (pct / 100)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return sorted_samples[int(rank)]
    lower_value = sorted_samples[int(lower)] * (upper - rank)
    upper_value = sorted_samples[int(upper)] * (rank - lower)
    return lower_value + upper_value


def assert_response_times(latencies_by_route, budgets_ms=ROUTE_BUDGETS_MS):
    """Fail when any exercised route's p95 latency exceeds its declared budget.

    Only asserts on routes actually exercised this run (a run against zero
    discovered services never fabricates a thumbnail-route sample), but a
    route that WAS exercised with zero recorded samples, or one with no
    declared budget at all, is an honest failure -- never a silent pass.
    """
    failures = []
    percentiles_by_route = {}
    for route, samples_ms in latencies_by_route.items():
        if not samples_ms:
            failures.append(f'{route}: no latency samples recorded')
            continue
        sorted_samples = sorted(samples_ms)
        p95 = _percentile(sorted_samples, 95)
        percentiles_by_route[route] = {
            'p50_ms': _percentile(sorted_samples, 50),
            'p95_ms': p95,
            'max_ms': sorted_samples[-1],
            'count': len(sorted_samples),
        }
        budget = budgets_ms.get(route)
        if budget is None:
            failures.append(f'{route}: no declared response-time budget')
            continue
        if p95 > budget:
            failures.append(f'{route}: p95 {p95:.1f}ms exceeds budget {budget}ms')
    return {'passed': not failures, 'failures': failures, 'percentiles_by_route': percentiles_by_route}


def _discover_ports(base_url, *, timeout_seconds=5):
    response = requests.get(base_url.rstrip('/') + '/api/services', timeout=timeout_seconds)
    response.raise_for_status()
    return [int(item['port']) for item in response.json()]


def _routes_for_ports(ports):
    routes = [
        {'label': label, 'url_path': label}
        for label in (
            '/api/services', '/api/scan-status', '/api/thumbnail-status',
            '/api/history', '/api/advanced/current',
        )
    ]
    routes.extend(
        {'label': '/api/thumbnail/<port>', 'url_path': f'/api/thumbnail/{port}'}
        for port in ports
    )
    return routes


def _load_worker(base_url, routes, latencies_by_route, latencies_lock, stop_event, session):
    """Issue a rotating mix of GETs against the dashboard's own routes.

    This is the "discovery + preview churn + analytics queries" mix
    06-RESEARCH.md Pattern 5 specifies; the worker's own discovery, preview,
    cleanup and sampling jobs supply the background half simply by running
    on the deployment under test.
    """
    if not routes:
        return
    index = 0
    while not stop_event.is_set():
        route = routes[index % len(routes)]
        index += 1
        url = base_url.rstrip('/') + route['url_path']
        start = time.monotonic()
        try:
            session.get(url, timeout=10)
        except requests.exceptions.RequestException:
            pass
        elapsed_ms = (time.monotonic() - start) * 1000
        with latencies_lock:
            latencies_by_route.setdefault(route['label'], []).append(elapsed_ms)


def _container_root_pid(name, *, runner=subprocess.run, timeout_seconds=DOCKER_INSPECT_TIMEOUT_SECONDS):
    """Resolve a running container's root PID via ``docker inspect``.

    Returns ``(pid, reason)``: a positive ``pid`` with ``reason`` ``None``
    on success, or ``pid`` ``None`` with a short named ``reason`` on any
    failure. Invokes docker as an argv list through ``runner`` -- never a
    shell string, never ``shell=True`` (T-06-31) -- issuing one invocation
    per container name so a missing container is attributable to that name
    rather than to an ambiguous position in a multi-name result. Docker
    reports PID ``0`` for a container that exists but is not running; that
    is treated as a failure, never as a valid target.
    """
    if not _CONTAINER_NAME_RE.fullmatch(name):
        raise ValueError(f'invalid container name: {name!r}')
    try:
        result = runner(
            ['docker', 'inspect', '--format', '{{.State.Pid}}', name],
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except FileNotFoundError:
        return None, f'{name}: docker binary not found'
    except subprocess.TimeoutExpired:
        return None, f'{name}: docker inspect timed out after {timeout_seconds}s'
    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        return None, f'{name}: docker inspect failed (rc={result.returncode}): {stderr}'
    raw = (result.stdout or '').strip()
    try:
        pid = int(raw)
    except ValueError:
        return None, f'{name}: unparseable docker inspect output: {raw!r}'
    if pid == 0:
        return None, f'{name}: container is not running (reported PID 0)'
    return pid, None


def resolve_container_process_tree(name, *, runner=subprocess.run):
    """Resolve a container's root process plus every descendant.

    Returns ``(processes, reason)`` -- a non-empty list of
    ``psutil.Process`` handles on success with ``reason`` unset, or an
    empty list with a reason on failure. Recursion into ``children`` is
    load-bearing, not defensive tidiness: on real hardware a web
    container's root process was an idle gunicorn master while the process
    actually serving requests was its forked child (06-UAT.md "Second
    defect"), so sampling only the root would reproduce that exact defect
    in a subtler form. A process that exits between enumeration and
    sampling is tolerated by skipping it, not by failing the run.
    """
    root_pid, reason = _container_root_pid(name, runner=runner)
    if root_pid is None:
        return [], reason
    try:
        root_process = psutil.Process(root_pid)
        processes = [root_process, *root_process.children(recursive=True)]
    except psutil.NoSuchProcess:
        return [], f'{name}: root PID {root_pid} exited before it could be sampled'
    return processes, None


def _resource_targets(*, self_test, worker_container='beacon-worker', web_container='beacon-web',
                       runner=subprocess.run):
    """Resolve the worker/web resource-sampling targets this run samples.

    Real acceptance runs resolve each role's targets from the Beacon
    containers themselves via ``resolve_container_process_tree`` -- never
    by host-wide command-line matching, which on real hardware sampled an
    unrelated co-tenant application's process because it happened to share
    a command-line substring with Beacon's own (06-UAT.md "Second
    defect"). A role whose container cannot be resolved comes back with an
    empty process list and a named reason; there is no fallback to any
    other process on the host. A ``--self-test`` run has no separate
    worker/web containers (it starts one in-process Flask app on a
    thread), so it resolves both roles to the current process -- this
    fallback is reachable only from ``self_test=True`` and structurally
    unreachable from an acceptance-shaped resolution (PROH-OPS-07-02,
    PROH-OPS-07-04).
    """
    if self_test:
        self_process = psutil.Process()
        return {
            role: ResourceTarget(
                role=role, container=None, method='self_test',
                root_pid=self_process.pid, processes=[self_process], reason=None,
            )
            for role in ('worker', 'web')
        }
    targets = {}
    for role, container in (('worker', worker_container), ('web', web_container)):
        processes, reason = resolve_container_process_tree(container, runner=runner)
        root_pid = processes[0].pid if processes else None
        targets[role] = ResourceTarget(
            role=role, container=container, method='docker_container_tree',
            root_pid=root_pid, processes=processes, reason=reason,
        )
    return targets


def _cached_handle(target, discovered):
    """Return the ``psutil.Process`` object the caller should actually use.

    ``discovered`` is a freshly-enumerated object for this tick. If
    ``target.handles`` already holds an object for the same PID *and* that
    cached object is still the same underlying process (``create_time()``
    matches), the cached object is returned so ``cpu_percent(interval=None)``
    keeps diffing against the same object's prior-tick state. Otherwise --
    no cached handle, or a PID recycled onto a different process -- the
    freshly-discovered object is stored and primed (``cpu_percent`` called
    once to establish a baseline) instead of inheriting a stale one.

    A newly-inserted handle reading ``0.0`` on the tick that inserted it is
    ``psutil``'s correct semantics for a process with no prior sample -- a
    real absence of a baseline, not the structural zero this fixes.
    """
    pid = discovered.pid
    cached = target.handles.get(pid)
    if cached is not None:
        try:
            same_process = cached.create_time() == discovered.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            same_process = False
        if same_process:
            return cached
    target.handles[pid] = discovered
    try:
        discovered.cpu_percent(interval=None)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return discovered


def _live_role_processes(target):
    """Return a role's currently-live process set for one sampling tick.

    For a container-resolved role this re-walks ``children(recursive=True)``
    from the held root PID on every call rather than returning a set fixed
    at run start (PROH-OPS-07-06): a gunicorn worker respawn mid-run would
    otherwise leave the role sampling only the surviving master. A root PID
    that has disappeared is a genuine failure for this tick, surfaced as an
    empty process list rather than a raised exception.

    Every freshly-discovered object is mapped through ``_cached_handle`` so
    the object identity ``cpu_percent(interval=None)`` depends on survives
    from tick to tick (D-DEBT-06-06), and ``target.handles`` is pruned to
    exactly the PID set discovered on this tick so the cache is bounded by
    the live process count rather than by run duration.
    """
    if target.method == 'self_test':
        # Route self-test processes through _cached_handle too. This branch
        # used to return before reaching it, so --self-test got no priming
        # at all and reported primed_pid_count: 0 -- which is precisely the
        # signature the cpu_sampling provenance block was added to flag as a
        # BROKEN CPU column (06-REVIEW-ROUND3.md CR-03). A diagnostic that
        # reports its own failure signature in a healthy mode is worse than
        # no diagnostic. Self-test targets are a fixed, already-enumerated
        # set, so caching is a no-op for identity here; what matters is that
        # priming and the accounting both happen.
        return [_cached_handle(target, process) for process in target.processes]
    if target.root_pid is None:
        return []
    try:
        root_process = psutil.Process(target.root_pid)
        discovered = [root_process, *root_process.children(recursive=True)]
    except psutil.NoSuchProcess:
        return []
    live = [_cached_handle(target, proc) for proc in discovered]
    live_pids = {proc.pid for proc in live}
    for pid in list(target.handles):
        if pid not in live_pids:
            del target.handles[pid]
    return live


def _prime_cpu_percent(targets):
    """Prime ``cpu_percent`` for every role's current process set.

    ``psutil``'s first ``cpu_percent(interval=None)`` call on a process is
    meaningless (no prior sample to diff against); priming here means the
    first real tick already has a baseline for every process resolved at
    run start. Priming resolves its process objects through
    ``_live_role_processes`` -- the same function every sampling tick uses
    -- so the priming pass and the sampling ticks now share one set of
    cached objects rather than two disjoint sets (D-DEBT-06-06).

    The actual ``cpu_percent(interval=None)`` baseline call now happens
    inside ``_cached_handle`` on a process's first insert into
    ``target.handles``, triggered as a side effect of calling
    ``_live_role_processes`` below -- this function no longer calls
    ``cpu_percent`` a second time itself. Doing so would double-prime every
    run-start process (one call from ``_cached_handle``'s insert path, one
    more from this loop), which contradicts the one-call-per-priming
    contract: "cpu_percent(interval=None) is called exactly once for
    priming plus exactly once per tick -- never twice per tick, and never
    re-primed."
    """
    for target in targets.values():
        if target.reason is not None:
            continue
        _live_role_processes(target)


def _sample_resources_tick(targets, samples_by_role, sampled_pids_by_role):
    """Take one resource-sampling pass across every resolved role.

    Re-derives each role's live process set fresh from ``_live_role_processes``
    on every call -- not once at run start -- so a respawned child is
    picked up on the very next tick (PROH-OPS-07-06). A role's sample is
    the sum of RSS and CPU across its live process set: summing RSS
    over-counts pages shared copy-on-write between a parent and its forked
    child, so the reading is an upper bound rather than an exact figure.
    For an acceptance oracle asserting against a ceiling, an upper bound
    can produce a false failure but never a false pass -- the correct
    direction to bias toward for evidence this phase has already been
    burned by trusting (06-UAT.md "Second defect").
    """
    for role, target in targets.items():
        if target.reason is not None:
            continue
        rss_total = 0
        cpu_total = 0.0
        pids_this_tick = []
        for proc in _live_role_processes(target):
            try:
                rss_total += proc.memory_info().rss
                cpu_total += proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            pids_this_tick.append(proc.pid)
        if not pids_this_tick:
            continue
        samples_by_role.setdefault(role, []).append({
            'ts': int(time.time()), 'rss_bytes': rss_total, 'cpu_percent': cpu_total,
            'pids': pids_this_tick,
        })
        sampled_pids_by_role.setdefault(role, set()).update(pids_this_tick)


def _sample_resources(targets, duration_seconds, samples_by_role, sampled_pids_by_role, stop_event):
    _prime_cpu_percent(targets)
    deadline = time.monotonic() + duration_seconds
    while time.monotonic() < deadline and not stop_event.is_set():
        _sample_resources_tick(targets, samples_by_role, sampled_pids_by_role)
        time.sleep(SAMPLE_INTERVAL_SECONDS)


def _resource_unavailable_reason(role, target, sample_count):
    """Return a named failure reason for a role the resource oracle could not measure.

    Replaces the old ``all(proc is None ...)`` guard, which required BOTH
    roles to be unresolved before it fired -- so one role resolving
    silently excused the other. Under container resolution a partial
    failure is the realistic case, not an edge case, so each role is
    judged on its own: an unresolved role's own resolution reason is
    surfaced verbatim, and a role that resolved but produced zero samples
    (its container could have exited mid-run) gets a reason explaining the
    absence rather than being summarised as a ``None`` peak that quietly
    passes. Returns ``None`` only when the role resolved and produced at
    least one sample -- ``assert_resource_budget`` remains the sole rule
    for whether that sample is within budget (PROH-OPS-07-01); this
    function only ever explains *why* there is no sample to judge.
    """
    if target.reason is not None:
        return f'resource oracle unavailable for {role}: container {target.container}: {target.reason}'
    if sample_count == 0:
        return (
            f'resource oracle unavailable for {role}: container {target.container} resolved '
            f'(root PID {target.root_pid}) but produced zero samples'
        )
    return None


# ---------------------------------------------------------------------------
# 06-17: lock-profile collection and the CONFIRMED/REFUTED/INCONCLUSIVE
# verdict. Everything in this section is diagnostic-only (PROH-OPS-07-11,
# PROH-OPS-07-12) -- it contributes to no assertion above and to neither
# report.overall_passed nor report.failure_reasons. See `06-VERIFICATION.md`
# Truth 5's `missing:` items for what this section derives and why.
# ---------------------------------------------------------------------------

# `06-VERIFICATION.md` Truth 5's own falsifiable predictions and
# `06-ACCEPTANCE-ROUND3.md`'s own figures, declared as data (T-06-89) so the
# verdict's thresholds are visible without re-deriving them, and so a test
# can assert each constant against the document it came from.
LOCK_ATTRIBUTION_PREDICTIONS = {
    # Truth 5 missing item 1: "/api/scan-status will show ~0ms hold" -- the
    # max median hold below which scan-status counts as "holding the lock
    # only briefly." 5ms is generous headroom above the instrument's own
    # ~1469.1ns per-acquisition cost (06-15-SUMMARY.md) while staying far
    # below /api/services' predicted 200-500ms hold.
    'scan_status_max_median_hold_ns': 5_000_000,
    # Same item, RETIRED FORM (D-DEBT-06-14): "/api/services will show
    # ~200-500ms hold" was originally an absolute band
    # (services_min_median_hold_ns / services_max_median_hold_ns,
    # [200_000_000, 500_000_000]) calibrated to round 3's 25,278-row
    # dataset. Round 4's hardware run measured /api/services' hold at
    # 596,245,129ns (596.245ms) against a Pi holding 56,828 rows (2.24x
    # that dataset) -- the band failed on the HIGH side purely because the
    # deployment's data volume had grown since the band was set, not
    # because the attribution was wrong (06-LOCK-DIAGNOSTIC.md's Verdict
    # section). services_min_hold_over_scan_status_hold_ratio replaces it:
    # both terms (/api/services' hold, /api/scan-status' hold) are
    # measured in the SAME run, so the ratio is dataset-size-invariant by
    # construction -- /api/services' hold scales with stored check count
    # while /api/scan-status' does not, so growth moves the measured ratio
    # AWAY from the floor, never through it. Calibrated against round 4's
    # own measured figures: 596.245ms / 2.532ms = 235.5, comfortably above
    # the 20.0 floor.
    'services_min_hold_over_scan_status_hold_ratio': 20.0,
    # Same item: "and a wait that grows with the number of siblings queued
    # ahead of it". 06-DEBT.md D-DEBT-06-09's arithmetic
    # (242.614 - 3.281 = 239.333ms is 1.143x one /api/services critical
    # section, 209.355ms control p50 -- 06-ACCEPTANCE-ROUND3.md) puts
    # scan-status' median wait at roughly one full /api/services hold. 0.5 is
    # a conservative floor: the wait must be at least half of services'
    # median hold to count as "queued behind one full critical section."
    'scan_status_min_wait_over_services_hold_fraction': 0.5,
    # Truth 5 missing item 2: the ~0.85 utilisation threshold where M/G/1
    # queueing delay goes superlinear.
    'utilisation_superlinear_threshold': 0.85,
    # Below this many acquisitions for a route, no median is read -- too few
    # samples for a bucketed percentile to mean anything.
    'min_acquisitions_for_median': 20,
    # The refutation condition (this is the constant that makes the round a
    # diagnostic rather than a confirmation exercise): the minimum lock-wait
    # share of a slow route's wall time below which the attribution is
    # CONTRADICTED, not merely unsupported.
    'min_lock_wait_share_of_wall_for_confirmation': 0.5,
    # Below this wall time, a run has not reproduced a slow /api/scan-status
    # at all and has nothing to explain either way.
    # 06-ACCEPTANCE-ROUND3.md's control p50 was 3.281ms; its acceptance p50
    # was 242.614ms (a 74x degradation) -- 50ms sits well above control noise
    # and well below the degraded figure.
    'scan_status_slow_wall_threshold_ns': 50_000_000,
}


class LockProfileCounterWentBackwardsError(Exception):
    """Raised by ``diff_lock_profile`` when an ``after`` counter (or bucket)
    is smaller than its ``before`` value -- meaning the collector's process
    restarted mid-window, so the window is not measurable. Never silently
    returns a negative or nonsense delta (D-DEBT-06-10)."""


def fetch_lock_profile(base_url, *, timeout_seconds):
    """One GET against ``LOCK_PROFILE_PATH``, derived from ``base_url`` so
    there is no second URL to keep in sync with a live deployment. Returns
    the parsed snapshot dict on success; raises for the caller to record
    honestly on any failure -- connection error, non-200 status (via
    ``raise_for_status``), or an unparseable body. Never swallowed here."""
    url = base_url.rstrip('/') + LOCK_PROFILE_PATH
    response = requests.get(url, timeout=timeout_seconds)
    response.raise_for_status()
    return response.json()


def percentile_from_histogram(counts, edges, pct):
    """Return ``(lower_edge_ns, upper_edge_ns)`` bounding the ``pct``-th
    percentile of a fixed-edge cumulative histogram's bucket counts -- never
    a single false-precision number (D-DEBT-06-10).

    ``counts`` has ``len(edges) + 1`` entries, mirroring
    ``dashboard/beacon/lockprofile.py``'s ``_bucket_index``: bucket ``i`` for
    ``i < len(edges)`` covers ``(edges[i-1], edges[i]]`` (with an implicit
    lower bound of 0 for ``i == 0``), and the final bucket (index
    ``len(edges)``) is the unbounded overflow bucket. Returns ``(0, 0)`` when
    every bucket is empty (nothing to bound), and ``(edges[-1], math.inf)``
    when the percentile falls in the overflow bucket.
    """
    total = sum(counts)
    if total <= 0:
        return (0, 0)
    rank = max(1, math.ceil(pct / 100 * total))
    cumulative = 0
    for index, count in enumerate(counts):
        cumulative += count
        if cumulative < rank:
            continue
        if index >= len(edges):
            return (edges[-1], math.inf)
        lower = 0 if index == 0 else edges[index - 1]
        return (lower, edges[index])
    return (edges[-1], math.inf)


# Field groups diffed by _diff_stats -- shared between the per-route
# acquisition table (`routes`/`lock`) and the per-route request table
# (`requests`/`requests_total`), which have different scalar-counter shapes.
_ROUTE_COUNTER_FIELDS = (
    'acquisitions', 'wait_ns_total', 'hold_ns_total', 'wait_ns_max', 'hold_ns_max',
    'connect_ns_total', 'lease_ns_total', 'sql_execute_ns_total', 'sql_fetch_ns_total',
    'python_ns_total',
)
_ROUTE_HISTOGRAM_FIELDS = ('wait_histogram', 'hold_histogram')

_REQUEST_COUNTER_FIELDS = (
    'requests', 'wall_ns_total', 'cpu_ns_total', 'lock_wait_ns_total',
    'other_off_cpu_ns_total', 'wall_ns_max', 'cpu_ns_max',
)
_REQUEST_HISTOGRAM_FIELDS = ('wall_histogram', 'cpu_histogram')


def _diff_stats(before, after, counter_fields, histogram_fields, *, context):
    result = {}
    for field_name in counter_fields:
        before_value = before.get(field_name, 0)
        after_value = after.get(field_name, 0)
        if after_value < before_value:
            raise LockProfileCounterWentBackwardsError(
                f'{context}.{field_name} went backwards ({before_value} -> {after_value}) -- '
                'the collector likely restarted mid-window; the window is not measurable.'
            )
        result[field_name] = after_value - before_value
    for field_name in histogram_fields:
        before_hist = before.get(field_name) or []
        after_hist = after.get(field_name) or []
        diffed = []
        for index, after_count in enumerate(after_hist):
            before_count = before_hist[index] if index < len(before_hist) else 0
            if after_count < before_count:
                raise LockProfileCounterWentBackwardsError(
                    f'{context}.{field_name}[{index}] went backwards '
                    f'({before_count} -> {after_count}) -- the collector likely restarted '
                    'mid-window; the window is not measurable.'
                )
            diffed.append(after_count - before_count)
        result[field_name] = diffed
    return result


def diff_lock_profile(before, after):
    """Windowed counters and histogram bucket counts from two cumulative
    ``lockprofile.snapshot()`` dicts. Raises
    ``LockProfileCounterWentBackwardsError`` rather than returning nonsense
    when any ``after`` value is smaller than its ``before`` counterpart --
    the collector's process restarted mid-window and the window is not
    measurable."""
    window_ns = after['captured_monotonic_ns'] - before['captured_monotonic_ns']
    if window_ns < 0:
        raise LockProfileCounterWentBackwardsError(
            f'captured_monotonic_ns went backwards ({before["captured_monotonic_ns"]} -> '
            f'{after["captured_monotonic_ns"]}) -- the collector likely restarted mid-window.'
        )

    route_labels = set(before.get('routes', {})) | set(after.get('routes', {}))
    routes = {
        label: _diff_stats(
            before.get('routes', {}).get(label, {}), after.get('routes', {}).get(label, {}),
            _ROUTE_COUNTER_FIELDS, _ROUTE_HISTOGRAM_FIELDS, context=f'routes[{label!r}]',
        )
        for label in route_labels
    }
    lock = _diff_stats(
        before.get('lock', {}), after.get('lock', {}),
        _ROUTE_COUNTER_FIELDS, _ROUTE_HISTOGRAM_FIELDS, context='lock',
    )

    request_labels = set(before.get('requests', {})) | set(after.get('requests', {}))
    requests_by_route = {
        label: _diff_stats(
            before.get('requests', {}).get(label, {}), after.get('requests', {}).get(label, {}),
            _REQUEST_COUNTER_FIELDS, _REQUEST_HISTOGRAM_FIELDS, context=f'requests[{label!r}]',
        )
        for label in request_labels
    }
    requests_total = _diff_stats(
        before.get('requests_total', {}), after.get('requests_total', {}),
        _REQUEST_COUNTER_FIELDS, _REQUEST_HISTOGRAM_FIELDS, context='requests_total',
    )

    for scalar_name in ('sql_outside_lock_ns', 'clamped_python_count', 'clamped_off_cpu_count'):
        before_value = before.get(scalar_name, 0)
        after_value = after.get(scalar_name, 0)
        if after_value < before_value:
            raise LockProfileCounterWentBackwardsError(
                f'{scalar_name} went backwards ({before_value} -> {after_value}) -- the '
                'collector likely restarted mid-window; the window is not measurable.'
            )

    return {
        'window_ns': window_ns,
        'routes': routes,
        'lock': lock,
        'requests': requests_by_route,
        'requests_total': requests_total,
        'sql_outside_lock_ns': after.get('sql_outside_lock_ns', 0) - before.get('sql_outside_lock_ns', 0),
        'clamped_python_count': (
            after.get('clamped_python_count', 0) - before.get('clamped_python_count', 0)
        ),
        'clamped_off_cpu_count': (
            after.get('clamped_off_cpu_count', 0) - before.get('clamped_off_cpu_count', 0)
        ),
        'route_overflow': after.get('route_overflow', False),
        'request_route_overflow': after.get('request_route_overflow', False),
    }


def _percentile_bounds(histogram, edges, pct):
    lower_ns, upper_ns = percentile_from_histogram(histogram, edges, pct)
    return {'lower_ns': lower_ns, 'upper_ns': upper_ns}


def summarize_lock_profile(before, after):
    """Derive the per-route wait/hold percentiles and hold-decomposition
    shares, the per-route request wall/cpu/lock-wait/other-off-cpu
    percentiles, and the global utilisation from two cumulative
    ``lockprofile.snapshot()`` dicts taken around the load window. Every
    percentile is a pair of bounding edges (``percentile_from_histogram``),
    never a single false-precision number.
    """
    diff = diff_lock_profile(before, after)
    window_ns = diff['window_ns']

    routes_summary = {}
    for label, route in diff['routes'].items():
        hold = route['hold_ns_total']
        sql = route['sql_execute_ns_total'] + route['sql_fetch_ns_total']
        routes_summary[label] = {
            'acquisitions': route['acquisitions'],
            'wait_ns_total': route['wait_ns_total'],
            'hold_ns_total': hold,
            'wait_ns_max': route['wait_ns_max'],
            'hold_ns_max': route['hold_ns_max'],
            'wait_percentiles_ns': {
                'p50': _percentile_bounds(
                    route['wait_histogram'], beacon_lockprofile.WAIT_HISTOGRAM_EDGES_NS, 50,
                ),
                'p95': _percentile_bounds(
                    route['wait_histogram'], beacon_lockprofile.WAIT_HISTOGRAM_EDGES_NS, 95,
                ),
            },
            'hold_percentiles_ns': {
                'p50': _percentile_bounds(
                    route['hold_histogram'], beacon_lockprofile.HOLD_HISTOGRAM_EDGES_NS, 50,
                ),
                'p95': _percentile_bounds(
                    route['hold_histogram'], beacon_lockprofile.HOLD_HISTOGRAM_EDGES_NS, 95,
                ),
            },
            'connect_share': (route['connect_ns_total'] / hold) if hold else None,
            'sql_share': (sql / hold) if hold else None,
            'python_share': (route['python_ns_total'] / hold) if hold else None,
        }

    requests_summary = {}
    for label, req in diff['requests'].items():
        requests_summary[label] = {
            'requests': req['requests'],
            'wall_ns_total': req['wall_ns_total'],
            'cpu_ns_total': req['cpu_ns_total'],
            'lock_wait_ns_total': req['lock_wait_ns_total'],
            'other_off_cpu_ns_total': req['other_off_cpu_ns_total'],
            'wall_percentiles_ns': {
                'p50': _percentile_bounds(
                    req['wall_histogram'], beacon_lockprofile.WALL_HISTOGRAM_EDGES_NS, 50,
                ),
                'p95': _percentile_bounds(
                    req['wall_histogram'], beacon_lockprofile.WALL_HISTOGRAM_EDGES_NS, 95,
                ),
            },
            'cpu_percentiles_ns': {
                'p50': _percentile_bounds(
                    req['cpu_histogram'], beacon_lockprofile.CPU_HISTOGRAM_EDGES_NS, 50,
                ),
                'p95': _percentile_bounds(
                    req['cpu_histogram'], beacon_lockprofile.CPU_HISTOGRAM_EDGES_NS, 95,
                ),
            },
        }

    total_hold = diff['lock']['hold_ns_total']
    utilisation = (total_hold / window_ns) if window_ns > 0 else None

    return {
        'window_ns': window_ns,
        'total_hold_ns': total_hold,
        'utilisation': utilisation,
        'route_overflow': diff['route_overflow'],
        'request_route_overflow': diff['request_route_overflow'],
        'sql_outside_lock_ns': diff['sql_outside_lock_ns'],
        'clamped_python_count': diff['clamped_python_count'],
        'clamped_off_cpu_count': diff['clamped_off_cpu_count'],
        'routes': routes_summary,
        'requests': requests_summary,
    }


def evaluate_lock_attribution(summary):
    """Three-valued verdict against ``LOCK_ATTRIBUTION_PREDICTIONS``:
    ``CONFIRMED``, ``REFUTED`` or ``INCONCLUSIVE``. Pure function of
    ``summary`` -- reads no module-level mutable state; called twice with
    the same input it returns equal output.

    Preconditions are evaluated first: an explicit ``collected: False``, a
    route overflow, or a missing/under-sampled route all read as
    ``INCONCLUSIVE`` -- a missing measurement is never a refutation. The
    refutation condition is evaluated next, BEFORE the confirmation
    condition -- deliberately: a function that checks its hypothesis first
    and only falls through to refutation is the shape that produced two
    wrong rounds this phase (D-DEBT-06-09, D-DEBT-06-10).
    """
    checks = []

    if summary.get('collected') is False:
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': 'collected is False -- no measurement was taken this window.',
            'checks': checks,
        }

    if summary.get('route_overflow') or summary.get('request_route_overflow'):
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': (
                'route_overflow or request_route_overflow is set -- the per-route table lost '
                'data and the measurement cannot be trusted.'
            ),
            'checks': checks,
        }

    routes = summary.get('routes', {})
    requests = summary.get('requests', {})
    services_route = routes.get('/api/services')
    scan_status_route = routes.get('/api/scan-status')
    scan_status_request = requests.get('/api/scan-status')

    missing = [
        name for name, value in (
            ("routes['/api/services']", services_route),
            ("routes['/api/scan-status']", scan_status_route),
            ("requests['/api/scan-status']", scan_status_request),
        ) if value is None
    ]
    if missing:
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': f'missing measurement: {", ".join(missing)} not present in this window.',
            'checks': checks,
        }

    min_acquisitions = LOCK_ATTRIBUTION_PREDICTIONS['min_acquisitions_for_median']
    if (
        services_route['acquisitions'] < min_acquisitions
        or scan_status_route['acquisitions'] < min_acquisitions
    ):
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': (
                f"too few acquisitions to read a median: /api/services="
                f"{services_route['acquisitions']}, /api/scan-status="
                f"{scan_status_route['acquisitions']} (need >= {min_acquisitions} each)."
            ),
            'checks': checks,
        }

    services_hold_median = services_route['hold_ns_total'] / services_route['acquisitions']
    scan_status_hold_median = scan_status_route['hold_ns_total'] / scan_status_route['acquisitions']
    scan_status_wait_median = scan_status_route['wait_ns_total'] / scan_status_route['acquisitions']
    scan_status_requests = scan_status_request['requests']
    scan_status_wall_median = (
        scan_status_request['wall_ns_total'] / scan_status_requests if scan_status_requests else 0
    )
    scan_status_lock_wait_median = (
        scan_status_request['lock_wait_ns_total'] / scan_status_requests if scan_status_requests else 0
    )

    slow_threshold = LOCK_ATTRIBUTION_PREDICTIONS['scan_status_slow_wall_threshold_ns']
    if scan_status_wall_median < slow_threshold:
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': (
                f'this run did not reproduce a slow /api/scan-status (median wall '
                f'{scan_status_wall_median:.0f}ns < {slow_threshold}ns threshold) -- nothing '
                'to explain either way.'
            ),
            'checks': checks,
        }

    lock_wait_share = (
        scan_status_lock_wait_median / scan_status_wall_median if scan_status_wall_median else 0
    )
    min_share = LOCK_ATTRIBUTION_PREDICTIONS['min_lock_wait_share_of_wall_for_confirmation']
    checks.append({
        'name': 'scan_status_lock_wait_share_of_wall',
        'threshold': min_share,
        'measured': lock_wait_share,
        'held': lock_wait_share >= min_share,
    })
    if lock_wait_share < min_share:
        return {
            'verdict': 'REFUTED',
            'reason': (
                f'/api/scan-status median wall time is {scan_status_wall_median:.0f}ns '
                f'(genuinely slow), but its measured lock-wait share of that wall time is only '
                f'{lock_wait_share:.4f}, below the {min_share} threshold -- the _db_lock '
                'attribution is contradicted by direct measurement.'
            ),
            'checks': checks,
        }

    # Confirmation conditions -- only reached when the refutation condition
    # above did not hold.
    scan_status_max_hold = LOCK_ATTRIBUTION_PREDICTIONS['scan_status_max_median_hold_ns']
    checks.append({
        'name': 'scan_status_median_hold_near_zero',
        'threshold': scan_status_max_hold,
        'measured': scan_status_hold_median,
        'held': scan_status_hold_median <= scan_status_max_hold,
    })

    # D-DEBT-06-14: services_hold_dominates_scan_status_hold replaces the
    # retired absolute band (services_median_hold_in_band). Both terms are
    # measured in this same run, so the ratio is dataset-size-invariant --
    # see the comment on services_min_hold_over_scan_status_hold_ratio
    # above for the full rationale and round-4 figures (596.245ms /
    # 2.532ms = 235.5 against the 20.0 floor). A zero scan-status hold
    # (division-by-zero risk) is a precondition failure, never a division
    # error -- an unmeasurable ratio must read as INCONCLUSIVE, not as a
    # crash or a fabricated held/not-held verdict.
    if scan_status_hold_median <= 0:
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': (
                f'scan_status_hold_median is {scan_status_hold_median} -- cannot compute '
                'services_hold_dominates_scan_status_hold without dividing by zero.'
            ),
            'checks': checks,
        }
    services_hold_ratio = services_hold_median / scan_status_hold_median
    services_min_ratio = LOCK_ATTRIBUTION_PREDICTIONS['services_min_hold_over_scan_status_hold_ratio']
    checks.append({
        'name': 'services_hold_dominates_scan_status_hold',
        'threshold': services_min_ratio,
        'measured': services_hold_ratio,
        'held': services_hold_ratio >= services_min_ratio,
    })

    wait_fraction = scan_status_wait_median / services_hold_median if services_hold_median else 0
    min_fraction = LOCK_ATTRIBUTION_PREDICTIONS['scan_status_min_wait_over_services_hold_fraction']
    checks.append({
        'name': 'scan_status_wait_tracks_services_hold',
        'threshold': min_fraction,
        'measured': wait_fraction,
        'held': wait_fraction >= min_fraction,
    })

    utilisation = summary.get('utilisation')
    utilisation_threshold = LOCK_ATTRIBUTION_PREDICTIONS['utilisation_superlinear_threshold']
    checks.append({
        'name': 'utilisation_above_superlinear_threshold',
        'threshold': utilisation_threshold,
        'measured': utilisation,
        'held': utilisation is not None and utilisation >= utilisation_threshold,
    })

    if all(check['held'] for check in checks):
        return {
            'verdict': 'CONFIRMED',
            'reason': (
                'every prediction held: /api/scan-status holds the lock only briefly and waits '
                "behind /api/services' critical section, /api/services' hold sits in the "
                'predicted band, and utilisation is above the superlinear threshold.'
            ),
            'checks': checks,
        }
    failed_names = ', '.join(
        f"{check['name']} (measured {check['measured']}, threshold {check['threshold']})"
        for check in checks if not check['held']
    )
    return {
        'verdict': 'INCONCLUSIVE',
        'reason': (
            f'the refutation condition did not hold, but not every confirmation prediction did '
            f'either: {failed_names}.'
        ),
        'checks': checks,
    }


# 06-19: the fix's own falsifiable prediction, written BEFORE the fix
# (06-20) and BEFORE any hardware measurement (06-21), per D-DEBT-06-09's
# lesson that a round arriving with no prior prediction can only confirm.
# Calibrated against round 4's measured /api/services figures
# (06-LOCK-DIAGNOSTIC.md sec4): held-region split under load .002 connect /
# .748 sql / .250 python. A successful narrowing should push the python
# share toward (near) zero and the sql share toward (near) the full held
# region. Every entry here is a share of the route's OWN hold, never a
# duration -- dimensionless by construction, so a dataset twice the size
# produces the same share if the fix worked (mirrors the same
# D-DEBT-06-14 lesson LOCK_ATTRIBUTION_PREDICTIONS above now follows).
NARROWING_OUTCOME_PREDICTIONS = {
    # CONFIRMED requires the post-fix python_share to sit at or below this
    # -- round 4 measured 25.0% Python under load; a narrowing that
    # actually moved the Python work out of the critical section should
    # land well under that, not merely a modest improvement on it.
    'services_max_python_share_of_hold': 0.10,
    # REFUTED fires when the post-fix python_share is still at or above
    # this -- i.e. the Python work provably did not leave the critical
    # section. Set below round 4's measured 25.0% baseline so a narrowing
    # that achieved nothing measurable is caught, not read as a partial win.
    'services_refutation_python_share_of_hold': 0.20,
    # CONFIRMED also requires the post-fix sql_share to sit at or above
    # this -- round 4 measured 74.8% SQL under load; a narrowing that
    # actually isolated the SQL-only work should push this share higher
    # still, toward the full held region.
    'services_min_sql_share_of_hold': 0.85,
    # CONFIRMED also requires post-fix utilisation to sit below this --
    # the same 0.85 superlinear threshold LOCK_ATTRIBUTION_PREDICTIONS uses
    # (06-17), reused rather than restated. D-DEBT-06-15's own arithmetic
    # estimates the achievable post-fix utilisation at 0.745-0.82,
    # comfortably under this if the fix works as sized.
    'max_utilisation_after_narrowing': 0.85,
    # Reused, never restated -- the same minimum-acquisitions-for-a-median
    # floor LOCK_ATTRIBUTION_PREDICTIONS uses.
    'min_acquisitions_for_median': LOCK_ATTRIBUTION_PREDICTIONS['min_acquisitions_for_median'],
}


def evaluate_narrowing_outcome(summary):
    """Three-valued verdict -- CONFIRMED, REFUTED, or INCONCLUSIVE -- on
    whether 06-20's narrowing achieved its predicted effect: moving
    /api/services' Python-side work out of the critical section. Written
    BEFORE the fix and BEFORE any hardware measurement, so 06-21 can only
    confirm or refute it, never fit it after the fact. Pure function of
    ``summary`` -- reads no module-level mutable state; called twice with
    the same input it returns equal output.

    Same precondition-first, refutation-before-confirmation ordering as
    ``evaluate_lock_attribution``, for the same reason (D-DEBT-06-09,
    D-DEBT-06-10): a function that checks its hypothesis before ruling out
    an inconclusive or contradicted run is the shape that produced two
    wrong verdicts this phase.

    D-DEBT-06-10's own lesson, applied directly: ``python_share`` is a
    DERIVED remainder (``hold - connect - sql_execute - sql_fetch``), not a
    directly measured quantity. 06-16's own mutation proved the summing
    identity survives a thread-local leak that pushed
    ``clamped_python_count`` to 706/3255 -- so the remainder can be
    arithmetically consistent and still be garbage. ``clamped_python_count``
    is the mutation-verified signal that the remainder is trustworthy; a
    non-zero count makes this verdict INCONCLUSIVE, never CONFIRMED,
    regardless of what the derived shares say.
    """
    checks = []

    if summary.get('collected') is False:
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': 'collected is False -- no measurement was taken this window.',
            'checks': checks,
        }

    if summary.get('route_overflow') or summary.get('request_route_overflow'):
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': (
                'route_overflow or request_route_overflow is set -- the per-route table lost '
                'data and the measurement cannot be trusted.'
            ),
            'checks': checks,
        }

    routes = summary.get('routes', {})
    services_route = routes.get('/api/services')
    if services_route is None:
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': "missing measurement: routes['/api/services'] not present in this window.",
            'checks': checks,
        }

    min_acquisitions = NARROWING_OUTCOME_PREDICTIONS['min_acquisitions_for_median']
    if services_route['acquisitions'] < min_acquisitions:
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': (
                f"too few acquisitions to read a share: /api/services="
                f"{services_route['acquisitions']} (need >= {min_acquisitions})."
            ),
            'checks': checks,
        }

    clamped_python_count = summary.get('clamped_python_count', 0)
    if clamped_python_count:
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': (
                f'clamped_python_count is {clamped_python_count} -- the derived python_share '
                'remainder went negative at least once this window and cannot be trusted '
                '(D-DEBT-06-10).'
            ),
            'checks': checks,
        }

    python_share = services_route.get('python_share')
    sql_share = services_route.get('sql_share')
    if python_share is None or sql_share is None:
        return {
            'verdict': 'INCONCLUSIVE',
            'reason': (
                "routes['/api/services'] carries no hold this window, so python_share/sql_share "
                'are undefined.'
            ),
            'checks': checks,
        }

    refutation_threshold = NARROWING_OUTCOME_PREDICTIONS['services_refutation_python_share_of_hold']
    checks.append({
        'name': 'services_python_share_below_refutation_threshold',
        'threshold': refutation_threshold,
        'measured': python_share,
        'held': python_share < refutation_threshold,
    })
    if python_share >= refutation_threshold:
        return {
            'verdict': 'REFUTED',
            'reason': (
                f"/api/services' python_share is {python_share:.4f}, at or above the "
                f'{refutation_threshold} refutation threshold -- the narrowing did not move the '
                'Python-side work out of the critical section.'
            ),
            'checks': checks,
        }

    # Confirmation conditions -- only reached when the refutation condition
    # above did not hold.
    max_python_share = NARROWING_OUTCOME_PREDICTIONS['services_max_python_share_of_hold']
    checks.append({
        'name': 'services_python_share_at_or_below_confirmation_threshold',
        'threshold': max_python_share,
        'measured': python_share,
        'held': python_share <= max_python_share,
    })

    min_sql_share = NARROWING_OUTCOME_PREDICTIONS['services_min_sql_share_of_hold']
    checks.append({
        'name': 'services_sql_share_at_or_above_confirmation_threshold',
        'threshold': min_sql_share,
        'measured': sql_share,
        'held': sql_share >= min_sql_share,
    })

    utilisation = summary.get('utilisation')
    max_utilisation = NARROWING_OUTCOME_PREDICTIONS['max_utilisation_after_narrowing']
    checks.append({
        'name': 'utilisation_below_max_after_narrowing',
        'threshold': max_utilisation,
        'measured': utilisation,
        'held': utilisation is not None and utilisation < max_utilisation,
    })

    if all(check['held'] for check in checks):
        return {
            'verdict': 'CONFIRMED',
            'reason': (
                "every prediction held: /api/services' python_share sits at or below the "
                'confirmation threshold, its sql_share sits at or above its own threshold, and '
                'utilisation is below the post-narrowing superlinear threshold.'
            ),
            'checks': checks,
        }
    failed_names = ', '.join(
        f"{check['name']} (measured {check['measured']}, threshold {check['threshold']})"
        for check in checks if not check['held']
    )
    return {
        'verdict': 'INCONCLUSIVE',
        'reason': (
            f'the refutation condition did not hold, but not every confirmation prediction did '
            f'either: {failed_names}.'
        ),
        'checks': checks,
    }


def _collect_lock_profile(scenario, before_snapshot, before_failure_reason):
    """Derive the report's ``lock_profile`` block from the ``before``
    snapshot captured immediately before the load window started and an
    ``after`` snapshot fetched here, immediately after the load window
    ended.

    PROH-OPS-07-12: this block is evidence a human reads, never an oracle.
    Any failure -- the before-fetch already failed, the after-fetch fails,
    an unexpected ``schema_version``, or a counter that went backwards --
    results in ``{'collected': False, 'reason': ...}`` and nothing else.
    This function never appends to ``report.failure_reasons``, never
    touches ``report.overall_passed``, and never raises. A later reader
    must not "improve" this into an oracle.
    """
    if before_snapshot is None:
        return {'collected': False, 'reason': before_failure_reason}
    if before_snapshot.get('schema_version') != LOCK_PROFILE_SCHEMA_VERSION:
        return {
            'collected': False,
            'reason': (
                f"before-snapshot schema_version {before_snapshot.get('schema_version')!r} is "
                f'not the {LOCK_PROFILE_SCHEMA_VERSION!r} this harness understands'
            ),
        }

    try:
        after_snapshot = fetch_lock_profile(
            scenario.base_url, timeout_seconds=LOCK_PROFILE_FETCH_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 -- any fetch failure is an honest collected: False
        return {'collected': False, 'reason': f'after-snapshot fetch failed: {exc}'}

    if after_snapshot.get('schema_version') != LOCK_PROFILE_SCHEMA_VERSION:
        return {
            'collected': False,
            'reason': (
                f"after-snapshot schema_version {after_snapshot.get('schema_version')!r} is not "
                f'the {LOCK_PROFILE_SCHEMA_VERSION!r} this harness understands'
            ),
        }

    try:
        summary = summarize_lock_profile(before_snapshot, after_snapshot)
    except LockProfileCounterWentBackwardsError as exc:
        return {'collected': False, 'reason': str(exc)}

    summary['collected'] = True
    # T-06-78 / PROH-OPS-07-11: self-identifying as a diagnostic run, so a
    # report carrying this block is never mistaken for OPS-07 acceptance
    # evidence just because overall_passed happens to be true.
    summary['instrumented'] = True
    summary['attribution'] = evaluate_lock_attribution(summary)
    # PROH-OPS-07-13 (06-19): the narrowing-outcome verdict is recorded
    # alongside attribution under this diagnostic block only. It is never
    # read by assert_response_times, assert_resource_budget, assert_cadence,
    # failure_reasons, or overall_passed -- see
    # test_structural_arm_lock_profile_never_feeds_the_verdict and
    # NarrowingOutcomeVerdictTests' own structural test in
    # tests/test_lock_profile.py.
    summary['narrowing_outcome'] = evaluate_narrowing_outcome(summary)
    return summary


def run_acceptance(scenario):
    """Run one full load-and-assert pass and return its ``AcceptanceReport``.

    Honest failure throughout: an unreachable target, a database that could
    not be opened, or an oracle that could not be sampled all produce
    ``overall_passed=False`` with the reason named in ``failure_reasons`` --
    never a pass with missing evidence.
    """
    started_at = int(time.time())
    run_kind = 'smoke' if scenario.self_test else 'acceptance'
    report = AcceptanceReport(
        run_kind=run_kind,
        host_machine=platform.machine(),
        host_node=platform.node(),
        scenario=asdict(scenario),
        started_at_epoch=started_at,
        finished_at_epoch=started_at,
    )

    try:
        ports = _discover_ports(scenario.base_url)
    except requests.exceptions.RequestException as exc:
        report.failure_reasons.append(
            f'target unreachable: GET {scenario.base_url}/api/services failed: {exc}'
        )
        report.finished_at_epoch = int(time.time())
        report.overall_passed = False
        return report

    routes = _routes_for_ports(ports)
    latencies_by_route = {}
    latencies_lock = threading.Lock()
    resource_samples = {}
    sampled_pids_by_role = {}
    stop_event = threading.Event()

    role_targets = _resource_targets(
        self_test=scenario.self_test,
        worker_container=scenario.worker_container,
        web_container=scenario.web_container,
    )

    session = requests.Session()
    resource_thread = threading.Thread(
        target=_sample_resources,
        args=(role_targets, scenario.duration_seconds, resource_samples, sampled_pids_by_role, stop_event),
        daemon=True,
    )
    load_threads = [
        threading.Thread(
            target=_load_worker,
            args=(scenario.base_url, routes, latencies_by_route, latencies_lock, stop_event, session),
            daemon=True,
        )
        for _ in range(max(1, scenario.concurrency))
    ]

    # 06-17: the `before` snapshot is taken immediately before
    # resource_thread.start() and the `after` snapshot (in the collection
    # block below) immediately after resource_thread's join, so the window
    # brackets exactly the load the latencies were measured over -- a
    # snapshot taken outside those boundaries would measure a different
    # window than the latencies it is read against (D-DEBT-06-10).
    before_lock_profile = None
    before_lock_profile_failure_reason = None
    if scenario.collect_lock_profile:
        try:
            before_lock_profile = fetch_lock_profile(
                scenario.base_url, timeout_seconds=LOCK_PROFILE_FETCH_TIMEOUT_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 -- an honest collected: False, not a crash
            before_lock_profile_failure_reason = f'before-snapshot fetch failed: {exc}'

    resource_thread.start()
    for thread in load_threads:
        thread.start()
    time.sleep(scenario.duration_seconds)
    stop_event.set()
    for thread in load_threads:
        thread.join(timeout=10)
    resource_thread.join(timeout=SAMPLE_INTERVAL_SECONDS + 5)

    report.route_latencies_ms = latencies_by_route
    report.resource_samples = resource_samples

    # PROH-OPS-07-12 / T-06-86: an optional observer, `None` in every real
    # invocation, lets a test capture overall_passed/failure_reasons
    # immediately before and immediately after the collection block below
    # without restructuring this function -- proving the block never moves
    # either value.
    if scenario.observer is not None:
        scenario.observer(list(report.failure_reasons), report.overall_passed)

    if scenario.collect_lock_profile:
        report.lock_profile = _collect_lock_profile(
            scenario, before_lock_profile, before_lock_profile_failure_reason,
        )

    if scenario.observer is not None:
        scenario.observer(list(report.failure_reasons), report.overall_passed)

    now = int(time.time())
    settings = load_settings(os.environ)
    job_health_by_id = {}
    try:
        with database_access(scenario.db_path) as conn:
            job_health_by_id = {
                row['job_id']: row
                for row in beacon_repositories.read_background_job_health(conn, limit=64)
            }
    except Exception as exc:  # noqa: BLE001 -- any DB-open failure is honest-failure evidence
        report.failure_reasons.append(
            f'database oracle unavailable: could not open {scenario.db_path}: {exc}'
        )

    report.background_job_health = list(job_health_by_id.values())

    cadence_result = assert_cadence(job_health_by_id, settings, now=now)
    report.freshness_by_job = cadence_result['freshness_by_job']
    report.failure_reasons.extend(cadence_result['failures'])

    memory_limits = {}
    try:
        memory_limits = parse_compose_memory_limits(scenario.compose_path)
    except (OSError, ValueError) as exc:
        report.failure_reasons.append(f'compose memory-limit oracle unavailable: {exc}')

    resource_summary = {}
    resource_results = []
    resource_targets_report = {}
    for role in ('worker', 'web'):
        target = role_targets[role]
        samples = resource_samples.get(role) or []
        sampled_pids = sorted(sampled_pids_by_role.get(role, set()))
        distinct_pid_sets = {tuple(sorted(sample['pids'])) for sample in samples}
        sampled_set_changed = len(distinct_pid_sets) > 1

        # Per-role resolution provenance: names the container resolved, the
        # method used, the root PID, the union of every PID sampled at any
        # point in the run, and whether that set changed mid-run. Without
        # this a run that silently substituted a respawned worker partway
        # through is indistinguishable in the report from one continuous
        # measurement -- an operator investigating an odd CPU curve has no
        # way to tell which they are holding (PROH-OPS-07-06).
        resource_targets_report[role] = {
            'container': target.container,
            'method': target.method,
            'root_pid': target.root_pid,
            'sampled_pids': sampled_pids,
            'sampled_set_changed': sampled_set_changed,
            'resolution_reason': target.reason,
        }

        # Every role that failed to resolve, or resolved but produced zero
        # samples, gets its own named failure reason. One role resolving
        # must never excuse the other -- the resource criterion covers both
        # the worker and the web tier (PROH-OPS-07-02, PROH-OPS-07-03).
        unavailable_reason = _resource_unavailable_reason(role, target, len(samples))
        if unavailable_reason is not None:
            report.failure_reasons.append(unavailable_reason)

        rss_values = [sample['rss_bytes'] for sample in samples]
        cpu_values = [sample['cpu_percent'] for sample in samples]
        peak_rss = max(rss_values, default=None)
        sample_count = len(samples)
        zero_sample_count = sum(1 for value in cpu_values if value == 0.0)
        nonzero_sample_count = len(cpu_values) - zero_sample_count
        all_samples_zero = nonzero_sample_count == 0 and sample_count > 0
        resource_summary[role] = {
            'sample_count': sample_count,
            'peak_rss_bytes': peak_rss,
            'mean_rss_bytes': (sum(rss_values) / len(rss_values)) if rss_values else None,
            # Peak/mean CPU percent are recorded as observed evidence, not
            # asserted against a limit -- no cpus: cgroup cap is declared in
            # docker-compose.yml (D-DEBT-06-02: a deliberate decision, not a
            # silent omission).
            'peak_cpu_percent': max(cpu_values, default=None),
            'mean_cpu_percent': (sum(cpu_values) / len(cpu_values)) if cpu_values else None,
            # D-DEBT-06-06 provenance: makes an untrue CPU column
            # self-announcing in the report instead of silently
            # indistinguishable from a genuinely idle deployment.
            # `all_samples_zero` being true on an acceptance-shaped run is
            # the broken-measurement signature D-DEBT-06-06 describes and
            # must be read as such, never as evidence of a low-CPU
            # deployment -- but it is deliberately never appended to
            # failure_reasons and never affects assertions.resources.passed
            # (PROH-OPS-07-01, D-DEBT-06-02: CPU carries no cap in this
            # round). The condition is for a human to read at 06-14's
            # hardware checkpoint, not for the harness to fail on.
            'cpu_sampling': {
                'handle_cache': 'per_pid_run_lifetime',
                'primed_pid_count': len(target.handles),
                'zero_sample_count': zero_sample_count,
                'nonzero_sample_count': nonzero_sample_count,
                'all_samples_zero': all_samples_zero,
            },
        }
        # assert_resource_budget is unchanged and stays the sole rule for
        # whether a role's peak RSS is within budget (PROH-OPS-07-01):
        # the resolution-level reason above explains *why* there is no
        # sample; this assertion is what makes a missing sample an honest
        # failure rather than a None that quietly passes.
        result = assert_resource_budget(peak_rss, memory_limits.get(role), role=role)
        resource_results.append(result)
        if not result['passed']:
            report.failure_reasons.append(
                result.get('reason', f'{role}: resource budget assertion failed')
            )

    response_time_result = assert_response_times(latencies_by_route)
    report.failure_reasons.extend(response_time_result['failures'])

    report.assertions = {
        'cadence': {'passed': cadence_result['passed'], 'failures': cadence_result['failures']},
        'resources': {
            # assert_resource_budget already fails on a missing peak_rss --
            # which is exactly what an unresolved role or an empty sample
            # set produces -- so this reduces cleanly to the same rule
            # governing every other role: no separate, competing check.
            'passed': all(result['passed'] for result in resource_results),
            'results': resource_results,
            'summary': resource_summary,
            'resource_targets': resource_targets_report,
        },
        'response_times': {
            'passed': response_time_result['passed'],
            'failures': response_time_result['failures'],
            'percentiles_by_route': response_time_result['percentiles_by_route'],
        },
    }
    report.finished_at_epoch = int(time.time())
    report.overall_passed = not report.failure_reasons
    return report


def run_self_test(*, collect_lock_profile=False):
    """Run a short, bounded smoke pass against a locally-started Beacon app.

    Never a substitute for real-hardware acceptance evidence: ``run_kind``
    is always ``smoke`` here (PROH-OPS-07-02), computed the same way
    ``run_acceptance`` computes it for any ``--self-test`` invocation --
    never settable independently.

    ``collect_lock_profile`` (06-17) requests the lock-profile snapshot
    pair the same way ``--lock-profile`` does for a real run; it does not
    itself flip the app's ``ENABLE_LOCK_PROFILE`` -- the caller sets that in
    the environment before this function's ``load_app()`` call for a
    rehearsal to exercise the diagnostic endpoint end to end.
    """
    from werkzeug.serving import make_server

    from tests.helpers import cleanup_db, load_app

    appmod, db_path = load_app()
    now = int(time.time())
    port = 8080

    with appmod._db_lock:
        conn = appmod.get_db()
        conn.execute(
            "INSERT INTO services (port, title, first_seen, last_seen, is_online, "
            "last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
            (port, 'Self-test smoke service', now - 120, now, 1, 12.0, None),
        )
        for job_id in ESSENTIAL_JOB_IDS:
            beacon_repositories.record_background_job_succeeded(conn, job_id, now=now)
        conn.commit()
        conn.close()

    server = make_server('127.0.0.1', 0, appmod.app, threaded=True)
    server_port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        scenario = LoadScenario(
            duration_seconds=SELF_TEST_DURATION_SECONDS,
            base_url=f'http://127.0.0.1:{server_port}',
            db_path=db_path,
            concurrency=SELF_TEST_CONCURRENCY,
            self_test=True,
            collect_lock_profile=collect_lock_profile,
        )
        return run_acceptance(scenario)
    finally:
        server.shutdown()
        server_thread.join(timeout=5)
        cleanup_db(db_path)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description='Beacon Raspberry Pi-class load acceptance harness (OPS-07).',
    )
    parser.add_argument(
        '--duration', type=int, default=600, help='Load duration in seconds (default: 600)',
    )
    parser.add_argument(
        '--base-url', default='http://127.0.0.1',
        help='Base URL of the running Beacon web tier (default: http://127.0.0.1)',
    )
    parser.add_argument(
        '--db', default='/data/dashboard.db',
        help='Path to the live dashboard.db (default: /data/dashboard.db)',
    )
    parser.add_argument(
        '--concurrency', type=int, default=8,
        help="Concurrent load-generation threads, matching gunicorn's thread count (default: 8)",
    )
    parser.add_argument('--output', default=None, help='JSON report path (default: stdout)')
    parser.add_argument(
        '--self-test', action='store_true',
        help='Run a short, bounded smoke pass against a locally-started app -- no Pi required',
    )
    parser.add_argument(
        '--worker-container', default='beacon-worker',
        help=(
            "Docker container name resolved for the worker role's resource sampling "
            "(default: beacon-worker, the container_name pinned in docker-compose.yml, so the "
            "harness and the deployment cannot drift apart silently; override for an operator "
            "running a modified compose file)"
        ),
    )
    parser.add_argument(
        '--web-container', default='beacon-web',
        help=(
            "Docker container name resolved for the web role's resource sampling "
            "(default: beacon-web, the container_name pinned in docker-compose.yml, so the "
            "harness and the deployment cannot drift apart silently; override for an operator "
            "running a modified compose file)"
        ),
    )
    parser.add_argument(
        '--lock-profile', action='store_true',
        help=(
            'Collect the `_db_lock` wait/hold snapshot pair around the load window and embed the '
            'derived figures and CONFIRMED/REFUTED/INCONCLUSIVE attribution verdict in the report '
            '(06-17). Off by default. Requires the deployment be started with '
            'ENABLE_LOCK_PROFILE=1 -- otherwise the diagnostic endpoint 404s and the report '
            "carries lock_profile: {'collected': False, ...} without affecting overall_passed "
            '(PROH-OPS-07-12). Diagnostic evidence only -- never OPS-07 acceptance evidence '
            '(PROH-OPS-07-11).'
        ),
    )
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        report = run_self_test(collect_lock_profile=args.lock_profile)
    else:
        scenario = LoadScenario(
            duration_seconds=args.duration,
            base_url=args.base_url,
            db_path=args.db,
            concurrency=args.concurrency,
            self_test=False,
            worker_container=args.worker_container,
            web_container=args.web_container,
            collect_lock_profile=args.lock_profile,
        )
        report = run_acceptance(scenario)

    report_json = report.to_json()
    if args.output:
        Path(args.output).write_text(report_json)
    else:
        print(report_json)
    return 0 if report.overall_passed else 1


if __name__ == '__main__':
    sys.exit(main())
