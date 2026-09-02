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
        return list(target.processes)
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
    run start. Because priming resolves its process objects through
    ``_live_role_processes`` -- the same function every sampling tick uses
    -- the priming pass and the sampling ticks now share one set of cached
    objects rather than two disjoint sets, so the priming survives into the
    ticks instead of being discarded (D-DEBT-06-06).
    """
    for target in targets.values():
        if target.reason is not None:
            continue
        for proc in _live_role_processes(target):
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass


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
        resource_summary[role] = {
            'sample_count': len(samples),
            'peak_rss_bytes': peak_rss,
            'mean_rss_bytes': (sum(rss_values) / len(rss_values)) if rss_values else None,
            # Peak/mean CPU percent are recorded as observed evidence, not
            # asserted against a limit -- no cpus: cgroup cap is declared in
            # docker-compose.yml (D-DEBT-06-02: a deliberate decision, not a
            # silent omission).
            'peak_cpu_percent': max(cpu_values, default=None),
            'mean_cpu_percent': (sum(cpu_values) / len(cpu_values)) if cpu_values else None,
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


def run_self_test():
    """Run a short, bounded smoke pass against a locally-started Beacon app.

    Never a substitute for real-hardware acceptance evidence: ``run_kind``
    is always ``smoke`` here (PROH-OPS-07-02), computed the same way
    ``run_acceptance`` computes it for any ``--self-test`` invocation --
    never settable independently.
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
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        report = run_self_test()
    else:
        scenario = LoadScenario(
            duration_seconds=args.duration,
            base_url=args.base_url,
            db_path=args.db,
            concurrency=args.concurrency,
            self_test=False,
            worker_container=args.worker_container,
            web_container=args.web_container,
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
