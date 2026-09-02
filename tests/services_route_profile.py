#!/usr/bin/env python3
"""Standalone, checked-in profiler attributing `/api/services`'s per-request cost
to named sub-computations (OPS-07 gap closure).

Not a pytest module -- the ``services_route_profile.py`` name deliberately does
not match pytest's ``test_*.py`` collection pattern, so it is never collected
by the suite, matching ``tests/pi_load_acceptance.py``'s convention. Run it
directly against the checked-out repository::

    uv run --project dashboard python tests/services_route_profile.py \\
        --services 8 --days 8 --repeats 5 --output beacon-profile.json

Or run the two-volume growth probe::

    uv run --project dashboard python tests/services_route_profile.py --growth \\
        --small-days 2 --large-days 8 --services 8 --repeats 3 --output beacon-growth.json

WHAT THIS IS AND IS NOT (PROH-OPS-07-09): every absolute millisecond figure
this module reports -- ``wall_ms_unprofiled``, ``wall_ms_profiled``, and every
bucket's ``tottime_ms`` -- was measured on the invoking host, named in the
report via ``platform.machine()`` / ``platform.node()`` as ``host_machine`` /
``host_node``. These figures are NEVER Raspberry Pi latency evidence. The
289.0ms p50 measured on the Pi control pass at concurrency 1
(``06-VERIFICATION.md``, ``06-DEBT.md`` D-DEBT-06-01) remains the sole
authority on absolute per-request cost. What this profiler contributes and
what may be carried into a decision is the PROPORTIONAL attribution
(``share_pct`` / ``attributed_pct``) and the measured growth ratios, not the
milliseconds themselves.

``cProfile`` adds real per-call overhead that is not evenly distributed: it
inflates Python-heavy buckets (pure-Python loops, comprehensions, dataclass
construction) relative to SQL-bound buckets, where most of the wall time is
spent inside the C-level sqlite3 driver outside cProfile's per-line
instrumentation. ``wall_ms_unprofiled`` is reported alongside
``wall_ms_profiled`` precisely so a reader can see how much the instrument
itself perturbed the measured total, rather than reading ``wall_ms_profiled``
as this route's real-world cost.
"""

import argparse
import cProfile
import inspect
import json
import platform
import pstats
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dashboard.beacon import maintenance as beacon_maintenance  # noqa: E402
from dashboard.beacon import monitoring as beacon_monitoring  # noqa: E402
from dashboard.beacon import repositories as beacon_repositories  # noqa: E402
from tests.helpers import cleanup_db, load_app  # noqa: E402


# The 289.0ms p50 the operator measured on real Pi hardware at concurrency 1,
# zero contention -- the fixed reference point every report this module
# produces must be read against, never against this run's own milliseconds
# (PROH-OPS-07-09).
PI_CONTROL_PASS_P50_MS = 289.0

HONESTY_CAVEAT = (
    "Every absolute millisecond figure below was measured on this run's own "
    "host_machine/host_node -- it is NOT Raspberry Pi latency evidence. The "
    f"authority on absolute /api/services cost remains the {PI_CONTROL_PASS_P50_MS}ms "
    "p50 measured on the Pi control pass at concurrency 1. Only the proportional "
    "attribution (share_pct/attributed_pct) and the growth ratios below may be "
    "carried into a decision. cProfile itself adds per-call overhead that "
    "inflates Python-heavy buckets relative to SQL-bound ones -- wall_ms_unprofiled "
    "is reported alongside wall_ms_profiled for exactly that reason."
)

# Deployment cadence this seeded dataset is sized against (dashboard/beacon/
# worker_main.py J3/J4): J3 runs do_uptime_check on every service every 5
# minutes; J4 runs it down-only every 1 minute. CHECK_RETENTION_SECONDS holds
# 8 days, so an 8-day seed writes roughly 2,304 rows per service from the
# 5-minute cadence alone, plus 1-minute rows for the offline fraction of the
# window.
_J3_INTERVAL_SECONDS = 300
_J4_INTERVAL_SECONDS = 60

# PROFILE_PHASES -- an explicit, auditable ordered mapping from bucket name to
# the (filename_suffix, function_name) pairs that belong to it. Every bucket
# names something that genuinely appears in dashboard/app.py's api_services
# (dashboard/app.py lines 2780-2880) or a function it calls.
#
# filename_suffix conventions used by the matcher below:
#   '~'  -- a C/builtin call. cProfile always reports these with filename '~'
#           and a bracketed function description (e.g. "<method 'execute' of
#           'sqlite3.Connection' objects>"); matched by substring on the
#           function name.
#   '*'  -- match the function name anywhere, regardless of file (used only
#           for third-party call sites -- e.g. flask.json.jsonify -- whose
#           exact source path is not part of this project's own contract).
#   else -- a real filename suffix. For the four modules this route actually
#           calls into (dashboard/app.py and dashboard/beacon/
#           {repositories,maintenance,monitoring}.py) the pair is resolved at
#           profiling time to the live function's exact source line range
#           (`_resolve_range_rules`), so a generator expression or
#           comprehension written directly inside that function's body is
#           attributed to the same bucket as the function itself, instead of
#           leaking into `other` under its own separate `<genexpr>` pstats
#           entry. For every other file (stdlib/third-party), the pair is
#           matched by exact filename-suffix + function-name equality only.
PROFILE_PHASES = {
    'sql_execute': [
        ('~', 'execute'),
    ],
    'sql_fetch': [
        ('~', 'fetchall'),
        ('~', 'fetchone'),
    ],
    'row_grouping': [
        ('app.py', 'api_services'),
    ],
    'uptime_sweep': [
        ('app.py', '_legacy_uptime_summary'),
    ],
    'monitoring_operations_binding': [
        ('app.py', '_monitoring_operations'),
        ('beacon/monitoring.py', 'uptime_summary'),
    ],
    'offline_intervals_read': [
        ('beacon/repositories.py', 'read_service_offline_intervals_by_port'),
        ('beacon/repositories.py', '_offline_intervals_from_points'),
    ],
    'maintenance_windows_read': [
        ('beacon/repositories.py', 'read_maintenance_windows_by_port'),
    ],
    'attributed_downtime': [
        ('beacon/maintenance.py', 'attributed_downtime_seconds'),
    ],
    'maintenance_coverage': [
        ('beacon/maintenance.py', 'coverage'),
        ('beacon/maintenance.py', 'window_from_row'),
        ('beacon/maintenance.py', '_local_occurrence_epochs'),
    ],
    'covering_boundaries': [
        ('beacon/maintenance.py', '_covering_boundaries'),
    ],
    'json_serialization': [
        ('*', 'jsonify'),
        ('json/encoder.py', 'iterencode'),
        ('json/encoder.py', 'encode'),
        ('flask/json/provider.py', 'dumps'),
        ('flask/json/provider.py', 'response'),
    ],
}
# Everything not matched by a declared pair above is reported under 'other'
# rather than silently dropped -- 'other' is deliberately not a PROFILE_PHASES
# key, because it names an absence, not a sub-computation.


def _local_module_for(appmod, filename_suffix):
    """Return the live module a declared local (filename_suffix, name) pair resolves
    against, or None if filename_suffix names a builtin/third-party/stdlib target
    that has no source range to resolve (matched by name only instead).
    """
    if filename_suffix == 'app.py':
        return appmod
    if filename_suffix == 'beacon/repositories.py':
        return beacon_repositories
    if filename_suffix == 'beacon/maintenance.py':
        return beacon_maintenance
    if filename_suffix == 'beacon/monitoring.py':
        return beacon_monitoring
    return None


def _resolve_range_rules(appmod):
    """Resolve every local PROFILE_PHASES pair to its live source file and exact
    line range, so a comprehension or generator expression nested inside a
    matched function's body is captured under that function's bucket.
    """
    range_rules = []
    for bucket, pairs in PROFILE_PHASES.items():
        for filename_suffix, function_name in pairs:
            module = _local_module_for(appmod, filename_suffix)
            if module is None:
                continue
            func = getattr(module, function_name)
            source_file = inspect.getsourcefile(func)
            source_lines, first_lineno = inspect.getsourcelines(func)
            range_rules.append(
                (bucket, source_file, first_lineno, first_lineno + len(source_lines) - 1),
            )
    return range_rules


def _classify_key(key, range_rules):
    """Classify one pstats (filename, lineno, funcname) key into a PROFILE_PHASES
    bucket, or 'other' if nothing declared matches it.
    """
    filename, lineno, funcname = key
    for bucket, source_file, start, end in range_rules:
        if filename == source_file and start <= lineno <= end:
            return bucket
    for bucket, pairs in PROFILE_PHASES.items():
        for filename_suffix, function_name in pairs:
            if filename_suffix == '~':
                if filename == '~' and function_name in funcname:
                    return bucket
            elif filename_suffix == '*':
                if funcname == function_name:
                    return bucket
            else:
                if filename.endswith(filename_suffix) and funcname == function_name:
                    return bucket
    return 'other'


def seed_pi_representative_dataset(
    appmod, *, services=8, days=8, all_interval_seconds=_J3_INTERVAL_SECONDS,
    down_interval_seconds=_J4_INTERVAL_SECONDS, offline_fraction=0.10, seed=20260902,
):
    """Seed a Pi-representative /api/services dataset directly through appmod's
    connection, in the ``_seed_services`` style (tests/test_services_route_scaling.py).

    Sized against the deployment's real check cadence (J3: every
    ``all_interval_seconds`` for every service; J4: down-only every
    ``down_interval_seconds`` for the offline fraction of the window) rather
    than an invented row count, so the profiled request's stored-check volume
    matches what a real ``days``-day-retention Beacon deployment would
    actually accumulate. All randomness is drawn from ``random.Random(seed)``,
    so two runs with the same arguments produce the identical dataset. Seeds
    one enabled maintenance window on the first port, so the
    ``attributed_downtime`` and ``maintenance_coverage`` buckets are exercised
    on a non-empty window set rather than measured only on their trivial
    empty-window path.

    Returns a dict describing the seeded shape (not the row count -- callers
    that need the true stored row count must read it back with
    ``SELECT COUNT(*)``, per this plan's growth-measurement contract).
    """
    rng = random.Random(seed)
    now = int(time.time())
    window_start = now - days * 86400

    with appmod._db_lock:
        conn = appmod.get_db()
        for i in range(services):
            port = 20000 + i
            conn.execute(
                "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) "
                "VALUES(?,?,?,?,?,?)",
                (port, f'Pi Service {port}', window_start, now, 1, now - 60),
            )

            # Deterministic offline sub-intervals across the window for this
            # service, so the offline-interval / maintenance-attribution
            # buckets have real, non-trivial work to do.
            offline_windows = []
            cursor = window_start
            while cursor < now:
                span = rng.randint(3600, 6 * 3600)
                segment_end = min(cursor + span, now)
                if rng.random() < offline_fraction:
                    offline_windows.append((cursor, segment_end))
                cursor = segment_end

            def _is_offline(ts, _windows=offline_windows):
                for start_ts, end_ts in _windows:
                    if start_ts <= ts < end_ts:
                        return True
                return False

            ts = window_start
            while ts < now:
                online = 0 if _is_offline(ts) else 1
                # INSERT OR IGNORE: J3's 5-minute cadence and J4's 1-minute
                # down-only cadence can land on the same ts (300 is a
                # multiple of 60); both would write the same online=0 value
                # during an offline segment, so silently keeping the first
                # write is correct, not lossy.
                conn.execute(
                    'INSERT OR IGNORE INTO service_checks(ts, port, online) VALUES (?,?,?)',
                    (ts, port, online),
                )
                ts += all_interval_seconds

            for start_ts, end_ts in offline_windows:
                ts = start_ts
                while ts < end_ts:
                    conn.execute(
                        'INSERT OR IGNORE INTO service_checks(ts, port, online) VALUES (?,?,?)',
                        (ts, port, 0),
                    )
                    ts += down_interval_seconds

            if i == 0:
                conn.execute(
                    "INSERT INTO maintenance_windows(port, start_minute, duration_minutes, "
                    "weekdays, grace_minutes, enabled, created_ts, updated_ts) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (port, 0, 60, '1,2,3,4,5,6,7', 5, 1, now, now),
                )
        conn.commit()
        conn.close()

    return {'services': services, 'days': days, 'seed': seed, 'now': now}


def _count_service_checks(appmod):
    """Read back the true stored service_checks row count -- never assumed
    from the seeding arguments, per this plan's growth-measurement contract.
    """
    with appmod._db_lock:
        conn = appmod.get_db()
        count = conn.execute('SELECT COUNT(*) AS c FROM service_checks').fetchone()['c']
        conn.close()
    return count


def profile_services_route(appmod, *, repeats=5):
    """Drive one real /api/services request repeatedly through
    ``appmod.app.test_client()`` -- never re-implemented or partially called --
    and attribute its measured self time to PROFILE_PHASES buckets.

    Returns a dict with ``wall_ms_unprofiled`` (mean of ``repeats`` unprofiled
    requests), ``wall_ms_profiled`` (mean of ``repeats`` requests under
    cProfile), ``phases`` (bucket -> {tottime_ms, calls, share_pct}, derived
    from pstats self ("tot") time so shares are non-overlapping and sum to
    the profiled total), and ``attributed_pct`` (100 minus the 'other'
    bucket's share).
    """
    client = appmod.app.test_client()

    # Discard the first request as a warm-up so connection setup and
    # import-time costs are never attributed to a per-request bucket.
    warmup = client.get('/api/services')
    if warmup.status_code != 200 or not warmup.get_json():
        raise RuntimeError('warm-up /api/services request did not return 200 with a non-empty body')

    unprofiled_seconds = []
    for _ in range(repeats):
        started = time.perf_counter()
        response = client.get('/api/services')
        elapsed = time.perf_counter() - started
        if response.status_code != 200 or not response.get_json():
            raise RuntimeError('unprofiled /api/services request did not return 200 with a non-empty body')
        unprofiled_seconds.append(elapsed)
    wall_ms_unprofiled = (sum(unprofiled_seconds) / len(unprofiled_seconds)) * 1000

    range_rules = _resolve_range_rules(appmod)
    profiler = cProfile.Profile()
    profiled_seconds = []
    profiler.enable()
    for _ in range(repeats):
        started = time.perf_counter()
        response = client.get('/api/services')
        elapsed = time.perf_counter() - started
        if response.status_code != 200 or not response.get_json():
            profiler.disable()
            raise RuntimeError('profiled /api/services request did not return 200 with a non-empty body')
        profiled_seconds.append(elapsed)
    profiler.disable()
    wall_ms_profiled = (sum(profiled_seconds) / len(profiled_seconds)) * 1000

    stats = pstats.Stats(profiler)
    bucket_tottime = defaultdict(float)
    bucket_calls = defaultdict(int)
    total_tottime = 0.0
    for key, value in stats.stats.items():
        _primitive_calls, num_calls, tottime, _cumtime, _callers = value
        bucket = _classify_key(key, range_rules)
        bucket_tottime[bucket] += tottime
        bucket_calls[bucket] += num_calls
        total_tottime += tottime

    phases = {}
    for bucket, tottime in bucket_tottime.items():
        share_pct = (tottime / total_tottime * 100.0) if total_tottime > 0 else 0.0
        phases[bucket] = {
            'tottime_ms': round(tottime * 1000, 3),
            'calls': bucket_calls[bucket],
            'share_pct': round(share_pct, 3),
        }

    other_share = phases.get('other', {}).get('share_pct', 0.0)
    attributed_pct = round(100.0 - other_share, 3)

    return {
        'wall_ms_unprofiled': round(wall_ms_unprofiled, 3),
        'wall_ms_profiled': round(wall_ms_profiled, 3),
        'phases': phases,
        'attributed_pct': attributed_pct,
        'total_tottime_ms': round(total_tottime * 1000, 3),
        'repeats': repeats,
        'host_machine': platform.machine(),
        'host_node': platform.node(),
        'pi_control_pass_p50_ms': PI_CONTROL_PASS_P50_MS,
        'caveat': HONESTY_CAVEAT,
    }


def profile_growth(appmod_factory, *, small_days, large_days, repeats, seed, services=8):
    """Run the full seed-and-profile cycle at two stored-check volumes against
    two independently constructed app/database fixtures, so neither run
    shares connection or page-cache state with the other -- the same
    isolation discipline test_query_count_is_independent_of_service_count
    already applies.

    Returns, per bucket shared by both runs, the small run's tottime_ms, the
    large run's tottime_ms, and growth_ratio as large-over-small, alongside
    check_row_ratio -- the actual ratio of seeded service_checks rows between
    the two runs, read back with SELECT COUNT(*) rather than assumed from the
    day counts.

    Interpretation rule (carried into the report): a bucket whose
    growth_ratio approaches check_row_ratio is proportional to stored check
    count; a bucket whose ratio stays near 1.0 is not. Which buckets land in
    which category is not hard-coded here -- it is measured.
    """
    small_appmod, small_db_path = appmod_factory()
    try:
        seed_pi_representative_dataset(small_appmod, services=services, days=small_days, seed=seed)
        small_row_count = _count_service_checks(small_appmod)
        small_profile = profile_services_route(small_appmod, repeats=repeats)
    finally:
        cleanup_db(small_db_path)

    large_appmod, large_db_path = appmod_factory()
    try:
        seed_pi_representative_dataset(large_appmod, services=services, days=large_days, seed=seed)
        large_row_count = _count_service_checks(large_appmod)
        large_profile = profile_services_route(large_appmod, repeats=repeats)
    finally:
        cleanup_db(large_db_path)

    check_row_ratio = large_row_count / small_row_count if small_row_count else float('inf')
    if check_row_ratio == float('inf'):
        check_row_ratio = None

    buckets = {}
    shared_bucket_names = set(small_profile['phases']) & set(large_profile['phases'])
    for bucket in shared_bucket_names:
        small_tottime_ms = small_profile['phases'][bucket]['tottime_ms']
        large_tottime_ms = large_profile['phases'][bucket]['tottime_ms']
        # A floor, not a rounding trick: keeps growth_ratio finite (never a
        # literal division by zero, never a non-JSON-serializable inf) even
        # for a bucket whose small-volume cost measured at exactly 0.0ms.
        growth_ratio = large_tottime_ms / max(small_tottime_ms, 1e-6)
        proportional = (
            check_row_ratio is not None and growth_ratio >= (check_row_ratio / 2.0)
        )
        buckets[bucket] = {
            'small_tottime_ms': small_tottime_ms,
            'large_tottime_ms': large_tottime_ms,
            'growth_ratio': round(growth_ratio, 3),
            'classification': 'proportional_to_check_count' if proportional else 'not_proportional_to_check_count',
        }

    worst_attributed_pct = min(small_profile['attributed_pct'], large_profile['attributed_pct'])

    return {
        'small_days': small_days,
        'large_days': large_days,
        'services': services,
        'seed': seed,
        'repeats': repeats,
        'small_row_count': small_row_count,
        'large_row_count': large_row_count,
        'check_row_ratio': round(check_row_ratio, 3) if check_row_ratio is not None else None,
        'buckets': buckets,
        'small_profile': small_profile,
        'large_profile': large_profile,
        'attributed_pct': worst_attributed_pct,
        'host_machine': platform.machine(),
        'host_node': platform.node(),
        'pi_control_pass_p50_ms': PI_CONTROL_PASS_P50_MS,
        'caveat': HONESTY_CAVEAT,
    }


def _render_attribution_markdown(report):
    lines = [
        '# /api/services attribution',
        '',
        f"Host: `{report['host_machine']}` / `{report['host_node']}` "
        "-- host-relative, NOT Pi latency evidence (PROH-OPS-07-09).",
        '',
        HONESTY_CAVEAT,
        '',
        f"wall_ms_unprofiled: {report['wall_ms_unprofiled']}ms   "
        f"wall_ms_profiled: {report['wall_ms_profiled']}ms   "
        f"attributed_pct: {report['attributed_pct']}%",
        '',
        '| bucket | tottime_ms | calls | share_pct |',
        '| --- | --- | --- | --- |',
    ]
    for bucket, data in sorted(report['phases'].items(), key=lambda kv: kv[1]['share_pct'], reverse=True):
        lines.append(f"| {bucket} | {data['tottime_ms']} | {data['calls']} | {data['share_pct']} |")
    return '\n'.join(lines) + '\n'


def _render_growth_markdown(report):
    lines = [
        '# /api/services growth probe',
        '',
        f"Host: `{report['host_machine']}` / `{report['host_node']}` "
        "-- host-relative, NOT Pi latency evidence (PROH-OPS-07-09).",
        '',
        HONESTY_CAVEAT,
        '',
        f"small_days={report['small_days']} (rows={report['small_row_count']})   "
        f"large_days={report['large_days']} (rows={report['large_row_count']})   "
        f"check_row_ratio={report['check_row_ratio']}",
        '',
        '| bucket | small_tottime_ms | large_tottime_ms | growth_ratio | classification |',
        '| --- | --- | --- | --- | --- |',
    ]
    for bucket, data in sorted(report['buckets'].items(), key=lambda kv: kv[1]['growth_ratio'], reverse=True):
        lines.append(
            f"| {bucket} | {data['small_tottime_ms']} | {data['large_tottime_ms']} | "
            f"{data['growth_ratio']} | {data['classification']} |",
        )
    return '\n'.join(lines) + '\n'


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Attribute /api/services's per-request cost to named sub-computations "
            "(OPS-07 gap closure, PROH-OPS-07-09)."
        ),
    )
    parser.add_argument('--services', type=int, default=8, help='Number of services to seed (default: 8)')
    parser.add_argument('--days', type=int, default=8, help='Days of check-retention window to seed (default: 8)')
    parser.add_argument('--repeats', type=int, default=5, help='Requests measured per run (default: 5)')
    parser.add_argument(
        '--seed', type=int, default=20260902,
        help='Deterministic seed for the seeded dataset (default: 20260902)',
    )
    parser.add_argument('--output', default=None, help='JSON report path (default: stdout)')
    parser.add_argument('--markdown', default=None, help='Human-readable attribution/growth table path')
    parser.add_argument(
        '--min-attributed', type=float, default=90.0,
        help=(
            'Minimum attributed_pct required for a zero exit (default: 90.0). The fast shape '
            'gates in this plan pass 0 here; the real 8-service/8-day report run leaves this at '
            'its default, which is the plan\'s only assertion of the 90.0 attribution contract.'
        ),
    )
    parser.add_argument(
        '--growth', action='store_true',
        help='Run the two-volume growth probe (profile_growth) instead of a single attribution run',
    )
    parser.add_argument(
        '--small-days', type=int, default=2, help='Small-volume day count for --growth (default: 2)',
    )
    parser.add_argument(
        '--large-days', type=int, default=8, help='Large-volume day count for --growth (default: 8)',
    )
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.growth:
        report = profile_growth(
            lambda: load_app({}),
            small_days=args.small_days, large_days=args.large_days,
            repeats=args.repeats, seed=args.seed, services=args.services,
        )
        markdown = _render_growth_markdown(report)
    else:
        appmod, db_path = load_app({})
        try:
            seed_pi_representative_dataset(appmod, services=args.services, days=args.days, seed=args.seed)
            report = profile_services_route(appmod, repeats=args.repeats)
        finally:
            cleanup_db(db_path)
        markdown = _render_attribution_markdown(report)

    report_json = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(report_json)
    else:
        print(report_json)

    if args.markdown:
        Path(args.markdown).write_text(markdown)

    return 0 if report['attributed_pct'] >= args.min_attributed else 1


if __name__ == '__main__':
    sys.exit(main())
