"""Phase 7 (DIA-09): ``ENABLE_ADVANCED_DIAGNOSTICS`` end to end.

07-01 is the tracer -- one configuration value wired from environment to
``Settings`` to ``dashboard/app.py``'s module constant to the single route
that actually costs something, ``/api/advanced/current``. 07-02 and 07-03
extend this module with the remaining routes, the front page's entry point,
and the front-page cost-equality and reversibility measurements.

MODULE RULE, established by 07-01 Task 1 and binding on every class added to
this module across all three plans in this phase: every ``load_app`` call in
this module passes an explicit ``ENABLE_ADVANCED_DIAGNOSTICS`` value -- ``'1'``
for an enabled application, ``'0'`` for a disabled one. No call site may rely
on the ambient environment.

Why this is load-bearing rather than stylistic: ``tests/helpers.py``'s
``load_app`` copies ``extra_env`` into ``os.environ`` and never removes it
(``tests/helpers.py:51-65``) -- it only rewrites its own six baseline keys on
each call, so anything passed through ``extra_env`` persists in the process
environment for the rest of the test run. ``importlib.reload`` then rebuilds
``SETTINGS`` from that polluted environment on every subsequent call,
including one that passes an empty or partial mapping. unittest orders
classes alphabetically within a module, which puts ``DisabledAdvancedApiTests``
ahead of ``EnabledResponseGoldenTests``; an enabled-side ``load_app`` call left
implicit would silently run disabled, and an enabled-side measurement that
runs disabled can never fail. The unset-default property itself -- that a
deployment setting nothing gets the feature -- is proven ONLY by
``SettingsAdvancedDiagnosticsTests``' direct ``load_settings({})`` call, which
never touches ``load_app`` and is therefore immune to this leak; no
``load_app`` call anywhere in this phase may be cited as evidence for the
default.

The leak also escapes this module: whatever value the last-run class here
leaves in ``os.environ`` persists into every later module in the same pytest
process. ``tearDownModule`` below restores ``ENABLE_ADVANCED_DIAGNOSTICS`` to
its pre-module state (deleting it if it was unset) so a later module's own
bare ``load_app({})`` -- for example
``tests/test_advanced_diagnosis_api.py::AdvancedCurrentCostTests
.test_the_snapshot_schema_version_advanced`` -- is never silently poisoned by
a run of this module.
"""

import contextlib
import hashlib
import importlib
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

import dashboard.app as _appmod_ref
import dashboard.beacon.db as _beacon_db_ref
from dashboard.beacon import frontpage as beacon_frontpage
from dashboard.beacon import migrations as beacon_migrations
from dashboard.beacon import repositories
from dashboard.beacon.config import load_settings
from tests.helpers import _ensure_psutil_stub, cleanup_db, load_app


def _epoch(year, month, day, hour, minute, second=0):
    return int(datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).timestamp())


FIXTURES_DIR = Path(__file__).resolve().parent / 'fixtures'
GOLDEN_PATH = FIXTURES_DIR / '07_advanced_current_enabled_response_golden.json'
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / 'dashboard'
STATIC_ASSET_NAMES = ('index.html', 'advanced.html', 'advanced.css', 'advanced.js')

# 07-03: docker-compose.yml lives at the repository root, one level above
# DASHBOARD_DIR.
COMPOSE_PATH = DASHBOARD_DIR.parent / 'docker-compose.yml'

# The last commit that touched dashboard/ before this phase's first
# production edit -- the fixed referent EnabledResponseGoldenTests compares
# against. The precondition this rests on, checked literally rather than by
# HEAD identity: `git diff --quiet ceef6da -- dashboard/` exits 0.
CAPTURED_AT_COMMIT = 'ceef6da'

# Monday, inside the seeded maintenance window below -- the same frozen
# instant shape `AdvancedCurrentCostTests` uses in
# tests/test_advanced_diagnosis_api.py, so this fixture is directly
# comparable to the two goldens that precede it.
_GOLDEN_FROZEN_NOW = _epoch(2026, 1, 5, 4, 0, 0)

# Read by generate_enabled_response_golden() alone -- no test in this module
# reads this constant, so a normal pytest run can never trigger a
# regeneration (idiom: tests/test_lock_profile.py's
# `_REGENERATE_GOLDEN_FIXTURES`).
_REGENERATE_ENABLED_GOLDEN = False

_ORIGINAL_ENABLE_ADVANCED_DIAGNOSTICS = 'unset'  # sentinel distinct from None

# The enabled response's `settings` block (dashboard/beacon/diagnosis.py's
# _settings_payload) is sensitive to TELEMETRY_* and METRIC_SAMPLE_SECONDS /
# DISCOVERY_TIMEOUT_SECONDS, none of which `load_app`'s own baseline reset
# covers (tests/helpers.py:52-59 resets only six unrelated keys). At least
# one other module (tests/test_historical_telemetry_api.py's
# ConfiguredTelemetryPolicyApiTests) sets TELEMETRY_RAW_DAYS/
# TELEMETRY_FIVE_MINUTE_DAYS/TELEMETRY_RETENTION_DAYS/TELEMETRY_POINT_BUDGET
# via `load_app` and never clears them either, so the golden comparison
# observed those values leak through when the full suite runs in
# alphabetical file order (that module sorts before this one) even though it
# passes cleanly in isolation. Every key `_settings_payload` reads is pinned
# here at `dashboard/beacon/config.py`'s literal defaults, so this test's
# result can never move because an unrelated module ran first.
_DEFAULT_SETTINGS_PAYLOAD_ENV = {
    'ENABLE_ADVANCED_DIAGNOSTICS': '1',
    'METRIC_SAMPLE_SECONDS': '5',
    'DISCOVERY_TIMEOUT_SECONDS': '180',
    'TELEMETRY_RAW_DAYS': '7',
    'TELEMETRY_FIVE_MINUTE_DAYS': '30',
    'TELEMETRY_RETENTION_DAYS': '90',
    'TELEMETRY_POINT_BUDGET': '2048',
    'TELEMETRY_DB_MAX_BYTES': '536870912',
    'TELEMETRY_MIN_FREE_BYTES': '1073741824',
    'TELEMETRY_PRESSURE_WARNING_PERCENT': '80',
    'TELEMETRY_PRESSURE_HARD_PERCENT': '90',
    'TELEMETRY_PRESSURE_RECOVERY_PERCENT': '75',
}


def setUpModule():
    global _ORIGINAL_ENABLE_ADVANCED_DIAGNOSTICS
    _ORIGINAL_ENABLE_ADVANCED_DIAGNOSTICS = os.environ.get('ENABLE_ADVANCED_DIAGNOSTICS')


def tearDownModule():
    """Undo this module's `load_app` environment leak so no later pytest
    module in the same process inherits a value this module wrote."""
    if _ORIGINAL_ENABLE_ADVANCED_DIAGNOSTICS is None:
        os.environ.pop('ENABLE_ADVANCED_DIAGNOSTICS', None)
    else:
        os.environ['ENABLE_ADVANCED_DIAGNOSTICS'] = _ORIGINAL_ENABLE_ADVANCED_DIAGNOSTICS


class DatabaseWorkCounter:
    """Counts SQLite connections opened and statements SQLite actually
    executed over the real `dashboard.beacon.db.connect_db` seam, during a
    real request served through the real Flask test client (Task 3). This
    is a measurement, not an inspection: it never asserts that a particular
    reader was called and does not depend on knowing which reader runs."""

    def __init__(self):
        self.connections = 0
        self.statements = 0

    def _on_statement(self, _statement):
        self.statements += 1


@contextlib.contextmanager
def _counting_connections():
    """Wrap the real `connect_db` so every connection a request opens,
    wherever in the call tree it is opened, is counted, and every statement
    SQLite executes on that connection is counted via
    `set_trace_callback`.

    Patches BOTH bindings of `connect_db`: the `dashboard.beacon.db` module
    attribute that `database_access`/`read_transaction`/`write_transaction`
    resolve internally, AND `dashboard.app`'s own imported alias
    (`from .beacon.db import connect_db`, which binds a second, independent
    name at import time and would resolve to the unpatched function if left
    alone -- this is why `get_db()` and every direct `connect_db(...)` call
    site in `dashboard/app.py` are also covered).
    """
    counter = DatabaseWorkCounter()
    real_connect_db = _beacon_db_ref.connect_db

    def _wrapped(settings_or_path):
        conn = real_connect_db(settings_or_path)
        counter.connections += 1
        conn.set_trace_callback(counter._on_statement)
        return conn

    with mock.patch.object(_beacon_db_ref, 'connect_db', _wrapped), \
         mock.patch.object(_appmod_ref, 'connect_db', _wrapped):
        yield counter


def _asset_sha256():
    return {
        name: hashlib.sha256((DASHBOARD_DIR / name).read_bytes()).hexdigest()
        for name in STATIC_ASSET_NAMES
    }


def _load_app_over_existing_db(extra_env, db_path):
    """Reopen `db_path` under a fresh `dashboard.app` reload -- the same
    mechanism `tests/helpers.py`'s `load_app` uses (write baseline env,
    reload the module, set `DB_PATH`, call `init_db()`), minus minting a
    fresh temporary database directory (`tests/helpers.py:73-74`).

    07-03 needs two application builds to see the SAME on-disk database --
    `FrontPageCostEqualityTests`' off-vs-on comparison and
    `ToggleReversibilityTests`' restart round trip both depend on it -- and
    plain `load_app` cannot do that; every call mints its own `db_dir`.

    Carries the module rule exactly like `load_app`: every caller passes
    its own explicit `ENABLE_ADVANCED_DIAGNOSTICS` value.
    """
    env = {
        'TRIGGER_SCAN_RATE_LIMIT': '2',
        'TRIGGER_SCAN_WINDOW_SECONDS': '60',
        'ALERT_WEBHOOK_URL': '',
        'ALERT_COOLDOWN_SECONDS': '60',
        'ALERT_ONLY_CRITICAL': '0',
        'EXPIRE_DAYS': '7',
    }
    if extra_env:
        for key, value in extra_env.items():
            env[key] = str(value)
    for key, value in env.items():
        os.environ[key] = value

    _ensure_psutil_stub()

    appmod = importlib.reload(_appmod_ref)
    appmod.DB_PATH = db_path
    appmod.init_db()
    return appmod


def _iterdump_sha256(db_path):
    """sha256 of a fresh connection's `iterdump()` output -- the
    database's LOGICAL content, not its bytes. The deployment runs SQLite
    in WAL mode, so read-only traffic can move the `-wal`/`-shm` sidecar
    files; a file-bytes oracle would fail for a reason unrelated to stored
    data, and a guard that fails for unrelated reasons is a guard that gets
    silenced by whoever hits that false failure first."""
    conn = sqlite3.connect(db_path)
    try:
        dump = '\n'.join(conn.iterdump())
    finally:
        conn.close()
    return hashlib.sha256(dump.encode('utf-8')).hexdigest()


# 07-03 Task 2: docker-compose.yml's ENABLE_ADVANCED_DIAGNOSTICS lives in the
# `environment: &beacon-environment` anchor under `x-beacon-common`, entirely
# ABOVE `services:` (docker-compose.yml lines 14-35 at the time this was
# written). tests/pi_load_acceptance.py's `parse_compose_memory_limits`
# (lines 254-291) is this repository's style precedent for a line-oriented,
# no-YAML-dependency compose scan -- copied for STYLE ONLY. Its own
# `in_services` gate confines it to lines below `services:` and would return
# an empty result for this key by construction; reusing its logic here would
# produce a guard that passes on nothing.
_BEACON_ENVIRONMENT_ANCHOR_HEADER = 'environment: &beacon-environment'


def _scan_beacon_environment_anchor(compose_path):
    """Scan the `environment: &beacon-environment` anchor block for its
    `KEY: value` entries, returning a LIST of `(key, raw_value)` pairs (not
    a dict) so a duplicated key is observable as two entries rather than
    silently collapsed to one."""
    lines = Path(compose_path).read_text().splitlines()
    in_anchor = False
    entries = []
    for line in lines:
        if line.strip() == _BEACON_ENVIRONMENT_ANCHOR_HEADER:
            in_anchor = True
            continue
        if not in_anchor:
            continue
        if not line.startswith('    '):
            # A blank line, or a dedent back to `environment:`'s own 2-space
            # indent (or shallower), ends the anchor block.
            break
        match = re.match(r'^ {4}([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$', line)
        if match:
            entries.append((match.group(1), match.group(2).strip()))
    return entries


def _enable_advanced_diagnostics_compose_entries(compose_path):
    return [
        raw_value for key, raw_value in _scan_beacon_environment_anchor(compose_path)
        if key == 'ENABLE_ADVANCED_DIAGNOSTICS'
    ]


_COMPOSE_INTERPOLATION_RE = re.compile(r'^\$\{[A-Za-z_][A-Za-z0-9_]*:-(.*)\}$')


def _resolve_unset_default(raw_value):
    """Resolve compose's `${NAME:-default}` interpolation form down to the
    value the deployment uses when the operator sets no shell variable.
    The raw scanned value is still quoted
    (e.g. `"${BEACON_ADVANCED_DIAGNOSTICS:-1}"`), so surrounding double
    quotes are stripped first."""
    text = raw_value.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1]
    match = _COMPOSE_INTERPOLATION_RE.match(text)
    if not match:
        raise ValueError(f'expected a ${{NAME:-default}} interpolation, got {raw_value!r}')
    return match.group(1)


class _SeedingHelpers:
    """Local duplicate of tests/test_advanced_diagnosis_api.py's
    `_MaintenanceDiagnosisFixture` seeding shape -- kept local, rather than
    imported, so every `load_app` call site relevant to this module's rule
    stays visible to a grep over this one file."""

    @staticmethod
    def seed_service(appmod, port, *, online, state_since, last_error=None):
        with appmod._db_lock:
            conn = appmod.get_db()
            conn.execute(
                'INSERT INTO services('
                'port,title,first_seen,last_seen,is_online,last_latency_ms,last_error,'
                'state_since,overrun_raised_ts'
                ') VALUES(?,?,?,?,?,?,?,?,?)',
                (
                    port, f'Service {port}', state_since - 100, state_since + 100000,
                    online, None, last_error, state_since, None,
                ),
            )
            conn.execute(
                'INSERT INTO service_meta(port,display_name,url,critical,pinned_order,tags,'
                'healthy_statuses) VALUES(?,?,?,?,?,?,?)',
                (port, f'Service {port}', f'http://127.0.0.1:{port}', 0, port, '', '200-399'),
            )
            conn.execute(
                'INSERT INTO service_checks(ts,port,online,latency_ms,error_class) '
                'VALUES(?,?,?,?,?)',
                (state_since, port, online, None, last_error),
            )
            conn.commit()
            conn.close()

    @staticmethod
    def write_window(appmod, port, *, start_minute, duration_minutes, weekdays, grace_minutes, now):
        with appmod._db_lock:
            conn = appmod.get_db()
            repositories.upsert_maintenance_windows(
                conn, port=port,
                windows=[{
                    'start_minute': start_minute, 'duration_minutes': duration_minutes,
                    'weekdays': set(weekdays), 'grace_minutes': grace_minutes, 'enabled': True,
                }],
                now=now,
            )
            conn.commit()
            conn.close()

    @staticmethod
    def seed_three_service_dataset(appmod, now):
        """One online service (20001), one offline covered by an enabled
        maintenance window (20002), one offline and unattributed (20003) --
        the same three-way shape `AdvancedCurrentCostTests`' golden uses in
        tests/test_advanced_diagnosis_api.py."""
        _SeedingHelpers.seed_service(appmod, 20001, online=1, state_since=now - 900)
        _SeedingHelpers.seed_service(
            appmod, 20002, online=0, state_since=now - 5400, last_error='ConnectionRefused',
        )
        _SeedingHelpers.write_window(
            appmod, 20002, start_minute=120, duration_minutes=180, weekdays=(1,),
            grace_minutes=10, now=now,
        )
        _SeedingHelpers.seed_service(
            appmod, 20003, online=0, state_since=now - 5400, last_error='ConnectionRefused',
        )


class _FrozenClockTestCase(unittest.TestCase):
    """Freeze process-global `time.time` for one test, unwound by
    `addCleanup` even on failure -- copied verbatim in mechanism from
    `tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests
    ._freeze_clock`, because that module's `ClockIsolationTests` exists
    precisely because a leaked frozen clock has escaped a module here
    before."""

    def setUp(self):
        super().setUp()
        self._clock = {'now': None}
        self._clock_patcher = None

    def _freeze_clock(self, value):
        self._clock['now'] = value
        if self._clock_patcher is None:
            real_time = time.time
            patcher = mock.patch(
                'time.time',
                lambda: real_time() if self._clock['now'] is None else self._clock['now'],
            )
            patcher.start()
            self.addCleanup(patcher.stop)
            self._clock_patcher = patcher
        return value


def generate_enabled_response_golden():
    """Regenerate tests/fixtures/07_advanced_current_enabled_response_golden.json
    against the tree as it stands. Guarded by `_REGENERATE_ENABLED_GOLDEN`
    (False by default) and read by no test in this module, so a normal
    pytest run can never trigger it (idiom: tests/test_lock_profile.py's
    `_REGENERATE_GOLDEN_FIXTURES`). Run manually, e.g.:

        python -c "from tests.test_optional_advanced_diagnostics import \\
            generate_enabled_response_golden as g; g()"

    with `_REGENERATE_ENABLED_GOLDEN` temporarily flipped to True.
    """
    if not _REGENERATE_ENABLED_GOLDEN:
        raise RuntimeError(
            'set _REGENERATE_ENABLED_GOLDEN = True to regenerate the enabled response golden',
        )

    appmod, db_path = load_app(dict(_DEFAULT_SETTINGS_PAYLOAD_ENV))  # ENABLE_ADVANCED_DIAGNOSTICS='1'
    try:
        client = appmod.app.test_client()
        with mock.patch('time.time', lambda: _GOLDEN_FROZEN_NOW):
            _SeedingHelpers.seed_three_service_dataset(appmod, _GOLDEN_FROZEN_NOW)
            response = client.get('/api/advanced/current')
            fixture = {
                'captured_at_commit': CAPTURED_AT_COMMIT,
                'captured_at_head': subprocess.check_output(
                    ['git', 'rev-parse', 'HEAD'], text=True, cwd=str(Path(__file__).resolve().parent.parent),
                ).strip(),
                'status_code': response.status_code,
                'content_type': response.content_type,
                'cache_control': response.headers.get('Cache-Control'),
                'body': response.get_data(as_text=True),
                'asset_sha256': _asset_sha256(),
            }
        GOLDEN_PATH.write_text(
            json.dumps(fixture, indent=2, sort_keys=True) + '\n', encoding='utf-8',
        )
    finally:
        cleanup_db(db_path)


class DisabledAdvancedApiTests(_FrozenClockTestCase):
    """Task 2: with ENABLE_ADVANCED_DIAGNOSTICS='0', /api/advanced/current
    answers 404 having done nothing -- Task 3 extends this class with the
    connection/statement measurement over the same disabled request, plus
    the counter's own sensitivity checks.

    Runs alphabetically BEFORE EnabledResponseGoldenTests and writes '0'
    into os.environ['ENABLE_ADVANCED_DIAGNOSTICS'] via `load_app`, which
    never clears it (tests/helpers.py:51-65) -- this class is why the
    module rule at the top of this file exists, and why
    EnabledResponseGoldenTests must never leave its own `load_app` call
    implicit.
    """

    def setUp(self):
        super().setUp()
        self.appmod, self.db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)
        super().tearDown()

    def test_the_disabled_route_answers_404_with_an_empty_body(self):
        response = self.client.get('/api/advanced/current')
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_data(as_text=True), '')

    def test_the_disabled_route_answers_404_even_with_a_query_string(self):
        """A disabled route reports absence, never the 400 the enabled
        handler reserves for an unexpected query string -- confirms the
        gate is the handler's first statement, ahead of `request.args`."""
        response = self.client.get('/api/advanced/current?foo=bar')
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_data(as_text=True), '')

    def test_disabled_request_opens_zero_connections_and_executes_zero_statements(self):
        """Task 3: the claim measured on real connections during a real
        request, never read out of the source. The statement-count
        assertion runs before the status-code assertion so a removed gate
        fails loudly with the real observed statement count, never merely
        "expected 0" -- see the mutation recorded in the SUMMARY."""
        with _counting_connections() as counter:
            response = self.client.get('/api/advanced/current')

        self.assertEqual(
            counter.statements, 0,
            f'disabled /api/advanced/current executed {counter.statements} SQLite '
            f'statement(s) across {counter.connections} connection(s) instead of zero',
        )
        self.assertEqual(counter.connections, 0)
        self.assertEqual(response.status_code, 404)

    def test_disabled_front_page_performs_zero_database_work(self):
        """Weak on its own -- `/` is a static `send_file` that performs no
        diagnosis work today even with advanced diagnostics fully enabled --
        and included as a STANDING guard rather than as evidence for
        criterion 3: it gains teeth the moment 07-02 gives `/` a conditional
        branch for the entry point, and it is the reason 07-02 cannot
        deliver the flag to the front page through a database read. The
        measurement with independent force is the zero-versus-observed
        contrast on /api/advanced/current below; 07-03 supplies the
        front-page cost equality that gives this claim its real weight."""
        with _counting_connections() as counter:
            response = self.client.get('/')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(counter.connections, 0)
        self.assertEqual(counter.statements, 0)

    def test_the_counter_fires_on_ordinary_traffic_not_only_the_route_under_test(self):
        """Sensitivity of the instrument itself: `/api/stats` has a single
        known read and is never gated by this phase. If this read zero the
        counter itself would be broken, independent of
        `api_advanced_current`'s own gate -- this is what makes the
        disabled-route zero-work measurement above believable rather than
        an artifact of an inert instrument. Built explicitly enabled via
        `load_app` because this class has already written '0' into an
        `os.environ` that `load_app` never clears."""
        appmod, db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '1'})
        try:
            client = appmod.app.test_client()
            with _counting_connections() as counter:
                response = client.get('/api/stats')
        finally:
            cleanup_db(db_path)

        self.assertIn(response.status_code, (200, 503))
        self.assertGreater(counter.statements, 0)

    def test_enabled_measurement_of_the_same_request_is_strictly_greater_than_disabled(self):
        """The relation off == 0 < on -- never an absolute count, ratio or
        duration for the enabled side (D-DEBT-06-14's lesson): the enabled
        figure depends on the dataset and will move as Beacon's readers
        change, and pinning it would convert a measurement into a brittle
        constant.

        Built explicitly enabled via `load_app({'ENABLE_ADVANCED_DIAGNOSTICS':
        '1'})` because this class has already written '0' into an
        `os.environ` `load_app` never cleans (tests/helpers.py:51-65). If
        this side were accidentally built disabled it would read zero too,
        the contrast would collapse to `0 == 0`, and the assertion below
        would fail loudly rather than pass -- that loudness is by design
        and the explicit '1' is what keeps it from ever being needed.
        """
        with _counting_connections() as off_counter:
            off_response = self.client.get('/api/advanced/current')

        on_appmod, on_db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '1'})
        try:
            on_client = on_appmod.app.test_client()
            self._freeze_clock(_GOLDEN_FROZEN_NOW)
            _SeedingHelpers.seed_three_service_dataset(on_appmod, _GOLDEN_FROZEN_NOW)
            with _counting_connections() as on_counter:
                on_response = on_client.get('/api/advanced/current')
        finally:
            cleanup_db(on_db_path)

        self.assertEqual(off_response.status_code, 404)
        self.assertEqual(on_response.status_code, 200)
        self.assertEqual(off_counter.connections, 0)
        self.assertEqual(off_counter.statements, 0)
        self.assertGreater(on_counter.connections, 0)
        self.assertGreater(on_counter.statements, 0)
        self.assertLess(off_counter.connections, on_counter.connections)
        self.assertLess(off_counter.statements, on_counter.statements)


class EnabledResponseGoldenTests(_FrozenClockTestCase):
    """Task 1: the pre-change `/api/advanced/current` response, captured
    from the tree at `CAPTURED_AT_COMMIT`, byte-for-byte. Failure messages
    name `captured_at_commit` -- the referent -- never `captured_at_head`,
    because this tree's HEAD is expected to be a docs-only descendant of it
    rather than the commit itself."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.golden = json.loads(GOLDEN_PATH.read_text(encoding='utf-8'))

    def setUp(self):
        super().setUp()
        # Module rule: explicit '1' -- DisabledAdvancedApiTests runs first
        # alphabetically and leaves '0' in os.environ that `load_app` never
        # clears (tests/helpers.py:51-65). This is the site that rule exists
        # to protect. Also pins every TELEMETRY_*/METRIC_SAMPLE_SECONDS/
        # DISCOVERY_TIMEOUT_SECONDS key `_settings_payload` reads at its
        # config.py default, so an unrelated module's own environment leak
        # (e.g. tests/test_historical_telemetry_api.py's
        # ConfiguredTelemetryPolicyApiTests, which sets TELEMETRY_RAW_DAYS
        # etc. via `load_app` and never clears them either) can never move
        # this golden comparison when the full suite runs in file order.
        self.appmod, self.db_path = load_app(dict(_DEFAULT_SETTINGS_PAYLOAD_ENV))
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)
        super().tearDown()

    def test_the_enabled_response_matches_the_pre_change_golden(self):
        self._freeze_clock(_GOLDEN_FROZEN_NOW)
        _SeedingHelpers.seed_three_service_dataset(self.appmod, _GOLDEN_FROZEN_NOW)

        response = self.client.get('/api/advanced/current')

        referent = f"the golden captured at {self.golden['captured_at_commit']}"
        self.assertEqual(
            response.status_code, self.golden['status_code'],
            f"/api/advanced/current's enabled status moved from {referent}",
        )
        self.assertEqual(
            response.content_type, self.golden['content_type'],
            f"/api/advanced/current's enabled content type moved from {referent}",
        )
        self.assertEqual(
            response.headers.get('Cache-Control'), self.golden['cache_control'],
            f"/api/advanced/current's enabled Cache-Control moved from {referent}",
        )
        self.assertEqual(
            response.get_data(as_text=True), self.golden['body'],
            f"/api/advanced/current's enabled response body moved from {referent}",
        )

    def test_the_static_advanced_assets_match_the_pre_change_golden_digests(self):
        self.assertEqual(_asset_sha256(), self.golden['asset_sha256'])


class DisabledAdvancedAssetTests(unittest.TestCase):
    """07-02 Task 1: the three remaining advanced surfaces (`/advanced`,
    `/advanced.css`, `/advanced.js`) 404 with the toggle off, mirroring
    `api_advanced_current`'s gate (D-07-02) -- and the front page's own
    assets (`/`, `/style.css`, `/app.js`) are never gated, only the advanced
    bundle is.

    Runs alphabetically after `DisabledAdvancedApiTests`, which has already
    written '0' into `os.environ['ENABLE_ADVANCED_DIAGNOSTICS']` via
    `load_app` (never cleared -- tests/helpers.py:51-65). This class's own
    `setUp` deepens that leak; every enabled-side method below builds its
    own application through an explicit `'1'`, per the module rule.
    """

    def setUp(self):
        super().setUp()
        self.appmod, self.db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)
        super().tearDown()

    def test_the_disabled_toggle_gates_only_the_advanced_bundle(self):
        """Drives the three gated paths and the three ungated front-page
        paths in one subtest loop so a regression names the path that
        moved, with its observed status."""
        cases = [
            ('/advanced', 404),
            ('/advanced.css', 404),
            ('/advanced.js', 404),
            ('/', 200),
            ('/style.css', 200),
            ('/app.js', 200),
        ]
        for path, expected_status in cases:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(
                    response.status_code, expected_status,
                    f'{path} answered {response.status_code}, expected {expected_status}',
                )
                if expected_status == 404:
                    self.assertEqual(response.get_data(as_text=True), '')

    def test_enabled_advanced_surfaces_are_byte_identical_to_disk(self):
        """The explicit '1' is required rather than stylistic: this class's
        own `setUp` above has already written '0' into `os.environ`, and
        `load_app` never clears it (tests/helpers.py:51-65) -- an implicit
        build here would compare a 404 body against a file's bytes.

        This assertion is deliberately an invariant rather than a frozen
        digest: it stays true across any legitimate future edit to these
        four files and still fails the moment the enabled path starts
        transforming a document -- the property criterion 4 actually needs,
        and the property 07-02 Task 2 puts at risk."""
        appmod, db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '1'})
        try:
            client = appmod.app.test_client()
            asset_directory = Path(appmod.__file__).resolve().parent
            for path, filename in [
                ('/', 'index.html'),
                ('/advanced', 'advanced.html'),
                ('/advanced.css', 'advanced.css'),
                ('/advanced.js', 'advanced.js'),
            ]:
                with self.subTest(path=path):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(
                        response.data, (asset_directory / filename).read_bytes(),
                        f'{path} diverged from {filename} on disk',
                    )
        finally:
            cleanup_db(db_path)

    def test_the_enabled_asset_digests_still_match_07_01s_fixture(self):
        """Distinct from the invariant above, and deliberately so: this
        phase must not change a served asset. A later phase legitimately
        editing one of these files is expected to update the fixture; this
        assertion failing is that phase's cue to do so, not evidence this
        assertion is wrong."""
        golden = json.loads(GOLDEN_PATH.read_text(encoding='utf-8'))
        self.assertEqual(
            _asset_sha256(), golden['asset_sha256'],
            'a served advanced asset moved from the digests captured in '
            "07-01's fixture -- this phase must not change a served asset; "
            'a later phase legitimately editing one of these files should '
            'update the fixture instead',
        )


class FrontPageEntryPointTests(unittest.TestCase):
    """07-02 Task 2: `/` with the toggle off serves a document that never
    carried the advanced-diagnosis entry point in its bytes; with the
    toggle on it serves `dashboard/index.html` verbatim and the transform
    is never invoked at all.

    Disabled-side members build through
    `load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})` and enabled-side
    members through `load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '1'})` --
    explicit on both sides, per the module rule, because `load_app` leaves
    `extra_env` in `os.environ` for the rest of the process and an implicit
    enabled build here would compare the transformed document against
    `index.html` rather than the raw file.
    """

    def test_the_markup_invariant_dashboard_index_html_has_exactly_one_entry_point(self):
        """TRIPWIRE, not evidence: this converts a future edit to
        dashboard/index.html's anchor markup into a failing test here
        rather than a failing deployment. The behavioural evidence that the
        feature actually works is the served body below and Task 3's
        rendered page -- never this inspection."""
        document = (DASHBOARD_DIR / 'index.html').read_text(encoding='utf-8')
        matches = beacon_frontpage._ENTRY_POINT_PATTERN.findall(document)
        self.assertEqual(
            len(matches), 1,
            "TRIPWIRE (not behavioural evidence): dashboard/index.html's "
            "advanced-diagnosis anchor markup moved away from the shape "
            'without_advanced_entry_point depends on -- update '
            'dashboard/beacon/frontpage.py to match the new markup.',
        )

    def test_disabled_body_omits_the_entry_point_and_keeps_the_rest_of_the_page(self):
        """Both halves matter: the first three assertions are criterion 2
        (absent, not hidden); the last two are that the transform excised
        only what it was aimed at."""
        appmod, db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})
        try:
            client = appmod.app.test_client()
            response = client.get('/')
            body = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('id="advanced-diagnosis-link"', body)
            self.assertNotIn('href="/advanced"', body)
            self.assertNotIn('Advanced diagnosis', body)
            self.assertIn('id="services-grid"', body)
            self.assertIn('id="toggle"', body)
        finally:
            cleanup_db(db_path)

    def test_enabled_body_is_byte_identical_to_index_html_and_the_transform_is_unreached(self):
        """The explicit '1' matters here specifically: an earlier class in
        this module has already written '0' into `os.environ`
        (tests/helpers.py:51-65)."""
        appmod, db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '1'})
        try:
            client = appmod.app.test_client()
            with mock.patch.object(
                beacon_frontpage, 'without_advanced_entry_point',
                side_effect=AssertionError('the transform must not be invoked on the enabled path'),
            ):
                response = client.get('/')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, (DASHBOARD_DIR / 'index.html').read_bytes())
        finally:
            cleanup_db(db_path)

    def test_the_transform_runs_at_most_once_per_process_across_five_disabled_requests(self):
        appmod, db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})
        appmod._index_document_without_advanced_entry_point_cache = None

        def _cleanup():
            appmod._index_document_without_advanced_entry_point_cache = None
            cleanup_db(db_path)

        self.addCleanup(_cleanup)

        client = appmod.app.test_client()
        real_transform = beacon_frontpage.without_advanced_entry_point
        calls = []

        def _counting(document):
            calls.append(1)
            return real_transform(document)

        with mock.patch.object(beacon_frontpage, 'without_advanced_entry_point', _counting):
            for _ in range(5):
                response = client.get('/')
                self.assertEqual(response.status_code, 200)

        self.assertEqual(
            len(calls), 1,
            f'expected exactly 1 transform invocation across 5 disabled GET / '
            f'requests, observed {len(calls)}',
        )

    def test_a_transform_failure_propagates_out_of_the_route_rather_than_serving_a_page(self):
        """Pinning zero-match and duplicate-match raises on the pure
        function (dashboard/beacon/frontpage.py) proves the *function*
        refuses; this proves the *server* refuses, which is the property a
        mismatched deployment actually depends on. The document cache is
        reset first so the patched function is genuinely reached rather
        than short-circuited by a value an earlier test already computed."""
        appmod, db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})
        appmod._index_document_without_advanced_entry_point_cache = None

        def _cleanup():
            appmod._index_document_without_advanced_entry_point_cache = None
            cleanup_db(db_path)

        self.addCleanup(_cleanup)

        client = appmod.app.test_client()

        def _raising(document):
            raise beacon_frontpage.AdvancedEntryPointNotFound('mutated for this test: forced raise')

        with mock.patch.object(beacon_frontpage, 'without_advanced_entry_point', _raising):
            response = client.get('/')

        body = response.get_data(as_text=True)
        self.assertFalse(
            response.status_code == 200 and 'advanced-diagnosis-link' in body,
            f'a transform failure must never be served as a 200 page carrying the '
            f'entry point -- observed status {response.status_code}',
        )


class FrontPageBootWithoutAdvancedTests(unittest.TestCase):
    """07-02 Task 3: the services front page still works with its advanced
    link gone -- proven in real Chromium, not by a source assertion about a
    null check.

    Assertion hierarchy, stated honestly rather than blurred: the populated
    services grid is the load-bearing evidence, because populating it
    requires `DOMContentLoaded` to have run past `dashboard/app.js` line
    772's lookup and reached the `Promise.allSettled` fetch fifteen
    statements below it -- this is the only assertion here that can
    actually fail if the T-07-07 defect is present. The empty collected
    `pageerror` list is genuine but indirect corroboration: a swallowed
    error would not appear in it. The theme toggle is exercised as a
    CONTROL, never as evidence -- it is registered one line above the
    breaking line-772 lookup, so it would keep responding even with boot
    broken below it; a passing toggle proves the page is alive, never that
    boot completed.

    Built through `load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})`, per the
    module rule, on the same `make_server` plus `sync_playwright` class
    fixture idiom `tests/test_advanced_ui.py::AdvancedUiTests` uses.
    """

    @classmethod
    def setUpClass(cls):
        cls.appmod, cls.db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})
        # A real seeded row so the services grid has something real to
        # render -- the assertion below is about the boot sequence
        # completing, not about an empty state.
        _SeedingHelpers.seed_service(
            cls.appmod, 20101, online=1, state_since=int(time.time()) - 900,
        )
        cls.server = make_server('127.0.0.1', 0, cls.appmod.app, threaded=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(
            executable_path=cls.playwright.chromium.executable_path,
        )
        cls.base_url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cleanup_db(cls.db_path)

    def _boot(self, *, theme, seed_scroll):
        """Navigate a fresh page, seeding theme and (optionally) a digit
        `sessionStorage[DASHBOARD_SCROLL_KEY]` before the document loads --
        the literal key ('beacon-dashboard-scroll-position', read from
        dashboard/app.js line 7 at implementation time; the two must stay
        in step) is written directly because the init script runs before
        app.js defines the DASHBOARD_SCROLL_KEY binding. Returns
        (page, collected pageerror texts)."""
        page = self.browser.new_page(viewport={'width': 1280, 'height': 900})
        errors = []
        page.on('pageerror', lambda exc: errors.append(str(exc)))
        if theme == 'light':
            page.add_init_script("localStorage.setItem('beacon-theme', 'light');")
        if seed_scroll:
            page.add_init_script(
                "sessionStorage.setItem('beacon-dashboard-scroll-position', '0');"
            )
        page.goto(self.base_url, wait_until='domcontentloaded')
        # The focus call (site 762) runs two animation frames after
        # restore; wait on something that necessarily follows both it and
        # the initial Promise.allSettled fetch (the populated services
        # grid), rather than asserting immediately on load.
        try:
            page.locator('.svc-title-link').first.wait_for(timeout=5_000)
        except PlaywrightTimeoutError:
            pass
        return page, errors

    def test_ordinary_load_boots_and_renders_seeded_services_with_no_page_error(self):
        for theme in ('dark', 'light'):
            with self.subTest(theme=theme):
                page, errors = self._boot(theme=theme, seed_scroll=False)
                try:
                    grid_html = page.locator('#services-grid').inner_html()
                    self.assertGreater(
                        page.locator('.svc-title-link').count(), 0,
                        f'services grid never rendered the seeded service -- boot did not '
                        f'reach Promise.allSettled; observed grid html: {grid_html!r}; '
                        f'collected pageerror(s): {errors}',
                    )
                    self.assertEqual(errors, [], f'unexpected page error(s): {errors}')

                    # CONTROL, not evidence -- registered above the break
                    # and would pass even with the defect present.
                    was_light = page.locator('html').evaluate(
                        '(node) => node.classList.contains("light")'
                    )
                    page.locator('#toggle').click()
                    page.wait_for_timeout(50)
                    is_light = page.locator('html').evaluate(
                        '(node) => node.classList.contains("light")'
                    )
                    self.assertNotEqual(is_light, was_light)

                    self.assertEqual(page.locator('#advanced-diagnosis-link').count(), 0)
                finally:
                    page.close()

    def test_seeded_scroll_position_reaches_restore_dashboard_scrolls_focus_call_with_no_page_error(self):
        """The only condition that reaches site 762: `restoreDashboardScroll`
        returns early unless `sessionStorage[DASHBOARD_SCROLL_KEY]` holds a
        digit string, and a freshly navigated page never has that key."""
        for theme in ('dark', 'light'):
            with self.subTest(theme=theme):
                page, errors = self._boot(theme=theme, seed_scroll=True)
                try:
                    grid_html = page.locator('#services-grid').inner_html()
                    self.assertGreater(
                        page.locator('.svc-title-link').count(), 0,
                        f'services grid never rendered the seeded service with a seeded '
                        f'scroll position -- observed grid html: {grid_html!r}; collected '
                        f'pageerror(s): {errors}',
                    )
                    self.assertEqual(errors, [], f'unexpected page error(s): {errors}')
                finally:
                    page.close()


class SettingsAdvancedDiagnosticsTests(unittest.TestCase):
    """Task 2: the parse vocabulary at the settings layer, driven through
    `load_settings` with an explicit mapping -- never through `load_app`.

    `test_an_unset_value_defaults_to_enabled` is the ONLY place in this
    phase's test suite that establishes criterion 1's unset default. It
    calls `load_settings({})` directly, reading the literal default in the
    parser rather than an environment any earlier `load_app` call may have
    polluted (tests/helpers.py:51-65). No `load_app` call anywhere in this
    phase may be cited as evidence for the default.
    """

    def test_an_unset_value_defaults_to_enabled(self):
        self.assertTrue(load_settings({}).enable_advanced_diagnostics)

    def test_the_enabled_vocabulary_matches_the_existing_enabled_helper(self):
        """`_enabled`'s existing vocabulary (dashboard/beacon/config.py:119),
        inherited rather than reinvented."""
        for value in ('0', 'false', 'no', 'off', ''):
            with self.subTest(value=value):
                self.assertFalse(
                    load_settings({'ENABLE_ADVANCED_DIAGNOSTICS': value}).enable_advanced_diagnostics,
                )
        for value in ('1', 'true', 'yes', 'on'):
            with self.subTest(value=value):
                self.assertTrue(
                    load_settings({'ENABLE_ADVANCED_DIAGNOSTICS': value}).enable_advanced_diagnostics,
                )

    def test_an_out_of_vocabulary_value_is_treated_as_disabled(self):
        """The one place a default-on toggle behaves differently from the
        two default-off toggles sharing `_enabled`: a typo degrades to
        disabled rather than to the default. Recorded in 07-DECISIONS.md
        by 07-03."""
        settings = load_settings({'ENABLE_ADVANCED_DIAGNOSTICS': 'enabled'})
        self.assertFalse(settings.enable_advanced_diagnostics)


class FrontPageCostEqualityTests(_FrozenClockTestCase):
    """07-03 Task 1: the property under test is "the toggle changed nothing
    about the front page's cost" -- what gives criterion 3 real content that
    07-01's zero-work assertion on `/` alone does not have, because `/` is a
    static `send_file` performing no diagnosis work today even with
    advanced diagnostics fully enabled. The measurement here is an equality
    between two measured statement counts over the front page's whole boot
    request set, never a threshold against either total (D-DEBT-06-14's
    lesson: an absolute figure ties a guard to the seeded dataset and the
    executing machine).

    BOOT_PATHS is derived from dashboard/app.js's own `DOMContentLoaded`
    handler (line 795's `Promise.allSettled([loadStats(), loadHistory(),
    loadScan(), loadServices(), loadEvents()])` at the time this was
    written) plus `/` itself -- the exact six requests the front page's own
    boot sequence issues, read from that line rather than from memory.

    THE EXPLICIT '1' IS THE ENTIRE INTEGRITY OF THIS TEST. Built without it,
    the enabled side would inherit the '0' `DisabledAdvancedApiTests` (and
    this class's own disabled build) leaves in `os.environ`
    (`load_app`/`_load_app_over_existing_db` never clear it --
    tests/helpers.py:51-65); both sides would then run disabled, their
    statement totals would agree by construction, and criterion 3 would be
    reported satisfied by a comparison of two identical disabled runs -- the
    same defect class Phase 6 found six times. `setUp` reads
    `enable_advanced_diagnostics` off each application's own `SETTINGS`
    IMMEDIATELY after building it.

    A SECOND, load-bearing hazard beyond the module rule: `dashboard.app` is
    a SINGLETON module. `importlib.reload` (inside `load_app` and
    `_load_app_over_existing_db`) mutates that ONE module object's
    namespace IN PLACE and returns the SAME object -- it does not hand back
    an independent copy. `ENABLE_ADVANCED_DIAGNOSTICS`/`SETTINGS` are plain
    globals snapshotted at reload time, read live via each route function's
    `__globals__` at call time, not frozen per Flask `app` instance. Building
    the enabled side therefore rebinds those globals for the ALREADY-BUILT
    disabled side too -- a request dispatched through the disabled side's
    OWN test client, issued AFTER the enabled side's reload, would silently
    run enabled. The only correct ordering is sequential: build disabled,
    read its `SETTINGS` value, issue its ENTIRE boot request set to
    completion -- THEN reload to enabled, read ITS `SETTINGS` value (this is
    where the settings pair is asserted, immediately upon the second build
    and before the enabled side's own requests), and only then issue the
    enabled boot request set.
    """

    BOOT_PATHS = (
        '/',
        '/api/stats',
        '/api/history',
        '/api/scan-status',
        '/api/services',
        '/api/events?limit=50',
    )

    def setUp(self):
        super().setUp()
        appmod, self.db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})
        self._freeze_clock(_GOLDEN_FROZEN_NOW)
        _SeedingHelpers.seed_three_service_dataset(appmod, _GOLDEN_FROZEN_NOW)

        off_enabled = appmod.SETTINGS.enable_advanced_diagnostics
        off_client = appmod.app.test_client()
        with _counting_connections() as self.off_counter:
            self.off_statuses = {path: off_client.get(path).status_code for path in self.BOOT_PATHS}

        # Reopen the SAME database, explicitly enabled -- see class
        # docstring's singleton-module hazard for why the off side's own
        # boot-request measurement above MUST run to completion before this
        # reload: dashboard.app.SETTINGS is one module global rebound by
        # every reload, shared by every previously-built Flask `app` object
        # too, so a disabled-side request issued after this call would
        # silently observe the enabled value.
        appmod = _load_app_over_existing_db({'ENABLE_ADVANCED_DIAGNOSTICS': '1'}, self.db_path)
        on_enabled = appmod.SETTINGS.enable_advanced_diagnostics

        self.settings_pair = (off_enabled, on_enabled)
        self.assertEqual(
            self.settings_pair, (False, True),
            f'expected (False, True) read off the two applications immediately as each was '
            f'built, observed {self.settings_pair} -- load_app/_load_app_over_existing_db '
            f'leak extra_env into os.environ and never clear it (tests/helpers.py:51-65); an '
            f'implicit enabled build after a disabled one in the same process would silently '
            f'run disabled too, and the cost equality below would then be satisfied by '
            f'comparing two identical disabled runs -- the vacuous pass this test exists to '
            f'refuse.',
        )

        on_client = appmod.app.test_client()
        with _counting_connections() as self.on_counter:
            self.on_statuses = {path: on_client.get(path).status_code for path in self.BOOT_PATHS}

    def tearDown(self):
        cleanup_db(self.db_path)
        super().tearDown()

    def test_the_settings_pair_is_false_true_read_immediately_upon_each_build(self):
        """The setUp assertion above IS this criterion; a dedicated test
        method makes the pair itself, not only its consequence, a named and
        independently reportable assertion."""
        self.assertEqual(self.settings_pair, (False, True))

    def test_per_path_status_codes_agree_between_the_two_sides(self):
        """A separate test from the statement-count equality below, so an
        early failure on one side (e.g. a 500) cannot masquerade as
        agreement by coincidentally producing equal totals."""
        for path in self.BOOT_PATHS:
            with self.subTest(path=path):
                self.assertEqual(
                    self.off_statuses[path], self.on_statuses[path],
                    f'{path} answered {self.off_statuses[path]} disabled vs '
                    f'{self.on_statuses[path]} enabled',
                )

    def test_front_page_boot_costs_the_same_measured_statements_and_connections_off_and_on(self):
        """The equality: a full front-page boot request set executes the
        same total SQLite statement count and the same total connection
        count with the toggle off as with it on, measured on the same
        seeded dataset. This is what gives criterion 3 independent force
        beyond 07-01's zero-work assertion on `/` alone."""
        self.assertEqual(
            self.off_counter.statements, self.on_counter.statements,
            f'front-page boot set executed {self.off_counter.statements} SQLite statement(s) '
            f'disabled vs {self.on_counter.statements} enabled -- the toggle-delivery '
            f'mechanism cost the front page something',
        )
        self.assertEqual(
            self.off_counter.connections, self.on_counter.connections,
            f'front-page boot set opened {self.off_counter.connections} connection(s) '
            f'disabled vs {self.on_counter.connections} enabled',
        )


class ToggleReversibilityTests(_FrozenClockTestCase):
    """07-03 Task 1: criterion 5 as a round trip, not an assertion --
    exercise a disabled deployment against a seeded database, confirm the
    database's logical content and applied schema version are unchanged,
    then reopen the SAME database file with the toggle back on and recover
    07-01's captured golden.

    Uses `_iterdump_sha256` (logical content), never file bytes, as the
    oracle -- see that function's docstring for why a file-bytes comparison
    would be a guard that fails for reasons unrelated to stored data.
    """

    def test_a_disabled_session_leaves_the_database_unchanged_and_restart_recovers_the_golden(self):
        appmod, db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '0'})
        self._freeze_clock(_GOLDEN_FROZEN_NOW)
        _SeedingHelpers.seed_three_service_dataset(appmod, _GOLDEN_FROZEN_NOW)

        before_dump = _iterdump_sha256(db_path)
        before_version = beacon_migrations._recorded_version(db_path)

        client = appmod.app.test_client()
        for path in FrontPageCostEqualityTests.BOOT_PATHS:
            client.get(path)
        for path in ('/advanced', '/advanced.css', '/advanced.js', '/api/advanced/current'):
            response = client.get(path)
            self.assertEqual(response.status_code, 404, f'{path} answered {response.status_code}, expected 404')

        after_dump = _iterdump_sha256(db_path)
        after_version = beacon_migrations._recorded_version(db_path)

        self.assertEqual(
            before_dump, after_dump,
            f"disabled session's database content moved -- before {before_dump}, "
            f'after {after_dump}',
        )
        self.assertEqual(
            before_version, after_version,
            f'applied schema version moved from {before_version} to {after_version} across a '
            f'disabled session',
        )

        # Reopen the SAME database file, explicitly enabled -- this call
        # follows a disabled build in the same process and an implicit one
        # would reopen disabled (tests/helpers.py:51-65). Pinned at
        # _DEFAULT_SETTINGS_PAYLOAD_ENV's literal defaults so no earlier
        # class's own load_app leak can move the golden comparison, exactly
        # like EnabledResponseGoldenTests.setUp.
        try:
            on_appmod = _load_app_over_existing_db(dict(_DEFAULT_SETTINGS_PAYLOAD_ENV), db_path)
            on_client = on_appmod.app.test_client()
            golden = json.loads(GOLDEN_PATH.read_text(encoding='utf-8'))
            response = on_client.get('/api/advanced/current')
            referent = f"the golden captured at {golden['captured_at_commit']}"
            self.assertEqual(
                response.status_code, golden['status_code'],
                f'reopened, toggle-on status moved from {referent}',
            )
            self.assertEqual(
                response.content_type, golden['content_type'],
                f'reopened, toggle-on content type moved from {referent}',
            )
            self.assertEqual(
                response.headers.get('Cache-Control'), golden['cache_control'],
                f'reopened, toggle-on Cache-Control moved from {referent}',
            )
            self.assertEqual(
                response.get_data(as_text=True), golden['body'],
                f'reopened, toggle-on body moved from {referent}',
            )
        finally:
            cleanup_db(db_path)


class AcceptanceConfigurationGuardTests(unittest.TestCase):
    """07-03 Task 2: `PROH-DIA-09-01`'s automated guard -- the value
    docker-compose.yml supplies for `ENABLE_ADVANCED_DIAGNOSTICS`, resolved
    for the case where the operator sets no shell variable, produces a
    `Settings` whose `enable_advanced_diagnostics` is True when fed to the
    real `load_settings`.

    Scans the `environment: &beacon-environment` anchor with this module's
    OWN scan (`_scan_beacon_environment_anchor`), not
    `tests/pi_load_acceptance.py`'s `parse_compose_memory_limits` -- see
    that helper's module-level comment for why reusing its logic here would
    scan zero lines. Assertion runs through the real parser, never a text
    comparison, so it tests the consequence the deployment actually gets.
    """

    def setUp(self):
        super().setUp()
        self.occurrences = _enable_advanced_diagnostics_compose_entries(COMPOSE_PATH)
        # Unable to pass on an empty (or ambiguous) result: this is
        # PROH-DIA-09-01's only automated guard, and a scan that silently
        # finds nothing must never report a pass over nothing.
        self.assertEqual(
            len(self.occurrences), 1,
            f'expected exactly one ENABLE_ADVANCED_DIAGNOSTICS entry in {COMPOSE_PATH}, '
            f'observed {len(self.occurrences)}: {self.occurrences!r}',
        )

    def test_the_scan_finds_exactly_one_entry_before_any_value_is_interpreted(self):
        """The setUp assertion above IS this criterion; a dedicated test
        method makes the count itself a named and independently reportable
        assertion, not only a precondition of the test below."""
        self.assertEqual(len(self.occurrences), 1)

    def test_the_shipped_default_resolves_to_enabled_through_the_real_parser(self):
        default_value = _resolve_unset_default(self.occurrences[0])
        settings = load_settings({'ENABLE_ADVANCED_DIAGNOSTICS': default_value})
        self.assertTrue(
            settings.enable_advanced_diagnostics,
            f"PROH-DIA-09-01: docker-compose.yml's shipped default for "
            f'ENABLE_ADVANCED_DIAGNOSTICS resolved to {default_value!r}, which load_settings '
            f'parses as disabled -- every OPS-07 acceptance run measures the fully-enabled '
            f'configuration; flipping the shipped default is the specific act PROH-DIA-09-01 '
            f'forbids.',
        )


if __name__ == '__main__':
    unittest.main()
