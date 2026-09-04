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
import json
import os
import subprocess
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import dashboard.app as _appmod_ref
import dashboard.beacon.db as _beacon_db_ref
from dashboard.beacon import frontpage as beacon_frontpage
from dashboard.beacon import repositories
from dashboard.beacon.config import load_settings
from tests.helpers import cleanup_db, load_app


def _epoch(year, month, day, hour, minute, second=0):
    return int(datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).timestamp())


FIXTURES_DIR = Path(__file__).resolve().parent / 'fixtures'
GOLDEN_PATH = FIXTURES_DIR / '07_advanced_current_enabled_response_golden.json'
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / 'dashboard'
STATIC_ASSET_NAMES = ('index.html', 'advanced.html', 'advanced.css', 'advanced.js')

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


if __name__ == '__main__':
    unittest.main()
