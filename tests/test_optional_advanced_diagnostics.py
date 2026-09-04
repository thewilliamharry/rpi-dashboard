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

import hashlib
import json
import os
import subprocess
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from dashboard.beacon import repositories
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

    appmod, db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '1'})
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
        # to protect.
        self.appmod, self.db_path = load_app({'ENABLE_ADVANCED_DIAGNOSTICS': '1'})
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


if __name__ == '__main__':
    unittest.main()
