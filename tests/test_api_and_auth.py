import inspect
import json
import os
import time
import unittest
from contextlib import contextmanager

from dashboard.beacon.db import exclusive_database_maintenance
from tests.helpers import cleanup_db, load_app


class FakeResponse:
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def _install_connection_spy(appmod, real_database_access):
    """Wrap ``real_database_access`` with a spy and patch it onto ``appmod``.

    Every connection the seam hands out is appended to the returned list.
    The list holding a strong reference to each connection is what makes the
    release assertions deterministic rather than dependent on garbage
    collection -- a leaked lease is guaranteed to still be held (or a
    released one guaranteed to still show released) when the assertion runs.
    """
    captured = []

    @contextmanager
    def spying_database_access(settings_or_path):
        with real_database_access(settings_or_path) as conn:
            captured.append(conn)
            yield conn

    appmod.database_access = spying_database_access
    return captured


class ApiAndAuthTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app({
            'TRIGGER_SCAN_RATE_LIMIT': '1',
            'TRIGGER_SCAN_WINDOW_SECONDS': '60',
        })
        self.client = self.appmod.app.test_client()
        self.ui_headers = {'X-Beacon-UI': '1'}

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_service(self, port=8080, url='http://127.0.0.1:8080'):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
                (port, 'Demo Service', now - 120, now, 1, 45.2, None),
            )
            conn.execute(
                "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
                (port, 'Friendly Demo', url, 1, 1, 'core,prod'),
            )
            conn.execute(
                "INSERT INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)",
                (now - 10, port, 1, 45.2, None),
            )
            conn.commit()
            conn.close()

    def _worker_owner(self, worker_id='api-preview-worker'):
        return self.appmod.beacon_queues.acquire_worker_lease(self.db_path, worker_id)

    def _drop_planned_maintenance_schema(self):
        """Undo migration 9's additions so the database matches the Pi's schema version 8.

        Reproduces G-03.1-2: the phase-03.1 bulk maintenance-window read
        (``read_maintenance_windows_by_port``, used by ``/api/services``) and the
        ``/api/events`` selection of ``suppressed_reason``/``maintenance_grace_until``/
        ``down_since_ts`` both raise against this shape, the way they did on the Pi.
        """
        conn = self.appmod.get_db()
        try:
            conn.execute('DROP TABLE maintenance_windows')
            conn.execute('ALTER TABLE events DROP COLUMN suppressed_reason')
            conn.execute('ALTER TABLE events DROP COLUMN maintenance_grace_until')
            conn.execute('ALTER TABLE events DROP COLUMN down_since_ts')
            conn.commit()
        finally:
            conn.close()

    def test_a_failing_request_releases_its_shared_maintenance_lease(self):
        self._insert_service()
        self._drop_planned_maintenance_schema()
        real_database_access = self.appmod.database_access

        for route_name, path in (('services', '/api/services'), ('events', '/api/events')):
            with self.subTest(route=route_name):
                captured = _install_connection_spy(self.appmod, real_database_access)

                response = self.client.get(path)

                # 1. A request that fails against an unmigrated schema is a loud
                #    server error, never a silent success.
                self.assertEqual(response.status_code, 500)
                # A test that silently opened no connection would pass the
                # remaining assertions vacuously -- forbid that.
                self.assertTrue(captured, f'the spy recorded no connections for {path}')
                # 2. Every connection the spy recorded has released its shared
                #    maintenance lease.
                for conn in captured:
                    self.assertIsNone(
                        getattr(conn, '_maintenance_handle', 'MISSING'),
                        f'a connection opened while serving {path} still holds its maintenance lease',
                    )
                # 3. The migrator's own exclusive acquisition -- the thing that
                #    was starved on the Pi -- is immediately available.
                with exclusive_database_maintenance(self.db_path, timeout_seconds=0):
                    pass

    def test_a_handler_that_raises_for_any_reason_releases_its_lease(self):
        self._insert_service()
        real_database_access = self.appmod.database_access
        captured = _install_connection_spy(self.appmod, real_database_access)

        original = self.appmod.beacon_repositories.read_maintenance_windows_by_port

        def _raise_unrelated_error(*_args, **_kwargs):
            raise RuntimeError('unrelated handler failure')

        self.appmod.beacon_repositories.read_maintenance_windows_by_port = _raise_unrelated_error
        try:
            response = self.client.get('/api/services')
        finally:
            self.appmod.beacon_repositories.read_maintenance_windows_by_port = original

        # Same three assertions as above: this proves the release belongs to
        # the exit path itself, not to one missing table.
        self.assertEqual(response.status_code, 500)
        self.assertTrue(captured, 'the spy recorded no connections')
        for conn in captured:
            self.assertIsNone(getattr(conn, '_maintenance_handle', 'MISSING'))
        with exclusive_database_maintenance(self.db_path, timeout_seconds=0):
            pass

    def test_trigger_scan_requires_ui_header_and_queues(self):
        self.assertEqual(self.client.post('/api/trigger-scan').status_code, 403)
        r = self.client.post('/api/trigger-scan', headers=self.ui_headers)
        self.assertEqual(r.status_code, 202)
        self.assertTrue(r.get_json()['queued'])

    def test_trigger_scan_rate_limit(self):
        r1 = self.client.post('/api/trigger-scan', headers=self.ui_headers)
        self.assertEqual(r1.status_code, 202)
        self.assertTrue(r1.get_json()['queued'])

        r2 = self.client.post('/api/trigger-scan', headers=self.ui_headers)
        self.assertEqual(r2.status_code, 429)
        self.assertEqual(r2.get_json()['reason'], 'rate_limited')

    def test_services_and_events_contract_fields(self):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
                (8080, 'Demo Service', now - 120, now, 1, 45.2, None),
            )
            conn.execute(
                "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
                (8080, 'Friendly Demo', 'http://127.0.0.1:8080', 1, 1, 'core,prod'),
            )
            conn.execute(
                "INSERT INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)",
                (now - 10, 8080, 1, 45.2, None),
            )
            conn.execute(
                "INSERT INTO events (ts, port, event_type, online, previous_online, details) VALUES (?,?,?,?,?,?)",
                (now, 8080, 'state_change', 1, 0, 'service recovered'),
            )
            conn.commit()
            conn.close()

        services_resp = self.client.get('/api/services')
        self.assertEqual(services_resp.status_code, 200)
        services = services_resp.get_json()
        self.assertEqual(len(services), 1)
        svc = services[0]

        for key in ['latency_ms', 'last_error', 'critical', 'display_name', 'url', 'path', 'uptime_buckets', 'uptime_pct']:
            self.assertIn(key, svc)
        self.assertIsInstance(svc['uptime_buckets'], list)
        self.assertEqual(svc['display_name'], 'Friendly Demo')
        self.assertTrue(svc['critical'])
        self.assertEqual(svc['path'], '/')

        events_resp = self.client.get('/api/events?limit=5')
        self.assertEqual(events_resp.status_code, 200)
        events = events_resp.get_json()
        self.assertGreaterEqual(len(events), 1)
        evt = events[0]
        for key in ['event_type', 'ts', 'service_name', 'details']:
            self.assertIn(key, evt)

    def test_browser_route_and_response_compatibility_matrix(self):
        self._insert_service()
        self.appmod.collect_system_stats()
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "UPDATE services SET thumb_ts=?, thumb_source='screenshot' WHERE port=8080",
                (now,),
            )
            conn.execute(
                "INSERT INTO thumbnails(port, data, mime, captured_ts, source, expires_ts) "
                "VALUES(8080, ?, ?, ?, 'screenshot', ?)",
                (b'compatibility-thumbnail', 'image/png', now, now + 86400),
            )
            conn.execute(
                "INSERT INTO events(ts,port,event_type,online,previous_online,details) VALUES(?,?,?,?,?,?)",
                (now, 8080, 'state_change', 1, 0, 'compatibility transition'),
            )
            conn.commit()
            conn.close()

        for path, content_type in [
            ('/', 'text/html'),
            ('/style.css', 'text/css'),
            ('/app.js', 'javascript'),
        ]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(content_type, response.content_type)

        config = self.client.get('/api/config').get_json()
        # 04-01/D-05: timezone is the new additive field exposing SETTINGS.timezone
        # to the browser so History can render every timestamp in the Pi's own
        # configured local time instead of the browser's.
        self.assertEqual(set(config), {
            'alerting_enabled', 'uptime_buckets', 'trigger_rate_limit', 'trigger_rate_window_seconds',
            'timezone',
        })
        stats = self.client.get('/api/stats')
        self.assertEqual(stats.status_code, 200)
        for key in ['sample_ts', 'cpu', 'ram', 'ram_used', 'ram_total', 'disk', 'disk_used', 'disk_total', 'temp', 'hostname']:
            self.assertIn(key, stats.get_json())
        history = self.client.get('/api/history').get_json()
        self.assertTrue(history)
        self.assertEqual(set(history[-1]), {'ts', 'cpu', 'ram', 'disk', 'temp'})

        service = self.client.get('/api/services').get_json()[0]
        for key in ['port', 'title', 'display_name', 'is_online', 'has_thumb', 'url', 'path', 'tags', 'uptime_pct', 'uptime_buckets']:
            self.assertIn(key, service)
        event = self.client.get('/api/events?limit=1').get_json()[0]
        for key in ['id', 'ts', 'port', 'event_type', 'online', 'previous_online', 'details', 'service_name']:
            self.assertIn(key, event)
        metadata = self.client.get('/api/service-meta/8080')
        self.assertEqual(metadata.status_code, 200)
        self.assertEqual(metadata.get_json()['display_name'], 'Friendly Demo')
        thumbnail = self.client.get('/api/thumbnail/8080')
        self.assertEqual(thumbnail.status_code, 200)
        self.assertEqual(thumbnail.data, b'compatibility-thumbnail')
        thumbnail_status = self.client.get('/api/thumbnail-status').get_json()[0]
        for key in ['port', 'url', 'thumb_source', 'thumb_ts', 'thumb_attempt_ts', 'thumb_error']:
            self.assertIn(key, thumbnail_status)
        scan_status = self.client.get('/api/scan-status').get_json()
        for key in ['stage', 'scanning', 'worker_ready', 'worker_stale', 'worker_heartbeat_ts', 'worker_heartbeat_age_seconds', 'recovery_required', 'queued_requests', 'found']:
            self.assertIn(key, scan_status)
        self.assertEqual(self.client.get('/healthz').status_code, 200)
        self.assertEqual(self.client.get('/readyz').status_code, 503)

    def test_only_screenshot_thumbnails_are_served_and_reported(self):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = [
                (8080, 'Fallback Thumb', b'fallback-bytes', 'image/png', now, 'fallback', now, 'old fallback'),
                (8081, 'Legacy Thumb', b'legacy-bytes', 'image/png', now, None, now, None),
                (8082, 'Screenshot Thumb', b'screenshot-bytes', 'image/png', now, 'screenshot', now, None),
            ]
            for port, title, data, mime, thumb_ts, source, attempt_ts, error in rows:
                conn.execute(
                    "INSERT INTO services (port, title, first_seen, last_seen, is_online, thumb_ts, thumb_source, thumb_attempt_ts, thumb_error) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (port, title, now - 120, now, 1, thumb_ts, source, attempt_ts, error),
                )
                conn.execute(
                    "INSERT INTO thumbnails(port, data, mime, captured_ts, source, expires_ts) "
                    "VALUES (?,?,?,?,?,?)",
                    (port, data, mime, thumb_ts, source, now + 86400),
                )
                conn.execute(
                    "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
                    (port, title, f'http://127.0.0.1:{port}', 0, port, ''),
                )
            conn.commit()
            conn.close()

        services = {svc['port']: svc for svc in self.client.get('/api/services').get_json()}
        self.assertFalse(services[8080]['has_thumb'])
        self.assertFalse(services[8081]['has_thumb'])
        self.assertTrue(services[8082]['has_thumb'])

        self.assertEqual(self.client.get('/api/thumbnail/8080').status_code, 404)
        self.assertEqual(self.client.get('/api/thumbnail/8081').status_code, 404)
        screenshot = self.client.get('/api/thumbnail/8082')
        self.assertEqual(screenshot.status_code, 200)
        self.assertEqual(screenshot.data, b'screenshot-bytes')

        status = {row['port']: row for row in self.client.get('/api/thumbnail-status').get_json()}
        self.assertEqual(status[8080]['thumb_source'], 'fallback')
        self.assertEqual(status[8080]['thumb_error'], 'old fallback')
        self.assertEqual(status[8082]['thumb_source'], 'screenshot')

    def test_thumb_state_precedence_across_the_four_has_thumb_and_preview_status_combinations(self):
        """WR-02: has_thumb and preview_status are independent facts -- the
        stored thumbnail's TTL deliberately outlives several missed refresh
        cycles, so a service can have a currently-servable image while its
        latest preview request is degraded. thumb_state must describe what
        the thumbnail route would actually serve, and the degraded signal
        must survive for services with no servable thumbnail (PROH-OPS-02-05)."""
        now = int(time.time())
        # Port 8091: a servable thumbnail exists AND the latest preview
        # request is degraded -- must report 'ok', not 'degraded'.
        # Port 8092: no servable thumbnail, latest preview request degraded
        #   -- must still report 'degraded'.
        # Port 8093: no servable thumbnail, latest preview request queued
        #   -- must report 'pending'.
        # Port 8094: no servable thumbnail, no preview request at all
        #   -- must report 'empty'.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for port in (8091, 8092, 8093, 8094):
                conn.execute(
                    "INSERT INTO services (port, title, first_seen, last_seen, is_online) "
                    "VALUES (?,?,?,?,?)",
                    (port, f'Service {port}', now - 120, now, 1),
                )
            conn.execute(
                "INSERT INTO thumbnails(port, data, mime, captured_ts, source, expires_ts) "
                "VALUES (8091, ?, ?, ?, 'screenshot', ?)",
                (b'still-good-bytes', 'image/png', now - 3600, now + 86400),
            )
            for port, status in ((8091, 'degraded'), (8092, 'degraded'), (8093, 'queued')):
                conn.execute(
                    "INSERT INTO preview_requests(port, requested_ts, deadline_ts, status, revision) "
                    "VALUES (?,?,?,?,1)",
                    (port, now - 60, now + 1800, status),
                )
            conn.commit()
            conn.close()

        status = {row['port']: row for row in self.client.get('/api/thumbnail-status').get_json()}
        self.assertEqual(status[8091]['thumb_state'], 'ok')
        self.assertEqual(status[8092]['thumb_state'], self.appmod.beacon_queues.PREVIEW_STATUS_DEGRADED)
        self.assertEqual(status[8093]['thumb_state'], 'pending')
        self.assertEqual(status[8094]['thumb_state'], 'empty')

    def test_scan_status_never_reports_degraded_and_stale_together(self):
        """A-04: an overlapping WORKER_READY_SECONDS must never assert both conditions."""
        # ``load_app`` writes its env into ``os.environ`` and never restores it, so the
        # deliberately-lowered cutoff below would otherwise outlive this test and be read
        # by every later module that reloads ``dashboard.app`` -- including
        # ``test_runtime_ownership``, whose monitoring-gap expectation is derived from
        # ``WORKER_READY_SECONDS`` and silently stops exceeding the 20s gap threshold.
        for _key in ('WORKER_READY_SECONDS', 'METRIC_SAMPLE_SECONDS'):
            _previous = os.environ.get(_key)
            if _previous is None:
                self.addCleanup(os.environ.pop, _key, None)
            else:
                self.addCleanup(os.environ.__setitem__, _key, _previous)
        appmod, db_path = load_app({'WORKER_READY_SECONDS': '10', 'METRIC_SAMPLE_SECONDS': '5'})
        client = appmod.app.test_client()
        try:
            # Edge (zero): no heartbeat row at all.
            response = client.get('/api/scan-status').get_json()
            self.assertIn('state', response['worker_freshness'])
            self.assertEqual(response['worker_freshness']['state'], 'unknown')
            self.assertFalse(response['worker_degraded'])

            cadence = appmod.beacon_diagnosis.worker_heartbeat_cadence_seconds(appmod.SETTINGS)
            self.assertEqual(cadence, 5)
            # 4 * cadence == 20 (fixed); WORKER_READY_SECONDS == 10 overlaps the
            # window (ages 11-20) where a heartbeat is both `aging` and past the
            # operator's own readiness cutoff.
            for age in range(1, 4 * cadence + 5):
                with self.subTest(age=age):
                    request_now = int(time.time())
                    heartbeat_ts = request_now - age
                    with appmod._db_lock:
                        conn = appmod.get_db()
                        conn.execute(
                            'INSERT INTO runtime_state(key,value,updated_ts) VALUES(?,?,?) '
                            'ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts',
                            ('worker_heartbeat', json.dumps({'ts': heartbeat_ts}), heartbeat_ts),
                        )
                        conn.commit()
                        conn.close()
                    response = client.get('/api/scan-status').get_json()
                    self.assertIn('state', response['worker_freshness'])
                    self.assertFalse(response['worker_stale'] and response['worker_degraded'])
        finally:
            cleanup_db(db_path)

    def test_scan_status_never_reports_degraded_while_recovery_is_required(self):
        """05-07 Task 2 (gap 2 / WR-01): a real on-disk recovery marker beside a real
        aging-not-stale heartbeat must suppress worker_degraded in the
        /api/scan-status payload -- the operator must never see both a
        paused-monitoring and a monitoring-continues reading about the same
        worker at the same instant."""
        _previous = os.environ.get('WORKER_READY_SECONDS')
        if _previous is None:
            self.addCleanup(os.environ.pop, 'WORKER_READY_SECONDS', None)
        else:
            self.addCleanup(os.environ.__setitem__, 'WORKER_READY_SECONDS', _previous)

        # WORKER_READY_SECONDS=30 puts the readiness cutoff above the whole
        # `aging` band (4 * cadence == 20 under the fixed J1 cadence of 5),
        # so the seeded 10s age below is unambiguously `aging` and
        # unambiguously not past the cutoff. METRIC_SAMPLE_SECONDS is
        # deliberately not passed here -- it is a no-op on the J1 cadence
        # (worker_main.py:84's fixed literal ('seconds', 5)), and passing it
        # would teach a false causal model of the config surface (05-DEBT.md
        # section 2 W-6).
        appmod, db_path = load_app({'WORKER_READY_SECONDS': '30'})
        client = appmod.app.test_client()
        marker_path = None
        try:
            cadence = appmod.beacon_diagnosis.worker_heartbeat_cadence_seconds(appmod.SETTINGS)
            self.assertEqual(cadence, 5)
            now = int(time.time())
            heartbeat_ts = now - 2 * cadence
            with appmod._db_lock:
                conn = appmod.get_db()
                conn.execute(
                    'INSERT INTO runtime_state(key,value,updated_ts) VALUES(?,?,?) '
                    'ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts',
                    ('worker_heartbeat', json.dumps({'ts': heartbeat_ts}), heartbeat_ts),
                )
                conn.commit()
                conn.close()

            marker_path = os.path.join(os.path.dirname(db_path), appmod.RECOVERY_MARKER)
            with open(marker_path, 'w', encoding='utf-8') as handle:
                json.dump(
                    {
                        'failed_target_version': 7,
                        'reason_class': 'RecoveryError',
                        'backup_catalog_id': 'backup-05-07-test',
                        'timestamp': int(time.time()),
                        'restore_in_progress': True,
                    },
                    handle,
                    sort_keys=True,
                )
                handle.write('\n')

            response = client.get('/api/scan-status').get_json()
            self.assertEqual(response['worker_freshness']['state'], 'aging')
            self.assertFalse(response['worker_stale'])
            self.assertTrue(response['recovery_required'])
            self.assertFalse(response['worker_degraded'])
            self.assertFalse(response['recovery_required'] and response['worker_degraded'])
        finally:
            if marker_path is not None:
                try:
                    os.remove(marker_path)
                except FileNotFoundError:
                    pass
            cleanup_db(db_path)

    def test_service_meta_path_normalization_variants(self):
        self._insert_service()
        cases = [
            ('', '/'),
            ('/app', '/app'),
            ('app', '/app'),
            ('/app?x=1', '/app?x=1'),
            ('/app#tab', '/app#tab'),
            ('/app?x=1#tab', '/app?x=1#tab'),
        ]

        for raw, expected in cases:
            r = self.client.put(
                '/api/service-meta/8080',
                json={'path': raw},
                headers=self.ui_headers,
            )
            self.assertEqual(r.status_code, 200)
            body = r.get_json()
            self.assertEqual(body['path'], expected)

            g = self.client.get('/api/service-meta/8080')
            self.assertEqual(g.status_code, 200)
            self.assertEqual(g.get_json()['path'], expected)

    def test_service_metadata_rejects_scalar_json_and_invalid_string_fields(self):
        self._insert_service()
        for body in ([], 'text', 7, 1.5, True, None):
            with self.subTest(body=body):
                response = self.client.put(
                    '/api/service-meta/8080',
                    data=json.dumps(body),
                    content_type='application/json',
                    headers=self.ui_headers,
                )
                self.assertEqual(response.status_code, 400)
                self.assertTrue(response.is_json)
                self.assertIn('error', response.get_json())

        invalid_values = ([], {}, 7, True, None)
        for field in ('display_name', 'url', 'path', 'tags', 'healthy_statuses'):
            for value in invalid_values:
                with self.subTest(field=field, value=value):
                    response = self.client.put(
                        '/api/service-meta/8080',
                        json={field: value},
                        headers=self.ui_headers,
                    )
                    self.assertEqual(response.status_code, 400)
                    self.assertTrue(response.is_json)
                    self.assertIn('error', response.get_json())

    def _metadata_durable_snapshot(self, port=8080):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            metadata = conn.execute(
                "SELECT * FROM service_meta WHERE port=?", (port,)
            ).fetchall()
            previews = conn.execute(
                "SELECT * FROM preview_requests WHERE port=? ORDER BY id", (port,)
            ).fetchall()
            events = conn.execute(
                "SELECT * FROM events WHERE port=? ORDER BY id", (port,)
            ).fetchall()
            conn.close()
        return {
            'metadata': [dict(row) for row in metadata],
            'previews': [dict(row) for row in previews],
            'events': [dict(row) for row in events],
        }

    def test_service_metadata_rejects_critical_and_pinned_order_without_side_effects(self):
        self._insert_service()
        baseline = self.client.put(
            '/api/service-meta/8080',
            json={'display_name': 'Baseline Demo', 'critical': False, 'pinned_order': 17},
            headers=self.ui_headers,
        )
        self.assertEqual(baseline.status_code, 200)
        baseline_metadata = self.client.get('/api/service-meta/8080').get_json()

        invalid_cases = [
            ('critical', None, 'critical must be a boolean'),
            ('critical', 'true', 'critical must be a boolean'),
            ('critical', 'false', 'critical must be a boolean'),
            ('critical', 0, 'critical must be a boolean'),
            ('critical', 1, 'critical must be a boolean'),
            ('critical', 1.5, 'critical must be a boolean'),
            ('critical', [], 'critical must be a boolean'),
            ('critical', {}, 'critical must be a boolean'),
            ('pinned_order', None, 'pinned_order must be an integer between 0 and 65535'),
            ('pinned_order', True, 'pinned_order must be an integer between 0 and 65535'),
            ('pinned_order', False, 'pinned_order must be an integer between 0 and 65535'),
            ('pinned_order', '17', 'pinned_order must be an integer between 0 and 65535'),
            ('pinned_order', 17.0, 'pinned_order must be an integer between 0 and 65535'),
            ('pinned_order', 17.5, 'pinned_order must be an integer between 0 and 65535'),
            ('pinned_order', [], 'pinned_order must be an integer between 0 and 65535'),
            ('pinned_order', {}, 'pinned_order must be an integer between 0 and 65535'),
            ('pinned_order', -1, 'pinned_order must be an integer between 0 and 65535'),
            ('pinned_order', 65536, 'pinned_order must be an integer between 0 and 65535'),
        ]
        for field, value, expected_error in invalid_cases:
            with self.subTest(field=field, value=value):
                before = self._metadata_durable_snapshot()
                response = self.client.put(
                    '/api/service-meta/8080',
                    json={field: value},
                    headers=self.ui_headers,
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.get_json(), {'error': expected_error})
                self.assertEqual(self._metadata_durable_snapshot(), before)
                self.assertEqual(
                    self.client.get('/api/service-meta/8080').get_json(),
                    baseline_metadata,
                )

        for critical, expected in ((True, True), (False, False)):
            with self.subTest(critical=critical):
                response = self.client.put(
                    '/api/service-meta/8080',
                    json={'critical': critical},
                    headers=self.ui_headers,
                )
                self.assertEqual(response.status_code, 200)
                self.assertIs(response.get_json()['critical'], expected)

        for pinned_order in (0, 65535):
            with self.subTest(pinned_order=pinned_order):
                response = self.client.put(
                    '/api/service-meta/8080',
                    json={'pinned_order': pinned_order},
                    headers=self.ui_headers,
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()['pinned_order'], pinned_order)

        response = self.client.put(
            '/api/service-meta/8080',
            json={'display_name': 'Pinned Order Retained'},
            headers=self.ui_headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['pinned_order'], 65535)

    def test_repository_metadata_upsert_is_transactional_and_flask_free(self):
        """The web adapter owns validation while the repository owns SQL only."""
        from dashboard.beacon import db, repositories

        self._insert_service()
        with db.write_transaction(self.appmod.DB_PATH) as conn:
            repositories.upsert_service_metadata(
                conn,
                port=8080,
                display_name='Repository Demo',
                url='http://127.0.0.1:8080/repository',
                critical=True,
                pinned_order=3,
                tags='core,repository',
                healthy_statuses='200-399',
                requested_ts=1234,
            )

        with db.read_transaction(self.appmod.DB_PATH) as conn:
            metadata = repositories.get_service_metadata(conn, 8080)
            preview = conn.execute(
                "SELECT requested_ts, status FROM preview_requests WHERE port=?", (8080,)
            ).fetchone()

        self.assertEqual(metadata['display_name'], 'Repository Demo')
        self.assertEqual(metadata['url'], 'http://127.0.0.1:8080/repository')
        self.assertEqual(dict(preview), {'requested_ts': 1234, 'status': 'queued'})
        source = inspect.getsource(repositories)
        self.assertNotIn('from flask', source.lower())
        self.assertNotIn('import flask', source.lower())

    def test_service_meta_path_merge_rules(self):
        self._insert_service(url='http://127.0.0.1:8080/root')

        url_only = self.client.put('/api/service-meta/8080', json={'url': 'http://127.0.0.1:8080/alpha'}, headers=self.ui_headers)
        self.assertEqual(url_only.status_code, 200)
        self.assertEqual(url_only.get_json()['path'], '/alpha')

        path_only = self.client.put('/api/service-meta/8080', json={'path': '/beta?x=1'}, headers=self.ui_headers)
        self.assertEqual(path_only.status_code, 200)
        self.assertEqual(path_only.get_json()['path'], '/beta?x=1')
        self.assertTrue(path_only.get_json()['url'].startswith('http://127.0.0.1:8080/'))

        both = self.client.put(
            '/api/service-meta/8080',
            json={'url': 'http://127.0.0.1:9090/ignored', 'path': '/gamma#frag'},
            headers=self.ui_headers,
        )
        self.assertEqual(both.status_code, 200)
        both_json = both.get_json()
        self.assertEqual(both_json['path'], '/gamma#frag')
        self.assertEqual(both_json['url'], 'http://127.0.0.1:9090/gamma#frag')

    def test_service_meta_refresh_success_updates_title_and_thumbnail(self):
        self._insert_service(url='http://127.0.0.1:8080/root')

        original_html_fetch = self.appmod._fetch_html_response
        original_thumb = self.appmod.fetch_thumbnail
        seen_fetch = []
        seen_thumb = []

        def fake_html_fetch(url, *_args, **_kwargs):
            seen_fetch.append(url)
            return True, None, FakeResponse(
                text='<html><head><title>Path Title</title></head><body></body></html>',
                status_code=200,
                headers={'Content-Type': 'text/html'},
            ), url

        def fake_thumb(port, service_url=None):
            seen_thumb.append((port, service_url))
            return b'png-bytes', 'image/png', 'screenshot', None

        self.appmod._fetch_html_response = fake_html_fetch
        self.appmod.fetch_thumbnail = fake_thumb

        try:
            r = self.client.put('/api/service-meta/8080', json={'path': '/app?view=1'}, headers=self.ui_headers)
            owner = self._worker_owner()
            processed = self.appmod.process_preview_requests(owner.worker_id, owner.owner_token)
        finally:
            self.appmod._fetch_html_response = original_html_fetch
            self.appmod.fetch_thumbnail = original_thumb

        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['path'], '/app?view=1')
        self.assertTrue(body['preview_queued'])
        self.assertTrue(processed)
        self.assertIsNone(body['refresh_warning'])
        self.assertEqual(seen_fetch[-1], 'http://127.0.0.1:8080/app?view=1')
        self.assertIn((8080, 'http://127.0.0.1:8080/app?view=1'), seen_thumb)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                "SELECT title, thumb_source FROM services WHERE port=8080"
            ).fetchone()
            thumbnail = conn.execute(
                "SELECT data, mime FROM thumbnails WHERE port=8080"
            ).fetchone()
            conn.close()

        self.assertEqual(row['title'], 'Path Title')
        self.assertEqual(row['thumb_source'], 'screenshot')
        self.assertIsNotNone(thumbnail['data'])
        self.assertEqual(thumbnail['mime'], 'image/png')

    def test_thumbnail_result_records_error_and_clears_it_on_success(self):
        self._insert_service()
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            self.appmod._store_thumbnail_result(conn, 8080, None, None, None, 'browser missing', ts=111)
            failed = conn.execute(
                "SELECT thumb_source, thumb_attempt_ts, thumb_error FROM services WHERE port=8080"
            ).fetchone()
            failed_thumbnail = conn.execute(
                "SELECT 1 FROM thumbnails WHERE port=8080 AND expires_ts > 111"
            ).fetchone()
            self.appmod._store_thumbnail_result(conn, 8080, b'png-bytes', 'image/png', 'screenshot', None, ts=222)
            succeeded = conn.execute(
                "SELECT thumb_source, thumb_ts, thumb_attempt_ts, thumb_error FROM services WHERE port=8080"
            ).fetchone()
            succeeded_thumbnail = conn.execute(
                "SELECT data, mime FROM thumbnails WHERE port=8080"
            ).fetchone()
            conn.close()

        self.assertIsNone(failed['thumb_source'])
        self.assertEqual(failed['thumb_attempt_ts'], 111)
        self.assertEqual(failed['thumb_error'], 'browser missing')
        self.assertIsNone(failed_thumbnail)
        self.assertEqual(bytes(succeeded_thumbnail['data']), b'png-bytes')
        self.assertEqual(succeeded_thumbnail['mime'], 'image/png')
        self.assertEqual(succeeded['thumb_source'], 'screenshot')
        self.assertEqual(succeeded['thumb_ts'], 222)
        self.assertEqual(succeeded['thumb_attempt_ts'], 222)
        self.assertIsNone(succeeded['thumb_error'])

    def test_invalid_legacy_service_url_is_safe_in_api_output(self):
        self._insert_service(port=8085, url='ftp://legacy-host/app')

        services_resp = self.client.get('/api/services')
        self.assertEqual(services_resp.status_code, 200)
        svc = services_resp.get_json()[0]
        self.assertEqual(svc['url'], 'http://127.0.0.1:8085')
        self.assertEqual(svc['path'], '/')

        meta_resp = self.client.get('/api/service-meta/8085')
        self.assertEqual(meta_resp.status_code, 200)
        meta = meta_resp.get_json()
        self.assertEqual(meta['url'], 'http://127.0.0.1:8085')
        self.assertEqual(meta['path'], '/')

        status_resp = self.client.get('/api/thumbnail-status')
        self.assertEqual(status_resp.status_code, 200)
        status = status_resp.get_json()[0]
        self.assertEqual(status['url'], 'http://127.0.0.1:8085')

    def test_service_meta_refresh_failure_keeps_existing_values_and_warns(self):
        self._insert_service(url='http://127.0.0.1:8080/root')
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "UPDATE services SET title=?, thumb_ts=? WHERE port=?",
                ('Existing Title', 12345, 8080),
            )
            conn.execute(
                "INSERT INTO thumbnails(port, data, mime, captured_ts, source, expires_ts) "
                "VALUES(8080, ?, ?, ?, 'screenshot', ?)",
                (b'old-bytes', 'image/png', 12345, 12345 + 86400 * 365),
            )
            conn.commit()
            conn.close()

        original_html_fetch = self.appmod._fetch_html_response
        original_thumb = self.appmod.fetch_thumbnail

        def fake_html_fetch(url, *_args, **_kwargs):
            _ = url
            return False, 'connection_error', None, url

        def fake_thumb(*_args, **_kwargs):
            raise AssertionError('thumbnail refresh should be skipped when path probe fails')

        self.appmod._fetch_html_response = fake_html_fetch
        self.appmod.fetch_thumbnail = fake_thumb

        try:
            r = self.client.put('/api/service-meta/8080', json={'path': '/broken'}, headers=self.ui_headers)
            owner = self._worker_owner()
            processed = self.appmod.process_preview_requests(owner.worker_id, owner.owner_token)
        finally:
            self.appmod._fetch_html_response = original_html_fetch
            self.appmod.fetch_thumbnail = original_thumb

        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['path'], '/broken')
        self.assertTrue(body['preview_queued'])
        self.assertTrue(processed)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                "SELECT title FROM services WHERE port=8080"
            ).fetchone()
            thumbnail = conn.execute(
                "SELECT data, mime FROM thumbnails WHERE port=8080"
            ).fetchone()
            preview = conn.execute("SELECT status, error FROM preview_requests WHERE port=8080").fetchone()
            conn.close()

        self.assertEqual(row['title'], 'Existing Title')
        self.assertEqual(bytes(thumbnail['data']), b'old-bytes')
        self.assertEqual(thumbnail['mime'], 'image/png')
        self.assertEqual(preview['status'], 'failed')
        self.assertIn('title refresh failed', preview['error'])

    def test_fetch_thumbnail_marks_playwright_screenshot_source(self):
        original_screenshot = self.appmod._screenshot_service
        original_fetch_html = self.appmod._fetch_html_response

        def fake_screenshot(port, target_url=None):
            self.assertEqual(port, 8080)
            self.assertEqual(target_url, 'http://127.0.0.1:8080/app?view=1')
            return b'png-bytes', 'image/png', None

        def fake_fetch_html(*_args, **_kwargs):
            raise AssertionError('fallback should not run after screenshot succeeds')

        self.appmod._screenshot_service = fake_screenshot
        self.appmod._fetch_html_response = fake_fetch_html
        try:
            data, mime, source, error = self.appmod.fetch_thumbnail(
                8080,
                'http://127.0.0.1:8080/app?view=1',
            )
        finally:
            self.appmod._screenshot_service = original_screenshot
            self.appmod._fetch_html_response = original_fetch_html

        self.assertEqual(data, b'png-bytes')
        self.assertEqual(mime, 'image/png')
        self.assertEqual(source, 'screenshot')
        self.assertIsNone(error)

    def test_fetch_thumbnail_returns_error_without_html_fallback_after_screenshot_failure(self):
        original_screenshot = self.appmod._screenshot_service
        original_fetch_html = self.appmod._fetch_html_response

        def fake_screenshot(port, target_url=None):
            self.assertEqual((port, target_url), (8080, 'http://127.0.0.1:8080/app'))
            return None, None, 'browser failed'

        def fake_fetch_html(*_args, **_kwargs):
            raise AssertionError('HTML fallback should not run after screenshot failure')

        self.appmod._screenshot_service = fake_screenshot
        self.appmod._fetch_html_response = fake_fetch_html
        try:
            data, mime, source, error = self.appmod.fetch_thumbnail(
                8080,
                'http://127.0.0.1:8080/app',
            )
        finally:
            self.appmod._screenshot_service = original_screenshot
            self.appmod._fetch_html_response = original_fetch_html

        self.assertIsNone(data)
        self.assertIsNone(mime)
        self.assertIsNone(source)
        self.assertEqual(error, 'browser failed')


if __name__ == '__main__':
    unittest.main()
