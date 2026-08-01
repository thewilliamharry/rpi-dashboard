import socket
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dashboard.beacon.config import load_settings
from dashboard.beacon.outbound import (
    OutboundTransport,
    OutboundPolicy,
    OutboundPolicyError,
    OutboundPurpose,
)
from dashboard.beacon.previews import route_browser_request


TLS_FIXTURES = Path(__file__).with_name('fixtures') / 'tls'


class _RecordingHandler(BaseHTTPRequestHandler):
    records = []

    def do_GET(self):
        type(self).records.append({
            'path': self.path,
            'host': self.headers.get('Host'),
            'client': self.client_address,
        })
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/final')
        else:
            self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *_args):
        return


class _LocalOrigin:
    def __init__(self, *, tls=False, sni_values=None):
        _RecordingHandler.records = []
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), _RecordingHandler)
        self.sni_values = sni_values if sni_values is not None else []
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(
                TLS_FIXTURES / 'beacon-test-cert.pem',
                TLS_FIXTURES / 'beacon-test-key.pem',
            )
            context.set_servername_callback(lambda _sock, name, _ctx: self.sni_values.append(name))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_port

    @property
    def records(self):
        return list(_RecordingHandler.records)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _resolver(*addresses):
    def resolve(host, port, *_args, **_kwargs):
        return [
            (socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, port))
            for address in addresses
        ]
    return resolve


class OutboundPolicyTests(unittest.TestCase):
    def setUp(self):
        self.settings = load_settings({
            'SERVICE_TARGET_HOSTS': 'service.local,127.0.0.1,::1',
            'SERVICE_TARGET_NETWORKS': '127.0.0.0/8,::1/128,192.168.1.0/24,fd00::/8',
            'ALERT_WEBHOOK_URL': 'https://alerts.example.test/beacon',
        })

    def test_plan_accepts_allowed_targets_and_is_immutable(self):
        plan = OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1')).plan(
            'http://service.local:8100/path?q=1', OutboundPurpose.SERVICE_PROBE,
        )
        self.assertEqual(plan.url, 'http://service.local:8100/path?q=1')
        self.assertEqual(plan.resolved_addresses, ('127.0.0.1',))
        self.assertFalse(plan.tls.verify_certificate)
        self.assertTrue(plan.tls.tls_unverified)
        with self.assertRaises(Exception):
            plan.url = 'http://changed.test/'

    def test_rejects_credentials_bad_ports_and_any_bad_dns_answer(self):
        policy = OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1', '8.8.8.8'))
        for url, reason in [
            ('ftp://service.local/', 'scheme_not_allowed'),
            ('http://user@service.local/', 'credentials_not_allowed'),
            ('http://service.local:0/', 'port_not_allowed'),
            ('http://service.local:99999/', 'port_not_allowed'),
        ]:
            with self.subTest(url=url):
                with self.assertRaisesRegex(OutboundPolicyError, reason):
                    policy.plan(url, OutboundPurpose.SERVICE_PROBE)
        with self.assertRaisesRegex(OutboundPolicyError, 'resolved_address_not_allowed'):
            policy.plan('http://service.local/', OutboundPurpose.SERVICE_PROBE)

    def test_redirects_replan_and_webhooks_are_strict(self):
        policy = OutboundPolicy(self.settings, resolver=_resolver('192.168.1.12'))
        service = policy.plan('https://service.local/', OutboundPurpose.HTML_PREVIEW)
        self.assertTrue(service.tls.tls_unverified)
        self.assertEqual(service.redirect_budget, 5)
        with self.assertRaisesRegex(OutboundPolicyError, 'redirect_not_allowed'):
            policy.plan('https://alerts.example.test/next', OutboundPurpose.WEBHOOK, redirect_count=1)

        webhook = OutboundPolicy(self.settings, resolver=_resolver('8.8.8.8')).plan(
            'https://alerts.example.test/beacon', OutboundPurpose.WEBHOOK,
        )
        self.assertTrue(webhook.tls.verify_certificate)
        self.assertFalse(webhook.tls.tls_unverified)
        with self.assertRaisesRegex(OutboundPolicyError, 'tls_required'):
            OutboundPolicy(self.settings, resolver=_resolver('8.8.8.8')).plan(
                'http://alerts.example.test/beacon', OutboundPurpose.WEBHOOK,
            )

    def test_policy_errors_redact_destination(self):
        policy = OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1'))
        with self.assertRaises(OutboundPolicyError) as raised:
            policy.plan('http://secret.example.test/', OutboundPurpose.SERVICE_PROBE)
        self.assertEqual(raised.exception.reason, 'target_not_allowed')
        self.assertNotIn('secret.example.test', str(raised.exception))

    def test_transport_disables_redirects_and_replans_every_hop(self):
        calls = []

        class Response:
            def __init__(self, status_code, location=None):
                self.status_code = status_code
                self.headers = {'Location': location} if location else {}

        def request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return Response(302, 'http://service.local/next') if len(calls) == 1 else Response(200)

        transport = OutboundTransport(
            OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1')),
            requester=request,
        )
        response, plan = transport.request('http://service.local/', OutboundPurpose.SERVICE_PROBE)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(plan.url, 'http://service.local/next')
        self.assertEqual([call[1] for call in calls], ['http://service.local/', 'http://service.local/next'])
        self.assertTrue(all(call[2]['allow_redirects'] is False for call in calls))
        self.assertTrue(all(call[2]['verify'] is False for call in calls))

    def test_browser_route_validates_before_continue(self):
        class Request:
            url = 'http://service.local/app.js'

        class Route:
            request = Request()
            continued = False
            aborted = False

            def continue_(self):
                self.continued = True

            def abort(self, _reason):
                self.aborted = True

        allowed = Route()
        policy = OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1'))
        self.assertTrue(route_browser_request(policy, allowed))
        self.assertTrue(allowed.continued)

        class BlockedPolicy:
            def plan(self, *_args, **_kwargs):
                raise OutboundPolicyError('target_not_allowed')

        blocked = Route()
        self.assertFalse(route_browser_request(BlockedPolicy(), blocked))
        self.assertTrue(blocked.aborted)
        self.assertFalse(blocked.continued)

    def test_concurrent_service_and_webhook_plans_keep_tls_isolated(self):
        def resolve(host, port, *_args, **_kwargs):
            address = '8.8.8.8' if host == 'alerts.example.test' else '127.0.0.1'
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, port))]

        policy = OutboundPolicy(self.settings, resolver=resolve)
        barrier = threading.Barrier(2)
        plans = {}

        def create(name, url, purpose):
            barrier.wait(timeout=1)
            plans[name] = policy.plan(url, purpose)

        workers = [
            threading.Thread(target=create, args=('service', 'https://service.local/', OutboundPurpose.SERVICE_PROBE)),
            threading.Thread(target=create, args=('webhook', 'https://alerts.example.test/beacon', OutboundPurpose.WEBHOOK)),
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=1)

        self.assertTrue(plans['service'].tls.tls_unverified)
        self.assertFalse(plans['service'].tls.verify_certificate)
        self.assertFalse(plans['webhook'].tls.tls_unverified)
        self.assertTrue(plans['webhook'].tls.verify_certificate)

    def test_socket_destination_and_host_header_are_pinned(self):
        with _LocalOrigin() as origin:
            policy = OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1'))
            transport = OutboundTransport(policy)

            response, plan = transport.request(
                f'http://service.local:{origin.port}/resource',
                OutboundPurpose.SERVICE_PROBE,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(plan.selected_address, '127.0.0.1')
        self.assertEqual(origin.records[0]['host'], f'service.local:{origin.port}')
        self.assertEqual(origin.records[0]['client'][0], '127.0.0.1')

    def test_tls_sni_and_certificate_hostname_survive_pinned_socket(self):
        with _LocalOrigin(tls=True) as origin:
            settings = load_settings({
                'SERVICE_TARGET_HOSTS': 'service.local,127.0.0.1,::1',
                'SERVICE_TARGET_NETWORKS': '127.0.0.0/8,::1/128',
                'ALERT_WEBHOOK_URL': f'https://alerts.example.test:{origin.port}/beacon',
            })
            policy = OutboundPolicy(settings, resolver=_resolver('127.0.0.1'))
            policy._webhook_address_allowed = lambda _address: True
            transport = OutboundTransport(
                policy,
                ca_certs=str(TLS_FIXTURES / 'beacon-test-cert.pem'),
            )

            response, plan = transport.request(
                f'https://alerts.example.test:{origin.port}/beacon', OutboundPurpose.WEBHOOK,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(plan.selected_address, '127.0.0.1')
        self.assertEqual(origin.records[0]['host'], f'alerts.example.test:{origin.port}')
        self.assertEqual(origin.sni_values, ['alerts.example.test'])

    def test_redirect_hop_replans_before_opening_its_selected_socket(self):
        calls = []

        def resolve(host, port, *_args, **_kwargs):
            calls.append((host, port))
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port))]

        with _LocalOrigin() as origin:
            transport = OutboundTransport(OutboundPolicy(self.settings, resolver=resolve))
            response, _plan = transport.request(
                f'http://service.local:{origin.port}/redirect', OutboundPurpose.SERVICE_PROBE,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(calls, [('service.local', origin.port), ('service.local', origin.port)])
        self.assertEqual([entry['path'] for entry in origin.records], ['/redirect', '/final'])

    def test_rebinding_after_planning_never_resolves_or_connects_by_hostname(self):
        calls = []

        def resolve(host, port, *_args, **_kwargs):
            calls.append((host, port))
            address = '127.0.0.1' if len(calls) == 1 else '203.0.113.8'
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, port))]

        with _LocalOrigin() as origin:
            response, plan = OutboundTransport(OutboundPolicy(self.settings, resolver=resolve)).request(
                f'http://service.local:{origin.port}/', OutboundPurpose.SERVICE_PROBE,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(plan.selected_address, '127.0.0.1')
        self.assertEqual(calls, [('service.local', origin.port)])
        self.assertEqual(len(origin.records), 1)
