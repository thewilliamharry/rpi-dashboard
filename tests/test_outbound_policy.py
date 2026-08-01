import socket
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

from dashboard.beacon.config import load_settings
from dashboard.beacon.outbound import (
    OutboundTransport,
    OutboundPolicy,
    OutboundPolicyError,
    OutboundPurpose,
    PolicyProxy,
)
from dashboard.beacon.previews import browser_proxy_context, route_browser_request


TLS_FIXTURES = Path(__file__).with_name('fixtures') / 'tls'


class _RecordingHandler(BaseHTTPRequestHandler):
    records = []

    def _record(self):
        type(self).records.append({
            'method': self.command,
            'path': self.path,
            'host': self.headers.get('Host'),
            'client': self.client_address,
        })
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/final')
            body = b''
        elif self.path == '/page' and self.server.page_body is not None:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            body = self.server.page_body
        elif self.path == '/page':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            body = b'<html><script src="/subresource.js"></script></html>'
        else:
            self.send_response(200)
            body = b'ok'
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record
    do_HEAD = _record
    do_POST = _record
    do_PUT = _record
    do_PATCH = _record
    do_DELETE = _record
    do_OPTIONS = _record
    do_TRACE = _record

    def log_message(self, *_args):
        return


class _LocalOrigin:
    def __init__(self, *, tls=False, sni_values=None, page_body=None):
        self._records = []
        handler = type('_LocalRecordingHandler', (_RecordingHandler,), {'records': self._records})
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        self.server.page_body = page_body
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
        return list(self._records)

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
            method = 'GET'

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

    def test_route_rejects_every_non_retrieval_method_before_policy_planning(self):
        class Policy:
            calls = []

            def plan(self, *args):
                self.calls.append(args)

        class Request:
            url = 'http://service.local/app.js'

        class Route:
            continued = False
            aborted = False

            def __init__(self, method):
                self.request = Request()
                if method is not None:
                    self.request.method = method

            def continue_(self):
                self.continued = True

            def abort(self, _reason):
                self.aborted = True

        policy = Policy()
        for method in ('GET', 'HEAD'):
            with self.subTest(method=method):
                route = Route(method)
                self.assertTrue(route_browser_request(policy, route))
                self.assertTrue(route.continued)
                self.assertFalse(route.aborted)

        calls_before_rejections = len(policy.calls)
        for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'pOsT', 'UNKNOWN', None):
            with self.subTest(method=method):
                route = Route(method)
                self.assertFalse(route_browser_request(policy, route))
                self.assertTrue(route.aborted)
                self.assertFalse(route.continued)
        self.assertEqual(len(policy.calls), calls_before_rejections)

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

    def test_chromium_proxy_absolute_request_pins_origin_and_preserves_host_header(self):
        with _LocalOrigin() as origin, PolicyProxy(
                OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1')),
        ) as proxy:
            with socket.create_connection(proxy.address, timeout=1) as client:
                client.sendall(
                    f'GET http://service.local:{origin.port}/main HTTP/1.1\r\n'
                    f'Host: service.local:{origin.port}\r\nConnection: close\r\n\r\n'.encode(),
                )
                response = client.recv(4096)

        self.assertIn(b'200', response)
        self.assertEqual(origin.records[0]['host'], f'service.local:{origin.port}')
        self.assertEqual(proxy.active_relays, 0)

    def test_proxy_rejects_unsafe_methods_before_planning_or_opening_an_origin(self):
        class Policy:
            calls = []

            def plan(self, *_args):
                self.calls.append(_args)
                raise AssertionError('unsafe request must not be planned')

        with PolicyProxy(Policy()) as proxy:
            for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'UNKNOWN'):
                with self.subTest(method=method), socket.create_connection(proxy.address, timeout=1) as client:
                    client.sendall(
                        f'{method} http://service.local:8123/mutate HTTP/1.1\r\n'
                        'Host: service.local:8123\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmutated'.encode(),
                    )
                    response = client.recv(4096)
                    self.assertIn(b'405 Method Not Allowed', response)
                    self.assertIn(b'Allow: GET, HEAD', response)

        self.assertEqual(Policy.calls, [])

    def test_hostile_chromium_preview_cannot_mutate_second_allowed_origin(self):
        with _LocalOrigin() as preview_origin, _LocalOrigin() as mutation_origin, _LocalOrigin(tls=True) as tls_origin, sync_playwright() as playwright:
            hostile_page = (
                '<html><body><img src="/subresource.js"><iframe name="mutation-target"></iframe>'
                f'<form action="http://service.local:{mutation_origin.port}/form" method="POST" target="mutation-target">'
                '<input name="unsafe" value="1"></form><script>'
                'document.forms[0].submit();'
                f'for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {{ fetch("http://service.local:{mutation_origin.port}/fetch", {{method}}).catch(() => {{}}); }}'
                f'fetch("https://service.local:{tls_origin.port}/unsafe", {{method: "POST"}}).catch(() => {{}});'
                '</script></body></html>'
            ).encode()
            preview_origin.server.page_body = hostile_page
            policy = OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1'))
            browser = playwright.chromium.launch()
            try:
                with browser_proxy_context(
                        browser,
                        policy,
                        ignore_https_errors=True,
                ) as context:
                    context.route('**/*', lambda route: route_browser_request(
                        policy, route,
                    ))
                    page = context.new_page()
                    page.goto(f'http://service.local:{preview_origin.port}/page', wait_until='networkidle')
            finally:
                browser.close()

        self.assertIn('/subresource.js', [entry['path'] for entry in preview_origin.records])
        self.assertEqual(mutation_origin.records, [])
        self.assertEqual(tls_origin.records, [])

    def test_chromium_main_frame_and_subresource_use_loopback_policy_proxy(self):
        with _LocalOrigin() as origin, sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                with browser_proxy_context(
                        browser,
                        OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1')),
                ) as context:
                    page = context.new_page()
                    page.goto(f'http://service.local:{origin.port}/page', wait_until='networkidle')
            finally:
                browser.close()

        self.assertEqual(
            [entry['path'] for entry in origin.records], ['/page', '/subresource.js'],
        )
        self.assertTrue(all(entry['host'] == f'service.local:{origin.port}' for entry in origin.records))

    def test_chromium_connect_tunnel_preserves_original_sni_at_pinned_origin(self):
        with _LocalOrigin(tls=True) as origin, sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                with browser_proxy_context(
                        browser,
                        OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1')),
                        ignore_https_errors=True,
                ) as context:
                    page = context.new_page()
                    page.goto(f'https://service.local:{origin.port}/secure', wait_until='networkidle')
            finally:
                browser.close()

        self.assertGreaterEqual(len(origin.sni_values), 1)
        self.assertTrue(all(value == 'service.local' for value in origin.sni_values))
        self.assertEqual(origin.records[0]['host'], f'service.local:{origin.port}')

    def test_connect_tunnel_uses_pinned_address_and_preserves_browser_sni(self):
        with _LocalOrigin(tls=True) as origin, PolicyProxy(
                OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1')),
        ) as proxy:
            with socket.create_connection(proxy.address, timeout=1) as client:
                client.sendall(f'CONNECT service.local:{origin.port} HTTP/1.1\r\nHost: service.local:{origin.port}\r\n\r\n'.encode())
                self.assertIn(b'200', client.recv(4096))
                tls = ssl.create_default_context()
                tls.check_hostname = False
                tls.verify_mode = ssl.CERT_NONE
                with tls.wrap_socket(client, server_hostname='service.local') as tunneled:
                    tunneled.sendall(b'GET /secure HTTP/1.1\r\nHost: service.local\r\nConnection: close\r\n\r\n')
                    self.assertIn(b'200', tunneled.recv(4096))

        self.assertEqual(origin.sni_values, ['service.local'])
        self.assertEqual(proxy.active_relays, 0)

    def test_proxy_rebinding_blocks_before_any_forbidden_origin_connection(self):
        calls = []

        def resolve(host, port, *_args, **_kwargs):
            calls.append((host, port))
            address = '127.0.0.1' if len(calls) == 1 else '203.0.113.8'
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, port))]

        policy = OutboundPolicy(self.settings, resolver=resolve)
        with _LocalOrigin() as origin:
            policy.plan(f'http://service.local:{origin.port}/early', OutboundPurpose.BROWSER_PREVIEW)
            with PolicyProxy(policy) as proxy, socket.create_connection(proxy.address, timeout=1) as client:
                client.sendall(
                    f'GET http://service.local:{origin.port}/blocked HTTP/1.1\r\n'
                    f'Host: service.local:{origin.port}\r\nConnection: close\r\n\r\n'.encode(),
                )
                self.assertIn(b'403', client.recv(4096))

        self.assertEqual(len(origin.records), 0)
        self.assertEqual(proxy.active_relays, 0)

    def test_browser_proxy_context_passes_only_loopback_proxy_and_closes_once(self):
        calls = []

        class Context:
            def close(self):
                calls.append('close')

        class Browser:
            def new_context(self, **kwargs):
                calls.append(kwargs)
                return Context()

        with browser_proxy_context(
                Browser(), OutboundPolicy(self.settings, resolver=_resolver('127.0.0.1')),
        ) as context:
            self.assertIsInstance(context, Context)

        self.assertEqual(calls[-1], 'close')
        self.assertTrue(calls[0]['proxy']['server'].startswith('http://127.0.0.1:'))
