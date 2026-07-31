import socket
import unittest

from dashboard.beacon.config import load_settings
from dashboard.beacon.outbound import (
    OutboundTransport,
    OutboundPolicy,
    OutboundPolicyError,
    OutboundPurpose,
)
from dashboard.beacon.previews import route_browser_request


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
