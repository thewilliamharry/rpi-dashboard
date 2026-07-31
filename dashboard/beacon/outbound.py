"""Immutable, purpose-specific policy for all Beacon outbound requests.

The policy validates a candidate immediately before each connection.  It keeps
the LAN certificate exception as request data, preventing it from leaking into
strict webhook delivery or concurrent requests.
"""

from dataclasses import dataclass
from enum import Enum
import ipaddress
import socket
from urllib.parse import urlparse, urlunparse


class OutboundPurpose(str, Enum):
    SERVICE_PROBE = 'service_probe'
    HTML_PREVIEW = 'html_preview'
    BROWSER_PREVIEW = 'browser_preview'
    WEBHOOK = 'webhook'


class OutboundPolicyError(ValueError):
    """A stable, destination-free policy rejection."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class TlsPosture:
    verify_certificate: bool
    tls_unverified: bool


@dataclass(frozen=True)
class RequestPlan:
    url: str
    scheme: str
    hostname: str
    port: int
    path_query: str
    resolved_addresses: tuple[str, ...]
    purpose: OutboundPurpose
    redirect_budget: int
    connect_timeout: float
    read_timeout: float
    tls: TlsPosture
    display_context: str


class OutboundPolicy:
    """Build immutable, DNS-validated connection decisions.

    ``resolver`` is injected for deterministic tests and called for every
    plan, including every redirect candidate.  Callers must never reuse a plan
    for a later hop.
    """

    SERVICE_PURPOSES = frozenset({
        OutboundPurpose.SERVICE_PROBE,
        OutboundPurpose.HTML_PREVIEW,
        OutboundPurpose.BROWSER_PREVIEW,
    })

    def __init__(self, settings, *, resolver=socket.getaddrinfo):
        self.settings = settings
        self._resolver = resolver

    def plan(self, url, purpose, redirect_count=0):
        try:
            purpose = OutboundPurpose(purpose)
        except ValueError as exc:
            raise OutboundPolicyError('target_not_allowed') from exc
        if redirect_count < 0:
            raise OutboundPolicyError('redirect_not_allowed')
        if purpose is OutboundPurpose.WEBHOOK and redirect_count:
            raise OutboundPolicyError('redirect_not_allowed')
        if purpose in self.SERVICE_PURPOSES and redirect_count > 5:
            raise OutboundPolicyError('redirect_not_allowed')

        parsed = self._parse(url)
        hostname = parsed.hostname.lower().rstrip('.')
        port = self._port(parsed)
        self._validate_target(parsed, hostname, port, purpose)
        addresses = self._resolve(hostname, port)
        self._validate_addresses(addresses, purpose)
        tls = self._tls_posture(parsed.scheme, hostname, purpose)
        normalized = self._normalized_url(parsed, hostname, port)
        return RequestPlan(
            url=normalized,
            scheme=parsed.scheme.lower(),
            hostname=hostname,
            port=port,
            path_query=(parsed.path or '/') + (f'?{parsed.query}' if parsed.query else ''),
            resolved_addresses=addresses,
            purpose=purpose,
            redirect_budget=0 if purpose is OutboundPurpose.WEBHOOK else 5 - redirect_count,
            connect_timeout=2.0 if purpose is OutboundPurpose.SERVICE_PROBE else 3.0,
            read_timeout=2.5 if purpose is OutboundPurpose.SERVICE_PROBE else 4.0,
            tls=tls,
            display_context=purpose.value,
        )

    @staticmethod
    def _parse(url):
        try:
            parsed = urlparse(str(url).strip())
            # Accessing ``port`` is what makes urllib reject malformed ports.
            _ = parsed.port
        except (TypeError, ValueError) as exc:
            raise OutboundPolicyError('port_not_allowed') from exc
        if parsed.scheme.lower() not in {'http', 'https'}:
            raise OutboundPolicyError('scheme_not_allowed')
        if not parsed.hostname:
            raise OutboundPolicyError('target_not_allowed')
        if parsed.username is not None or parsed.password is not None:
            raise OutboundPolicyError('credentials_not_allowed')
        if parsed.fragment:
            raise OutboundPolicyError('target_not_allowed')
        return parsed

    @staticmethod
    def _port(parsed):
        try:
            port = parsed.port
        except ValueError as exc:
            raise OutboundPolicyError('port_not_allowed') from exc
        port = (443 if parsed.scheme.lower() == 'https' else 80) if port is None else port
        if not 1 <= port <= 65535:
            raise OutboundPolicyError('port_not_allowed')
        return port

    def _validate_target(self, parsed, hostname, port, purpose):
        if purpose is OutboundPurpose.WEBHOOK:
            configured = self._configured_webhook()
            if configured is None:
                raise OutboundPolicyError('target_not_allowed')
            if parsed.scheme.lower() != 'https':
                raise OutboundPolicyError('tls_required')
            expected_port = configured.port or 443
            if (
                hostname != configured.hostname.lower().rstrip('.')
                or port != expected_port
                or (parsed.path or '/') != (configured.path or '/')
                or parsed.query != configured.query
            ):
                raise OutboundPolicyError('target_not_allowed')
            return

        literal = self._ip_or_none(hostname)
        if hostname not in self.settings.service_target_hosts:
            if literal is None or not self._in_service_networks(literal):
                raise OutboundPolicyError('target_not_allowed')

    def _validate_addresses(self, addresses, purpose):
        if purpose is OutboundPurpose.WEBHOOK:
            if not all(self._webhook_address_allowed(address) for address in addresses):
                raise OutboundPolicyError('resolved_address_not_allowed')
            return
        if not all(self._in_service_networks(address) for address in addresses):
            raise OutboundPolicyError('resolved_address_not_allowed')

    def _resolve(self, hostname, port):
        try:
            results = self._resolver(hostname, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise OutboundPolicyError('resolution_failed') from exc
        addresses = []
        for family, _socktype, _proto, _canonname, sockaddr in results:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                address = ipaddress.ip_address(sockaddr[0])
            except ValueError as exc:
                raise OutboundPolicyError('resolved_address_not_allowed') from exc
            text = str(address)
            if text not in addresses:
                addresses.append(text)
        if not addresses:
            raise OutboundPolicyError('resolution_failed')
        return tuple(addresses)

    @staticmethod
    def _ip_or_none(value):
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    def _in_service_networks(self, address):
        value = address if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(address)
        return any(value in network for network in self.settings.service_target_networks)

    @staticmethod
    def _webhook_address_allowed(address):
        value = ipaddress.ip_address(address)
        return value.is_global

    def _configured_webhook(self):
        raw = (self.settings.alert_webhook_url or '').strip()
        if not raw:
            return None
        try:
            parsed = urlparse(raw)
            _ = parsed.port
        except (TypeError, ValueError):
            return None
        if (
            parsed.scheme.lower() != 'https'
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            return None
        return parsed

    def _tls_posture(self, scheme, hostname, purpose):
        # Host aliases are eligible only if all their already-resolved addresses
        # are in configured service networks.  ``plan`` computes that branch.
        if purpose in self.SERVICE_PURPOSES and hostname in self.settings.service_target_hosts:
            return TlsPosture(verify_certificate=False, tls_unverified=True)
        return TlsPosture(verify_certificate=True, tls_unverified=False)

    @staticmethod
    def _normalized_url(parsed, hostname, port):
        scheme = parsed.scheme.lower()
        default_port = 443 if scheme == 'https' else 80
        host = f'[{hostname}]' if ':' in hostname else hostname
        netloc = host if port == default_port else f'{host}:{port}'
        return urlunparse((scheme, netloc, parsed.path or '/', '', parsed.query, ''))
