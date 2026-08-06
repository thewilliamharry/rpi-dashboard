"""Immutable, purpose-specific policy for all Beacon outbound requests.

The policy validates a candidate immediately before each connection.  It keeps
the LAN certificate exception as request data, preventing it from leaking into
strict webhook delivery or concurrent requests.
"""

from dataclasses import dataclass
from enum import Enum
import ipaddress
import json
import selectors
import socket
import socketserver
import threading
from urllib.parse import urljoin, urlparse, urlunparse

from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.util import Timeout


RETRIEVAL_METHODS = frozenset({'GET', 'HEAD'})


def is_retrieval_method(method):
    """Return whether an untrusted browser method is safe to retrieve with."""
    return isinstance(method, str) and method.upper() in RETRIEVAL_METHODS


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
    selected_address: str
    authority: str
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

        parsed = self._parse(url, purpose)
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
            selected_address=addresses[0],
            authority=self._authority(hostname, port, parsed.scheme),
            purpose=purpose,
            redirect_budget=0 if purpose is OutboundPurpose.WEBHOOK else 5 - redirect_count,
            connect_timeout=2.0 if purpose is OutboundPurpose.SERVICE_PROBE else 3.0,
            read_timeout=2.5 if purpose is OutboundPurpose.SERVICE_PROBE else 4.0,
            tls=tls,
            display_context=purpose.value,
        )

    @staticmethod
    def _parse(url, purpose):
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
        if parsed.fragment and purpose is OutboundPurpose.WEBHOOK:
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

    @staticmethod
    def _authority(hostname, port, scheme):
        default_port = 443 if scheme.lower() == 'https' else 80
        host = f'[{hostname}]' if ':' in hostname else hostname
        return host if port == default_port else f'{host}:{port}'


@dataclass
class PinnedResponse:
    """Small requests-compatible result with evidence of the opened address."""

    status_code: int
    headers: object
    content: bytes
    selected_address: str

    @property
    def text(self):
        return self.content.decode('utf-8', errors='replace')


class _PolicyProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, proxy):
        self.proxy = proxy
        super().__init__(address, _PolicyProxyHandler)


class _PolicyProxyHandler(socketserver.BaseRequestHandler):
    HEADER_LIMIT = 16 * 1024

    def handle(self):
        client = self.request
        origin = None
        relay_owns_origin = False
        try:
            header, remainder = self._read_header(client)
            method, target, version, headers = self._parse_header(header)
            if method == 'CONNECT':
                plan = self.server.proxy.policy.plan(
                    f'https://{target}/', OutboundPurpose.BROWSER_PREVIEW,
                )
                origin = self.server.proxy._connect(plan)
                client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                if remainder:
                    origin.sendall(remainder)
                relay_owns_origin = True
                self.server.proxy._relay(client, origin)
                return

            if not is_retrieval_method(method):
                self._method_not_allowed(client)
                return

            plan = self.server.proxy.policy.plan(target, OutboundPurpose.BROWSER_PREVIEW)
            origin = self.server.proxy._connect(plan)
            first_line = f'{method} {plan.path_query} {version}\r\n'.encode('ascii')
            forwarded = self._format_headers(headers, plan.authority)
            origin.sendall(first_line + forwarded + b'\r\n' + remainder)
            relay_owns_origin = True
            self.server.proxy._relay(client, origin)
        except (OutboundPolicyError, ValueError, OSError, UnicodeError):
            if origin is not None and not relay_owns_origin:
                self.server.proxy._close_unrelayed_origin(origin)
            self._reject(client)

    def _read_header(self, client):
        client.settimeout(self.server.proxy.idle_timeout)
        data = bytearray()
        while b'\r\n\r\n' not in data:
            chunk = client.recv(min(4096, self.HEADER_LIMIT - len(data)))
            if not chunk:
                raise ValueError('incomplete_header')
            data.extend(chunk)
            if len(data) >= self.HEADER_LIMIT:
                raise ValueError('header_too_large')
        header, remainder = bytes(data).split(b'\r\n\r\n', 1)
        return header, remainder

    @staticmethod
    def _parse_header(header):
        lines = header.decode('iso-8859-1').split('\r\n')
        method, target, version = lines[0].split(' ', 2)
        if version not in {'HTTP/1.0', 'HTTP/1.1'}:
            raise ValueError('invalid_version')
        headers = []
        for line in lines[1:]:
            if not line or ':' not in line:
                raise ValueError('invalid_header')
            name, value = line.split(':', 1)
            if not name or '\n' in value or '\r' in value:
                raise ValueError('invalid_header')
            headers.append((name, value.strip()))
        return method.upper(), target, version, headers

    @staticmethod
    def _format_headers(headers, authority):
        safe = [f'Host: {authority}\r\n', 'Connection: close\r\n']
        for name, value in headers:
            if name.lower() not in {'host', 'connection', 'proxy-connection'}:
                safe.append(f'{name}: {value}\r\n')
        return ''.join(safe).encode('iso-8859-1')

    @staticmethod
    def _reject(client):
        try:
            client.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
        except OSError:
            pass

    @staticmethod
    def _method_not_allowed(client):
        try:
            client.sendall(
                b'HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\n'
                b'Connection: close\r\nContent-Length: 0\r\n\r\n',
            )
        except OSError:
            pass


class PolicyProxy:
    """Loopback-only browser proxy that pins every origin socket to a plan."""

    def __init__(self, policy, *, max_connections=4, idle_timeout=4.0):
        self.policy = policy
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self._server = None
        self._thread = None
        self._slots = threading.BoundedSemaphore(max_connections)
        self._active_relays = 0
        self._active_lock = threading.Lock()

    @property
    def address(self):
        if self._server is None:
            raise RuntimeError('proxy is not running')
        return self._server.server_address

    @property
    def url(self):
        host, port = self.address
        return f'http://{host}:{port}'

    @property
    def active_relays(self):
        with self._active_lock:
            return self._active_relays

    def start(self):
        if self._server is not None:
            return self
        self._server = _PolicyProxyServer(('127.0.0.1', 0), self)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self):
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=self.idle_timeout + 1)
        self._server = None
        self._thread = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_args):
        self.close()

    def _connect(self, plan):
        if not self._slots.acquire(blocking=False):
            raise OSError('proxy_busy')
        try:
            origin = socket.create_connection(
                (plan.selected_address, plan.port), timeout=plan.connect_timeout,
            )
            origin.settimeout(self.idle_timeout)
            return origin
        except Exception:
            self._slots.release()
            raise

    def _close_unrelayed_origin(self, origin):
        """Release an origin socket still owned by the request handler."""
        try:
            origin.close()
        finally:
            self._slots.release()

    def _relay(self, client, origin):
        with self._active_lock:
            self._active_relays += 1
        try:
            client.setblocking(False)
            origin.setblocking(False)
            selector = selectors.DefaultSelector()
            selector.register(client, selectors.EVENT_READ, origin)
            selector.register(origin, selectors.EVENT_READ, client)
            try:
                while selector.get_map():
                    events = selector.select(self.idle_timeout)
                    if not events:
                        return
                    for key, _mask in events:
                        source = key.fileobj
                        destination = key.data
                        try:
                            chunk = source.recv(64 * 1024)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            return
                        destination.sendall(chunk)
            finally:
                selector.close()
        finally:
            try:
                origin.close()
            finally:
                self._slots.release()
                with self._active_lock:
                    self._active_relays -= 1


class OutboundTransport:
    """Small redirect-owning transport which only sends pre-built plans.

    ``requester`` receives ``(method, url, **kwargs)`` and is intentionally
    injectable.  The production adapter supplies requests while tests can prove
    a rejected target reaches no network callback.
    """

    def __init__(self, policy, *, requester=None, ca_certs=None):
        self.policy = policy
        self._requester = requester
        self._ca_certs = ca_certs

    def request(self, url, purpose, *, method='GET', **kwargs):
        redirect_count = 0
        candidate = url
        while True:
            try:
                plan = self.policy.plan(candidate, purpose, redirect_count=redirect_count)
            except OutboundPolicyError as exc:
                if redirect_count:
                    redirect_error = OutboundPolicyError('redirect_not_allowed')
                    redirect_error.response = previous_response
                    raise redirect_error from exc
                raise
            if self._requester is not None:
                response = self._requester(
                    method,
                    plan.url,
                    timeout=(plan.connect_timeout, plan.read_timeout),
                    verify=plan.tls.verify_certificate,
                    allow_redirects=False,
                    **kwargs,
                )
            else:
                response = self._send_pinned(method, plan, **kwargs)
            location = getattr(response, 'headers', {}).get('Location')
            if not (300 <= response.status_code < 400 and location):
                return response, plan
            if plan.redirect_budget <= 0:
                raise OutboundPolicyError('redirect_not_allowed')
            redirect_count += 1
            candidate = urljoin(plan.url, location)
            previous_response = response

    def request_plan(self, plan, *, method='GET', **kwargs):
        """Send exactly one already-authorized, redirect-free pinned request."""
        if plan.purpose is not OutboundPurpose.WEBHOOK:
            raise OutboundPolicyError('target_not_allowed')
        if self._requester is not None:
            return self._requester(
                method, plan.url, timeout=(plan.connect_timeout, plan.read_timeout),
                verify=plan.tls.verify_certificate, allow_redirects=False, **kwargs,
            )
        return self._send_pinned(method, plan, **kwargs)

    def _send_pinned(self, method, plan, **kwargs):
        """Open exactly the validated numeric address, never the hostname.

        The URL authority stays at the HTTP and TLS layers while the pool host
        is the immutable numeric address selected by ``OutboundPolicy.plan``.
        This prevents a resolver call in urllib3 from changing the socket
        destination after policy approval.
        """
        headers = dict(kwargs.pop('headers', {}) or {})
        headers['Host'] = plan.authority
        body = kwargs.pop('data', None)
        payload = kwargs.pop('json', None)
        if payload is not None:
            if body is not None:
                raise ValueError('request body is ambiguous')
            body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            headers.setdefault('Content-Type', 'application/json')
        if kwargs:
            raise ValueError('unsupported outbound request option')

        timeout = Timeout(connect=plan.connect_timeout, read=plan.read_timeout)
        common = {
            'timeout': timeout,
            'retries': False,
            'headers': headers,
        }
        if plan.scheme == 'https':
            pool = HTTPSConnectionPool(
                plan.selected_address,
                plan.port,
                cert_reqs='CERT_REQUIRED' if plan.tls.verify_certificate else 'CERT_NONE',
                assert_hostname=plan.hostname if plan.tls.verify_certificate else False,
                server_hostname=plan.hostname,
                ca_certs=self._ca_certs,
                **common,
            )
        else:
            pool = HTTPConnectionPool(plan.selected_address, plan.port, **common)
        try:
            response = pool.urlopen(
                method.upper(),
                plan.path_query,
                body=body,
                redirect=False,
                preload_content=True,
            )
            return PinnedResponse(
                status_code=response.status,
                headers=response.headers,
                content=response.data,
                selected_address=plan.selected_address,
            )
        finally:
            pool.close()
