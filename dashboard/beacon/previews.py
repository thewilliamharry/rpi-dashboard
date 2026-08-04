"""Framework-free preview operation interfaces.

Browser creation stays behind injected callables so importing this module cannot
start Chromium.  The worker composition root supplies the one process-local
preview owner and persistence collaborators when a preview job actually runs.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Protocol

from .outbound import (
    OutboundPolicyError,
    OutboundPurpose,
    PolicyProxy,
    is_retrieval_method,
)


class ThumbnailResultRepository(Protocol):
    """Named persistence boundary for preview completion results."""

    def store_thumbnail_result(
        self, conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts=None,
    ) -> None: ...


@dataclass(frozen=True)
class PreviewOperations:
    """Explicit preview collaborators supplied by a composition root."""

    fetch_html_response: Callable
    extract_title: Callable
    get_browser: Callable
    shutdown_browser: Callable
    screenshot_service: Callable
    fetch_thumbnail: Callable
    thumbnail_repository: ThumbnailResultRepository
    refresh_service_preview: Callable


def fetch_html_response(operations, url, timeout=3, allow_remote=False):
    return operations.fetch_html_response(url, timeout, allow_remote)


def extract_title(operations, response, port):
    return operations.extract_title(response, port)


def get_browser(operations):
    return operations.get_browser()


def shutdown_browser(operations):
    return operations.shutdown_browser()


def screenshot_service(operations, port, target_url=None):
    return operations.screenshot_service(port, target_url)


def fetch_thumbnail(operations, port, service_url=None):
    return operations.fetch_thumbnail(port, service_url)


def store_thumbnail_result(operations, conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts=None):
    return operations.thumbnail_repository.store_thumbnail_result(
        conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts,
    )


def refresh_service_preview(operations, port, service_url):
    return operations.refresh_service_preview(port, service_url)


def route_browser_request(policy, route):
    """Gate every Chromium resource before its network continuation."""
    if not is_retrieval_method(getattr(route.request, 'method', None)):
        route.abort('blockedbyclient')
        return False
    try:
        policy.plan(route.request.url, OutboundPurpose.BROWSER_PREVIEW)
    except OutboundPolicyError:
        route.abort('blockedbyclient')
        return False
    route.continue_()
    return True


def block_browser_web_socket(web_socket_route):
    """Close preview sockets before Chromium can open an opaque tunnel."""
    close = getattr(web_socket_route, '_impl_obj', None)
    if close is not None:
        return close.close(code=1008, reason='preview policy')
    web_socket_route.close(code=1008, reason='preview policy')


def configure_browser_context_policy(context, policy):
    """Install every retrieval-only transport gate before pages are exposed."""
    context.route('**/*', lambda route: route_browser_request(policy, route))
    context.route_web_socket('**/*', block_browser_web_socket)


@contextmanager
def browser_proxy_context(browser, policy, **context_options):
    """Create one Chromium context with a short-lived enforcing proxy."""
    with PolicyProxy(policy) as proxy:
        context = browser.new_context(proxy={'server': proxy.url}, **context_options)
        configure_browser_context_policy(context, policy)
        try:
            yield context
        finally:
            context.close()
