"""Framework-free preview operation interfaces.

Browser creation stays behind injected callables so importing this module cannot
start Chromium.  The worker composition root supplies the one process-local
preview owner and persistence collaborators when a preview job actually runs.
"""

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class PreviewOperations:
    """Explicit preview collaborators supplied by a composition root."""

    fetch_html_response: Callable
    extract_title: Callable
    get_browser: Callable
    shutdown_browser: Callable
    screenshot_service: Callable
    fetch_thumbnail: Callable
    store_thumbnail_result: Callable
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
    return operations.store_thumbnail_result(
        conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts,
    )


def refresh_service_preview(operations, port, service_url):
    return operations.refresh_service_preview(port, service_url)
