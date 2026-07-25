"""Flask-facing compatibility adapters with no lifecycle side effects."""

from flask import Flask, jsonify

from .config import Settings, load_settings
from .db import connect_db, read_transaction, write_transaction
from . import repositories


def metadata_response(conn, port, *, safe_url, path_from_url, parse_tags):
    """Translate a repository row into the established metadata response shape."""
    row = repositories.get_service_metadata(conn, port)
    if not row:
        return None
    row['url'] = safe_url(row.get('url'), port)
    row['path'] = path_from_url(row['url'], port)
    row['tags'] = parse_tags(row.get('tags'))
    row['critical'] = bool(row.get('critical'))
    return row


def register_compatibility_routes(app):
    """Register factory-owned routes exactly once without opening the database."""
    if app.extensions.get('beacon_routes_registered'):
        return

    @app.get('/healthz')
    def healthz():
        return jsonify({'status': 'configured'})

    app.extensions['beacon_routes_registered'] = True


def create_app(settings: Settings | None = None, *, legacy_app=None) -> Flask:
    """Build a side-effect-free Flask composition root.

    ``legacy_app`` is the temporary compatibility bridge while existing handlers
    continue to be extracted; it receives the same explicit service registry.
    """
    resolved_settings = settings or load_settings()
    app = legacy_app or Flask(__name__, static_folder=None)
    app.extensions['beacon'] = {
        'settings': resolved_settings,
        'connect_db': connect_db,
        'read_transaction': read_transaction,
        'write_transaction': write_transaction,
        'repositories': repositories,
    }
    if legacy_app is None:
        register_compatibility_routes(app)
    return app
