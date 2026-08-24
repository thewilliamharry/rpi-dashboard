"""Flask-facing compatibility adapters with no lifecycle side effects."""

from flask import Flask, jsonify

from .config import Settings, load_settings
from .db import connect_db, read_transaction, write_transaction
from . import maintenance
from . import repositories


def _window_response(row):
    """Translate a stored window row into the editor's response shape."""
    return {
        'id': row['id'],
        'start_minute': row['start_minute'],
        'duration_minutes': row['duration_minutes'],
        'weekdays': sorted(maintenance.parse_weekdays(row.get('weekdays'))),
        'grace_minutes': row['grace_minutes'],
        'enabled': bool(row['enabled']),
    }


def _suggestion_response(suggestion):
    """Translate the raw suggestion mapping into a JSON-safe response shape.

    The detector returns ``weekdays`` as a ``frozenset`` -- not
    JSON-serializable -- so this mirrors ``_window_response``'s sorted-list
    convention for the same field.
    """
    if suggestion is None:
        return None
    return {
        'occurrence_count': suggestion['occurrence_count'],
        'start_minute': suggestion['start_minute'],
        'duration_minutes': suggestion['duration_minutes'],
        'weekdays': sorted(suggestion['weekdays']),
    }


def metadata_response(
    conn, port, *, safe_url, path_from_url, parse_tags,
    now_epoch, tz_name, start_tolerance_seconds, duration_tolerance_seconds, lookback_days,
    default_grace_minutes,
):
    """Translate a repository row into the established metadata response shape.

    Recomputes the MNT-02 suggestion on every call (D-12: never frozen at
    first detection, never stored) from the port's recent state-change
    evidence, withholding it when it substantially overlaps a window the
    port already has enabled (RESEARCH Q3) so the operator is never asked to
    confirm what they already own. The ``suggestion`` key is always present:
    a mapping when a qualifying pattern exists, ``None`` otherwise -- an
    absence, never an empty-state object. The ``default_grace_minutes`` key
    is likewise always present: the deployment's configured default grace,
    in whole minutes, which is the prefill the editor offers for a NEW row
    -- it is never applied to a stored window's own grace value.
    """
    row = repositories.get_service_metadata(conn, port)
    if not row:
        return None
    row['url'] = safe_url(row.get('url'), port)
    row['path'] = path_from_url(row['url'], port)
    row['tags'] = parse_tags(row.get('tags'))
    row['critical'] = bool(row.get('critical'))
    stored_windows = repositories.get_maintenance_windows(conn, port)
    row['windows'] = [_window_response(window) for window in stored_windows]
    row['default_grace_minutes'] = int(default_grace_minutes)

    since_ts = int(now_epoch) - int(lookback_days) * 86400
    evidence = repositories.get_maintenance_suggestion_evidence(conn, port, since_ts=since_ts)
    suggestion = maintenance.detect_suggestion(
        evidence, tz_name, now_epoch=now_epoch,
        start_tolerance_seconds=start_tolerance_seconds,
        duration_tolerance_seconds=duration_tolerance_seconds,
    )
    if suggestion is not None and maintenance.suggestion_overlaps_enabled_window(
        suggestion, stored_windows, start_tolerance_seconds=start_tolerance_seconds,
    ):
        suggestion = None
    row['suggestion'] = _suggestion_response(suggestion)
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
