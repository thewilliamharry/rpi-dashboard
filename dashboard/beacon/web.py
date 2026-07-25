"""Flask-facing compatibility adapters with no lifecycle side effects."""

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
