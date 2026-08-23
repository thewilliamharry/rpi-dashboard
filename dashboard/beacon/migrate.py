"""One-shot operator command that brings the Beacon database schema current.

This module runs the single migration preparation boundary
(``beacon.db.prepare_database``) once and reports what it did. It is meant to
run as its own process, before any long-running Beacon process starts, so no
ordinary shared database-access lease can exist while migrations are being
applied.

Deliberately installs NO exception handling around the preparation call. An
unhandled exception writes the full traceback to standard error, and the
traceback's last line is the migration layer's own exception class and
message -- the schema version, the rejected structural fingerprint, and the
``beacon.inventory`` remediation command an operator needs. Wrapping this call
in a try/except to print a friendlier summary would replace that diagnostic
with a generic one, which is exactly the failure mode this module exists to
avoid: a real migration refusal reaching the operator as an opaque message
instead of its own explanation. Do not add a try/except here.
"""

import json
import sys

from .config import load_settings
from .db import prepare_database


def main(argv=None):
    settings = load_settings()
    result = prepare_database(settings)
    print(json.dumps({
        'applied_versions': list(result.applied_versions),
        'backups': [backup.name for backup in result.backups],
    }))
    return 0


if __name__ == '__main__':
    sys.exit(main())
