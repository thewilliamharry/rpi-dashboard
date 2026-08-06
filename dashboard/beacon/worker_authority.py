"""Immutable authority carried from worker lease acquisition to each write."""

from dataclasses import dataclass, field
from os import fspath
from pathlib import Path
import time
from typing import Callable


@dataclass(frozen=True)
class WorkerAuthority:
    """The exact durable epoch that may authorize worker-owned SQLite work.

    The epoch is intentionally omitted from representations and comparisons so
    diagnostics cannot accidentally publish a bearer-like durable credential.
    """

    db_path: str
    worker_id: str
    owner_token: str = field(repr=False, compare=False)
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    @classmethod
    def from_lease(cls, lease, db_path, *, clock=None):
        """Create one authority from the lease returned by acquisition."""
        return cls(
            db_path=str(Path(fspath(db_path)).expanduser().resolve()),
            worker_id=str(lease.worker_id),
            owner_token=str(lease.owner_token),
            clock=clock or time.time,
        )

    def now(self):
        """Return deterministic integer seconds from the injected clock."""
        return int(self.clock())
