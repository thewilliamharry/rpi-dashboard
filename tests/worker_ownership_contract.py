"""Immutable ownership-closure inventory shared by Plans 01-21 through 01-23.

This module deliberately contains data only.  The RED matrix imports the same
rows that the later production-fencing plans must satisfy, so a callback cannot
quietly disappear from the definition of a worker-owned mutation.
"""

from dataclasses import dataclass


DATABASE_SURFACES = frozenset({
    'worker_owner',
    'worker_heartbeat',
    'runtime_state',
    'scan_state',
    'service_tls_posture',
    'scan_requests',
    'preview_requests',
    'services',
    'service_meta',
    'service_checks',
    'events',
    'system_stats',
    'stats_history',
    'scan_rate_hits',
    'telemetry_streams',
    'host_metric_rollups',
    'service_rollups',
    'telemetry_coverage',
    'telemetry_rollup_jobs',
    'thumbnails',
})

EFFECT_SURFACES = frozenset({
    'webhook_delivery',
    'thumbnail_publication',
    'filesystem_publication',
    'browser_resource_lifecycle',
})


@dataclass(frozen=True)
class OwnershipRow:
    """One production lifecycle callback and its required closure evidence."""

    identifier: str
    operation_fields: tuple[str, ...]
    invocation: str
    admission_category: str
    database_surfaces: tuple[str, ...]
    effect_surfaces: tuple[str, ...]
    pause_boundaries: tuple[str, ...]
    takeover_assertion_ids: tuple[str, ...]
    transaction_assertion_ids: tuple[str, ...]
    admission_assertion_ids: tuple[str, ...]
    effect_assertion_ids: tuple[str, ...]
    current_b_control_id: str | None
    ownership_required: bool
    regression_contracts: tuple[str, ...]


def _row(
    identifier, operation_fields, invocation, admission_category, database_surfaces,
    effect_surfaces, pause_boundaries, *, ownership_required=True,
    regressions=('Plan 19 lifecycle matrix', 'Wave 14 durable queue matrix'),
):
    """Give every ownership-required callback stable assertion identifiers."""
    prefix = identifier.lower()
    required = (identifier,) if ownership_required else ()
    return OwnershipRow(
        identifier=identifier,
        operation_fields=tuple(operation_fields),
        invocation=invocation,
        admission_category=admission_category,
        database_surfaces=tuple(database_surfaces),
        effect_surfaces=tuple(effect_surfaces),
        pause_boundaries=tuple(pause_boundaries),
        takeover_assertion_ids=tuple(f'{prefix}:takeover:{surface}' for surface in required),
        transaction_assertion_ids=tuple(f'{prefix}:transaction:{surface}' for surface in required),
        admission_assertion_ids=tuple(f'{prefix}:admission:{surface}' for surface in required),
        effect_assertion_ids=tuple(f'{prefix}:effect:{surface}' for surface in required),
        current_b_control_id=f'{prefix}:current-b-control' if ownership_required else None,
        ownership_required=ownership_required,
        regression_contracts=tuple(regressions),
    )


# P0 and L1 stay in this equality inventory even though their existing dedicated
# migration/recovery and lifecycle contracts own their dynamic proof.
PRODUCTION_OWNERSHIP_INVENTORY = (
    _row(
        'P0', ('prepare_database',), 'run_worker before lease acquisition', 'pre_epoch_preparation',
        (), ('filesystem_publication',), ('before_upgrade_maintenance',),
        ownership_required=False,
        regressions=('D-05/D-06/D-07 migration and recovery contracts',),
    ),
    _row(
        'S1', ('recover_worker_state',), 'first post-acquisition startup callback', 'startup',
        ('scan_requests', 'preview_requests', 'events', 'scan_state'), (),
        ('before_queue_recovery', 'before_gap_event', 'before_scan_state'),
    ),
    _row(
        'S2', ('update_worker_heartbeat', 'renew_worker_lease'), 'initial heartbeat', 'startup',
        ('worker_owner', 'worker_heartbeat'), ('browser_resource_lifecycle',),
        ('before_epoch_renewal', 'before_compatibility_heartbeat', 'before_stop_request'),
    ),
    _row(
        'S3', ('collect_system_stats',), 'initial metrics sample', 'startup',
        ('system_stats', 'stats_history', 'telemetry_streams', 'telemetry_coverage', 'runtime_state'), (), ('before_metric_write',),
    ),
    _row(
        'J1', ('update_worker_heartbeat', 'renew_worker_lease'), 'scheduler job heartbeat', 'scheduled',
        ('worker_owner', 'worker_heartbeat'), ('browser_resource_lifecycle',),
        ('before_epoch_renewal', 'before_compatibility_heartbeat', 'before_stop_request'),
    ),
    _row(
        'J2', ('collect_system_stats',), 'scheduler job metrics', 'scheduled',
        ('system_stats', 'stats_history', 'telemetry_streams', 'telemetry_coverage', 'runtime_state'), (), ('before_metric_write',),
    ),
    _row(
        'J3', ('do_uptime_check',), 'scheduler job uptime_all', 'scheduled',
        ('services', 'service_checks', 'service_tls_posture', 'preview_requests', 'events', 'scan_state', 'telemetry_streams', 'telemetry_coverage', 'runtime_state'),
        ('webhook_delivery',), ('before_service_transaction', 'before_preview_enqueue', 'before_transition', 'before_webhook'),
    ),
    _row(
        'J4', ('do_uptime_check',), 'scheduler job uptime_down', 'scheduled',
        ('services', 'service_checks', 'service_tls_posture', 'preview_requests', 'events', 'scan_state', 'telemetry_streams', 'telemetry_coverage', 'runtime_state'),
        ('webhook_delivery',), ('before_service_transaction', 'before_preview_enqueue', 'before_transition', 'before_webhook'),
    ),
    _row(
        'J5', ('process_scan_requests',), 'scheduler job scan_requests', 'scheduled',
        ('scan_requests', 'scan_state', 'services', 'service_meta', 'service_checks', 'service_tls_posture', 'events', 'preview_requests'),
        ('webhook_delivery',), ('before_claim', 'before_discovery_transaction', 'before_terminal_scan', 'before_webhook'),
    ),
    _row(
        'J6', ('process_preview_requests',), 'scheduler job preview_requests', 'scheduled',
        ('preview_requests', 'services', 'events', 'thumbnails'),
        ('thumbnail_publication', 'browser_resource_lifecycle'),
        ('before_preview_claim', 'before_browser_capture', 'before_preview_completion'),
    ),
    _row(
        'J7', ('run_discovery', 'read_scan_state'), 'scheduler job scheduled_discovery', 'scheduled',
        ('scan_state', 'events', 'services', 'service_meta', 'service_checks', 'service_tls_posture', 'preview_requests'),
        ('webhook_delivery',), ('before_scan_state', 'before_service_transaction', 'before_preview_enqueue', 'before_transition', 'before_webhook'),
    ),
    _row(
        'J8', ('cleanup_history',), 'scheduler job cleanup', 'scheduled',
        ('stats_history', 'service_checks', 'events', 'scan_rate_hits', 'host_metric_rollups', 'service_rollups', 'telemetry_streams', 'telemetry_coverage', 'telemetry_rollup_jobs', 'runtime_state', 'thumbnails'), (), ('before_cleanup_transaction',),
    ),
    _row(
        'J9', ('run_discovery', 'read_scan_state'), 'scheduler job startup_discovery', 'scheduled',
        ('scan_state', 'events', 'services', 'service_meta', 'service_checks', 'service_tls_posture', 'preview_requests'),
        ('webhook_delivery',), ('before_scan_state', 'before_service_transaction', 'before_preview_enqueue', 'before_transition', 'before_webhook'),
    ),
    _row(
        'L1', ('shutdown_browser', 'release_worker_lease'), 'worker terminal finalization', 'lifecycle_finalization',
        ('worker_owner',), ('browser_resource_lifecycle',),
        ('before_admission_close', 'before_drain', 'before_browser_cleanup', 'before_owner_release', 'before_global_reset'),
        ownership_required=False,
        regressions=('Plan 19 terminal-path and drain matrix',),
    ),
)

TAKEOVER_CASE_REGISTRY = {
    row.identifier: row
    for row in PRODUCTION_OWNERSHIP_INVENTORY
    if row.ownership_required
}

# A field can be a read-only gate or a durable-lease primitive.  It is still
# explicitly classified so adding a new WorkerOperations field fails static
# closure rather than becoming invisible to Plans 01-22/23.
OPERATION_FIELD_CLASSIFICATIONS = {
    'prepare_database': 'P0',
    'recover_worker_state': 'S1',
    'update_worker_heartbeat': 'S2,J1',
    'collect_system_stats': 'S3,J2',
    'read_scan_state': 'J7,J9',
    'run_discovery': 'J7,J9',
    'do_uptime_check': 'J3,J4',
    'process_scan_requests': 'J5',
    'process_preview_requests': 'J6',
    'cleanup_history': 'J8',
    'shutdown_browser': 'L1',
    'acquire_worker_lease': 'worker-acquisition-support',
    'renew_worker_lease': 'S2,J1',
    'release_worker_lease': 'L1',
}

# No post-acquisition production path publishes files today: screenshot bytes are
# retained in SQLite.  Keeping an explicit empty producer set prevents a future
# file writer from evading the closure registry by omitting this category.
EFFECT_PRODUCERS = {
    'webhook_delivery': frozenset({'J3', 'J4', 'J5', 'J7', 'J9'}),
    'thumbnail_publication': frozenset({'J6'}),
    'filesystem_publication': frozenset(),
    'browser_resource_lifecycle': frozenset({'S2', 'J1', 'J6', 'L1'}),
}

OWNER_FREE_WEB_CONTROLS = frozenset({
    'metadata_persistence_plus_preview_enqueue',
    'manual_scan_enqueue',
    'scan_rate_write',
    'meta_updated_event',
})
