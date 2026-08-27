'use strict';

const MAINTENANCE_OVERRUN_EVENT_TYPE = 'maintenance_overrun';
const EVENT_TYPES_VISIBLE = new Set(['state_change', 'alert_failed', 'meta_updated', 'monitoring_gap', MAINTENANCE_OVERRUN_EVENT_TYPE]);
const UI_HEADERS = {'X-Beacon-UI': '1'};
const WORKER_STALE_COPY = 'Monitoring paused — worker unavailable. Dashboard data may be stale; service settings changes are still saved.';
const DASHBOARD_SCROLL_KEY = 'beacon-dashboard-scroll-position';
let servicesByPort = new Map();
let editingService = null;
let modalReturnFocus = null;
let lastStatsSample = null;
let pollFailures = 0;
let workerWasStale = false;
let workerIsStale = false;
let scanSubmitting = false;
let suppressedEventsRevealed = false;

const $ = (id) => document.getElementById(id);

function fmtAgo(ts) {
  if (!ts) return 'unknown';
  const d = Math.max(0, Math.floor(Date.now() / 1000) - Number(ts));
  if (d < 5) return 'just now';
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}

function fmtLocalDateTime(ts) {
  if (ts === null || ts === undefined) return 'unknown';
  const date = new Date(Number(ts) * 1000);
  if (Number.isNaN(date.getTime())) return 'unknown';
  return date.toLocaleString();
}

function normalizedBytes(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? numeric : 0;
}

function fmtDecimalBytes(bytes, unit = 'GB') {
  const divisor = unit === 'TB' ? 1e12 : 1e9;
  return `${(normalizedBytes(bytes) / divisor).toFixed(1)} ${unit}`;
}

function fmtRamPair(used, total) {
  return `${fmtDecimalBytes(used)} / ${fmtDecimalBytes(total)}`;
}

function fmtDiskPair(used, total) {
  const unit = normalizedBytes(total) >= 1e12 ? 'TB' : 'GB';
  return `${fmtDecimalBytes(used, unit)} / ${fmtDecimalBytes(total, unit)}`;
}

globalThis.BeaconFormatters = Object.freeze({fmtDecimalBytes, fmtRamPair, fmtDiskPair});

function fmtLatency(ms) {
  return ms === null || ms === undefined ? 'n/a' : `${Math.round(ms)} ms`;
}

function uptimeLabel(value) {
  if (value === null || value === undefined) return 'unknown';
  const numeric = Number(value);
  if (numeric === 100) return '100%';
  const rounded = Number(numeric.toFixed(2));
  return `${numeric < 100 && rounded >= 100 ? '99.99' : numeric.toFixed(2)}%`;
}

function arcOffset(pct) {
  return 53 + 160.6 * (1 - Math.max(0, Math.min(100, Number(pct || 0))) / 100);
}

async function apiFetch(path, options = {}) {
  const response = await fetch(path, {cache: 'no-store', ...options});
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try { message = (await response.json()).error || message; } catch (_) { /* ignore */ }
    throw new Error(message);
  }
  return response.json();
}

function setConnectionState(disconnected) {
  $('connection-banner').hidden = !disconnected;
  document.body.classList.toggle('disconnected', disconnected);
}

function feedbackRegion() {
  let region = $('dashboard-feedback');
  if (!region) {
    region = Object.assign(document.createElement('div'), {id: 'dashboard-feedback', className: 'dashboard-feedback'});
    region.setAttribute('role', 'status');
    region.setAttribute('aria-live', 'polite');
    document.body.appendChild(region);
  }
  return region;
}

function updateWorkerWarning(stale) {
  $('worker-warning').textContent = WORKER_STALE_COPY;
  $('worker-warning').hidden = !stale;
  workerIsStale = stale;
  if (workerWasStale && !stale) {
    feedbackRegion().textContent = 'Monitoring resumed. The outage was recorded in Events.';
  }
  workerWasStale = stale;
}

function markPollSuccess() {
  pollFailures = 0;
}

function markPollFailure() {
  pollFailures += 1;
  if (pollFailures >= 2) setConnectionState(true);
}

function updateStats(data) {
  lastStatsSample = Number(data.sample_ts);
  $('tb-host').textContent = data.hostname || 'beacon';
  document.title = `${data.hostname || 'Beacon'} Beacon`;
  for (const key of ['cpu', 'ram', 'disk']) {
    $(`${key}-pct`).textContent = Math.round(Number(data[key]));
    $(`${key}-arc`).style.strokeDashoffset = arcOffset(data[key]);
  }
  $('ram-sub').textContent = fmtRamPair(data.ram_used, data.ram_total);
  $('disk-sub').textContent = fmtDiskPair(data.disk_used, data.disk_total);
  $('temp-val').textContent = data.temp === null ? 'n/a' : `${Number(data.temp).toFixed(1)}°C`;
  $('stats-ts').textContent = fmtAgo(data.sample_ts);
}

function updateHistory(rows) {
  for (const key of ['cpu', 'ram', 'disk']) {
    const values = rows.slice(-80).map((row) => Math.max(0, Math.min(100, Number(row[key] || 0))));
    if (!values.length) continue;
    const points = values.map((value, i) => `${(i / Math.max(1, values.length - 1)) * 200},${40 - value * 0.4}`).join(' ');
    const linePoints = points.replaceAll(' ', ' L');
    $(`${key}-sparkline`).setAttribute('d', `M${linePoints}`);
    $(`${key}-sparkfill`).setAttribute('d', `M0,40 L${linePoints} L200,40 Z`);
  }
}

function updateScanStatus(data) {
  const pip = $('scan-pip');
  pip.className = 'scan-pip';
  const workerReady = Boolean(data.worker_ready);
  setConnectionState(false);
  updateWorkerWarning(Boolean(data.worker_stale));
  $('recovery-warning').hidden = !Boolean(data.recovery_required);
  $('degraded-warning').hidden = !Boolean(data.worker_degraded);
  const requestStatus = data.latest_request_status;
  if (requestStatus === 'expired') {
    $('scan-label').textContent = 'Scan request expired — it was not run. Scan again.';
  } else if (data.stage === 'queued' || requestStatus === 'queued') {
    pip.classList.add('scanning');
    $('scan-label').textContent = 'Scan queued — runs when monitoring resumes';
  } else if (data.scanning || data.stage === 'running') {
    pip.classList.add('scanning');
    const pct = Math.round(Number(data.progress || 0) * 100);
    const found = Number(data.current_found || 0);
    $('scan-label').textContent = `${data.stage} ${pct}% · ${found} found`;
  } else if (workerReady) {
    pip.classList.add('ready');
    $('scan-label').textContent = `${Number(data.last_completed_found || 0)} found · ${data.last_discovery ? fmtAgo(data.last_discovery) : 'pending scan'}`;
  } else {
    $('scan-label').textContent = 'worker unavailable';
  }
  document.querySelector('.btn-scan').disabled = scanSubmitting || data.stage === 'running' || Boolean(data.scanning && data.stage !== 'queued');
}

function serviceHref(service) {
  try {
    const url = new URL(service.url, window.location.origin);
    if (['127.0.0.1', 'localhost', '::1'].includes(url.hostname)) url.hostname = window.location.hostname;
    return url.toString();
  } catch (_) {
    return `http://${window.location.hostname}:${service.port}/`;
  }
}

function uptimeStrip(values) {
  const wrapper = document.createElement('div');
  const strip = document.createElement('div');
  strip.className = 'uptime-strip';
  for (const value of values || []) {
    const segment = document.createElement('span');
    const n = Number(value);
    segment.className = `us ${n < 0 ? 'unknown' : n === 0 ? 'down' : n === 1 ? 'up' : 'partial'}`;
    // 05-04 Task 1 (A-18): the disclosure-only image role plus an
    // aria-label computed once and assigned to both attributes, so the
    // hover title and the accessible name can never drift apart. Not made
    // focusable -- a 7-day strip on every service card would insert dozens
    // of new stops into the main dashboard's primary keyboard flow.
    const text = n < 0 ? 'No data' : `${(n * 100).toFixed(n === 1 ? 0 : 1)}% available`;
    segment.setAttribute('role', 'img');
    segment.setAttribute('title', text);
    segment.setAttribute('aria-label', text);
    strip.appendChild(segment);
  }
  const labels = document.createElement('div');
  labels.className = 'uptime-labels';
  labels.append(Object.assign(document.createElement('span'), {textContent: '7d ago'}), Object.assign(document.createElement('span'), {textContent: 'now'}));
  wrapper.append(strip, labels);
  return wrapper;
}

function serviceCardAvailability(service) {
  // Fail-closed: only the recognised 'maintenance' literal ever produces the
  // calm state. Anything else (unset, 'online', 'offline', or an unrecognised
  // future value) falls back to the true is_online-derived classification, so
  // an unknown literal can never be coerced into the calm treatment (D-06).
  const raw = String(service.availability || '').toLowerCase();
  if (raw === 'maintenance') return 'maintenance';
  return service.is_online ? 'online' : 'offline';
}

function buildServiceCard(service) {
  const online = Boolean(service.is_online);
  const availability = serviceCardAvailability(service);
  const maintenance = availability === 'maintenance';
  const card = document.createElement('article');
  card.className = maintenance ? 'svc-card svc-maintenance' : `svc-card${online ? '' : ' offline'}`;

  const link = document.createElement('a');
  link.className = 'svc-link';
  link.href = serviceHref(service);
  link.setAttribute('aria-label', `Open ${service.display_name || service.title || `port ${service.port}`}`);
  const preview = document.createElement('div');
  preview.className = 'svc-preview';
  const fallback = document.createElement('div');
  fallback.className = 'svc-preview-fallback';
  fallback.style.display = service.has_thumb ? 'none' : 'flex';
  const fallbackPort = document.createElement('span');
  fallbackPort.className = 'fallback-port';
  fallbackPort.textContent = `:${service.port}`;
  fallback.append(fallbackPort, Object.assign(document.createElement('span'), {textContent: 'NO PREVIEW'}));
  if (service.has_thumb) {
    const image = document.createElement('img');
    image.className = 'svc-thumb';
    image.alt = '';
    image.src = `/api/thumbnail/${service.port}?v=${service.last_seen || 0}`;
    image.addEventListener('error', () => { image.remove(); fallback.style.display = 'flex'; });
    preview.appendChild(image);
  }
  preview.append(fallback, Object.assign(document.createElement('div'), {className: 'preview-fade'}));
  link.appendChild(preview);

  const meta = document.createElement('div');
  meta.className = 'svc-meta';
  const titleRow = document.createElement('div');
  titleRow.className = 'svc-title-row';
  const titleLink = document.createElement('a');
  titleLink.className = 'svc-title svc-title-link';
  titleLink.href = link.href;
  titleLink.textContent = service.display_name || service.title || `:${service.port}`;
  const actions = document.createElement('div');
  actions.className = 'svc-title-right';
  if (service.critical) actions.appendChild(Object.assign(document.createElement('span'), {className: 'svc-critical', textContent: 'critical'}));
  actions.appendChild(Object.assign(document.createElement('span'), {className: 'svc-port-badge', textContent: `:${service.port}`}));
  if (service.tls_unverified) {
    const tls = Object.assign(document.createElement('span'), {className: 'svc-tls-unverified', textContent: 'TLS'});
    tls.title = 'TLS certificate is not verified for this trusted local service.';
    tls.setAttribute('aria-label', 'TLS certificate is not verified for this trusted local service.');
    actions.appendChild(tls);
  }
  const edit = Object.assign(document.createElement('button'), {className: 'svc-edit', type: 'button', textContent: 'Edit'});
  edit.setAttribute('aria-label', 'Edit service');
  edit.dataset.port = String(service.port);
  edit.addEventListener('click', () => openMetaEditor(service, edit));
  actions.appendChild(edit);
  titleRow.append(titleLink, actions);

  const statusRow = document.createElement('div');
  statusRow.className = 'svc-status-row';
  const status = document.createElement('span');
  status.className = maintenance ? 'svc-maintenance-status' : (online ? 'svc-online' : 'svc-offline');
  status.append(Object.assign(document.createElement('span'), {className: 'status-pip'}), Object.assign(document.createElement('span'), {textContent: maintenance ? 'MAINTENANCE' : (online ? 'ONLINE' : 'OFFLINE')}));
  if (maintenance) {
    status.title = `Offline and covered by a confirmed maintenance window until ${fmtLocalDateTime(service.maintenance_until)}. Downtime is still counted in the 7-day availability figure.`;
  }
  const since = Object.assign(document.createElement('span'), {className: 'svc-since', textContent: `${online ? 'up' : 'down'} since ${fmtAgo(service.state_since)}`});
  statusRow.append(status, since);

  const detail = document.createElement('div');
  detail.className = 'svc-detail-row';
  const detailLeft = Object.assign(document.createElement('span'), {
    className: online ? 'svc-latency' : 'svc-error',
    textContent: online ? fmtLatency(service.latency_ms) : (service.last_error || 'probe failed').replaceAll('_', ' '),
  });
  const uptime = Object.assign(document.createElement('span'), {className: 'svc-uptime-pct', textContent: `7d ${uptimeLabel(service.uptime_pct)}`});
  detail.append(detailLeft, uptime);
  meta.append(titleRow, statusRow, detail);
  if (service.tags?.length) meta.appendChild(Object.assign(document.createElement('div'), {className: 'svc-tags', textContent: service.tags.join(' · ')}));
  const previewCopy = {
    queued: 'Preview refresh queued',
    running: 'Refreshing preview',
    failed: 'Preview refresh failed — saved settings are unaffected',
    expired: 'Preview refresh expired — save service details to request a new preview.',
  }[service.preview_status];
  if (previewCopy) meta.appendChild(Object.assign(document.createElement('div'), {className: 'svc-preview-status', textContent: previewCopy}));
  meta.appendChild(uptimeStrip(service.uptime_buckets));
  card.append(link, meta);
  return card;
}

function updateServices(services) {
  servicesByPort = new Map(services.map((service) => [Number(service.port), service]));
  const grid = $('services-grid');
  grid.replaceChildren();
  if (!services.length) {
    const empty = Object.assign(document.createElement('div'), {className: 'svc-empty'});
    empty.append(
      Object.assign(document.createElement('strong'), {textContent: 'No HTTP services discovered'}),
      Object.assign(document.createElement('span'), {textContent: 'Run a scan to look for configured services.'}),
    );
    grid.appendChild(empty);
  }
  else services.forEach((service) => grid.appendChild(buildServiceCard(service)));
  const online = services.filter((service) => service.is_online).length;
  $('svc-count-label').textContent = `${online}/${services.length} online`;
}

function monitoringGapDuration(event) {
  try {
    const details = JSON.parse(event.details || '{}');
    const seconds = Math.max(0, Number(details.end_ts) - Number(details.start_ts));
    return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  } catch (_) {
    return 'an unknown duration';
  }
}

function isOverrunEvent(event) {
  return event.event_type === MAINTENANCE_OVERRUN_EVENT_TYPE;
}

function isSuppressedEvent(event) {
  // The overrun outage is excluded from the suppressed partition
  // unconditionally, regardless of any other field it carries (MNT-04) --
  // it must never be tagged Expected or hidden behind the reveal control.
  return !isOverrunEvent(event) && Boolean(event.suppressed_reason);
}

function eventTitle(event) {
  if (isOverrunEvent(event)) return `${event.service_name} still down past maintenance`;
  if (event.event_type === 'state_change') return `${event.service_name} ${event.online ? 'recovered' : 'went down'}`;
  if (event.event_type === 'monitoring_gap') return 'Monitoring gap recorded';
  return event.event_type.replaceAll('_', ' ');
}

function renderEvents(events) {
  const visible = events.filter((event) => EVENT_TYPES_VISIBLE.has(event.event_type)).slice(0, 20);
  const suppressedCount = visible.filter(isSuppressedEvent).length;
  const panel = $('events-panel');
  panel.replaceChildren();

  // Suppressed entries are always retained and always counted; they are
  // filtered at render time only -- the reveal control is the only signal
  // that the feed is not showing everything (D-10). It is not rendered at
  // all when zero suppressed entries are loaded, and its own label always
  // states the exact hidden count.
  if (suppressedCount > 0) {
    const reveal = document.createElement('button');
    reveal.type = 'button';
    reveal.className = 'evt-reveal';
    reveal.textContent = suppressedEventsRevealed
      ? 'Hide suppressed entries'
      : suppressedCount === 1
        ? 'Show 1 suppressed entry'
        : `Show ${suppressedCount} suppressed entries`;
    reveal.addEventListener('click', () => {
      suppressedEventsRevealed = !suppressedEventsRevealed;
      renderEvents(events);
    });
    panel.appendChild(reveal);
  }

  const rendered = visible.filter((event) => suppressedEventsRevealed || !isSuppressedEvent(event));
  if (!rendered.length) panel.appendChild(Object.assign(document.createElement('div'), {className: 'evt-empty', textContent: 'no recent incidents'}));
  for (const event of rendered) {
    const overrun = isOverrunEvent(event);
    const suppressed = isSuppressedEvent(event);
    const row = document.createElement('div');
    const state = overrun ? 'down' : event.event_type === 'state_change' ? (event.online ? 'up' : 'down') : event.event_type;
    row.className = `evt-row evt-${state}`;
    const left = document.createElement('div');
    left.className = 'evt-left';
    left.appendChild(Object.assign(document.createElement('span'), {className: 'evt-title', textContent: eventTitle(event)}));
    if (suppressed) {
      left.appendChild(Object.assign(document.createElement('span'), {className: 'evt-pill evt-pill-expected', textContent: 'Expected'}));
    }
    if (overrun) {
      // D-08: down-since and raised-at are always two separately rendered
      // values, never merged into one truncatable string.
      left.append(
        Object.assign(document.createElement('span'), {className: 'evt-sub', textContent: `Down since ${fmtLocalDateTime(event.down_since_ts)}`}),
        Object.assign(document.createElement('span'), {className: 'evt-sub', textContent: `Raised at ${fmtLocalDateTime(event.ts)}`}),
      );
    } else {
      left.appendChild(Object.assign(document.createElement('span'), {className: 'evt-sub', textContent: event.event_type === 'monitoring_gap' ? `Worker unavailable for ${monitoringGapDuration(event)}.` : event.details || event.error_class || ''}));
    }
    row.append(left, Object.assign(document.createElement('span'), {className: 'evt-time', textContent: fmtAgo(event.ts)}));
    panel.appendChild(row);
  }
  // Loaded count, not just the currently-rendered count -- a suppressed
  // entry stays counted here even while collapsed (D-10).
  $('events-label').textContent = `${visible.length} recent`;
}

const MAINTENANCE_WEEKDAYS = [
  {abbr: 'Mo', label: 'Monday', iso: 1},
  {abbr: 'Tu', label: 'Tuesday', iso: 2},
  {abbr: 'We', label: 'Wednesday', iso: 3},
  {abbr: 'Th', label: 'Thursday', iso: 4},
  {abbr: 'Fr', label: 'Friday', iso: 5},
  {abbr: 'Sa', label: 'Saturday', iso: 6},
  {abbr: 'Su', label: 'Sunday', iso: 7},
];
// The fail-closed fallback used until the server's configured default_grace_minutes
// arrives, and whenever a metadata fetch fails outright. This deliberately matches
// the server's own documented default (config.py) so the two cannot drift apart
// silently. Once a fetch has successfully published a value, it is retained here
// -- a later failed fetch must NOT reset it, because the setting is a deployment-wide
// fact (SETTINGS.maintenance_default_grace_minutes), not stale per-service data.
let currentDefaultGraceMinutes = 15;
const MAINTENANCE_GRACE_HELP = 'How long the service may stay down after this window ends before Beacon raises a real outage.';
let currentSuggestion = null;

function minutesToTimeValue(minutes) {
  const total = Number(minutes);
  if (!Number.isFinite(total) || total < 0) return '';
  const hours = Math.floor(total / 60) % 24;
  const mins = Math.floor(total % 60);
  return `${String(hours).padStart(2, '0')}:${String(mins).padStart(2, '0')}`;
}

function timeValueToMinutes(value) {
  const match = /^(\d{2}):(\d{2})$/.exec(value || '');
  if (!match) return null;
  return Number(match[1]) * 60 + Number(match[2]);
}

function updateMaintenanceWindowCount() {
  const rowCount = $('meta-window-list').children.length;
  $('meta-window-count').hidden = rowCount === 0;
  $('meta-window-empty').hidden = rowCount !== 0;
  if (rowCount > 0) {
    $('meta-window-count').textContent = rowCount === 1 ? '1 maintenance window' : `${rowCount} maintenance windows`;
  }
}

function addMaintenanceWindowRow(values) {
  const isNewRow = !values;
  const data = values || {};
  const row = document.createElement('div');
  row.className = 'meta-window-row';

  const startField = document.createElement('label');
  startField.className = 'meta-field';
  const startInput = document.createElement('input');
  startInput.type = 'time';
  startInput.className = 'meta-window-start';
  startInput.value = data.start_minute === undefined ? '' : minutesToTimeValue(data.start_minute);
  startField.append(
    Object.assign(document.createElement('span'), {className: 'meta-label', textContent: 'Start'}),
    startInput,
  );

  const durationField = document.createElement('label');
  durationField.className = 'meta-field';
  const durationInput = document.createElement('input');
  durationInput.type = 'number';
  durationInput.min = '1';
  durationInput.className = 'meta-window-duration';
  durationInput.value = data.duration_minutes === undefined ? '' : String(data.duration_minutes);
  durationField.append(
    Object.assign(document.createElement('span'), {className: 'meta-label', textContent: 'Duration (minutes)'}),
    durationInput,
  );

  const weekdaysField = document.createElement('div');
  weekdaysField.className = 'meta-field meta-window-weekdays';
  const chipsWrap = document.createElement('div');
  chipsWrap.className = 'meta-weekday-chips';
  const selectedDays = new Set((data.weekdays || []).map(Number));
  for (const day of MAINTENANCE_WEEKDAYS) {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'meta-weekday-chip';
    chip.textContent = day.abbr;
    chip.setAttribute('aria-label', day.label);
    chip.dataset.iso = String(day.iso);
    chip.setAttribute('aria-pressed', String(selectedDays.has(day.iso)));
    chip.addEventListener('click', () => {
      const pressed = chip.getAttribute('aria-pressed') === 'true';
      chip.setAttribute('aria-pressed', String(!pressed));
    });
    chipsWrap.appendChild(chip);
  }
  weekdaysField.append(
    Object.assign(document.createElement('span'), {className: 'meta-label', textContent: 'Weekdays'}),
    chipsWrap,
  );

  const graceField = document.createElement('label');
  graceField.className = 'meta-field';
  const graceInput = document.createElement('input');
  graceInput.type = 'number';
  graceInput.min = '0';
  graceInput.className = 'meta-window-grace';
  graceInput.value = data.grace_minutes === undefined ? String(currentDefaultGraceMinutes) : String(data.grace_minutes);
  graceField.append(
    Object.assign(document.createElement('span'), {className: 'meta-label', textContent: 'Grace period (minutes)'}),
    graceInput,
    Object.assign(document.createElement('span'), {className: 'meta-help', textContent: MAINTENANCE_GRACE_HELP}),
  );

  const enabledField = document.createElement('label');
  enabledField.className = 'meta-field meta-checkbox';
  const enabledInput = document.createElement('input');
  enabledInput.type = 'checkbox';
  enabledInput.className = 'meta-window-enabled';
  enabledInput.checked = data.enabled !== false;
  enabledInput.addEventListener('change', () => {
    row.classList.toggle('is-disabled', !enabledInput.checked);
  });
  enabledField.append(enabledInput, Object.assign(document.createElement('span'), {textContent: 'Enabled'}));

  const removeButton = document.createElement('button');
  removeButton.type = 'button';
  removeButton.className = 'meta-window-remove';
  removeButton.textContent = 'Remove';
  let armed = false;
  removeButton.addEventListener('click', () => {
    if (!armed) {
      armed = true;
      removeButton.textContent = 'Confirm remove';
      return;
    }
    row.remove();
    updateMaintenanceWindowCount();
  });

  row.classList.toggle('is-disabled', data.enabled === false);
  row.append(startField, durationField, weekdaysField, graceField, enabledField, removeButton);
  $('meta-window-list').appendChild(row);
  if (isNewRow) startInput.focus();
  return row;
}

function renderMaintenanceWindows(windows) {
  $('meta-window-list').replaceChildren();
  for (const entry of windows || []) addMaintenanceWindowRow(entry);
  updateMaintenanceWindowCount();
}

function readMaintenanceWindows() {
  return [...$('meta-window-list').children].map((row) => ({
    start_minute: timeValueToMinutes(row.querySelector('.meta-window-start').value),
    duration_minutes: Number(row.querySelector('.meta-window-duration').value),
    weekdays: [...row.querySelectorAll('.meta-weekday-chip')]
      .filter((chip) => chip.getAttribute('aria-pressed') === 'true')
      .map((chip) => Number(chip.dataset.iso))
      .sort((a, b) => a - b),
    grace_minutes: Number(row.querySelector('.meta-window-grace').value),
    enabled: row.querySelector('.meta-window-enabled').checked,
  }));
}

function formatSuggestionWeekdays(weekdays) {
  const selected = new Set((weekdays || []).map(Number));
  return MAINTENANCE_WEEKDAYS.filter((day) => selected.has(day.iso)).map((day) => day.label).join(', ');
}

function renderMaintenanceSuggestion(suggestion) {
  currentSuggestion = suggestion || null;
  if (!currentSuggestion) {
    $('meta-suggestion').hidden = true;
    return;
  }
  const start = minutesToTimeValue(currentSuggestion.start_minute);
  const end = minutesToTimeValue((currentSuggestion.start_minute + currentSuggestion.duration_minutes) % 1440);
  const weekdays = formatSuggestionWeekdays(currentSuggestion.weekdays);
  $('meta-suggestion-evidence').textContent =
    `Beacon observed ${currentSuggestion.occurrence_count} similar restarts recently, typically around ${start}–${end} on ${weekdays}.`;
  $('meta-suggestion').hidden = false;
}

async function loadMaintenanceWindowsForEditor(service) {
  let windows = service.windows || [];
  let suggestion = null;
  try {
    const meta = await apiFetch(`/api/service-meta/${service.port}`);
    windows = meta.windows || [];
    suggestion = meta.suggestion || null;
    // Server-global setting, not per-service: a value already learned from a
    // previous successful fetch is deliberately retained if a later fetch for
    // a different service fails (see the comment on the binding's declaration).
    if (Number.isFinite(meta.default_grace_minutes) && meta.default_grace_minutes >= 0) {
      currentDefaultGraceMinutes = meta.default_grace_minutes;
    }
  } catch (_) {
    windows = service.windows || [];
  }
  if (!editingService || editingService.port !== service.port) return;
  renderMaintenanceWindows(windows);
  renderMaintenanceSuggestion(suggestion);
}

function openMetaEditor(service, returnFocus) {
  editingService = service;
  modalReturnFocus = returnFocus || document.activeElement;
  $('meta-modal-port').textContent = `:${service.port}`;
  $('meta-display-name').value = service.display_name || '';
  $('meta-path').value = service.path || '/';
  $('meta-critical').checked = Boolean(service.critical);
  $('meta-tags').value = (service.tags || []).join(', ');
  $('meta-url').value = service.url || '';
  $('meta-healthy-statuses').value = service.healthy_statuses || '200-399';
  $('meta-window-list').replaceChildren();
  $('meta-window-count').hidden = true;
  $('meta-window-empty').hidden = true;
  $('meta-suggestion').hidden = true;
  currentSuggestion = null;
  $('meta-error').hidden = true;
  $('meta-stale-warning').hidden = !workerIsStale;
  $('meta-modal').hidden = false;
  document.body.classList.add('modal-open');
  $('meta-display-name').focus();
  loadMaintenanceWindowsForEditor(service);
}

function closeMetaEditor() {
  const returnPort = editingService?.port;
  $('meta-modal').hidden = true;
  document.body.classList.remove('modal-open');
  editingService = null;
  $('meta-suggestion').hidden = true;
  currentSuggestion = null;
  const focusTarget = modalReturnFocus?.isConnected
    ? modalReturnFocus
    : document.querySelector(`.svc-edit[data-port="${returnPort}"]`);
  focusTarget?.focus();
}

function confirmMaintenanceSuggestion() {
  if (!currentSuggestion) return;
  addMaintenanceWindowRow({
    start_minute: currentSuggestion.start_minute,
    duration_minutes: currentSuggestion.duration_minutes,
    weekdays: currentSuggestion.weekdays,
    grace_minutes: currentDefaultGraceMinutes,
    enabled: true,
  });
  updateMaintenanceWindowCount();
  $('meta-suggestion').hidden = true;
}

function adjustMaintenanceSuggestion() {
  if (!currentSuggestion) return;
  const row = addMaintenanceWindowRow({
    start_minute: currentSuggestion.start_minute,
    duration_minutes: currentSuggestion.duration_minutes,
    weekdays: currentSuggestion.weekdays,
    grace_minutes: currentDefaultGraceMinutes,
    enabled: true,
  });
  updateMaintenanceWindowCount();
  row.querySelector('.meta-window-start').focus();
  $('meta-suggestion').hidden = true;
}

async function submitMetaEditor(event) {
  event.preventDefault();
  if (!editingService) return;
  const save = $('meta-save');
  save.disabled = true;
  try {
    const payload = {
      display_name: $('meta-display-name').value.trim(),
      path: $('meta-path').value.trim() || '/',
      critical: $('meta-critical').checked,
      tags: $('meta-tags').value.trim(),
      url: $('meta-url').value.trim(),
      healthy_statuses: $('meta-healthy-statuses').value.trim(),
      maintenance_windows: readMaintenanceWindows(),
    };
    const updated = await apiFetch(`/api/service-meta/${editingService.port}`, {
      method: 'PUT', headers: {...UI_HEADERS, 'Content-Type': 'application/json'}, body: JSON.stringify(payload),
    });
    const merged = {...editingService, ...updated};
    servicesByPort.set(Number(merged.port), merged);
    updateServices([...servicesByPort.values()]);
    const previewQueued = updated.preview_queued || Boolean(updated.refresh_warning);
    feedbackRegion().textContent = previewQueued
      ? 'Service details saved. Preview refresh queued.'
      : 'Service details saved.';
    closeMetaEditor();
  } catch (error) {
    const windowMessage = typeof error.message === 'string' && /^Window \d+: /.test(error.message) ? error.message : null;
    $('meta-error').textContent = windowMessage || 'Beacon could not use that destination. Review the service details and try again.';
    $('meta-error').hidden = false;
    $('meta-error').focus();
  } finally {
    save.disabled = false;
  }
}

function trapModalFocus(event) {
  if (event.key === 'Escape') return closeMetaEditor();
  if (event.key !== 'Tab') return;
  const focusable = [...$('meta-modal').querySelectorAll('button,input,summary,[href],[tabindex]:not([tabindex="-1"])')].filter((element) => !element.disabled);
  if (!focusable.length) return;
  const first = focusable[0], last = focusable.at(-1);
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
}

async function loadStats() { try { updateStats(await apiFetch('/api/stats')); markPollSuccess(); } catch (_) { markPollFailure(); } }
async function loadHistory() { try { updateHistory(await apiFetch('/api/history')); } catch (_) { markPollFailure(); } }
async function loadScan() { try { updateScanStatus(await apiFetch('/api/scan-status')); markPollSuccess(); } catch (_) { markPollFailure(); } }
async function loadServices() { try { updateServices(await apiFetch('/api/services')); } catch (_) { markPollFailure(); } }
async function loadEvents() { try { renderEvents(await apiFetch('/api/events?limit=50')); } catch (_) { markPollFailure(); } }

async function triggerScan() {
  const button = document.querySelector('.btn-scan');
  scanSubmitting = true;
  button.disabled = true;
  try {
    await apiFetch('/api/trigger-scan', {method: 'POST', headers: UI_HEADERS});
    await loadScan();
  } catch (error) {
    $('scan-label').textContent = 'Scan request could not be queued. Try again.';
  } finally {
    scanSubmitting = false;
    await loadScan();
  }
}

function applyTheme(light) {
  document.documentElement.classList.toggle('light', light);
  $('toggle').setAttribute('aria-pressed', String(light));
  localStorage.setItem('beacon-theme', light ? 'light' : 'dark');
}

function captureDashboardScroll() {
  const offset = Math.floor(window.scrollY);
  if (Number.isFinite(offset) && offset >= 0) sessionStorage.setItem(DASHBOARD_SCROLL_KEY, String(offset));
}

function restoreDashboardScroll() {
  const stored = sessionStorage.getItem(DASHBOARD_SCROLL_KEY);
  sessionStorage.removeItem(DASHBOARD_SCROLL_KEY);
  if (!stored || !/^\d+$/.test(stored)) return;
  const offset = Number(stored);
  if (!Number.isFinite(offset) || offset < 0 || !Number.isInteger(offset)) return;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    window.scrollTo(0, offset);
    const link = $('advanced-diagnosis-link');
    try { link.focus({preventScroll: true}); } catch (_) { link.focus(); }
  }));
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(localStorage.getItem('beacon-theme') === 'light');
    restoreDashboardScroll();
    $('toggle').addEventListener('click', () => applyTheme(!document.documentElement.classList.contains('light')));
    $('advanced-diagnosis-link').addEventListener('click', captureDashboardScroll);
    document.querySelector('.btn-scan').addEventListener('click', triggerScan);
    $('meta-form').addEventListener('submit', submitMetaEditor);
    $('meta-cancel').addEventListener('click', closeMetaEditor);
    $('meta-window-add').addEventListener('click', () => {
      addMaintenanceWindowRow();
      updateMaintenanceWindowCount();
    });
    $('meta-suggestion-confirm').addEventListener('click', confirmMaintenanceSuggestion);
    $('meta-suggestion-adjust').addEventListener('click', adjustMaintenanceSuggestion);
    $('meta-modal').addEventListener('click', (event) => { if (event.target === $('meta-modal')) closeMetaEditor(); });
    $('meta-modal').addEventListener('keydown', trapModalFocus);
    Promise.allSettled([loadStats(), loadHistory(), loadScan(), loadServices(), loadEvents()]);
    setInterval(() => { loadStats(); loadScan(); }, 5000);
    setInterval(() => { loadServices(); loadEvents(); }, 15000);
    setInterval(loadHistory, 60000);
    setInterval(() => {
      if (lastStatsSample) {
        $('stats-ts').textContent = fmtAgo(lastStatsSample);
        if (Date.now() / 1000 - lastStatsSample > 20) setConnectionState(true);
      }
    }, 1000);
  });
}
