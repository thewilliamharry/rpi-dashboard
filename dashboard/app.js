'use strict';

const EVENT_TYPES_VISIBLE = new Set(['state_change', 'alert_failed', 'meta_updated', 'monitoring_gap']);
const UI_HEADERS = {'X-Beacon-UI': '1'};
const WORKER_STALE_COPY = 'Monitoring paused — worker unavailable. Dashboard data may be stale; service settings changes are still saved.';
let servicesByPort = new Map();
let editingService = null;
let modalReturnFocus = null;
let lastStatsSample = null;
let pollFailures = 0;
let workerWasStale = false;
let workerIsStale = false;
let scanSubmitting = false;

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
    segment.title = n < 0 ? 'No data' : `${(n * 100).toFixed(n === 1 ? 0 : 1)}% available`;
    strip.appendChild(segment);
  }
  const labels = document.createElement('div');
  labels.className = 'uptime-labels';
  labels.append(Object.assign(document.createElement('span'), {textContent: '7d ago'}), Object.assign(document.createElement('span'), {textContent: 'now'}));
  wrapper.append(strip, labels);
  return wrapper;
}

function buildServiceCard(service) {
  const online = Boolean(service.is_online);
  const card = document.createElement('article');
  card.className = `svc-card${online ? '' : ' offline'}`;

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
    const tls = Object.assign(document.createElement('span'), {className: 'svc-tls-unverified', textContent: 'TLS unverified'});
    tls.title = 'TLS certificate is not verified for this trusted local service.';
    tls.setAttribute('aria-label', 'TLS certificate is not verified for this trusted local service.');
    actions.appendChild(tls);
  }
  const edit = Object.assign(document.createElement('button'), {className: 'svc-edit', type: 'button', textContent: 'Edit service'});
  edit.dataset.port = String(service.port);
  edit.addEventListener('click', () => openMetaEditor(service, edit));
  actions.appendChild(edit);
  titleRow.append(titleLink, actions);

  const statusRow = document.createElement('div');
  statusRow.className = 'svc-status-row';
  const status = document.createElement('span');
  status.className = online ? 'svc-online' : 'svc-offline';
  status.append(Object.assign(document.createElement('span'), {className: 'status-pip'}), Object.assign(document.createElement('span'), {textContent: online ? 'ONLINE' : 'OFFLINE'}));
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

function renderEvents(events) {
  const visible = events.filter((event) => EVENT_TYPES_VISIBLE.has(event.event_type)).slice(0, 20);
  const panel = $('events-panel');
  panel.replaceChildren();
  if (!visible.length) panel.appendChild(Object.assign(document.createElement('div'), {className: 'evt-empty', textContent: 'no recent incidents'}));
  for (const event of visible) {
    const row = document.createElement('div');
    const state = event.event_type === 'state_change' ? (event.online ? 'up' : 'down') : event.event_type;
    row.className = `evt-row evt-${state}`;
    const left = document.createElement('div');
    left.className = 'evt-left';
    left.append(
      Object.assign(document.createElement('span'), {className: 'evt-title', textContent: event.event_type === 'state_change' ? `${event.service_name} ${event.online ? 'recovered' : 'went down'}` : event.event_type === 'monitoring_gap' ? 'Monitoring gap recorded' : event.event_type.replaceAll('_', ' ')}),
      Object.assign(document.createElement('span'), {className: 'evt-sub', textContent: event.event_type === 'monitoring_gap' ? `Worker unavailable for ${monitoringGapDuration(event)}.` : event.details || event.error_class || ''}),
    );
    row.append(left, Object.assign(document.createElement('span'), {className: 'evt-time', textContent: fmtAgo(event.ts)}));
    panel.appendChild(row);
  }
  $('events-label').textContent = `${visible.length} recent`;
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
  $('meta-error').hidden = true;
  $('meta-stale-warning').hidden = !workerIsStale;
  $('meta-modal').hidden = false;
  document.body.classList.add('modal-open');
  $('meta-display-name').focus();
}

function closeMetaEditor() {
  const returnPort = editingService?.port;
  $('meta-modal').hidden = true;
  document.body.classList.remove('modal-open');
  editingService = null;
  const focusTarget = modalReturnFocus?.isConnected
    ? modalReturnFocus
    : document.querySelector(`.svc-edit[data-port="${returnPort}"]`);
  focusTarget?.focus();
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
    $('meta-error').textContent = 'Beacon could not use that destination. Review the service details and try again.';
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

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(localStorage.getItem('beacon-theme') === 'light');
    $('toggle').addEventListener('click', () => applyTheme(!document.documentElement.classList.contains('light')));
    document.querySelector('.btn-scan').addEventListener('click', triggerScan);
    $('meta-form').addEventListener('submit', submitMetaEditor);
    $('meta-cancel').addEventListener('click', closeMetaEditor);
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
