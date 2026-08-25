(() => {
  const PREFS_KEY = 'beacon-advanced-preferences-v1';
  const DEFAULT_PREFERENCES = {refreshSeconds: 15, paused: false, density: null, range: '24h', filters: {}, historyRange: {preset: '24h'}};
  const REFRESH_CHOICES = new Set([5, 15, 30, 60]);
  // D-02 preset ladder, mapped onto the Phase 2 retention-tier boundaries.
  const HISTORY_PRESETS = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800, '30d': 2592000, '90d': 7776000};
  const HISTORY_PRESET_ORDER = ['1h', '6h', '24h', '7d', '30d', '90d'];
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const HIST_CHART_WIDTH = 1000;
  const HIST_CHART_HEIGHT = 96;
  const HIST_STRIP_HEIGHT = 16;
  const HIST_MIN_SEGMENT_WIDTH = 3;
  // D-07: same order and same keys as the server's HOST_METRICS tuple
  // (dashboard/beacon/telemetry.py:12), so selector values and DOM ids agree.
  const HOST_METRIC_ORDER = ['cpu', 'ram', 'disk', 'temp'];
  const HOST_METRIC_LABELS = {cpu: 'CPU', ram: 'Memory', disk: 'Disk', temp: 'Temperature'};
  const HOST_METRIC_UNITS = {cpu: '%', ram: '%', disk: '%', temp: '°C'};
  // D-10: two honest lines rather than four symmetrical ones. cpu/ram carry no
  // entry and there is no fallback branch that invents one for them.
  const THRESHOLD_LINES = {temp: [80, 85], disk: [100]};
  const THRESHOLD_PROVENANCE = {
    temp: 'Raspberry Pi documented default soft/hard thermal throttle point — not a Beacon-configured alert.',
    disk: 'Filesystem-reported total capacity — the disk cannot exceed this line.',
  };
  const state = {
    snapshot: null, lastSuccessLabel: null, activeSection: 'overview', timer: null,
    preferences: {...DEFAULT_PREFERENCES}, filters: {}, serviceSort: null,
    expandedPorts: new Set(), connectionUnavailable: false, requestGeneration: 0,
    timezone: 'UTC', historyRequestGeneration: 0,
  };
  const $ = (id) => document.getElementById(id);

  function validFilters(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
    const allowed = new Set(['query', 'status', 'criticality', 'freshness', 'tags']);
    return Object.fromEntries(Object.entries(value).filter(([key, item]) => allowed.has(key) && typeof item === 'string'));
  }

  // D-04/D-18: never trust stored data. Only an object carrying a `preset` that
  // is a known key of HISTORY_PRESETS is accepted; anything else -- an array, a
  // nested object, an unknown string -- resolves to the documented 24h default
  // without ever building a request from the untrusted value.
  function validHistoryRange(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {preset: '24h'};
    const preset = value.preset;
    if (typeof preset !== 'string' || !Object.prototype.hasOwnProperty.call(HISTORY_PRESETS, preset)) {
      return {preset: '24h'};
    }
    return {preset};
  }

  function loadPreferences() {
    let stored = {};
    try {
      const candidate = JSON.parse(localStorage.getItem(PREFS_KEY) || '{}');
      stored = candidate && typeof candidate === 'object' && !Array.isArray(candidate) ? candidate : {};
    } catch (_) { /* malformed browser-local data uses documented defaults */ }
    const refreshSeconds = REFRESH_CHOICES.has(stored.refreshSeconds) ? stored.refreshSeconds : DEFAULT_PREFERENCES.refreshSeconds;
    state.preferences = {
      refreshSeconds,
      paused: typeof stored.paused === 'boolean' ? stored.paused : DEFAULT_PREFERENCES.paused,
      density: stored.density === 'comfortable' || stored.density === 'compact' ? stored.density : null,
      range: stored.range === '24h' ? stored.range : DEFAULT_PREFERENCES.range,
      filters: validFilters(stored.filters),
      historyRange: validHistoryRange(stored.historyRange),
    };
    state.filters = state.preferences.filters;
    return state.preferences;
  }

  function savePreferences() {
    const prefs = state.preferences;
    localStorage.setItem(PREFS_KEY, JSON.stringify({
      refreshSeconds: prefs.refreshSeconds,
      paused: prefs.paused,
      density: prefs.density,
      range: prefs.range,
      filters: validFilters(state.filters),
      historyRange: validHistoryRange(prefs.historyRange),
    }));
  }

  function applyTheme() {
    document.documentElement.classList.toggle('light', localStorage.getItem('beacon-theme') === 'light');
  }

  function applyDensity() {
    const density = state.preferences.density || (document.documentElement.classList.contains('light') ? 'comfortable' : 'compact');
    document.body.classList.toggle('density-comfortable', density === 'comfortable');
    document.body.classList.toggle('density-compact', density === 'compact');
  }

  async function apiFetch() {
    const response = await fetch('/api/advanced/current', {cache: 'no-store'});
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { message = (await response.json()).error || message; } catch (_) { /* bounded status evidence */ }
      throw new Error(message);
    }
    return response.json();
  }

  function displayValue(value, suffix = '') {
    return value === null || value === undefined || value === '' ? 'Unknown' : `${value}${suffix}`;
  }

  // The single absent-value rule for every surface that turns a server value into
  // a number: the latency cell, the latency sort key and the state duration. The
  // decision is made on type, not on a list of observed values, because anything
  // this accepts becomes an assertion Beacon is making about the Pi. A boolean, an
  // array, an object and a blank string are absences — Number() would coerce them
  // to a measurement of zero, which is exactly the fabricated copy this workspace
  // must never show. A genuine zero from either accepted type is a measurement.
  function finiteMeasurement(value) {
    if (typeof value === 'number') return Number.isFinite(value) ? value : null;
    if (typeof value !== 'string' || value.trim() === '') return null;
    const measurement = Number(value);
    return Number.isFinite(measurement) ? measurement : null;
  }

  function displayTimestamp(timestamp) {
    if (!Number.isFinite(timestamp)) return 'Unknown';
    return new Date(timestamp * 1000).toLocaleString();
  }

  function relativeAge(seconds) {
    if (!Number.isFinite(seconds)) return 'Unknown age';
    if (seconds < 60) return `${Math.round(seconds)} seconds ago`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes ago`;
    return `${Math.round(seconds / 3600)} hours ago`;
  }

  function addEvidence(parent, label, value) {
    const row = document.createElement('div');
    const name = document.createElement('strong');
    const evidence = document.createElement('span');
    row.className = 'evidence-row';
    name.textContent = `${label}: `;
    evidence.textContent = value;
    row.append(name, evidence);
    parent.append(row);
  }

  function addCard(parent, title, text, section) {
    const article = document.createElement('article');
    const heading = document.createElement('h3');
    const value = document.createElement('p');
    heading.textContent = title;
    value.textContent = text;
    article.className = 'diagnosis-card';
    article.append(heading, value);
    if (section) {
      const link = document.createElement('a');
      link.href = `#${section}-section`;
      link.textContent = `View ${section}`;
      link.addEventListener('click', (event) => { event.preventDefault(); selectSection(section); });
      article.append(link);
    }
    parent.append(article);
    return article;
  }

  const FRESHNESS_WORDS = new Set(['fresh', 'aging', 'stale', 'unknown']);

  function freshnessWord(state) {
    return FRESHNESS_WORDS.has(state) ? state : 'unknown';
  }

  function streamName(item) {
    return `${displayValue(item.stream_kind)}: ${displayValue(item.stream_key)}`;
  }

  function gapInterval(item) {
    return `Interval ${displayTimestamp(item.start_ts)} to ${displayTimestamp(item.end_ts)}; detail ${displayValue(item.detail)}.`;
  }

  // One entry per kind compose_active_exceptions emits, built only from the fields
  // that kind actually carries. A Map is used so an exception kind can never resolve
  // through Object.prototype. Copy states the observation and directs the operator to
  // the owning section; it never asserts a cause.
  const EXCEPTION_COPY = new Map([
    ['recovery_required', () => ({
      title: 'Database recovery required',
      evidence: 'Beacon reports that database recovery is required. See Pipeline for worker heartbeat and recovery evidence.',
    })],
    ['host_freshness', (item) => ({
      title: `Host evidence is ${freshnessWord(item.state)}`,
      evidence: `The current host sample is ${freshnessWord(item.state)}. See Host for its exact sample timestamp and expected cadence.`,
    })],
    ['worker_freshness', (item) => ({
      title: `Worker heartbeat is ${freshnessWord(item.state)}`,
      evidence: `The worker heartbeat is ${freshnessWord(item.state)}. See Pipeline for its exact timestamp and expected cadence.`,
    })],
    ['critical_service_offline', (item) => ({
      title: `Critical service offline \u2014 ${displayValue(item.name)} on port ${displayValue(item.port)}`,
      evidence: `${displayValue(item.name)} is offline and is marked critical. See Services for its failure class and probe evidence.`,
    })],
    ['service_offline', (item) => ({
      title: `Service offline \u2014 ${displayValue(item.name)} on port ${displayValue(item.port)}`,
      evidence: `${displayValue(item.name)} is offline. See Services for its failure class and probe evidence.`,
    })],
    ['service_freshness', (item) => ({
      title: `Service evidence is ${freshnessWord(item.state)} \u2014 port ${displayValue(item.port)}`,
      evidence: `The probe evidence for port ${displayValue(item.port)} is ${freshnessWord(item.state)}. See Services for its exact probe timestamp and expected cadence.`,
    })],
    ['collection_gap', (item) => ({
      title: `${item.open ? 'Open' : 'Recently resolved'} collection gap \u2014 ${streamName(item)}`,
      evidence: gapInterval(item),
    })],
    ['coverage_unknown', (item) => ({
      title: `Coverage could not be determined \u2014 ${streamName(item)}`,
      evidence: `Beacon could not determine coverage for the interval ${displayTimestamp(item.start_ts)} to ${displayTimestamp(item.end_ts)}; this is recorded coverage evidence, not a confirmed fault. Detail ${displayValue(item.detail)}.`,
    })],
    ['job_failed', (item) => ({
      title: `Background job failed \u2014 ${displayValue(item.job_id)}`,
      evidence: `The background job ${displayValue(item.job_id)} reported state failed. See Pipeline for its last start, last finish, and error class.`,
    })],
    ['job_outcome_unrecorded', (item) => ({
      title: `Background job outcome not recorded \u2014 ${displayValue(item.job_id)}`,
      evidence: `The background job ${displayValue(item.job_id)} recorded a start and no outcome has been recorded since, for longer than any run of this job should take. See Pipeline for its last start, last success, and configured cadence.`,
    })],
    ['database_pressure', () => ({
      title: 'Database pressure is not normal',
      evidence: 'Storage pressure is outside its normal state. See Pipeline for its state, reason, and snapshot.',
    })],
  ]);

  function exceptionCopy(item) {
    const exception = item || {};
    const builder = EXCEPTION_COPY.get(exception.kind);
    if (builder) return builder(exception);
    const kind = displayValue(exception.kind);
    return {
      title: `Unrecognised exception \u2014 ${kind}`,
      evidence: `This page does not recognise the exception kind ${kind}. See ${exception.section || 'its owning section'} for the evidence the server supplied.`,
    };
  }

  // apiFetch throws a plain Error carrying the server's own structured `error` field
  // or its bounded status line. Browser-raised failures -- a TypeError from the
  // network, a SyntaxError from an unparseable body -- are not server-supplied
  // reasons and are never shown to the operator.
  function serverSuppliedReason(error) {
    return error instanceof Error && error.constructor === Error ? error.message : null;
  }

  // ------------------------------------------------------------------
  // History section (Phase 4, 04-01): shared range control, gap-honest
  // CPU chart, per-chart coverage strip, and a Pi-local-time shared axis.
  // ------------------------------------------------------------------

  // D-05: reads state.timezone (fetched once from /api/config) rather than the
  // browser's own zone -- the bare toLocaleString() pattern at line ~87 above
  // is the wrong contract for History and must never be reused here.
  function formatLocalTimestamp(ts, options = {}) {
    if (!Number.isFinite(ts)) return 'Unknown';
    const formatter = new Intl.DateTimeFormat(undefined, {timeZone: state.timezone || 'UTC', ...options});
    return formatter.format(new Date(ts * 1000));
  }

  async function fetchRuntimeConfig() {
    try {
      const response = await fetch('/api/config', {cache: 'no-store'});
      const data = response.ok ? await response.json() : {};
      state.timezone = typeof data.timezone === 'string' && data.timezone ? data.timezone : 'UTC';
    } catch (_) {
      state.timezone = 'UTC';
    }
  }

  // D-18 scope note: the two integers this returns are the only values ever
  // interpolated into a history request URL -- never a raw stored preference.
  function resolveRangeBounds() {
    const end_ts = Math.floor(Date.now() / 1000);
    const preset = state.preferences.historyRange.preset;
    const span = Object.prototype.hasOwnProperty.call(HISTORY_PRESETS, preset)
      ? HISTORY_PRESETS[preset]
      : HISTORY_PRESETS['24h'];
    return {start_ts: end_ts - span, end_ts};
  }

  async function fetchHostMetricHistory(metric, startTs, endTs) {
    const url = `/api/telemetry/history?kind=host&metric=${encodeURIComponent(metric)}&start_ts=${startTs}&end_ts=${endTs}`;
    const response = await fetch(url, {cache: 'no-store'});
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { message = (await response.json()).error || message; } catch (_) { /* bounded status evidence */ }
      throw new Error(message);
    }
    return response.json();
  }

  function histTimeToX(ts, startTs, endTs) {
    const span = Math.max(1, endTs - startTs);
    return ((ts - startTs) / span) * HIST_CHART_WIDTH;
  }

  function histValueToY(value, domain) {
    const [min, max] = domain || [0, 100];
    const clamped = Math.min(max, Math.max(min, value));
    return HIST_CHART_HEIGHT - ((clamped - min) / (max - min || 1)) * HIST_CHART_HEIGHT;
  }

  // Percent metrics use a fixed 0-100 domain so the three percent charts are
  // comparable at a glance (UI-SPEC "renderYAxis"). Temperature uses an
  // observed-range domain padded to include any drawn threshold line, so an
  // idle Pi's chart still shows how far it is from throttling rather than
  // rescaling the lines off screen.
  function metricValueDomain(metric, points) {
    if (metric !== 'temp') return [0, 100];
    const thresholds = THRESHOLD_LINES.temp || [];
    const observed = (Array.isArray(points) ? points : [])
      .map((point) => point.avg_value)
      .filter((value) => typeof value === 'number' && Number.isFinite(value));
    const values = observed.length ? [...observed, ...thresholds] : thresholds;
    const min = Math.min(0, ...values);
    const max = Math.max(...values);
    const span = max - min || 1;
    const pad = span * 0.1;
    return [min - pad, max + pad];
  }

  // D-06/Pitfall 2: gate line-drawing exclusively on state === 'observed'; every
  // other state (collection_gap, unknown, expired, not_yet_monitored) is equally
  // "do not connect here", so an interval can straddle several non-observed
  // reasons and still correctly refuse to connect. Contiguous 'observed'
  // intervals are walked with a cursor so a multi-segment observed span still
  // counts as fully covering [startTs, endTs).
  function intervalFullyObserved(startTs, endTs, coverage) {
    if (startTs >= endTs) return true;
    const observed = (Array.isArray(coverage) ? coverage : [])
      .filter((interval) => interval && interval.state === 'observed')
      .slice()
      .sort((left, right) => left.start_ts - right.start_ts);
    let cursor = startTs;
    for (const interval of observed) {
      if (interval.start_ts > cursor) break;
      if (interval.end_ts > cursor) cursor = interval.end_ts;
      if (cursor >= endTs) return true;
    }
    return false;
  }

  // D-06: emits an `L` only when the half-open interval between the previous and
  // current point is entirely covered by `observed` evidence; otherwise the pen
  // lifts (`M`). A point with a null avg_value is skipped entirely (not drawn,
  // not treated as a connectable neighbour), per the host bucket contract.
  function buildSeriesPath(points, coverage, scale) {
    let d = '';
    let previous = null;
    (Array.isArray(points) ? points : []).forEach((point) => {
      if (point.avg_value === null || point.avg_value === undefined) { previous = null; return; }
      const x = scale.xFor(point.ts);
      const y = scale.yFor(point.avg_value);
      const canConnect = previous !== null && intervalFullyObserved(previous.ts, point.ts, coverage);
      d += `${canConnect ? 'L' : 'M'}${x},${y} `;
      previous = point;
    });
    return d.trim();
  }

  // D-06/UI-SPEC Chart Contract: branches on (state, detail) together --
  // storage_pressure is a detail under collection_gap, never a sixth state.
  const COVERAGE_STRIP_VOCABULARY = {
    collection_gap: {
      default: {pattern: 'dots', label: 'Collection gap'},
      storage_pressure: {pattern: 'diagonal-hatch', label: 'Storage pressure (no persistence)'},
    },
    unknown: {default: {pattern: 'dashed', label: 'Unknown'}},
    expired: {default: {pattern: 'diagonal-thin', label: 'Expired (outside retention)'}},
    not_yet_monitored: {default: {pattern: 'solid-muted', label: 'Not yet monitored'}},
  };

  function stripSegmentShape(interval) {
    const vocabulary = COVERAGE_STRIP_VOCABULARY[interval.state];
    if (!vocabulary) return null; // 'observed' (or an unrecognised state) draws no segment
    if (interval.state === 'collection_gap' && interval.detail === 'storage_pressure') return vocabulary.storage_pressure;
    return vocabulary.default;
  }

  function coverageStripSegments(coverage) {
    return (Array.isArray(coverage) ? coverage : [])
      .map((interval) => {
        const shape = stripSegmentShape(interval || {});
        if (!shape) return null;
        return {start_ts: interval.start_ts, end_ts: interval.end_ts, pattern: shape.pattern, label: shape.label};
      })
      .filter(Boolean);
  }

  // Merges only *adjacent* segments carrying the same reason whose rendered
  // width would fall below the 3px minimum -- two adjacent segments with
  // different reasons are never merged, even if both are sub-pixel, so each
  // keeps its own minimum-width slot and the five-state partition survives on
  // screen at the 90d preset.
  function mergeStripSegments(segments, pixelsPerSecond) {
    const input = Array.isArray(segments) ? segments : [];
    const merged = [];
    input.forEach((segment) => {
      const rawWidth = (segment.end_ts - segment.start_ts) * pixelsPerSecond;
      const last = merged[merged.length - 1];
      const lastRawWidth = last ? (last.end_ts - last.start_ts) * pixelsPerSecond : null;
      const canMerge = last
        && last.label === segment.label
        && last.end_ts === segment.start_ts
        && (lastRawWidth < HIST_MIN_SEGMENT_WIDTH || rawWidth < HIST_MIN_SEGMENT_WIDTH);
      if (canMerge) {
        last.end_ts = segment.end_ts;
        last.count += 1;
      } else {
        merged.push({start_ts: segment.start_ts, end_ts: segment.end_ts, pattern: segment.pattern, label: segment.label, count: 1});
      }
    });
    return merged;
  }

  function formatMergedDuration(totalSeconds) {
    if (!Number.isFinite(totalSeconds) || totalSeconds <= 0) return '0 minutes';
    if (totalSeconds < 60) return `${Math.round(totalSeconds)} second${Math.round(totalSeconds) === 1 ? '' : 's'}`;
    const minutes = Math.round(totalSeconds / 60);
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  }

  // A merged segment discloses the true count and total duration it stands
  // for, so compression can neither overstate nor hide how much is actually
  // missing. A single unmerged segment keeps its plain reason label instead
  // (see renderCoverageStrip).
  function segmentTooltipText(segment) {
    return `${segment.label} — ${segment.count} intervals, ${formatMergedDuration(segment.end_ts - segment.start_ts)} total`;
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) return null;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = bytes;
    let index = 0;
    while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
    return `${value.toFixed(1)} ${units[index]}`;
  }

  function currentDiskTotalBytes() {
    const snapshot = state.snapshot;
    const disk = snapshot && snapshot.host && snapshot.host.metrics && snapshot.host.metrics.disk;
    return disk ? finiteMeasurement(disk.total_bytes) : null;
  }

  // D-10: threshold lines are dashed --muted in both themes (never --accent),
  // because a fixed documented constant is not a live alert. Each line carries
  // a <title> child with the provenance string, reachable on inspection
  // without a pointer.
  function renderThresholdLines(metric, scale, diskTotalBytes) {
    const svg = $(`chart-${metric}`);
    if (!svg) return;
    svg.querySelectorAll('.hist-threshold, .hist-threshold-label').forEach((node) => node.remove());
    const values = THRESHOLD_LINES[metric];
    if (!values) return;
    const provenance = THRESHOLD_PROVENANCE[metric];
    const unit = HOST_METRIC_UNITS[metric] || '';
    const bytesLabel = metric === 'disk' ? formatBytes(diskTotalBytes) : null;
    values.forEach((value) => {
      const y = scale.yFor(value);
      const line = document.createElementNS(SVG_NS, 'line');
      line.setAttribute('x1', '0');
      line.setAttribute('x2', String(HIST_CHART_WIDTH));
      line.setAttribute('y1', String(y));
      line.setAttribute('y2', String(y));
      line.setAttribute('class', 'hist-threshold');
      const title = document.createElementNS(SVG_NS, 'title');
      title.textContent = provenance;
      line.append(title);
      svg.append(line);
      const label = document.createElementNS(SVG_NS, 'text');
      label.setAttribute('x', '4');
      label.setAttribute('y', String(Math.max(10, y - 2)));
      label.setAttribute('class', 'hist-threshold-label');
      label.textContent = bytesLabel ? `${value}${unit} (${bytesLabel})` : `${value}${unit}`;
      svg.append(label);
    });
  }

  // Each chart draws its own Y axis, ticked in that metric's unit -- percent
  // metrics tick 0/50/100; temperature ticks the observed-range-plus-threshold
  // domain's own min/mid/max so idle and near-throttle readings both stay
  // legible.
  function renderYAxis(metric, points) {
    const svg = $(`chart-${metric}`);
    if (!svg) return;
    svg.querySelectorAll('.hist-y-axis-tick').forEach((node) => node.remove());
    const domain = metricValueDomain(metric, points);
    const unit = HOST_METRIC_UNITS[metric] || '';
    const tickValues = metric === 'temp'
      ? [domain[0], (domain[0] + domain[1]) / 2, domain[1]]
      : [0, 50, 100];
    tickValues.forEach((value) => {
      const text = document.createElementNS(SVG_NS, 'text');
      text.setAttribute('x', '4');
      text.setAttribute('y', String(Math.min(HIST_CHART_HEIGHT - 2, Math.max(10, histValueToY(value, domain)))));
      text.setAttribute('class', 'hist-y-axis-tick');
      text.textContent = `${Math.round(value)}${unit}`;
      svg.append(text);
    });
  }

  // ------------------------------------------------------------------
  // Point tooltips (HIS-01, Phase 4 04-03). Pointer-driven updates are
  // coalesced through requestAnimationFrame -- chart <path> `d` attributes are
  // never regenerated in response to a pointer event (Research Pitfall 3).
  // ------------------------------------------------------------------

  let pendingTooltipFrame = null;

  function renderPointTooltip(metric, point) {
    const tooltip = $('history-chart-tooltip');
    if (!tooltip || !point) return;
    const unit = HOST_METRIC_UNITS[metric] || '';
    const label = HOST_METRIC_LABELS[metric] || metric;
    const value = typeof point.avg_value === 'number' ? point.avg_value : null;
    if (value === null) return;
    const timestamp = formatLocalTimestamp(point.ts, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'});
    tooltip.textContent = `${label}: ${value}${unit} at ${timestamp}`;
  }

  function hidePointTooltip() {
    const tooltip = $('history-chart-tooltip');
    if (!tooltip) return;
    tooltip.hidden = true;
    tooltip.textContent = '';
  }

  function showPointTooltipAt(clientX, clientY) {
    const tooltip = $('history-chart-tooltip');
    if (!tooltip) return;
    tooltip.hidden = false;
    tooltip.style.left = `${clientX + 12}px`;
    tooltip.style.top = `${clientY + 12}px`;
  }

  function schedulePointTooltipUpdate(metric, point, clientX, clientY) {
    if (pendingTooltipFrame !== null) cancelAnimationFrame(pendingTooltipFrame);
    pendingTooltipFrame = requestAnimationFrame(() => {
      pendingTooltipFrame = null;
      renderPointTooltip(metric, point);
      showPointTooltipAt(clientX, clientY);
    });
  }

  // One small hit-target circle per plotted point, reachable by pointer and by
  // keyboard focus alike -- never by regenerating the chart <path> itself.
  function renderPointTargets(metric, points, scale) {
    const svg = $(`chart-${metric}`);
    if (!svg) return;
    svg.querySelectorAll('.hist-point-target').forEach((node) => node.remove());
    (Array.isArray(points) ? points : []).forEach((point) => {
      if (point.avg_value === null || point.avg_value === undefined) return;
      const target = document.createElementNS(SVG_NS, 'circle');
      target.setAttribute('cx', String(scale.xFor(point.ts)));
      target.setAttribute('cy', String(scale.yFor(point.avg_value)));
      target.setAttribute('r', '6');
      target.setAttribute('class', 'hist-point-target');
      target.setAttribute('tabindex', '0');
      target.setAttribute('role', 'img');
      const unit = HOST_METRIC_UNITS[metric] || '';
      const label = HOST_METRIC_LABELS[metric] || metric;
      target.setAttribute('aria-label', `${label} ${point.avg_value}${unit} at ${formatLocalTimestamp(point.ts)}`);
      target.addEventListener('pointerover', (event) => schedulePointTooltipUpdate(metric, point, event.clientX, event.clientY));
      target.addEventListener('pointerout', hidePointTooltip);
      target.addEventListener('focus', () => {
        const rect = target.getBoundingClientRect();
        schedulePointTooltipUpdate(metric, point, rect.left, rect.top);
      });
      target.addEventListener('blur', hidePointTooltip);
      svg.append(target);
    });
  }

  function renderHistoryChart(metric, result) {
    const svg = $(`chart-${metric}`);
    if (!svg) return;
    const path = svg.querySelector('.hist-series');
    if (!path) return;
    const requested = result.requested || resolveRangeBounds();
    const points = Array.isArray(result.points) ? result.points : [];
    const domain = metricValueDomain(metric, points);
    const scale = {
      xFor: (ts) => histTimeToX(ts, requested.start_ts, requested.end_ts),
      yFor: (value) => histValueToY(value, domain),
    };
    path.setAttribute('d', buildSeriesPath(points, result.coverage, scale));
    renderThresholdLines(metric, scale, metric === 'disk' ? currentDiskTotalBytes() : null);
    renderYAxis(metric, points);
    renderPointTargets(metric, points, scale);
  }

  // UI-SPEC Coverage Strip Mechanics: every rendered segment is at least 3px
  // wide regardless of its true time span, so a sub-pixel-duration reason at
  // the 90d preset is never visually hidden or rounded away.
  function renderCoverageStrip(metric, coverage, requestedRange) {
    const svg = $(`strip-${metric}`);
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const range = requestedRange || resolveRangeBounds();
    const span = Math.max(1, range.end_ts - range.start_ts);
    const pixelsPerSecond = HIST_CHART_WIDTH / span;
    const rawSegments = coverageStripSegments(coverage);
    mergeStripSegments(rawSegments, pixelsPerSecond).forEach((segment) => {
      const x1 = histTimeToX(segment.start_ts, range.start_ts, range.end_ts);
      const x2 = histTimeToX(segment.end_ts, range.start_ts, range.end_ts);
      const width = Math.max(HIST_MIN_SEGMENT_WIDTH, x2 - x1);
      const rect = document.createElementNS(SVG_NS, 'rect');
      rect.setAttribute('x', String(x1));
      rect.setAttribute('y', '0');
      rect.setAttribute('width', String(width));
      rect.setAttribute('height', String(HIST_STRIP_HEIGHT));
      rect.setAttribute('class', `hist-coverage-segment hist-pattern-${segment.pattern}`);
      const title = document.createElementNS(SVG_NS, 'title');
      title.textContent = segment.count > 1 ? segmentTooltipText(segment) : segment.label;
      rect.append(title);
      svg.append(rect);
    });
  }

  function renderSharedTimeAxis(startTs, endTs) {
    const svg = $('history-time-axis');
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    if (!Number.isFinite(startTs) || !Number.isFinite(endTs) || endTs <= startTs) return;
    const tickCount = 6;
    for (let index = 0; index <= tickCount; index += 1) {
      const ts = startTs + ((endTs - startTs) * index) / tickCount;
      const text = document.createElementNS(SVG_NS, 'text');
      text.setAttribute('x', String(histTimeToX(ts, startTs, endTs)));
      text.setAttribute('y', '16');
      text.textContent = formatLocalTimestamp(ts, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'});
      svg.append(text);
    }
  }

  // D-02: the server, not the client, owns resolution selection -- this only
  // renders the value select_resolution() already reported.
  function updateRangeResolutionNote(effectiveResolutionSeconds) {
    const note = $('range-resolution-note');
    if (!note) return;
    note.textContent = Number.isFinite(effectiveResolutionSeconds)
      ? `Showing ${effectiveResolutionSeconds}-second resolution`
      : '';
  }

  function syncHistoryPresetButtons() {
    const active = state.preferences.historyRange.preset;
    HISTORY_PRESET_ORDER.forEach((preset) => {
      const button = $(`range-preset-${preset}`);
      if (button) button.setAttribute('aria-pressed', String(preset === active));
    });
  }

  function historyStateElement(metric, suffix) {
    return $(`history-${metric}-${suffix}`);
  }

  // Never renders a zeroed chart, an empty-looking plot frame, or a bare axis
  // while loading: the previous series/strip content is cleared up front, and
  // the loading skeleton is the only thing visible until the fetch settles.
  function beginMetricLoadingState(metric) {
    const loading = historyStateElement(metric, 'loading');
    const empty = historyStateElement(metric, 'empty');
    const error = historyStateElement(metric, 'error');
    if (loading) loading.hidden = false;
    if (empty) empty.hidden = true;
    if (error) error.hidden = true;
    const chartSvg = $(`chart-${metric}`);
    const path = chartSvg ? chartSvg.querySelector('.hist-series') : null;
    if (path) path.setAttribute('d', '');
    if (chartSvg) {
      chartSvg.querySelectorAll('.hist-threshold, .hist-threshold-label, .hist-y-axis-tick, .hist-point-target')
        .forEach((node) => node.remove());
    }
    const stripSvg = $(`strip-${metric}`);
    if (stripSvg) while (stripSvg.firstChild) stripSvg.removeChild(stripSvg.firstChild);
  }

  // Four parallel host-metric fetches, one per HOST_METRIC_ORDER entry,
  // composed with Promise.allSettled so one metric's rejection can never take
  // the other three down (Research Pattern 1).
  async function fetchHostHistory(startTs, endTs) {
    const settled = await Promise.allSettled(
      HOST_METRIC_ORDER.map((metric) => fetchHostMetricHistory(metric, startTs, endTs)),
    );
    const results = {};
    HOST_METRIC_ORDER.forEach((metric, index) => { results[metric] = settled[index]; });
    return results;
  }

  // Renders one metric's outcome, isolated from every other metric's outcome
  // (Research Pattern 1): a rejected fetch renders only this metric's own
  // error copy and never blanks the loading/empty/chart state of its
  // siblings. Every branch leaves the chart *frame* in the stack -- a metric
  // is never removed from the DOM, so stack height and metric order stay
  // identical for every range.
  function applyMetricResult(metric, outcome) {
    const loading = historyStateElement(metric, 'loading');
    const empty = historyStateElement(metric, 'empty');
    const error = historyStateElement(metric, 'error');
    if (loading) loading.hidden = true;
    if (outcome && outcome.status === 'fulfilled') {
      const result = outcome.value;
      const points = Array.isArray(result.points) ? result.points : [];
      const hasObservedValue = points.some((point) => point.avg_value !== null && point.avg_value !== undefined);
      if (empty) empty.hidden = hasObservedValue;
      if (error) error.hidden = true;
      renderHistoryChart(metric, result);
      const requested = result.requested || resolveRangeBounds();
      renderCoverageStrip(metric, result.coverage, requested);
      return {metric, result};
    }
    if (empty) empty.hidden = true;
    if (error) {
      const reason = outcome ? serverSuppliedReason(outcome.reason) : null;
      const label = HOST_METRIC_LABELS[metric] || metric;
      error.textContent = `This chart could not load. ${label} data is unavailable — other charts and the coverage evidence below are unaffected.${reason ? ` Server reported: ${reason}` : ''}`;
      error.hidden = false;
    }
    return null;
  }

  // Walks HOST_METRIC_ORDER and renders each metric independently -- the
  // fixed CPU, memory, disk, temperature order regardless of how many metrics
  // have retained data.
  function renderHostStack(results) {
    return HOST_METRIC_ORDER.map((metric) => applyMetricResult(metric, results[metric])).filter(Boolean);
  }

  async function renderHistorySection() {
    // A dedicated counter, not state.requestGeneration: that counter belongs to
    // refreshCurrentDiagnosis's own periodic poll (every refreshSeconds), and
    // sharing it would let an unrelated overview refresh discard an in-flight,
    // still-current History render. Same staleness-guard idiom, own generation.
    const requestId = ++state.historyRequestGeneration;
    const bounds = resolveRangeBounds();
    HOST_METRIC_ORDER.forEach((metric) => beginMetricLoadingState(metric));
    // R-01: a real, measured render figure for the four-chart stack, captured
    // in the browser during the automated test run rather than deferred to
    // Phase 6 -- see 04-03-SUMMARY.md for the recorded baseline.
    const renderStart = performance.now();
    const results = await fetchHostHistory(bounds.start_ts, bounds.end_ts);
    if (requestId !== state.historyRequestGeneration) return;
    const succeeded = renderHostStack(results);
    window.__historyStackRenderMs = performance.now() - renderStart;
    const firstSucceeded = succeeded[0];
    if (firstSucceeded) {
      const requested = firstSucceeded.result.requested || bounds;
      updateRangeResolutionNote(firstSucceeded.result.effective_resolution_seconds);
      renderSharedTimeAxis(requested.start_ts, requested.end_ts);
    } else {
      // Every metric failed (or returned nothing to anchor the axis on): the
      // shared axis still renders from the requested bounds so it never
      // disappears alongside a per-metric fetch failure.
      updateRangeResolutionNote(null);
      renderSharedTimeAxis(bounds.start_ts, bounds.end_ts);
    }
  }

  // D-04: validated before assignment, persisted, then re-rendered -- never a
  // request built from anything but the two integers resolveRangeBounds emits.
  function selectRangePreset(preset) {
    if (!Object.prototype.hasOwnProperty.call(HISTORY_PRESETS, preset)) return;
    state.preferences.historyRange = {preset};
    savePreferences();
    syncHistoryPresetButtons();
    renderHistorySection();
  }

  function renderSafety(snapshot) {
    const safety = snapshot.safety || {};
    $('connection-banner').hidden = !state.connectionUnavailable;
    $('worker-warning').hidden = !safety.worker_stale;
    $('recovery-warning').hidden = !safety.recovery_required;
  }

  function renderOverview(snapshot) {
    const content = $('overview-content');
    const fragment = document.createDocumentFragment();
    const exceptions = Array.isArray(snapshot.exceptions) ? snapshot.exceptions : [];
    const exceptionRegion = document.createElement('section');
    const exceptionHeading = document.createElement('h3');
    exceptionHeading.textContent = 'Active exceptions';
    exceptionRegion.append(exceptionHeading);
    if (exceptions.length === 0) {
      const emptyHeading = document.createElement('p');
      const emptyBody = document.createElement('p');
      emptyHeading.textContent = 'No active exceptions';
      emptyBody.textContent = 'Host, services, and collection pipeline are reporting normally.';
      exceptionRegion.append(emptyHeading, emptyBody);
    } else {
      const count = document.createElement('p');
      count.textContent = `${exceptions.length} active exception${exceptions.length === 1 ? '' : 's'}`;
      exceptionRegion.append(count);
      exceptions.forEach((item) => {
        const copy = exceptionCopy(item);
        addCard(exceptionRegion, copy.title, copy.evidence, item.section);
      });
    }
    fragment.append(exceptionRegion);
    if (!snapshot.services || !snapshot.pipeline) {
      const partial = document.createElement('p');
      partial.className = 'advanced-partial';
      partial.textContent = 'Some current-state evidence is unavailable. Available values are shown; see freshness and pipeline details for timestamps and cadence.';
      fragment.append(partial);
    }
    const summaries = document.createElement('div');
    summaries.className = 'summary-grid';
    const host = snapshot.host || {};
    const hostCard = addCard(summaries, 'Host', `${displayValue((host.identity || {}).hostname)} — Freshness: ${(host.freshness || {}).state || 'Unknown'}`, 'host');
    hostCard.setAttribute('data-testid', 'host-summary');
    addCard(summaries, 'Services', snapshot.services ? 'Current service evidence is available.' : 'Unknown', 'services');
    addCard(summaries, 'Collection Health', snapshot.pipeline ? 'Current pipeline evidence is available.' : 'Unknown', 'pipeline');
    fragment.append(summaries);
    content.replaceChildren(fragment);
  }

  function formatFreshnessEvidence(freshness, cadence) {
    const evidence = freshness || {};
    return `${evidence.state || 'unknown'} — ${relativeAge(evidence.age_seconds)}; expected every ${displayValue(cadence, ' seconds')}`;
  }

  // The four completeness states the server derives for a service's gap block.
  // Anything else — an absent block, a raw container, an unrecognised state — is
  // evidence the workspace cannot vouch for, and reads as unavailable.
  //
  // This array is the wire vocabulary: it is the complete set of literals the
  // server can send, which is why it deliberately still lists 'not_established'
  // even though the very next statement rejects that state. Membership here
  // means "the server may send this", not "the workspace can render it".
  // test_gap_evidence_vocabulary_matches_the_server binds this array to the
  // server's own SERVICE_GAP_EVIDENCE_* constants at source level, so a rename
  // on either side fails a test instead of greying out every service row.
  const SERVICE_GAP_EVIDENCE_STATES = ['complete', 'possibly_incomplete', 'absent', 'not_established'];

  function formatServiceGapEvidence(block) {
    if (!block || typeof block !== 'object' || Array.isArray(block)) return 'Gap evidence unavailable';
    const state = block.evidence;
    if (!SERVICE_GAP_EVIDENCE_STATES.includes(state) || state === 'not_established') {
      return 'Gap evidence unavailable';
    }
    const items = Array.isArray(block.items) ? block.items : [];
    const declaredCount = finiteMeasurement(block.count);
    const count = declaredCount === null ? items.length : declaredCount;
    // 'absent' means the stream list was complete and carried no stream for this
    // service, so the pipeline has no record of ever observing it. That is a
    // different fact from having been collected and found clean, and only the
    // copy can carry the difference. Per D-11 the sentence states the observed
    // condition and stops short of diagnosing a cause.
    if (state === 'absent') return 'No collection stream established for this service';
    if (state === 'complete' && count === 0) return 'No gap evidence';
    const declaredOpen = finiteMeasurement(block.open_count);
    const openCount = declaredOpen === null
      ? items.filter((item) => item && item.open === true).length
      : declaredOpen;
    // countLabel owns the singular/plural rule for both this surface and the
    // Pipeline collection-gaps region, so the copy cannot drift between them.
    const phrase = `${countLabel(count, 'gap')} (${openCount} open)`;
    return state === 'possibly_incomplete' ? `${phrase}; more gap evidence may exist` : phrase;
  }

  function renderHost(host) {
    const content = $('host-content');
    const metrics = host.metrics || {};
    const grid = document.createElement('div');
    grid.className = 'evidence-grid';
    addEvidence(grid, 'Host identity', displayValue((host.identity || {}).hostname));
    addEvidence(grid, 'CPU', displayValue((metrics.cpu || {}).value, '%'));
    addEvidence(grid, 'Memory', displayValue((metrics.memory || {}).value, '%'));
    addEvidence(grid, 'Disk', displayValue((metrics.disk || {}).value, '%'));
    addEvidence(grid, 'Temperature', displayValue((metrics.temperature || {}).value, ' °C'));
    addEvidence(grid, 'Sample timestamp', displayTimestamp(host.sample_ts));
    addEvidence(grid, 'Sample age', relativeAge((host.freshness || {}).age_seconds));
    addEvidence(grid, 'Expected cadence', displayValue(host.expected_cadence_seconds, ' seconds'));
    addEvidence(grid, 'Freshness', formatFreshnessEvidence(host.freshness, host.expected_cadence_seconds));
    content.replaceChildren(grid);
  }

  function countLabel(count, noun) {
    return `${Number.isFinite(count) ? count : 0} ${noun}${count === 1 ? '' : 's'}`;
  }

  function addCollectionRegion(parent, title, collection, emptyCopy, renderItem) {
    const region = document.createElement('section');
    const heading = document.createElement('h3');
    const items = Array.isArray(collection) ? collection : null;
    heading.textContent = title;
    region.append(heading);
    if (!items) {
      const unknown = document.createElement('p');
      unknown.textContent = 'Unknown';
      region.append(unknown);
    } else if (items.length === 0) {
      const empty = document.createElement('p');
      empty.textContent = emptyCopy;
      region.append(empty);
    } else {
      const list = document.createElement('div');
      list.className = 'evidence-list';
      items.forEach((item) => renderItem(list, item));
      region.append(list);
    }
    parent.append(region);
  }

  function renderPipeline(pipeline) {
    const content = $('pipeline-section');
    const heading = document.createElement('h2');
    const root = document.createElement('div');
    const retention = pipeline.retention || {};
    const pressure = pipeline.database_pressure || {};
    const worker = pipeline.worker || {};
    const streamsField = pipeline.streams || {};
    const streams = Array.isArray(streamsField.items) ? streamsField.items : null;
    const gaps = pipeline.gaps || {};
    const pending = pipeline.aggregation_pending || {};
    const jobs = Array.isArray(pipeline.jobs) ? pipeline.jobs : null;
    heading.id = 'pipeline-heading';
    heading.tabIndex = -1;
    heading.textContent = 'Pipeline';
    root.className = 'pipeline-grid';

    const retentionRegion = document.createElement('section');
    const retentionHeading = document.createElement('h3');
    const retentionGrid = document.createElement('div');
    retentionHeading.textContent = 'Retention and resolution';
    retentionGrid.className = 'evidence-grid';
    addEvidence(retentionGrid, '7-day raw', displayValue(retention.raw_days, ' days'));
    addEvidence(retentionGrid, '5-minute through day 30', displayValue(retention.five_minute_days, ' days'));
    addEvidence(retentionGrid, 'hourly through day 90', displayValue(retention.retention_days, ' days'));
    addEvidence(retentionGrid, 'Point budget', displayValue(retention.point_budget));
    retentionRegion.append(retentionHeading, retentionGrid);
    root.append(retentionRegion);

    const pressureRegion = document.createElement('section');
    const pressureHeading = document.createElement('h3');
    const pressureGrid = document.createElement('div');
    pressureHeading.textContent = 'Database pressure';
    pressureGrid.className = 'evidence-grid';
    addEvidence(pressureGrid, 'State', displayValue(pressure.state));
    addEvidence(pressureGrid, 'Reason', displayValue(pressure.reason));
    addEvidence(pressureGrid, 'Snapshot', pressure.snapshot ? JSON.stringify(pressure.snapshot) : 'Unknown');
    pressureRegion.append(pressureHeading, pressureGrid);
    root.append(pressureRegion);

    const workerRegion = document.createElement('section');
    const workerHeading = document.createElement('h3');
    const workerGrid = document.createElement('div');
    workerHeading.textContent = 'Worker heartbeat';
    workerGrid.className = 'evidence-grid';
    addEvidence(workerGrid, 'Timestamp', displayTimestamp(worker.heartbeat_ts));
    addEvidence(workerGrid, 'Freshness', formatFreshnessEvidence(worker.freshness, worker.expected_cadence_seconds));
    addEvidence(workerGrid, 'Lease until', displayTimestamp(worker.lease_until));
    workerRegion.append(workerHeading, workerGrid);
    root.append(workerRegion);

    addCollectionRegion(root, `Streams (${countLabel(streamsField.count, 'stream')}${streamsField.truncated ? ', truncated' : ''})`, streams, 'No pipeline streams are configured', (list, stream) => {
      const item = document.createElement('article');
      const name = `${displayValue(stream.stream_kind)}: ${displayValue(stream.stream_key)}`;
      const freshness = stream.freshness || {};
      item.className = 'diagnosis-card';
      item.textContent = `${name} — ${formatFreshnessEvidence(freshness, stream.cadence_seconds)}. Last sample: ${displayTimestamp(stream.last_observed_ts)}.`;
      if (freshness.state === 'stale') {
        const stale = document.createElement('p');
        stale.textContent = `This stream is stale. Its last sample was ${relativeAge(freshness.age_seconds)}; expected every ${displayValue(stream.cadence_seconds, ' seconds')}.`;
        item.append(stale);
        if ((worker.freshness || {}).state === 'fresh') {
          const comparison = document.createElement('p');
          comparison.textContent = 'The worker heartbeat is fresh, but this stream is stale. Review its cadence and background-job evidence.';
          item.append(comparison);
        }
      }
      list.append(item);
    });

    addCollectionRegion(root, `Collection gaps (${countLabel(gaps.count, 'gap')}${gaps.truncated ? ', truncated' : ''})`, gaps.items, 'No active collection gaps', (list, gap) => {
      const item = document.createElement('article');
      item.className = 'diagnosis-card';
      item.textContent = `${displayValue(gap.stream_kind)}: ${displayValue(gap.stream_key)} — ${gap.open ? 'Open' : 'Resolved'} ${gap.actionable ? 'actionable' : 'historical'} gap.`;
      list.append(item);
    });

    addCollectionRegion(root, `Pending aggregation (${countLabel(pending.count, 'item')}${pending.truncated ? ', truncated' : ''})`, pending.items, 'No pending aggregation', (list, item) => {
      const row = document.createElement('p');
      row.textContent = displayValue(item.stream_key || item.job_id || item.key);
      list.append(row);
    });

    addCollectionRegion(root, `Background jobs (${countLabel(jobs ? jobs.length : null, 'job')})`, jobs, 'No background jobs are configured', (list, job) => {
      const item = document.createElement('article');
      item.className = 'diagnosis-card';
      item.textContent = `${displayValue(job.job_id)} — ${displayValue(job.state)}; last start ${displayTimestamp(job.last_started_ts)}; last finish ${displayTimestamp(job.last_finished_ts)}; last success ${displayTimestamp(job.last_success_ts)}; ${job.not_scheduled ? 'Not scheduled' : `expected every ${displayValue(job.cadence_seconds, ' seconds')}`}; error ${displayValue(job.error_class)}.`;
      list.append(item);
    });
    content.replaceChildren(heading, root);
  }

  function addSettingsGroup(parent, title, settings, optionalKeys = []) {
    const region = document.createElement('section');
    const heading = document.createElement('h3');
    const grid = document.createElement('div');
    heading.textContent = title;
    grid.className = 'evidence-grid';
    const entries = Object.entries(settings || {});
    if (entries.length === 0) addEvidence(grid, 'Effective value', 'Unknown');
    entries.forEach(([key, value]) => addEvidence(grid, key.replaceAll('_', ' '), value === null || value === undefined ? (optionalKeys.includes(key) ? 'Not configured' : 'Unknown') : String(value)));
    region.append(heading, grid);
    parent.append(region);
  }

  function renderSettings(settings) {
    const content = $('settings-section');
    const heading = document.createElement('h2');
    const root = document.createElement('div');
    heading.id = 'settings-heading';
    heading.tabIndex = -1;
    heading.textContent = 'Settings';
    root.className = 'settings-grid';
    addSettingsGroup(root, 'Effective monitoring', settings.sampling);
    addSettingsGroup(root, 'Effective probes', settings.probes);
    addSettingsGroup(root, 'Effective discovery and cleanup', settings.discovery_cleanup);
    addSettingsGroup(root, 'Effective retention', settings.retention);
    addSettingsGroup(root, 'Effective pressure', settings.pressure, ['alert_webhook_url']);
    addSettingsGroup(root, 'Effective alerting', {alerting: settings.alerting_enabled ? 'Configured' : 'Not configured'}, ['alerting']);
    const local = document.createElement('section');
    const localHeading = document.createElement('h3');
    const localGrid = document.createElement('div');
    localHeading.textContent = 'Local presentation preferences';
    localGrid.className = 'evidence-grid';
    const densityLabel = document.createElement('label');
    const densitySelect = document.createElement('select');
    densityLabel.textContent = 'Density';
    densitySelect.id = 'density-preference';
    [['', 'Theme default'], ['comfortable', 'Comfortable'], ['compact', 'Compact']].forEach(([value, text]) => {
      const option = document.createElement('option'); option.value = value; option.textContent = text; densitySelect.append(option);
    });
    densitySelect.value = state.preferences.density || '';
    densitySelect.addEventListener('change', () => { state.preferences.density = densitySelect.value || null; applyDensity(); savePreferences(); });
    densityLabel.append(densitySelect);
    const rangeLabel = document.createElement('label');
    const rangeSelect = document.createElement('select');
    rangeLabel.textContent = 'Range';
    rangeSelect.id = 'range-preference';
    const rangeOption = document.createElement('option'); rangeOption.value = '24h'; rangeOption.textContent = '24 hours'; rangeSelect.append(rangeOption);
    rangeSelect.value = state.preferences.range;
    rangeSelect.addEventListener('change', () => { state.preferences.range = rangeSelect.value; savePreferences(); });
    rangeLabel.append(rangeSelect);
    localGrid.append(densityLabel, rangeLabel);
    addEvidence(localGrid, 'Refresh interval', `${state.preferences.refreshSeconds} seconds`);
    addEvidence(localGrid, 'Service filters', Object.keys(state.filters).length ? 'Configured locally' : 'Not configured');
    local.append(localHeading, localGrid);
    root.append(local);
    content.replaceChildren(heading, root);
  }

  function serviceAvailability(service) {
    const value = String(service.availability || service.status || 'unknown').toLowerCase();
    if (value === 'online' || value === 'up') return 'online';
    if (value === 'offline' || value === 'down') return 'offline';
    // D-06: a service covered by an active confirmed maintenance window is its own
    // status value, never folded into 'offline' -- WR-01's fail-closed vocabulary
    // discipline still governs everything this branch does not recognise below.
    if (value === 'maintenance') return 'maintenance';
    return 'unknown';
  }

  function serviceFreshness(service) {
    const value = String((service.freshness || {}).state || 'unknown').toLowerCase();
    return ['fresh', 'aging', 'stale', 'unknown'].includes(value) ? value : 'unknown';
  }

  function serviceDuration(service) {
    const seconds = finiteMeasurement(service.state_duration_seconds);
    return seconds !== null && seconds >= 0 ? seconds : null;
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds)) return 'Unknown duration';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
    return `${Math.floor(seconds / 3600)} hours`;
  }

  // Monday-first ISO weekday names (1..7), local to this file: D-01 keeps the
  // read-only workspace's JavaScript wholly independent of the editor's own
  // weekday vocabulary in app.js, so nothing here is shared or imported.
  const WEEKDAY_NAMES = {
    1: 'Monday', 2: 'Tuesday', 3: 'Wednesday', 4: 'Thursday',
    5: 'Friday', 6: 'Saturday', 7: 'Sunday',
  };

  function formatClockMinutes(minutes) {
    const wrapped = ((Math.trunc(minutes) % 1440) + 1440) % 1440;
    const hours = String(Math.floor(wrapped / 60)).padStart(2, '0');
    const mins = String(wrapped % 60).padStart(2, '0');
    return `${hours}:${mins}`;
  }

  function formatWeekdayNames(weekdays) {
    return (Array.isArray(weekdays) ? weekdays : [])
      .map((day) => WEEKDAY_NAMES[day])
      .filter((name) => Boolean(name))
      .join(', ');
  }

  // A span of seconds rendered in its largest sensible whole unit. Distinct from
  // formatDuration (the state-duration cell's own helper, left untouched) because
  // this one also renders in days -- the maintenance attribution period is
  // routinely a multi-day retention window, never just seconds/minutes/hours.
  function formatSpan(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return 'an unknown period';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`;
    return `${Math.floor(seconds / 86400)} days`;
  }

  // D-06/UI-SPEC "partial (advanced services)": always renders, with an explicit
  // inactive sentence rather than a blank evidence-row cell. A malformed window
  // (any required numeric field missing) is treated the same as inactive rather
  // than surfacing a half-composed sentence.
  function formatMaintenanceEvidence(maintenance) {
    const block = maintenance && typeof maintenance === 'object' ? maintenance : {};
    const window = block.window && typeof block.window === 'object' ? block.window : null;
    if (!block.active || !window) return 'No active maintenance window.';
    const startMinute = finiteMeasurement(window.start_minute);
    const durationMinutes = finiteMeasurement(window.duration_minutes);
    const graceMinutes = finiteMeasurement(window.grace_minutes);
    if (startMinute === null || durationMinutes === null || graceMinutes === null) {
      return 'No active maintenance window.';
    }
    const start = formatClockMinutes(startMinute);
    const end = formatClockMinutes(startMinute + durationMinutes);
    const weekdays = formatWeekdayNames(window.weekdays) || 'Unknown days';
    const ending = displayTimestamp(block.covered_until_ts);
    return `Covered by a confirmed window: ${start}–${end} on ${weekdays}, grace ${graceMinutes} minutes, ending ${ending}.`;
  }

  // D-09: a duration sentence, never a percentage -- this surface carries no
  // second, competing availability figure at any weight. Always renders, with
  // an explicit zero sentence rather than an omitted row.
  function formatMaintenanceAttribution(attribution) {
    const block = attribution && typeof attribution === 'object' ? attribution : {};
    const attributedSeconds = finiteMeasurement(block.attributed_seconds);
    const range = formatSpan(finiteMeasurement(block.period_seconds));
    if (attributedSeconds === null || attributedSeconds <= 0) {
      return `No downtime in the past ${range} was attributed to confirmed maintenance.`;
    }
    return `${formatSpan(attributedSeconds)} of the past ${range}'s downtime occurred during confirmed maintenance.`;
  }

  function serviceTags(service) {
    return Array.isArray(service.tags) ? service.tags.filter((tag) => typeof tag === 'string') : [];
  }

  function operationalServiceCompare(left, right) {
    const priority = (service) => {
      const availability = serviceAvailability(service);
      if (availability === 'offline' && service.critical) return 0;
      if (availability === 'offline') return 1;
      if (availability === 'unknown' || ['stale', 'unknown'].includes(serviceFreshness(service))) return 2;
      return 3;
    };
    const leftKey = [priority(left), Number(left.pinned_order) || 0, Number(left.port) || 0];
    const rightKey = [priority(right), Number(right.pinned_order) || 0, Number(right.port) || 0];
    for (let index = 0; index < leftKey.length; index += 1) {
      if (leftKey[index] !== rightKey[index]) return leftKey[index] - rightKey[index];
    }
    return 0;
  }

  function stableServiceSort(services) {
    const sort = state.serviceSort;
    const ordering = {
      status: ['offline', 'unknown', 'online'],
      freshness: ['stale', 'unknown', 'aging', 'fresh'],
      criticality: ['critical', 'standard'],
    };
    return services.map((service, index) => ({service, index})).sort((left, right) => {
      if (!sort) {
        const operational = operationalServiceCompare(left.service, right.service);
        return operational || left.index - right.index;
      }
      const value = (service) => {
        if (sort.field === 'name') return `${service.name || ''} ${service.port || ''}`.toLowerCase();
        if (sort.field === 'status') return ordering.status.indexOf(serviceAvailability(service));
        if (sort.field === 'latency') {
          const latency = finiteMeasurement(service.latency_ms);
          return latency === null ? Number.POSITIVE_INFINITY : latency;
        }
        if (sort.field === 'duration') return serviceDuration(service) ?? Number.POSITIVE_INFINITY;
        if (sort.field === 'criticality') return ordering.criticality.indexOf(service.critical ? 'critical' : 'standard');
        return ordering.freshness.indexOf(serviceFreshness(service));
      };
      const leftValue = value(left.service);
      const rightValue = value(right.service);
      let result = typeof leftValue === 'string' ? leftValue.localeCompare(rightValue) : leftValue - rightValue;
      if (sort.direction === 'descending') result *= -1;
      return result || left.index - right.index;
    }).map((item) => item.service);
  }

  function applyServiceFilters(services = (state.snapshot || {}).services) {
    const unique = new Map();
    (Array.isArray(services) ? services : []).forEach((service) => {
      const port = Number(service && service.port);
      if (Number.isFinite(port) && !unique.has(port)) unique.set(port, service);
    });
    const filters = state.filters;
    const query = (filters.query || '').trim().toLowerCase();
    const filtered = [...unique.values()].filter((service) => {
      const tags = serviceTags(service);
      const searchable = `${service.name || ''} ${service.port || ''} ${tags.join(' ')}`.toLowerCase();
      return (!query || searchable.includes(query))
        && (!filters.status || serviceAvailability(service) === filters.status)
        && (!filters.criticality || (filters.criticality === 'critical' ? Boolean(service.critical) : !service.critical))
        && (!filters.freshness || serviceFreshness(service) === filters.freshness)
        && (!filters.tags || tags.some((tag) => tag.toLowerCase() === filters.tags.toLowerCase()));
    });
    return {total: unique.size, services: stableServiceSort(filtered)};
  }

  function updateMatchingCount(matching, total) {
    $('matching-service-count').textContent = `${matching} of ${total} services`;
  }

  function syncServiceFilterControls(services) {
    const controls = {
      query: $('service-search'), status: $('service-status-filter'), criticality: $('service-criticality-filter'),
      freshness: $('service-freshness-filter'), tags: $('service-tag-filter'),
    };
    Object.entries(controls).forEach(([key, control]) => { control.value = state.filters[key] || ''; });
    const tagControl = controls.tags;
    const current = state.filters.tags || '';
    const tags = [...new Set((Array.isArray(services) ? services : []).flatMap(serviceTags))].sort((left, right) => left.localeCompare(right));
    tagControl.replaceChildren(Object.assign(document.createElement('option'), {value: '', textContent: 'Any tag'}));
    tags.forEach((tag) => tagControl.append(Object.assign(document.createElement('option'), {value: tag, textContent: tag})));
    if (current && !tags.includes(current)) tagControl.append(Object.assign(document.createElement('option'), {value: current, textContent: current}));
    tagControl.value = current;
  }

  function setServiceSort(field) {
    state.serviceSort = state.serviceSort && state.serviceSort.field === field
      ? {field, direction: state.serviceSort.direction === 'ascending' ? 'descending' : 'ascending'}
      : {field, direction: 'ascending'};
    $('advanced-status').textContent = `Services sorted by ${field} ${state.serviceSort.direction}`;
    renderServices();
  }

  function toggleServiceDetails(port) {
    if (state.expandedPorts.has(port)) state.expandedPorts.delete(port);
    else state.expandedPorts.add(port);
    renderServices();
  }

  function collapseAllDetails() {
    state.expandedPorts.clear();
    renderServices();
    $('advanced-status').textContent = 'All service details collapsed';
  }

  function resetOperationalOrder() {
    state.serviceSort = null;
    renderServices();
    $('advanced-status').textContent = 'Operational service order restored';
  }

  function renderServices() {
    const source = (state.snapshot || {}).services;
    const body = $('services-table-body');
    const empty = $('services-empty');
    const partial = $('services-partial');
    const {total, services} = applyServiceFilters(source);
    syncServiceFilterControls(source);
    updateMatchingCount(services.length, total);
    partial.hidden = Array.isArray(source);
    empty.hidden = services.length !== 0;
    body.setAttribute('aria-label', services.length ? 'Current service diagnosis' : 'No matching service diagnosis');
    const headers = {
      name: $('service-sort-name'), status: $('service-sort-status'), latency: $('service-sort-latency'),
      duration: $('service-sort-duration'), criticality: $('service-sort-criticality'), freshness: $('service-sort-freshness'),
    };
    Object.entries(headers).forEach(([field, button]) => {
      const active = state.serviceSort && state.serviceSort.field === field;
      const sort = active ? state.serviceSort.direction : 'none';
      button.setAttribute('aria-sort', sort);
      button.parentElement.setAttribute('aria-sort', sort);
    });
    $('reset-service-order').hidden = !state.serviceSort;
    $('collapse-service-details').hidden = state.expandedPorts.size === 0;
    const fragment = document.createDocumentFragment();
    services.forEach((service) => {
      const port = Number(service.port);
      const detailId = `service-detail-${port}`;
      const expanded = state.expandedPorts.has(port);
      const row = document.createElement('tr');
      row.className = 'service-row';
      const identity = document.createElement('th');
      identity.scope = 'row';
      identity.className = 'service-identity';
      const name = document.createElement('span');
      name.className = 'service-name';
      name.textContent = displayValue(service.name);
      name.title = displayValue(service.name);
      const portLabel = document.createElement('span');
      portLabel.className = 'service-port';
      portLabel.textContent = `:${displayValue(port)}`;
      const details = document.createElement('button');
      details.type = 'button'; details.className = 'service-details-toggle';
      details.textContent = expanded ? 'Hide details' : 'Show details';
      details.setAttribute('aria-expanded', String(expanded)); details.setAttribute('aria-controls', detailId);
      details.addEventListener('click', () => toggleServiceDetails(port));
      identity.append(name, portLabel, details);
      const status = document.createElement('td');
      const availability = serviceAvailability(service);
      status.textContent = `● ${availability}`;
      // The Maintenance colour is a status-text role only (03.1-UI-SPEC.md "Color") --
      // never applied to a button, link, or any other interactive element on this
      // read-only surface, and no new custom property is introduced: this reuses the
      // existing --accent3 token already declared for both themes in style.css.
      if (availability === 'maintenance') status.className = 'service-status-maintenance';
      const latency = document.createElement('td');
      const latencyValue = finiteMeasurement(service.latency_ms);
      latency.textContent = latencyValue === null ? displayValue(service.failure_class || service.last_error, '') : `${latencyValue} ms`;
      const duration = document.createElement('td'); duration.textContent = formatDuration(serviceDuration(service));
      const criticality = document.createElement('td'); criticality.textContent = service.critical ? 'Critical' : 'Standard';
      const freshness = document.createElement('td'); freshness.textContent = `● ${serviceFreshness(service)} — ${relativeAge((service.freshness || {}).age_seconds)}`;
      row.append(identity, status, latency, duration, criticality, freshness);
      const detailRow = document.createElement('tr');
      detailRow.id = detailId; detailRow.className = 'service-detail-row'; detailRow.hidden = !expanded;
      const detail = document.createElement('td'); detail.colSpan = 6;
      const evidence = document.createElement('div'); evidence.className = 'service-detail-evidence';
      addEvidence(evidence, 'Complete service name', displayValue(service.name));
      addEvidence(evidence, 'Failure class', displayValue(service.failure_class));
      addEvidence(evidence, 'Tags', serviceTags(service).join(', ') || 'No tags');
      addEvidence(evidence, 'Effective health rule', displayValue(service.effective_health_rule || service.health_rule));
      addEvidence(evidence, 'Exact probe timestamp', displayTimestamp(service.last_probe_ts));
      addEvidence(evidence, 'Selected cadence', displayValue(service.expected_cadence_seconds, ' seconds'));
      addEvidence(evidence, 'TLS trust annotation', service.tls_unverified ? 'Trusted-LAN TLS; certificate verification disabled' : ((service.tls || {}).posture || 'TLS posture unknown'));
      addEvidence(evidence, 'Last error', displayValue(service.last_error));
      addEvidence(evidence, 'Freshness', formatFreshnessEvidence(service.freshness, service.expected_cadence_seconds));
      addEvidence(evidence, 'Collection-gap evidence', formatServiceGapEvidence(service.collection_gaps));
      // D-06/D-08/D-09: three evidence-row entries appended after the existing
      // collection-gap evidence-row, reusing that same builder and grid --
      // Maintenance and Maintenance attribution always render (no blank cell);
      // Down since / Raised at render only while an overrun is genuinely open,
      // and always as two separate evidence rows, never merged into one string.
      addEvidence(evidence, 'Maintenance', formatMaintenanceEvidence(service.maintenance));
      const overrun = service.overrun && typeof service.overrun === 'object' ? service.overrun : null;
      if (overrun) {
        addEvidence(evidence, 'Down since', displayTimestamp(overrun.down_since_ts));
        addEvidence(evidence, 'Raised at', displayTimestamp(overrun.raised_at_ts));
      }
      addEvidence(evidence, 'Maintenance attribution', formatMaintenanceAttribution(service.maintenance_attribution));
      // D-01: plain text, not a link -- the workspace stays strictly read-only and
      // never implies an action can be performed from this surface.
      addEvidence(evidence, 'Maintenance windows', "Maintenance windows are managed from the main dashboard's service editor.");
      detail.append(evidence); detailRow.append(detail); fragment.append(row, detailRow);
    });
    body.replaceChildren(fragment);
  }

  function renderSnapshot(snapshot) {
    renderSafety(snapshot);
    renderOverview(snapshot);
    renderHost(snapshot.host || {});
    renderServices();
    renderPipeline(snapshot.pipeline || {});
    renderSettings(snapshot.settings || {});
  }

  function updateRefreshEvidence() {
    const lastSuccess = $('advanced-last-success');
    const prior = state.lastSuccessLabel || 'No successful update yet';
    lastSuccess.textContent = `${prior}${state.preferences.paused ? ' — Updates paused' : ''}`;
    lastSuccess.title = state.lastSuccessLabel || 'No successful update yet';
    $('pause-updates').textContent = state.preferences.paused ? 'Resume updates' : 'Pause updates';
    $('refresh-interval').value = String(state.preferences.refreshSeconds);
  }

  function scheduleRefresh() {
    if (state.timer !== null) { clearInterval(state.timer); state.timer = null; }
    if (!state.preferences.paused) state.timer = setInterval(refreshCurrentDiagnosis, state.preferences.refreshSeconds * 1000);
    updateRefreshEvidence();
  }

  function togglePause() {
    state.preferences.paused = !state.preferences.paused;
    savePreferences();
    scheduleRefresh();
    $('advanced-status').textContent = state.preferences.paused ? 'Updates paused' : 'Updates resumed';
  }

  function selectSection(section) {
    // A section value can arrive from the server on an exception card. Resolve and
    // validate its heading before any visibility mutation, so an unrecognised value
    // can neither hide every section nor reach a null dereference.
    const heading = $(`${section}-heading`);
    if (!heading) return;
    state.activeSection = section;
    document.querySelectorAll('#section-navigation button').forEach((button) => {
      const selected = button.dataset.section === section;
      button.setAttribute('aria-selected', String(selected));
    });
    document.querySelectorAll('.advanced-detail > section').forEach((node) => { node.hidden = node.id !== `${section}-section`; });
    heading.focus();
    $('advanced-status').textContent = `${heading.textContent} selected`;
  }

  function renderRefreshError(reason) {
    const error = $('advanced-refresh-error');
    const prior = state.lastSuccessLabel || 'no successful update yet';
    const contracted = `Beacon could not refresh current diagnosis. Showing data from ${prior}. Check the connection warning, then try again.`;
    error.textContent = reason ? `${contracted} Server reported: ${reason}` : contracted;
    error.hidden = false;
  }

  async function refreshCurrentDiagnosis() {
    const requestId = ++state.requestGeneration;
    try {
      const snapshot = await apiFetch();
      if (requestId !== state.requestGeneration) return;
      state.connectionUnavailable = false;
      state.snapshot = snapshot;
      state.lastSuccessLabel = displayTimestamp(snapshot.generated_ts);
      updateRefreshEvidence();
      $('advanced-refresh-error').hidden = true;
      renderSnapshot(snapshot);
    } catch (error) {
      if (requestId !== state.requestGeneration) return;
      state.connectionUnavailable = true;
      renderSafety(state.snapshot || {});
      renderRefreshError(serverSuppliedReason(error));
    }
  }

  applyTheme();
  loadPreferences();
  applyDensity();
  savePreferences();
  document.querySelectorAll('#section-navigation button').forEach((button) => button.addEventListener('click', () => selectSection(button.dataset.section)));
  $('advanced-refresh').addEventListener('click', refreshCurrentDiagnosis);
  $('pause-updates').addEventListener('click', togglePause);
  $('refresh-interval').addEventListener('change', () => {
    const choice = Number($('refresh-interval').value);
    state.preferences.refreshSeconds = REFRESH_CHOICES.has(choice) ? choice : DEFAULT_PREFERENCES.refreshSeconds;
    savePreferences();
    scheduleRefresh();
  });
  const filterControls = {
    query: $('service-search'), status: $('service-status-filter'), criticality: $('service-criticality-filter'),
    freshness: $('service-freshness-filter'), tags: $('service-tag-filter'),
  };
  Object.entries(filterControls).forEach(([key, control]) => control.addEventListener(key === 'query' ? 'input' : 'change', () => {
    state.filters = {...state.filters, [key]: control.value};
    if (!control.value) delete state.filters[key];
    savePreferences();
    renderServices();
  }));
  $('clear-service-filters').addEventListener('click', () => {
    state.filters = {};
    state.serviceSort = null;
    savePreferences();
    renderServices();
    $('advanced-status').textContent = 'All service filters cleared; operational order restored';
  });
  $('reset-service-order').addEventListener('click', resetOperationalOrder);
  $('collapse-service-details').addEventListener('click', collapseAllDetails);
  {
    const sortButtons = {
      name: $('service-sort-name'), status: $('service-sort-status'), latency: $('service-sort-latency'),
      duration: $('service-sort-duration'), criticality: $('service-sort-criticality'), freshness: $('service-sort-freshness'),
    };
    Object.entries(sortButtons).forEach(([field, button]) => button.addEventListener('click', () => setServiceSort(field)));
  }
  // History section (04-01): the generic selectSection() above needs no change --
  // it already toggles history-section by the same data-section/{id}-heading
  // convention every other section uses. This adds only the History-specific
  // hook (one render on entry) and the six preset buttons.
  syncHistoryPresetButtons();
  HISTORY_PRESET_ORDER.forEach((preset) => {
    const button = $(`range-preset-${preset}`);
    if (button) button.addEventListener('click', () => selectRangePreset(preset));
  });
  // 04-03: each chart's unit label is set once from HOST_METRIC_UNITS, the
  // single source of truth the renderers below also read.
  HOST_METRIC_ORDER.forEach((metric) => {
    const unit = $(`unit-${metric}`);
    if (unit) unit.textContent = HOST_METRIC_UNITS[metric] || '';
  });
  const historyNavButton = document.querySelector('[data-section="history"]');
  if (historyNavButton) historyNavButton.addEventListener('click', renderHistorySection);
  // refreshCurrentDiagnosis() must be invoked before fetchRuntimeConfig(): both
  // dispatch their fetch() call synchronously (before their first await), so
  // this order keeps /api/advanced/current the first network call the page
  // ever makes -- the exact assumption test_advanced_ui.py's reverse-order
  // regression harness pins its "first call held, second call wins" scenario on.
  scheduleRefresh();
  refreshCurrentDiagnosis();
  fetchRuntimeConfig();
})();
