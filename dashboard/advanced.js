(() => {
  const PREFS_KEY = 'beacon-advanced-preferences-v1';
  const DEFAULT_HISTORY_FILTERS = {service: null, criticality: null, eventType: null};
  const DEFAULT_PREFERENCES = {
    refreshSeconds: 15, paused: false, density: null, range: '24h', filters: {},
    historyRange: {preset: '24h'}, selectedService: null, historyFilters: {...DEFAULT_HISTORY_FILTERS},
  };
  const REFRESH_CHOICES = new Set([5, 15, 30, 60]);
  // D-02 preset ladder, mapped onto the Phase 2 retention-tier boundaries.
  const HISTORY_PRESETS = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800, '30d': 2592000, '90d': 7776000};
  const HISTORY_PRESET_ORDER = ['1h', '6h', '24h', '7d', '30d', '90d'];
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const HIST_CHART_WIDTH = 1000;
  const HIST_CHART_HEIGHT = 96;
  const HIST_STRIP_HEIGHT = 16;
  const HIST_MIN_SEGMENT_WIDTH = 3;
  // D-11 (Phase 4 04-06): the state band's own four-state wire vocabulary --
  // the exact literals dashboard/beacon/diagnosis.py already uses for
  // current service availability. No fifth state, no new color.
  const SERVICE_BAND_STATES = ['online', 'offline', 'unknown', 'maintenance'];
  const MIN_BAND_SEGMENT_PX = 3;
  const HIST_BAND_HEIGHT = 32;
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
  // D-15: the shared navigation-stack bound -- drop the oldest entry beyond
  // this rather than growing without bound. In-memory/browser-local only
  // (never persisted, never the URL, per D-18).
  const RANGE_STACK_LIMIT = 20;
  // D-15's resolved incident-window padding rule (plan 04-07 applies this
  // when it pushes an incident window onto the stack this plan builds):
  // 15% of the episode's own duration on each side, floored at 5 minutes per
  // side, so a one-minute blip stays legible and a long outage is not padded
  // into an unreasonably wide window.
  const INCIDENT_PAD_FRACTION = 0.15;
  const INCIDENT_PAD_FLOOR_SECONDS = 300;
  // D-12/D-13 (Phase 4 04-07): mirrored verbatim from dashboard/beacon/incidents.py's
  // EVENT_TYPES/CRITICALITY_VALUES/MAINTENANCE_MODES so a stored or selected
  // filter value can never diverge from what the server itself accepts --
  // the server independently re-validates and rejects with a 400 regardless.
  const INCIDENT_EVENT_TYPES = [
    'state_change', 'monitoring_gap', 'alert_sent', 'alert_failed',
    'preview_capture', 'preview_complete', 'maintenance_overrun',
  ];
  const INCIDENT_CRITICALITY_VALUES = ['critical', 'standard'];
  const INCIDENT_MAINTENANCE_MODES = ['exclude', 'only'];
  const state = {
    snapshot: null, lastSuccessLabel: null, activeSection: 'overview', timer: null,
    preferences: {...DEFAULT_PREFERENCES}, filters: {}, serviceSort: null,
    expandedPorts: new Set(), connectionUnavailable: false, requestGeneration: 0,
    timezone: 'UTC', historyRequestGeneration: 0,
    // D-15/D-18: purely browser-local, in-memory investigation state -- never
    // persisted (loadPreferences/savePreferences never touch this) and never
    // the URL. rangeStack holds {descriptor, origin, label} entries.
    rangeStack: [], historyBounds: null,
    // D-16 (Phase 4 04-06): a dedicated staleness-guard generation for the
    // selected-service history fetch, independent of historyRequestGeneration
    // (the host stack's own guard) -- a service selection change must not
    // discard an in-flight host-metric render, and vice versa.
    serviceHistoryRequestGeneration: 0,
    // A dedicated staleness-guard generation for the Incidents list's own
    // fetch pair (filtered + unfiltered-baseline), independent of every
    // other section's own generation counter -- same idiom as
    // serviceHistoryRequestGeneration above.
    incidentsRequestGeneration: 0,
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
  //
  // T-04-04: a stored `custom` member is accepted only when both start_ts/end_ts
  // are integers that themselves pass validateCustomRange's own bounds -- a
  // hostile shape (strings, nulls, an inverted pair, an over-90-day span, a
  // future end) resolves to the 24h default, exactly like an unrecognised
  // preset, and no request is ever built from the untrusted stored value.
  function validHistoryRange(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {preset: '24h'};
    if (Object.prototype.hasOwnProperty.call(value, 'custom')) {
      const custom = value.custom;
      if (
        custom && typeof custom === 'object' && !Array.isArray(custom)
        && Number.isInteger(custom.start_ts) && Number.isInteger(custom.end_ts)
        && validateCustomRange(custom.start_ts, custom.end_ts).valid
      ) {
        return {custom: {start_ts: custom.start_ts, end_ts: custom.end_ts}};
      }
      return {preset: '24h'};
    }
    const preset = value.preset;
    if (typeof preset !== 'string' || !Object.prototype.hasOwnProperty.call(HISTORY_PRESETS, preset)) {
      return {preset: '24h'};
    }
    return {preset};
  }

  // D-16/T-04-04: a service selection carried between the Phase 3 Services
  // table and the History section. Only `null` or an integer port in
  // 1..65535 is accepted -- a numeric-looking string ("8080"), a negative or
  // out-of-range number, an object, or an array all resolve to no selection.
  // The server independently re-validates the port before it ever reaches
  // SQLite (`_history_selector`), so a hostile stored value cannot reach a
  // query as anything but this same bounded integer.
  function validSelectedService(value) {
    if (value === null || value === undefined) return null;
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 65535) return null;
    return value;
  }

  // D-13/T-04-04 (Phase 4 04-07): the Incidents filter object, validated
  // against exactly the server's own allowlists (CRITICALITY_VALUES,
  // EVENT_TYPES, MAINTENANCE_MODES, plus the same bounded-port rule
  // validSelectedService already applies) before it is ever persisted or
  // read back. A stored value outside any of these resolves to that one
  // field's documented default rather than reaching a request URL --
  // `service` in particular is kept identical to `selectedService`
  // (D-16: the two must never disagree about which service is under
  // investigation), so it is re-derived from the validated selection
  // rather than trusted independently.
  //
  // `eventType` carries one of two disjoint namespaces in a single string,
  // since the UI-SPEC's "event type" filter combines EVENT_TYPES with the
  // two maintenance-visibility options onto one control:
  //   'event_type:<EVENT_TYPES member>' -> the `event_type` query parameter
  //   'maintenance:exclude'|'maintenance:only' -> the `maintenance` parameter
  function validHistoryFilters(value, selectedService) {
    const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    const criticality = INCIDENT_CRITICALITY_VALUES.includes(source.criticality) ? source.criticality : null;
    let eventType = null;
    if (typeof source.eventType === 'string') {
      if (source.eventType.startsWith('event_type:') && INCIDENT_EVENT_TYPES.includes(source.eventType.slice('event_type:'.length))) {
        eventType = source.eventType;
      } else if (source.eventType.startsWith('maintenance:') && INCIDENT_MAINTENANCE_MODES.includes(source.eventType.slice('maintenance:'.length))) {
        eventType = source.eventType;
      }
    }
    return {service: validSelectedService(selectedService), criticality, eventType};
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
      selectedService: validSelectedService(stored.selectedService),
      historyFilters: validHistoryFilters(stored.historyFilters, stored.selectedService),
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
      selectedService: validSelectedService(prefs.selectedService),
      historyFilters: validHistoryFilters(prefs.historyFilters, prefs.selectedService),
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
    // D-05: every field formatted from state.timezone must reflect the Pi's
    // configured zone once it becomes known, even if it rendered against the
    // 'UTC' default before this fetch settled.
    renderRangeFields();
  }

  function boundsForPreset(preset) {
    const end_ts = Math.floor(Date.now() / 1000);
    const span = Object.prototype.hasOwnProperty.call(HISTORY_PRESETS, preset)
      ? HISTORY_PRESETS[preset]
      : HISTORY_PRESETS['24h'];
    return {start_ts: end_ts - span, end_ts};
  }

  // D-18 scope note: the two integers this returns are the only values ever
  // interpolated into a history request URL -- never a raw stored preference.
  // A `custom` descriptor's own two integers are returned as-is (already
  // validated on the way into state.preferences.historyRange by either
  // validHistoryRange on load or validateCustomRange on apply); a `preset`
  // descriptor is always recomputed from Date.now() so a live preset stays
  // live across every render.
  function resolveRangeBounds() {
    const descriptor = state.preferences.historyRange;
    if (descriptor && descriptor.custom) {
      return {start_ts: descriptor.custom.start_ts, end_ts: descriptor.custom.end_ts};
    }
    return boundsForPreset(descriptor && descriptor.preset);
  }

  // ------------------------------------------------------------------
  // Selected-service history (Phase 4 04-06, D-16, T-04-13): one carried,
  // read-only service selection published by the Phase 3 Services table and
  // the History service picker alike, consumed only by this section's own
  // service-history group. Neither affordance alters the row's existing
  // data, sort, filter behaviour, or expand toggle, and neither ever adds a
  // parameter to /api/advanced/current -- that request stays parameterless
  // and byte-identical before and after a selection (T-04-13's own gate is
  // the existing Phase 3 suites re-run at the plan's <verify> boundary).
  // ------------------------------------------------------------------

  function selectedServiceRecord() {
    const port = state.preferences.selectedService;
    if (port === null) return null;
    const services = Array.isArray(state.snapshot && state.snapshot.services) ? state.snapshot.services : [];
    return services.find((service) => Number(service.port) === port) || null;
  }

  function selectedServiceName() {
    const port = state.preferences.selectedService;
    if (port === null) return null;
    const record = selectedServiceRecord();
    return (record && (record.name || record.title)) || `Port ${port}`;
  }

  // Renders immediately from client-side state alone -- no fetch is
  // involved, so this (and the clear action) stay visible and operable
  // while a service-history request is pending and after it fails, letting
  // the operator navigate out of a failed investigation (UI-SPEC E5).
  function renderInvestigatingIndicator() {
    const indicator = $('investigating-service');
    const clearButton = $('clear-selected-service');
    const port = state.preferences.selectedService;
    if (indicator) {
      if (port === null) {
        indicator.hidden = true;
        indicator.textContent = '';
        indicator.removeAttribute('title');
      } else {
        const name = selectedServiceName();
        indicator.hidden = false;
        indicator.textContent = `Investigating: ${name}`;
        indicator.title = name;
      }
    }
    if (clearButton) clearButton.hidden = port === null;
  }

  // Populated from the same current snapshot's service list the Services
  // table itself reads -- never a second, independently-fetched list.
  function renderHistoryServicePicker() {
    const picker = $('history-service-picker');
    if (!picker) return;
    const services = Array.isArray(state.snapshot && state.snapshot.services) ? state.snapshot.services : [];
    const unique = new Map();
    services.forEach((service) => {
      const port = Number(service.port);
      if (Number.isFinite(port) && !unique.has(port)) unique.set(port, service);
    });
    const sorted = [...unique.values()].sort((left, right) => (
      String(left.name || left.title || '').localeCompare(String(right.name || right.title || ''))
      || Number(left.port) - Number(right.port)
    ));
    const currentValue = state.preferences.selectedService === null ? '' : String(state.preferences.selectedService);
    picker.replaceChildren(Object.assign(document.createElement('option'), {value: '', textContent: 'Select a service'}));
    sorted.forEach((service) => {
      const option = document.createElement('option');
      option.value = String(Number(service.port));
      option.textContent = `${service.name || service.title || `Port ${service.port}`} :${service.port}`;
      picker.append(option);
    });
    picker.value = currentValue;
  }

  // The single entry point both affordances (a Services-table row control
  // and the History picker) call -- a `null` port clears the selection.
  // Re-renders every surface that must state the current selection from
  // every source, then triggers a service-history render only when the
  // History section is the one currently active (Task 1 action text) --
  // selecting a service from the Services table must not itself issue a
  // request while History is not even visible.
  function setSelectedService(port) {
    const validated = validSelectedService(port);
    state.preferences.selectedService = validated;
    // D-16 (Phase 4 04-07): the Incidents service filter is never an
    // independent second fact about "which service is under investigation"
    // -- it is always re-derived from the one carried selection, so the two
    // can never quietly disagree.
    state.preferences.historyFilters = {...state.preferences.historyFilters, service: validated};
    savePreferences();
    renderInvestigatingIndicator();
    renderHistoryServicePicker();
    syncIncidentServiceFilterControl();
    renderServices();
    if (state.activeSection === 'history') renderServiceHistorySection();
    if (state.activeSection === 'incidents') renderIncidentsSection();
  }

  // Unsets the subject without touching the range -- clearing who is being
  // investigated is not clearing the window being investigated.
  function clearSelectedService() {
    setSelectedService(null);
  }

  async function fetchServiceTelemetryHistory(port, startTs, endTs) {
    const url = `/api/telemetry/history?kind=service&port=${encodeURIComponent(port)}&start_ts=${startTs}&end_ts=${endTs}`;
    const response = await fetch(url, {cache: 'no-store'});
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { message = (await response.json()).error || message; } catch (_) { /* bounded status evidence */ }
      throw new Error(message);
    }
    return response.json();
  }

  async function fetchServiceEventsHistory(port, startTs, endTs) {
    const url = `/api/events/history?start_ts=${startTs}&end_ts=${endTs}&port=${encodeURIComponent(port)}`;
    const response = await fetch(url, {cache: 'no-store'});
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { message = (await response.json()).error || message; } catch (_) { /* bounded status evidence */ }
      throw new Error(message);
    }
    return response.json();
  }

  // Task 2 (D-11): the service's own telemetry history and the
  // maintenance-suppressed spans that reclassify part of its band both
  // fetched in parallel via Promise.allSettled -- one failing stream
  // renders its own error while the other renders normally, and a failure
  // here never disturbs the host stack above (Research Pattern 1).
  async function fetchServiceHistory(port, startTs, endTs) {
    const [telemetry, events] = await Promise.allSettled([
      fetchServiceTelemetryHistory(port, startTs, endTs),
      fetchServiceEventsHistory(port, startTs, endTs),
    ]);
    return {telemetry, events};
  }

  function serviceHistoryElement(suffix) {
    return $(`service-history-${suffix}`);
  }

  function beginServiceHistoryLoadingState() {
    const loading = serviceHistoryElement('loading');
    const empty = serviceHistoryElement('empty');
    const error = serviceHistoryElement('error');
    const content = serviceHistoryElement('content');
    if (loading) loading.hidden = false;
    if (empty) empty.hidden = true;
    if (error) error.hidden = true;
    // Never a zeroed band or chart while loading (UI-SPEC E3 "loading") --
    // any previously-rendered content is hidden until the new fetch settles.
    if (content) content.hidden = true;
  }

  function renderServiceHistoryPlaceholder() {
    const loading = serviceHistoryElement('loading');
    const empty = serviceHistoryElement('empty');
    const error = serviceHistoryElement('error');
    const content = serviceHistoryElement('content');
    if (loading) loading.hidden = true;
    if (error) error.hidden = true;
    if (content) content.hidden = true;
    if (empty) { empty.hidden = false; empty.textContent = 'Select a service to view its history'; }
  }

  // ------------------------------------------------------------------
  // The state band (Phase 4 04-06 Task 2, D-11): a 32px horizontal bar
  // spanning the shared time axis, directly above its own latency chart.
  // ------------------------------------------------------------------

  // Turns each episode the events fetch returned into the exact span this
  // band must reclassify from `offline` to `maintenance`: a fully
  // maintenance-suppressed episode's whole down-to-recovered span, or (for
  // an overrun episode) only the grace-covered portion before the fault
  // split takes over -- never the post-grace fault portion, which is
  // genuine unplanned downtime per plan 04-02's own split.
  function maintenanceSuppressedSpans(episodes, fallbackEndTs) {
    const spans = [];
    (Array.isArray(episodes) ? episodes : []).forEach((episode) => {
      if (!episode || typeof episode !== 'object') return;
      const downTs = finiteMeasurement(episode.down_ts);
      if (downTs === null) return;
      if (episode.overrun) {
        const graceSeconds = finiteMeasurement(episode.grace_seconds);
        if (graceSeconds !== null && graceSeconds > 0) {
          spans.push({start_ts: downTs, end_ts: downTs + graceSeconds});
        }
        return;
      }
      if (episode.suppressed_reason) {
        const recoveredTs = finiteMeasurement(episode.recovered_ts);
        const endTs = recoveredTs === null ? fallbackEndTs : recoveredTs;
        if (Number.isFinite(endTs) && endTs > downTs) spans.push({start_ts: downTs, end_ts: endTs});
      }
    });
    return spans;
  }

  function intervalOverlapsAnySpan(startTs, endTs, spans) {
    return spans.some((span) => startTs < span.end_ts && endTs > span.start_ts);
  }

  // Splits each bucket into sub-segments whose widths are proportional to
  // its real online/offline/unknown+gap seconds -- unknown and gap seconds
  // are folded into one `unknown` sub-segment because the band's own
  // four-state vocabulary carries no fifth "gap" state; both mean "we did
  // not observe a definite online/offline state" to an operator reading
  // the band. A bucket with zero online and zero offline seconds renders
  // as `unknown` across its full width rather than being split at all. An
  // `offline` sub-segment overlapping a maintenance-suppressed span
  // becomes `maintenance` instead. A bucket whose split produces both an
  // `online` and an `offline` sub-segment (the "mixed bucket" case) is
  // marked `mixedWith` so the render step can disclose the exact counts
  // and the below-resolution ordering caveat -- and so mergeBandSegments
  // never silently folds that disclosure into a neighbour's duration.
  function deriveBandSegments(points, episodes, resolutionSeconds, rangeEndTs) {
    const maintenanceSpans = maintenanceSuppressedSpans(episodes, rangeEndTs);
    const segments = [];
    (Array.isArray(points) ? points : []).forEach((point) => {
      const bucketStart = point.ts;
      if (!Number.isFinite(bucketStart)) return;
      const span = Number.isFinite(resolutionSeconds) && resolutionSeconds > 0 ? resolutionSeconds : 1;
      const bucketEnd = bucketStart + span;
      const online = Math.max(0, finiteMeasurement(point.online_seconds) || 0);
      const offline = Math.max(0, finiteMeasurement(point.offline_seconds) || 0);
      const unknown = Math.max(0, finiteMeasurement(point.unknown_seconds) || 0)
        + Math.max(0, finiteMeasurement(point.gap_seconds) || 0);
      if (online === 0 && offline === 0) {
        segments.push({start_ts: bucketStart, end_ts: bucketEnd, state: 'unknown'});
        return;
      }
      const parts = [];
      if (online > 0) parts.push({seconds: online, state: 'online'});
      if (offline > 0) parts.push({seconds: offline, state: 'offline'});
      if (unknown > 0) parts.push({seconds: unknown, state: 'unknown'});
      const totalSeconds = online + offline + unknown;
      const mixed = online > 0 && offline > 0 ? {onlineSeconds: online, offlineSeconds: offline} : null;
      let cursor = bucketStart;
      parts.forEach((part, index) => {
        const isLast = index === parts.length - 1;
        const fraction = totalSeconds > 0 ? part.seconds / totalSeconds : 0;
        const segStart = cursor;
        const segEnd = isLast ? bucketEnd : segStart + fraction * (bucketEnd - bucketStart);
        let state = part.state;
        if (state === 'offline' && intervalOverlapsAnySpan(segStart, segEnd, maintenanceSpans)) {
          state = 'maintenance';
        }
        segments.push({start_ts: segStart, end_ts: segEnd, state, mixedWith: mixed});
        cursor = segEnd;
      });
    });
    return segments;
  }

  // Merges only adjacent segments carrying the same state into one segment
  // with one duration label -- adjacent segments of different states are
  // never merged, even when either would render below MIN_BAND_SEGMENT_PX,
  // so a genuine state transition can never be compressed out of
  // existence. A segment carrying a `mixedWith` disclosure never merges
  // (in either direction) -- its exact per-bucket counts would otherwise
  // be silently absorbed into a neighbour's plain duration.
  function mergeBandSegments(segments) {
    const merged = [];
    (Array.isArray(segments) ? segments : []).forEach((segment) => {
      const last = merged[merged.length - 1];
      const canMerge = last && !last.mixedWith && !segment.mixedWith
        && last.state === segment.state && last.end_ts === segment.start_ts;
      if (canMerge) {
        last.end_ts = segment.end_ts;
      } else {
        merged.push({...segment});
      }
    });
    return merged;
  }

  // The exact disclosure text a segment's <title> and aria-label share --
  // reachable on hover (native SVG title) and via the shared, rAF-coalesced
  // tooltip on keyboard focus, matching the host chart's own point-tooltip
  // idiom (renderPointTooltip/schedulePointTooltipUpdate).
  function bandSegmentTooltipText(segment) {
    const duration = formatMergedDuration(segment.end_ts - segment.start_ts);
    const startLabel = formatLocalTimestamp(segment.start_ts, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'});
    const endLabel = formatLocalTimestamp(segment.end_ts, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'});
    let text = `${segment.state} — ${startLabel} to ${endLabel} (${duration})`;
    if (segment.mixedWith) {
      text += ` — online ${segment.mixedWith.onlineSeconds}s, offline ${segment.mixedWith.offlineSeconds}s observed in this bucket; the ordering within the bucket is below the displayed resolution.`;
    }
    return text;
  }

  let pendingBandTooltipFrame = null;

  // The same shared #history-chart-tooltip element and rAF coalescing the
  // host chart's point tooltips already use -- reused here with plain text
  // rather than a (metric, point) pair, since a band segment's disclosure
  // is a state/duration sentence, not a single measured value.
  function scheduleBandTooltipUpdate(text, clientX, clientY) {
    if (pendingBandTooltipFrame !== null) cancelAnimationFrame(pendingBandTooltipFrame);
    pendingBandTooltipFrame = requestAnimationFrame(() => {
      pendingBandTooltipFrame = null;
      const tooltip = $('history-chart-tooltip');
      if (tooltip) tooltip.textContent = text;
      showPointTooltipAt(clientX, clientY);
    });
  }

  function renderServiceStateBand(segments, requestedRange) {
    const svg = $('service-state-band');
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    (Array.isArray(segments) ? segments : []).forEach((segment) => {
      const x1 = histTimeToX(segment.start_ts, requestedRange.start_ts, requestedRange.end_ts);
      const x2 = histTimeToX(segment.end_ts, requestedRange.start_ts, requestedRange.end_ts);
      const width = Math.max(MIN_BAND_SEGMENT_PX, x2 - x1);
      const rect = document.createElementNS(SVG_NS, 'rect');
      rect.setAttribute('x', String(x1));
      rect.setAttribute('y', '0');
      rect.setAttribute('width', String(width));
      rect.setAttribute('height', String(HIST_BAND_HEIGHT));
      rect.setAttribute('class', `hist-band-segment hist-band-${segment.state}`);
      rect.setAttribute('tabindex', '0');
      rect.setAttribute('role', 'img');
      const text = bandSegmentTooltipText(segment);
      rect.setAttribute('aria-label', text);
      const title = document.createElementNS(SVG_NS, 'title');
      title.textContent = text;
      rect.append(title);
      rect.addEventListener('pointerover', (event) => scheduleBandTooltipUpdate(text, event.clientX, event.clientY));
      rect.addEventListener('pointerout', hidePointTooltip);
      rect.addEventListener('focus', () => {
        const box = rect.getBoundingClientRect();
        scheduleBandTooltipUpdate(text, box.left, box.top);
      });
      rect.addEventListener('blur', hidePointTooltip);
      svg.append(rect);
    });
  }

  // ------------------------------------------------------------------
  // The latency chart (Phase 4 04-06 Task 2): reuses buildSeriesPath and
  // the coverage-strip machinery verbatim -- the same gap-breaking rule,
  // the same five-reason vocabulary, its own strip element. No state
  // shading is ever applied to #service-latency-chart -- that visual
  // channel belongs exclusively to the coverage strip (D-11).
  // ------------------------------------------------------------------

  // Latency has no host-metric-style fixed domain (0-100) or documented
  // threshold -- an observed-range-plus-10%-pad domain, floored at 0,
  // mirrors metricValueDomain's own temperature branch.
  function latencyValueDomain(points) {
    const observed = (Array.isArray(points) ? points : [])
      .map((point) => finiteMeasurement(point.latency_avg))
      .filter((value) => value !== null);
    if (!observed.length) return [0, 1];
    const min = Math.min(0, ...observed);
    const max = Math.max(...observed);
    const span = max - min || 1;
    const pad = span * 0.1;
    return [min - pad, max + pad];
  }

  function renderLatencyChart(points, coverage, requestedRange) {
    const svg = $('service-latency-chart');
    if (!svg) return;
    const path = svg.querySelector('.hist-series');
    const seriesPoints = (Array.isArray(points) ? points : [])
      .map((point) => ({ts: point.ts, avg_value: finiteMeasurement(point.latency_avg)}));
    const domain = latencyValueDomain(points);
    const scale = {
      xFor: (ts) => histTimeToX(ts, requestedRange.start_ts, requestedRange.end_ts),
      yFor: (value) => histValueToY(value, domain),
    };
    if (path) path.setAttribute('d', buildSeriesPath(seriesPoints, coverage, scale));
    // renderCoverageStrip keys its target element off `strip-${metric}` --
    // passing 'service-latency' targets #strip-service-latency without any
    // new lookup logic.
    renderCoverageStrip('service-latency', coverage, requestedRange);
  }

  // ------------------------------------------------------------------
  // Time-weighted availability and failure classes (Phase 4 04-06 Task 3).
  // ------------------------------------------------------------------

  // Sums online_seconds/offline_seconds across every bucket and returns the
  // ratio plus the unknown/gap totals reported separately -- a pure sum, so
  // it is invariant to the order `points` is processed in. Unknown and gap
  // seconds are excluded from BOTH the numerator and the denominator:
  // folding either in would turn "we did not observe" into either a
  // fabricated outage or a fabricated uptime. `availability` is `null`
  // when online+offline is zero -- a range with no observed service
  // seconds asserts nothing about that window (03.1 D-09).
  function timeWeightedAvailability(points) {
    let online = 0;
    let offline = 0;
    let unknown = 0;
    let gap = 0;
    (Array.isArray(points) ? points : []).forEach((point) => {
      online += Math.max(0, finiteMeasurement(point.online_seconds) || 0);
      offline += Math.max(0, finiteMeasurement(point.offline_seconds) || 0);
      unknown += Math.max(0, finiteMeasurement(point.unknown_seconds) || 0);
      gap += Math.max(0, finiteMeasurement(point.gap_seconds) || 0);
    });
    const observedSeconds = online + offline;
    return {
      availability: observedSeconds > 0 ? online / observedSeconds : null,
      observedSeconds, unknownSeconds: unknown, gapSeconds: gap,
    };
  }

  // The seconds of this range's downtime that fall inside a
  // maintenance-suppressed or overrun-grace span -- reuses Task 2's own
  // maintenanceSuppressedSpans so the band's reclassification and this
  // attribution figure can never quietly disagree about which seconds are
  // maintenance-covered. Clipped to the requested range, since a span may
  // extend past either edge (an open suppressed episode, or one that began
  // before the range).
  function maintenanceAttributedSeconds(episodes, requestedRange) {
    const spans = maintenanceSuppressedSpans(episodes, requestedRange.end_ts);
    let total = 0;
    spans.forEach((span) => {
      const start = Math.max(span.start_ts, requestedRange.start_ts);
      const end = Math.min(span.end_ts, requestedRange.end_ts);
      if (end > start) total += end - start;
    });
    return total;
  }

  // The detail region's own exact-count formatter: unlike formatSpan (the
  // largest-sensible-unit formatter the state-duration/maintenance-window
  // cells use), the observed/unknown/gap/attributed second counts here are
  // disclosed at exact second precision -- rounding 500 unknown seconds to
  // "8 minutes" would be a genuine loss of the evidence this detail exists
  // to disclose.
  function exactSecondsLabel(value) {
    const measurement = finiteMeasurement(value);
    return measurement === null ? 'Unknown' : `${measurement} second${measurement === 1 ? '' : 's'}`;
  }

  // Writes the 28px headline percentage (or `Unknown`, never `0%`/`100%`)
  // beside the range bounds, and the observed/unknown/gap/maintenance-
  // attributed seconds into the expandable detail. Per 03.1 D-09 the
  // headline is never adjusted for maintenance -- attribution appears only
  // here, in the detail, and no excluding-maintenance figure is ever
  // rendered at the headline's own weight.
  function renderAvailability(result, requestedRange, episodes) {
    const headline = $('service-availability');
    const rangeLabel = `${formatLocalTimestamp(requestedRange.start_ts, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'})} – ${formatLocalTimestamp(requestedRange.end_ts, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'})}`;
    if (headline) {
      const value = result && result.availability !== null
        ? `${(result.availability * 100).toFixed(1)}%`
        : 'Unknown';
      headline.textContent = `Availability: ${value} (${rangeLabel})`;
    }
    const detailBody = $('service-availability-detail-body');
    if (detailBody) {
      while (detailBody.firstChild) detailBody.removeChild(detailBody.firstChild);
      const attributedSeconds = maintenanceAttributedSeconds(episodes, requestedRange);
      [
        `Observed: ${exactSecondsLabel(result ? result.observedSeconds : null)}`,
        `Unknown: ${exactSecondsLabel(result ? result.unknownSeconds : null)}`,
        `Collection gap: ${exactSecondsLabel(result ? result.gapSeconds : null)}`,
        `Maintenance-attributed downtime: ${exactSecondsLabel(attributedSeconds)}`,
      ].forEach((text) => {
        const row = document.createElement('p');
        row.textContent = text;
        detailBody.append(row);
      });
    }
  }

  // Sums each bucket's failure_class_counts map across the range, reusing
  // the server's own failure-class vocabulary verbatim (http_{code},
  // invalid_target, invalid_url, not_responding, timeout,
  // connection_error, request_error, probe_error) -- no display name is
  // ever invented for a class the server did not emit.
  function aggregateFailureClasses(points) {
    const counts = {};
    (Array.isArray(points) ? points : []).forEach((point) => {
      const perBucket = point.failure_class_counts;
      if (!perBucket || typeof perBucket !== 'object' || Array.isArray(perBucket)) return;
      Object.entries(perBucket).forEach(([failureClass, count]) => {
        const value = finiteMeasurement(count);
        if (value === null) return;
        counts[failureClass] = (counts[failureClass] || 0) + value;
      });
    });
    return counts;
  }

  // One `{class}: {count}` chip per class, sorted by descending count then
  // ascending class name so equal counts never reorder between identical
  // requests -- preceded by an explicit `countLabel` count (`0 failure
  // classes` rather than an omitted list) so the list's own completeness is
  // never in question.
  function renderFailureClassChips(counts) {
    const container = $('failure-class-chips');
    if (!container) return;
    while (container.firstChild) container.removeChild(container.firstChild);
    const entries = Object.entries(counts || {}).sort((left, right) => (
      right[1] - left[1] || left[0].localeCompare(right[0])
    ));
    const summary = document.createElement('p');
    summary.className = 'hist-failure-chip-count';
    // Not countLabel (that generic pluralizer only ever appends a bare
    // "s", which would render "classs") -- "class" pluralizes irregularly
    // ("classes"), so this list owns its own exact copy rule instead.
    summary.textContent = entries.length === 1 ? '1 failure class' : `${entries.length} failure classes`;
    container.append(summary);
    const list = document.createElement('div');
    list.className = 'hist-failure-chip-list';
    entries.forEach(([failureClass, count]) => {
      const chip = document.createElement('span');
      chip.className = 'hist-failure-chip';
      chip.textContent = `${failureClass}: ${count}`;
      list.append(chip);
    });
    container.append(list);
  }

  // The service-history render entry point: a dedicated staleness-guard
  // generation (never state.historyRequestGeneration, which belongs to the
  // host stack's own render cycle) so a rapid service-selection change or
  // range change can never let a stale response overwrite a newer one.
  // With no service selected this issues no request at all -- the
  // documented placeholder renders instead (UI-SPEC E3 "zero-one-many").
  async function renderServiceHistorySection() {
    const port = state.preferences.selectedService;
    const requestId = ++state.serviceHistoryRequestGeneration;
    if (port === null) {
      renderServiceHistoryPlaceholder();
      return;
    }
    const bounds = state.historyBounds || resolveRangeBounds();
    beginServiceHistoryLoadingState();
    const {telemetry, events} = await fetchServiceHistory(port, bounds.start_ts, bounds.end_ts);
    if (requestId !== state.serviceHistoryRequestGeneration) return;
    const loading = serviceHistoryElement('loading');
    if (loading) loading.hidden = true;
    const errorEl = serviceHistoryElement('error');
    const telemetryOutcome = telemetry.status === 'fulfilled' ? telemetry.value : null;
    const eventsOutcome = events.status === 'fulfilled' ? events.value : null;
    if (!telemetryOutcome && !eventsOutcome) {
      if (errorEl) {
        const reason = serverSuppliedReason(telemetry.reason) || serverSuppliedReason(events.reason);
        errorEl.textContent = `This service history could not load.${reason ? ` Server reported: ${reason}` : ''}`;
        errorEl.hidden = false;
      }
      return;
    }
    // The band and the latency chart are both composed from telemetry's own
    // points -- there is no independent "latency present, band absent (or
    // the reverse)" split at this fetch boundary, since both read the same
    // response. The events fetch is the one genuinely independent leg: on
    // its own failure, the band still renders from telemetry alone (every
    // offline second stays `offline` rather than being silently
    // reclassified `maintenance`) and the latency chart is unaffected, so
    // one stream's failure never blanks the whole service view.
    const content = serviceHistoryElement('content');
    if (!telemetryOutcome) {
      if (content) content.hidden = true;
      if (errorEl) {
        const reason = serverSuppliedReason(telemetry.reason);
        errorEl.textContent = `This service history could not load.${reason ? ` Server reported: ${reason}` : ''}`;
        errorEl.hidden = false;
      }
      return;
    }
    const points = Array.isArray(telemetryOutcome.points) ? telemetryOutcome.points : [];
    const coverage = telemetryOutcome.coverage;
    const requestedRange = telemetryOutcome.requested || bounds;
    const episodes = eventsOutcome && Array.isArray(eventsOutcome.episodes) ? eventsOutcome.episodes : [];
    if (content) content.hidden = false;
    if (errorEl) {
      if (eventsOutcome) {
        errorEl.hidden = true;
      } else {
        // Partial result (UI-SPEC E3): the band and chart still render
        // fully from telemetry alone -- this note discloses only the
        // missing maintenance-reclassification evidence, it never hides
        // the content that did load.
        const reason = serverSuppliedReason(events.reason);
        errorEl.textContent = `Maintenance-suppressed spans could not load for this range; offline time below may include maintenance that has not been reclassified.${reason ? ` Server reported: ${reason}` : ''}`;
        errorEl.hidden = false;
      }
    }
    const segments = mergeBandSegments(
      deriveBandSegments(points, episodes, telemetryOutcome.effective_resolution_seconds, requestedRange.end_ts),
    );
    renderServiceStateBand(segments, requestedRange);
    renderLatencyChart(points, coverage, requestedRange);
    renderAvailability(timeWeightedAvailability(points), requestedRange, episodes);
    renderFailureClassChips(aggregateFailureClasses(points));
  }

  // ------------------------------------------------------------------
  // Incidents section (Phase 4 04-07, D-12/D-13/D-14): a filterable list
  // where one row is one grouped down-to-recovered episode. Governed by the
  // same shared range control as History (D-16) -- never a second, section-
  // owned range.
  // ------------------------------------------------------------------

  // Builds the exact query params /api/events/history accepts. `filters`
  // carries the validated {service, criticality, eventType} shape
  // validHistoryFilters produces; a null/absent field is simply omitted
  // from the URL rather than sent as an empty string, matching the "no
  // maintenance parameter at all" default the server itself documents.
  function incidentQueryParams(startTs, endTs, filters) {
    const params = new URLSearchParams();
    params.set('start_ts', String(startTs));
    params.set('end_ts', String(endTs));
    const source = filters || DEFAULT_HISTORY_FILTERS;
    if (source.service !== null && source.service !== undefined) params.set('port', String(source.service));
    if (source.criticality) params.set('criticality', source.criticality);
    if (typeof source.eventType === 'string' && source.eventType.startsWith('event_type:')) {
      params.set('event_type', source.eventType.slice('event_type:'.length));
    } else if (typeof source.eventType === 'string' && source.eventType.startsWith('maintenance:')) {
      params.set('maintenance', source.eventType.slice('maintenance:'.length));
    }
    return params;
  }

  async function fetchIncidents(startTs, endTs, filters) {
    const url = `/api/events/history?${incidentQueryParams(startTs, endTs, filters).toString()}`;
    const response = await fetch(url, {cache: 'no-store'});
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { message = (await response.json()).error || message; } catch (_) { /* bounded status evidence */ }
      throw new Error(message);
    }
    return response.json();
  }

  function incidentsElement(suffix) {
    return $(`incidents-${suffix}`);
  }

  function beginIncidentsLoadingState() {
    const loading = incidentsElement('loading');
    const empty = incidentsElement('empty');
    const error = incidentsElement('error');
    const truncated = incidentsElement('truncated');
    const list = incidentsElement('list');
    if (loading) loading.hidden = false;
    if (empty) empty.hidden = true;
    if (error) { error.hidden = true; error.textContent = ''; }
    if (truncated) { truncated.hidden = true; truncated.textContent = ''; }
    if (list) list.replaceChildren();
  }

  function updateMatchingIncidentCount(matching, total) {
    const el = $('matching-incident-count');
    if (el) el.textContent = `${matching} of ${total} incidents`;
  }

  // Populated from the same current snapshot's service list the Services
  // table and the History picker already read -- never a second,
  // independently-fetched list (mirrors renderHistoryServicePicker).
  function populateIncidentServiceFilterOptions() {
    const select = $('incident-service-filter');
    if (!select) return;
    const services = Array.isArray(state.snapshot && state.snapshot.services) ? state.snapshot.services : [];
    const unique = new Map();
    services.forEach((service) => {
      const port = Number(service.port);
      if (Number.isFinite(port) && !unique.has(port)) unique.set(port, service);
    });
    const sorted = [...unique.values()].sort((left, right) => (
      String(left.name || left.title || '').localeCompare(String(right.name || right.title || ''))
      || Number(left.port) - Number(right.port)
    ));
    const currentValue = state.preferences.historyFilters.service === null ? '' : String(state.preferences.historyFilters.service);
    select.replaceChildren(Object.assign(document.createElement('option'), {value: '', textContent: 'All services'}));
    sorted.forEach((service) => {
      const option = document.createElement('option');
      option.value = String(Number(service.port));
      option.textContent = `${service.name || service.title || `Port ${service.port}`} :${service.port}`;
      select.append(option);
    });
    select.value = currentValue;
  }

  // D-16: the filter's own value is never an independent fact -- it always
  // states the one carried selection (setSelectedService is what mutates
  // it; this only reflects that state into the control after a change made
  // from elsewhere, e.g. the Services table or an incident focus).
  function syncIncidentServiceFilterControl() {
    const select = $('incident-service-filter');
    if (!select) return;
    const value = state.preferences.historyFilters.service;
    select.value = value === null ? '' : String(value);
  }

  function syncIncidentFilterControls() {
    syncIncidentServiceFilterControl();
    const criticality = $('incident-criticality-filter');
    if (criticality) criticality.value = state.preferences.historyFilters.criticality || '';
    const eventType = $('incident-event-type-filter');
    if (eventType) eventType.value = state.preferences.historyFilters.eventType || '';
  }

  // D-14: renders the full down_ts-to-recovered_ts span split at grace
  // expiry into a grace-covered sub-segment and a post-grace unplanned-
  // fault sub-segment, sized by the server's own grace_seconds/fault_seconds
  // -- never recomputed client-side. A non-overrun closed episode is simply
  // the degenerate case (grace_seconds 0, fault_seconds the whole span), so
  // no special-case branch is needed for the common incident. An open
  // episode renders no bar at all: its fault portion cannot be measured
  // against a clock nobody observed (D-12 Pitfall 4).
  function incidentDurationBar(episode) {
    const bar = document.createElement('div');
    bar.className = 'incident-duration-bar';
    if (episode.open) return bar;
    const grace = Number(episode.grace_seconds) || 0;
    const fault = Number(episode.fault_seconds) || 0;
    const total = grace + fault;
    if (total <= 0) return bar;
    if (grace > 0) {
      const graceEl = document.createElement('span');
      graceEl.className = 'incident-duration-grace';
      graceEl.style.width = `${(grace / total) * 100}%`;
      graceEl.title = `Grace-covered: ${formatSpan(grace)}`;
      bar.append(graceEl);
    }
    if (fault > 0) {
      const faultEl = document.createElement('span');
      faultEl.className = 'incident-duration-fault';
      faultEl.style.width = `${(fault / total) * 100}%`;
      faultEl.title = `Unplanned fault: ${formatSpan(fault)}`;
      bar.append(faultEl);
    }
    return bar;
  }

  const INCIDENT_TIMESTAMP_OPTIONS = {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'};

  // One grouped down-to-recovered episode (D-12), rendered in the existing
  // .diagnosis-card/.evidence-row visual language rather than a dense table
  // cell -- incident rows carry more prose than the Services table's
  // compact cells warrant. Every timestamp goes through formatLocalTimestamp.
  function incidentRow(episode) {
    const serviceLabel = `${displayValue(episode.service_name)} :${displayValue(episode.port)}`;
    const startLabel = formatLocalTimestamp(episode.down_ts, INCIDENT_TIMESTAMP_OPTIONS);

    const row = document.createElement('div');
    row.className = 'incident-row';
    row.setAttribute('role', 'button');
    row.tabIndex = 0;
    row.setAttribute('aria-label', `Investigate ${serviceLabel} incident starting ${startLabel}`);

    const header = document.createElement('div');
    header.className = 'incident-row-header';
    const service = document.createElement('span');
    service.className = 'incident-service';
    service.textContent = serviceLabel;
    header.append(service);
    if (episode.suppressed_reason) {
      const chip = document.createElement('span');
      chip.className = 'incident-chip-expected';
      chip.textContent = 'Expected';
      header.append(chip);
    }
    // D-12/Pitfall 4: never a synthesized end-time or a duration computed
    // against "now" -- the badge is text plus glyph so it never depends on
    // colour alone (UI-SPEC Copywriting Contract).
    if (episode.open) {
      const badge = document.createElement('span');
      badge.className = 'incident-badge-open';
      badge.textContent = '▶ Ongoing — not yet recovered';
      header.append(badge);
    }
    row.append(header);

    const timestamps = document.createElement('div');
    timestamps.className = 'incident-timestamps';
    if (!episode.open && episode.overrun) {
      // D-14: both durable timestamps, always two separate lines, never
      // merged into one string -- matching the existing Down since/Raised
      // at precedent this file already established for the Services
      // section's own overrun evidence rows.
      const downLine = document.createElement('p');
      downLine.textContent = `Down since ${formatLocalTimestamp(episode.down_ts, INCIDENT_TIMESTAMP_OPTIONS)}`;
      const raisedLine = document.createElement('p');
      raisedLine.textContent = `Raised at ${formatLocalTimestamp(episode.raised_ts, INCIDENT_TIMESTAMP_OPTIONS)}`;
      timestamps.append(downLine, raisedLine);
    } else {
      const startLine = document.createElement('p');
      startLine.textContent = `Start: ${formatLocalTimestamp(episode.down_ts, INCIDENT_TIMESTAMP_OPTIONS)}`;
      timestamps.append(startLine);
      // D-12/Pitfall 4: an open episode renders no end line at all -- never
      // a synthesized end-time, not even a placeholder word in an "End:"
      // slot -- so "the row contains no end timestamp" is literal, not
      // merely un-dated text.
      if (!episode.open) {
        const endLine = document.createElement('p');
        endLine.textContent = `End: ${formatLocalTimestamp(episode.recovered_ts, INCIDENT_TIMESTAMP_OPTIONS)}`;
        timestamps.append(endLine);
      }
    }
    row.append(timestamps);
    row.append(incidentDurationBar(episode));

    // UI-SPEC "Incidents list": duration, failure class and criticality are
    // one wrapping inline-metadata group that collapses to a second line at
    // narrow widths rather than truncating any of it.
    const meta = document.createElement('div');
    meta.className = 'incident-meta';
    const criticalityEl = document.createElement('span');
    criticalityEl.textContent = episode.critical ? 'Critical' : 'Standard';
    meta.append(criticalityEl);
    const durationEl = document.createElement('span');
    durationEl.textContent = episode.open ? 'Duration: Ongoing' : `Duration: ${formatSpan(episode.duration_seconds)}`;
    meta.append(durationEl);
    const failureClassEl = document.createElement('span');
    failureClassEl.textContent = `Failure class: ${displayValue(episode.failure_class)}`;
    meta.append(failureClassEl);
    row.append(meta);

    // D-12: the raw state_change transitions this episode was grouped from,
    // available on expand -- reusing the existing expand-on-click
    // detail-row pattern (toggleServiceDetails's own aria-expanded idiom).
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'incident-transitions-toggle';
    toggle.textContent = 'Show transitions';
    toggle.setAttribute('aria-expanded', 'false');
    const transitionsList = document.createElement('div');
    transitionsList.className = 'incident-transitions';
    transitionsList.hidden = true;
    (Array.isArray(episode.transitions) ? episode.transitions : []).forEach((transition) => {
      const line = document.createElement('p');
      const onlineWord = transition.online === 1 ? 'online' : transition.online === 0 ? 'offline' : 'unknown';
      line.textContent = `${displayValue(transition.event_type)} — ${formatLocalTimestamp(transition.ts, INCIDENT_TIMESTAMP_OPTIONS)} — ${onlineWord}`;
      transitionsList.append(line);
    });
    toggle.addEventListener('click', (event) => {
      event.stopPropagation();
      const expanded = toggle.getAttribute('aria-expanded') === 'true';
      toggle.setAttribute('aria-expanded', String(!expanded));
      toggle.textContent = expanded ? 'Show transitions' : 'Hide transitions';
      transitionsList.hidden = expanded;
    });
    row.append(toggle, transitionsList);

    // Task 3 (D-15): the whole row is the focus target rather than a
    // separate button -- guarded so a click/keypress on the nested
    // transitions toggle never also triggers a focus push.
    row.addEventListener('click', (event) => {
      if (event.target.closest('.incident-transitions-toggle')) return;
      focusIncident(episode);
    });
    row.addEventListener('keydown', (event) => {
      if (event.target !== row) return;
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        focusIncident(episode);
      }
    });
    return row;
  }

  // A purely presentational grouping label above a dense run of same-service
  // episodes (Claude's Discretion resolved, D-12): it merges no rows,
  // filters nothing, and creates no record. Every episode in the group
  // still renders as its own row.
  function renderFlappingBanner(group) {
    const banner = document.createElement('div');
    banner.className = 'incident-flapping-banner';
    banner.textContent = `Flapping — ${group.count} episodes in ${formatSpan(group.span_seconds)}`;
    return banner;
  }

  function renderIncidents(episodes, flappingGroups) {
    const list = $('incidents-list');
    if (!list) return;
    const groupsById = new Map((Array.isArray(flappingGroups) ? flappingGroups : []).map((group) => [group.id, group]));
    const seenGroups = new Set();
    const fragment = document.createDocumentFragment();
    episodes.forEach((episode) => {
      const groupId = episode.flapping_group_id;
      if (groupId !== null && groupId !== undefined && groupsById.has(groupId) && !seenGroups.has(groupId)) {
        seenGroups.add(groupId);
        fragment.append(renderFlappingBanner(groupsById.get(groupId)));
      }
      fragment.append(incidentRow(episode));
    });
    list.replaceChildren(fragment);
  }

  // Fetches the currently-filtered list and an unfiltered baseline for the
  // same range in parallel -- "N of M incidents" needs both numbers (M is
  // deliberately never narrowed by the operator's own filter selection),
  // and the two are otherwise independent reads of the same range.
  async function renderIncidentsSection() {
    const requestId = ++state.incidentsRequestGeneration;
    const bounds = state.historyBounds || resolveRangeBounds();
    const filters = state.preferences.historyFilters;
    populateIncidentServiceFilterOptions();
    syncIncidentFilterControls();
    beginIncidentsLoadingState();
    const [filteredOutcome, totalOutcome] = await Promise.allSettled([
      fetchIncidents(bounds.start_ts, bounds.end_ts, filters),
      fetchIncidents(bounds.start_ts, bounds.end_ts, DEFAULT_HISTORY_FILTERS),
    ]);
    if (requestId !== state.incidentsRequestGeneration) return;
    const loading = incidentsElement('loading');
    if (loading) loading.hidden = true;
    const errorEl = incidentsElement('error');
    const emptyEl = incidentsElement('empty');
    const truncatedEl = incidentsElement('truncated');
    const listEl = incidentsElement('list');
    if (filteredOutcome.status !== 'fulfilled') {
      if (errorEl) {
        errorEl.textContent = 'Beacon could not load incidents for this range. Try again, or narrow the range.';
        errorEl.hidden = false;
      }
      if (emptyEl) emptyEl.hidden = true;
      if (listEl) listEl.replaceChildren();
      return;
    }
    if (errorEl) { errorEl.hidden = true; errorEl.textContent = ''; }
    const payload = filteredOutcome.value;
    const episodes = Array.isArray(payload.episodes) ? payload.episodes : [];
    const flappingGroups = Array.isArray(payload.flapping_groups) ? payload.flapping_groups : [];
    const total = totalOutcome.status === 'fulfilled' && Array.isArray(totalOutcome.value.episodes)
      ? totalOutcome.value.episodes.length
      : episodes.length;
    updateMatchingIncidentCount(episodes.length, total);
    if (truncatedEl) {
      if (payload.truncated) {
        truncatedEl.textContent = 'This incidents list was truncated at the row budget; not every matching incident in this range and these filters is shown.';
        truncatedEl.hidden = false;
      } else {
        truncatedEl.hidden = true;
        truncatedEl.textContent = '';
      }
    }
    if (episodes.length === 0) {
      if (emptyEl) emptyEl.hidden = false;
      if (listEl) listEl.replaceChildren();
      return;
    }
    if (emptyEl) emptyEl.hidden = true;
    renderIncidents(episodes, flappingGroups);
  }

  // ------------------------------------------------------------------
  // Investigation focus (Phase 4 04-07 Task 3, D-15): choosing an incident
  // moves the whole investigation -- range, carried service, and every
  // range-aware/service-aware view -- together, non-destructively.
  // ------------------------------------------------------------------

  // The window to push onto the shared navigation stack (D-15's resolved
  // padding rule): 15% of the episode's own span on each side, floored at
  // INCIDENT_PAD_FLOOR_SECONDS -- so a one-minute blip stays legible and a
  // long outage is not padded into an unreasonably wide window. An open
  // episode's end is `now`, capped at the current shared range's own
  // end_ts, both before AND after padding, so a focus can never ask for a
  // window later than the range control can state. The padded window is
  // then clamped to the 90-day retention bound the server itself enforces,
  // so a focus can never request a span the server will reject.
  function incidentFocusWindow(episode, currentRange) {
    const nowTs = Math.floor(Date.now() / 1000);
    const baseEnd = episode.open ? Math.min(nowTs, currentRange.end_ts) : episode.recovered_ts;
    const baseStart = episode.down_ts;
    const span = Math.max(0, baseEnd - baseStart);
    const pad = Math.max(INCIDENT_PAD_FLOOR_SECONDS, Math.round(span * INCIDENT_PAD_FRACTION));
    let start_ts = baseStart - pad;
    let end_ts = baseEnd + pad;
    if (episode.open) end_ts = Math.min(end_ts, currentRange.end_ts);
    const retentionSeconds = HISTORY_PRESETS['90d'];
    if (end_ts - start_ts > retentionSeconds) start_ts = end_ts - retentionSeconds;
    return {start_ts, end_ts};
  }

  // Does exactly two things, in this order (Task 3 action text): the
  // episode's own service becomes the carried selection, then its padded
  // window is pushed onto the shared range stack -- so the host charts, the
  // service views and the incident list all move together.
  function focusIncident(episode) {
    const currentRange = state.historyBounds || resolveRangeBounds();
    const window = incidentFocusWindow(episode, currentRange);
    const label = currentRangeLabel();
    setSelectedService(Number(episode.port));
    setInvestigationRange({...window, origin: 'incident', label});
  }

  // ------------------------------------------------------------------
  // Custom local-time range entry (Phase 4 04-05, D-03): explicit start/end
  // fields are the canonical, statable entry -- interpreted in the Pi's
  // configured timezone (state.timezone), never the browser's.
  // ------------------------------------------------------------------

  const CUSTOM_RANGE_TEXT_PATTERN = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})$/;

  // Interprets `text` as wall-clock time in the Pi's configured timezone by
  // building a candidate instant and correcting it against localWallClockMinutes'
  // own reading of that instant -- reusing the exact naive-local-minutes
  // technique the DST-tick detector below already establishes, rather than
  // manual UTC-offset arithmetic or a hard-coded transition table. Converges
  // in at most a couple of iterations since a timezone offset only ever
  // changes in fixed-size (typically one-hour) steps. Returns null for
  // anything that does not parse as YYYY-MM-DD HH:MM (or a T separator).
  function parseLocalRangeInput(text) {
    if (typeof text !== 'string') return null;
    const match = text.trim().match(CUSTOM_RANGE_TEXT_PATTERN);
    if (!match) return null;
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59) return null;
    const targetMinutes = Date.UTC(year, month - 1, day, hour, minute) / 60000;
    let candidate = targetMinutes * 60;
    for (let iteration = 0; iteration < 3; iteration += 1) {
      const renderedMinutes = localWallClockMinutes(candidate);
      const deltaMinutes = targetMinutes - renderedMinutes;
      if (deltaMinutes === 0) break;
      candidate += deltaMinutes * 60;
    }
    return Number.isFinite(candidate) ? Math.round(candidate) : null;
  }

  // The exact inverse of parseLocalRangeInput's expected shape, for writing
  // the fields back after every range change from any source.
  function formatLocalRangeInput(ts) {
    if (!Number.isFinite(ts)) return '';
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: state.timezone || 'UTC', hourCycle: 'h23',
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
    }).formatToParts(new Date(ts * 1000));
    const get = (type) => parts.find((part) => part.type === type).value;
    return `${get('year')}-${get('month')}-${get('day')} ${get('hour')}:${get('minute')}`;
  }

  // Applies exactly the bounds the server applies (dashboard/beacon/telemetry.py
  // HistoricalRange, dashboard/app.py api_telemetry_history's future-end check),
  // reading every rejection string from that server behaviour rather than
  // inventing a paraphrase -- a change on either side shows up as a failing
  // test, never as two different wordings.
  function validateCustomRange(startTs, endTs) {
    if (startTs === null || endTs === null || !Number.isFinite(startTs) || !Number.isFinite(endTs)) {
      return {valid: false, message: 'Enter both a start and an end time.'};
    }
    if (startTs >= endTs) {
      return {valid: false, message: 'start_ts must be before end_ts'};
    }
    if (endTs - startTs > HISTORY_PRESETS['90d']) {
      return {valid: false, message: 'requested span exceeds 90 days'};
    }
    if (endTs > Math.floor(Date.now() / 1000)) {
      return {valid: false, message: 'end_ts must not be in the future'};
    }
    return {valid: true, message: null};
  }

  // Names the range currently governing the charts, in words -- a preset id
  // such as '24h', or the custom range's own start/end. Used both by the
  // Back label (naming the range a pop restores) and as the fallback push
  // label when a caller does not supply one of its own.
  function currentRangeLabel() {
    const descriptor = state.preferences.historyRange;
    if (descriptor && descriptor.custom) {
      return `${formatLocalRangeInput(descriptor.custom.start_ts)} – ${formatLocalRangeInput(descriptor.custom.end_ts)}`;
    }
    return (descriptor && descriptor.preset) || '24h';
  }

  // D-15: the shared in-memory navigation stack every narrowing gesture
  // (drag, incident focus -- plan 04-07) pushes onto, bounded by
  // RANGE_STACK_LIMIT (oldest entry dropped beyond that, never grown
  // unbounded). Never persisted, never the URL (D-18).
  function pushRange(entry) {
    state.rangeStack.push(entry);
    while (state.rangeStack.length > RANGE_STACK_LIMIT) state.rangeStack.shift();
  }

  // Restores exactly one entry -- N pushes followed by N pops restore the
  // original range exactly. A no-op (empty stack) is silently ignored.
  function popRange() {
    const entry = state.rangeStack.pop();
    if (!entry) return;
    state.preferences.historyRange = entry.descriptor;
    applyRangeAndRender();
  }

  function clearRangeStack() {
    state.rangeStack = [];
  }

  // Writes the currently governing range into the two fields (D-03: the
  // fields are the authoritative, statable representation of the current
  // range at all times) and shows/hides the custom-range label. When a
  // custom range is active, exactly one thing indicates it -- the fields'
  // own active styling -- and no preset carries aria-pressed (already true
  // by construction: syncHistoryPresetButtons compares against .preset,
  // which is undefined on a custom descriptor).
  function renderRangeFields() {
    const bounds = resolveRangeBounds();
    const startField = $('range-start');
    const endField = $('range-end');
    if (startField) startField.value = formatLocalRangeInput(bounds.start_ts);
    if (endField) endField.value = formatLocalRangeInput(bounds.end_ts);
    const descriptor = state.preferences.historyRange;
    const isCustom = Boolean(descriptor && descriptor.custom);
    const fieldsContainer = $('hist-range-fields');
    if (fieldsContainer) fieldsContainer.classList.toggle('hist-range-active', isCustom);
    const label = $('range-custom-label');
    if (label) {
      if (isCustom) {
        label.textContent = `Custom range: ${currentRangeLabel()}`;
        label.hidden = false;
      } else {
        label.textContent = '';
        label.hidden = true;
      }
    }
  }

  // D-15: absent from the DOM entirely with an empty stack -- not merely
  // hidden -- so popping is unreachable rather than present-and-disabled.
  // The button is created/removed here rather than toggled via `hidden`.
  function renderBackControl() {
    const container = $('range-back-row');
    if (!container) return;
    const entry = state.rangeStack[state.rangeStack.length - 1];
    let button = $('range-back');
    if (!entry) {
      if (button) button.remove();
      return;
    }
    const text = `Back to ${entry.label}`;
    if (!button) {
      button = document.createElement('button');
      button.type = 'button';
      button.id = 'range-back';
      button.className = 'hist-back';
      button.addEventListener('click', () => popRange());
      container.append(button);
    }
    button.textContent = text;
    button.title = text;
  }

  // The single tail every range-change entry point (setInvestigationRange,
  // popRange) shares: persist, then re-render every surface that must state
  // the current range, per every source (D-03).
  function applyRangeAndRender() {
    savePreferences();
    syncHistoryPresetButtons();
    renderRangeFields();
    renderBackControl();
    renderHistorySection();
    // D-16: the shared range governs both range-aware sections at once --
    // Incidents must reflect a drag/incident-focus/Back range change even
    // while History is the one currently visible, so switching tabs never
    // shows a stale list.
    renderIncidentsSection();
  }

  // D-15: the single entry point every range change -- preset, custom apply,
  // drag, incident focus (plan 04-07), and popRange's own restore -- flows
  // through, and the only place that owns the stack.
  //   next.origin === 'manual' (a preset button or Apply custom range) calls
  //     clearRangeStack() first -- a manual range change is a fresh
  //     investigation, not a continuation of the drill-down chain.
  //   next.origin === 'drag' | 'incident' pushes the range being left before
  //     adopting the new one, UNLESS the resulting bounds are exactly equal
  //     to the current bounds -- that push is a no-op: nothing is recorded,
  //     and Back does not appear for it, because there is nothing to return
  //     to.
  //   next.presetId, when present, records the adopted range as a live
  //     preset descriptor (recomputed from Date.now() on every future
  //     render) rather than a fixed custom range -- this is what keeps that
  //     preset's own aria-pressed state correct after the range changes.
  function setInvestigationRange(next) {
    const {start_ts, end_ts, origin, label, presetId} = next;
    if (origin === 'manual') {
      clearRangeStack();
    } else {
      const before = resolveRangeBounds();
      const isNoOp = before.start_ts === start_ts && before.end_ts === end_ts;
      if (!isNoOp) {
        pushRange({descriptor: {...state.preferences.historyRange}, origin, label: label || currentRangeLabel()});
      }
    }
    state.preferences.historyRange = presetId ? {preset: presetId} : {custom: {start_ts, end_ts}};
    applyRangeAndRender();
  }

  // Applying a valid custom range routes through setInvestigationRange, the
  // single entry point every range change flows through -- never builds a
  // request from anything but the two parsed, validated integers. A blank,
  // whitespace-only, unparseable, reversed, equal, over-90-day, or
  // future-ending input surfaces its message in #range-error and issues no
  // request; the previously rendered charts are left intact because
  // renderHistorySection is never invoked on this path.
  function applyCustomRange() {
    const startField = $('range-start');
    const endField = $('range-end');
    const startTs = parseLocalRangeInput(startField ? startField.value : '');
    const endTs = parseLocalRangeInput(endField ? endField.value : '');
    const result = validateCustomRange(startTs, endTs);
    const errorEl = $('range-error');
    if (!result.valid) {
      if (errorEl) { errorEl.textContent = result.message; errorEl.hidden = false; }
      return;
    }
    if (errorEl) { errorEl.hidden = true; errorEl.textContent = ''; }
    setInvestigationRange({start_ts: startTs, end_ts: endTs, origin: 'manual'});
  }

  // ------------------------------------------------------------------
  // Drag-to-select (Phase 4 04-05 Task 3, D-03): dragging across any host
  // chart narrows the range through the exact same setInvestigationRange
  // entry point the fields and presets use -- never a second, competing
  // range-state mechanism. Pointer-driven updates are coalesced through
  // requestAnimationFrame and touch only the overlay rectangle's geometry;
  // chart <path> `d` attributes are never regenerated during a drag
  // (Research Pitfall 3, R-01's single largest Pi-performance hazard).
  // ------------------------------------------------------------------

  const HIST_DRAG_MIN_PIXELS = 1;
  let dragState = null;
  let pendingDragFrame = null;

  function dragOverlayEl() {
    return $('history-drag-overlay');
  }

  function stackContainerEl() {
    return $('history-content');
  }

  // The domain a drag maps pixels into: the bounds the chart stack is
  // actually rendered against (set by renderHistorySection from the
  // server's own `requested` echo, falling back to the locally-resolved
  // bounds before any fetch has completed), never the browser's own guess.
  function chartTimeDomain() {
    return state.historyBounds || resolveRangeBounds();
  }

  function clientXToTs(clientX, chartRect) {
    const domain = chartTimeDomain();
    const clamped = Math.min(chartRect.right, Math.max(chartRect.left, clientX));
    const fraction = (clamped - chartRect.left) / Math.max(1, chartRect.width);
    return domain.start_ts + fraction * (domain.end_ts - domain.start_ts);
  }

  function updateDragOverlayGeometry() {
    const overlay = dragOverlayEl();
    if (!overlay || !dragState) return;
    const {chartRect, containerRect, startClientX, currentClientX} = dragState;
    const left = Math.max(chartRect.left, Math.min(startClientX, currentClientX));
    const right = Math.min(chartRect.right, Math.max(startClientX, currentClientX));
    overlay.style.left = `${left}px`;
    overlay.style.width = `${Math.max(0, right - left)}px`;
    overlay.style.top = `${containerRect.top}px`;
    overlay.style.height = `${containerRect.height}px`;
  }

  function dragEscapeListener(event) {
    if (event.key === 'Escape') cancelDragSelect();
  }

  function endDragListeners() {
    window.removeEventListener('pointermove', updateDragSelect);
    window.removeEventListener('pointerup', commitDragSelect);
    window.removeEventListener('pointercancel', cancelDragSelect);
    window.removeEventListener('keydown', dragEscapeListener);
  }

  // Clears the overlay on pointer-cancel, on Escape, and on a drag that ends
  // where it began (see commitDragSelect's own degenerate-drag check, which
  // calls this same cleanup rather than duplicating it).
  function cancelDragSelect() {
    if (pendingDragFrame !== null) { cancelAnimationFrame(pendingDragFrame); pendingDragFrame = null; }
    const overlay = dragOverlayEl();
    if (overlay) { overlay.hidden = true; overlay.style.width = '0px'; }
    dragState = null;
    endDragListeners();
  }

  // R-03: dragging to select a range has no keyboard equivalent in this
  // phase -- the canonical #range-start/#range-end fields remain the fully
  // keyboard-operable path to any range (DIA-05). This is known Phase 5 / UX-06
  // debt, recorded here at creation rather than discovered later.
  function beginDragSelect(event) {
    if (event.pointerType === 'mouse' && event.button !== 0) return;
    const chartSvg = event.currentTarget;
    const container = stackContainerEl();
    if (!chartSvg || !container) return;
    dragState = {
      chartRect: chartSvg.getBoundingClientRect(),
      containerRect: container.getBoundingClientRect(),
      startClientX: event.clientX,
      currentClientX: event.clientX,
    };
    const overlay = dragOverlayEl();
    if (overlay) overlay.hidden = false;
    updateDragOverlayGeometry();
    window.addEventListener('pointermove', updateDragSelect);
    window.addEventListener('pointerup', commitDragSelect);
    window.addEventListener('pointercancel', cancelDragSelect);
    window.addEventListener('keydown', dragEscapeListener);
  }

  // Coalesces every pointermove through requestAnimationFrame -- updates
  // only the overlay rectangle's geometry, never a chart <path>.
  function updateDragSelect(event) {
    if (!dragState) return;
    dragState.currentClientX = event.clientX;
    if (pendingDragFrame !== null) return;
    pendingDragFrame = requestAnimationFrame(() => {
      pendingDragFrame = null;
      updateDragOverlayGeometry();
    });
  }

  // Converts the two x positions to timestamps, ordering them so a
  // right-to-left drag produces the same range as a left-to-right one, and
  // routes through the same setInvestigationRange entry point the fields
  // and presets use. A degenerate drag (equal timestamps, or narrower than
  // one rendered pixel) is cancelled rather than applied -- the server
  // would reject a zero-width range, and the gesture was almost certainly a
  // click, not a selection.
  function commitDragSelect(event) {
    if (!dragState) return;
    const {chartRect, startClientX} = dragState;
    const endClientX = event.clientX;
    const widthPixels = Math.abs(endClientX - startClientX);
    cancelDragSelect();
    if (widthPixels < HIST_DRAG_MIN_PIXELS) return;
    const tsA = clientXToTs(startClientX, chartRect);
    const tsB = clientXToTs(endClientX, chartRect);
    const start_ts = Math.round(Math.min(tsA, tsB));
    const end_ts = Math.round(Math.max(tsA, tsB));
    if (end_ts <= start_ts) return;
    setInvestigationRange({start_ts, end_ts, origin: 'drag', label: currentRangeLabel()});
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

  // ------------------------------------------------------------------
  // Trend (HIS-06, D-08, D-09, Phase 4 04-04): a least-squares slope over
  // observed points only -- withheld below TREND_MIN_POINTS, qualified
  // below TREND_CONFIDENT_POINTS, flat-banded to "steady", and never
  // extrapolated into a projection. Composed over the same points array
  // renderHistoryChart already fetched -- no second request is issued.
  // ------------------------------------------------------------------

  const TREND_MIN_POINTS = 3;
  const TREND_CONFIDENT_POINTS = 10;
  const TREND_HOURLY_MAX_SPAN_SECONDS = 86400;
  const TREND_ARROWS = {up: '↑', down: '↓'};

  // Keeps only points whose avg_value is a finite measurement -- finiteMeasurement's
  // type discipline means a boolean, array, object or blank string is an absence,
  // never a zero -- sorted ascending by ts. The server composes one bucket per ts,
  // so two points sharing a ts cannot occur; sorting only guards against caller
  // order, which is what makes the slope invariant to input order.
  function usableTrendPoints(points) {
    return (Array.isArray(points) ? points : [])
      .map((point) => ({ts: point.ts, value: finiteMeasurement(point.avg_value)}))
      .filter((point) => point.value !== null && Number.isFinite(point.ts))
      .sort((left, right) => left.ts - right.ts);
  }

  // Closed-form least-squares gradient of value against ts, in value-units per
  // second. Fewer than two usable points returns null -- there is no line to fit.
  function leastSquaresSlope(points) {
    const usable = usableTrendPoints(points);
    if (usable.length < 2) return null;
    const n = usable.length;
    const meanX = usable.reduce((sum, point) => sum + point.ts, 0) / n;
    const meanY = usable.reduce((sum, point) => sum + point.value, 0) / n;
    let numerator = 0;
    let denominator = 0;
    usable.forEach((point) => {
      const dx = point.ts - meanX;
      numerator += dx * (point.value - meanY);
      denominator += dx * dx;
    });
    return denominator === 0 ? 0 : numerator / denominator;
  }

  // Turns the raw per-second slope into the exact contracted copy. Nothing
  // returned here may express a future arrival at some value or a countdown
  // to one -- the slope describes only the window that was observed. The
  // internal predicted-change-over-window quantity used below to decide the
  // flat band is a comparison only and is never rendered.
  function trendDisplay(metric, points, spanSeconds) {
    const usable = usableTrendPoints(points);
    const label = (HOST_METRIC_LABELS[metric] || metric).toLowerCase();
    if (usable.length < TREND_MIN_POINTS) return 'Not enough data for a trend';
    const perSecond = leastSquaresSlope(points);
    const hourly = spanSeconds <= TREND_HOURLY_MAX_SPAN_SECONDS;
    const secondsPerUnit = hourly ? 3600 : 86400;
    const timeUnit = hourly ? 'hour' : 'day';
    const magnitude = (perSecond || 0) * secondsPerUnit;
    const formattedMagnitude = Math.abs(magnitude).toFixed(1);
    if (Number(formattedMagnitude) === 0) return `${label} steady`;
    const sign = magnitude >= 0 ? '+' : '-';
    const arrow = magnitude >= 0 ? TREND_ARROWS.up : TREND_ARROWS.down;
    const unit = HOST_METRIC_UNITS[metric] || '';
    const base = `${label} ${sign}${formattedMagnitude}${unit}/${timeUnit} ${arrow}`;
    return usable.length < TREND_CONFIDENT_POINTS ? `${base} (low confidence — ${usable.length} points)` : base;
  }

  // Test-only hook, same pattern as window.__historyStackRenderMs: these two
  // functions are pure and otherwise private to this IIFE, so Playwright's
  // page.evaluate needs a reachable handle to drive them directly.
  window.__historyTrendTestHooks = {leastSquaresSlope, trendDisplay};

  // ------------------------------------------------------------------
  // Comparison row (HIS-06, D-08, D-09, Phase 4 04-04): latest, minimum,
  // maximum, average, and trend, all describing the same selected-range
  // window as each other -- reduced from the same points array the chart
  // already fetched, no second request.
  // ------------------------------------------------------------------

  // Reduces the fetched points to the five range-comparison values. minimum
  // and maximum are the extremes of the points' own min_value/max_value;
  // average is the sample_count-weighted mean of avg_value, matching how
  // the server itself composes an average across mixed-resolution buckets
  // (_compose_host_bucket) -- an unweighted mean of bucket averages would
  // silently over-weight sparse buckets. latest is the latest_value of the
  // latest point (by ts) that has one -- the latest *observed* point inside
  // the range, never "now" (D-09).
  function rangeAggregate(points) {
    const list = (Array.isArray(points) ? points : []).slice().sort((left, right) => left.ts - right.ts);
    const minimums = list.map((point) => finiteMeasurement(point.min_value)).filter((value) => value !== null);
    const maximums = list.map((point) => finiteMeasurement(point.max_value)).filter((value) => value !== null);
    const weighted = list
      .map((point) => ({value: finiteMeasurement(point.avg_value), weight: finiteMeasurement(point.sample_count)}))
      .filter((point) => point.value !== null && point.weight !== null && point.weight > 0);
    const totalWeight = weighted.reduce((sum, point) => sum + point.weight, 0);
    const latestCandidates = list.filter((point) => finiteMeasurement(point.latest_value) !== null && Number.isFinite(point.ts));
    const latest = latestCandidates.length ? latestCandidates[latestCandidates.length - 1] : null;
    return {
      minimum: minimums.length ? Math.min(...minimums) : null,
      maximum: maximums.length ? Math.max(...maximums) : null,
      average: totalWeight > 0 ? weighted.reduce((sum, point) => sum + point.value * point.weight, 0) / totalWeight : null,
      latestValue: latest ? finiteMeasurement(latest.latest_value) : null,
      latestTs: latest ? latest.ts : null,
    };
  }

  // The single rounding site for the comparison row: a fixed one-decimal
  // formatter, so no displayed rounded value is ever read back and fed into
  // a further computation. null/undefined/non-finite is the absence string
  // "Unknown" -- never a fabricated 0.
  function formatComparisonValue(value, unit) {
    if (value === null || value === undefined || !Number.isFinite(value)) return 'Unknown';
    return `${value.toFixed(1)}${unit || ''}`;
  }

  // Writes Latest, Minimum, Maximum, Average, and Trend into comparison-{metric}.
  // Latest always renders its own exact local timestamp beside it (D-09) --
  // the range bounds are the disambiguator that stops a past-ending range from
  // reading as a current reading. A range with no usable point renders Unknown
  // for all four values and the withheld trend string; none of them is ever 0.
  function renderComparisonRow(metric, points, spanSeconds) {
    const container = $(`comparison-${metric}`);
    if (!container) return;
    while (container.firstChild) container.removeChild(container.firstChild);
    const unit = HOST_METRIC_UNITS[metric] || '';
    const aggregate = rangeAggregate(points);
    const latestText = aggregate.latestValue === null
      ? 'Latest: Unknown'
      : `Latest: ${formatComparisonValue(aggregate.latestValue, unit)} (as of ${formatLocalTimestamp(aggregate.latestTs, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'})})`;
    const rows = [
      {text: latestText, extraClass: null},
      {text: `Minimum: ${formatComparisonValue(aggregate.minimum, unit)}`, extraClass: null},
      {text: `Maximum: ${formatComparisonValue(aggregate.maximum, unit)}`, extraClass: null},
      {text: `Average: ${formatComparisonValue(aggregate.average, unit)}`, extraClass: null},
      {text: trendDisplay(metric, points, spanSeconds), extraClass: 'hist-trend'},
    ];
    rows.forEach((row) => {
      const span = document.createElement('span');
      span.className = row.extraClass ? `hist-comparison-value ${row.extraClass}` : 'hist-comparison-value';
      span.textContent = row.text;
      container.append(span);
    });
  }

  // D-05/Research Pitfall 6: a "naive" local wall-clock minute index built
  // from Intl.DateTimeFormat's own year/month/day/hour/minute parts for the
  // configured zone -- never manual UTC-offset arithmetic. Treating those
  // components as if they were UTC (via Date.UTC) gives a number that is
  // directly comparable across two ticks, correctly handling a date
  // rollover, so its difference from the fixed epoch interval that produced
  // the two ticks is exactly zero except across a genuine DST transition.
  function localWallClockMinutes(ts) {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: state.timezone || 'UTC', hourCycle: 'h23',
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
    }).formatToParts(new Date(ts * 1000));
    const get = (type) => Number(parts.find((part) => part.type === type).value);
    return Date.UTC(get('year'), get('month') - 1, get('day'), get('hour') % 24, get('minute')) / 60000;
  }

  // A DST transition always moves the local wall clock by exactly one hour
  // relative to the fixed epoch interval that produced it, regardless of the
  // surrounding tick spacing -- so a signed 60-minute mismatch between the
  // local-label delta and the epoch delta is sufficient to detect and
  // classify it, with no hand-rolled transition table and no hard-coded
  // date. When state.timezone is UTC (including the fail-closed case), local
  // minutes always advance exactly as fast as epoch minutes, so this can
  // never fire. Returns one entry per tick, null unless that tick is part of
  // a detected transition.
  function dstAnnotations(tickTimestamps) {
    const ticks = Array.isArray(tickTimestamps) ? tickTimestamps : [];
    const annotations = ticks.map(() => null);
    for (let index = 1; index < ticks.length; index += 1) {
      const epochDiffMinutes = (ticks[index] - ticks[index - 1]) / 60;
      const localDiffMinutes = localWallClockMinutes(ticks[index]) - localWallClockMinutes(ticks[index - 1]);
      const delta = localDiffMinutes - epochDiffMinutes;
      if (delta === -60) {
        // Fall-back: the local clock repeated an hour, so both adjacent
        // ticks read the same wall-clock label despite differing epoch
        // values. Both are annotated.
        const label = formatLocalTimestamp(ticks[index - 1], {hour: '2-digit', minute: '2-digit'});
        const title = `The local time ${label} occurs twice here (DST fall-back) -- both ticks read the same clock time.`;
        annotations[index - 1] = {title};
        annotations[index] = {title};
      } else if (delta === 60) {
        // Spring-forward: an hour of local wall-clock time never occurred.
        // Only the tick after the skip is annotated.
        const label = formatLocalTimestamp(ticks[index - 1], {hour: '2-digit', minute: '2-digit'});
        annotations[index] = {title: `The hour after ${label} is absent here (DST spring-forward).`};
      }
    }
    return annotations;
  }

  function renderSharedTimeAxis(startTs, endTs) {
    const svg = $('history-time-axis');
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    if (!Number.isFinite(startTs) || !Number.isFinite(endTs) || endTs <= startTs) return;
    const tickCount = 6;
    const ticks = [];
    for (let index = 0; index <= tickCount; index += 1) {
      ticks.push(startTs + ((endTs - startTs) * index) / tickCount);
    }
    const annotations = dstAnnotations(ticks);
    ticks.forEach((ts, index) => {
      const text = document.createElementNS(SVG_NS, 'text');
      text.setAttribute('x', String(histTimeToX(ts, startTs, endTs)));
      text.setAttribute('y', '16');
      const annotation = annotations[index];
      if (annotation) {
        // Never re-spaced to hide the discontinuity: the tick keeps its
        // computed x position, but its label is replaced by the explicit
        // warning instead of a compressed hour or a duplicate-looking
        // timestamp -- text and glyph, never colour alone.
        text.setAttribute('class', 'hist-dst-tick');
        text.textContent = '⚠ DST transition';
        const title = document.createElementNS(SVG_NS, 'title');
        title.textContent = annotation.title;
        text.append(title);
      } else {
        text.textContent = formatLocalTimestamp(ts, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'});
      }
      svg.append(text);
    });
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
    const comparison = $(`comparison-${metric}`);
    if (comparison) while (comparison.firstChild) comparison.removeChild(comparison.firstChild);
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
      renderComparisonRow(metric, points, requested.end_ts - requested.start_ts);
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
    // D-03: the fields state the governing range from every source, including
    // the moment the section is entered or a request begins -- not only once
    // a fetch completes.
    syncHistoryPresetButtons();
    renderRangeFields();
    renderBackControl();
    // D-16: the indicator/picker state from every source (client-side, no
    // fetch involved) every time History is entered or the range changes.
    renderInvestigatingIndicator();
    renderHistoryServicePicker();
    const applyButton = $('apply-custom-range');
    if (applyButton) applyButton.disabled = true;
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
      state.historyBounds = requested;
      updateRangeResolutionNote(firstSucceeded.result.effective_resolution_seconds);
      renderSharedTimeAxis(requested.start_ts, requested.end_ts);
    } else {
      // Every metric failed (or returned nothing to anchor the axis on): the
      // shared axis still renders from the requested bounds so it never
      // disappears alongside a per-metric fetch failure.
      state.historyBounds = bounds;
      updateRangeResolutionNote(null);
      renderSharedTimeAxis(bounds.start_ts, bounds.end_ts);
    }
    if (applyButton) applyButton.disabled = false;
    // D-11: the selected service's own history is an independent fetch,
    // never awaited here -- a slow or failed service-history request must
    // never delay or blank the host stack above it (Research Pattern 1).
    renderServiceHistorySection();
  }

  // D-04: validated before assignment, routed through setInvestigationRange
  // (origin 'manual' -- a preset click is a fresh investigation, D-15) --
  // never a request built from anything but the two integers boundsForPreset
  // computes.
  function selectRangePreset(preset) {
    if (!Object.prototype.hasOwnProperty.call(HISTORY_PRESETS, preset)) return;
    const bounds = boundsForPreset(preset);
    setInvestigationRange({start_ts: bounds.start_ts, end_ts: bounds.end_ts, origin: 'manual', presetId: preset});
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
      // D-16 (Phase 4 04-06): a selection control that publishes this
      // service's port for the History section's own views to read --
      // never a value this row's own rendering, sort, filter, or expand
      // behaviour consumes. Toggling it off (already-selected) clears the
      // selection rather than leaving it unreachable from this row.
      // `position: absolute` (advanced.css) takes it entirely out of the
      // identity grid's row/column sizing -- name/portLabel/details keep
      // their exact original grid placement. Two in-flow placements (a
      // stacked third row, and an inline flex sibling of name) were each
      // found to distort .service-details-toggle's own spanned-row height
      // at the narrow (<=959px) breakpoint, intercepting the next row's
      // clicks (Rule 1 fix) -- only removing it from grid flow proved
      // stable. A single-glyph label keeps its own footprint tiny.
      const investigating = state.preferences.selectedService === port;
      const investigate = document.createElement('button');
      investigate.type = 'button'; investigate.id = `service-investigate-${port}`;
      investigate.className = 'service-investigate-toggle';
      investigate.textContent = investigating ? '★' : '☆';
      investigate.setAttribute('aria-pressed', String(investigating));
      const investigateLabel = `${investigating ? 'Stop investigating' : 'Investigate'} ${displayValue(service.name)}`;
      investigate.setAttribute('aria-label', investigateLabel);
      investigate.title = investigateLabel;
      investigate.addEventListener('click', () => setSelectedService(investigating ? null : port));
      identity.append(name, portLabel, details, investigate);
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
    // D-16: the picker and indicator both read the same current snapshot's
    // service list -- refreshed on every successful poll so a renamed or
    // newly-discovered service is reflected without a page reload.
    renderHistoryServicePicker();
    renderInvestigatingIndicator();
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
    // D-16/UI-SPEC "Shared range control": one range-control header governs
    // History and Incidents only -- the querySelector above already leaves
    // this explicit `<div>` (not a `<section>`) untouched, so this is the
    // one added hook selecting it in or out. The five Phase 3 sections
    // remain untouched by this and stay strictly current-state.
    const investigationHeader = $('investigation-header');
    if (investigationHeader) investigationHeader.hidden = section !== 'history' && section !== 'incidents';
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
  // 04-05: the canonical custom-range entry point (D-03) and its render on
  // boot -- fields must state the governing range before the operator ever
  // visits History, and a stored custom range must render correctly on reload.
  renderRangeFields();
  renderBackControl();
  const applyCustomRangeButton = $('apply-custom-range');
  if (applyCustomRangeButton) applyCustomRangeButton.addEventListener('click', applyCustomRange);
  // Test-only hooks, same pattern as window.__historyTrendTestHooks: these
  // functions are pure/stateful but otherwise private to this IIFE, so
  // Playwright's page.evaluate needs a reachable handle to drive the
  // navigation-stack and custom-range machinery directly.
  window.__historyRangeTestHooks = {
    parseLocalRangeInput, formatLocalRangeInput, validateCustomRange,
    setInvestigationRange, pushRange, popRange, clearRangeStack,
    resolveRangeBounds, rangeStack: () => state.rangeStack, RANGE_STACK_LIMIT,
  };
  // 04-03: each chart's unit label is set once from HOST_METRIC_UNITS, the
  // single source of truth the renderers below also read.
  HOST_METRIC_ORDER.forEach((metric) => {
    const unit = $(`unit-${metric}`);
    if (unit) unit.textContent = HOST_METRIC_UNITS[metric] || '';
  });
  // 04-05 Task 3: dragging across any host chart narrows the range (D-03).
  HOST_METRIC_ORDER.forEach((metric) => {
    const svg = $(`chart-${metric}`);
    if (svg) svg.addEventListener('pointerdown', beginDragSelect);
  });
  const historyNavButton = document.querySelector('[data-section="history"]');
  if (historyNavButton) historyNavButton.addEventListener('click', renderHistorySection);
  // D-16 (Phase 4 04-06): the History picker and the Clear action both call
  // the same setSelectedService/clearSelectedService entry points the
  // Services table row control uses -- one carried selection, published and
  // consumed from either side.
  renderInvestigatingIndicator();
  renderHistoryServicePicker();
  const historyServicePicker = $('history-service-picker');
  if (historyServicePicker) {
    historyServicePicker.addEventListener('change', () => {
      const value = historyServicePicker.value;
      setSelectedService(value === '' ? null : Number(value));
    });
  }
  const clearSelectedServiceButton = $('clear-selected-service');
  if (clearSelectedServiceButton) clearSelectedServiceButton.addEventListener('click', clearSelectedService);
  // Phase 4 04-07: entering Incidents (directly, not via a range change)
  // must fetch too -- applyRangeAndRender only covers the range-change path.
  const incidentsNavButton = document.querySelector('[data-section="incidents"]');
  if (incidentsNavButton) incidentsNavButton.addEventListener('click', renderIncidentsSection);
  syncIncidentFilterControls();
  const incidentCriticalityFilter = $('incident-criticality-filter');
  if (incidentCriticalityFilter) {
    incidentCriticalityFilter.addEventListener('change', () => {
      state.preferences.historyFilters = {
        ...state.preferences.historyFilters,
        criticality: incidentCriticalityFilter.value === '' ? null : incidentCriticalityFilter.value,
      };
      savePreferences();
      renderIncidentsSection();
    });
  }
  const incidentEventTypeFilter = $('incident-event-type-filter');
  if (incidentEventTypeFilter) {
    incidentEventTypeFilter.addEventListener('change', () => {
      state.preferences.historyFilters = {
        ...state.preferences.historyFilters,
        eventType: incidentEventTypeFilter.value === '' ? null : incidentEventTypeFilter.value,
      };
      savePreferences();
      renderIncidentsSection();
    });
  }
  // D-16: selecting a service here is the same carried selection every
  // other affordance publishes to -- never an independent second fact.
  const incidentServiceFilter = $('incident-service-filter');
  if (incidentServiceFilter) {
    incidentServiceFilter.addEventListener('change', () => {
      setSelectedService(incidentServiceFilter.value === '' ? null : Number(incidentServiceFilter.value));
    });
  }
  const clearIncidentFiltersButton = $('clear-incident-filters');
  if (clearIncidentFiltersButton) {
    clearIncidentFiltersButton.addEventListener('click', () => {
      // UI-SPEC "Filters": service, criticality, and event type are all
      // four AND-combined filters this control resets -- only the shared
      // range (the investigation context itself, per D-16) is untouched.
      // Clearing the service filter routes through setSelectedService so
      // the carried selection and the filter can never disagree afterward.
      state.preferences.historyFilters = {...state.preferences.historyFilters, criticality: null, eventType: null};
      savePreferences();
      setSelectedService(null);
      syncIncidentFilterControls();
      $('advanced-status').textContent = 'All incident filters cleared';
    });
  }
  // Test-only hook, same pattern as window.__historyRangeTestHooks.
  window.__incidentTestHooks = {incidentFocusWindow, focusIncident, INCIDENT_PAD_FRACTION, INCIDENT_PAD_FLOOR_SECONDS};
  // refreshCurrentDiagnosis() must be invoked before fetchRuntimeConfig(): both
  // dispatch their fetch() call synchronously (before their first await), so
  // this order keeps /api/advanced/current the first network call the page
  // ever makes -- the exact assumption test_advanced_ui.py's reverse-order
  // regression harness pins its "first call held, second call wins" scenario on.
  scheduleRefresh();
  refreshCurrentDiagnosis();
  fetchRuntimeConfig();
})();
