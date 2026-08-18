(() => {
  const PREFS_KEY = 'beacon-advanced-preferences-v1';
  const DEFAULT_PREFERENCES = {refreshSeconds: 15, paused: false, density: null, range: '24h', filters: {}};
  const REFRESH_CHOICES = new Set([5, 15, 30, 60]);
  const state = {
    snapshot: null, lastSuccessLabel: null, activeSection: 'overview', timer: null,
    preferences: {...DEFAULT_PREFERENCES}, filters: {}, serviceSort: null,
    expandedPorts: new Set(), connectionUnavailable: false,
  };
  const $ = (id) => document.getElementById(id);

  function validFilters(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
    const allowed = new Set(['query', 'status', 'criticality', 'freshness', 'tags']);
    return Object.fromEntries(Object.entries(value).filter(([key, item]) => allowed.has(key) && typeof item === 'string'));
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
      exceptions.forEach((item) => addCard(exceptionRegion, item.label || item.kind || 'Unknown exception', item.evidence || item.detail || 'Unknown evidence', item.section));
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
    return 'unknown';
  }

  function serviceFreshness(service) {
    const value = String((service.freshness || {}).state || 'unknown').toLowerCase();
    return ['fresh', 'aging', 'stale', 'unknown'].includes(value) ? value : 'unknown';
  }

  function serviceDuration(service) {
    const seconds = Number(service.state_duration_seconds);
    return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds)) return 'Unknown duration';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
    return `${Math.floor(seconds / 3600)} hours`;
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
          const latency = Number(service.latency_ms);
          return Number.isFinite(latency) ? latency : Number.POSITIVE_INFINITY;
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
      status.textContent = `● ${serviceAvailability(service)}`;
      const latency = document.createElement('td');
      const latencyValue = Number(service.latency_ms);
      latency.textContent = Number.isFinite(latencyValue) ? `${latencyValue} ms` : displayValue(service.failure_class || service.last_error, '');
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
      addEvidence(evidence, 'Collection-gap evidence', JSON.stringify(service.collection_gaps || service.collection_gap || 'No gap evidence'));
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
    state.activeSection = section;
    document.querySelectorAll('#section-navigation button').forEach((button) => {
      const selected = button.dataset.section === section;
      button.setAttribute('aria-selected', String(selected));
    });
    document.querySelectorAll('.advanced-detail > section').forEach((node) => { node.hidden = node.id !== `${section}-section`; });
    const heading = $(`${section}-heading`);
    heading.focus();
    $('advanced-status').textContent = `${heading.textContent} selected`;
  }

  function renderRefreshError() {
    const error = $('advanced-refresh-error');
    const prior = state.lastSuccessLabel || 'no successful update yet';
    error.textContent = `Beacon could not refresh current diagnosis. Showing data from ${prior}. Check the connection warning, then try again.`;
    error.hidden = false;
  }

  async function refreshCurrentDiagnosis() {
    try {
      const snapshot = await apiFetch();
      state.connectionUnavailable = false;
      state.snapshot = snapshot;
      state.serviceSort = null;
      state.lastSuccessLabel = displayTimestamp(snapshot.generated_ts);
      updateRefreshEvidence();
      $('advanced-refresh-error').hidden = true;
      renderSnapshot(snapshot);
    } catch (_) {
      state.connectionUnavailable = true;
      renderSafety(state.snapshot || {});
      renderRefreshError();
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
  scheduleRefresh();
  refreshCurrentDiagnosis();
})();
