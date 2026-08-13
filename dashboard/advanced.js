(() => {
  const state = {snapshot: null, lastSuccessLabel: null};
  const $ = (id) => document.getElementById(id);

  async function apiFetch() {
    const response = await fetch('/api/advanced/current', {cache: 'no-store'});
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        message = (await response.json()).error || message;
      } catch (_) {
        // The response may not be JSON; retain the status as bounded evidence.
      }
      throw new Error(message);
    }
    return response.json();
  }

  function displayValue(value, suffix = '') {
    return value === null || value === undefined ? 'Unknown' : `${value}${suffix}`;
  }

  function displayTimestamp(timestamp) {
    if (timestamp === null || timestamp === undefined) {
      return 'Unknown';
    }
    return new Date(timestamp * 1000).toLocaleString();
  }

  function addEvidence(parent, label, value) {
    const row = document.createElement('div');
    const name = document.createElement('strong');
    const evidence = document.createElement('span');
    name.textContent = `${label}: `;
    evidence.textContent = value;
    row.append(name, evidence);
    parent.append(row);
  }

  function renderHostSummary(host) {
    const section = document.createElement('section');
    const heading = document.createElement('h2');
    const summary = document.createElement('div');
    const metrics = host.metrics || {};
    const freshness = host.freshness || {state: 'unknown', age_seconds: null};
    section.setAttribute('data-testid', 'host-summary');
    heading.textContent = 'Current host';
    summary.className = 'advanced-host-summary';
    addEvidence(summary, 'Host', displayValue(host.identity && host.identity.hostname));
    addEvidence(summary, 'CPU', displayValue(metrics.cpu && metrics.cpu.value, '%'));
    addEvidence(summary, 'Memory', displayValue(metrics.memory && metrics.memory.value, '%'));
    addEvidence(summary, 'Disk', displayValue(metrics.disk && metrics.disk.value, '%'));
    addEvidence(summary, 'Temperature', displayValue(metrics.temperature && metrics.temperature.value, ' °C'));
    addEvidence(summary, 'Sample timestamp', displayTimestamp(host.sample_ts));
    addEvidence(summary, 'Expected cadence', displayValue(host.expected_cadence_seconds, ' seconds'));
    addEvidence(summary, 'Freshness', `${freshness.state} (${displayValue(freshness.age_seconds, ' seconds')})`);
    section.append(heading, summary);
    $('advanced-content').replaceChildren(section);
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
      state.snapshot = snapshot;
      state.lastSuccessLabel = displayTimestamp(snapshot.generated_ts);
      $('advanced-last-success').textContent = state.lastSuccessLabel;
      $('advanced-last-success').title = state.lastSuccessLabel;
      $('advanced-refresh-error').hidden = true;
      renderHostSummary(snapshot.host);
    } catch (_) {
      renderRefreshError();
    }
  }

  $('advanced-refresh').addEventListener('click', refreshCurrentDiagnosis);
  refreshCurrentDiagnosis();
})();
