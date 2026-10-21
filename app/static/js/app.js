/**
 * Cybersecurity GRC & Compliance Management Platform
 * Client-side utilities and asynchronous health monitoring
 */

document.addEventListener('DOMContentLoaded', () => {
  initHealthMonitor();
});

async function initHealthMonitor() {
  const latencyEl = document.getElementById('api-latency');
  const dbStatusEl = document.getElementById('db-status');
  const apiStatusEl = document.getElementById('api-status');

  if (!latencyEl && !dbStatusEl && !apiStatusEl) return;

  const startTime = performance.now();
  try {
    const res = await fetch('/api/health');
    const elapsed = Math.round(performance.now() - startTime);

    if (res.ok) {
      const data = await res.json();
      if (latencyEl) latencyEl.textContent = `${elapsed}ms`;
      if (dbStatusEl) dbStatusEl.textContent = data.database || 'Active';
      if (apiStatusEl) {
        apiStatusEl.textContent = 'ONLINE';
        apiStatusEl.style.color = '#34d399';
      }
    } else {
      if (apiStatusEl) {
        apiStatusEl.textContent = 'DEGRADED';
        apiStatusEl.style.color = '#f59e0b';
      }
    }
  } catch (err) {
    if (apiStatusEl) {
      apiStatusEl.textContent = 'OFFLINE';
      apiStatusEl.style.color = '#f43f5e';
    }
  }
}
