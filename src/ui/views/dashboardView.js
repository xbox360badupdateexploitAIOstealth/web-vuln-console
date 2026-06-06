// src/ui/views/dashboardView.js
// TODO-09: Wired to GET /api/stats — real stats, severity breakdown,
//          recent jobs, and recent critical findings.

import { moduleDefs } from '../../core/moduleRegistry.js';
import { scanPolicies } from '../../core/policyRegistry.js';

const API = window.API_BASE || '';

// ── Severity colour map ───────────────────────────────────────────────────────
const SEV_COLOR = {
  critical : '#ff2a2a',
  high     : '#ff6b2b',
  medium   : '#f5a623',
  low      : '#4fc3f7',
  info     : '#78909c',
};

// ─────────────────────────────────────────────────────────────────────────────
// renderDashboard(container)
// ─────────────────────────────────────────────────────────────────────────────
export async function renderDashboard(container) {
  // Optimistic skeleton while data loads
  container.innerHTML = _skeleton();

  let stats = null;
  let jobs  = [];
  let recentFindings = [];

  try {
    const [sRes, jRes] = await Promise.all([
      fetch(`${API}/api/stats`),
      fetch(`${API}/api/scans?limit=5`),
    ]);

    if (sRes.ok) stats = await sRes.json();
    if (jRes.ok) {
      const body = await jRes.json();
      jobs = Array.isArray(body) ? body.slice(0, 5) : (body.jobs || []).slice(0, 5);
    }

    // Pull recent critical+high findings if we have a stats object
    if (stats) {
      const fRes = await fetch(`${API}/api/projects?limit=1`);
      if (fRes.ok) {
        const projects = await fRes.json();
        const pid = Array.isArray(projects) ? projects[0]?.id : null;
        if (pid) {
          const rfRes = await fetch(`${API}/api/projects/${pid}/findings?severity=critical&limit=5`);
          if (rfRes.ok) recentFindings = await rfRes.json();
        }
      }
    }
  } catch (e) {
    console.warn('[dashboard] fetch error', e);
  }

  container.innerHTML = _render(stats, jobs, recentFindings);
  _attachRefresh(container);
}

// ─────────────────────────────────────────────────────────────────────────────
// Skeleton (shown while loading)
// ─────────────────────────────────────────────────────────────────────────────
function _skeleton() {
  return `
    <div class="dash-header">
      <h1 class="dash-title">Dashboard</h1>
      <span class="dash-loading">⟳ Loading…</span>
    </div>
    <div class="dash-cards">
      ${['Projects','Targets','Jobs','Findings'].map(l =>
        `<div class="dash-card dash-card--loading"><span class="dash-card-label">${l}</span><span class="dash-card-value">—</span></div>`
      ).join('')}
    </div>
  `;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main render
// ─────────────────────────────────────────────────────────────────────────────
function _render(stats, jobs, recentFindings) {
  const s = stats || {};

  const cards = [
    { label: 'Projects',  value: s.projects  ?? '—', icon: '🗂' },
    { label: 'Targets',   value: s.targets   ?? '—', icon: '🎯' },
    { label: 'Jobs Run',  value: s.jobs      ?? '—', icon: '⚙️'  },
    { label: 'Findings',  value: s.findings  ?? '—', icon: '🔍' },
  ];

  const sevBreakdown = s.severity || {};

  return `
    <div class="dash-header">
      <h1 class="dash-title">Dashboard</h1>
      <button class="btn btn--sm" id="dash-refresh-btn" title="Refresh stats">⟳ Refresh</button>
    </div>

    <!-- ── Stat cards ────────────────────────────────────────────────────── -->
    <div class="dash-cards">
      ${cards.map(c => `
        <div class="dash-card">
          <span class="dash-card-icon">${c.icon}</span>
          <span class="dash-card-value">${c.value}</span>
          <span class="dash-card-label">${c.label}</span>
        </div>`).join('')}
    </div>

    <!-- ── Severity breakdown ────────────────────────────────────────────── -->
    ${Object.keys(sevBreakdown).length ? `
    <section class="dash-section">
      <h2 class="dash-section-title">Findings by Severity</h2>
      <div class="dash-sev-bars">
        ${Object.entries(SEV_COLOR).map(([sev, col]) => {
          const count = sevBreakdown[sev] || 0;
          const total = Object.values(sevBreakdown).reduce((a, b) => a + b, 0) || 1;
          const pct   = Math.round((count / total) * 100);
          return `
            <div class="dash-sev-row">
              <span class="dash-sev-label" style="color:${col}">${sev}</span>
              <div class="dash-sev-track">
                <div class="dash-sev-fill" style="width:${pct}%;background:${col}"></div>
              </div>
              <span class="dash-sev-count">${count}</span>
            </div>`;
        }).join('')}
      </div>
    </section>` : ''}

    <!-- ── Recent jobs ───────────────────────────────────────────────────── -->
    <section class="dash-section">
      <h2 class="dash-section-title">Recent Jobs</h2>
      ${jobs.length ? `
        <table class="dash-table">
          <thead><tr><th>ID</th><th>Policy</th><th>Status</th><th>Started</th></tr></thead>
          <tbody>
            ${jobs.map(j => `
              <tr>
                <td class="mono" title="${j.id}">${String(j.id).slice(0, 8)}…</td>
                <td>${j.policy_id || j.policyId || '—'}</td>
                <td><span class="badge badge--${_statusClass(j.status)}">${j.status}</span></td>
                <td>${j.created_at ? new Date(j.created_at).toLocaleString() : '—'}</td>
              </tr>`).join('')}
          </tbody>
        </table>` : `<p class="dash-empty">No jobs yet. Run a scan to get started.</p>`}
    </section>

    <!-- ── Recent critical findings ──────────────────────────────────────── -->
    ${recentFindings.length ? `
    <section class="dash-section">
      <h2 class="dash-section-title">Recent Critical Findings</h2>
      <ul class="dash-findings-list">
        ${recentFindings.map(f => `
          <li class="dash-finding-item">
            <span class="badge badge--critical">CRIT</span>
            <span class="dash-finding-title">${_esc(f.title)}</span>
            <span class="dash-finding-target mono">${_esc(f.target || '')}</span>
          </li>`).join('')}
      </ul>
    </section>` : ''}

    <!-- ── Engine info (always shown) ───────────────────────────────────── -->
    <section class="dash-section dash-section--muted">
      <h2 class="dash-section-title">Engine</h2>
      <p>${moduleDefs.length} modules loaded &nbsp;·&nbsp; ${scanPolicies.length} scan policies</p>
      <details style="margin-top:8px">
        <summary style="cursor:pointer;opacity:.7">Module IDs</summary>
        <pre class="dash-pre">${moduleDefs.map(m => ` - ${m.id}`).join('\n')}</pre>
      </details>
    </section>
  `;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
function _attachRefresh(container) {
  const btn = container.querySelector('#dash-refresh-btn');
  if (btn) btn.addEventListener('click', () => renderDashboard(container));
}

function _statusClass(status) {
  const map = { completed: 'ok', running: 'running', queued: 'queued',
                failed: 'error', interrupted: 'warn', cancelled: 'warn' };
  return map[status] || 'default';
}

function _esc(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
