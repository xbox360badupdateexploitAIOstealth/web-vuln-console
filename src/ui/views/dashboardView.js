// src/ui/views/dashboardView.js
// TODO-09 v2: Fully wired dashboard
//   - GET /api/health   → health status card (online / degraded / offline)
//   - GET /api/stats    → 4 stat cards (projects / targets / jobs / findings)
//   - GET /api/scans    → 5 most-recent jobs table w/ status badges
//   - GET /api/projects → all projects → GET critical findings per project (parallel)
//   - Severity breakdown bar chart (all 5 levels)
//   - Animated count-up on stat card numbers
//   - Auto-refresh toggle (30 s interval)
//   - Engine summary: module count, policy count, passive vs active split
//   - Full offline graceful degradation

'use strict';

const SEV_COLOR = {
  critical: '#ef4444',
  high    : '#f97316',
  medium  : '#eab308',
  low     : '#3b82f6',
  info    : '#94a3b8',
};

const STATUS_COLOR = {
  completed  : '#22c55e',
  running    : '#38bdf8',
  queued     : '#a78bfa',
  failed     : '#ef4444',
  interrupted: '#f97316',
  cancelled  : '#64748b',
};

// Module counts — inline so view works without bundler import from core
const _PASSIVE_IDS = [
  'exposure.env.direct','exposure.env.variants','exposure.backup.db_dumps',
  'exposure.backup.archives','misconfig.dirlisting.generic','vcs.git.exposed',
  'debug.stacktraces','tls.headers.basic','cookie.session.flags',
  'exposure.js.secrets','exposure.sourcemap','exposure.cve.cpanel_whm',
  'exposure.cve.laravel_env_hunt','cve.fingerprints','misconfig.phpinfo.exposed',
  'vcs.svn_hg.exposed','exposure.cve.vite_bypass','exposure.cve.mautic_env',
  'exposure.cve.moodle_listing','exposure.cloud.open_bucket','exposure.cms.wp_debug',
];
const _ACTIVE_IDS = [
  'injection.sqli.basic','injection.xss.reflected_basic','injection.path_traversal.basic',
  'injection.cmdi.basic','injection.ssti.basic','injection.fileupload.detect',
];
const _MODULE_TOTAL  = _PASSIVE_IDS.length + _ACTIVE_IDS.length;
const _POLICY_TOTAL  = 3;

let _autoRefreshTimer = null;
let _autoRefreshOn    = false;
let _container        = null;

// ── Entry point ───────────────────────────────────────────────────────────────
export async function renderDashboard(container) {
  _container = container;
  _showSkeleton(container);

  const [health, stats, jobs, critFindings] = await Promise.all([
    _fetchHealth(),
    _fetchStats(),
    _fetchRecentJobs(),
    _fetchCriticalFindings(),
  ]);

  container.innerHTML = _buildHTML(health, stats, jobs, critFindings);
  _wireButtons(container);
  _animateCounters(container);
}

// ── Data fetchers ────────────────────────────────────────────────────────────
async function _fetchHealth() {
  try {
    const res = await fetch(`${_api()}/api/health`, { signal: _timeout(4000) });
    if (res.ok) return { ok: true, ...(await res.json().catch(() => ({}))) };
    return { ok: false, status: res.status };
  } catch {
    return { ok: false, offline: true };
  }
}

async function _fetchStats() {
  try {
    const res = await fetch(`${_api()}/api/stats`, { signal: _timeout(6000) });
    if (res.ok) return await res.json().catch(() => null);
  } catch { /* offline */ }
  return null;
}

async function _fetchRecentJobs() {
  try {
    const res = await fetch(`${_api()}/api/scans?limit=6`, { signal: _timeout(6000) });
    if (!res.ok) return [];
    const body = await res.json().catch(() => []);
    const arr  = Array.isArray(body) ? body : (body.jobs || body.scans || []);
    return arr.slice(0, 6);
  } catch {
    return [];
  }
}

async function _fetchCriticalFindings() {
  try {
    // Get all projects first
    const pRes = await fetch(`${_api()}/api/projects`, { signal: _timeout(6000) });
    if (!pRes.ok) return [];
    const pBody    = await pRes.json().catch(() => []);
    const projects = (Array.isArray(pBody) ? pBody : (pBody.projects || [])).slice(0, 8);
    if (!projects.length) return [];

    // Fan out: fetch critical findings per project in parallel
    const perProject = await Promise.all(
      projects.map(p =>
        fetch(`${_api()}/api/projects/${encodeURIComponent(p.id)}/findings?severity=critical&limit=4`, {
          signal: _timeout(5000),
        })
        .then(r => r.ok ? r.json().catch(() => []) : [])
        .catch(() => [])
      )
    );
    // Flatten, deduplicate by id, return newest 8
    const all  = perProject.flat();
    const seen = new Set();
    return all.filter(f => { if (seen.has(f.id)) return false; seen.add(f.id); return true; })
              .slice(0, 8);
  } catch {
    return [];
  }
}

// ── HTML builder ──────────────────────────────────────────────────────────────
function _buildHTML(health, stats, jobs, critFindings) {
  const s  = stats || {};
  const sev = s.severity || {};
  const totalSev = Object.values(sev).reduce((a, b) => a + b, 0) || 1;

  return `
    <!-- Header row -->
    <div style="display:flex;align-items:center;justify-content:space-between;
      flex-wrap:wrap;gap:8px;margin-bottom:16px;">
      <h1 style="margin:0;">Dashboard</h1>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        ${_healthBadge(health)}
        <button id="dash-auto-btn" style="${_btn('#1e293b','#94a3b8')}font-size:10px;">
          ${_autoRefreshOn ? '⏸ Auto-refresh ON' : '⏵ Auto-refresh'}
        </button>
        <button id="dash-refresh-btn" style="${_btn('#1e293b','#94a3b8')}font-size:10px;">↻ Refresh</button>
      </div>
    </div>

    <!-- Stat cards -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
      gap:10px;margin-bottom:16px;">
      ${_statCard('🗂', 'Projects',  s.projects ?? 0,  '#38bdf8')}
      ${_statCard('🎯', 'Targets',   s.targets  ?? 0,  '#a78bfa')}
      ${_statCard('⚙️',  'Jobs Run',  s.jobs     ?? 0,  '#22c55e')}
      ${_statCard('🔍', 'Findings',  s.findings  ?? 0, '#ef4444')}
    </div>

    <!-- Two-column grid on wide screens -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));
      gap:12px;margin-bottom:12px;">

      <!-- Severity breakdown -->
      <div style="${_card()}">
        <div style="${_sectionTitle()}">Findings by Severity</div>
        ${Object.entries(SEV_COLOR).map(([sev, col]) => {
          const count = s.severity?.[sev] ?? 0;
          const pct   = Math.round((count / totalSev) * 100);
          return `
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
              <span style="width:62px;font-size:10px;font-weight:700;color:${col};
                text-transform:uppercase;text-align:right;">${sev}</span>
              <div style="flex:1;background:#0f172a;border-radius:4px;height:12px;overflow:hidden;">
                <div style="height:100%;background:${col};border-radius:4px;
                  width:${pct}%;transition:width .6s ease;"></div>
              </div>
              <span style="width:30px;font-size:11px;color:#94a3b8;text-align:right;">${count}</span>
            </div>`;
        }).join('')}
        ${!Object.keys(sev).length ? `<p style="color:#475569;font-size:11px;margin:0;">No findings yet.</p>` : ''}
      </div>

      <!-- Engine summary -->
      <div style="${_card()}">
        <div style="${_sectionTitle()}">Engine</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
          ${_pill(_MODULE_TOTAL + ' modules', '#38bdf8')}
          ${_pill(_POLICY_TOTAL + ' policies', '#a78bfa')}
          ${_pill(_PASSIVE_IDS.length + ' passive', '#22c55e')}
          ${_pill(_ACTIVE_IDS.length + ' active', '#ef4444')}
        </div>
        <div style="font-size:11px;color:#475569;line-height:1.7;">
          <div>Version &nbsp;<span style="color:#94a3b8;">v1.8.0</span></div>
          <div>Policies &nbsp;<span style="color:#94a3b8;">Normal &middot; Aggressive &middot; Extreme</span></div>
          <div>Last scan &nbsp;<span style="color:#94a3b8;">${
            jobs.length
              ? _fmtTime(jobs[0]?.created_at || jobs[0]?.started_at)
              : 'never'
          }</span></div>
        </div>
        <details style="margin-top:10px;">
          <summary style="cursor:pointer;font-size:10px;color:#475569;">Module IDs</summary>
          <pre style="font-size:9px;color:#64748b;line-height:1.6;margin-top:6px;overflow-x:auto;">${
            [..._PASSIVE_IDS, ..._ACTIVE_IDS].map(id => ` • ${id}`).join('\n')
          }</pre>
        </details>
      </div>
    </div>

    <!-- Recent jobs -->
    <div style="${_card()}margin-bottom:12px;">
      <div style="${_sectionTitle()}">Recent Jobs</div>
      ${ jobs.length
        ? `<div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:11px;">
              <thead>
                <tr style="border-bottom:2px solid #1e293b;">
                  ${['Job ID','Policy','Status','Targets','Started'].map(h =>
                    `<th style="text-align:left;padding:5px 8px;font-size:10px;
                      text-transform:uppercase;letter-spacing:.07em;color:#64748b;">${h}</th>`
                  ).join('')}
                </tr>
              </thead>
              <tbody>
                ${jobs.map(j => {
                  const sc  = STATUS_COLOR[j.status] || '#64748b';
                  const tgt = j.targets_json
                    ? (() => { try { return JSON.parse(j.targets_json).length; } catch { return '?'; } })()
                    : (j.targets?.length ?? '—');
                  return `<tr style="border-bottom:1px solid #111827;">
                    <td style="padding:6px 8px;font-family:monospace;color:#e2e8f0;">
                      ${_esc(String(j.id).slice(0,10))}…</td>
                    <td style="padding:6px 8px;color:#94a3b8;">${_esc(j.policy_id || j.policyId || '—')}</td>
                    <td style="padding:6px 8px;">
                      <span style="background:${sc}22;color:${sc};border:1px solid ${sc}55;
                        border-radius:4px;padding:2px 7px;font-size:10px;font-weight:700;
                        text-transform:uppercase;">${_esc(j.status || '?')}</span></td>
                    <td style="padding:6px 8px;color:#64748b;">${tgt}</td>
                    <td style="padding:6px 8px;color:#64748b;">${_fmtTime(j.created_at)}</td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>`
        : `<p style="color:#475569;font-size:12px;margin:0;">No jobs yet. Run a scan to get started.</p>`
      }
    </div>

    <!-- Recent critical findings -->
    ${ critFindings.length ? `
    <div style="${_card()}">
      <div style="${_sectionTitle()}">Recent Critical Findings</div>
      ${critFindings.map(f => `
        <div style="display:flex;align-items:flex-start;gap:8px;padding:7px 0;
          border-bottom:1px solid #111827;">
          <span style="background:#ef444422;color:#ef4444;border:1px solid #ef444455;
            border-radius:4px;padding:2px 7px;font-size:9px;font-weight:700;
            white-space:nowrap;margin-top:2px;">CRIT</span>
          <div style="flex:1;min-width:0;">
            <div style="font-size:12px;color:#e2e8f0;font-weight:600;">${_esc(f.title || f.name || '(untitled)')}</div>
            <div style="font-size:10px;color:#64748b;font-family:monospace;margin-top:2px;
              overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${_esc(f.target || f.url || '')}</div>
          </div>
          <span style="font-size:9px;color:#475569;white-space:nowrap;margin-top:4px;">${_esc(f.module_id || f.moduleId || '')}</span>
        </div>`).join('')}
    </div>` : '' }
  `;
}

// ── Component helpers ──────────────────────────────────────────────────────────
function _statCard(icon, label, value, color) {
  return `
    <div style="${_card()}text-align:center;">
      <div style="font-size:22px;margin-bottom:4px;">${icon}</div>
      <div class="dash-counter" data-target="${value}"
        style="font-size:28px;font-weight:800;color:${color};font-family:monospace;">
        ${value}
      </div>
      <div style="font-size:11px;color:#64748b;text-transform:uppercase;
        letter-spacing:.07em;margin-top:2px;">${label}</div>
    </div>`;
}

function _healthBadge(h) {
  if (!h) return '';
  if (h.offline)         return `<span style="${_badgeStyle('#64748b')}">⚫ Offline</span>`;
  if (!h.ok)             return `<span style="${_badgeStyle('#ef4444')}">🔴 Degraded (${h.status || '?'})</span>`;
  return                        `<span style="${_badgeStyle('#22c55e')}">🟢 Online</span>`;
}

function _badgeStyle(color) {
  return `background:${color}22;color:${color};border:1px solid ${color}55;` +
    'border-radius:20px;padding:3px 10px;font-size:11px;font-weight:700;';
}

function _pill(text, color) {
  return `<span style="background:${color}22;color:${color};border:1px solid ${color}44;
    border-radius:4px;padding:2px 8px;font-size:10px;font-weight:700;">${_esc(text)}</span>`;
}

// ── Animated count-up ─────────────────────────────────────────────────────────
function _animateCounters(container) {
  container.querySelectorAll('.dash-counter').forEach(el => {
    const target = parseInt(el.dataset.target, 10) || 0;
    if (target === 0) return;
    const duration = 600;
    const start    = performance.now();
    const tick = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      el.textContent = Math.round(progress * target);
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
}

// ── Buttons ─────────────────────────────────────────────────────────────────────
function _wireButtons(container) {
  container.querySelector('#dash-refresh-btn')
    ?.addEventListener('click', () => renderDashboard(container));

  const autoBtn = container.querySelector('#dash-auto-btn');
  autoBtn?.addEventListener('click', () => {
    _autoRefreshOn = !_autoRefreshOn;
    autoBtn.textContent = _autoRefreshOn ? '⏸ Auto-refresh ON' : '⏵ Auto-refresh';
    autoBtn.style.color = _autoRefreshOn ? '#38bdf8' : '#94a3b8';
    clearInterval(_autoRefreshTimer);
    if (_autoRefreshOn) {
      _autoRefreshTimer = setInterval(() => renderDashboard(container), 30_000);
    }
  });
}

// ── Skeleton ────────────────────────────────────────────────────────────────────
function _showSkeleton(container) {
  container.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <h1 style="margin:0;">Dashboard</h1>
      <span style="font-size:11px;color:#475569;">⟳ Loading…</span>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;">
      ${[...Array(4)].map(() => `
        <div style="${_card()}text-align:center;animation:pulse 1.5s infinite;">
          <div style="height:22px;background:#1e293b;border-radius:4px;margin-bottom:8px;"></div>
          <div style="height:36px;background:#1e293b;border-radius:4px;margin-bottom:6px;"></div>
          <div style="height:12px;background:#1e293b;border-radius:4px;width:60%;margin:0 auto;"></div>
        </div>`).join('')}
    </div>`;
}

// ── Utility ──────────────────────────────────────────────────────────────────────
function _api() {
  return (window._wvcState?.cfg?.backendUrl)
    || (window.CFG?.backendUrl)
    || localStorage.getItem('wvc_backend_url')
    || window.API_BASE
    || '';
}

function _timeout(ms) {
  return AbortSignal.timeout ? AbortSignal.timeout(ms) : new AbortController().signal;
}

function _fmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

function _esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _card() {
  return 'background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;';
}

function _btn(bg, fg) {
  return `background:${bg};color:${fg};border:1px solid #1e293b;border-radius:5px;` +
    'padding:5px 10px;font-family:monospace;cursor:pointer;' +
    'display:inline-flex;align-items:center;gap:4px;';
}

function _sectionTitle() {
  return 'font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;' +
    'letter-spacing:.07em;margin-bottom:10px;';
}
