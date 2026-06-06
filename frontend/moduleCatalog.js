/* ================================================================
   WebVulnConsole ⚡ — Module Catalog UI  (Task 5)
   Renders the Module Catalog page with:
   - Full module registry (mirrors src/core/moduleRegistry.js)
   - Per-policy enable/disable matrix
   - Category + severity filters + live search
   - Inline detail expand per module
   Usage: injected by app.js when page "catalog" is shown.
   ================================================================ */
'use strict';

// ─── Module Registry (mirrors backend moduleRegistry.js) ─────────────────────
const MODULE_REGISTRY = [
  // ── Exposure ──────────────────────────────────────────────────────────────
  {
    id: 'exposure.env.direct',
    name: '.env Direct Exposure',
    description: 'Checks if the application\'s root .env file is publicly accessible via a direct HTTP GET.',
    category: 'exposure',
    class: 'passive',
    severity: 'critical',
    owaspTag: 'A02-Cryptographic-Failures',
    cweTag: 'CWE-359',
    policies: { policy_normal: true, policy_aggressive: true, policy_extreme: true },
  },
  {
    id: 'exposure.env.variants',
    name: '.env Variant Files',
    description: 'Probes common .env variant paths: .env.local, .env.production, .env.staging, .env.development, .env.backup.',
    category: 'exposure',
    class: 'passive',
    severity: 'critical',
    owaspTag: 'A02-Cryptographic-Failures',
    cweTag: 'CWE-359',
    policies: { policy_normal: true, policy_aggressive: true, policy_extreme: true },
  },
  {
    id: 'exposure.backup.db_dumps',
    name: 'Database Dump Exposure',
    description: 'Checks candidate paths for publicly accessible SQL dump files (dump.sql, backup.sql, db.sql, database.sql, etc.).',
    category: 'exposure',
    class: 'passive',
    severity: 'critical',
    owaspTag: 'A01-Broken-Access-Control',
    cweTag: 'CWE-200',
    policies: { policy_normal: true, policy_aggressive: true, policy_extreme: true },
  },
  {
    id: 'exposure.backup.archives',
    name: 'Backup Archive Exposure',
    description: 'Checks candidate paths for publicly accessible ZIP/TAR backup archives that may contain source code or database exports.',
    category: 'exposure',
    class: 'passive',
    severity: 'high',
    owaspTag: 'A01-Broken-Access-Control',
    cweTag: 'CWE-530',
    policies: { policy_normal: true, policy_aggressive: true, policy_extreme: true },
  },
  // ── VCS ──────────────────────────────────────────────────────────────────
  {
    id: 'vcs.git.exposed',
    name: 'Exposed .git Repository',
    description: 'Probes .git/HEAD, .git/config, and .git/COMMIT_EDITMSG to detect publicly accessible Git repository components that allow source reconstruction.',
    category: 'exposure',
    class: 'passive',
    severity: 'high',
    owaspTag: 'A05-Security-Misconfiguration',
    cweTag: 'CWE-200',
    policies: { policy_normal: true, policy_aggressive: true, policy_extreme: true },
  },
  // ── Misconfiguration ──────────────────────────────────────────────────────
  {
    id: 'misconfig.dirlisting.generic',
    name: 'Directory Listing Enabled',
    description: 'Checks common paths for open directory listings (Apache/Nginx index pages) that expose internal file structure.',
    category: 'misconfig',
    class: 'passive',
    severity: 'medium',
    owaspTag: 'A05-Security-Misconfiguration',
    cweTag: 'CWE-548',
    policies: { policy_normal: true, policy_aggressive: true, policy_extreme: true },
  },
  // ── TLS / Headers ─────────────────────────────────────────────────────────
  {
    id: 'tls.headers.basic',
    name: 'TLS & Security Headers',
    description: 'Checks for: plain HTTP access without HTTPS redirect, missing or weak HSTS, missing CSP / X-Frame-Options / X-Content-Type-Options / Permissions-Policy / Referrer-Policy, server version banners, and cookie flag issues (Secure, HttpOnly, SameSite).',
    category: 'tls',
    class: 'passive',
    severity: 'medium',
    owaspTag: 'A02-Cryptographic-Failures / A05-Security-Misconfiguration',
    cweTag: 'CWE-319 / CWE-1021',
    policies: { policy_normal: true, policy_aggressive: true, policy_extreme: true },
  },
  // ── Debug ─────────────────────────────────────────────────────────────────
  {
    id: 'debug.stacktraces',
    name: 'Debug / Stack Trace Leakage',
    description: 'Probes a non-existent path to trigger 500 errors and inspects the response for stack traces, exception messages, or framework debug pages.',
    category: 'misconfig',
    class: 'passive',
    severity: 'medium',
    owaspTag: 'A05-Security-Misconfiguration',
    cweTag: 'CWE-209',
    policies: { policy_normal: true, policy_aggressive: true, policy_extreme: true },
  },
  // ── Injection ─────────────────────────────────────────────────────────────
  {
    id: 'injection.sqli.basic',
    name: 'SQL Injection (Basic Error-Based)',
    description: 'Sends common SQL injection payloads (\'  1=1 --, etc.) to discovered GET/POST parameters and checks responses for database error signatures from MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and DB2.',
    category: 'injection',
    class: 'active',
    severity: 'critical',
    owaspTag: 'A03-Injection',
    cweTag: 'CWE-89',
    policies: { policy_normal: false, policy_aggressive: true, policy_extreme: true },
  },
  {
    id: 'injection.xss.reflected',
    name: 'Reflected XSS (Basic)',
    description: 'Injects XSS payloads into discovered parameters and checks if the payload is reflected verbatim in the response body, indicating potential reflected cross-site scripting.',
    category: 'injection',
    class: 'active',
    severity: 'high',
    owaspTag: 'A03-Injection',
    cweTag: 'CWE-79',
    policies: { policy_normal: false, policy_aggressive: true, policy_extreme: true },
  },
  {
    id: 'injection.path_traversal.basic',
    name: 'Path Traversal (Basic)',
    description: 'Sends Linux and Windows path traversal payloads (../../etc/passwd, encoded variants) directly against the base URL and checks responses for /etc/passwd content or win.ini signatures.',
    category: 'injection',
    class: 'active',
    severity: 'high',
    owaspTag: 'A01-Broken-Access-Control',
    cweTag: 'CWE-22',
    policies: { policy_normal: false, policy_aggressive: false, policy_extreme: true },
  },
];

const POLICY_LABELS = {
  policy_normal:     { label: 'Normal',     color: '#22c55e', desc: 'Passive-only. Safe for production recon.' },
  policy_aggressive: { label: 'Aggressive', color: '#f97316', desc: 'Passive + active injection. Use with written authorization.' },
  policy_extreme:    { label: 'Extreme',    color: '#ef4444', desc: 'All modules including path traversal. Full red-team mode.' },
};

const CATEGORY_LABELS = {
  exposure:  { icon: '📂', label: 'Exposure' },
  injection: { icon: '💉', label: 'Injection' },
  tls:       { icon: '🔒', label: 'TLS / Headers' },
  misconfig: { icon: '⚙️',  label: 'Misconfiguration' },
  auth:      { icon: '🔑', label: 'Authentication' },
};

const CLASS_LABELS = {
  passive:  { label: 'Passive',  color: '#22c55e' },
  active:   { label: 'Active',   color: '#f97316' },
  external: { label: 'External', color: '#818cf8' },
};

// ─── State ────────────────────────────────────────────────────────────────────
let _catFilter  = '';
let _classFilter = '';
let _searchStr  = '';
let _expanded   = new Set();

// ─── Helpers ──────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function sevBadgeC(sev) {
  const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' };
  const c = colors[sev] || '#6b7280';
  return `<span style="display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;background:${c}22;color:${c};border:1px solid ${c}44">${esc(sev)}</span>`;
}
function policyDot(enabled) {
  return enabled
    ? `<span style="color:#22c55e;font-size:14px;" title="Enabled">✓</span>`
    : `<span style="color:#374151;font-size:14px;" title="Disabled">—</span>`;
}

// ─── Render ───────────────────────────────────────────────────────────────────
export function renderModuleCatalog(containerEl) {
  if (!containerEl) return;

  const policies = Object.keys(POLICY_LABELS);
  const categories = [...new Set(MODULE_REGISTRY.map(m => m.category))];

  // Filter
  let mods = MODULE_REGISTRY.filter(m => {
    if (_catFilter   && m.category !== _catFilter)   return false;
    if (_classFilter && m.class    !== _classFilter)  return false;
    if (_searchStr) {
      const q = _searchStr.toLowerCase();
      if (!m.name.toLowerCase().includes(q) && !m.id.toLowerCase().includes(q) && !m.description.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  // Policy legend
  const legendHtml = Object.entries(POLICY_LABELS).map(([id, p]) =>
    `<div style="display:flex;align-items:center;gap:6px;">
      <span style="width:10px;height:10px;border-radius:50%;background:${esc(p.color)};flex-shrink:0;"></span>
      <span style="font-weight:700;color:${esc(p.color)};font-size:11px;">${esc(p.label)}</span>
      <span style="color:#64748b;font-size:10px;">— ${esc(p.desc)}</span>
    </div>`
  ).join('');

  // Filter bar
  const catOptions = ['', ...categories].map(c =>
    `<option value="${esc(c)}" ${c === _catFilter ? 'selected' : ''}>${c ? ((CATEGORY_LABELS[c]?.icon || '') + ' ' + (CATEGORY_LABELS[c]?.label || c)) : 'All Categories'}</option>`
  ).join('');

  const classOptions = [
    `<option value="" ${!_classFilter ? 'selected' : ''}>All Classes</option>`,
    `<option value="passive"  ${_classFilter === 'passive'  ? 'selected' : ''}>🟢 Passive</option>`,
    `<option value="active"   ${_classFilter === 'active'   ? 'selected' : ''}>🟠 Active</option>`,
    `<option value="external" ${_classFilter === 'external' ? 'selected' : ''}>🟣 External</option>`,
  ].join('');

  // Module rows
  const rowsHtml = mods.length === 0
    ? `<div style="padding:32px;text-align:center;color:#475569;font-size:12px;">No modules match the current filters.</div>`
    : mods.map(m => {
        const catMeta   = CATEGORY_LABELS[m.category]  || { icon: '🔧', label: m.category };
        const classMeta = CLASS_LABELS[m.class]         || { label: m.class, color: '#6b7280' };
        const isOpen    = _expanded.has(m.id);

        const policyMatrix = policies.map(pid => {
          const pol = POLICY_LABELS[pid];
          const en  = !!m.policies?.[pid];
          return `<td style="text-align:center;padding:7px 10px;">${policyDot(en)}</td>`;
        }).join('');

        const detailHtml = isOpen ? `
          <tr id="detail-${esc(m.id)}">
            <td colspan="${5 + policies.length}" style="background:#020617;padding:14px 18px;border-bottom:1px solid #1e293b;">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
                <div>
                  <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px;">Description</div>
                  <div style="font-size:12px;color:#cbd5e1;line-height:1.6;">${esc(m.description)}</div>
                </div>
                <div style="display:flex;flex-direction:column;gap:8px;">
                  <div><span style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;">Module ID</span><br/>
                    <code style="font-size:11px;color:#38bdf8;">${esc(m.id)}</code></div>
                  <div><span style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;">OWASP</span><br/>
                    <span style="font-size:11px;color:#94a3b8;">${esc(m.owaspTag)}</span></div>
                  <div><span style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;">CWE</span><br/>
                    <span style="font-size:11px;color:#94a3b8;">${esc(m.cweTag)}</span></div>
                </div>
              </div>
              <div style="margin-top:10px;padding-top:10px;border-top:1px solid #1e293b;display:flex;gap:8px;flex-wrap:wrap;">
                ${policies.map(pid => {
                  const pol = POLICY_LABELS[pid];
                  const en  = !!m.policies?.[pid];
                  return `<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:12px;
                    background:${en ? pol.color + '22' : '#1e293b'};border:1px solid ${en ? pol.color + '55' : '#334155'};
                    font-size:10px;font-weight:700;color:${en ? pol.color : '#475569'};">
                    ${en ? '✓' : '✕'} ${esc(pol.label)}
                  </span>`;
                }).join('')}
              </div>
            </td>
          </tr>` : '';

        return `
          <tr class="mod-row" data-id="${esc(m.id)}" style="cursor:pointer;transition:background .15s;"
            onclick="window._catalogToggle('${esc(m.id)}')">
            <td style="padding:9px 12px;">
              <div style="font-size:12px;font-weight:600;color:#e2e8f0;">${esc(m.name)}</div>
              <div style="font-size:10px;color:#64748b;margin-top:2px;">${catMeta.icon} ${esc(catMeta.label)}</div>
            </td>
            <td style="padding:9px 10px;">
              <code style="font-size:10px;color:#64748b;">${esc(m.id)}</code>
            </td>
            <td style="padding:9px 10px;">${sevBadgeC(m.severity)}</td>
            <td style="padding:9px 10px;">
              <span style="display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;
                text-transform:uppercase;background:${classMeta.color}22;color:${classMeta.color};border:1px solid ${classMeta.color}44;">
                ${esc(classMeta.label)}
              </span>
            </td>
            ${policyMatrix}
            <td style="padding:9px 10px;text-align:center;color:#475569;font-size:12px;">${isOpen ? '▲' : '▼'}</td>
          </tr>
          ${detailHtml}
        `;
      }).join('');

  // Stats bar
  const total    = MODULE_REGISTRY.length;
  const passive  = MODULE_REGISTRY.filter(m => m.class === 'passive').length;
  const active   = MODULE_REGISTRY.filter(m => m.class === 'active').length;
  const showing  = mods.length;

  containerEl.innerHTML = `
    <!-- Stats -->
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;">
      ${[
        { num: total,   lbl: 'Total Modules',  col: 'var(--accent)' },
        { num: passive, lbl: 'Passive',         col: '#22c55e' },
        { num: active,  lbl: 'Active',          col: '#f97316' },
        { num: showing, lbl: 'Showing',         col: '#818cf8' },
      ].map(s => `
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:10px 16px;min-width:80px;flex:1;">
          <div style="font-size:22px;font-weight:800;color:${s.col};font-family:monospace;">${s.num}</div>
          <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-top:2px;">${s.lbl}</div>
        </div>`).join('')}
    </div>

    <!-- Policy Legend -->
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:12px 16px;margin-bottom:14px;
      display:flex;flex-direction:column;gap:6px;">
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:2px;">Scan Policy Legend</div>
      ${legendHtml}
    </div>

    <!-- Filters -->
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center;">
      <input
        id="catalog-search"
        type="text"
        placeholder="🔍  Search modules..."
        value="${esc(_searchStr)}"
        style="background:#0f172a;border:1px solid #1e293b;border-radius:5px;color:#e2e8f0;
          font-family:monospace;font-size:12px;padding:6px 10px;outline:none;flex:1;min-width:160px;"
        oninput="window._catalogSearch(this.value)"
      />
      <select
        style="background:#0f172a;border:1px solid #1e293b;color:#e2e8f0;font-family:monospace;
          font-size:11px;padding:5px 7px;border-radius:5px;outline:none;"
        onchange="window._catalogFilterCat(this.value)">
        ${catOptions}
      </select>
      <select
        style="background:#0f172a;border:1px solid #1e293b;color:#e2e8f0;font-family:monospace;
          font-size:11px;padding:5px 7px;border-radius:5px;outline:none;"
        onchange="window._catalogFilterClass(this.value)">
        ${classOptions}
      </select>
      ${(_catFilter || _classFilter || _searchStr)
        ? `<button onclick="window._catalogClearFilters()"
            style="background:#1e293b;border:1px solid #334155;color:#94a3b8;font-family:monospace;
              font-size:11px;padding:5px 10px;border-radius:5px;cursor:pointer;">✕ Clear</button>`
        : ''}
    </div>

    <!-- Table -->
    <div style="overflow-x:auto;border-radius:8px;border:1px solid #1e293b;">
      <table style="width:100%;border-collapse:collapse;font-size:12px;">
        <thead>
          <tr style="background:#0f172a;border-bottom:1px solid #1e293b;">
            <th style="text-align:left;padding:8px 12px;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;">Module</th>
            <th style="text-align:left;padding:8px 10px;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;">ID</th>
            <th style="text-align:left;padding:8px 10px;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.07em;">Severity</th>
            <th style="text-align:left;padding:8px 10px;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.07em;">Class</th>
            ${policies.map(pid =>
              `<th style="text-align:center;padding:8px 10px;color:${POLICY_LABELS[pid].color};font-size:10px;text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;">${POLICY_LABELS[pid].label}</th>`
            ).join('')}
            <th style="width:30px;"></th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
    </div>
  `;

  // Row hover effect via JS (no stylesheet needed)
  containerEl.querySelectorAll('.mod-row').forEach(row => {
    row.addEventListener('mouseenter', () => { row.style.background = 'rgba(56,189,248,.04)'; });
    row.addEventListener('mouseleave', () => { row.style.background = ''; });
  });
}

// ─── Global handlers (called from inline onclick) ─────────────────────────────
window._catalogToggle = function(id) {
  if (_expanded.has(id)) _expanded.delete(id); else _expanded.add(id);
  const container = document.getElementById('catalog-container');
  if (container) renderModuleCatalog(container);
};
window._catalogSearch = function(val) {
  _searchStr = val;
  const container = document.getElementById('catalog-container');
  if (container) renderModuleCatalog(container);
};
window._catalogFilterCat = function(val) {
  _catFilter = val;
  const container = document.getElementById('catalog-container');
  if (container) renderModuleCatalog(container);
};
window._catalogFilterClass = function(val) {
  _classFilter = val;
  const container = document.getElementById('catalog-container');
  if (container) renderModuleCatalog(container);
};
window._catalogClearFilters = function() {
  _catFilter = ''; _classFilter = ''; _searchStr = '';
  const container = document.getElementById('catalog-container');
  if (container) renderModuleCatalog(container);
};
