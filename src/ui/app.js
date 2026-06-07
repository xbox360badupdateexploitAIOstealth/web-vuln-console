// src/ui/app.js
// Main application shell.
//
// Responsibilities:
//   - Boot sequence: TOS gate → state.loadProjects() → initial render
//   - Sidebar navigation with active-item highlight
//   - Route all nav clicks to the correct view renderer
//   - Expose window._wvcToast global for cross-view toast notifications
//   - Keep active project name visible in the sidebar footer

import { ensureTosAccepted }        from './tos.js';
import { state }                    from './state.js';
import { renderDashboard }          from './views/dashboardView.js';
import { renderProjectList }        from './views/projectListView.js';
import { renderJobConsole }         from './views/jobConsoleView.js';
import { renderFindingsList }       from './views/findingsListView.js';
import { renderTargetsView }        from './views/targetsView.js';
import { moduleDefs }               from '../core/moduleRegistry.js';
import { scanPolicies }             from '../core/policyRegistry.js';

// ── DOM refs ──────────────────────────────────────────────────────────────────
const viewContainer = document.getElementById('view-container');
const sidebar       = document.querySelector('.sidebar');

// ── Active view tracking ──────────────────────────────────────────────────────
let _currentView = null;

// ── Navigation map ────────────────────────────────────────────────────────────
// Each entry: [viewKey, label, icon]
const NAV_ITEMS = [
  ['dashboard', 'Dashboard',  '◈'],
  ['projects',  'Projects',   '🗂'],
  ['targets',   'Targets',    '🎯'],
  ['jobs',      'Scan Jobs',  '⚙️'],
  ['findings',  'Findings',   '🔍'],
  ['modules',   'Modules',    '🧩'],
  ['policies',  'Policies',   '📋'],
  ['settings',  'Settings',   '⚙'],
];

// ─────────────────────────────────────────────────────────────────────────────
// showView — route to a view renderer
// ─────────────────────────────────────────────────────────────────────────────
function showView(view) {
  _currentView = view;
  _setActiveNav(view);

  switch (view) {
    case 'dashboard':
      renderDashboard(viewContainer);
      break;

    case 'projects':
      renderProjectList(viewContainer);
      break;

    case 'targets':
      renderTargetsView(viewContainer, state.currentProjectId);
      break;

    case 'jobs':
      renderJobConsole(viewContainer);
      break;

    case 'findings':
      renderFindingsList(viewContainer);
      break;

    case 'modules':
      _renderModulesView(viewContainer);
      break;

    case 'policies':
      _renderPoliciesView(viewContainer);
      break;

    case 'settings':
      _renderSettingsView(viewContainer);
      break;

    default:
      renderDashboard(viewContainer);
      break;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sidebar active highlight
// ─────────────────────────────────────────────────────────────────────────────
function _setActiveNav(view) {
  sidebar.querySelectorAll('[data-view]').forEach(btn => {
    const isActive = btn.dataset.view === view;
    btn.style.background  = isActive ? '#0f172a' : '';
    btn.style.color       = isActive ? '#38bdf8' : '';
    btn.style.borderLeft  = isActive ? '2px solid #38bdf8' : '2px solid transparent';
    btn.style.fontWeight  = isActive ? '700' : '';
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Sidebar project footer
// ─────────────────────────────────────────────────────────────────────────────
function _updateSidebarProject() {
  let el = document.getElementById('sb-project-footer');
  if (!el) {
    el = document.createElement('div');
    el.id = 'sb-project-footer';
    Object.assign(el.style, {
      padding       : '10px 12px',
      borderTop     : '1px solid #1e293b',
      fontSize      : '11px',
      color         : '#64748b',
      marginTop     : 'auto',
      wordBreak     : 'break-word',
      lineHeight    : '1.4',
    });
    sidebar.appendChild(el);
  }
  const p = state.currentProject;
  el.innerHTML = p
    ? `<span style="opacity:.5;">Project</span><br>
       <strong style="color:#38bdf8;font-size:12px;">${_esc(p.name)}</strong>`
    : `<span style="opacity:.4;">No project selected</span>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Modules view
// ─────────────────────────────────────────────────────────────────────────────
function _renderModulesView(container) {
  const catGroups = {};
  for (const m of moduleDefs) {
    const cat = m.category || 'other';
    if (!catGroups[cat]) catGroups[cat] = [];
    catGroups[cat].push(m);
  }

  const clazzColor = { passive:'#3b82f6', active:'#f97316', aggressive:'#ef4444' };
  const sevColor   = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280' };

  container.innerHTML = `
    <div style="max-width:860px;">
      <div style="display:flex;align-items:center;justify-content:space-between;
        flex-wrap:wrap;gap:8px;margin-bottom:14px;">
        <h1 style="margin:0;font-size:18px;">Modules
          <span style="font-size:12px;opacity:.4;margin-left:6px;">${moduleDefs.length} loaded</span>
        </h1>
        <input id="mod-search" type="text" placeholder="🔍 Search modules…"
          style="${_iStyle()}width:200px;" />
      </div>

      <div id="mod-list">
        ${Object.entries(catGroups).map(([cat, mods]) => `
          <div style="margin-bottom:18px;">
            <div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;
              letter-spacing:.07em;margin-bottom:8px;padding-bottom:4px;
              border-bottom:1px solid #1e293b;">${_esc(cat)} (${mods.length})</div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;">
              ${mods.map(m => {
                const cc = clazzColor[m.clazz] || '#6b7280';
                const sc = sevColor[m.severityDefault] || '#6b7280';
                const owasp = (m.owaspTags||[]).join(', ');
                const cwe   = (m.cweTags||[]).join(', ');
                return `
                <div class="mod-card" data-name="${_esc((m.name||'').toLowerCase())}"
                  data-desc="${_esc((m.description||'').toLowerCase())}"
                  style="background:#0f172a;border:1px solid #1e293b;border-radius:7px;
                    padding:12px;font-size:11px;">
                  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:4px;margin-bottom:6px;">
                    <div style="font-weight:700;color:#e2e8f0;font-size:12px;">${_esc(m.name||m.id)}</div>
                    <div style="display:flex;gap:4px;flex-shrink:0;">
                      <span style="background:${cc}18;color:${cc};border:1px solid ${cc}44;
                        padding:1px 6px;border-radius:4px;font-size:9px;font-weight:700;
                        text-transform:uppercase;">${_esc(m.clazz||'')}</span>
                      <span style="background:${sc}18;color:${sc};border:1px solid ${sc}44;
                        padding:1px 6px;border-radius:4px;font-size:9px;font-weight:700;
                        text-transform:uppercase;">${_esc(m.severityDefault||'')}</span>
                    </div>
                  </div>
                  <div style="color:#64748b;margin-bottom:6px;line-height:1.5;">${_esc(m.description||'')}</div>
                  ${owasp ? `<div style="font-size:9px;color:#475569;margin-bottom:2px;">OWASP: ${_esc(owasp)}</div>` : ''}
                  ${cwe   ? `<div style="font-size:9px;color:#475569;">CWE: ${_esc(cwe)}</div>` : ''}
                  ${(m.stackFilters||[]).length ? `
                    <div style="margin-top:6px;display:flex;gap:3px;flex-wrap:wrap;">
                      ${m.stackFilters.map(s =>
                        `<span style="background:#1e293b;color:#94a3b8;padding:1px 5px;
                          border-radius:3px;font-size:9px;">${_esc(s)}</span>`
                      ).join('')}
                    </div>` : ''}
                </div>`;
              }).join('')}
            </div>
          </div>`
        ).join('')}
      </div>
    </div>`;

  // Live search
  container.querySelector('#mod-search')?.addEventListener('input', e => {
    const q = e.target.value.trim().toLowerCase();
    container.querySelectorAll('.mod-card').forEach(card => {
      const match = !q
        || card.dataset.name.includes(q)
        || card.dataset.desc.includes(q);
      card.closest('div[style*="grid"]') && (card.style.display = match ? '' : 'none');
      card.style.display = match ? '' : 'none';
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Policies view
// ─────────────────────────────────────────────────────────────────────────────
function _renderPoliciesView(container) {
  container.innerHTML = `
    <div style="max-width:860px;">
      <h1 style="margin:0 0 14px;font-size:18px;">Scan Policies
        <span style="font-size:12px;opacity:.4;margin-left:6px;">${scanPolicies.length} policies</span>
      </h1>
      ${scanPolicies.map(p => {
        const limits = p.globalLimits || {};
        const overrideCount = Object.keys(p.moduleOverrides||{}).length;
        return `
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;
          padding:16px;margin-bottom:12px;">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;
            flex-wrap:wrap;gap:8px;margin-bottom:10px;">
            <div>
              <div style="font-size:14px;font-weight:700;color:#e2e8f0;">${_esc(p.name)}</div>
              <div style="font-size:11px;color:#64748b;margin-top:2px;">${_esc(p.id)}</div>
            </div>
            <span style="background:#38bdf818;color:#38bdf8;border:1px solid #38bdf844;
              padding:3px 10px;border-radius:4px;font-size:10px;font-weight:700;">
              ${overrideCount} module override${overrideCount !== 1 ? 's' : ''}
            </span>
          </div>
          ${p.description ? `<div style="font-size:12px;color:#94a3b8;margin-bottom:10px;">${_esc(p.description)}</div>` : ''}
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;">
            ${[
              ['Max Req/s',      limits.maxRequestsPerSecond ?? '—'],
              ['Max Parallel',   limits.maxParallelTargets   ?? '—'],
              ['Max Duration',   limits.maxScanDurationSeconds ? `${limits.maxScanDurationSeconds}s` : '—'],
            ].map(([k,v]) => `
              <div style="background:#070d18;border:1px solid #0f172a;border-radius:5px;
                padding:8px 10px;">
                <div style="font-size:9px;color:#475569;text-transform:uppercase;
                  letter-spacing:.06em;margin-bottom:3px;">${k}</div>
                <div style="font-size:14px;font-weight:700;color:#e2e8f0;">${v}</div>
              </div>`
            ).join('')}
          </div>
          ${overrideCount ? `
            <details style="margin-top:10px;">
              <summary style="font-size:10px;color:#64748b;cursor:pointer;
                user-select:none;">
                Module overrides (${overrideCount})
              </summary>
              <pre style="margin:6px 0 0;font-size:10px;background:#020617;
                border:1px solid #0f172a;border-radius:5px;padding:8px;
                overflow:auto;max-height:160px;color:#94a3b8;">${
                  _esc(JSON.stringify(p.moduleOverrides, null, 2))
                }</pre>
            </details>` : ''}
        </div>`;
      }).join('')}
    </div>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings view
// ─────────────────────────────────────────────────────────────────────────────
function _renderSettingsView(container) {
  const savedUrl = localStorage.getItem('wvc_backend_url') || '';
  const savedTos = localStorage.getItem('web_vuln_console_tos_accepted_v1') === '1';

  container.innerHTML = `
    <div style="max-width:600px;">
      <h1 style="margin:0 0 14px;font-size:18px;">Settings</h1>

      <!-- Backend URL -->
      <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;
        padding:16px;margin-bottom:12px;">
        <div style="font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;
          letter-spacing:.07em;margin-bottom:10px;">Backend / API</div>
        <label style="${_lblStyle()}">Backend URL</label>
        <div style="display:flex;gap:8px;align-items:center;">
          <input id="cfg-backend-url" type="text"
            value="${_esc(savedUrl)}" placeholder="http://127.0.0.1:8787"
            style="${_iStyle()}flex:1;" />
          <button id="cfg-save-url"
            style="${_btnStyle('#38bdf8','#020617')}">Save</button>
        </div>
        <div style="font-size:10px;color:#475569;margin-top:5px;">
          Used by the Targets view, Dashboard, and any API-backed calls.
          Leave blank to run fully offline.
        </div>
      </div>

      <!-- TOS status -->
      <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;
        padding:16px;margin-bottom:12px;">
        <div style="font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;
          letter-spacing:.07em;margin-bottom:10px;">Authorization &amp; ToS</div>
        <div style="font-size:12px;color:#94a3b8;margin-bottom:10px;">
          Status:
          <strong style="color:${savedTos ? '#22c55e' : '#ef4444'}">
            ${savedTos ? '✓ Accepted' : '✗ Not accepted'}
          </strong>
        </div>
        <button id="cfg-reset-tos"
          style="${_btnStyle('#ef444418','#ef4444')}border:1px solid #ef444444;">
          Reset ToS acceptance
        </button>
      </div>

      <!-- Clear db -->
      <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;
        padding:16px;margin-bottom:12px;">
        <div style="font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;
          letter-spacing:.07em;margin-bottom:10px;">Data</div>
        <div style="font-size:12px;color:#94a3b8;margin-bottom:10px;">
          Clear all locally stored projects, jobs, findings, and evidences.
          This cannot be undone.
        </div>
        <button id="cfg-clear-db"
          style="${_btnStyle('#ef444418','#ef4444')}border:1px solid #ef444444;">
          🗑 Clear all local data
        </button>
        <span id="cfg-clear-msg" style="font-size:11px;color:#64748b;margin-left:10px;"></span>
      </div>

      <!-- About -->
      <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;
        padding:16px;">
        <div style="font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;
          letter-spacing:.07em;margin-bottom:8px;">About</div>
        <div style="font-size:12px;color:#64748b;line-height:1.6;">
          <div>Web Vulnerability Console</div>
          <div style="margin-top:4px;opacity:.6;">
            ${moduleDefs.length} modules &nbsp;·&nbsp;
            ${scanPolicies.length} policies
          </div>
        </div>
      </div>
    </div>`;

  // Save backend URL
  container.querySelector('#cfg-save-url').addEventListener('click', () => {
    const url = container.querySelector('#cfg-backend-url').value.trim();
    if (url) localStorage.setItem('wvc_backend_url', url);
    else     localStorage.removeItem('wvc_backend_url');
    _toast('Settings saved.', 'ok');
  });

  // Reset TOS
  container.querySelector('#cfg-reset-tos').addEventListener('click', () => {
    localStorage.removeItem('web_vuln_console_tos_accepted_v1');
    _toast('ToS acceptance cleared. Reload to see the gate.', 'warn');
    _renderSettingsView(container); // re-render to update badge
  });

  // Clear all data
  container.querySelector('#cfg-clear-db').addEventListener('click', async () => {
    if (!confirm('Clear ALL local data (projects, jobs, findings, evidences)?\nThis cannot be undone.')) return;
    const msgEl = container.querySelector('#cfg-clear-msg');
    msgEl.textContent = 'Clearing…';
    try {
      const { db, S } = await import('../core/db.js');
      await Promise.all([
        db.clear(S.PROJECTS),
        db.clear(S.SCAN_JOBS),
        db.clear(S.FINDINGS),
        db.clear(S.EVIDENCES),
        db.clear(S.TARGETS),
        db.clear(S.AUDIT_EVENTS),
      ]);
      await state.loadProjects();
      msgEl.textContent = '✓ Done.';
      _toast('All local data cleared.', 'warn');
    } catch(e) {
      msgEl.textContent = `Error: ${e.message}`;
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Sidebar nav click handler
// ─────────────────────────────────────────────────────────────────────────────
function handleNavClick(e) {
  const btn = e.target.closest('[data-view]');
  if (!btn) return;
  showView(btn.dataset.view);
}

sidebar.addEventListener('click', handleNavClick);

// ─────────────────────────────────────────────────────────────────────────────
// Global toast helper (used by views via window._wvcToast)
// ─────────────────────────────────────────────────────────────────────────────
window._wvcToast = function(msg, type = 'info') {
  const t = document.createElement('div');
  t.textContent = msg;
  Object.assign(t.style, {
    position   : 'fixed',
    bottom     : '20px',
    right      : '20px',
    zIndex     : '9999',
    background : type === 'ok' ? '#16a34a' : type === 'warn' ? '#b45309' : '#1e293b',
    color      : '#fff',
    padding    : '8px 14px',
    borderRadius: '6px',
    fontSize   : '12px',
    fontFamily : 'monospace',
    boxShadow  : '0 4px 12px rgba(0,0,0,.4)',
    opacity    : '1',
    transition : 'opacity .3s',
    maxWidth   : '320px',
    wordBreak  : 'break-word',
  });
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 320); }, 2600);
};

// ─────────────────────────────────────────────────────────────────────────────
// State bus hooks
// ─────────────────────────────────────────────────────────────────────────────

// Keep sidebar project footer in sync
state.on('project', () => {
  _updateSidebarProject();
  // If targets view is currently open, re-render it with new project
  if (_currentView === 'targets') {
    renderTargetsView(viewContainer, state.currentProjectId);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Boot sequence
// ─────────────────────────────────────────────────────────────────────────────
async function boot() {
  // 1. TOS gate — blocks if not accepted yet
  if (!ensureTosAccepted()) return;

  // 2. Load projects from db into state
  await state.loadProjects();

  // 3. Paint sidebar project footer
  _updateSidebarProject();

  // 4. Initial render
  showView('dashboard');
}

boot();

// ─────────────────────────────────────────────────────────────────────────────
// Tiny shared helpers (used by inline view renderers above)
// ─────────────────────────────────────────────────────────────────────────────
function _toast(msg, type) { window._wvcToast(msg, type); }

function _esc(s) {
  return String(s||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _iStyle() {
  return 'background:#020617;border:1px solid #1e293b;border-radius:5px;' +
    'color:#e2e8f0;font-size:12px;padding:7px 10px;outline:none;box-sizing:border-box;';
}

function _lblStyle() {
  return 'display:block;font-size:10px;color:#64748b;text-transform:uppercase;' +
    'letter-spacing:.07em;margin-bottom:3px;';
}

function _btnStyle(bg, fg) {
  return `background:${bg};color:${fg};border:none;border-radius:5px;` +
    'padding:7px 14px;font-size:12px;font-weight:700;cursor:pointer;' +
    'white-space:nowrap;font-family:inherit;';
}
