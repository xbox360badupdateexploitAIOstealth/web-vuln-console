// src/ui/views/policyView.js
// TODO-13: Policy editor UI
//   - Shows all 3 scan policies (Normal / Aggressive / Extreme)
//   - Per-module toggle checkboxes, grouped by category
//   - Aggressiveness slider (0 = off, 1 = normal, 2 = aggressive)
//   - Global limits: maxRequestsPerSecond, maxParallelTargets, maxScanDurationSeconds
//   - Save to backend (PUT /api/policies/:id) with offline localStorage fallback
//   - Reset to factory defaults
//   - Read-only preview of module metadata (severity, OWASP, CWE, CVE examples)
//   - Module class badge: passive (blue) / active (red)

'use strict';

// ── Module catalogue (mirrors src/core/moduleRegistry.js) ──────────────────────
// Kept inline so policyView works as a standalone UI module without
// a bundler import from src/core.
const MODULE_CATALOG = [
  // ── PASSIVE: EXPOSURE ────────────────────────────────────────────────────────
  { id:'exposure.env.direct',          name:'Direct .env Exposure',                        clazz:'passive', category:'Exposure',   severityDefault:'critical', owasp:['A02'], cwe:['CWE-359'] },
  { id:'exposure.env.variants',        name:'.env Variant Exposure',                       clazz:'passive', category:'Exposure',   severityDefault:'critical', owasp:['A02'], cwe:['CWE-359'] },
  { id:'exposure.backup.db_dumps',     name:'Database Backup Files',                       clazz:'passive', category:'Exposure',   severityDefault:'critical', owasp:['A01'], cwe:['CWE-200'] },
  { id:'exposure.backup.archives',     name:'Archive Backup Files',                        clazz:'passive', category:'Exposure',   severityDefault:'high',     owasp:['A01'], cwe:['CWE-530'] },
  { id:'misconfig.dirlisting.generic', name:'Directory Listing Detection',                 clazz:'passive', category:'Misconfig',  severityDefault:'medium',   owasp:['A05'], cwe:['CWE-548'] },
  { id:'vcs.git.exposed',              name:'Exposed .git Repository',                     clazz:'passive', category:'Exposure',   severityDefault:'high',     owasp:['A05'], cwe:['CWE-200'] },
  { id:'debug.stacktraces',            name:'Verbose Error & Stack Trace Detection',       clazz:'passive', category:'Exposure',   severityDefault:'medium',   owasp:['A05'], cwe:['CWE-209'] },
  { id:'tls.headers.basic',            name:'TLS & Security Header Check',                 clazz:'passive', category:'TLS',        severityDefault:'info',     owasp:['A02','A05'], cwe:['CWE-319'] },
  { id:'cookie.session.flags',         name:'Cookie & Session Security Checks',            clazz:'passive', category:'Misconfig',  severityDefault:'high',     owasp:['A07'], cwe:['CWE-539'] },
  { id:'exposure.js.secrets',          name:'JavaScript Asset Secret Scanner',             clazz:'passive', category:'JS',         severityDefault:'critical', owasp:['A02'], cwe:['CWE-312','CWE-798'] },
  { id:'exposure.sourcemap',           name:'JavaScript Source Map Exposure',              clazz:'passive', category:'JS',         severityDefault:'critical', owasp:['A05'], cwe:['CWE-540'] },
  // ── PASSIVE: CVE ─────────────────────────────────────────────────────────────
  { id:'exposure.cve.cpanel_whm',      name:'cPanel & WHM Exposure (CVE-2026-41940)',      clazz:'passive', category:'CVE',        severityDefault:'critical', owasp:['A05'], cwe:['CWE-200'],        cveExamples:['CVE-2026-41940'] },
  { id:'exposure.cve.laravel_env_hunt',name:'Laravel .env Hunt (CVE-2024-55556)',           clazz:'passive', category:'CVE',        severityDefault:'critical', owasp:['A02','A05'], cwe:['CWE-312'], cveExamples:['CVE-2024-55556','CVE-2025-70841'] },
  { id:'cve.fingerprints',             name:'CVE Fingerprint Checks (2025–2026)',           clazz:'passive', category:'CVE',        severityDefault:'high',     owasp:['A01','A05','A07'], cwe:['CWE-287'],cveExamples:['CVE-2025-32432','CVE-2026-33017','+ 15 more'] },
  { id:'misconfig.phpinfo.exposed',    name:'PHP Info / Debug Page Exposed',               clazz:'passive', category:'CVE',        severityDefault:'critical', owasp:['A05'], cwe:['CWE-200'] },
  { id:'vcs.svn_hg.exposed',           name:'SVN / Mercurial Repository Exposure',         clazz:'passive', category:'Exposure',   severityDefault:'critical', owasp:['A05'], cwe:['CWE-200'] },
  { id:'exposure.cve.vite_bypass',     name:'Vite Dev Server @fs LFI (CVE-2025-30208)',    clazz:'passive', category:'CVE',        severityDefault:'critical', owasp:['A01'], cwe:['CWE-22'],  cveExamples:['CVE-2025-30208','CVE-2025-46565'] },
  { id:'exposure.cve.mautic_env',      name:'Mautic .env Disclosure (CVE-2024-47056)',     clazz:'passive', category:'CVE',        severityDefault:'critical', owasp:['A02'], cwe:['CWE-312'], cveExamples:['CVE-2024-47056'] },
  { id:'exposure.cve.moodle_listing',  name:'Moodle Data Dir / r.php (CVE-2025-62396)',    clazz:'passive', category:'CVE',        severityDefault:'high',     owasp:['A05'], cwe:['CWE-548'], cveExamples:['CVE-2025-62396'] },
  { id:'exposure.cloud.open_bucket',   name:'Open Cloud Storage Bucket (S3/Azure/GCS)',    clazz:'passive', category:'Exposure',   severityDefault:'critical', owasp:['A01'], cwe:['CWE-284'] },
  { id:'exposure.cms.wp_debug',        name:'WordPress Debug Artifacts Exposed',           clazz:'passive', category:'CVE',        severityDefault:'critical', owasp:['A02','A05'], cwe:['CWE-312'] },
  // ── ACTIVE: INJECTION ────────────────────────────────────────────────────────
  { id:'injection.sqli.basic',         name:'Basic SQL Injection Probes',                  clazz:'active',  category:'Injection',  severityDefault:'high',     owasp:['A03'], cwe:['CWE-89'] },
  { id:'injection.xss.reflected_basic',name:'Reflected XSS Probes',                        clazz:'active',  category:'Injection',  severityDefault:'medium',   owasp:['A03'], cwe:['CWE-79'] },
  { id:'injection.path_traversal.basic',name:'Path Traversal / Local File Read',           clazz:'active',  category:'Injection',  severityDefault:'critical', owasp:['A01'], cwe:['CWE-22'] },
  { id:'injection.cmdi.basic',         name:'OS Command Injection Probes',                 clazz:'active',  category:'Injection',  severityDefault:'critical', owasp:['A03'], cwe:['CWE-78'] },
  { id:'injection.ssti.basic',         name:'SSTI Probes',                                  clazz:'active',  category:'Injection',  severityDefault:'critical', owasp:['A03'], cwe:['CWE-94'] },
  { id:'injection.fileupload.detect',  name:'Dangerous File Upload Detection',             clazz:'active',  category:'Injection',  severityDefault:'critical', owasp:['A03'], cwe:['CWE-434'] },
];

const CATEGORIES = [...new Set(MODULE_CATALOG.map(m => m.category))];

// ── Factory defaults (mirrors policyRegistry.js) ──────────────────────────────
const FACTORY_DEFAULTS = {
  policy_normal: {
    name: 'Normal (Passive Only)',
    description: 'Low-impact passive scanning — safe for production systems.',
    limits: { maxRequestsPerSecond: 3, maxParallelTargets: 2, maxScanDurationSeconds: 1200 },
    modules: {
      'exposure.env.direct':true,'exposure.env.variants':true,'exposure.backup.db_dumps':true,
      'exposure.backup.archives':true,'misconfig.dirlisting.generic':true,'vcs.git.exposed':true,
      'debug.stacktraces':true,'tls.headers.basic':true,'cookie.session.flags':true,
      'exposure.js.secrets':true,'exposure.sourcemap':true,'cve.fingerprints':true,
    },
    aggressiveness: {},
  },
  policy_aggressive: {
    name: 'Aggressive (Passive + Full Injection Suite)',
    description: 'All passive checks plus SQLi, XSS, path traversal, CMDi, SSTI, file upload. Authorized targets only.',
    limits: { maxRequestsPerSecond: 5, maxParallelTargets: 3, maxScanDurationSeconds: 2400 },
    modules: {
      'exposure.env.direct':true,'exposure.env.variants':true,'exposure.backup.db_dumps':true,
      'exposure.backup.archives':true,'misconfig.dirlisting.generic':true,'vcs.git.exposed':true,
      'debug.stacktraces':true,'tls.headers.basic':true,'cookie.session.flags':true,
      'exposure.js.secrets':true,'exposure.sourcemap':true,'cve.fingerprints':true,
      'injection.sqli.basic':true,'injection.xss.reflected_basic':true,
      'injection.path_traversal.basic':true,'injection.cmdi.basic':true,
      'injection.ssti.basic':true,'injection.fileupload.detect':true,
    },
    aggressiveness: {},
  },
  policy_extreme: {
    name: 'Extreme (Full Suite — All Modules)',
    description: 'Every module enabled at max aggressiveness. Lab / dedicated pentest environments only.',
    limits: { maxRequestsPerSecond: 10, maxParallelTargets: 5, maxScanDurationSeconds: 7200 },
    modules: Object.fromEntries(MODULE_CATALOG.map(m => [m.id, true])),
    aggressiveness: Object.fromEntries(MODULE_CATALOG.map(m => [m.id, m.clazz === 'active' ? 2 : 1])),
  },
};

// ── Working copies (loaded from API / localStorage, then edited in place) ─────
let _policies = {};
let _activeId  = 'policy_normal';
let _container = null;
let _dirty     = false;

// ── Entry point ────────────────────────────────────────────────────────────────
export async function renderPolicyView(container) {
  _container = container;
  await _loadPolicies();

  container.innerHTML = `
    <h1>Scan Policies</h1>
    <p style="color:#64748b;font-size:12px;margin:-4px 0 16px;">
      Toggle modules per policy, adjust rate limits, and save. Changes are stored locally
      and synced to the backend if available.
    </p>

    <!-- Policy tab strip -->
    <div id="pv-tabs" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px;"></div>

    <!-- Policy editor panel -->
    <div id="pv-editor"></div>

    <!-- Action bar -->
    <div id="pv-actions" style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap;align-items:center;">
      <button id="pv-save-btn"   style="${_btn('#38bdf8','#020617')}">✓ Save Policy</button>
      <button id="pv-reset-btn"  style="${_btn('#64748b','#fff')}">↺ Reset to Defaults</button>
      <span   id="pv-save-status" style="font-size:11px;color:#64748b;"></span>
    </div>
  `;

  _buildTabs();
  _renderEditor();

  container.querySelector('#pv-save-btn') .addEventListener('click', _handleSave);
  container.querySelector('#pv-reset-btn').addEventListener('click', _handleReset);
}

// ── Load policies ─────────────────────────────────────────────────────────────
async function _loadPolicies() {
  // Try API first
  try {
    const base = _apiBase();
    const res  = await fetch(`${base}/api/policies`);
    if (res.ok) {
      const json = await res.json();
      const arr  = json.policies || json || [];
      if (arr.length) {
        arr.forEach(p => { _policies[p.id] = p; });
        return;
      }
    }
  } catch { /* fallthrough to localStorage */ }

  // Try localStorage
  try {
    const saved = localStorage.getItem('wvc_policies');
    if (saved) {
      const parsed = JSON.parse(saved);
      Object.assign(_policies, parsed);
      return;
    }
  } catch { /* fallthrough to factory */ }

  // Factory defaults
  _policies = JSON.parse(JSON.stringify(FACTORY_DEFAULTS));
}

// ── Tab strip ─────────────────────────────────────────────────────────────────
function _buildTabs() {
  const tabsEl = _container.querySelector('#pv-tabs');
  tabsEl.innerHTML = Object.keys(_policies).map(id => {
    const p      = _policies[id];
    const active = id === _activeId;
    const risk   = _riskLevel(id);
    return `<button class="pv-tab" data-id="${id}" style="
      background:${active ? '#0f172a' : '#020617'};
      border:${active ? '1px solid #38bdf8' : '1px solid #1e293b'};
      border-radius:6px;padding:7px 14px;cursor:pointer;
      color:${active ? '#38bdf8' : '#94a3b8'};
      font-family:monospace;font-size:12px;font-weight:${active ? 700 : 400};
      display:inline-flex;align-items:center;gap:6px;
    ">
      <span style="width:7px;height:7px;border-radius:50%;background:${risk.color};display:inline-block;"></span>
      ${_esc(p.name || id)}
    </button>`;
  }).join('');

  tabsEl.querySelectorAll('.pv-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      if (_dirty) {
        const ok = confirm('You have unsaved changes. Switch policy anyway?');
        if (!ok) return;
        _dirty = false;
      }
      _activeId = btn.dataset.id;
      _buildTabs();
      _renderEditor();
    });
  });
}

// ── Main editor ───────────────────────────────────────────────────────────────
function _renderEditor() {
  const p = _policies[_activeId];
  if (!p) return;

  const editorEl = _container.querySelector('#pv-editor');
  editorEl.innerHTML = `
    <!-- Policy meta -->
    <div style="${_card()}margin-bottom:12px;">
      <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;">
        Policy Settings
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <div style="flex:1;min-width:180px;">
          <label style="${_lbl()}">Name</label>
          <input id="pv-policy-name" type="text" value="${_esc(p.name || '')}" style="${_inp()}" />
        </div>
        <div style="flex:2;min-width:240px;">
          <label style="${_lbl()}">Description</label>
          <input id="pv-policy-desc" type="text" value="${_esc(p.description || '')}" style="${_inp()}" />
        </div>
      </div>

      <!-- Global limits -->
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
        <div>
          <label style="${_lbl()}">Req/sec</label>
          <input id="pv-rps" type="number" min="1" max="50" value="${_esc(p.limits?.maxRequestsPerSecond ?? 3)}"
            style="${_inp()}width:70px;" />
        </div>
        <div>
          <label style="${_lbl()}">Parallel targets</label>
          <input id="pv-par" type="number" min="1" max="20" value="${_esc(p.limits?.maxParallelTargets ?? 2)}"
            style="${_inp()}width:80px;" />
        </div>
        <div>
          <label style="${_lbl()}">Max duration (s)</label>
          <input id="pv-dur" type="number" min="60" max="86400" value="${_esc(p.limits?.maxScanDurationSeconds ?? 1200)}"
            style="${_inp()}width:100px;" />
        </div>
      </div>
    </div>

    <!-- Module toggles, grouped by category -->
    <div id="pv-modules">
      ${CATEGORIES.map(cat => _renderCategoryBlock(cat, p)).join('')}
    </div>
  `;

  // Wire field change → mark dirty
  ['#pv-policy-name','#pv-policy-desc','#pv-rps','#pv-par','#pv-dur'].forEach(sel => {
    editorEl.querySelector(sel)?.addEventListener('input', () => { _dirty = true; });
  });

  // Wire module checkboxes
  editorEl.querySelectorAll('.pv-mod-check').forEach(cb => {
    cb.addEventListener('change', () => {
      _policies[_activeId].modules = _policies[_activeId].modules || {};
      _policies[_activeId].modules[cb.dataset.id] = cb.checked;
      _dirty = true;
      // update row style
      const row = _container.querySelector(`#pv-row-${cb.dataset.id.replace(/[^a-z0-9]/gi,'_')}`);
      if (row) row.style.opacity = cb.checked ? '1' : '0.45';
    });
  });

  // Wire category select-all
  editorEl.querySelectorAll('.pv-cat-all').forEach(btn => {
    btn.addEventListener('click', () => {
      const cat   = btn.dataset.cat;
      const state = btn.dataset.state !== 'on';
      btn.dataset.state = state ? 'on' : 'off';
      btn.textContent   = state ? 'Deselect All' : 'Select All';
      MODULE_CATALOG.filter(m => m.category === cat).forEach(m => {
        const cb = _container.querySelector(`.pv-mod-check[data-id="${m.id}"]`);
        if (cb) { cb.checked = state; cb.dispatchEvent(new Event('change')); }
      });
    });
  });

  // Wire aggressiveness sliders
  editorEl.querySelectorAll('.pv-aggr').forEach(sl => {
    sl.addEventListener('input', () => {
      _policies[_activeId].aggressiveness = _policies[_activeId].aggressiveness || {};
      _policies[_activeId].aggressiveness[sl.dataset.id] = parseInt(sl.value, 10);
      const lbl = _container.querySelector(`#pv-aggr-lbl-${sl.dataset.id.replace(/[^a-z0-9]/gi,'_')}`);
      if (lbl) lbl.textContent = _aggrLabel(parseInt(sl.value, 10));
      _dirty = true;
    });
  });
}

function _renderCategoryBlock(cat, p) {
  const mods     = MODULE_CATALOG.filter(m => m.category === cat);
  const enabledN = mods.filter(m => p.modules?.[m.id]).length;
  return `
    <div style="${_card()}margin-bottom:10px;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;margin-bottom:10px;">
        <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.07em;">
          ${_esc(cat)}
          <span style="font-size:10px;color:#475569;font-weight:400;margin-left:6px;">
            ${enabledN}/${mods.length} enabled
          </span>
        </div>
        <button class="pv-cat-all" data-cat="${_esc(cat)}" data-state="${enabledN>0?'on':'off'}"
          style="${_btn('#1e293b','#94a3b8')}font-size:10px;padding:4px 10px;">
          ${enabledN > 0 ? 'Deselect All' : 'Select All'}
        </button>
      </div>
      ${mods.map(m => _renderModuleRow(m, p)).join('')}
    </div>`;
}

function _renderModuleRow(m, p) {
  const enabled = !!(p.modules?.[m.id]);
  const aggr    = p.aggressiveness?.[m.id] ?? (m.clazz === 'active' ? 1 : 1);
  const safeId  = m.id.replace(/[^a-z0-9]/gi,'_');
  const sevCol  = _sevColor(m.severityDefault);
  const clazzBadge = m.clazz === 'active'
    ? `<span style="background:#ef444422;color:#ef4444;border:1px solid #ef444455;border-radius:3px;font-size:9px;font-weight:700;padding:1px 5px;text-transform:uppercase;">active</span>`
    : `<span style="background:#3b82f622;color:#60a5fa;border:1px solid #3b82f655;border-radius:3px;font-size:9px;font-weight:700;padding:1px 5px;text-transform:uppercase;">passive</span>`;

  return `
    <div id="pv-row-${safeId}" style="display:flex;align-items:flex-start;gap:10px;padding:8px 4px;
      border-bottom:1px solid #111827;opacity:${enabled?'1':'0.45'};transition:opacity .15s;">

      <!-- Checkbox -->
      <input type="checkbox" class="pv-mod-check" data-id="${_esc(m.id)}"
        ${enabled?'checked':''}
        style="margin-top:3px;cursor:pointer;accent-color:#38bdf8;" />

      <!-- Module info -->
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
          <span style="font-size:12px;font-weight:600;color:#e2e8f0;">${_esc(m.name)}</span>
          ${clazzBadge}
          <span style="font-size:10px;font-weight:700;color:${sevCol};">${m.severityDefault.toUpperCase()}</span>
        </div>
        <div style="font-size:10px;color:#475569;margin-top:2px;font-family:monospace;">${_esc(m.id)}</div>
        <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:4px;">
          ${(m.owasp||[]).map(t=>`<span style="${_tag('#0ea5e9')}">${_esc(t)}</span>`).join('')}
          ${(m.cwe  ||[]).map(t=>`<span style="${_tag('#8b5cf6')}">${_esc(t)}</span>`).join('')}
          ${(m.cveExamples||[]).map(t=>`<span style="${_tag('#ef4444')}">${_esc(t)}</span>`).join('')}
        </div>
      </div>

      <!-- Aggressiveness (active modules only) -->
      ${m.clazz === 'active' ? `
      <div style="min-width:100px;text-align:center;">
        <label style="${_lbl()}text-align:center;">Intensity</label>
        <input type="range" class="pv-aggr" data-id="${_esc(m.id)}"
          min="0" max="2" step="1" value="${aggr}"
          style="width:90px;accent-color:#f97316;cursor:pointer;" />
        <div id="pv-aggr-lbl-${safeId}" style="font-size:10px;color:#f97316;text-align:center;">
          ${_aggrLabel(aggr)}
        </div>
      </div>` : `<div style="min-width:100px;"></div>`}
    </div>`;
}

// ── Save ─────────────────────────────────────────────────────────────────────
async function _handleSave() {
  const p      = _policies[_activeId];
  const stat   = _container.querySelector('#pv-save-status');
  if (!p) return;

  // Collect edited values from DOM
  p.name        = _container.querySelector('#pv-policy-name')?.value?.trim() || p.name;
  p.description = _container.querySelector('#pv-policy-desc')?.value?.trim() || p.description;
  p.limits = {
    maxRequestsPerSecond  : parseInt(_container.querySelector('#pv-rps')?.value, 10) || 3,
    maxParallelTargets    : parseInt(_container.querySelector('#pv-par')?.value, 10) || 2,
    maxScanDurationSeconds: parseInt(_container.querySelector('#pv-dur')?.value, 10) || 1200,
  };

  stat.textContent = 'Saving…';

  // Try backend first
  let savedToBackend = false;
  try {
    const base = _apiBase();
    const res  = await fetch(`${base}/api/policies/${encodeURIComponent(_activeId)}`, {
      method : 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify(p),
    });
    if (res.ok) savedToBackend = true;
  } catch { /* offline */ }

  // Always persist to localStorage as fallback / cache
  try {
    localStorage.setItem('wvc_policies', JSON.stringify(_policies));
  } catch { /* storage full */ }

  _dirty = false;
  stat.textContent = savedToBackend ? '✓ Saved to backend' : '✓ Saved locally (backend offline)';
  stat.style.color  = savedToBackend ? '#22c55e' : '#f97316';
  _toast(savedToBackend ? '✓ Policy saved' : '✓ Saved locally', savedToBackend ? 'ok' : 'warn');
  setTimeout(() => { stat.textContent = ''; }, 4000);
}

// ── Reset to factory ──────────────────────────────────────────────────────────
function _handleReset() {
  if (!confirm(`Reset "${_policies[_activeId]?.name}" to factory defaults?`)) return;
  _policies[_activeId] = JSON.parse(JSON.stringify(FACTORY_DEFAULTS[_activeId] || FACTORY_DEFAULTS.policy_normal));
  _dirty = false;
  _renderEditor();
  _toast('↺ Reset to defaults', 'ok');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function _apiBase() {
  return (window._wvcState?.cfg?.backendUrl)
    || (window.CFG?.backendUrl)
    || localStorage.getItem('wvc_backend_url')
    || 'http://127.0.0.1:8787';
}

function _riskLevel(id) {
  if (id === 'policy_extreme')    return { color: '#ef4444' };
  if (id === 'policy_aggressive') return { color: '#f97316' };
  return { color: '#22c55e' };
}

function _sevColor(sev) {
  const map = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#94a3b8' };
  return map[sev] || '#94a3b8';
}

function _aggrLabel(v) {
  return v === 0 ? 'Off' : v === 1 ? 'Normal' : 'Max';
}

function _toast(msg, type = 'info') {
  if (window._wvcToast) { window._wvcToast(msg, type); return; }
  const t = document.createElement('div');
  t.textContent = msg;
  Object.assign(t.style, {
    position:'fixed', bottom:'20px', right:'20px', zIndex:9999,
    background: type === 'ok' ? '#16a34a' : type === 'warn' ? '#b45309' : '#1e293b',
    color:'#fff', padding:'8px 14px', borderRadius:'6px', fontSize:'12px',
    fontFamily:'monospace', boxShadow:'0 4px 12px rgba(0,0,0,.4)',
  });
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2800);
}

function _esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Style snippets ────────────────────────────────────────────────────────────
function _card() {
  return 'background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;';
}
function _inp() {
  return 'width:100%;background:#020617;border:1px solid #1e293b;border-radius:5px;' +
    'color:#e2e8f0;font-family:monospace;font-size:12px;padding:7px 10px;' +
    'outline:none;box-sizing:border-box;';
}
function _btn(bg, fg) {
  return `background:${bg};color:${fg};border:none;border-radius:5px;` +
    'padding:7px 14px;font-family:monospace;font-size:12px;font-weight:700;' +
    'cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;gap:4px;';
}
function _lbl() {
  return 'display:block;font-size:10px;color:#64748b;text-transform:uppercase;' +
    'letter-spacing:.07em;margin-bottom:3px;';
}
function _tag(color) {
  return `background:${color}22;color:${color};border:1px solid ${color}55;` +
    'border-radius:3px;font-size:9px;padding:1px 5px;font-weight:600;';
}
function _sel() {
  return 'background:#0f172a;border:1px solid #1e293b;border-radius:5px;' +
    'color:#e2e8f0;font-size:11px;padding:5px 8px;outline:none;';
}
