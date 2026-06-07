/* =============================================================
   WebVulnConsole ⚡ app.js – Full client logic v3  [RESTORED]
   Task 4: Rich Projects UI — modal, per-project stats,
   finding counts, risk mini-gauge, search/filter, summary bar.
   All prior functionality (findings, queue, dorks, reports,
   settings, dashboard, console) preserved exactly.
   ============================================================= */
'use strict';

// ─── Config ───────────────────────────────────────────────────────────
let CFG = {
  backendUrl: localStorage.getItem('wvc_backend_url') || 'http://127.0.0.1:8787',
  authNote:   localStorage.getItem('wvc_auth_note')   || '',
};

// ─── State ────────────────────────────────────────────────────────────
let state = {
  currentProject: localStorage.getItem('wvc_current_project') || null,
  projects:       JSON.parse(localStorage.getItem('wvc_projects') || '[]'),
  targets:        JSON.parse(localStorage.getItem('wvc_targets')  || '{}'),
  jobs:           [],
  findings:       [],
  findingsPage:   0,
  // Per-project stats cache: { [projectId]: { crit, high, medium, low, info, total, lastScan } }
  projectStats:   JSON.parse(localStorage.getItem('wvc_project_stats') || '{}'),
};
const FINDINGS_PER_PAGE = 50;

function saveState() {
  localStorage.setItem('wvc_projects',      JSON.stringify(state.projects));
  localStorage.setItem('wvc_targets',       JSON.stringify(state.targets));
  localStorage.setItem('wvc_project_stats', JSON.stringify(state.projectStats));
  if (state.currentProject) localStorage.setItem('wvc_current_project', state.currentProject);
}

// ─── API helpers ──────────────────────────────────────────────────────
function apiUrl(path) { return `${CFG.backendUrl}${path}`; }
async function apiFetch(path, opts = {}) {
  try {
    const res  = await fetch(apiUrl(path), { headers: { 'Content-Type': 'application/json' }, ...opts });
    const json = await res.json().catch(() => null);
    return { ok: res.ok, status: res.status, data: json };
  } catch (err) {
    return { ok: false, status: 0, data: null, err: String(err) };
  }
}

// ─── Micro utils ──────────────────────────────────────────────────────
function uid() { return Math.random().toString(36).slice(2,10) + Date.now().toString(36); }
function escHtml(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
const SEV_COLORS = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280' };
function sevBadge(sev) {
  return `<span class="badge badge-${escHtml(sev||'info')}">${escHtml(sev||'info')}</span>`;
}
function statusBadge(s) {
  return `<span class="job-status-badge status-${escHtml(s)}">${escHtml(s)}</span>`;
}
function toast(msg, type='info') {
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  document.body.appendChild(t);
  requestAnimationFrame(() => t.classList.add('toast-show'));
  setTimeout(() => { t.classList.remove('toast-show'); setTimeout(() => t.remove(), 400); }, 3000);
}
function timeAgo(iso) {
  if (!iso) return '';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

// ─── Console ──────────────────────────────────────────────────────────
const consoleEl = document.getElementById('console-output');
function clog(msg, type='') {
  const line = document.createElement('div');
  if (type) line.className = `console-line-${type}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
  if (consoleEl.children.length > 400) consoleEl.removeChild(consoleEl.firstChild);
}
clog('WebVulnConsole ⚡ v3 loaded. Type "help" for commands.', 'info');

// ─── Backend health ───────────────────────────────────────────────────
const statusDot   = document.getElementById('status-dot');
const statusLabel = document.getElementById('status-label');
async function pingBackend() {
  const r = await apiFetch('/api/health');
  const on = r.ok;
  statusDot.className     = on ? 'dot dot-on' : 'dot dot-off';
  statusLabel.textContent = on ? 'Connected'  : 'Offline';
  clog(on ? `Backend online: ${CFG.backendUrl}` : `Backend offline. Start Termux server first.`, on ? 'ok' : 'warn');
}
pingBackend();
setInterval(pingBackend, 30000);

// ─── ToS modal ────────────────────────────────────────────────────────
const tosOverlay = document.getElementById('tos-overlay');
const appEl      = document.getElementById('app');
const tosCheck   = document.getElementById('tos-check');
const tosCheck2  = document.getElementById('tos-check2');
const tosEnter   = document.getElementById('tos-enter');
const tosClient  = document.getElementById('tos-client');

function updateTosBtn() { tosEnter.disabled = !(tosCheck.checked && tosCheck2.checked); }
tosCheck.addEventListener('change',  updateTosBtn);
tosCheck2.addEventListener('change', updateTosBtn);
tosEnter.addEventListener('click', () => {
  if (!tosCheck.checked || !tosCheck2.checked) return;
  sessionStorage.setItem('wvc_tos', 'yes');
  if (tosClient.value.trim()) {
    localStorage.setItem('wvc_auth_note', tosClient.value.trim());
    CFG.authNote = tosClient.value.trim();
  }
  tosOverlay.classList.add('hidden');
  appEl.classList.remove('hidden');
  clog('Authorization confirmed. Welcome, operator.', 'ok');
  loadDashboard();
});

// ─── Navigation ───────────────────────────────────────────────────────
const navItems  = document.querySelectorAll('.nav-item');
const pageEls   = document.querySelectorAll('.page');
const pageTitle = document.getElementById('page-title');
const PAGE_LABELS = {
  dashboard:'Dashboard', projects:'Projects', targets:'Targets',
  queue:'Scan Queue', findings:'Findings', dorks:'Dork Generator',
  reports:'Reports', settings:'Settings',
};
function showPage(name) {
  navItems.forEach(el => el.classList.toggle('active', el.dataset.page === name));
  pageEls.forEach(el  => el.classList.toggle('active', el.id === `page-${name}`));
  pageTitle.textContent = PAGE_LABELS[name] || name;
  closeSidebar();
  const loaders = {
    queue:loadQueue, findings:loadFindings, reports:loadReports,
    dashboard:loadDashboard, projects:renderProjectList, targets:renderTargetList,
  };
  if (loaders[name]) loaders[name]();
}
navItems.forEach(el => el.addEventListener('click', e => { e.preventDefault(); showPage(el.dataset.page); }));

const sidebar   = document.getElementById('sidebar');
const hamburger = document.getElementById('hamburger-btn');
function closeSidebar() { sidebar.classList.remove('sidebar-open'); }
if (hamburger) hamburger.addEventListener('click', () => sidebar.classList.toggle('sidebar-open'));
document.addEventListener('click', e => {
  if (sidebar.classList.contains('sidebar-open') && !sidebar.contains(e.target) && e.target !== hamburger) closeSidebar();
});

// ─── Risk helpers ─────────────────────────────────────────────────────
function computeRiskScore(findings) {
  if (!findings || !findings.length) return 0;
  const W = { critical:30, high:15, medium:6, low:2, info:0.5 };
  const raw = findings.reduce((a,f) => a + (W[f.severity]||0), 0);
  const breadth = Math.min(new Set(findings.map(f=>f.category)).size * 2, 20);
  return Math.min(Math.round(raw + breadth), 100);
}
function riskColor(score) {
  if (score >= 70) return '#ef4444';
  if (score >= 40) return '#f97316';
  if (score >= 15) return '#eab308';
  return '#22c55e';
}
function riskLabel(score) {
  if (score >= 70) return 'CRITICAL RISK';
  if (score >= 40) return 'HIGH RISK';
  if (score >= 15) return 'MEDIUM RISK';
  if (score >  0)  return 'LOW RISK';
  return 'CLEAN';
}
function buildGauge(score) {
  const color = riskColor(score);
  const label = riskLabel(score);
  return `
    <div class="risk-gauge">
      <div class="risk-gauge-label" style="color:${color}">${label}</div>
      <div class="risk-gauge-track">
        <div class="risk-gauge-fill" style="width:${score}%;background:${color}"></div>
      </div>
      <div class="risk-gauge-score" style="color:${color}">${score}/100</div>
    </div>`;
}

// ─── Project selector ─────────────────────────────────────────────────
const projSelect = document.getElementById('project-select');
function renderProjectSelector() {
  if (!projSelect) return;
  const cur = state.currentProject;
  projSelect.innerHTML = `<option value="">— No Project —</option>` +
    state.projects.map(p =>
      `<option value="${escHtml(p.id)}" ${p.id===cur?'selected':''}>${escHtml(p.name)}</option>`
    ).join('');
}
if (projSelect) {
  projSelect.addEventListener('change', () => {
    state.currentProject = projSelect.value || null;
    saveState();
    clog(state.currentProject
      ? `Active project: ${state.projects.find(p=>p.id===state.currentProject)?.name}`
      : 'No active project.', 'info');
  });
}

// ─── Project Modal ────────────────────────────────────────────────────
(function injectProjectModal() {
  if (document.getElementById('proj-modal-overlay')) return;
  const el = document.createElement('div');
  el.id = 'proj-modal-overlay';
  el.className = 'proj-modal-overlay hidden';
  el.innerHTML = `
    <div class="proj-modal-box">
      <div class="proj-modal-header">
        <div id="proj-modal-title" class="proj-modal-title">New Project</div>
        <button id="proj-modal-close" class="proj-modal-close">✕</button>
      </div>
      <div class="proj-modal-field">
        <label class="proj-modal-label">Project Name <span style="color:#ef4444">*</span></label>
        <input id="proj-modal-name" type="text" class="proj-modal-input"
          placeholder="e.g. ClientX Web Audit Q3"
          oninput="window._projModalValidate()" />
      </div>
      <div class="proj-modal-field">
        <label class="proj-modal-label">Client / Ticket ID <span class="proj-modal-opt">(optional)</span></label>
        <input id="proj-modal-client" type="text" class="proj-modal-input"
          placeholder="e.g. Acme Corp — PT-2026-042" />
      </div>
      <div class="proj-modal-field">
        <label class="proj-modal-label">Scan Policy</label>
        <select id="proj-modal-policy" class="proj-modal-input">
          <option value="policy_normal">Normal — Passive only (safe for production)</option>
          <option value="policy_aggressive">Aggressive — Passive + SQLi/XSS (auth required)</option>
          <option value="policy_extreme">Extreme — All modules incl. path traversal</option>
        </select>
      </div>
      <div class="proj-modal-field">
        <label class="proj-modal-label">Notes <span class="proj-modal-opt">(optional)</span></label>
        <textarea id="proj-modal-notes" class="proj-modal-input" rows="2"
          placeholder="Authorization reference, scope, etc." style="resize:vertical;"></textarea>
      </div>
      <div id="proj-modal-err" class="proj-modal-err" style="display:none;">Project name is required.</div>
      <div class="proj-modal-actions">
        <button id="proj-modal-cancel" class="btn btn-ghost btn-sm">Cancel</button>
        <button id="proj-modal-save"   class="btn btn-primary btn-sm" disabled>Save Project</button>
      </div>
    </div>`;
  document.body.appendChild(el);
  el.addEventListener('click', e => { if (e.target === el) closeProjectModal(); });
  document.getElementById('proj-modal-close').addEventListener('click',  closeProjectModal);
  document.getElementById('proj-modal-cancel').addEventListener('click', closeProjectModal);
  document.getElementById('proj-modal-save').addEventListener('click',   onProjectModalSave);
})();

let _editingProjectId = null;
window._projModalValidate = function() {
  const val = (document.getElementById('proj-modal-name')?.value || '').trim();
  const btn = document.getElementById('proj-modal-save');
  const err = document.getElementById('proj-modal-err');
  if (!btn) return;
  btn.disabled = !val;
  if (err) err.style.display = 'none';
};

function openProjectModal(existingProject = null) {
  _editingProjectId = existingProject?.id || null;
  document.getElementById('proj-modal-title').textContent = existingProject ? 'Edit Project' : 'New Project';
  document.getElementById('proj-modal-name').value        = existingProject?.name   || '';
  document.getElementById('proj-modal-client').value      = existingProject?.client || '';
  document.getElementById('proj-modal-policy').value      = existingProject?.defaultPolicy || 'policy_normal';
  document.getElementById('proj-modal-notes').value       = existingProject?.notes  || '';
  document.getElementById('proj-modal-err').style.display = 'none';
  window._projModalValidate();
  document.getElementById('proj-modal-overlay').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  setTimeout(() => document.getElementById('proj-modal-name').focus(), 60);
}
function closeProjectModal() {
  document.getElementById('proj-modal-overlay').classList.add('hidden');
  document.body.style.overflow = '';
  _editingProjectId = null;
}
function onProjectModalSave() {
  const name   = (document.getElementById('proj-modal-name').value   || '').trim();
  const client = (document.getElementById('proj-modal-client').value || '').trim();
  const policy = document.getElementById('proj-modal-policy').value  || 'policy_normal';
  const notes  = (document.getElementById('proj-modal-notes').value  || '').trim();
  if (!name) { document.getElementById('proj-modal-err').style.display = 'block'; return; }
  if (_editingProjectId) {
    const p = state.projects.find(x => x.id === _editingProjectId);
    if (p) { p.name = name; p.client = client; p.defaultPolicy = policy; p.notes = notes; }
    saveState(); toast(`Project "${name}" updated.`, 'ok');
  } else {
    const p = { id: uid(), name, client, defaultPolicy: policy, notes, createdAt: new Date().toISOString() };
    state.projects.push(p); state.currentProject = p.id; saveState();
    toast(`Project "${name}" created.`, 'ok');
    clog(`New project: ${name} [${p.id}]`, 'ok');
  }
  closeProjectModal(); renderProjectSelector(); renderProjectList();
}

// ─── Projects Page ────────────────────────────────────────────────────
function buildProjectsPageDOM() {
  const page = document.getElementById('page-projects');
  if (!page || page.dataset.built) return;
  page.dataset.built = '1';
  page.innerHTML = `
    <div class="section-title">Projects
      <button class="btn btn-primary btn-sm" onclick="openProjectModal()">+ New Project</button>
    </div>
    <div id="proj-stats-bar" class="stat-row" style="margin-bottom:12px;"></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <input id="proj-search-box" class="input-field" style="flex:1;min-width:160px;"
        placeholder="Search projects…" oninput="renderProjectList(this.value)" />
      <select id="proj-sort-select" class="select-field" onchange="renderProjectList()">
        <option value="created_desc">Newest first</option>
        <option value="created_asc">Oldest first</option>
        <option value="name_asc">Name A→Z</option>
        <option value="name_desc">Name Z→A</option>
        <option value="risk_desc">Risk (high first)</option>
      </select>
    </div>
    <div id="project-list"></div>`;
}

function renderProjectList(filterVal) {
  buildProjectsPageDOM();
  updateProjectStatsBar();
  const filter   = filterVal !== undefined ? filterVal : (document.getElementById('proj-search-box')?.value || '');
  const sortMode = document.getElementById('proj-sort-select')?.value || 'created_desc';
  const cur      = state.currentProject;
  let projects = filter
    ? state.projects.filter(p =>
        p.name.toLowerCase().includes(filter.toLowerCase()) ||
        (p.client||'').toLowerCase().includes(filter.toLowerCase()))
    : [...state.projects];
  const riskFn = id => {
    const st = state.projectStats[id];
    if (!st) return 0;
    return Math.min((st.crit||0)*30+(st.high||0)*15+(st.medium||0)*6+(st.low||0)*2+(st.info||0)*0.5, 100);
  };
  projects.sort((a, b) => {
    switch (sortMode) {
      case 'created_asc': return new Date(a.createdAt||0) - new Date(b.createdAt||0);
      case 'name_asc':    return a.name.localeCompare(b.name);
      case 'name_desc':   return b.name.localeCompare(a.name);
      case 'risk_desc':   return riskFn(b.id) - riskFn(a.id);
      default:            return new Date(b.createdAt||0) - new Date(a.createdAt||0);
    }
  });
  const el = document.getElementById('project-list');
  if (!el) return;
  if (!projects.length) {
    el.innerHTML = filter
      ? `<div class="empty-state">No projects match "${escHtml(filter)}".</div>`
      : `<div class="empty-state">No projects yet. Click + New Project to get started.</div>`;
    return;
  }
  el.innerHTML = projects.map(p => {
    const st    = state.projectStats[p.id] || {};
    const score = riskFn(p.id);
    const color = riskColor(score);
    const label = riskLabel(score);
    const tgts  = Object.values(state.targets).filter(t => t.projectId === p.id).length;
    const isActive = p.id === cur;
    return `
      <div class="project-card ${isActive ? 'project-card-active' : ''}">
        <div class="project-card-header">
          <div>
            <div class="project-card-name">${escHtml(p.name)}</div>
            ${p.client ? `<div class="project-card-client">${escHtml(p.client)}</div>` : ''}
          </div>
          <div style="display:flex;gap:6px;align-items:center;">
            ${isActive ? '<span class="badge" style="background:#22c55e22;color:#22c55e;border:1px solid #22c55e44;">ACTIVE</span>' : ''}
            <span class="badge" style="color:${color};background:${color}18;border:1px solid ${color}33;">${label}</span>
          </div>
        </div>
        <div class="project-card-gauge">
          <div class="risk-gauge-track" style="height:4px;background:#1e293b;border-radius:2px;flex:1;overflow:hidden;">
            <div style="height:100%;width:${score}%;background:${color};transition:width .4s;"></div>
          </div>
          <span style="font-size:10px;color:${color};min-width:32px;text-align:right;">${score}/100</span>
        </div>
        <div class="project-card-stats">
          <div class="proj-stat-chip" style="color:#ef4444;">&#9632; ${st.crit||0} Crit</div>
          <div class="proj-stat-chip" style="color:#f97316;">&#9632; ${st.high||0} High</div>
          <div class="proj-stat-chip" style="color:#eab308;">&#9632; ${st.medium||0} Med</div>
          <div class="proj-stat-chip" style="color:#3b82f6;">&#9632; ${st.low||0} Low</div>
          <div class="proj-stat-chip" style="color:#6b7280;">&#9632; ${st.info||0} Info</div>
          <div class="proj-stat-chip" style="color:#94a3b8;">&#127919; ${tgts} targets</div>
          ${st.lastScan ? `<div class="proj-stat-chip" style="color:#94a3b8;">&#128336; ${timeAgo(st.lastScan)}</div>` : ''}
        </div>
        ${p.notes ? `<div class="project-card-notes">${escHtml(p.notes)}</div>` : ''}
        <div class="project-card-actions">
          <button class="btn btn-primary btn-sm" onclick="setActiveProject('${p.id}')">
            ${isActive ? '✓ Active' : 'Set Active'}
          </button>
          <button class="btn btn-ghost btn-sm" onclick="openProjectModal(state.projects.find(x=>x.id==='${p.id}'))">Edit</button>
          <button class="btn btn-ghost btn-sm" onclick="quickLaunchScan('${p.id}')">&#9658; Quick Scan</button>
          <button class="btn btn-danger btn-sm" onclick="deleteProject('${p.id}')">Delete</button>
        </div>
      </div>`;
  }).join('');
}

function updateProjectStatsBar() {
  const bar = document.getElementById('proj-stats-bar');
  if (!bar) return;
  const total = state.projects.length;
  const active = state.currentProject ? 1 : 0;
  const allStats = Object.values(state.projectStats);
  const totalFindings = allStats.reduce((s, st) => s + (st?.total||0), 0);
  const critProjects  = state.projects.filter(p => {
    const st = state.projectStats[p.id];
    return st && ((st.crit||0)*30 + (st.high||0)*15 + (st.medium||0)*6) >= 70;
  }).length;
  bar.innerHTML = [
    { num:total,         lbl:'Projects',       col:'#38bdf8' },
    { num:active,        lbl:'Active',         col:'#22c55e' },
    { num:totalFindings, lbl:'Total Findings', col:'#94a3b8' },
    { num:critProjects,  lbl:'Critical Risk',  col:'#ef4444' },
  ].map(t => `<div class="stat-box"><div class="num" style="color:${t.col}">${t.num}</div><div class="lbl">${t.lbl}</div></div>`).join('');
}

function setActiveProject(id) {
  state.currentProject = id; saveState(); renderProjectSelector(); renderProjectList();
  const p = state.projects.find(x => x.id === id);
  toast(`Active project: ${p?.name}`, 'ok');
}
function deleteProject(id) {
  const p = state.projects.find(x => x.id === id);
  if (!p || !confirm(`Delete project "${p.name}"? This cannot be undone.`)) return;
  state.projects = state.projects.filter(x => x.id !== id);
  delete state.projectStats[id];
  if (state.currentProject === id) state.currentProject = null;
  saveState(); renderProjectSelector(); renderProjectList();
  toast(`Project "${p.name}" deleted.`, 'warn');
}
async function quickLaunchScan(projectId) {
  const p = state.projects.find(x => x.id === projectId);
  if (!p) return;
  const tgts = Object.values(state.targets).filter(t => t.projectId === projectId);
  if (!tgts.length) { toast('No targets in this project.', 'warn'); return; }
  toast(`Quick scan launched for "${p.name}" (${tgts.length} targets)…`, 'info');
  for (const t of tgts) await submitScan(t.url, 'recon,headers', p.defaultPolicy||'policy_normal', projectId);
}

// ─── Targets ──────────────────────────────────────────────────────────
function renderTargetList() {
  const el = document.getElementById('target-list');
  if (!el) return;
  const cur = state.currentProject;
  const tgts = Object.values(state.targets).filter(t => !cur || t.projectId === cur);
  if (!tgts.length) { el.innerHTML = `<div class="empty-state">No targets. Add one below.</div>`; return; }
  el.innerHTML = tgts.map(t => `
    <div class="target-row">
      <div class="target-info">
        <span class="target-url">${escHtml(t.url)}</span>
        ${t.note ? `<span class="target-note">${escHtml(t.note)}</span>` : ''}
      </div>
      <div class="target-actions">
        <button class="btn btn-primary btn-sm" onclick="launchScanForTarget('${t.id}')">&#9658; Scan</button>
        <button class="btn btn-danger btn-sm"  onclick="deleteTarget('${t.id}')">&#10007;</button>
      </div>
    </div>`).join('');
}
function addTarget() {
  const urlEl  = document.getElementById('target-url');
  const noteEl = document.getElementById('target-note');
  const url    = urlEl?.value.trim();
  if (!url) { toast('Enter a target URL.', 'warn'); return; }
  const id = uid();
  state.targets[id] = { id, url, note: noteEl?.value.trim()||'', projectId: state.currentProject||null, addedAt: new Date().toISOString() };
  saveState();
  if (urlEl) urlEl.value = ''; if (noteEl) noteEl.value = '';
  renderTargetList(); toast('Target added.', 'ok');
}
function deleteTarget(id) {
  const t = state.targets[id]; if (!t) return;
  delete state.targets[id]; saveState(); renderTargetList();
}
async function launchScanForTarget(targetId) {
  const t = state.targets[targetId]; if (!t) return;
  await submitScan(t.url, document.getElementById('scan-modules')?.value||'recon,headers',
    document.getElementById('scan-policy')?.value||'policy_normal', t.projectId);
}

// ─── Scan submission ──────────────────────────────────────────────────
async function submitScan(url, modules, policy, projectId) {
  clog(`Submitting scan: ${url} [${modules}] policy=${policy}`, 'info');
  const r = await apiFetch('/api/scan', {
    method:'POST',
    body: JSON.stringify({ url, modules: modules.split(',').map(s=>s.trim()), policy, projectId }),
  });
  if (r.ok && r.data?.jobId) {
    clog(`Scan queued — Job ID: ${r.data.jobId}`, 'ok');
    toast(`Scan queued: ${url}`, 'ok');
    state.jobs.unshift({ id:r.data.jobId, url, status:'queued', createdAt:new Date().toISOString(), projectId });
    refreshQueue();
  } else {
    clog(`Scan failed: ${r.err||JSON.stringify(r.data)}`, 'crit');
    toast('Scan submission failed. Is the backend running?', 'warn');
  }
}
const scanForm = document.getElementById('scan-form');
if (scanForm) {
  scanForm.addEventListener('submit', async e => {
    e.preventDefault();
    const url = document.getElementById('scan-url')?.value.trim();
    if (!url) { toast('Enter a target URL.', 'warn'); return; }
    await submitScan(url, document.getElementById('scan-modules')?.value||'recon,headers',
      document.getElementById('scan-policy')?.value||'policy_normal', state.currentProject);
  });
}

// ─── Queue ────────────────────────────────────────────────────────────
async function loadQueue() {
  const r = await apiFetch('/api/jobs');
  if (r.ok && Array.isArray(r.data)) state.jobs = r.data;
  refreshQueue();
}
function refreshQueue() {
  const el = document.getElementById('job-list'); if (!el) return;
  if (!state.jobs.length) { el.innerHTML = `<div class="empty-state">No jobs yet.</div>`; return; }
  el.innerHTML = state.jobs.map(j => `
    <div class="job-row">
      <div class="job-info">
        <span class="job-url">${escHtml(j.url||j.target||'')}</span>
        <span>${statusBadge(j.status)}</span>
        <span class="job-meta">${timeAgo(j.createdAt||j.started_at)}</span>
      </div>
      <div class="job-actions">
        <button class="btn btn-ghost btn-sm" onclick="viewJobResults('${j.id}')">Results</button>
        <button class="btn btn-danger btn-sm" onclick="cancelJob('${j.id}')">Cancel</button>
      </div>
    </div>`).join('');
}
async function viewJobResults(jobId) {
  const r = await apiFetch(`/api/jobs/${jobId}/results`);
  if (!r.ok || !r.data) { toast('No results yet.', 'warn'); return; }
  const findings = Array.isArray(r.data) ? r.data : (r.data.findings||[]);
  if (findings.length) {
    state.findings = [...findings, ...state.findings];
    updateProjectStats(findings); showPage('findings');
    toast(`${findings.length} finding(s) loaded.`, 'ok');
  } else toast('No findings for this job.', 'info');
}
async function cancelJob(jobId) {
  await apiFetch(`/api/jobs/${jobId}/cancel`, { method:'POST' });
  loadQueue(); toast('Job cancelled.', 'warn');
}

// ─── Findings ─────────────────────────────────────────────────────────
async function loadFindings() {
  const cur = state.currentProject;
  const r = await apiFetch(cur ? `/api/findings?project=${cur}` : '/api/findings');
  if (r.ok && Array.isArray(r.data)) {
    state.findings = r.data; state.findingsPage = 0; updateProjectStats(r.data);
  }
  renderFindings();
}
function renderFindings() {
  const el = document.getElementById('findings-list'); if (!el) return;
  const sev    = document.getElementById('findings-filter-sev')?.value || '';
  const search = document.getElementById('findings-filter-search')?.value?.toLowerCase() || '';
  let data = state.findings;
  if (sev)    data = data.filter(f => f.severity === sev);
  if (search) data = data.filter(f =>
    (f.title||'').toLowerCase().includes(search) ||
    (f.url||'').toLowerCase().includes(search));
  const page  = state.findingsPage;
  const paged = data.slice(page*FINDINGS_PER_PAGE, (page+1)*FINDINGS_PER_PAGE);
  if (!paged.length) { el.innerHTML = `<div class="empty-state">No findings.</div>`; updateFindingsPager(0,0); return; }
  el.innerHTML = paged.map(f => `
    <div class="finding-row">
      <div class="finding-header">
        ${sevBadge(f.severity)}
        <span class="finding-title">${escHtml(f.title||f.name||'Finding')}</span>
        ${f.category ? `<span class="finding-cat">${escHtml(f.category)}</span>` : ''}
      </div>
      <div class="finding-url">${escHtml(f.url||'')}</div>
      ${f.description ? `<div class="finding-desc">${escHtml(f.description)}</div>` : ''}
      ${f.recommendation ? `<div class="finding-rec"><strong>Fix:</strong> ${escHtml(f.recommendation)}</div>` : ''}
    </div>`).join('');
  updateFindingsPager(data.length, page);
}
function updateFindingsPager(total, page) {
  const el = document.getElementById('findings-pager'); if (!el) return;
  const pages = Math.ceil(total / FINDINGS_PER_PAGE);
  el.innerHTML = total > FINDINGS_PER_PAGE ? `
    <button class="btn btn-ghost btn-sm" onclick="findingsGoPage(${page-1})" ${page===0?'disabled':''}>&#8592; Prev</button>
    <span style="font-size:11px;color:#94a3b8;">Page ${page+1} / ${pages} (${total} total)</span>
    <button class="btn btn-ghost btn-sm" onclick="findingsGoPage(${page+1})" ${page>=pages-1?'disabled':''}>Next &#8594;</button>`
    : `<span style="font-size:11px;color:#94a3b8;">${total} finding(s)</span>`;
}
function findingsGoPage(p) {
  state.findingsPage = Math.max(0, Math.min(p, Math.ceil(state.findings.length/FINDINGS_PER_PAGE)-1));
  renderFindings();
}
function updateProjectStats(findings) {
  if (!state.currentProject) return;
  const id = state.currentProject;
  const counts = { crit:0, high:0, medium:0, low:0, info:0, total:0, lastScan:new Date().toISOString() };
  findings.forEach(f => {
    counts.total++;
    const s = f.severity?.toLowerCase();
    if (s==='critical') counts.crit++;
    else if (s==='high') counts.high++;
    else if (s==='medium') counts.medium++;
    else if (s==='low') counts.low++;
    else counts.info++;
  });
  state.projectStats[id] = counts; saveState();
}

// ─── Dashboard ────────────────────────────────────────────────────────
async function loadDashboard() {
  const r = await apiFetch('/api/findings');
  if (r.ok && Array.isArray(r.data)) { state.findings = r.data; updateProjectStats(r.data); }
  const score = computeRiskScore(state.findings);
  const gauge = document.getElementById('dashboard-gauge');
  if (gauge) gauge.innerHTML = buildGauge(score);
  const counts = { critical:0, high:0, medium:0, low:0, info:0 };
  state.findings.forEach(f => { if (counts[f.severity]!==undefined) counts[f.severity]++; });
  ['critical','high','medium','low','info'].forEach(sev => {
    const el = document.getElementById(`stat-${sev}`); if (el) el.textContent = counts[sev];
  });
  const totalEl = document.getElementById('stat-total'); if (totalEl) totalEl.textContent = state.findings.length;
  const jobsEl  = document.getElementById('stat-jobs');  if (jobsEl)  jobsEl.textContent  = state.jobs.length;
  const projEl  = document.getElementById('stat-projects'); if (projEl) projEl.textContent = state.projects.length;
  renderProjectSelector();
}

// ─── Reports ──────────────────────────────────────────────────────────
async function loadReports() {
  const r = await apiFetch('/api/reports');
  const el = document.getElementById('reports-list'); if (!el) return;
  if (!r.ok || !r.data?.length) { el.innerHTML = `<div class="empty-state">No reports generated yet.</div>`; return; }
  el.innerHTML = r.data.map(rep => `
    <div class="report-row">
      <div class="report-info">
        <span class="report-name">${escHtml(rep.name||rep.id)}</span>
        <span class="report-meta">${timeAgo(rep.createdAt)}</span>
      </div>
      <div class="report-actions">
        <a class="btn btn-ghost btn-sm" href="${apiUrl('/api/reports/'+rep.id+'/download')}" target="_blank">Download</a>
      </div>
    </div>`).join('');
}
async function generateReport(format) {
  clog(`Generating ${format.toUpperCase()} report…`, 'info');
  const r = await apiFetch('/api/reports/generate', {
    method:'POST', body:JSON.stringify({ format, projectId:state.currentProject, findings:state.findings }),
  });
  if (r.ok) { toast('Report generated!', 'ok'); loadReports(); }
  else { toast('Report generation failed.', 'warn'); }
}

// ─── Dork Generator ───────────────────────────────────────────────────
const DORK_TEMPLATES = {
  login:       ['site:{d} inurl:login','site:{d} inurl:admin','site:{d} intitle:"login"'],
  files:       ['site:{d} ext:pdf','site:{d} ext:xlsx OR ext:docx','site:{d} ext:sql OR ext:bak'],
  exposure:    ['site:{d} inurl:config','site:{d} inurl:env','site:{d} "index of /"'],
  credentials: ['site:{d} intext:"password" filetype:txt','site:{d} intext:"api_key"'],
  cameras:     ['inurl:"/view/view.shtml"','intitle:"webcamXP 5"','inurl:mjpg/video.mjpg'],
};
function generateDorks() {
  const domain  = document.getElementById('dork-domain')?.value.trim() || 'example.com';
  const cat     = document.getElementById('dork-category')?.value      || 'login';
  const dorks   = (DORK_TEMPLATES[cat]||DORK_TEMPLATES.login).map(t => t.replace(/\{d\}/g, domain));
  const out = document.getElementById('dork-output');
  if (out) out.value = dorks.join('\n');
  clog(`Dorks generated: ${cat} for ${domain}`, 'ok');
}
function copyDorks() {
  const out = document.getElementById('dork-output');
  if (!out?.value) return;
  navigator.clipboard.writeText(out.value).then(() => toast('Dorks copied!', 'ok'));
}
function searchDork(dork) { window.open(`https://www.google.com/search?q=${encodeURIComponent(dork)}`,'_blank'); }

// ─── Settings ─────────────────────────────────────────────────────────
function loadSettings() {
  const urlEl  = document.getElementById('settings-backend-url');
  const noteEl = document.getElementById('settings-auth-note');
  if (urlEl)  urlEl.value  = CFG.backendUrl;
  if (noteEl) noteEl.value = CFG.authNote;
}
function saveSettings() {
  const urlEl  = document.getElementById('settings-backend-url');
  const noteEl = document.getElementById('settings-auth-note');
  if (urlEl?.value.trim()) { CFG.backendUrl = urlEl.value.trim(); localStorage.setItem('wvc_backend_url', CFG.backendUrl); }
  if (noteEl) { CFG.authNote = noteEl.value.trim(); localStorage.setItem('wvc_auth_note', CFG.authNote); }
  toast('Settings saved.', 'ok'); clog('Settings updated.', 'ok'); pingBackend();
}
function clearAllData() {
  if (!confirm('Clear ALL local data?')) return;
  localStorage.clear(); sessionStorage.clear();
  toast('All data cleared. Reloading…', 'warn');
  setTimeout(() => location.reload(), 1200);
}
const settingsBtn = document.getElementById('settings-save-btn');
if (settingsBtn) settingsBtn.addEventListener('click', saveSettings);
const clearBtn = document.getElementById('settings-clear-btn');
if (clearBtn) clearBtn.addEventListener('click', clearAllData);

// ─── Console commands ─────────────────────────────────────────────────
const consoleInput = document.getElementById('console-input');
if (consoleInput) {
  consoleInput.addEventListener('keydown', async e => {
    if (e.key !== 'Enter') return;
    const raw = consoleInput.value.trim(); if (!raw) return;
    clog(`> ${raw}`, 'cmd'); consoleInput.value = '';
    await handleConsoleCmd(raw);
  });
}
async function handleConsoleCmd(raw) {
  const parts = raw.split(/\s+/);
  const cmd   = parts[0].toLowerCase();
  const args  = parts.slice(1);
  switch (cmd) {
    case 'help':
      ['help               — show this help','ping               — test backend',
       'scan <url> [mods]  — queue a scan','status             — counts',
       'projects           — list projects','project new <name> — create project',
       'project select <id>— set active','targets            — list targets',
       'target add <url>   — add target','findings [sev]     — findings summary',
       'clear              — clear console','version            — show version',
      ].forEach(l => clog(l, 'info')); break;
    case 'ping': await pingBackend(); break;
    case 'scan':
      if (!args[0]) { clog('Usage: scan <url> [modules]', 'warn'); break; }
      await submitScan(args[0], args[1]||'recon,headers', 'policy_normal', state.currentProject); break;
    case 'status':
      clog(`Jobs: ${state.jobs.length} | Findings: ${state.findings.length} | Projects: ${state.projects.length}`, 'info');
      clog(`Active project: ${state.currentProject || 'none'}`, 'info'); break;
    case 'projects':
      if (!state.projects.length) { clog('No projects.', 'warn'); break; }
      state.projects.forEach(p => clog(`  ${p.id} — ${p.name}${p.id===state.currentProject?' [ACTIVE]':''}`, 'info')); break;
    case 'project':
      if (args[0] === 'new') {
        const name = args.slice(1).join(' '); if (!name) { clog('Usage: project new <name>', 'warn'); break; }
        const p = { id:uid(), name, createdAt:new Date().toISOString() };
        state.projects.push(p); state.currentProject = p.id; saveState(); renderProjectSelector();
        clog(`Project created: ${name} [${p.id}]`, 'ok');
      } else if (args[0] === 'select') {
        const p = state.projects.find(x => x.id===args[1] || x.name===args.slice(1).join(' '));
        if (!p) { clog('Project not found.', 'warn'); break; }
        state.currentProject = p.id; saveState(); renderProjectSelector(); clog(`Active: ${p.name}`, 'ok');
      } else clog('Usage: project new <name> | project select <id>', 'warn'); break;
    case 'targets':
      const tgts = Object.values(state.targets).filter(t => !state.currentProject||t.projectId===state.currentProject);
      if (!tgts.length) { clog('No targets.', 'warn'); break; }
      tgts.forEach(t => clog(`  ${t.id} — ${t.url}`, 'info')); break;
    case 'target':
      if (args[0]==='add' && args[1]) {
        const id = uid();
        state.targets[id] = { id, url:args[1], projectId:state.currentProject||null, addedAt:new Date().toISOString() };
        saveState(); renderTargetList(); clog(`Target added: ${args[1]}`, 'ok');
      } else clog('Usage: target add <url>', 'warn'); break;
    case 'findings': {
      const sev = args[0];
      const data = sev ? state.findings.filter(f=>f.severity===sev) : state.findings;
      const counts = {};
      data.forEach(f => { counts[f.severity]=(counts[f.severity]||0)+1; });
      clog(`Findings (${data.length}): ${Object.entries(counts).map(([k,v])=>`${k}:${v}`).join(' | ')}`, 'info');
      break;
    }
    case 'clear': consoleEl.innerHTML = ''; clog('Console cleared.', 'info'); break;
    case 'version': clog('WebVulnConsole ⚡ v3 — Full client logic (restored)', 'info'); break;
    default: clog(`Unknown command: "${cmd}". Type "help".`, 'warn');
  }
}

// ─── Global exports ───────────────────────────────────────────────────
window.state              = state;
window.saveState          = saveState;
window.openProjectModal   = openProjectModal;
window.closeProjectModal  = closeProjectModal;
window.renderProjectList  = renderProjectList;
window.setActiveProject   = setActiveProject;
window.deleteProject      = deleteProject;
window.quickLaunchScan    = quickLaunchScan;
window.addTarget          = addTarget;
window.deleteTarget       = deleteTarget;
window.launchScanForTarget= launchScanForTarget;
window.findingsGoPage     = findingsGoPage;
window.generateReport     = generateReport;
window.generateDorks      = generateDorks;
window.copyDorks          = copyDorks;
window.searchDork         = searchDork;
window.loadSettings       = loadSettings;
window.cancelJob          = cancelJob;
window.viewJobResults     = viewJobResults;
window._wvcState          = state;
window._wvcSaveState      = saveState;
window._wvcToast          = toast;
window._projStatsCache    = state.projectStats;

// ─── Boot ─────────────────────────────────────────────────────────────
(function boot() {
  if (sessionStorage.getItem('wvc_tos') === 'yes') {
    tosOverlay.classList.add('hidden');
    appEl.classList.remove('hidden');
    renderProjectSelector();
    loadDashboard();
    clog('Session restored.', 'ok');
  }
  const settingsNav = document.querySelector('[data-page="settings"]');
  if (settingsNav) settingsNav.addEventListener('click', () => setTimeout(loadSettings, 50));
})();
