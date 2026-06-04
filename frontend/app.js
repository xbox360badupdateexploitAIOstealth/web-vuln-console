/* =========================================================
   WebVulnConsole ⚡ app.js
   Full client-side logic. Communicates with Node backend.
   ========================================================= */

'use strict';

// ─── Config ──────────────────────────────────────────────────────────────────
let CFG = {
  backendUrl: localStorage.getItem('wvc_backend_url') || 'http://127.0.0.1:8787',
  authNote:   localStorage.getItem('wvc_auth_note')   || '',
};

// ─── State ───────────────────────────────────────────────────────────────────
let state = {
  currentProject: localStorage.getItem('wvc_current_project') || null,
  projects: JSON.parse(localStorage.getItem('wvc_projects') || '[]'),
  targets:  JSON.parse(localStorage.getItem('wvc_targets')  || '{}'),
  jobs:     [],
  findings: [],
};

function saveState() {
  localStorage.setItem('wvc_projects', JSON.stringify(state.projects));
  localStorage.setItem('wvc_targets',  JSON.stringify(state.targets));
  if (state.currentProject) localStorage.setItem('wvc_current_project', state.currentProject);
}

// ─── Utils ───────────────────────────────────────────────────────────────────
function apiUrl(path) { return `${CFG.backendUrl}${path}`; }

async function apiFetch(path, opts = {}) {
  try {
    const res = await fetch(apiUrl(path), {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
    });
    const json = await res.json().catch(() => null);
    return { ok: res.ok, status: res.status, data: json };
  } catch (err) {
    return { ok: false, status: 0, data: null, err: String(err) };
  }
}

function uid() { return Math.random().toString(36).slice(2, 10) + Date.now().toString(36); }

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function sevBadge(sev) {
  return `<span class="badge badge-${escHtml(sev||'info')}">${escHtml(sev||'info')}</span>`;
}

function statusBadge(s) {
  return `<span class="job-status-badge status-${escHtml(s)}">${escHtml(s)}</span>`;
}

function toast(msg, type = 'info') {
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  document.body.appendChild(t);
  requestAnimationFrame(() => t.classList.add('toast-show'));
  setTimeout(() => { t.classList.remove('toast-show'); setTimeout(() => t.remove(), 400); }, 3000);
}

// ─── Console output ──────────────────────────────────────────────────────────
const consoleEl = document.getElementById('console-output');

function clog(msg, type = '') {
  const line = document.createElement('div');
  if (type) line.className = `console-line-${type}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
  if (consoleEl.children.length > 300) consoleEl.removeChild(consoleEl.firstChild);
}

clog('WebVulnConsole ⚡ ready. Type "help" for commands.', 'info');

// ─── Backend health ──────────────────────────────────────────────────────────
const statusDot   = document.getElementById('status-dot');
const statusLabel = document.getElementById('status-label');

async function pingBackend() {
  const r = await apiFetch('/api/health');
  if (r.ok) {
    statusDot.className    = 'dot dot-on';
    statusLabel.textContent = 'Connected';
    clog('Backend online: ' + CFG.backendUrl, 'ok');
  } else {
    statusDot.className    = 'dot dot-off';
    statusLabel.textContent = 'Offline';
    clog('Backend offline at ' + CFG.backendUrl + '. Start Termux server first.', 'warn');
  }
}

pingBackend();
setInterval(pingBackend, 30000);

// ─── ToS modal ─────────────────────────────────────────────────────────────────
const tosOverlay = document.getElementById('tos-overlay');
const appEl      = document.getElementById('app');
const tosCheck   = document.getElementById('tos-check');
const tosCheck2  = document.getElementById('tos-check2');
const tosEnter   = document.getElementById('tos-enter');
const tosClient  = document.getElementById('tos-client');

function updateTosBtn() {
  tosEnter.disabled = !(tosCheck.checked && tosCheck2.checked);
}
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

// ─── Navigation ───────────────────────────────────────────────────────────────
const navItems  = document.querySelectorAll('.nav-item');
const pageEls   = document.querySelectorAll('.page');
const pageTitle = document.getElementById('page-title');

const PAGE_LABELS = {
  dashboard: 'Dashboard', projects: 'Projects', targets: 'Targets',
  queue: 'Scan Queue', findings: 'Findings', dorks: 'Dork Generator',
  reports: 'Reports', settings: 'Settings',
};

function showPage(name) {
  navItems.forEach((el) => el.classList.toggle('active', el.dataset.page === name));
  pageEls.forEach((el)  => el.classList.toggle('active', el.id === `page-${name}`));
  pageTitle.textContent = PAGE_LABELS[name] || name;
  if (name === 'queue')     loadQueue();
  if (name === 'findings')  loadFindings();
  if (name === 'reports')   loadReports();
  if (name === 'dashboard') loadDashboard();
  if (name === 'projects')  renderProjectList();
  if (name === 'targets')   renderTargetList();
}

navItems.forEach((el) =>
  el.addEventListener('click', (e) => { e.preventDefault(); showPage(el.dataset.page); })
);

// ─── Projects ─────────────────────────────────────────────────────────────────
const projectSelect = document.getElementById('project-select');

function renderProjectSelect() {
  const cur = state.currentProject;
  projectSelect.innerHTML =
    '<option value="">— Select project —</option>' +
    state.projects.map((p) =>
      `<option value="${escHtml(p.id)}" ${p.id === cur ? 'selected' : ''}>${escHtml(p.name)}</option>`
    ).join('');
}

function renderProjectList() {
  const el = document.getElementById('project-list');
  if (!state.projects.length) {
    el.innerHTML = '<p style="opacity:.5;font-size:12px;">No projects yet. Create one to get started.</p>';
    return;
  }
  el.innerHTML = state.projects.map((p) => `
    <div class="job-card">
      <div>
        <div class="job-desc">${escHtml(p.name)}</div>
        <div class="job-id">
          ID: ${escHtml(p.id)} &nbsp;|
          Targets: ${(state.targets[p.id] || []).length} &nbsp;|
          Created: ${p.createdAt ? new Date(p.createdAt).toLocaleDateString() : 'n/a'}
        </div>
      </div>
      <div style="display:flex;gap:6px;">
        ${p.id === state.currentProject
          ? '<span class="badge badge-info">active</span>'
          : `<button class="btn btn-sm btn-primary" onclick="window._selectProject('${escHtml(p.id)}')">Select</button>`
        }
        <button class="btn btn-sm btn-ghost" onclick="window._renameProject('${escHtml(p.id)}')">Rename</button>
        <button class="btn btn-sm btn-danger" onclick="window._deleteProject('${escHtml(p.id)}')">Delete</button>
        <button class="btn btn-sm btn-ghost" onclick="window._exportProject('${escHtml(p.id)}')">Export</button>
      </div>
    </div>
  `).join('');
}

function selectProject(id) {
  state.currentProject = id;
  saveState();
  renderProjectSelect();
  renderTargetList();
  const p = state.projects.find((x) => x.id === id);
  clog(`Active project: ${p ? p.name : id}`, 'info');
}

window._selectProject = selectProject;

window._renameProject = function(id) {
  const p = state.projects.find((x) => x.id === id);
  if (!p) return;
  const name = prompt('New project name:', p.name);
  if (!name || !name.trim()) return;
  p.name = name.trim();
  saveState();
  renderProjectSelect();
  renderProjectList();
  clog(`Renamed project to: ${name.trim()}`, 'ok');
};

window._deleteProject = function(id) {
  if (!confirm('Delete this project and all its targets?')) return;
  state.projects = state.projects.filter((p) => p.id !== id);
  delete state.targets[id];
  if (state.currentProject === id) {
    state.currentProject = state.projects[0]?.id || null;
    localStorage.removeItem('wvc_current_project');
  }
  saveState();
  renderProjectSelect();
  renderProjectList();
  clog(`Project deleted: ${id}`, 'warn');
};

window._exportProject = function(id) {
  const p = state.projects.find((x) => x.id === id);
  if (!p) return;
  const data = { project: p, targets: state.targets[id] || [] };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: `${p.name.replace(/\s+/g,'_')}.json` });
  a.click();
  URL.revokeObjectURL(url);
  clog(`Exported project: ${p.name}`, 'ok');
};

projectSelect.addEventListener('change', (e) => { if (e.target.value) selectProject(e.target.value); });

function createProjectPrompt() {
  const name = prompt('Project name:');
  if (!name || !name.trim()) return;
  const id = uid();
  const client = prompt('Client name / ticket ID (optional):') || '';
  state.projects.push({ id, name: name.trim(), client, createdAt: new Date().toISOString() });
  saveState();
  selectProject(id);
  renderProjectSelect();
  renderProjectList();
  clog(`> create project "${name.trim()}" [${id}]`, 'cmd');
  toast(`Project "${name.trim()}" created`, 'ok');
}

document.getElementById('btn-new-project').addEventListener('click', createProjectPrompt);
document.getElementById('btn-create-project').addEventListener('click', createProjectPrompt);

renderProjectSelect();
renderProjectList();

// ─── Targets ──────────────────────────────────────────────────────────────────
function getTargets() { return state.currentProject ? (state.targets[state.currentProject] || []) : []; }

function renderTargetList() {
  const el      = document.getElementById('target-list');
  const targets = getTargets();
  if (!targets.length) {
    el.innerHTML = '<p style="opacity:.5;font-size:12px;margin-top:8px;">No targets yet. Paste targets above.</p>';
    return;
  }
  el.innerHTML = `
    <div style="display:flex;justify-content:flex-end;margin-bottom:4px;">
      <button class="btn btn-sm btn-danger" onclick="clearAllTargets()">Clear All</button>
    </div>
    <table class="findings-table">
      <thead><tr><th>#</th><th>Target</th><th></th></tr></thead>
      <tbody>
        ${targets.map((t, i) => `
          <tr>
            <td>${i + 1}</td>
            <td>${escHtml(t)}</td>
            <td><button class="btn btn-sm btn-ghost" onclick="window._removeTarget(${i})">&#x2715;</button></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

window._removeTarget = function(idx) {
  if (!state.currentProject) return;
  const arr = state.targets[state.currentProject] || [];
  arr.splice(idx, 1);
  state.targets[state.currentProject] = arr;
  saveState();
  renderTargetList();
};

window.clearAllTargets = function() {
  if (!state.currentProject) return;
  if (!confirm('Clear all targets for this project?')) return;
  state.targets[state.currentProject] = [];
  saveState();
  renderTargetList();
  clog('All targets cleared.', 'warn');
};

document.getElementById('btn-add-targets').addEventListener('click', () => {
  if (!state.currentProject) { clog('Select or create a project first.', 'warn'); toast('No project selected', 'warn'); return; }
  const raw = document.getElementById('targets-input').value.trim();
  if (!raw) return;
  const lines = [...new Set(raw.split(/[\n,\s]+/).map((l) => l.trim()).filter(Boolean))];
  if (!state.targets[state.currentProject]) state.targets[state.currentProject] = [];
  const existing = new Set(state.targets[state.currentProject]);
  const fresh = lines.filter((l) => !existing.has(l));
  state.targets[state.currentProject].push(...fresh);
  saveState();
  renderTargetList();
  document.getElementById('targets-input').value = '';
  clog(`Added ${fresh.length} target(s) (${lines.length - fresh.length} dupes skipped).`, 'ok');
  toast(`${fresh.length} target(s) added`, 'ok');
});

document.getElementById('btn-run-scan').addEventListener('click', async () => {
  if (!state.currentProject) { clog('Select a project first.', 'warn'); return; }
  const targets = getTargets();
  if (!targets.length) { clog('No targets to scan.', 'warn'); return; }
  clog(`> queue scan --project "${state.currentProject}" --targets ${targets.length} --profile policy_normal`, 'cmd');
  const r = await apiFetch('/api/scans', {
    method: 'POST',
    body:   JSON.stringify({ projectId: state.currentProject, targets }),
  });
  if (r.ok) {
    clog(`Scan job queued: ${r.data.jobId}`, 'ok');
    toast('Scan queued ⚡', 'ok');
    showPage('queue');
  } else {
    clog(`Failed to queue scan: ${JSON.stringify(r.data)}`, 'crit');
    toast('Failed to queue scan', 'crit');
  }
});

renderTargetList();

// ─── Scan Queue ────────────────────────────────────────────────────────────────
window.loadQueue = async function() {
  const qs = state.currentProject ? `?projectId=${encodeURIComponent(state.currentProject)}` : '';
  const r  = await apiFetch(`/api/scans${qs}`);
  const el = document.getElementById('queue-list');
  if (!r.ok) { el.innerHTML = '<p style="opacity:.5;">Backend offline?</p>'; return; }
  const jobs = r.data.jobs || [];
  state.jobs = jobs;
  if (!jobs.length) { el.innerHTML = '<p style="opacity:.5;font-size:12px;">No scan jobs yet. Add targets and hit Run Scan.</p>'; return; }
  el.innerHTML = jobs.map((j) => `
    <div class="job-card">
      <div>
        <div class="job-desc">${escHtml(j.description || j.projectId)}</div>
        <div class="job-id">${escHtml(j.id)} &nbsp;|&nbsp; ${Array.isArray(j.targets) ? j.targets.length : 0} targets &nbsp;|&nbsp; ${j.createdAt ? new Date(j.createdAt).toLocaleString() : ''}</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        ${statusBadge(j.status)}
        ${['completed','failed'].includes(j.status)
          ? `<button class="btn btn-sm btn-ghost" onclick="window._viewResults('${escHtml(j.id)}')">Results</button>` : ''}
        ${['running','queued'].includes(j.status)
          ? `<button class="btn btn-sm btn-ghost" onclick="window._cancelJob('${escHtml(j.id)}')">Cancel</button>` : ''}
      </div>
    </div>
  `).join('');
  // Auto-refresh if any jobs are running.
  if (jobs.some((j) => ['running','queued'].includes(j.status))) {
    setTimeout(window.loadQueue, 4000);
  }
};

window._viewResults = async function(jobId) {
  clog(`> show results --job ${jobId}`, 'cmd');
  const r = await apiFetch(`/api/scans/${jobId}/results`);
  if (!r.ok) { clog('Could not load results.', 'warn'); return; }
  state.findings = r.data.findings || [];
  showPage('findings');
  renderFindingsTable(state.findings);
  populateCategoryFilter();
};

window._cancelJob = async function(jobId) {
  const r = await apiFetch(`/api/scans/${jobId}/cancel`, { method: 'POST', body: '{}' });
  clog(r.ok ? `Job ${jobId} canceled.` : `Cancel failed: ${JSON.stringify(r.data)}`, r.ok ? 'warn' : 'crit');
  window.loadQueue();
};

// ─── Findings ─────────────────────────────────────────────────────────────────
window.loadFindings = async function() {
  if (!state.currentProject) {
    document.getElementById('findings-table-wrap').innerHTML = '<p style="opacity:.5;font-size:12px;">Select a project first.</p>';
    return;
  }
  const r = await apiFetch(`/api/scans?projectId=${encodeURIComponent(state.currentProject)}`);
  if (!r.ok) return;
  const done = (r.data.jobs || []).filter((j) => j.status === 'completed');
  if (!done.length) {
    document.getElementById('findings-table-wrap').innerHTML = '<p style="opacity:.5;font-size:12px;">No completed scans yet.</p>';
    return;
  }
  // Aggregate findings from all completed jobs for this project.
  const allF = [];
  for (const job of done.slice(0, 5)) {
    const rr = await apiFetch(`/api/scans/${job.id}/results`);
    if (rr.ok) allF.push(...(rr.data.findings || []));
  }
  state.findings = allF;
  renderFindingsTable(allF);
  populateCategoryFilter();
};

function renderFindingsTable(findings) {
  const sevFilter = document.getElementById('filter-sev').value;
  const catFilter = document.getElementById('filter-cat').value;
  let rows = findings;
  if (sevFilter) rows = rows.filter((f) => f.severity === sevFilter);
  if (catFilter) rows = rows.filter((f) => f.category  === catFilter);
  const wrap = document.getElementById('findings-table-wrap');
  if (!rows.length) {
    wrap.innerHTML = '<p style="opacity:.5;font-size:12px;">No findings match the current filters.</p>';
    return;
  }
  wrap.innerHTML = `
    <div style="font-size:11px;opacity:.5;margin-bottom:6px;">${rows.length} finding(s) shown</div>
    <table class="findings-table">
      <thead><tr><th>#</th><th>Sev</th><th>Category</th><th>Title</th><th>URL</th><th>HTTP</th></tr></thead>
      <tbody>
        ${rows.map((f, i) => `
          <tr>
            <td>${i + 1}</td>
            <td>${sevBadge(f.severity)}</td>
            <td style="opacity:.7;font-size:11px;">${escHtml(f.category || '')}</td>
            <td>${escHtml(f.title || '')}</td>
            <td><a href="${escHtml(f.url || '')}" target="_blank" rel="noopener">${escHtml(f.url || '')}</a></td>
            <td>${escHtml(String(f.statusCode || ''))}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function populateCategoryFilter() {
  const cats = [...new Set(state.findings.map((f) => f.category).filter(Boolean))];
  const el   = document.getElementById('filter-cat');
  el.innerHTML = '<option value="">All Categories</option>' +
    cats.map((c) => `<option>${escHtml(c)}</option>`).join('');
}

document.getElementById('filter-sev').addEventListener('change', () => renderFindingsTable(state.findings));
document.getElementById('filter-cat').addEventListener('change', () => renderFindingsTable(state.findings));

// ─── Dorks ─────────────────────────────────────────────────────────────────────
document.getElementById('btn-gen-dorks').addEventListener('click', async () => {
  const domain = document.getElementById('dork-domain-input').value.trim();
  if (!domain) { clog('Enter a domain first.', 'warn'); return; }
  clog(`> dorks ${domain}`, 'cmd');
  const r    = await apiFetch(`/api/dorks?domain=${encodeURIComponent(domain)}`);
  const wrap = document.getElementById('dork-results');
  if (!r.ok) {
    wrap.innerHTML = '<p style="opacity:.5;">Backend offline – cannot generate dorks.</p>';
    clog('Backend offline for dorks.', 'warn');
    return;
  }
  const { google = [], github = [] } = r.data;

  function dorkCards(dorks) {
    return dorks.map((d) => `
      <div class="dork-card">
        <div>
          <div class="dork-title">${sevBadge(d.severity)} ${escHtml(d.title)}</div>
          <div class="dork-query">${escHtml(d.rawQuery)}</div>
        </div>
        <a class="btn btn-sm btn-primary" href="${escHtml(d.url)}" target="_blank" rel="noopener">Open ↗</a>
      </div>
    `).join('');
  }

  wrap.innerHTML = `
    <div class="dork-section-title">🔍 Google Dorks (${google.length})</div>
    ${dorkCards(google)}
    <div class="dork-section-title">🐙 GitHub Dorks (${github.length})</div>
    ${dorkCards(github)}
  `;
  clog(`Generated ${google.length} Google + ${github.length} GitHub dorks for ${domain}`, 'ok');
});

// ─── Reports ───────────────────────────────────────────────────────────────────
window.loadReports = async function() {
  const qs = state.currentProject ? `?projectId=${encodeURIComponent(state.currentProject)}` : '';
  const r  = await apiFetch(`/api/scans${qs}`);
  const el = document.getElementById('report-list');
  if (!r.ok) { el.innerHTML = '<p style="opacity:.5;">Backend offline.</p>'; return; }
  const done = (r.data.jobs || []).filter((j) => j.status === 'completed');
  if (!done.length) { el.innerHTML = '<p style="opacity:.5;font-size:12px;">No completed scans yet.</p>'; return; }
  el.innerHTML = done.map((j) => `
    <div class="job-card">
      <div>
        <div class="job-desc">${escHtml(j.description || j.projectId)}</div>
        <div class="job-id">${escHtml(j.id)} &nbsp;|&nbsp; ${j.completedAt ? new Date(j.completedAt).toLocaleString() : ''}</div>
      </div>
      <div style="display:flex;gap:6px;">
        <a class="btn btn-sm btn-primary" href="${escHtml(CFG.backendUrl)}/api/scans/${escHtml(j.id)}/report.html" target="_blank">HTML Report</a>
        <a class="btn btn-sm btn-ghost"   href="${escHtml(CFG.backendUrl)}/api/scans/${escHtml(j.id)}/report.md"   target="_blank">Markdown</a>
      </div>
    </div>
  `).join('');
};

// ─── Settings ─────────────────────────────────────────────────────────────────
document.getElementById('setting-backend-url').value = CFG.backendUrl;
document.getElementById('setting-auth-note').value   = CFG.authNote;

document.getElementById('btn-save-settings').addEventListener('click', () => {
  const url  = document.getElementById('setting-backend-url').value.trim();
  const note = document.getElementById('setting-auth-note').value.trim();
  if (url)  { CFG.backendUrl = url;  localStorage.setItem('wvc_backend_url', url);  }
  if (note) { CFG.authNote  = note; localStorage.setItem('wvc_auth_note',   note); }
  const saved = document.getElementById('settings-saved');
  saved.style.display = 'block';
  setTimeout(() => { saved.style.display = 'none'; }, 2500);
  clog('Settings saved. Pinging backend...', 'info');
  pingBackend();
});

// ─── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  const statRow = document.getElementById('stat-row');
  const recEl   = document.getElementById('recent-findings');

  const targetCount = Object.values(state.targets).flat().length;

  const r = await apiFetch('/api/scans');
  let jobs = [], allFindings = [];
  if (r.ok) {
    jobs = r.data.jobs || [];
    const done = jobs.filter((j) => j.status === 'completed');
    if (done.length) {
      const rr = await apiFetch(`/api/scans/${done[0].id}/results`);
      if (rr.ok) allFindings = rr.data.findings || [];
    }
  }

  const crit  = allFindings.filter((f) => f.severity === 'critical').length;
  const high  = allFindings.filter((f) => f.severity === 'high').length;
  const jobsDone = jobs.filter((j) => j.status === 'completed').length;
  const jobsRun  = jobs.filter((j) => j.status === 'running').length;

  statRow.innerHTML = [
    { num: state.projects.length, lbl: 'Projects',      color: '' },
    { num: targetCount,           lbl: 'Targets',        color: '' },
    { num: jobs.length,           lbl: 'Total Jobs',     color: '' },
    { num: jobsDone,              lbl: 'Completed',       color: 'var(--green)' },
    { num: jobsRun,               lbl: 'Running',         color: 'var(--accent)' },
    { num: crit,                  lbl: 'Critical',        color: 'var(--red)' },
    { num: high,                  lbl: 'High',            color: 'var(--orange)' },
    { num: allFindings.length,    lbl: 'Total Findings',  color: '' },
  ].map((s) => `
    <div class="stat-box">
      <div class="num" style="color:${s.color || 'var(--accent)'}">${s.num}</div>
      <div class="lbl">${s.lbl}</div>
    </div>
  `).join('');

  const topFindings = allFindings
    .filter((f) => ['critical','high'].includes(f.severity))
    .slice(0, 10);

  recEl.innerHTML = topFindings.length
    ? `<table class="findings-table">
        <thead><tr><th>Sev</th><th>Category</th><th>Title</th><th>URL</th></tr></thead>
        <tbody>
          ${topFindings.map((f) => `
            <tr>
              <td>${sevBadge(f.severity)}</td>
              <td style="opacity:.7;font-size:11px;">${escHtml(f.category||'')}</td>
              <td>${escHtml(f.title||'')}</td>
              <td><a href="${escHtml(f.url||'')}" target="_blank" rel="noopener">${escHtml(f.url||'')}</a></td>
            </tr>`).join('')}
        </tbody>
      </table>`
    : '<p style="opacity:.5;font-size:12px;">No high/critical findings yet. Run your first scan.</p>';
}

// ─── Console commands ──────────────────────────────────────────────────────────
const consoleInput = document.getElementById('console-input');
const CMD_HISTORY  = [];
let   histIdx      = -1;

consoleInput.addEventListener('keydown', async (e) => {
  if (e.key === 'ArrowUp')   { histIdx = Math.min(histIdx + 1, CMD_HISTORY.length - 1); consoleInput.value = CMD_HISTORY[histIdx] || ''; return; }
  if (e.key === 'ArrowDown') { histIdx = Math.max(histIdx - 1, -1); consoleInput.value = histIdx < 0 ? '' : CMD_HISTORY[histIdx]; return; }
  if (e.key !== 'Enter') return;

  const raw = consoleInput.value.trim();
  if (!raw) return;
  CMD_HISTORY.unshift(raw);
  if (CMD_HISTORY.length > 50) CMD_HISTORY.pop();
  histIdx = -1;
  consoleInput.value = '';
  clog(`> ${raw}`, 'cmd');

  const parts = raw.split(/\s+/);
  const cmd   = parts[0].toLowerCase();

  const CMDS = {
    help: () => [
      'help                      – this menu',
      'ping                      – check backend',
      'show dashboard|queue|findings|targets|dorks|reports',
      'dorks <domain>            – generate dorks',
      'scan                      – run scan on current project',
      'project <name>            – create new project',
      'clear                     – clear console',
      'status                    – show current project + target count',
    ].forEach((l) => clog(l, 'info')),

    ping:    () => pingBackend(),
    clear:   () => { consoleEl.innerHTML = ''; clog('Console cleared.', 'info'); },
    status:  () => {
      const p = state.projects.find((x) => x.id === state.currentProject);
      clog(`Project: ${p ? p.name : 'none'} | Targets: ${getTargets().length}`, 'info');
    },
    show: () => {
      const sub = (parts[1] || '').toLowerCase();
      const valid = ['dashboard','queue','findings','targets','dorks','reports','projects','settings'];
      if (valid.includes(sub)) { showPage(sub); return; }
      clog(`Unknown page: ${sub}. Options: ${valid.join(', ')}`, 'warn');
    },
    dorks: () => {
      const domain = parts[1];
      if (!domain) { clog('Usage: dorks <domain>', 'warn'); return; }
      document.getElementById('dork-domain-input').value = domain;
      showPage('dorks');
      document.getElementById('btn-gen-dorks').click();
    },
    scan:    () => document.getElementById('btn-run-scan').click(),
    project: () => {
      const name = parts.slice(1).join(' ');
      if (!name) { clog('Usage: project <name>', 'warn'); return; }
      const id = uid();
      state.projects.push({ id, name, createdAt: new Date().toISOString() });
      saveState();
      selectProject(id);
      renderProjectSelect();
      renderProjectList();
      clog(`Project created: ${name} [${id}]`, 'ok');
    },
  };

  if (CMDS[cmd]) { CMDS[cmd](); }
  else { clog(`Unknown: "${cmd}". Type help.`, 'warn'); }
});

// ─── Toast styles (injected dynamically) ───────────────────────────────────────────
const toastStyle = document.createElement('style');
toastStyle.textContent = `
  .toast { position:fixed;bottom:20px;right:20px;z-index:9999;padding:10px 18px;
    background:#0f172a;border:1px solid #1f2937;border-radius:6px;font-size:12px;
    color:#e5e7eb;font-family:monospace;opacity:0;transform:translateY(10px);
    transition:opacity .3s,transform .3s;pointer-events:none; }
  .toast-show { opacity:1;transform:translateY(0); }
  .toast-ok   { border-color:#22c55e60;color:#22c55e; }
  .toast-warn { border-color:#eab30860;color:#eab308; }
  .toast-crit { border-color:#ef444460;color:#ef4444; }
`;
document.head.appendChild(toastStyle);

// ─── Init ──────────────────────────────────────────────────────────────────────
if (sessionStorage.getItem('wvc_tos') === 'yes') {
  loadDashboard();
}
