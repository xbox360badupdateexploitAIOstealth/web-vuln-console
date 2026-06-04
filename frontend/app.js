/* =========================================================
   WebVulnConsole – app.js
   Full client-side app logic. Talks to the Node backend.
   ========================================================= */

'use strict';

// ─── Config ────────────────────────────────────────────────────────────────

let CFG = {
  backendUrl: localStorage.getItem('wvc_backend_url') || 'http://127.0.0.1:8787',
  authNote:   localStorage.getItem('wvc_auth_note')   || '',
};

// ─── State ─────────────────────────────────────────────────────────────────

let state = {
  currentProject: localStorage.getItem('wvc_current_project') || null,
  projects:  JSON.parse(localStorage.getItem('wvc_projects')  || '[]'),
  targets:   JSON.parse(localStorage.getItem('wvc_targets')   || '{}'), // { projectId: [hosts] }
  jobs:      [],
  findings:  [],
};

function saveProjects()  { localStorage.setItem('wvc_projects', JSON.stringify(state.projects)); }
function saveTargets()   { localStorage.setItem('wvc_targets',  JSON.stringify(state.targets)); }

// ─── Utilities ──────────────────────────────────────────────────────────────

function apiUrl(path) { return `${CFG.backendUrl}${path}`; }

async function apiFetch(path, opts = {}) {
  try {
    const res = await fetch(apiUrl(path), {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
    });
    const json = await res.json();
    return { ok: res.ok, status: res.status, data: json };
  } catch (err) {
    return { ok: false, status: 0, data: null, err: String(err) };
  }
}

function uid() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function sevBadge(sev) {
  return `<span class="badge badge-${sev || 'info'}">${escHtml(sev || 'info')}</span>`;
}

function statusBadge(status) {
  return `<span class="job-status-badge status-${status}">${escHtml(status)}</span>`;
}

// ─── Console output ─────────────────────────────────────────────────────────

const consoleEl = document.getElementById('console-output');

function clog(msg, type = '') {
  const cls = type ? `console-line-${type}` : '';
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

clog('WebVulnConsole initialized. Type "help" for commands.', 'info');

// ─── Backend health ping ─────────────────────────────────────────────────────

const statusDot   = document.getElementById('status-dot');
const statusLabel = document.getElementById('status-label');

async function pingBackend() {
  const r = await apiFetch('/api/health');
  if (r.ok) {
    statusDot.className   = 'dot dot-on';
    statusLabel.textContent = 'Connected';
    clog('Backend connected: ' + CFG.backendUrl, 'ok');
  } else {
    statusDot.className   = 'dot dot-off';
    statusLabel.textContent = 'Disconnected';
    clog('Backend unreachable at ' + CFG.backendUrl + '. Check Termux / server.', 'warn');
  }
}

pingBackend();
setInterval(pingBackend, 30000);

// ─── ToS Modal ───────────────────────────────────────────────────────────────

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

const tosAccepted = sessionStorage.getItem('wvc_tos') === 'yes';
if (tosAccepted) {
  tosOverlay.classList.add('hidden');
  appEl.classList.remove('hidden');
}

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
});

// ─── Sidebar navigation ──────────────────────────────────────────────────────

const navItems = document.querySelectorAll('.nav-item');
const pages    = document.querySelectorAll('.page');
const pageTitle= document.getElementById('page-title');

function showPage(name) {
  navItems.forEach((el) => el.classList.toggle('active', el.dataset.page === name));
  pages.forEach((el)    => el.classList.toggle('active', el.id === `page-${name}`));
  pageTitle.textContent = name.charAt(0).toUpperCase() + name.slice(1);
  if (name === 'queue')    loadQueue();
  if (name === 'findings') loadFindings();
  if (name === 'reports')  loadReports();
  if (name === 'dashboard') loadDashboard();
}

navItems.forEach((el) => {
  el.addEventListener('click', (e) => { e.preventDefault(); showPage(el.dataset.page); });
});

// ─── Project management ──────────────────────────────────────────────────────

const projectSelect = document.getElementById('project-select');

function renderProjectSelect() {
  const cur = state.currentProject;
  projectSelect.innerHTML = '<option value="">Select project</option>' +
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
        <div class="job-id">${escHtml(p.id)} &nbsp;|&nbsp; ${(state.targets[p.id] || []).length} targets</div>
      </div>
      <button class="btn btn-sm btn-primary" onclick="selectProject('${escHtml(p.id)}')">Select</button>
    </div>
  `).join('');
}

function selectProject(id) {
  state.currentProject = id;
  localStorage.setItem('wvc_current_project', id);
  renderProjectSelect();
  renderTargetList();
  clog(`Switched to project: ${id}`, 'info');
}

projectSelect.addEventListener('change', (e) => {
  if (e.target.value) selectProject(e.target.value);
});

document.getElementById('btn-new-project').addEventListener('click', createProjectPrompt);
document.getElementById('btn-create-project').addEventListener('click', createProjectPrompt);

function createProjectPrompt() {
  const name = prompt('Project name:');
  if (!name) return;
  const id = uid();
  state.projects.push({ id, name, createdAt: new Date().toISOString() });
  saveProjects();
  selectProject(id);
  renderProjectList();
  clog(`> create project "${name}" [${id}]`, 'cmd');
}

renderProjectSelect();
renderProjectList();

// ─── Targets ─────────────────────────────────────────────────────────────────

function getTargets() {
  if (!state.currentProject) return [];
  return state.targets[state.currentProject] || [];
}

function renderTargetList() {
  const el = document.getElementById('target-list');
  const targets = getTargets();
  if (!targets.length) {
    el.innerHTML = '<p style="opacity:.5;font-size:12px;margin-top:8px;">No targets added yet.</p>';
    return;
  }
  el.innerHTML = `
    <table class="findings-table" style="margin-top:8px;">
      <thead><tr><th>#</th><th>Host</th><th></th></tr></thead>
      <tbody>
        ${targets.map((t, i) => `
          <tr>
            <td>${i + 1}</td>
            <td>${escHtml(t)}</td>
            <td><button class="btn btn-sm btn-ghost" onclick="removeTarget(${i})">Remove</button></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

window.removeTarget = function(idx) {
  if (!state.currentProject) return;
  const arr = state.targets[state.currentProject] || [];
  arr.splice(idx, 1);
  state.targets[state.currentProject] = arr;
  saveTargets();
  renderTargetList();
};

document.getElementById('btn-add-targets').addEventListener('click', () => {
  if (!state.currentProject) { clog('Select a project first.', 'warn'); return; }
  const raw = document.getElementById('targets-input').value.trim();
  if (!raw) return;
  const lines = raw.split(/\n/).map((l) => l.trim()).filter(Boolean);
  if (!state.targets[state.currentProject]) state.targets[state.currentProject] = [];
  state.targets[state.currentProject].push(...lines);
  saveTargets();
  renderTargetList();
  document.getElementById('targets-input').value = '';
  clog(`Added ${lines.length} target(s) to project ${state.currentProject}`, 'ok');
});

document.getElementById('btn-run-scan').addEventListener('click', async () => {
  if (!state.currentProject) { clog('Select a project first.', 'warn'); return; }
  const targets = getTargets();
  if (!targets.length) { clog('No targets to scan.', 'warn'); return; }

  clog(`> queue scan --project "${state.currentProject}" --targets ${targets.length}`, 'cmd');
  const r = await apiFetch('/api/scans', {
    method: 'POST',
    body: JSON.stringify({ projectId: state.currentProject, targets }),
  });
  if (r.ok) {
    clog(`Scan job created: ${r.data.jobId} (status: ${r.data.status})`, 'ok');
    showPage('queue');
  } else {
    clog(`Failed to create scan job: ${JSON.stringify(r.data)}`, 'crit');
  }
});

renderTargetList();

// ─── Scan Queue ──────────────────────────────────────────────────────────────

async function loadQueue() {
  const r = await apiFetch('/api/scans' + (state.currentProject ? `?projectId=${state.currentProject}` : ''));
  const el = document.getElementById('queue-list');
  if (!r.ok) { el.innerHTML = '<p style="opacity:.5;">Could not load queue. Backend offline?</p>'; return; }
  const jobs = r.data.jobs || [];
  state.jobs = jobs;
  if (!jobs.length) { el.innerHTML = '<p style="opacity:.5;font-size:12px;">No scan jobs yet.</p>'; return; }
  el.innerHTML = jobs.map((j) => `
    <div class="job-card">
      <div>
        <div class="job-desc">${escHtml(j.description || j.projectId)}</div>
        <div class="job-id">${escHtml(j.id)} &nbsp;|&nbsp; ${Array.isArray(j.targets) ? j.targets.length : 0} targets &nbsp;|&nbsp; ${j.createdAt ? new Date(j.createdAt).toLocaleString() : ''}</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        ${statusBadge(j.status)}
        ${['completed','failed'].includes(j.status)
          ? `<button class="btn btn-sm btn-ghost" onclick="viewResults('${escHtml(j.id)}')">Results</button>` : ''}
        ${'running|queued'.includes(j.status)
          ? `<button class="btn btn-sm btn-ghost" onclick="cancelJob('${escHtml(j.id)}')">Cancel</button>` : ''}
      </div>
    </div>
  `).join('');
}

window.viewResults = async function(jobId) {
  clog(`> show results --job ${jobId}`, 'cmd');
  showPage('findings');
  const r = await apiFetch(`/api/scans/${jobId}/results`);
  if (!r.ok) { clog('Could not load results.', 'warn'); return; }
  state.findings = r.data.findings || [];
  renderFindingsTable(state.findings);
};

window.cancelJob = async function(jobId) {
  const r = await apiFetch(`/api/scans/${jobId}/cancel`, { method: 'POST', body: '{}' });
  clog(r.ok ? `Job ${jobId} canceled.` : `Cancel failed.`, r.ok ? 'warn' : 'crit');
  loadQueue();
};

// ─── Findings ────────────────────────────────────────────────────────────────

async function loadFindings() {
  if (!state.currentProject) return;
  // Load from all completed jobs of the project.
  const r = await apiFetch(`/api/scans?projectId=${state.currentProject}`);
  if (!r.ok) return;
  const jobs = (r.data.jobs || []).filter((j) => j.status === 'completed');
  if (!jobs.length) {
    document.getElementById('findings-table-wrap').innerHTML = '<p style="opacity:.5;font-size:12px;">No completed scans found.</p>';
    return;
  }
  // Load results for most recent completed job.
  const latest = jobs[0];
  const rr = await apiFetch(`/api/scans/${latest.id}/results`);
  state.findings = rr.ok ? (rr.data.findings || []) : [];
  renderFindingsTable(state.findings);
  populateCategoryFilter();
}

function renderFindingsTable(findings) {
  const sevFilter = document.getElementById('filter-sev').value;
  const catFilter = document.getElementById('filter-cat').value;
  let rows = findings;
  if (sevFilter) rows = rows.filter((f) => f.severity === sevFilter);
  if (catFilter) rows = rows.filter((f) => f.category === catFilter);
  const wrap = document.getElementById('findings-table-wrap');
  if (!rows.length) {
    wrap.innerHTML = '<p style="opacity:.5;font-size:12px;">No findings matching current filters.</p>';
    return;
  }
  wrap.innerHTML = `
    <table class="findings-table">
      <thead>
        <tr><th>#</th><th>Severity</th><th>Category</th><th>Title</th><th>URL</th><th>HTTP</th></tr>
      </thead>
      <tbody>
        ${rows.map((f, i) => `
          <tr>
            <td>${i + 1}</td>
            <td>${sevBadge(f.severity)}</td>
            <td style="opacity:.7;">${escHtml(f.category || '')}</td>
            <td>${escHtml(f.title || '')}</td>
            <td><a href="${escHtml(f.url || '')}" target="_blank">${escHtml(f.url || '')}</a></td>
            <td>${escHtml(String(f.statusCode || ''))}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function populateCategoryFilter() {
  const cats = [...new Set(state.findings.map((f) => f.category).filter(Boolean))];
  const el = document.getElementById('filter-cat');
  el.innerHTML = '<option value="">All Categories</option>' +
    cats.map((c) => `<option>${escHtml(c)}</option>`).join('');
}

document.getElementById('filter-sev').addEventListener('change', () => renderFindingsTable(state.findings));
document.getElementById('filter-cat').addEventListener('change', () => renderFindingsTable(state.findings));

// ─── Dorks ───────────────────────────────────────────────────────────────────

document.getElementById('btn-gen-dorks').addEventListener('click', async () => {
  const domain = document.getElementById('dork-domain-input').value.trim();
  if (!domain) { clog('Enter a domain first.', 'warn'); return; }
  clog(`> dorks ${domain}`, 'cmd');
  const r = await apiFetch(`/api/dorks?domain=${encodeURIComponent(domain)}`);
  const wrap = document.getElementById('dork-results');
  if (!r.ok) {
    wrap.innerHTML = '<p style="opacity:.5;">Backend offline – showing local dorks only.</p>';
    return;
  }
  const { google, github } = r.data;

  function renderDorkList(dorks) {
    return dorks.map((d) => `
      <div class="dork-card">
        <div>
          <div class="dork-title">${sevBadge(d.severity)} ${escHtml(d.title)}</div>
          <div class="dork-query">${escHtml(d.rawQuery)}</div>
        </div>
        <a href="${escHtml(d.url)}" target="_blank" rel="noopener">Open ↗</a>
      </div>
    `).join('');
  }

  wrap.innerHTML = `
    <div class="dork-section-title">🔍 Google Dorks (${google.length})</div>
    ${renderDorkList(google)}
    <div class="dork-section-title">🐙 GitHub Dorks (${github.length})</div>
    ${renderDorkList(github)}
  `;
  clog(`Generated ${google.length} Google + ${github.length} GitHub dorks for ${domain}`, 'ok');
});

// ─── Reports ─────────────────────────────────────────────────────────────────

async function loadReports() {
  const r = await apiFetch('/api/scans' + (state.currentProject ? `?projectId=${state.currentProject}` : ''));
  const el = document.getElementById('report-list');
  if (!r.ok) { el.innerHTML = '<p style="opacity:.5;">Backend offline.</p>'; return; }
  const jobs = (r.data.jobs || []).filter((j) => j.status === 'completed');
  if (!jobs.length) { el.innerHTML = '<p style="opacity:.5;font-size:12px;">No completed scans to report on.</p>'; return; }
  el.innerHTML = jobs.map((j) => `
    <div class="job-card">
      <div>
        <div class="job-desc">${escHtml(j.description || j.projectId)}</div>
        <div class="job-id">${escHtml(j.id)}</div>
      </div>
      <div style="display:flex;gap:6px;">
        <a class="btn btn-sm btn-primary" href="${escHtml(CFG.backendUrl)}/api/scans/${escHtml(j.id)}/report.html" target="_blank">HTML</a>
        <a class="btn btn-sm btn-ghost"   href="${escHtml(CFG.backendUrl)}/api/scans/${escHtml(j.id)}/report.md"   target="_blank">Markdown</a>
      </div>
    </div>
  `).join('');
}

// ─── Settings ────────────────────────────────────────────────────────────────

document.getElementById('setting-backend-url').value = CFG.backendUrl;
document.getElementById('setting-auth-note').value   = CFG.authNote;

document.getElementById('btn-save-settings').addEventListener('click', () => {
  const url  = document.getElementById('setting-backend-url').value.trim();
  const note = document.getElementById('setting-auth-note').value.trim();
  if (url) { CFG.backendUrl = url; localStorage.setItem('wvc_backend_url', url); }
  if (note){ CFG.authNote  = note; localStorage.setItem('wvc_auth_note',   note); }
  clog('Settings saved. Reconnecting...', 'info');
  pingBackend();
});

// ─── Dashboard ───────────────────────────────────────────────────────────────

async function loadDashboard() {
  const statRow = document.getElementById('stat-row');
  const recEl   = document.getElementById('recent-findings');

  // Count targets.
  const targetCount = Object.values(state.targets).flat().length;

  // Fetch jobs.
  let jobs = [];
  let allFindings = [];
  const r = await apiFetch('/api/scans');
  if (r.ok) {
    jobs = r.data.jobs || [];
    // Get latest completed job findings for quick stats.
    const done = jobs.filter((j) => j.status === 'completed');
    if (done.length) {
      const rr = await apiFetch(`/api/scans/${done[0].id}/results`);
      if (rr.ok) allFindings = rr.data.findings || [];
    }
  }

  const crit = allFindings.filter((f) => f.severity === 'critical').length;
  const high = allFindings.filter((f) => f.severity === 'high').length;

  statRow.innerHTML = [
    { num: state.projects.length, lbl: 'Projects',       color: '' },
    { num: targetCount,           lbl: 'Targets',         color: '' },
    { num: jobs.length,           lbl: 'Scan Jobs',       color: '' },
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
    .slice(0, 8);

  recEl.innerHTML = topFindings.length
    ? `<table class="findings-table">
        <thead><tr><th>Sev</th><th>Category</th><th>Title</th><th>URL</th></tr></thead>
        <tbody>${topFindings.map((f) => `
          <tr>
            <td>${sevBadge(f.severity)}</td>
            <td style="opacity:.7">${escHtml(f.category||'')}</td>
            <td>${escHtml(f.title||'')}</td>
            <td><a href="${escHtml(f.url||'')}" target="_blank">${escHtml(f.url||'')}</a></td>
          </tr>
        `).join('')}</tbody>
      </table>`
    : '<p style="opacity:.5;font-size:12px;">No high/critical findings yet. Run a scan.</p>';
}

loadDashboard();

// ─── Console command handler ──────────────────────────────────────────────────

const consoleInput = document.getElementById('console-input');

consoleInput.addEventListener('keydown', async (e) => {
  if (e.key !== 'Enter') return;
  const raw = consoleInput.value.trim();
  if (!raw) return;
  consoleInput.value = '';
  clog(`> ${raw}`, 'cmd');

  const parts = raw.split(/\s+/);
  const cmd   = parts[0].toLowerCase();

  if (cmd === 'help') {
    ['help                    – show this help',
     'show findings           – go to findings page',
     'show queue              – go to scan queue page',
     'show dashboard          – go to dashboard',
     'dorks <domain>          – generate dorks for domain',
     'scan                    – run scan on current project targets',
     'ping                    – check backend connection',
     'project <name>          – create a new project',
    ].forEach((l) => clog(l, 'info'));
    return;
  }

  if (cmd === 'ping') { pingBackend(); return; }

  if (cmd === 'show') {
    const sub = parts[1]?.toLowerCase();
    if (sub === 'findings')  { showPage('findings');  return; }
    if (sub === 'queue')     { showPage('queue');      return; }
    if (sub === 'dashboard') { showPage('dashboard'); return; }
    if (sub === 'targets')   { showPage('targets');   return; }
    if (sub === 'dorks')     { showPage('dorks');     return; }
    if (sub === 'reports')   { showPage('reports');   return; }
    clog(`Unknown: show ${sub}`, 'warn'); return;
  }

  if (cmd === 'dorks') {
    const domain = parts[1];
    if (!domain) { clog('Usage: dorks <domain>', 'warn'); return; }
    document.getElementById('dork-domain-input').value = domain;
    showPage('dorks');
    document.getElementById('btn-gen-dorks').click();
    return;
  }

  if (cmd === 'scan') {
    document.getElementById('btn-run-scan').click();
    return;
  }

  if (cmd === 'project') {
    const name = parts.slice(1).join(' ');
    if (!name) { clog('Usage: project <name>', 'warn'); return; }
    const id = uid();
    state.projects.push({ id, name, createdAt: new Date().toISOString() });
    saveProjects();
    selectProject(id);
    renderProjectList();
    clog(`Created project: ${name} [${id}]`, 'ok');
    return;
  }

  clog(`Unknown command: "${cmd}". Type "help" for list.`, 'warn');
});
