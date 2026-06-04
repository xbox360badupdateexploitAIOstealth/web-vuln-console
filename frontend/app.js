/* =============================================================
   WebVulnConsole ⚡ app.js  – Full client logic v2
   All sections rewritten: modal, risk gauge, Shodan tab,
   aggregated findings, mobile nav, expanded console cmds.
   ============================================================= */
'use strict';

// ─── Config ──────────────────────────────────────────────────────────────────
let CFG = {
  backendUrl: localStorage.getItem('wvc_backend_url') || 'http://127.0.0.1:8787',
  authNote:   localStorage.getItem('wvc_auth_note')   || '',
};

// ─── State ───────────────────────────────────────────────────────────────────
let state = {
  currentProject: localStorage.getItem('wvc_current_project') || null,
  projects:  JSON.parse(localStorage.getItem('wvc_projects') || '[]'),
  targets:   JSON.parse(localStorage.getItem('wvc_targets')  || '{}'),
  jobs:      [],
  findings:  [],
  findingsPage: 0,
};
const FINDINGS_PER_PAGE = 50;

function saveState() {
  localStorage.setItem('wvc_projects', JSON.stringify(state.projects));
  localStorage.setItem('wvc_targets',  JSON.stringify(state.targets));
  if (state.currentProject) localStorage.setItem('wvc_current_project', state.currentProject);
}

// ─── API helpers ─────────────────────────────────────────────────────────────
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

// ─── Micro utils ─────────────────────────────────────────────────────────────
function uid()    { return Math.random().toString(36).slice(2,10) + Date.now().toString(36); }
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
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

// ─── Console ─────────────────────────────────────────────────────────────────
const consoleEl = document.getElementById('console-output');
function clog(msg, type='') {
  const line = document.createElement('div');
  if (type) line.className = `console-line-${type}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
  if (consoleEl.children.length > 400) consoleEl.removeChild(consoleEl.firstChild);
}
clog('WebVulnConsole ⚡ v2 loaded. Type "help" for commands.', 'info');

// ─── Backend health ───────────────────────────────────────────────────────────
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

// ─── ToS modal ───────────────────────────────────────────────────────────────
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

// ─── Navigation ──────────────────────────────────────────────────────────────
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
  const loaders = { queue:loadQueue, findings:loadFindings, reports:loadReports,
                    dashboard:loadDashboard, projects:renderProjectList, targets:renderTargetList };
  if (loaders[name]) loaders[name]();
}
navItems.forEach(el => el.addEventListener('click', e => { e.preventDefault(); showPage(el.dataset.page); }));

// Mobile sidebar toggle
const sidebar   = document.getElementById('sidebar');
const hamburger = document.getElementById('hamburger-btn');
function closeSidebar() { sidebar.classList.remove('sidebar-open'); }
if (hamburger) hamburger.addEventListener('click', () => sidebar.classList.toggle('sidebar-open'));
document.addEventListener('click', e => {
  if (sidebar.classList.contains('sidebar-open') && !sidebar.contains(e.target) && e.target !== hamburger) closeSidebar();
});

// ─── Risk score gauge ────────────────────────────────────────────────────────
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
  return 'NO FINDINGS';
}
function buildGauge(score) {
  const color = riskColor(score);
  const label = riskLabel(score);
  const pct   = score;
  return `
    <div class="risk-gauge">
      <div class="risk-gauge-label" style="color:${color}">${label}</div>
      <div class="risk-gauge-track">
        <div class="risk-gauge-fill" style="width:${pct}%;background:${color};"></div>
      </div>
      <div class="risk-gauge-score" style="color:${color}">${score}<span>/100</span></div>
    </div>
  `;
}

// ─── Finding detail modal ────────────────────────────────────────────────────
(function injectModal() {
  const m = document.createElement('div');
  m.id        = 'finding-modal-overlay';
  m.className = 'modal-overlay hidden';
  m.innerHTML = `
    <div class="modal-box" id="finding-modal-box">
      <div class="modal-header">
        <span id="modal-sev-badge"></span>
        <span id="modal-cat" style="opacity:.6;font-size:11px;margin-left:8px;"></span>
        <button class="modal-close" id="modal-close-btn">✕</button>
      </div>
      <div class="modal-title" id="modal-title"></div>
      <div class="modal-meta">
        <div><span class="modal-meta-label">URL</span>
          <a id="modal-url" href="#" target="_blank" rel="noopener" style="color:var(--accent);word-break:break-all;"></a>
        </div>
        <div><span class="modal-meta-label">HTTP Status</span>
          <span id="modal-status"></span></div>
        <div id="modal-note-row" style="display:none;"><span class="modal-meta-label">Note</span>
          <span id="modal-note" style="opacity:.8;"></span></div>
        <div id="modal-payload-row" style="display:none;"><span class="modal-meta-label">Payload</span>
          <code id="modal-payload" style="color:var(--accent);"></code></div>
      </div>
      <div id="modal-snippet-wrap" style="display:none;">
        <div class="modal-meta-label" style="margin-bottom:4px;">Evidence Snippet</div>
        <pre class="modal-snippet" id="modal-snippet"></pre>
      </div>
      <div class="modal-footer">
        <div class="modal-meta-label" style="margin-bottom:6px;">Recommended Remediation</div>
        <div id="modal-remediation" style="font-size:12px;line-height:1.6;opacity:.85;"></div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-sm btn-primary"  id="modal-btn-confirm">✓ Mark Confirmed</button>
        <button class="btn btn-sm btn-ghost"    id="modal-btn-mitigate">🛡 Mark Mitigated</button>
        <button class="btn btn-sm btn-ghost"    id="modal-btn-copy">📋 Copy URL</button>
        <button class="btn btn-sm btn-danger"   id="modal-close-btn2">Close</button>
      </div>
    </div>
  `;
  document.body.appendChild(m);
  document.getElementById('modal-close-btn').addEventListener('click',  closeModal);
  document.getElementById('modal-close-btn2').addEventListener('click', closeModal);
  m.addEventListener('click', e => { if (e.target === m) closeModal(); });
  document.getElementById('modal-btn-copy').addEventListener('click', () => {
    const url = document.getElementById('modal-url').textContent;
    navigator.clipboard?.writeText(url).then(() => toast('URL copied','ok'));
  });
  document.getElementById('modal-btn-confirm').addEventListener('click', () => {
    toast('Finding marked as Confirmed','ok');
    clog('Finding confirmed by operator.','ok');
    closeModal();
  });
  document.getElementById('modal-btn-mitigate').addEventListener('click', () => {
    toast('Finding marked as Mitigated','ok');
    clog('Finding marked mitigated.','warn');
    closeModal();
  });
})();

const REMEDIATION_MAP = {
  ENV_FILE:       'Remove .env files from web root. Add .env to .gitignore. Use environment variables injected at runtime by your host/CI system — never commit secrets.',
  GIT_REPO:       'Delete /.git directory from web root or block access via web server rules (deny /\.git). Use a proper deployment pipeline that never exposes the repo directory.',
  SVN_REPO:       'Remove .svn directories from web root. Block access via server config.',
  HG_REPO:        'Remove .hg directories from web root and block via server config.',
  CONFIG_FILE:    'Move config files outside the web root. Restrict file permissions. Never commit config files with credentials.',
  DB_DUMP:        'Remove SQL dump files immediately. Store database backups off-server in secured storage (S3 with private ACL, encrypted). Rotate all credentials in the dump.',
  BACKUP:         'Remove backup archives from web root. Store backups off-server. Rotate any credentials they may contain.',
  RECON:          'Review robots.txt for sensitive path disclosures. Ensure disallowed paths are actually protected by authentication, not just hidden.',
  DEBUG:          'Disable debug modes in production (APP_DEBUG=false, display_errors=Off). Remove phpinfo.php and test files from production servers.',
  ADMIN:          'Ensure admin panels require strong authentication. Consider IP allowlisting for admin routes. Use 2FA.',
  LEAK:           'Remove .DS_Store files (add to .gitignore). They expose directory structure.',
  POLICY:         'Review crossdomain.xml/clientaccesspolicy.xml. Restrict access origins to only trusted domains.',
  CLOUD_META:     'Block access to cloud metadata endpoint from application layer. Apply IMDSv2 on AWS. Restrict SSRF vectors.',
  SQLI:           'Use parameterized queries / prepared statements. Never interpolate user input into SQL strings. Deploy a WAF.',
  XSS:            'HTML-encode all user-supplied output. Implement a Content-Security-Policy header. Use framework-level auto-escaping.',
  ERROR_PAGE:     'Set generic error pages. Disable stack traces in production. Configure proper error handling middleware.',
  DEBUG_LEAK:     'Disable debug mode. Configure proper error handling so stack traces never reach the client.',
  HEADERS:        'Add the missing security header to your web server or application config. Use securityheaders.com to validate.',
  CORS:           'Restrict Access-Control-Allow-Origin to your own domain. Never reflect arbitrary origins. Avoid using wildcard * with credentialed requests.',
  REDIRECT:       'Force HTTPS via HSTS. Ensure your server does not redirect HTTPS traffic to HTTP.',
  OPEN_REDIRECT:  'Validate redirect destinations against an allowlist. Reject or sanitize user-supplied redirect URLs.',
  PATH_TRAVERSAL: 'Validate and sanitize all file path inputs. Use chroot jails or allowlisted directory access. Ensure web server does not serve files outside web root.',
  WORDPRESS:      'Disable XML-RPC if not needed. Restrict REST API user enumeration. Keep WordPress core, themes, and plugins updated. Use a security plugin like Wordfence.',
};

function openFindingModal(f) {
  document.getElementById('modal-sev-badge').innerHTML = sevBadge(f.severity);
  document.getElementById('modal-cat').textContent     = f.category || '';
  document.getElementById('modal-title').textContent   = f.title    || 'Finding Detail';
  const urlEl = document.getElementById('modal-url');
  urlEl.textContent = f.url || '';
  urlEl.href        = f.url || '#';
  document.getElementById('modal-status').textContent = f.statusCode ? String(f.statusCode) : 'N/A';
  const noteRow = document.getElementById('modal-note-row');
  const note    = f.note || '';
  noteRow.style.display = note ? 'block' : 'none';
  document.getElementById('modal-note').textContent = note;
  const payRow = document.getElementById('modal-payload-row');
  payRow.style.display = f.payload ? 'block' : 'none';
  document.getElementById('modal-payload').textContent = f.payload || '';
  const snipWrap = document.getElementById('modal-snippet-wrap');
  const snip     = (f.bodySnippet || '').trim();
  snipWrap.style.display = snip ? 'block' : 'none';
  document.getElementById('modal-snippet').textContent = snip.slice(0, 800);
  const remKey = (f.category || '').toUpperCase().replace(/[^A-Z_]/g,'');
  document.getElementById('modal-remediation').textContent =
    REMEDIATION_MAP[remKey] || 'Review the finding manually and apply the principle of least privilege. Restrict access and remove exposure.';
  document.getElementById('finding-modal-overlay').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}
function closeModal() {
  document.getElementById('finding-modal-overlay').classList.add('hidden');
  document.body.style.overflow = '';
}
window.openFindingModal = openFindingModal;

// ─── Projects ─────────────────────────────────────────────────────────────────
const projectSelect = document.getElementById('project-select');
function renderProjectSelect() {
  const cur = state.currentProject;
  projectSelect.innerHTML =
    '<option value="">— Select project —</option>' +
    state.projects.map(p =>
      `<option value="${escHtml(p.id)}" ${p.id===cur?'selected':''}>${escHtml(p.name)}</option>`
    ).join('');
}
function renderProjectList() {
  const el = document.getElementById('project-list');
  if (!state.projects.length) {
    el.innerHTML = '<p style="opacity:.5;font-size:12px;">No projects yet. Create one to get started.</p>';
    return;
  }
  el.innerHTML = state.projects.map(p => {
    const score = computeRiskScore(
      state.findings.filter ? state.findings : []
    );
    return `
    <div class="job-card">
      <div>
        <div class="job-desc">${escHtml(p.name)}</div>
        <div class="job-id">
          ID: ${escHtml(p.id)} &nbsp;|
          Client: ${escHtml(p.client||'—')} &nbsp;|
          Targets: ${(state.targets[p.id]||[]).length} &nbsp;|
          ${p.createdAt ? timeAgo(p.createdAt) : ''}
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        ${p.id===state.currentProject
          ? '<span class="badge badge-info">active</span>'
          : `<button class="btn btn-sm btn-primary" onclick="window._selectProject('${escHtml(p.id)}')">Select</button>`
        }
        <button class="btn btn-sm btn-ghost"  onclick="window._renameProject('${escHtml(p.id)}')">Rename</button>
        <button class="btn btn-sm btn-danger" onclick="window._deleteProject('${escHtml(p.id)}')">Delete</button>
        <button class="btn btn-sm btn-ghost"  onclick="window._exportProject('${escHtml(p.id)}')">Export</button>
      </div>
    </div>`;
  }).join('');
}
function selectProject(id) {
  state.currentProject = id;
  saveState();
  renderProjectSelect();
  renderTargetList();
  const p = state.projects.find(x=>x.id===id);
  clog(`Active project: ${p?p.name:id}`, 'info');
  loadDashboard();
}
window._selectProject = selectProject;
window._renameProject = function(id) {
  const p = state.projects.find(x=>x.id===id);
  if (!p) return;
  const name = prompt('New name:', p.name);
  if (!name?.trim()) return;
  p.name = name.trim(); saveState(); renderProjectSelect(); renderProjectList();
  clog(`Renamed to: ${name.trim()}`,'ok');
};
window._deleteProject = function(id) {
  if (!confirm('Delete this project and all its targets?')) return;
  state.projects = state.projects.filter(p=>p.id!==id);
  delete state.targets[id];
  if (state.currentProject===id) { state.currentProject=state.projects[0]?.id||null; localStorage.removeItem('wvc_current_project'); }
  saveState(); renderProjectSelect(); renderProjectList();
  clog(`Project deleted: ${id}`,'warn');
};
window._exportProject = function(id) {
  const p = state.projects.find(x=>x.id===id);
  if (!p) return;
  const blob = new Blob([JSON.stringify({project:p,targets:state.targets[id]||[],findings:state.findings},null,2)],{type:'application/json'});
  const url  = URL.createObjectURL(blob);
  Object.assign(document.createElement('a'),{href:url,download:`${p.name.replace(/\s+/g,'_')}_export.json`}).click();
  URL.revokeObjectURL(url);
  clog(`Exported: ${p.name}`,'ok');
};
projectSelect.addEventListener('change', e => { if (e.target.value) selectProject(e.target.value); });
function createProjectPrompt() {
  const name = prompt('Project name:');
  if (!name?.trim()) return;
  const id     = uid();
  const client = prompt('Client name / ticket ID (optional):') || '';
  state.projects.push({id,name:name.trim(),client,createdAt:new Date().toISOString()});
  saveState(); selectProject(id); renderProjectSelect(); renderProjectList();
  clog(`> create project "${name.trim()}" [${id}]`,'cmd');
  toast(`Project "${name.trim()}" created`,'ok');
}
document.getElementById('btn-new-project').addEventListener('click',    createProjectPrompt);
document.getElementById('btn-create-project').addEventListener('click', createProjectPrompt);
renderProjectSelect(); renderProjectList();

// ─── Targets ──────────────────────────────────────────────────────────────────
function getTargets() { return state.currentProject ? (state.targets[state.currentProject]||[]) : []; }
function renderTargetList() {
  const el      = document.getElementById('target-list');
  const targets = getTargets();
  if (!targets.length) {
    el.innerHTML = '<p style="opacity:.5;font-size:12px;margin-top:8px;">No targets. Paste above and click Add Targets.</p>';
    return;
  }
  el.innerHTML = `
    <div style="display:flex;justify-content:flex-end;margin-bottom:4px;">
      <button class="btn btn-sm btn-danger" onclick="clearAllTargets()">Clear All</button>
    </div>
    <table class="findings-table">
      <thead><tr><th>#</th><th>Target</th><th></th></tr></thead>
      <tbody>
        ${targets.map((t,i)=>`
          <tr>
            <td>${i+1}</td>
            <td>${escHtml(t)}</td>
            <td><button class="btn btn-sm btn-ghost" onclick="window._removeTarget(${i})">✕</button></td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}
window._removeTarget = function(idx) {
  if (!state.currentProject) return;
  const arr = state.targets[state.currentProject]||[];
  arr.splice(idx,1);
  state.targets[state.currentProject]=arr; saveState(); renderTargetList();
};
window.clearAllTargets = function() {
  if (!state.currentProject) return;
  if (!confirm('Clear all targets?')) return;
  state.targets[state.currentProject]=[];
  saveState(); renderTargetList();
  clog('All targets cleared.','warn');
};
document.getElementById('btn-add-targets').addEventListener('click', () => {
  if (!state.currentProject) { clog('Select or create a project first.','warn'); toast('No project selected','warn'); return; }
  const raw = document.getElementById('targets-input').value.trim();
  if (!raw) return;
  const lines = [...new Set(raw.split(/[\n,\s]+/).map(l=>l.trim()).filter(Boolean))];
  if (!state.targets[state.currentProject]) state.targets[state.currentProject]=[];
  const existing = new Set(state.targets[state.currentProject]);
  const fresh    = lines.filter(l=>!existing.has(l));
  state.targets[state.currentProject].push(...fresh);
  saveState(); renderTargetList();
  document.getElementById('targets-input').value='';
  clog(`Added ${fresh.length} target(s). ${lines.length-fresh.length} dupes skipped.`,'ok');
  toast(`${fresh.length} target(s) added`,'ok');
});
document.getElementById('btn-run-scan').addEventListener('click', async () => {
  if (!state.currentProject) { clog('Select a project first.','warn'); return; }
  const targets = getTargets();
  if (!targets.length)       { clog('No targets to scan.','warn'); return; }
  clog(`> queue scan --project "${state.currentProject}" --targets ${targets.length}`,'cmd');
  const r = await apiFetch('/api/scans',{ method:'POST', body:JSON.stringify({projectId:state.currentProject,targets}) });
  if (r.ok) {
    clog(`Scan queued: ${r.data.jobId}`,'ok'); toast('Scan queued ⚡','ok'); showPage('queue');
  } else {
    clog(`Queue failed: ${JSON.stringify(r.data)}`,'crit'); toast('Failed to queue scan','crit');
  }
});
renderTargetList();

// ─── Scan Queue ────────────────────────────────────────────────────────────────
window.loadQueue = async function() {
  const qs = state.currentProject ? `?projectId=${encodeURIComponent(state.currentProject)}` : '';
  const r  = await apiFetch(`/api/scans${qs}`);
  const el = document.getElementById('queue-list');
  if (!r.ok) { el.innerHTML='<p style="opacity:.5;">Backend offline?</p>'; return; }
  const jobs = r.data.jobs||[]; state.jobs=jobs;
  if (!jobs.length) { el.innerHTML='<p style="opacity:.5;font-size:12px;">No scan jobs yet. Add targets and hit Run Scan.</p>'; return; }
  el.innerHTML = jobs.map(j=>`
    <div class="job-card">
      <div>
        <div class="job-desc">${escHtml(j.description||j.projectId)}</div>
        <div class="job-id">
          ${escHtml(j.id)} &nbsp;|&nbsp;
          ${Array.isArray(j.targets)?j.targets.length:0} targets &nbsp;|&nbsp;
          ${j.findingCount!=null?`<span style="color:var(--accent)">${j.findingCount} findings</span> &nbsp;|&nbsp;`:''}
          ${timeAgo(j.createdAt)}
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
        ${statusBadge(j.status)}
        ${['completed','failed'].includes(j.status)
          ? `<button class="btn btn-sm btn-primary" onclick="window._viewResults('${escHtml(j.id)}')">Results</button>` : ''}
        ${['running','queued'].includes(j.status)
          ? `<button class="btn btn-sm btn-ghost" onclick="window._cancelJob('${escHtml(j.id)}')">Cancel</button>` : ''}
      </div>
    </div>`).join('');
  if (jobs.some(j=>['running','queued'].includes(j.status))) setTimeout(window.loadQueue, 4000);
};
window._viewResults = async function(jobId) {
  clog(`> show results --job ${jobId}`,'cmd');
  const r = await apiFetch(`/api/scans/${jobId}/results`);
  if (!r.ok) { clog('Could not load results.','warn'); return; }
  state.findings = r.data.findings||[]; state.findingsPage=0;
  showPage('findings'); renderFindingsTable(state.findings); populateCategoryFilter();
};
window._cancelJob = async function(jobId) {
  const r = await apiFetch(`/api/scans/${jobId}/cancel`,{method:'POST',body:'{}'});
  clog(r.ok?`Job ${jobId} canceled.`:`Cancel failed.`,r.ok?'warn':'crit');
  window.loadQueue();
};

// ─── Findings ─────────────────────────────────────────────────────────────────
window.loadFindings = async function() {
  const wrap = document.getElementById('findings-table-wrap');
  if (!state.currentProject) {
    wrap.innerHTML='<p style="opacity:.5;font-size:12px;">Select a project first.</p>'; return;
  }
  const r = await apiFetch(`/api/scans?projectId=${encodeURIComponent(state.currentProject)}`);
  if (!r.ok) return;
  const done = (r.data.jobs||[]).filter(j=>j.status==='completed');
  if (!done.length) {
    wrap.innerHTML='<p style="opacity:.5;font-size:12px;">No completed scans yet.</p>'; return;
  }
  // Aggregate ALL completed jobs for this project (not just 1)
  const allF = [];
  await Promise.all(done.map(async job => {
    const rr = await apiFetch(`/api/scans/${job.id}/results`);
    if (rr.ok) allF.push(...(rr.data.findings||[]));
  }));
  // Deduplicate by URL+category
  const seen = new Set();
  state.findings = allF.filter(f => {
    const k = `${f.url}|${f.category}|${f.severity}`;
    if (seen.has(k)) return false; seen.add(k); return true;
  });
  state.findingsPage = 0;
  renderFindingsTable(state.findings); populateCategoryFilter();
};

function renderFindingsTable(findings) {
  const sevFilter = document.getElementById('filter-sev').value;
  const catFilter = document.getElementById('filter-cat').value;
  let rows = findings;
  if (sevFilter) rows = rows.filter(f=>f.severity===sevFilter);
  if (catFilter) rows = rows.filter(f=>f.category===catFilter);

  const wrap   = document.getElementById('findings-table-wrap');
  const page   = state.findingsPage;
  const total  = rows.length;
  const paged  = rows.slice(page*FINDINGS_PER_PAGE, (page+1)*FINDINGS_PER_PAGE);

  if (!rows.length) {
    wrap.innerHTML='<p style="opacity:.5;font-size:12px;">No findings match the current filters.</p>'; return;
  }

  const totalPages = Math.ceil(total/FINDINGS_PER_PAGE);
  const paginationBar = totalPages > 1 ? `
    <div class="pagination-bar">
      <button class="btn btn-sm btn-ghost" onclick="changeFindingsPage(-1)" ${page===0?'disabled':''}>← Prev</button>
      <span style="font-size:11px;opacity:.6;">Page ${page+1} / ${totalPages} &nbsp;(${total} total)</span>
      <button class="btn btn-sm btn-ghost" onclick="changeFindingsPage(1)" ${page>=totalPages-1?'disabled':''}>Next →</button>
    </div>` : `<div style="font-size:11px;opacity:.5;margin-bottom:6px;">${total} finding(s)</div>`;

  wrap.innerHTML = `
    ${buildGauge(computeRiskScore(rows))}
    ${paginationBar}
    <table class="findings-table">
      <thead><tr><th>#</th><th>Sev</th><th>Category</th><th>Title</th><th>URL</th><th>HTTP</th><th></th></tr></thead>
      <tbody>
        ${paged.map((f,i)=>`
          <tr style="cursor:pointer;" onclick="openFindingModal(window.__findings[${page*FINDINGS_PER_PAGE+i}])">
            <td>${page*FINDINGS_PER_PAGE+i+1}</td>
            <td>${sevBadge(f.severity)}</td>
            <td style="opacity:.7;font-size:11px;">${escHtml(f.category||'')}</td>
            <td>${escHtml(f.title||'')}</td>
            <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
              <a href="${escHtml(f.url||'')}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${escHtml(f.url||'')}</a>
            </td>
            <td>${escHtml(String(f.statusCode||''))}</td>
            <td><button class="btn btn-sm btn-ghost" onclick="event.stopPropagation();openFindingModal(window.__findings[${page*FINDINGS_PER_PAGE+i}])">Details</button></td>
          </tr>`).join('')}
      </tbody>
    </table>
    ${paginationBar}`;
  window.__findings = rows; // Store filtered rows for modal access
}

window.changeFindingsPage = function(dir) {
  const sevFilter = document.getElementById('filter-sev').value;
  const catFilter = document.getElementById('filter-cat').value;
  let rows = state.findings;
  if (sevFilter) rows = rows.filter(f=>f.severity===sevFilter);
  if (catFilter) rows = rows.filter(f=>f.category===catFilter);
  const totalPages = Math.ceil(rows.length/FINDINGS_PER_PAGE);
  state.findingsPage = Math.min(Math.max(state.findingsPage+dir,0),totalPages-1);
  renderFindingsTable(state.findings);
};

function populateCategoryFilter() {
  const cats = [...new Set(state.findings.map(f=>f.category).filter(Boolean))];
  const el   = document.getElementById('filter-cat');
  el.innerHTML = '<option value="">All Categories</option>' + cats.map(c=>`<option>${escHtml(c)}</option>`).join('');
}
document.getElementById('filter-sev').addEventListener('change', ()=>{ state.findingsPage=0; renderFindingsTable(state.findings); });
document.getElementById('filter-cat').addEventListener('change', ()=>{ state.findingsPage=0; renderFindingsTable(state.findings); });

// ─── Dorks ────────────────────────────────────────────────────────────────────
document.getElementById('btn-gen-dorks').addEventListener('click', async () => {
  const domain = document.getElementById('dork-domain-input').value.trim();
  if (!domain) { clog('Enter a domain.','warn'); return; }
  clog(`> dorks ${domain}`,'cmd');
  const r    = await apiFetch(`/api/dorks?domain=${encodeURIComponent(domain)}`);
  const wrap = document.getElementById('dork-results');
  if (!r.ok) { wrap.innerHTML='<p style="opacity:.5;">Backend offline.</p>'; return; }
  const { google=[], github=[], shodan=[] } = r.data;
  function dorkCards(dorks) {
    return dorks.map(d=>`
      <div class="dork-card">
        <div>
          <div class="dork-title">${sevBadge(d.severity)} ${escHtml(d.title)}</div>
          <div class="dork-query">${escHtml(d.rawQuery)}</div>
        </div>
        <a class="btn btn-sm btn-primary" href="${escHtml(d.url)}" target="_blank" rel="noopener">Open ↗</a>
      </div>`).join('');
  }
  wrap.innerHTML = `
    <div class="dork-tabs">
      <button class="dork-tab active" onclick="switchDorkTab(this,'dt-google')">🔍 Google (${google.length})</button>
      <button class="dork-tab"        onclick="switchDorkTab(this,'dt-github')">🐙 GitHub (${github.length})</button>
      <button class="dork-tab"        onclick="switchDorkTab(this,'dt-shodan')">📡 Shodan (${shodan.length})</button>
    </div>
    <div class="dork-tab-panel active" id="dt-google">${dorkCards(google)}</div>
    <div class="dork-tab-panel"        id="dt-github">${dorkCards(github)}</div>
    <div class="dork-tab-panel"        id="dt-shodan">${dorkCards(shodan)}</div>`;
  clog(`Generated ${google.length} Google + ${github.length} GitHub + ${shodan.length} Shodan dorks for ${domain}`,'ok');
});
window.switchDorkTab = function(btn, panelId) {
  btn.closest('.dork-tabs').querySelectorAll('.dork-tab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  btn.closest('.dork-results-inner,.page')?.querySelectorAll('.dork-tab-panel').forEach(p=>p.classList.remove('active'));
  document.getElementById(panelId)?.classList.add('active');
  const parent = document.getElementById(panelId)?.parentElement;
  if (parent) parent.querySelectorAll('.dork-tab-panel').forEach(p=>p.classList.toggle('active',p.id===panelId));
};

// ─── Reports ──────────────────────────────────────────────────────────────────
window.loadReports = async function() {
  const qs = state.currentProject ? `?projectId=${encodeURIComponent(state.currentProject)}` : '';
  const r  = await apiFetch(`/api/scans${qs}`);
  const el = document.getElementById('report-list');
  if (!r.ok) { el.innerHTML='<p style="opacity:.5;">Backend offline.</p>'; return; }
  const done = (r.data.jobs||[]).filter(j=>j.status==='completed');
  if (!done.length) { el.innerHTML='<p style="opacity:.5;font-size:12px;">No completed scans yet.</p>'; return; }
  el.innerHTML = done.map(j=>`
    <div class="job-card">
      <div>
        <div class="job-desc">${escHtml(j.description||j.projectId)}</div>
        <div class="job-id">
          ${escHtml(j.id)} &nbsp;|&nbsp;
          ${j.findingCount!=null?`${j.findingCount} findings &nbsp;|&nbsp;`:''}
          ${timeAgo(j.completedAt)}
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        <a class="btn btn-sm btn-primary" href="${escHtml(CFG.backendUrl)}/api/scans/${escHtml(j.id)}/report.html" target="_blank">HTML Report</a>
        <a class="btn btn-sm btn-ghost"   href="${escHtml(CFG.backendUrl)}/api/scans/${escHtml(j.id)}/report.md"   target="_blank">Markdown</a>
        <button class="btn btn-sm btn-ghost" onclick="window._copyReportUrl('${escHtml(j.id)}')">📋 Copy URL</button>
      </div>
    </div>`).join('');
};
window._copyReportUrl = function(jobId) {
  const url = `${CFG.backendUrl}/api/scans/${jobId}/report.html`;
  navigator.clipboard?.writeText(url).then(()=>toast('Report URL copied','ok'));
};

// ─── Settings ─────────────────────────────────────────────────────────────────
document.getElementById('setting-backend-url').value = CFG.backendUrl;
document.getElementById('setting-auth-note').value   = CFG.authNote;
document.getElementById('btn-save-settings').addEventListener('click', () => {
  const url  = document.getElementById('setting-backend-url').value.trim();
  const note = document.getElementById('setting-auth-note').value.trim();
  if (url)  { CFG.backendUrl=url;  localStorage.setItem('wvc_backend_url',url);  }
  if (note) { CFG.authNote=note;  localStorage.setItem('wvc_auth_note',note);   }
  document.getElementById('settings-saved').style.display='block';
  setTimeout(()=>document.getElementById('settings-saved').style.display='none',2500);
  clog('Settings saved. Pinging backend...','info');
  pingBackend();
});

// ─── Dashboard ────────────────────────────────────────────────────────────────
async function loadDashboard() {
  const statRow = document.getElementById('stat-row');
  const recEl   = document.getElementById('recent-findings');
  const targetCount = Object.values(state.targets).flat().length;
  const r = await apiFetch('/api/scans');
  let jobs=[], allFindings=[];
  if (r.ok) {
    jobs = r.data.jobs||[];
    // Aggregate findings from ALL completed jobs
    const done = jobs.filter(j=>j.status==='completed');
    const results = await Promise.all(done.slice(0,10).map(j=>apiFetch(`/api/scans/${j.id}/results`)));
    results.forEach(rr=>{ if(rr.ok) allFindings.push(...(rr.data.findings||[])); });
    // Deduplicate
    const seen=new Set();
    allFindings = allFindings.filter(f=>{ const k=`${f.url}|${f.category}`; if(seen.has(k))return false; seen.add(k); return true; });
  }
  const score    = computeRiskScore(allFindings);
  const crit     = allFindings.filter(f=>f.severity==='critical').length;
  const high     = allFindings.filter(f=>f.severity==='high').length;
  const medium   = allFindings.filter(f=>f.severity==='medium').length;
  const jobsDone = jobs.filter(j=>j.status==='completed').length;
  const jobsRun  = jobs.filter(j=>j.status==='running').length;

  statRow.innerHTML = [
    {num:state.projects.length, lbl:'Projects',     color:''},
    {num:targetCount,           lbl:'Targets',       color:''},
    {num:jobs.length,           lbl:'Total Jobs',    color:''},
    {num:jobsDone,              lbl:'Completed',     color:'var(--green)'},
    {num:jobsRun,               lbl:'Running',       color:'var(--accent)'},
    {num:crit,                  lbl:'Critical',      color:'var(--red)'},
    {num:high,                  lbl:'High',          color:'var(--orange)'},
    {num:medium,                lbl:'Medium',        color:'var(--yellow)'},
    {num:allFindings.length,    lbl:'Total Findings',color:''},
  ].map(s=>`
    <div class="stat-box">
      <div class="num" style="color:${s.color||'var(--accent)'}">${s.num}</div>
      <div class="lbl">${s.lbl}</div>
    </div>`).join('');

  // Risk gauge on dashboard
  const gaugeEl = document.getElementById('dashboard-risk-gauge');
  if (gaugeEl) gaugeEl.innerHTML = buildGauge(score);

  const topFindings = allFindings.filter(f=>['critical','high'].includes(f.severity)).slice(0,10);
  state.findings = allFindings;

  recEl.innerHTML = topFindings.length
    ? `<table class="findings-table">
        <thead><tr><th>Sev</th><th>Category</th><th>Title</th><th>URL</th><th></th></tr></thead>
        <tbody>
          ${topFindings.map((f,i)=>`
            <tr style="cursor:pointer;" onclick="openFindingModal(window.__dashFindings[${i}])">
              <td>${sevBadge(f.severity)}</td>
              <td style="opacity:.7;font-size:11px;">${escHtml(f.category||'')}</td>
              <td>${escHtml(f.title||'')}</td>
              <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                <a href="${escHtml(f.url||'')}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${escHtml(f.url||'')}</a>
              </td>
              <td><button class="btn btn-sm btn-ghost" onclick="event.stopPropagation();openFindingModal(window.__dashFindings[${i}])">Details</button></td>
            </tr>`).join('')}
        </tbody>
      </table>`
    : '<p style="opacity:.5;font-size:12px;">No high/critical findings yet. Run your first scan.</p>';
  window.__dashFindings = topFindings;
}

// ─── Console commands ─────────────────────────────────────────────────────────
const consoleInput = document.getElementById('console-input');
const CMD_HISTORY  = []; let histIdx = -1;
consoleInput.addEventListener('keydown', async e => {
  if (e.key==='ArrowUp')   { histIdx=Math.min(histIdx+1,CMD_HISTORY.length-1); consoleInput.value=CMD_HISTORY[histIdx]||''; return; }
  if (e.key==='ArrowDown') { histIdx=Math.max(histIdx-1,-1); consoleInput.value=histIdx<0?'':CMD_HISTORY[histIdx]; return; }
  if (e.key!=='Enter') return;
  const raw = consoleInput.value.trim(); if (!raw) return;
  CMD_HISTORY.unshift(raw); if(CMD_HISTORY.length>50) CMD_HISTORY.pop();
  histIdx=-1; consoleInput.value='';
  clog(`> ${raw}`,'cmd');
  const parts = raw.split(/\s+/); const cmd = parts[0].toLowerCase();
  const CMDS = {
    help: () => [
      'help                        – this menu',
      'ping                        – check backend connection',
      'clear                       – clear console',
      'status                      – current project + targets + risk score',
      'show <page>                 – navigate: dashboard|queue|findings|targets|dorks|reports|projects|settings',
      'dorks <domain>              – generate dork queries for domain',
      'scan                        – run scan on current project targets',
      'project <name>              – create new project',
      'add target <url>            – add target to current project',
      'targets                     – list current targets',
      'results <jobId>             – load findings from job',
      'risk                        – show risk score for loaded findings',
      'export                      – export current project as JSON',
    ].forEach(l=>clog(l,'info')),
    ping:   () => pingBackend(),
    clear:  () => { consoleEl.innerHTML=''; clog('Console cleared.','info'); },
    status: () => {
      const p = state.projects.find(x=>x.id===state.currentProject);
      const score = computeRiskScore(state.findings);
      clog(`Project: ${p?p.name:'none'} | Targets: ${getTargets().length} | Findings: ${state.findings.length} | Risk: ${score}/100 (${riskLabel(score)})`,'info');
    },
    risk: () => {
      const score = computeRiskScore(state.findings);
      clog(`Risk Score: ${score}/100 — ${riskLabel(score)} | ${state.findings.filter(f=>f.severity==='critical').length} critical, ${state.findings.filter(f=>f.severity==='high').length} high`,'info');
    },
    show: () => {
      const sub = (parts[1]||'').toLowerCase();
      const valid = ['dashboard','queue','findings','targets','dorks','reports','projects','settings'];
      if (valid.includes(sub)) { showPage(sub); return; }
      clog(`Unknown page. Options: ${valid.join(', ')}`,'warn');
    },
    dorks: () => {
      const domain = parts[1]; if (!domain) { clog('Usage: dorks <domain>','warn'); return; }
      document.getElementById('dork-domain-input').value = domain;
      showPage('dorks'); document.getElementById('btn-gen-dorks').click();
    },
    scan: () => document.getElementById('btn-run-scan').click(),
    project: () => {
      const name = parts.slice(1).join(' '); if(!name) { clog('Usage: project <name>','warn'); return; }
      const id = uid();
      state.projects.push({id,name,createdAt:new Date().toISOString()});
      saveState(); selectProject(id); renderProjectSelect(); renderProjectList();
      clog(`Project created: ${name} [${id}]`,'ok');
    },
    add: () => {
      if ((parts[1]||'').toLowerCase()!=='target') { clog('Usage: add target <url>','warn'); return; }
      const url = parts[2]; if(!url) { clog('Usage: add target <url>','warn'); return; }
      if (!state.currentProject) { clog('Select a project first.','warn'); return; }
      if (!state.targets[state.currentProject]) state.targets[state.currentProject]=[];
      if (state.targets[state.currentProject].includes(url)) { clog('Target already exists.','warn'); return; }
      state.targets[state.currentProject].push(url);
      saveState(); renderTargetList();
      clog(`Target added: ${url}`,'ok'); toast(`Target added: ${url}`,'ok');
    },
    targets: () => {
      const t = getTargets();
      if (!t.length) { clog('No targets in current project.','warn'); return; }
      t.forEach((url,i)=>clog(`  ${i+1}. ${url}`,'info'));
    },
    results: async () => {
      const jobId = parts[1]; if(!jobId) { clog('Usage: results <jobId>','warn'); return; }
      await window._viewResults(jobId);
    },
    export: () => {
      if (!state.currentProject) { clog('Select a project first.','warn'); return; }
      window._exportProject(state.currentProject);
    },
  };
  if (CMDS[cmd]) await CMDS[cmd]();
  else clog(`Unknown command: "${cmd}". Type help.`,'warn');
});

// ─── Dynamic styles ───────────────────────────────────────────────────────────
const dynStyle = document.createElement('style');
dynStyle.textContent = `
/* Toast */
.toast{position:fixed;bottom:20px;right:20px;z-index:9999;padding:10px 18px;
  background:#0f172a;border:1px solid #1f2937;border-radius:6px;font-size:12px;
  color:#e5e7eb;font-family:monospace;opacity:0;transform:translateY(10px);
  transition:opacity .3s,transform .3s;pointer-events:none;}
.toast-show{opacity:1;transform:translateY(0);}
.toast-ok{border-color:#22c55e60;color:#22c55e;}
.toast-warn{border-color:#eab30860;color:#eab308;}
.toast-crit{border-color:#ef444460;color:#ef4444;}
/* Modal */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:8000;
  display:flex;align-items:center;justify-content:center;padding:16px;}
.modal-overlay.hidden{display:none;}
.modal-box{background:#0f172a;border:1px solid #1e293b;border-radius:10px;
  width:100%;max-width:680px;max-height:90vh;overflow-y:auto;
  display:flex;flex-direction:column;gap:0;}
.modal-header{display:flex;align-items:center;padding:14px 16px 0;
  border-bottom:1px solid #1e293b;padding-bottom:12px;}
.modal-close{margin-left:auto;background:none;border:none;color:#6b7280;
  font-size:16px;cursor:pointer;line-height:1;padding:2px 6px;}
.modal-close:hover{color:#e5e7eb;}
.modal-title{padding:14px 16px 6px;font-size:15px;font-weight:700;color:#f1f5f9;line-height:1.4;}
.modal-meta{padding:0 16px 10px;display:flex;flex-direction:column;gap:8px;}
.modal-meta>div{display:flex;gap:8px;flex-wrap:wrap;align-items:baseline;font-size:12px;}
.modal-meta-label{color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.05em;min-width:80px;}
.modal-snippet{background:#020617;border:1px solid #1e293b;border-radius:4px;
  padding:10px;font-size:11px;color:#94a3b8;overflow-x:auto;max-height:180px;
  overflow-y:auto;white-space:pre-wrap;word-break:break-all;margin:0 16px 10px;}
.modal-footer{padding:0 16px 10px;border-top:1px solid #1e293b;padding-top:12px;}
.modal-actions{padding:10px 16px 14px;display:flex;gap:8px;flex-wrap:wrap;
  border-top:1px solid #1e293b;}
/* Risk gauge */
.risk-gauge{margin:10px 0 14px;}
.risk-gauge-label{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin-bottom:4px;}
.risk-gauge-track{height:8px;background:#1e293b;border-radius:4px;overflow:hidden;}
.risk-gauge-fill{height:100%;border-radius:4px;transition:width .6s ease;}
.risk-gauge-score{font-size:22px;font-weight:800;margin-top:4px;font-family:monospace;}
.risk-gauge-score span{font-size:13px;opacity:.5;}
/* Dork tabs */
.dork-tabs{display:flex;gap:4px;margin:12px 0 0;border-bottom:1px solid #1e293b;}
.dork-tab{background:none;border:none;border-bottom:2px solid transparent;color:#64748b;
  font-size:12px;font-family:monospace;padding:6px 12px;cursor:pointer;transition:all .2s;}
.dork-tab:hover{color:#e2e8f0;}
.dork-tab.active{color:var(--accent);border-bottom-color:var(--accent);}
.dork-tab-panel{display:none;padding-top:8px;}
.dork-tab-panel.active{display:block;}
/* Pagination */
.pagination-bar{display:flex;align-items:center;gap:10px;padding:8px 0;
  border-bottom:1px solid #1e293b;margin-bottom:8px;}
/* Mobile sidebar */
@media(max-width:640px){
  .sidebar{position:fixed;left:-240px;top:0;height:100vh;z-index:500;
    transition:left .25s ease;box-shadow:none;}
  .sidebar.sidebar-open{left:0;box-shadow:4px 0 24px #000a;}
  .main{margin-left:0!important;}
  #hamburger-btn{display:flex!important;}
}
/* Yellow for medium */
:root{--yellow:#eab308;}
`;
document.head.appendChild(dynStyle);

// ─── Init ─────────────────────────────────────────────────────────────────────
if (sessionStorage.getItem('wvc_tos')==='yes') loadDashboard();
