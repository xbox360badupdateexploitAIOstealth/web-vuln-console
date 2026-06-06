/* =============================================================
   WebVulnConsole ⚡ app.js – Full client logic v3
   Task 4: Rich Projects UI — inline modal, per-project stats,
   finding breakdowns, risk badges, quick-launch scan.
   All previous functionality preserved + enhanced.
   ============================================================= */
'use strict';

// ─── Config ───────────────────────────────────────────────────────────────
let CFG = {
  backendUrl: localStorage.getItem('wvc_backend_url') || 'http://127.0.0.1:8787',
  authNote:   localStorage.getItem('wvc_auth_note')   || '',
};

// ─── State ────────────────────────────────────────────────────────────────
let state = {
  currentProject: localStorage.getItem('wvc_current_project') || null,
  projects:  JSON.parse(localStorage.getItem('wvc_projects') || '[]'),
  targets:   JSON.parse(localStorage.getItem('wvc_targets')  || '{}'),
  jobs:      [],
  findings:  [],
  findingsPage: 0,
  // Per-project stats cache: { [projectId]: { crit, high, medium, low, info, total, score, lastScan } }
  projectStats: {},
};
const FINDINGS_PER_PAGE = 50;

function saveState() {
  localStorage.setItem('wvc_projects', JSON.stringify(state.projects));
  localStorage.setItem('wvc_targets',  JSON.stringify(state.targets));
  if (state.currentProject) localStorage.setItem('wvc_current_project', state.currentProject);
}

// ─── API helpers ───────────────────────────────────────────────────────────
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

// ─── Micro utils ──────────────────────────────────────────────────────────
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

// ─── Console ──────────────────────────────────────────────────────────────
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

// ─── Backend health ────────────────────────────────────────────────────────
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

// ─── ToS modal ────────────────────────────────────────────────────────────
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

// ─── Navigation ───────────────────────────────────────────────────────────
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
                    dashboard:loadDashboard, projects:loadProjectsPage, targets:renderTargetList };
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

// ─── Risk score gauge ─────────────────────────────────────────────────────────
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
  return `
    <div class="risk-gauge">
      <div class="risk-gauge-label" style="color:${color}">${label}</div>
      <div class="risk-gauge-track">
        <div class="risk-gauge-fill" style="width:${score}%;background:${color};"></div>
      </div>
      <div class="risk-gauge-score" style="color:${color}">${score}<span>/100</span></div>
    </div>`;
}

// ─── Finding detail modal ───────────────────────────────────────────────────────
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
        <div><span class="modal-meta-label">HTTP Status</span><span id="modal-status"></span></div>
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
        <button class="btn btn-sm btn-primary" id="modal-btn-confirm">✓ Mark Confirmed</button>
        <button class="btn btn-sm btn-ghost"   id="modal-btn-mitigate">🛡 Mark Mitigated</button>
        <button class="btn btn-sm btn-ghost"   id="modal-btn-copy">📋 Copy URL</button>
        <button class="btn btn-sm btn-danger"  id="modal-close-btn2">Close</button>
      </div>
    </div>`;
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
  TLS:            'Enable HTTPS, configure HSTS (max-age≥31536000), add all missing security headers. Test with securityheaders.com.',
  CORS:           'Restrict Access-Control-Allow-Origin to your own domain. Never reflect arbitrary origins. Avoid using wildcard * with credentialed requests.',
  REDIRECT:       'Force HTTPS via HSTS. Ensure your server does not redirect HTTPS traffic to HTTP.',
  OPEN_REDIRECT:  'Validate redirect destinations against an allowlist. Reject or sanitize user-supplied redirect URLs.',
  PATH_TRAVERSAL: 'Validate and sanitize all file path inputs. Use chroot jails or allowlisted directory access. Ensure web server does not serve files outside web root.',
  EXPOSURE:       'Restrict access to sensitive files and directories. Ensure backups, logs, and config files are not web-accessible.',
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
  noteRow.style.display = (f.note||'') ? 'block' : 'none';
  document.getElementById('modal-note').textContent = f.note || '';
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

// ─────────────────────────────────────────────────────────────────────────────
// PROJECTS — NEW INLINE MODAL
// ─────────────────────────────────────────────────────────────────────────────

// Inject the New Project modal once at boot.
(function injectProjectModal() {
  const m = document.createElement('div');
  m.id        = 'proj-modal-overlay';
  m.className = 'modal-overlay hidden';
  m.innerHTML = `
    <div class="modal-box" style="max-width:460px;">
      <div class="modal-header" style="align-items:center;">
        <span style="font-size:14px;font-weight:700;color:var(--text)" id="proj-modal-title">New Project</span>
        <button class="modal-close" id="proj-modal-close">✕</button>
      </div>
      <div style="padding:16px;display:flex;flex-direction:column;gap:12px;">
        <div>
          <label class="settings-label">Project Name <span style="color:var(--red)">*</span></label>
          <input class="input-text" id="proj-input-name"  type="text" placeholder="e.g. ACME Corp Pentest Q2-2026" style="margin-top:4px;" />
        </div>
        <div>
          <label class="settings-label">Client / Ticket ID</label>
          <input class="input-text" id="proj-input-client" type="text" placeholder="e.g. CLIENT-042 or Acme Corp" style="margin-top:4px;" />
        </div>
        <div>
          <label class="settings-label">Scope Note</label>
          <input class="input-text" id="proj-input-scope" type="text" placeholder="e.g. *.acme.com — authorized by Jane Doe" style="margin-top:4px;" />
        </div>
        <div>
          <label class="settings-label">Status</label>
          <select class="select-sm" id="proj-input-status" style="margin-top:4px;width:100%;padding:7px 8px;">
            <option value="active">Active</option>
            <option value="in_review">In Review</option>
            <option value="completed">Completed</option>
            <option value="archived">Archived</option>
          </select>
        </div>
      </div>
      <div class="modal-actions" style="justify-content:flex-end;">
        <button class="btn btn-ghost btn-sm" id="proj-modal-cancel">Cancel</button>
        <button class="btn btn-primary"      id="proj-modal-save">Create Project</button>
      </div>
    </div>`;
  document.body.appendChild(m);

  // Expose for Edit mode: prefill existing project data.
  window._openProjectModal = function(editId = null) {
    const overlay = document.getElementById('proj-modal-overlay');
    const titleEl = document.getElementById('proj-modal-title');
    const saveBtn = document.getElementById('proj-modal-save');
    document.getElementById('proj-input-name').value   = '';
    document.getElementById('proj-input-client').value = '';
    document.getElementById('proj-input-scope').value  = '';
    document.getElementById('proj-input-status').value = 'active';

    if (editId) {
      const p = state.projects.find(x => x.id === editId);
      if (!p) return;
      titleEl.textContent = 'Edit Project';
      saveBtn.textContent = 'Save Changes';
      document.getElementById('proj-input-name').value   = p.name   || '';
      document.getElementById('proj-input-client').value = p.client || '';
      document.getElementById('proj-input-scope').value  = p.scope  || '';
      document.getElementById('proj-input-status').value = p.status || 'active';
      saveBtn.onclick = () => {
        const name = document.getElementById('proj-input-name').value.trim();
        if (!name) { toast('Project name required','warn'); return; }
        p.name   = name;
        p.client = document.getElementById('proj-input-client').value.trim();
        p.scope  = document.getElementById('proj-input-scope').value.trim();
        p.status = document.getElementById('proj-input-status').value;
        saveState(); renderProjectSelect(); loadProjectsPage();
        closeProjectModal();
        toast(`Project updated: ${name}`, 'ok');
        clog(`Project edited: ${name} [${editId}]`, 'ok');
      };
    } else {
      titleEl.textContent = 'New Project';
      saveBtn.textContent = 'Create Project';
      saveBtn.onclick = () => {
        const name = document.getElementById('proj-input-name').value.trim();
        if (!name) { toast('Project name required','warn'); return; }
        const id = uid();
        state.projects.push({
          id,
          name,
          client: document.getElementById('proj-input-client').value.trim(),
          scope:  document.getElementById('proj-input-scope').value.trim(),
          status: document.getElementById('proj-input-status').value,
          createdAt: new Date().toISOString(),
        });
        saveState(); selectProject(id); renderProjectSelect(); loadProjectsPage();
        closeProjectModal();
        toast(`Project created: ${name}`, 'ok');
        clog(`> create project "${name}" [${id}]`, 'cmd');
      };
    }

    overlay.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    document.getElementById('proj-input-name').focus();
  };

  function closeProjectModal() {
    document.getElementById('proj-modal-overlay').classList.add('hidden');
    document.body.style.overflow = '';
  }
  document.getElementById('proj-modal-close').addEventListener('click',  closeProjectModal);
  document.getElementById('proj-modal-cancel').addEventListener('click', closeProjectModal);
  document.getElementById('proj-modal-overlay').addEventListener('click', e => {
    if (e.target === document.getElementById('proj-modal-overlay')) closeProjectModal();
  });
})();

// ── Project list — with stats loading ───────────────────────────────────────────────

const projectSelect = document.getElementById('project-select');
function renderProjectSelect() {
  const cur = state.currentProject;
  projectSelect.innerHTML =
    '<option value="">— Select project —</option>' +
    state.projects.map(p =>
      `<option value="${escHtml(p.id)}" ${p.id===cur?'selected':''}>${escHtml(p.name)}</option>`
    ).join('');
}

// Load projects page: render skeleton cards, then hydrate each with backend stats.
async function loadProjectsPage() {
  renderProjectListSkeleton();
  if (state.projects.length === 0) return;
  // Fetch stats for each project in parallel (fire-and-forget per card).
  await Promise.all(state.projects.map(p => loadProjectStats(p.id)));
  renderProjectCards();
}
window.renderProjectList = loadProjectsPage; // Keep compat alias.

async function loadProjectStats(projectId) {
  const r = await apiFetch(`/api/scans?projectId=${encodeURIComponent(projectId)}`);
  if (!r.ok) return;
  const done = (r.data.jobs||[]).filter(j => j.status === 'completed');
  if (!done.length) {
    state.projectStats[projectId] = { crit:0, high:0, medium:0, low:0, info:0, total:0, score:0, jobCount:(r.data.jobs||[]).length, lastScan: done[0]?.completedAt || null };
    return;
  }
  const allF = [];
  await Promise.all(done.slice(0, 5).map(async j => {
    const rr = await apiFetch(`/api/scans/${j.id}/results`);
    if (rr.ok) allF.push(...(rr.data.findings||[]));
  }));
  const seen = new Set();
  const deduped = allF.filter(f => { const k=`${f.url}|${f.category}|${f.severity}`; if(seen.has(k)) return false; seen.add(k); return true; });
  state.projectStats[projectId] = {
    crit:   deduped.filter(f=>f.severity==='critical').length,
    high:   deduped.filter(f=>f.severity==='high').length,
    medium: deduped.filter(f=>f.severity==='medium').length,
    low:    deduped.filter(f=>f.severity==='low').length,
    info:   deduped.filter(f=>f.severity==='info').length,
    total:  deduped.length,
    score:  computeRiskScore(deduped),
    jobCount: (r.data.jobs||[]).length,
    lastSca