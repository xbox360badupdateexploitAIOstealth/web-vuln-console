// src/ui/views/jobConsoleView.js
// Scan job console view.
//
// Features:
//   ─ Target URL input (not hardcoded) + env/type selectors
//   ─ Policy selector populated from policyRegistry
//   ─ Uses jobQueue.enqueue() → runPersistedJob() → all results written to db
//   ─ Live log stream via onProgress callback
//   ─ Queue status badge (running / queued count)
//   ─ Active project context pulled from state (falls back to ad-hoc project)
//   ─ Job history table loaded from db on mount, refreshes after each run
//   ─ Abort button (cancels queued job; shows notice if already running)
//   ─ Findings summary table inline after scan completes
//   ─ State bus: listens to 'project' so active project badge updates live

import { jobQueue }          from '../../core/jobQueue.js';
import { EngineConfig }      from '../../core/engine.js';
import { Project, Target, ScanJob } from '../../core/models.js';
import { scanPolicies }      from '../../core/policyRegistry.js';
import { db, S }             from '../../core/db.js';
import { state, setLastScanContext } from '../state.js';

// ── Module-level refs ────────────────────────────────────────────────────────
let _container   = null;
let _unsubscribe = null;
let _activeJobId = null;   // id of the job we most recently enqueued

// ── Severity colour map ──────────────────────────────────────────────────────
const SEV_COLOR = {
  critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280',
};

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
export async function renderJobConsole(container) {
  _container = container;
  if (_unsubscribe) { _unsubscribe(); _unsubscribe = null; }

  container.innerHTML = _shell();
  _populatePolicies();
  _updateProjectBadge();
  await _loadHistory();
  _renderQueueBadge();

  // Wire events
  container.querySelector('#jc-run-btn').addEventListener('click', _handleRun);
  container.querySelector('#jc-abort-btn').addEventListener('click', _handleAbort);
  container.querySelector('#jc-target').addEventListener('keydown', e => {
    if (e.key === 'Enter') _handleRun();
  });
  container.querySelector('#jc-clear-log').addEventListener('click', () => {
    container.querySelector('#jc-log').textContent = '';
  });

  // Subscribe to project changes → update badge
  const _onProject = () => _updateProjectBadge();
  state.on('project', _onProject);
  _unsubscribe = () => state.off('project', _onProject);
}

// ─────────────────────────────────────────────────────────────────────────────
// Shell
// ─────────────────────────────────────────────────────────────────────────────
function _shell() {
  return `
  <div style="max-width:860px;">

    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;
      flex-wrap:wrap;gap:8px;margin-bottom:14px;">
      <div>
        <h1 style="margin:0;font-size:18px;">Scan Console</h1>
        <div id="jc-project-badge" style="font-size:11px;color:#64748b;margin-top:3px;"></div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;">
        <span id="jc-queue-badge" style="font-size:11px;"></span>
      </div>
    </div>

    <!-- Config card -->
    <div style="${_card()}margin-bottom:12px;">
      <div style="display:grid;grid-template-columns:1fr auto auto;gap:10px;align-items:end;">

        <!-- Target input -->
        <div>
          <label style="${_lbl()}">Target URL / Host</label>
          <input id="jc-target" type="text" placeholder="https://example.com"
            style="${_inp()}font-family:monospace;" />
        </div>

        <!-- Policy -->
        <div style="min-width:140px;">
          <label style="${_lbl()}">Scan Policy</label>
          <select id="jc-policy" style="${_sel()}"></select>
        </div>

        <!-- Env -->
        <div style="min-width:100px;">
          <label style="${_lbl()}">Environment</label>
          <select id="jc-env" style="${_sel()}">
            <option value="lab">lab</option>
            <option value="dev">dev</option>
            <option value="staging">staging</option>
            <option value="prod">prod</option>
          </select>
        </div>
      </div>

      <!-- Action row -->
      <div style="display:flex;gap:8px;margin-top:12px;align-items:center;flex-wrap:wrap;">
        <button id="jc-run-btn" style="${_btn('#38bdf8','#020617')}">▶ Run Scan</button>
        <button id="jc-abort-btn"
          style="${_btn('#ef444418','#ef4444')}border:1px solid #ef444444;display:none;">
          ■ Abort
        </button>
        <span id="jc-run-error" style="font-size:11px;color:#ef4444;"></span>
      </div>
    </div>

    <!-- Log card -->
    <div style="${_card()}margin-bottom:12px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-size:11px;font-weight:700;color:#64748b;
          text-transform:uppercase;letter-spacing:.07em;">
          💻 Console Log
          <span id="jc-status-pill" style="margin-left:8px;"></span>
        </div>
        <button id="jc-clear-log"
          style="background:none;border:none;color:#475569;font-size:10px;cursor:pointer;">
          Clear
        </button>
      </div>
      <pre id="jc-log"
        style="margin:0;font-size:11px;background:#020617;border:1px solid #0f172a;
          border-radius:5px;padding:10px;max-height:320px;overflow-y:auto;
          white-space:pre-wrap;word-break:break-all;color:#94a3b8;
          font-family:'Cascadia Code','Fira Mono',monospace;"></pre>
    </div>

    <!-- Findings summary (injected after scan) -->
    <div id="jc-findings-summary" style="display:none;${_card()}margin-bottom:12px;"></div>

    <!-- Job history -->
    <div style="${_card()}">
      <div style="font-size:11px;font-weight:700;color:#64748b;
        text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px;">
        📜 Job History
      </div>
      <div id="jc-history"></div>
    </div>

  </div>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Run scan
// ─────────────────────────────────────────────────────────────────────────────
async function _handleRun() {
  const errEl  = _container.querySelector('#jc-run-error');
  errEl.textContent = '';

  const targetStr = (_container.querySelector('#jc-target').value || '').trim();
  if (!targetStr) {
    errEl.textContent = 'Enter a target URL or host.';
    _flash(_container.querySelector('#jc-target'));
    return;
  }

  const policyId = _container.querySelector('#jc-policy').value;
  const env      = _container.querySelector('#jc-env').value;

  // Resolve active project or create a transient one
  const project = state.currentProject || new Project({
    workspaceId : 'ws_default',
    name        : 'Ad-hoc Scan',
    clientName  : '',
    authNotes   : 'Transient ad-hoc project created from Scan Console.',
  });

  const target = new Target({
    projectId : project.id,
    host      : _normaliseUrl(targetStr),
    type      : 'website',
    env,
  });

  const job = new ScanJob({
    projectId  : project.id,
    policyId,
    targetIds  : [target.id],
    initiatedBy: 'user',
    initSource : 'ui',
  });

  _activeJobId = job.id;

  // UI state → running
  _setRunning(true);
  const logEl = _container.querySelector('#jc-log');
  logEl.textContent = '';
  _log(`[${_ts()}] Job ${job.id}`);
  _log(`[${_ts()}] Target: ${target.host}`);
  _log(`[${_ts()}] Policy: ${policyId}`);
  _log(`[${_ts()}] Queuing…`);
  _renderQueueBadge();

  const engineConfig = new EngineConfig({
    fetchAdapter    : _browserFetch(),
    baseUrlResolver : (t) => t.host,
  });

  try {
    const ctx = await jobQueue.enqueue({
      jobInput     : job,
      project,
      targets      : [target],
      engineConfig,
      onProgress   : (c) => {
        _log(`[${_ts()}] Progress — findings: ${c.findings.length}, requests: ${c.evidences.length}`);
        _renderQueueBadge();
      },
    });

    setLastScanContext(ctx);

    _log(`[${_ts()}] ✓ Scan complete.`);
    _log(`[${_ts()}] Findings  : ${ctx.findings.length}`);
    _log(`[${_ts()}] Evidences : ${ctx.evidences.length}`);
    ctx.logs.forEach(l => _log(l));

    _setStatusPill('done');
    _renderFindingsSummary(ctx);
    await _loadHistory();

  } catch (err) {
    _log(`[${_ts()}] ✗ Error: ${err.message || err}`);
    _setStatusPill('error');
  } finally {
    _setRunning(false);
    _activeJobId = null;
    _renderQueueBadge();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abort
// ─────────────────────────────────────────────────────────────────────────────
function _handleAbort() {
  if (!_activeJobId) return;
  const cancelled = jobQueue.cancel(_activeJobId);
  if (cancelled) {
    _log(`[${_ts()}] Job ${_activeJobId} cancelled before it started.`);
    _setRunning(false);
    _activeJobId = null;
    _renderQueueBadge();
  } else {
    _log(`[${_ts()}] Job is already running — cannot abort mid-scan.`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Job history
// ─────────────────────────────────────────────────────────────────────────────
async function _loadHistory() {
  if (!_container) return;
  const histEl = _container.querySelector('#jc-history');
  if (!histEl) return;

  let jobs = [];
  try {
    const all = await db.getAll(S.SCAN_JOBS);
    jobs = all
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 20);
  } catch (_) {}

  if (!jobs.length) {
    histEl.innerHTML = `<div style="font-size:12px;color:#475569;padding:8px 0;">
      No jobs recorded yet.</div>`;
    return;
  }

  histEl.innerHTML = `
    <table style="width:100%;border-collapse:collapse;font-size:11px;">
      <thead>
        <tr style="border-bottom:2px solid #1e293b;">
          <th style="${_th()}">Job ID</th>
          <th style="${_th()}">Policy</th>
          <th style="${_th()}width:80px;">Status</th>
          <th style="${_th()}width:80px;">Findings</th>
          <th style="${_th()}width:80px;">Requests</th>
          <th style="${_th()}width:140px;">Started</th>
          <th style="${_th()}width:70px;">Duration</th>
        </tr>
      </thead>
      <tbody>
        ${jobs.map(_historyRow).join('')}
      </tbody>
    </table>`;
}

function _historyRow(j) {
  const statusMap = {
    done   : ['#22c55e', '✓ done'],
    running: ['#38bdf8', '▶ running'],
    queued : ['#eab308', '⏳ queued'],
    error  : ['#ef4444', '✗ error'],
  };
  const [col, label] = statusMap[j.status] || ['#6b7280', j.status];
  const started  = j.startedAt  ? new Date(j.startedAt).toLocaleString()  : '—';
  const duration = (j.startedAt && j.finishedAt)
    ? `${Math.round((new Date(j.finishedAt) - new Date(j.startedAt)) / 1000)}s`
    : '—';
  return `
    <tr style="border-bottom:1px solid #0f172a;">
      <td style="padding:5px 8px;font-family:monospace;color:#64748b;"
        title="${_esc(j.id)}">${_esc(j.id.slice(0,14))}…</td>
      <td style="padding:5px 8px;color:#94a3b8;">${_esc(j.policyId||'—')}</td>
      <td style="padding:5px 8px;">
        <span style="color:${col};font-weight:600;">${label}</span>
      </td>
      <td style="padding:5px 8px;text-align:right;color:#e2e8f0;">${j.stats?.numFindings ?? '—'}</td>
      <td style="padding:5px 8px;text-align:right;color:#94a3b8;">${j.stats?.numRequests ?? '—'}</td>
      <td style="padding:5px 8px;color:#475569;">${started}</td>
      <td style="padding:5px 8px;color:#475569;">${duration}</td>
    </tr>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Findings summary (inline after scan)
// ─────────────────────────────────────────────────────────────────────────────
function _renderFindingsSummary(ctx) {
  const wrap = _container.querySelector('#jc-findings-summary');
  if (!wrap) return;

  if (!ctx.findings.length) {
    wrap.style.display = 'none';
    return;
  }

  const sorted = [...ctx.findings].sort((a, b) => {
    const order = { critical:1, high:2, medium:3, low:4, info:5 };
    return (order[a.severity]||9) - (order[b.severity]||9);
  });

  wrap.style.display = 'block';
  wrap.innerHTML = `
    <div style="font-size:11px;font-weight:700;color:#64748b;
      text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px;">
      🔍 Findings (${sorted.length})
      <span style="font-size:10px;font-weight:400;opacity:.6;margin-left:6px;">
        Open Findings view for full details &amp; evidence.
      </span>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:11px;">
      <thead>
        <tr style="border-bottom:2px solid #1e293b;">
          <th style="${_th()}width:80px;">Severity</th>
          <th style="${_th()}">Title</th>
          <th style="${_th()}width:100px;">Category</th>
          <th style="${_th()}">URL</th>
        </tr>
      </thead>
      <tbody>
        ${sorted.map(f => {
          const col = SEV_COLOR[f.severity] || '#6b7280';
          return `
          <tr style="border-bottom:1px solid #0f172a;">
            <td style="padding:5px 8px;">
              <span style="background:${col}22;color:${col};border:1px solid ${col}55;
                padding:2px 6px;border-radius:4px;font-size:9px;font-weight:700;
                text-transform:uppercase;">${_esc(f.severity||'info')}</span>
            </td>
            <td style="padding:5px 8px;color:#e2e8f0;font-weight:500;">${_esc(f.title||'')}</td>
            <td style="padding:5px 8px;color:#64748b;">${_esc(f.category||'')}</td>
            <td style="padding:5px 8px;font-family:monospace;font-size:10px;color:#38bdf8;
              max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
              title="${_esc(f.url||'')}">${_esc(f.url||'—')}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// UI helpers
// ─────────────────────────────────────────────────────────────────────────────
function _populatePolicies() {
  const sel = _container.querySelector('#jc-policy');
  if (!sel) return;
  sel.innerHTML = scanPolicies.map(p =>
    `<option value="${_esc(p.id)}">${_esc(p.name)}</option>`
  ).join('');
}

function _updateProjectBadge() {
  const el = _container?.querySelector('#jc-project-badge');
  if (!el) return;
  const p = state.currentProject;
  el.innerHTML = p
    ? `Project: <strong style="color:#38bdf8;">${_esc(p.name)}</strong>`
    : `<span style="color:#ef4444;">No project selected — scan will create an ad-hoc project.</span>`;
}

function _setRunning(running) {
  if (!_container) return;
  const runBtn   = _container.querySelector('#jc-run-btn');
  const abortBtn = _container.querySelector('#jc-abort-btn');
  const targetIn = _container.querySelector('#jc-target');
  if (runBtn)   { runBtn.disabled = running; runBtn.textContent = running ? '⏳ Scanning…' : '▶ Run Scan'; }
  if (abortBtn) { abortBtn.style.display = running ? 'inline-flex' : 'none'; }
  if (targetIn) { targetIn.disabled = running; }
  if (!running) _setStatusPill('');
}

function _setStatusPill(status) {
  const el = _container?.querySelector('#jc-status-pill');
  if (!el) return;
  const map = {
    done : ['#22c55e', '✓ Complete'],
    error: ['#ef4444', '✗ Error'],
    ''   : ['', ''],
  };
  const [col, label] = map[status] || ['#eab308', status];
  el.innerHTML = label
    ? `<span style="color:${col};font-weight:700;font-size:11px;">${label}</span>`
    : '';
}

function _renderQueueBadge() {
  const el = _container?.querySelector('#jc-queue-badge');
  if (!el) return;
  const { running, queued } = jobQueue.status();
  if (!running && queued === 0) { el.textContent = ''; return; }
  const parts = [];
  if (running) parts.push(`<span style="color:#38bdf8;">▶ 1 running</span>`);
  if (queued)  parts.push(`<span style="color:#eab308;">${queued} queued</span>`);
  el.innerHTML = parts.join(' &nbsp;·&nbsp; ');
}

function _log(line) {
  const el = _container?.querySelector('#jc-log');
  if (!el) return;
  el.textContent += line + '\n';
  el.scrollTop = el.scrollHeight;
}

function _ts() {
  return new Date().toTimeString().slice(0, 8);
}

function _normaliseUrl(raw) {
  const s = raw.trim();
  if (/^https?:\/\//i.test(s)) return s;
  // bare host → assume https
  return `https://${s}`;
}

function _browserFetch() {
  return async ({ method, url, headers, body }) => {
    const res  = await fetch(url, { method, headers, body, mode: 'cors' });
    const text = await res.text();
    const hdrs = {};
    res.headers.forEach((v, k) => { hdrs[k] = v; });
    return { status: res.status, headers: hdrs, body: text };
  };
}

function _flash(el) {
  if (!el) return;
  el.style.borderColor = '#ef4444';
  setTimeout(() => { el.style.borderColor = ''; }, 1400);
}

function _esc(s) {
  return String(s||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Style helpers ─────────────────────────────────────────────────────────────
function _card()  { return 'background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;'; }
function _inp()   { return 'width:100%;background:#020617;border:1px solid #1e293b;border-radius:5px;color:#e2e8f0;font-size:12px;padding:7px 10px;outline:none;box-sizing:border-box;'; }
function _sel()   { return 'width:100%;background:#0f172a;border:1px solid #1e293b;border-radius:5px;color:#e2e8f0;font-size:12px;padding:6px 8px;outline:none;'; }
function _lbl()   { return 'display:block;font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:3px;'; }
function _btn(bg,fg) { return `background:${bg};color:${fg};border:none;border-radius:5px;padding:7px 14px;font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap;font-family:inherit;display:inline-flex;align-items:center;gap:5px;`; }
function _th()    { return 'text-align:left;padding:5px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#64748b;'; }
