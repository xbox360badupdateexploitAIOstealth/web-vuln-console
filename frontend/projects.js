/* =================================================================
   WebVulnConsole ⚡ — Projects UI  (Task 4)
   Rich project cards with:
   - Per-project finding counts by severity pulled from backend
   - Risk score gauge per project
   - Target count
   - Last scan time
   - Quick-launch scan button
   - Proper create / rename modal (replaces prompt())
   =================================================================
   USAGE: loaded by app.js after DOM ready.
   Exports: initProjectsUI()  — call once on app boot.
   ================================================================= */
'use strict';

// ─── Inject modal HTML once ─────────────────────────────────────────────────
function injectProjectModal() {
  if (document.getElementById('proj-modal-overlay')) return;
  const el = document.createElement('div');
  el.id = 'proj-modal-overlay';
  el.style.cssText = [
    'position:fixed', 'inset:0', 'background:rgba(0,0,0,.78)',
    'z-index:8500', 'display:flex', 'align-items:center',
    'justify-content:center', 'padding:16px',
  ].join(';');
  el.classList.add('hidden');
  el.innerHTML = `
    <div id="proj-modal-box" style="
      background:#0f172a;border:1px solid #1e293b;border-radius:10px;
      width:100%;max-width:440px;padding:24px;display:flex;
      flex-direction:column;gap:14px;">
      <div style="display:flex;align-items:center;justify-content:space-between;">
        <div id="proj-modal-title" style="font-size:15px;font-weight:700;color:#f1f5f9;">New Project</div>
        <button id="proj-modal-close" style="background:none;border:none;color:#6b7280;font-size:16px;cursor:pointer;padding:2px 6px;line-height:1;">✕</button>
      </div>

      <div style="display:flex;flex-direction:column;gap:5px;">
        <label style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;">Project Name <span style="color:#ef4444;">*</span></label>
        <input id="proj-modal-name" type="text" placeholder="e.g. ClientX Web Audit Q3"
          style="background:#020617;border:1px solid #1e293b;border-radius:5px;color:#e2e8f0;
            font-family:monospace;font-size:12px;padding:8px 10px;outline:none;width:100%;"
          oninput="window._projModalValidate()" />
      </div>

      <div style="display:flex;flex-direction:column;gap:5px;">
        <label style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;">Client / Ticket ID <span style="color:#475569;font-size:9px;">(optional)</span></label>
        <input id="proj-modal-client" type="text" placeholder="e.g. Acme Corp — PT-2026-042"
          style="background:#020617;border:1px solid #1e293b;border-radius:5px;color:#e2e8f0;
            font-family:monospace;font-size:12px;padding:8px 10px;outline:none;width:100%;" />
      </div>

      <div style="display:flex;flex-direction:column;gap:5px;">
        <label style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;">Scan Policy</label>
        <select id="proj-modal-policy"
          style="background:#020617;border:1px solid #1e293b;border-radius:5px;color:#e2e8f0;
            font-family:monospace;font-size:12px;padding:8px 10px;outline:none;width:100%;">
          <option value="policy_normal">Normal — Passive only (safe for production)</option>
          <option value="policy_aggressive">Aggressive — Passive + SQLi/XSS (auth required)</option>
          <option value="policy_extreme">Extreme — All modules incl. path traversal</option>
        </select>
      </div>

      <div style="display:flex;flex-direction:column;gap:5px;">
        <label style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;">Notes <span style="color:#475569;font-size:9px;">(optional)</span></label>
        <textarea id="proj-modal-notes" rows="2" placeholder="Authorization reference, scope, etc."
          style="background:#020617;border:1px solid #1e293b;border-radius:5px;color:#e2e8f0;
            font-family:monospace;font-size:12px;padding:8px 10px;outline:none;width:100%;resize:vertical;"></textarea>
      </div>

      <div id="proj-modal-err" style="font-size:11px;color:#ef4444;display:none;">Project name is required.</div>

      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button id="proj-modal-cancel"
          style="background:#1e293b;border:1px solid #334155;color:#94a3b8;font-family:monospace;
            font-size:12px;font-weight:600;padding:7px 16px;border-radius:5px;cursor:pointer;">Cancel</button>
        <button id="proj-modal-save" disabled
          style="background:#38bdf8;color:#020617;border:none;font-family:monospace;
            font-size:12px;font-weight:700;padding:7px 18px;border-radius:5px;cursor:pointer;
            transition:opacity .15s;opacity:.35;">Save Project</button>
      </div>
    </div>
  `;
  document.body.appendChild(el);

  // Close handlers
  el.addEventListener('click', e => { if (e.target === el) closeProjectModal(); });
  document.getElementById('proj-modal-close').addEventListener('click',  closeProjectModal);
  document.getElementById('proj-modal-cancel').addEventListener('click', closeProjectModal);
  document.getElementById('proj-modal-save').addEventListener('click',   onProjectModalSave);

  // Focus style
  ['proj-modal-name','proj-modal-client','proj-modal-notes','proj-modal-policy'].forEach(id => {
    const inp = document.getElementById(id);
    if (!inp) return;
    inp.addEventListener('focus', () => inp.style.borderColor = '#38bdf8');
    inp.addEventListener('blur',  () => inp.style.borderColor = '#1e293b');
  });
}

// ─── Modal open / close ───────────────────────────────────────────────────
let _editingProjectId = null;

function openProjectModal(existingProject = null) {
  _editingProjectId = existingProject?.id || null;
  document.getElementById('proj-modal-title').textContent  = existingProject ? 'Edit Project' : 'New Project';
  document.getElementById('proj-modal-name').value         = existingProject?.name   || '';
  document.getElementById('proj-modal-client').value       = existingProject?.client || '';
  document.getElementById('proj-modal-policy').value       = existingProject?.defaultPolicy || 'policy_normal';
  document.getElementById('proj-modal-notes').value        = existingProject?.notes  || '';
  document.getElementById('proj-modal-err').style.display  = 'none';
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

window._projModalValidate = function() {
  const val  = (document.getElementById('proj-modal-name')?.value || '').trim();
  const btn  = document.getElementById('proj-modal-save');
  const err  = document.getElementById('proj-modal-err');
  if (!btn) return;
  btn.disabled    = !val;
  btn.style.opacity = val ? '1' : '.35';
  btn.style.cursor  = val ? 'pointer' : 'not-allowed';
  if (err) err.style.display = 'none';
};

function onProjectModalSave() {
  const name   = (document.getElementById('proj-modal-name').value   || '').trim();
  const client = (document.getElementById('proj-modal-client').value || '').trim();
  const policy = document.getElementById('proj-modal-policy').value  || 'policy_normal';
  const notes  = (document.getElementById('proj-modal-notes').value  || '').trim();

  if (!name) {
    document.getElementById('proj-modal-err').style.display = 'block';
    return;
  }

  if (_editingProjectId) {
    // Update existing
    const p = (window._wvcState?.projects || []).find(x => x.id === _editingProjectId);
    if (p) {
      p.name = name; p.client = client; p.defaultPolicy = policy; p.notes = notes;
      window._wvcSaveState?.();
      window._wvcToast?.(`Project "${name}" updated`, 'ok');
      window._wvcClog?.(`Project renamed/updated: ${name}`, 'ok');
    }
  } else {
    // Create new
    const id = Math.random().toString(36).slice(2,10) + Date.now().toString(36);
    const proj = { id, name, client, defaultPolicy: policy, notes, createdAt: new Date().toISOString() };
    (window._wvcState.projects = window._wvcState.projects || []).push(proj);
    window._wvcSaveState?.();
    window._wvcSelectProject?.(id);
    window._wvcToast?.(`Project "${name}" created ⚡`, 'ok');
    window._wvcClog?.(`> create project "${name}" [${id}]`, 'cmd');
  }

  closeProjectModal();
  renderProjectCards();
  window._wvcRenderProjectSelect?.();
}

// ─── Rich project cards ──────────────────────────────────────────────────────
// Cache: projectId -> { crit, high, medium, low, info, total, lastScan }
const _projStatsCache = {};

async function fetchProjectStats(projectId) {
  if (_projStatsCache[projectId]) return _projStatsCache[projectId];
  try {
    const backendUrl = window._wvcCfg?.backendUrl || 'http://127.0.0.1:8787';
    const res  = await fetch(`${backendUrl}/api/scans?projectId=${encodeURIComponent(projectId)}`);
    if (!res.ok) return null;
    const data = await res.json();
    const done = (data.jobs || []).filter(j => j.status === 'completed');
    if (!done.length) return { crit:0, high:0, medium:0, low:0, info:0, total:0, lastScan: null };

    // Aggregate findings from all completed jobs (cap at 5 for speed)
    const allF = [];
    await Promise.all(done.slice(0, 5).map(async j => {
      const r2 = await fetch(`${backendUrl}/api/scans/${j.id}/results`);
      if (r2.ok) { const d2 = await r2.json(); allF.push(...(d2.findings || [])); }
    }));

    const stats = { crit:0, high:0, medium:0, low:0, info:0, total: allF.length,
      lastScan: done[0]?.completedAt || done[0]?.createdAt || null };
    allF.forEach(f => {
      if      (f.severity === 'critical') stats.crit++;
      else if (f.severity === 'high')     stats.high++;
      else if (f.severity === 'medium')   stats.medium++;
      else if (f.severity === 'low')      stats.low++;
      else                                stats.info++;
    });
    _projStatsCache[projectId] = stats;
    return stats;
  } catch { return null; }
}

function riskScore(stats) {
  if (!stats || !stats.total) return 0;
  const raw = stats.crit*30 + stats.high*15 + stats.medium*6 + stats.low*2 + stats.info*0.5;
  return Math.min(Math.round(raw), 100);
}
function riskColor(s) {
  if (s >= 70) return '#ef4444';
  if (s >= 40) return '#f97316';
  if (s >= 15) return '#eab308';
  return '#22c55e';
}
function riskLabel(s) {
  if (s >= 70) return 'CRITICAL';
  if (s >= 40) return 'HIGH';
  if (s >= 15) return 'MEDIUM';
  if (s > 0)   return 'LOW';
  return 'CLEAN';
}
function timeAgo(iso) {
  if (!iso) return 'Never';
  const sec = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (sec < 60)    return `${sec}s ago`;
  if (sec < 3600)  return `${Math.floor(sec/60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec/3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function buildProjectCard(p, stats, isCurrent) {
  const targets   = (window._wvcState?.targets?.[p.id] || []).length;
  const score     = riskScore(stats);
  const col       = riskColor(score);
  const lbl       = riskLabel(score);
  const lastScan  = stats?.lastScan ? timeAgo(stats.lastScan) : 'No scans yet';
  const policyMap = { policy_normal:'Normal', policy_aggressive:'Aggressive', policy_extreme:'Extreme' };
  const policyLbl = policyMap[p.defaultPolicy || 'policy_normal'] || 'Normal';
  const policyCol = { Normal:'#22c55e', Aggressive:'#f97316', Extreme:'#ef4444' }[policyLbl] || '#22c55e';

  const sevPills = stats ? [
    stats.crit   ? `<span style="background:#ef444422;color:#ef4444;border:1px solid #ef444444;
      padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;">${stats.crit} CRIT</span>` : '',
    stats.high   ? `<span style="background:#f9731622;color:#f97316;border:1px solid #f9731644;
      padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;">${stats.high} HIGH</span>` : '',
    stats.medium ? `<span style="background:#eab30822;color:#eab308;border:1px solid #eab30844;
      padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;">${stats.medium} MED</span>` : '',
    stats.low    ? `<span style="background:#3b82f622;color:#3b82f6;border:1px solid #3b82f644;
      padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;">${stats.low} LOW</span>` : '',
  ].filter(Boolean).join('') : '<span style="color:#475569;font-size:10px;">No findings yet</span>';

  return `
  <div class="proj-card" data-pid="${esc(p.id)}" style="
    background:#0f172a;
    border:1px solid ${isCurrent ? '#38bdf855' : '#1e293b'};
    border-left:3px solid ${isCurrent ? '#38bdf8' : col === '#22c55e' ? '#1e293b' : col};
    border-radius:9px;padding:16px;margin-bottom:10px;
    transition:border-color .2s, box-shadow .2s;
    ${isCurrent ? 'box-shadow:0 0 0 1px #38bdf822;' : ''}">

    <!-- Header row -->
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px;">
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <span style="font-size:14px;font-weight:700;color:#f1f5f9;">${esc(p.name)}</span>
          ${isCurrent ? '<span style="background:#38bdf822;color:#38bdf8;border:1px solid #38bdf844;padding:2px 8px;border-radius:10px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;">ACTIVE</span>' : ''}
          <span style="background:${policyCol}22;color:${policyCol};border:1px solid ${policyCol}44;
            padding:2px 7px;border-radius:4px;font-size:9px;font-weight:700;text-transform:uppercase;">${esc(policyLbl)}</span>
        </div>
        ${p.client ? `<div style="font-size:11px;color:#64748b;margin-top:3px;">📁 ${esc(p.client)}</div>` : ''}
        <div style="font-size:10px;color:#475569;margin-top:2px;">
          ID: <code style="color:#64748b;">${esc(p.id)}</code>
          &nbsp;•&nbsp; Created: ${p.createdAt ? new Date(p.createdAt).toLocaleDateString() : 'unknown'}
        </div>
      </div>

      <!-- Risk score circle -->
      <div style="flex-shrink:0;text-align:center;min-width:56px;">
        <div style="font-size:22px;font-weight:800;color:${col};font-family:monospace;line-height:1;">${score}</div>
        <div style="font-size:8px;font-weight:700;color:${col};letter-spacing:.08em;text-transform:uppercase;margin-top:2px;">${lbl}</div>
        <div style="font-size:8px;color:#475569;margin-top:1px;">/100</div>
      </div>
    </div>

    <!-- Stats row -->
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px;align-items:center;">
      <div style="font-size:11px;color:#64748b;">
        🎯 <strong style="color:#94a3b8;">${targets}</strong> target${targets !== 1 ? 's' : ''}
      </div>
      <div style="font-size:11px;color:#64748b;">
        🕒 Last scan: <strong style="color:#94a3b8;">${lastScan}</strong>
      </div>
      ${stats?.total != null ? `<div style="font-size:11px;color:#64748b;">
        📊 <strong style="color:#94a3b8;">${stats.total}</strong> finding${stats.total !== 1 ? 's' : ''}
      </div>` : ''}
    </div>

    <!-- Severity pills -->
    <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:12px;">${sevPills}</div>

    <!-- Risk bar -->
    ${score > 0 ? `
    <div style="height:4px;background:#1e293b;border-radius:2px;overflow:hidden;margin-bottom:12px;">
      <div style="height:100%;width:${score}%;background:${col};border-radius:2px;transition:width .5s ease;"></div>
    </div>` : ''}

    ${p.notes ? `<div style="font-size:11px;color:#475569;font-style:italic;margin-bottom:10px;border-left:2px solid #1e293b;padding-left:8px;">${esc(p.notes)}</div>` : ''}

    <!-- Action buttons -->
    <div style="display:flex;gap:6px;flex-wrap:wrap;">
      ${!isCurrent ? `<button class="proj-btn-primary" onclick="window._wvcSelectProject('${esc(p.id)}')">Select</button>` : ''}
      <button class="proj-btn-primary" onclick="window._projLaunchScan('${esc(p.id)}')">&#9654; Scan</button>
      <button class="proj-btn-ghost"   onclick="window._projEdit('${esc(p.id)}')">Edit</button>
      <button class="proj-btn-ghost"   onclick="window._projViewFindings('${esc(p.id)}')">Findings</button>
      <button class="proj-btn-ghost"   onclick="window._wvcExportProject('${esc(p.id)}')">Export</button>
      <button class="proj-btn-danger"  onclick="window._wvcDeleteProject('${esc(p.id)}')">Delete</button>
    </div>
  </div>`;
}

export async function renderProjectCards() {
  const el = document.getElementById('project-list');
  if (!el) return;

  const projects = window._wvcState?.projects || [];
  if (!projects.length) {
    el.innerHTML = `
      <div style="text-align:center;padding:40px 20px;color:#475569;">
        <div style="font-size:32px;margin-bottom:10px;">📁</div>
        <div style="font-size:13px;font-weight:600;color:#64748b;margin-bottom:6px;">No projects yet</div>
        <div style="font-size:11px;margin-bottom:16px;">Create your first project to start scanning.</div>
        <button class="proj-btn-primary" onclick="window._projOpenModal()">+ New Project</button>
      </div>`;
    return;
  }

  const cur = window._wvcState?.currentProject;

  // Show skeleton cards first, then hydrate with stats
  el.innerHTML = projects.map(p =>
    buildProjectCard(p, _projStatsCache[p.id] || null, p.id === cur)
  ).join('');

  // Async: fetch stats for projects not yet cached, re-render when ready
  const toFetch = projects.filter(p => !_projStatsCache[p.id]);
  if (toFetch.length) {
    await Promise.all(toFetch.map(async p => {
      const stats = await fetchProjectStats(p.id);
      if (stats) _projStatsCache[p.id] = stats;
    }));
    // Re-render with real stats
    el.innerHTML = projects.map(p =>
      buildProjectCard(p, _projStatsCache[p.id] || null, p.id === cur)
    ).join('');
  }
}

// ─── Project action handlers ────────────────────────────────────────────────
window._projOpenModal = () => openProjectModal(null);

window._projEdit = function(id) {
  const p = (window._wvcState?.projects || []).find(x => x.id === id);
  if (p) openProjectModal(p);
};

window._projLaunchScan = async function(id) {
  window._wvcSelectProject?.(id);
  const targets = window._wvcState?.targets?.[id] || [];
  if (!targets.length) {
    window._wvcToast?.('No targets in this project. Add targets first.', 'warn');
    window._wvcClog?.('No targets. Add targets first.', 'warn');
    // Navigate to targets page
    if (typeof showPage === 'function') showPage('targets');
    return;
  }
  window._wvcClog?.(`> queue scan --project "${id}" --targets ${targets.length}`, 'cmd');
  try {
    const backendUrl = window._wvcCfg?.backendUrl || 'http://127.0.0.1:8787';
    const proj = (window._wvcState?.projects || []).find(x => x.id === id);
    const res  = await fetch(`${backendUrl}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ projectId: id, targets, policyId: proj?.defaultPolicy || 'policy_normal' }),
    });
    if (res.ok) {
      const data = await res.json();
      window._wvcToast?.(`Scan queued ⚡ Job: ${data.jobId}`, 'ok');
      window._wvcClog?.(`Scan queued: ${data.jobId}`, 'ok');
      if (typeof showPage === 'function') showPage('queue');
    } else {
      window._wvcToast?.('Failed to queue scan', 'crit');
      window._wvcClog?.('Scan queue failed.', 'crit');
    }
  } catch (e) {
    window._wvcToast?.('Backend offline', 'warn');
    window._wvcClog?.(`Scan error: ${e.message}`, 'crit');
  }
};

window._projViewFindings = function(id) {
  window._wvcSelectProject?.(id);
  if (typeof showPage === 'function') showPage('findings');
};

// ─── Button styles injected once ───────────────────────────────────────────────
function injectProjectStyles() {
  if (document.getElementById('proj-ui-styles')) return;
  const s = document.createElement('style');
  s.id = 'proj-ui-styles';
  s.textContent = `
    .proj-btn-primary {
      background:#38bdf8;color:#020617;border:none;font-family:monospace;
      font-size:11px;font-weight:700;padding:5px 12px;border-radius:5px;
      cursor:pointer;transition:opacity .15s;white-space:nowrap;
    }
    .proj-btn-primary:hover { opacity:.85; }
    .proj-btn-ghost {
      background:#1e293b;color:#94a3b8;border:1px solid #334155;
      font-family:monospace;font-size:11px;font-weight:600;
      padding:5px 12px;border-radius:5px;cursor:pointer;transition:opacity .15s;white-space:nowrap;
    }
    .proj-btn-ghost:hover { opacity:.8;color:#e2e8f0; }
    .proj-btn-danger {
      background:#ef444422;color:#ef4444;border:1px solid #ef444444;
      font-family:monospace;font-size:11px;font-weight:600;
      padding:5px 12px;border-radius:5px;cursor:pointer;transition:opacity .15s;white-space:nowrap;
    }
    .proj-btn-danger:hover { background:#ef444433; }
    .proj-card:hover {
      border-color:#38bdf833 !important;
      box-shadow: 0 2px 16px rgba(56,189,248,.07);
    }
  `;
  document.head.appendChild(s);
}

// ─── Init (call once from app.js) ────────────────────────────────────────────────
export function initProjectsUI() {
  injectProjectStyles();
  injectProjectModal();

  // Wire New Project buttons to modal (replace old prompt-based handlers)
  ['btn-new-project', 'btn-create-project'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) {
      // Clone to remove old listeners
      const fresh = btn.cloneNode(true);
      btn.parentNode.replaceChild(fresh, btn);
      fresh.addEventListener('click', () => openProjectModal(null));
    }
  });
}
