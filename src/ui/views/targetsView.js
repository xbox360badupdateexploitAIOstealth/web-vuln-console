// src/ui/views/targetsView.js
// TODO-12: Targets management view
//   - Per-project target list with env tags (prod/staging/dev/internal)
//   - Add single target with env + type
//   - Bulk paste import (one per line, auto-normalise)
//   - CIDR / IP range input (feeds cidrExpand on backend)
//   - Edit hostname inline
//   - Delete single or select-all-delete
//   - Live target count badge
//   - POST /api/projects/:id/targets (single)
//   - POST /api/projects/:id/targets/bulk (array)
//   - DELETE /api/targets/:targetId

'use strict';

import { getLastScanContext } from '../state.js';

// ── Constants ───────────────────────────────────────────────────────────────────────
const ENV_OPTS   = ['prod', 'staging', 'dev', 'internal', 'other'];
const TYPE_OPTS  = ['website', 'api', 'ip', 'cidr', 'subdomain', 'other'];
const ENV_COLOR  = {
  prod    : '#ef4444',
  staging : '#f97316',
  dev     : '#3b82f6',
  internal: '#8b5cf6',
  other   : '#6b7280',
};

// ── Module-level targets cache (populated from API on render) ────────────────
/** @type {Array<{id:string, host:string, type:string, env:string}>} */
let _targets = [];
let _projectId = null;
let _container = null;

// ── Entry point ────────────────────────────────────────────────────────────────────
export async function renderTargetsView(container, projectId) {
  _container = container;
  _projectId = projectId || _resolveProjectId();

  container.innerHTML = `
    <h1>Targets <span id="tv-count" style="font-size:13px;opacity:.5;"></span></h1>

    <!-- No project guard -->
    <div id="tv-no-project" style="display:none;padding:24px;text-align:center;color:#64748b;">
      <div style="font-size:24px;margin-bottom:8px;">🎯</div>
      <div style="font-weight:600;">No project selected.</div>
      <div style="font-size:11px;margin-top:4px;">Select or create a project first.</div>
    </div>

    <div id="tv-main">

      <!-- Add single target card -->
      <div style="${_card()}margin-bottom:12px;">
        <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;
          letter-spacing:.07em;margin-bottom:10px;">➕ Add Target</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;">
          <div style="flex:2;min-width:160px;">
            <label style="${_lbl()}">Host / URL / CIDR</label>
            <input id="tv-host-input" type="text" style="${_inp()}"
              placeholder="example.com | 192.168.1.0/24 | https://api.example.com" />
          </div>
          <div style="min-width:100px;">
            <label style="${_lbl()}">Type</label>
            <select id="tv-type-select" style="${_sel()}">
              ${TYPE_OPTS.map(t => `<option value="${t}">${t}</option>`).join('')}
            </select>
          </div>
          <div style="min-width:100px;">
            <label style="${_lbl()}">Environment</label>
            <select id="tv-env-select" style="${_sel()}">
              ${ENV_OPTS.map(e => `<option value="${e}">${e}</option>`).join('')}
            </select>
          </div>
          <button id="tv-add-btn" style="${_btn('#38bdf8','#020617')}">Add</button>
        </div>
      </div>

      <!-- Bulk import card -->
      <div style="${_card()}margin-bottom:12px;">
        <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;
          letter-spacing:.07em;margin-bottom:8px;">📄 Bulk Import</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:flex-end;margin-bottom:8px;">
          <div style="min-width:100px;">
            <label style="${_lbl()}">Default Env</label>
            <select id="tv-bulk-env" style="${_sel()}">
              ${ENV_OPTS.map(e => `<option value="${e}">${e}</option>`).join('')}
            </select>
          </div>
          <div style="font-size:11px;color:#475569;padding-bottom:6px;">
            One target per line — URLs, hosts, or CIDR ranges.
          </div>
        </div>
        <textarea id="tv-bulk-input" rows="5" style="${_inp()}resize:vertical;font-family:monospace;font-size:11px;"
          placeholder="example.com&#10;https://api.example.com&#10;192.168.0.0/24&#10;staging.example.com"></textarea>
        <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;align-items:center;">
          <button id="tv-bulk-btn" style="${_btn('#38bdf8','#020617')}">Import All</button>
          <span id="tv-bulk-status" style="font-size:11px;color:#64748b;"></span>
        </div>
      </div>

      <!-- Target list -->
      <div style="${_card()}">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;
          gap:8px;margin-bottom:10px;">
          <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.07em;">
            🎯 Target List
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            <input id="tv-search" type="text" placeholder="🔍 Filter…"
              style="${_sel()}width:140px;" />
            <select id="tv-filter-env" style="${_sel()}">
              <option value="">All Envs</option>
              ${ENV_OPTS.map(e => `<option value="${e}">${e}</option>`).join('')}
            </select>
            <button id="tv-delete-selected-btn"
              style="${_btn('#ef4444','#fff')}display:none;">
              🗑 Delete Selected
            </button>
          </div>
        </div>
        <div id="tv-list"></div>
      </div>
    </div>
  `;

  // Wire add single
  container.querySelector('#tv-add-btn').addEventListener('click', _handleAdd);
  container.querySelector('#tv-host-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') _handleAdd();
  });

  // Wire bulk import
  container.querySelector('#tv-bulk-btn').addEventListener('click', _handleBulk);

  // Wire filters
  container.querySelector('#tv-search').addEventListener('input', _applyFilters);
  container.querySelector('#tv-filter-env').addEventListener('change', _applyFilters);

  // Wire delete-selected
  container.querySelector('#tv-delete-selected-btn').addEventListener('click', _handleDeleteSelected);

  // Load targets
  if (!_projectId) {
    container.querySelector('#tv-no-project').style.display = 'block';
    container.querySelector('#tv-main').style.display = 'none';
    return;
  }
  await _loadTargets();
}

// ── Load from API ───────────────────────────────────────────────────────────────────
async function _loadTargets() {
  try {
    const base = _apiBase();
    const res  = await fetch(`${base}/api/projects/${encodeURIComponent(_projectId)}/targets`);
    const json = await res.json().catch(() => ({ targets: [] }));
    _targets = json.targets || json || [];
  } catch {
    _targets = [];
  }
  // Fall back to state if API unavailable (offline / no backend)
  if (!_targets.length) {
    const ctx = getLastScanContext();
    _targets = (ctx?.targets || []).filter(t => !_projectId || t.projectId === _projectId);
  }
  _updateCount();
  _applyFilters();
}

// ── Add single target ───────────────────────────────────────────────────────────────
async function _handleAdd() {
  const hostEl = _container.querySelector('#tv-host-input');
  const host   = (hostEl.value || '').trim();
  if (!host) { _flash(hostEl); return; }

  const type = _container.querySelector('#tv-type-select').value;
  const env  = _container.querySelector('#tv-env-select').value;

  const payload = { host, type, env };

  try {
    const base = _apiBase();
    const res  = await fetch(`${base}/api/projects/${encodeURIComponent(_projectId)}/targets`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify(payload),
    });
    const json = await res.json().catch(() => ({}));
    if (res.ok) {
      _targets.push(json.target || { id: _uid(), ...payload });
      hostEl.value = '';
      _updateCount();
      _applyFilters();
      _toast(`✓ Added: ${host}`, 'ok');
    } else {
      _toast(json.error || 'Failed to add target', 'warn');
    }
  } catch {
    // Offline fallback — add locally
    _targets.push({ id: _uid(), host, type, env, projectId: _projectId });
    hostEl.value = '';
    _updateCount();
    _applyFilters();
    _toast(`✓ Added locally: ${host}`, 'warn');
  }
}

// ── Bulk import ──────────────────────────────────────────────────────────────────────
async function _handleBulk() {
  const raw  = (_container.querySelector('#tv-bulk-input').value || '').trim();
  if (!raw)  return;
  const env  = _container.querySelector('#tv-bulk-env').value;
  const stat = _container.querySelector('#tv-bulk-status');

  const lines = raw.split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  if (!lines.length) { stat.textContent = 'Nothing to import.'; return; }

  const targets = lines.map(host => ({
    host : _normaliseHost(host),
    type : _guessType(host),
    env,
  }));

  stat.textContent = `Importing ${targets.length} targets…`;

  try {
    const base = _apiBase();
    const res  = await fetch(`${base}/api/projects/${encodeURIComponent(_projectId)}/targets/bulk`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ targets }),
    });
    const json = await res.json().catch(() => ({}));
    if (res.ok) {
      const added = json.targets || targets.map((t, i) => ({ id: _uid(), ...t }));
      _targets.push(...added);
      _container.querySelector('#tv-bulk-input').value = '';
      stat.textContent = `✓ Imported ${added.length} targets.`;
      _updateCount();
      _applyFilters();
      _toast(`✓ ${added.length} targets imported`, 'ok');
    } else {
      stat.textContent = json.error || 'Import failed.';
      _toast('Bulk import failed', 'warn');
    }
  } catch {
    // Offline fallback
    const added = targets.map(t => ({ id: _uid(), ...t, projectId: _projectId }));
    _targets.push(...added);
    _container.querySelector('#tv-bulk-input').value = '';
    stat.textContent = `✓ Imported ${added.length} targets (offline).`;
    _updateCount();
    _applyFilters();
    _toast(`✓ ${added.length} targets imported locally`, 'warn');
  }
}

// ── Delete ─────────────────────────────────────────────────────────────────────────────
async function _deleteTarget(id) {
  try {
    const base = _apiBase();
    await fetch(`${base}/api/targets/${encodeURIComponent(id)}`, { method: 'DELETE' });
  } catch { /* offline — remove locally */ }
  _targets = _targets.filter(t => t.id !== id);
  _updateCount();
  _applyFilters();
  _toast('Target removed', 'ok');
}

async function _handleDeleteSelected() {
  const checked = [..._container.querySelectorAll('.tv-row-check:checked')];
  if (!checked.length) return;
  const ids = checked.map(cb => cb.dataset.id);
  await Promise.all(ids.map(id => _deleteTarget(id)));
}

// ── Edit inline (host field only) ──────────────────────────────────────────────
async function _saveEdit(id, host, env, type) {
  try {
    const base = _apiBase();
    await fetch(`${base}/api/targets/${encodeURIComponent(id)}`, {
      method : 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ host, env, type }),
    });
  } catch { /* offline — update locally */ }
  const t = _targets.find(x => x.id === id);
  if (t) { t.host = host; t.env = env; t.type = type; }
  _applyFilters();
  _toast(`✓ Updated: ${host}`, 'ok');
}

// ── Filter + render list ─────────────────────────────────────────────────────────────
function _applyFilters() {
  if (!_container) return;
  const q       = (_container.querySelector('#tv-search')?.value || '').toLowerCase();
  const envF    = _container.querySelector('#tv-filter-env')?.value || '';
  const visible = _targets.filter(t => {
    if (envF && t.env !== envF) return false;
    if (q && !(t.host || '').toLowerCase().includes(q)) return false;
    return true;
  });
  _renderList(visible);
}

function _renderList(targets) {
  const listEl   = _container.querySelector('#tv-list');
  const delBtnEl = _container.querySelector('#tv-delete-selected-btn');
  if (!targets.length) {
    listEl.innerHTML = `<div style="padding:16px;text-align:center;color:#475569;font-size:12px;">
      ${ _targets.length ? 'No targets match the current filter.' : 'No targets yet. Add one above.' }
    </div>`;
    delBtnEl.style.display = 'none';
    return;
  }

  listEl.innerHTML = `
    <table style="width:100%;border-collapse:collapse;font-size:12px;">
      <thead>
        <tr style="border-bottom:2px solid #1e293b;">
          <th style="${_th()}width:28px;">
            <input type="checkbox" id="tv-check-all" title="Select all" />
          </th>
          <th style="${_th()}">Host / URL</th>
          <th style="${_th()}width:90px;">Type</th>
          <th style="${_th()}width:90px;">Env</th>
          <th style="${_th()}width:80px;">Actions</th>
        </tr>
      </thead>
      <tbody id="tv-tbody">
        ${targets.map(t => _targetRow(t)).join('')}
      </tbody>
    </table>`;

  // Select-all
  const checkAll = _container.querySelector('#tv-check-all');
  checkAll.addEventListener('change', () => {
    _container.querySelectorAll('.tv-row-check').forEach(cb => cb.checked = checkAll.checked);
    delBtnEl.style.display = _anyChecked() ? 'inline-flex' : 'none';
  });

  // Per-row check
  _container.querySelectorAll('.tv-row-check').forEach(cb => {
    cb.addEventListener('change', () => {
      delBtnEl.style.display = _anyChecked() ? 'inline-flex' : 'none';
    });
  });

  // Delete single
  _container.querySelectorAll('.tv-del-btn').forEach(btn => {
    btn.addEventListener('click', () => _deleteTarget(btn.dataset.id));
  });

  // Edit button → expand inline edit row
  _container.querySelectorAll('.tv-edit-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id  = btn.dataset.id;
      const t   = _targets.find(x => x.id === id);
      if (!t) return;
      const editRow = _container.querySelector(`#tv-edit-row-${id}`);
      if (!editRow) return;
      const visible = editRow.style.display !== 'none';
      editRow.style.display = visible ? 'none' : 'table-row';
      if (!visible) {
        editRow.querySelector('.tv-edit-host').focus();
      }
    });
  });

  // Save edit
  _container.querySelectorAll('.tv-save-edit-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id      = btn.dataset.id;
      const editRow = _container.querySelector(`#tv-edit-row-${id}`);
      const host    = editRow.querySelector('.tv-edit-host').value.trim();
      const env     = editRow.querySelector('.tv-edit-env').value;
      const type    = editRow.querySelector('.tv-edit-type').value;
      if (!host) return;
      editRow.style.display = 'none';
      _saveEdit(id, host, env, type);
    });
  });

  delBtnEl.style.display = 'none';
}

function _targetRow(t) {
  const envCol   = ENV_COLOR[t.env] || '#6b7280';
  const envLabel = t.env || 'other';
  return `
    <tr style="border-bottom:1px solid #111827;" id="tv-row-${_esc(t.id)}">
      <td style="padding:6px 8px;">
        <input type="checkbox" class="tv-row-check" data-id="${_esc(t.id)}" />
      </td>
      <td style="padding:6px 8px;font-family:monospace;font-size:11px;color:#e2e8f0;
        max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
        title="${_esc(t.host)}">${_esc(t.host || '—')}</td>
      <td style="padding:6px 8px;font-size:11px;color:#94a3b8;">${_esc(t.type || 'website')}</td>
      <td style="padding:6px 8px;">
        <span style="background:${envCol}22;color:${envCol};border:1px solid ${envCol}55;
          padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;
          text-transform:uppercase;">${_esc(envLabel)}</span>
      </td>
      <td style="padding:6px 8px;">
        <div style="display:flex;gap:4px;">
          <button class="tv-edit-btn" data-id="${_esc(t.id)}"
            style="background:#1e293b;border:none;border-radius:4px;padding:3px 8px;
              color:#94a3b8;font-size:10px;cursor:pointer;">✏️ Edit</button>
          <button class="tv-del-btn" data-id="${_esc(t.id)}"
            style="background:#ef444411;border:1px solid #ef444444;border-radius:4px;
              padding:3px 8px;color:#ef4444;font-size:10px;cursor:pointer;">🗑</button>
        </div>
      </td>
    </tr>
    <!-- Inline edit row (hidden by default) -->
    <tr id="tv-edit-row-${_esc(t.id)}" style="display:none;background:#0a0f1a;">
      <td></td>
      <td colspan="3" style="padding:8px;">
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:flex-end;">
          <input class="tv-edit-host" type="text" value="${_esc(t.host || '')}" style="${_inp()}flex:1;min-width:140px;" />
          <select class="tv-edit-type" style="${_sel()}">
            ${TYPE_OPTS.map(x => `<option value="${x}"${t.type===x?' selected':''}>${x}</option>`).join('')}
          </select>
          <select class="tv-edit-env" style="${_sel()}">
            ${ENV_OPTS.map(x => `<option value="${x}"${t.env===x?' selected':''}>${x}</option>`).join('')}
          </select>
        </div>
      </td>
      <td style="padding:8px;">
        <button class="tv-save-edit-btn" data-id="${_esc(t.id)}"
          style="${_btn('#22c55e','#020617')}font-size:10px;">✓ Save</button>
      </td>
    </tr>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────────────
function _resolveProjectId() {
  // Try window state (app.js keeps project in window._wvcState or state global)
  const st = window._wvcState || window.state || {};
  return st.currentProject || null;
}

function _apiBase() {
  return (window._wvcState?.cfg?.backendUrl)
    || (window.CFG?.backendUrl)
    || localStorage.getItem('wvc_backend_url')
    || 'http://127.0.0.1:8787';
}

function _updateCount() {
  const el = _container?.querySelector('#tv-count');
  if (el) el.textContent = `(${_targets.length})`;
}

function _anyChecked() {
  return !!_container?.querySelector('.tv-row-check:checked');
}

function _normaliseHost(raw) {
  const s = raw.trim();
  // If looks like a bare host (no scheme), leave as-is; otherwise keep URL
  return s;
}

function _guessType(host) {
  if (/\/\d+$/.test(host) || /^\d+\.\d+\.\d+\.\d+\//.test(host)) return 'cidr';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host))                           return 'ip';
  if (/^https?:\/\//i.test(host)) {
    return host.includes('api.') || host.includes('/api') ? 'api' : 'website';
  }
  if (host.split('.').length > 2) return 'subdomain';
  return 'website';
}

function _uid() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

function _flash(el) {
  el.style.borderColor = '#ef4444';
  setTimeout(() => { el.style.borderColor = ''; }, 1200);
}

function _toast(msg, type = 'info') {
  if (window._wvcToast) { window._wvcToast(msg, type); return; }
  // Fallback mini toast
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
  return String(s || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Style snippets ─────────────────────────────────────────────────────────────────────
function _card() {
  return 'background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px;';
}
function _inp() {
  return 'width:100%;background:#020617;border:1px solid #1e293b;border-radius:5px;' +
    'color:#e2e8f0;font-family:monospace;font-size:12px;padding:7px 10px;' +
    'outline:none;box-sizing:border-box;';
}
function _sel() {
  return 'background:#0f172a;border:1px solid #1e293b;border-radius:5px;' +
    'color:#e2e8f0;font-size:11px;padding:5px 8px;outline:none;';
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
function _th() {
  return 'text-align:left;padding:6px 8px;font-size:10px;text-transform:uppercase;' +
    'letter-spacing:.07em;color:#64748b;';
}
