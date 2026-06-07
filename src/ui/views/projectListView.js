// src/ui/views/projectListView.js
// Full project management view.
//
// Features:
//   ─ Lists all projects from IndexedDB (via state.loadProjects)
//   ─ "New Project" slide-down form: name, client name, auth notes, tags, default policy
//   ─ Inline edit: click ✏️ to expand an edit row for any project
//   ─ Delete single project (with confirm guard)
//   ─ Row click / "Select" button → sets state.currentProjectId, emits 'project'
//   ─ Active project highlighted with accent border
//   ─ Live search filter across name / client / tags
//   ─ Risk score badge (null → —, 0–33 low, 34–66 med, 67+ high)
//   ─ Listens to state 'projects' bus so it auto-refreshes when another view mutates the db
//   ─ Seed button (dev) — inserts two demo projects if db is empty

import { state }   from '../state.js';
import { Project } from '../../core/models.js';
import { scanPolicies } from '../../core/policyRegistry.js';

// ── Module-level refs so event handlers can reach them without re-querying DOM ──
let _container  = null;
let _unsubscribe = null;   // cleanup fn for state bus

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
export async function renderProjectList(container) {
  _container = container;

  // Tear down any previous subscription to avoid double-firing
  if (_unsubscribe) { _unsubscribe(); _unsubscribe = null; }

  container.innerHTML = _shell();

  // Wire new-project toggle
  container.querySelector('#pl-new-toggle').addEventListener('click', _toggleNewForm);
  container.querySelector('#pl-new-cancel').addEventListener('click', _toggleNewForm);
  container.querySelector('#pl-new-submit').addEventListener('click', _handleCreate);

  // Allow submit on Enter inside the name field
  container.querySelector('#pl-name').addEventListener('keydown', e => {
    if (e.key === 'Enter') _handleCreate();
  });

  // Wire search
  container.querySelector('#pl-search').addEventListener('input', () => _renderList());

  // Subscribe to state changes so any external mutation (e.g. from another view) re-renders
  const _onProjects = () => _renderList();
  const _onProject  = () => _renderList(); // active project changed → re-highlight
  state.on('projects', _onProjects);
  state.on('project',  _onProject);
  _unsubscribe = () => {
    state.off('projects', _onProjects);
    state.off('project',  _onProject);
  };

  // Load from db
  await state.loadProjects();
  _renderList();
}

// ─────────────────────────────────────────────────────────────────────────────
// Shell HTML (static scaffolding — list is injected separately)
// ─────────────────────────────────────────────────────────────────────────────
function _shell() {
  const policyOpts = scanPolicies.map(p =>
    `<option value="${_esc(p.id)}">${_esc(p.name)}</option>`
  ).join('');

  return `
  <div style="max-width:860px;">

    <!-- Header row -->
    <div style="display:flex;align-items:center;justify-content:space-between;
      flex-wrap:wrap;gap:8px;margin-bottom:14px;">
      <h1 style="margin:0;font-size:18px;">Projects
        <span id="pl-count" style="font-size:12px;opacity:.45;margin-left:6px;"></span>
      </h1>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        <input id="pl-search" type="text" placeholder="🔍 Search…"
          style="${_iStyle()}width:170px;" />
        <button id="pl-new-toggle" style="${_btnStyle('#38bdf8','#020617')}">➕ New Project</button>
      </div>
    </div>

    <!-- New project form (hidden by default) -->
    <div id="pl-new-form" style="display:none;${_cardStyle()}margin-bottom:14px;
      border-color:#38bdf844;">
      <div style="font-size:11px;font-weight:700;color:#38bdf8;text-transform:uppercase;
        letter-spacing:.07em;margin-bottom:12px;">New Project</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
        <div>
          <label style="${_lblStyle()}">Project Name *</label>
          <input id="pl-name" type="text" placeholder="ACME Corp External Recon"
            style="${_iStyle()}" />
        </div>
        <div>
          <label style="${_lblStyle()}">Client Name</label>
          <input id="pl-client" type="text" placeholder="ACME Corp"
            style="${_iStyle()}" />
        </div>
        <div>
          <label style="${_lblStyle()}">Client Contact</label>
          <input id="pl-contact" type="text" placeholder="security@acme.com"
            style="${_iStyle()}" />
        </div>
        <div>
          <label style="${_lblStyle()}">Default Scan Policy</label>
          <select id="pl-policy" style="${_sStyle()}">
            <option value="">— None —</option>
            ${policyOpts}
          </select>
        </div>
        <div style="grid-column:1/-1;">
          <label style="${_lblStyle()}">Authorization Notes</label>
          <textarea id="pl-auth" rows="2"
            placeholder="Written authorization ref, scope, exclusions…"
            style="${_iStyle()}resize:vertical;font-family:monospace;font-size:11px;"></textarea>
        </div>
        <div style="grid-column:1/-1;">
          <label style="${_lblStyle()}">Tags <span style="opacity:.5;">(comma-separated)</span></label>
          <input id="pl-tags" type="text" placeholder="external, web, api"
            style="${_iStyle()}" />
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:12px;">
        <button id="pl-new-submit" style="${_btnStyle('#22c55e','#020617')}">✓ Create Project</button>
        <button id="pl-new-cancel"  style="${_btnStyle('#1e293b','#94a3b8')}">Cancel</button>
        <span id="pl-form-error" style="font-size:11px;color:#ef4444;align-self:center;"></span>
      </div>
    </div>

    <!-- Project list -->
    <div id="pl-list"></div>

  </div>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Render list (called after any data change or filter change)
// ─────────────────────────────────────────────────────────────────────────────
function _renderList() {
  if (!_container) return;
  const listEl   = _container.querySelector('#pl-list');
  const countEl  = _container.querySelector('#pl-count');
  const q        = (_container.querySelector('#pl-search')?.value || '').trim().toLowerCase();
  const projects = state.getProjects();

  const visible = projects.filter(p => {
    if (!q) return true;
    const haystack = [
      p.name        || '',
      p.clientName  || '',
      (p.tags || []).join(' '),
    ].join(' ').toLowerCase();
    return haystack.includes(q);
  });

  countEl.textContent = `(${visible.length}${
    visible.length !== projects.length ? ` of ${projects.length}` : ''
  })`;

  if (!projects.length) {
    listEl.innerHTML = _emptyState();
    return;
  }
  if (!visible.length) {
    listEl.innerHTML = `<div style="${_emptyInner()}">No projects match your search.</div>`;
    return;
  }

  const activeId = state.currentProjectId;

  listEl.innerHTML = `
    <table style="width:100%;border-collapse:collapse;font-size:12px;">
      <thead>
        <tr style="border-bottom:2px solid #1e293b;">
          <th style="${_thStyle()}">Name</th>
          <th style="${_thStyle()}width:130px;">Client</th>
          <th style="${_thStyle()}width:80px;">Risk</th>
          <th style="${_thStyle()}width:130px;">Policy</th>
          <th style="${_thStyle()}width:90px;">Created</th>
          <th style="${_thStyle()}width:110px;">Actions</th>
        </tr>
      </thead>
      <tbody>
        ${visible.map(p => _projectRow(p, p.id === activeId)).join('')}
      </tbody>
    </table>`;

  // ── Wire row-level events ──────────────────────────────────────────────────
  // Select
  listEl.querySelectorAll('.pl-select-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      state.selectProject(btn.dataset.id);
      _renderList();
      _toast(`Project selected: ${btn.dataset.name}`, 'ok');
    });
  });

  // Edit toggle
  listEl.querySelectorAll('.pl-edit-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const id      = btn.dataset.id;
      const editRow = _container.querySelector(`#pl-edit-row-${CSS.escape(id)}`);
      if (!editRow) return;
      const open = editRow.style.display !== 'none';
      // Collapse all other edit rows first
      _container.querySelectorAll('.pl-edit-row').forEach(r => { r.style.display = 'none'; });
      editRow.style.display = open ? 'none' : 'table-row';
      if (!open) editRow.querySelector('.pl-edit-name')?.focus();
    });
  });

  // Save edit
  listEl.querySelectorAll('.pl-save-edit-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id      = btn.dataset.id;
      const editRow = _container.querySelector(`#pl-edit-row-${CSS.escape(id)}`);
      const project = state.getProjects().find(p => p.id === id);
      if (!project || !editRow) return;

      const name = editRow.querySelector('.pl-edit-name').value.trim();
      if (!name) { _flash(editRow.querySelector('.pl-edit-name')); return; }

      const updated = new Project({
        ...project,
        name,
        clientName  : editRow.querySelector('.pl-edit-client').value.trim(),
        clientContact: editRow.querySelector('.pl-edit-contact').value.trim(),
        authNotes   : editRow.querySelector('.pl-edit-auth').value.trim(),
        defaultScanPolicyId: editRow.querySelector('.pl-edit-policy').value || null,
        tags        : _parseTags(editRow.querySelector('.pl-edit-tags').value),
      });

      btn.textContent = '…';
      btn.disabled    = true;
      await state.saveProject(updated);
      _toast(`✓ Saved: ${name}`, 'ok');
    });
  });

  // Delete
  listEl.querySelectorAll('.pl-del-btn').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const name = btn.dataset.name;
      if (!confirm(`Delete project "${name}"?\nThis cannot be undone.`)) return;
      await state.deleteProject(btn.dataset.id);
      _toast(`Deleted: ${name}`, 'warn');
    });
  });

  // Row click (anywhere on main row) → select
  listEl.querySelectorAll('tr.pl-main-row').forEach(tr => {
    tr.addEventListener('click', () => {
      const id   = tr.dataset.id;
      const name = tr.dataset.name;
      state.selectProject(id);
      _renderList();
      _toast(`Project selected: ${name}`, 'ok');
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Row templates
// ─────────────────────────────────────────────────────────────────────────────
function _projectRow(p, isActive) {
  const policyName = _policyName(p.defaultScanPolicyId);
  const riskBadge  = _riskBadge(p.riskScore);
  const tags       = (p.tags || []).map(t =>
    `<span style="${_tagStyle()}">${_esc(t)}</span>`
  ).join('');
  const created    = p.createdAt
    ? new Date(p.createdAt).toISOString().slice(0,10)
    : '—';
  const activeBorder = isActive
    ? 'border-left:3px solid #38bdf8;background:#0f172a;'
    : 'border-left:3px solid transparent;';
  const policyOpts = scanPolicies.map(pol =>
    `<option value="${_esc(pol.id)}"${p.defaultScanPolicyId===pol.id?' selected':''}>${_esc(pol.name)}</option>`
  ).join('');

  return `
  <!-- Main row -->
  <tr class="pl-main-row" data-id="${_esc(p.id)}" data-name="${_esc(p.name)}"
    style="${activeBorder}border-bottom:1px solid #111827;cursor:pointer;
      transition:background .12s;"
    onmouseover="this.style.background='#0f172a'"
    onmouseout="this.style.background='${ isActive ? '#0f172a' : '' }'">

    <td style="padding:8px 10px;">
      <div style="font-weight:600;color:#e2e8f0;">${_esc(p.name)}
        ${ isActive ? '<span style="font-size:9px;background:#38bdf811;color:#38bdf8;border:1px solid #38bdf844;padding:1px 6px;border-radius:4px;margin-left:6px;vertical-align:middle;">ACTIVE</span>' : '' }
      </div>
      <div style="font-size:10px;color:#475569;margin-top:2px;display:flex;gap:4px;flex-wrap:wrap;">
        ${tags}
      </div>
    </td>
    <td style="padding:8px 10px;color:#94a3b8;">${_esc(p.clientName || '—')}</td>
    <td style="padding:8px 10px;">${riskBadge}</td>
    <td style="padding:8px 10px;font-size:11px;color:#64748b;">${_esc(policyName)}</td>
    <td style="padding:8px 10px;font-size:11px;color:#475569;">${created}</td>
    <td style="padding:8px 10px;">
      <div style="display:flex;gap:4px;" onclick="event.stopPropagation()">
        <button class="pl-select-btn" data-id="${_esc(p.id)}" data-name="${_esc(p.name)}"
          style="${_microBtn(isActive ? '#38bdf8' : '#1e293b', isActive ? '#020617' : '#94a3b8')}">
          ${ isActive ? '✓' : 'Select' }
        </button>
        <button class="pl-edit-btn" data-id="${_esc(p.id)}"
          style="${_microBtn('#1e293b','#94a3b8')}">✏️</button>
        <button class="pl-del-btn" data-id="${_esc(p.id)}" data-name="${_esc(p.name)}"
          style="${_microBtn('#ef444411','#ef4444')}border:1px solid #ef444433;">🗑</button>
      </div>
    </td>
  </tr>

  <!-- Inline edit row (hidden) -->
  <tr class="pl-edit-row" id="pl-edit-row-${_esc(p.id)}"
    style="display:none;background:#070d18;">
    <td colspan="6" style="padding:12px 14px;">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
        <div>
          <label style="${_lblStyle()}">Name *</label>
          <input class="pl-edit-name" type="text" value="${_esc(p.name)}"
            style="${_iStyle()}" />
        </div>
        <div>
          <label style="${_lblStyle()}">Client Name</label>
          <input class="pl-edit-client" type="text" value="${_esc(p.clientName||'')}"
            style="${_iStyle()}" />
        </div>
        <div>
          <label style="${_lblStyle()}">Client Contact</label>
          <input class="pl-edit-contact" type="text" value="${_esc(p.clientContact||'')}"
            style="${_iStyle()}" />
        </div>
        <div>
          <label style="${_lblStyle()}">Default Policy</label>
          <select class="pl-edit-policy" style="${_sStyle()}">
            <option value="">— None —</option>
            ${policyOpts}
          </select>
        </div>
        <div style="grid-column:1/-1;">
          <label style="${_lblStyle()}">Auth Notes</label>
          <textarea class="pl-edit-auth" rows="2"
            style="${_iStyle()}resize:vertical;font-family:monospace;font-size:11px;">${_esc(p.authNotes||'')}</textarea>
        </div>
        <div style="grid-column:1/-1;">
          <label style="${_lblStyle()}">Tags</label>
          <input class="pl-edit-tags" type="text" value="${_esc((p.tags||[]).join(', '))}"
            style="${_iStyle()}" />
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;">
        <button class="pl-save-edit-btn" data-id="${_esc(p.id)}"
          style="${_btnStyle('#22c55e','#020617')}">✓ Save</button>
        <button class="pl-cancel-edit-btn"
          style="${_btnStyle('#1e293b','#94a3b8')}"
          onclick="this.closest('tr').style.display='none'">Cancel</button>
      </div>
    </td>
  </tr>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Create project
// ─────────────────────────────────────────────────────────────────────────────
async function _handleCreate() {
  const errEl = _container.querySelector('#pl-form-error');
  errEl.textContent = '';

  const name = _container.querySelector('#pl-name').value.trim();
  if (!name) {
    errEl.textContent = 'Project name is required.';
    _flash(_container.querySelector('#pl-name'));
    return;
  }

  const project = new Project({
    name,
    clientName   : _container.querySelector('#pl-client').value.trim(),
    clientContact: _container.querySelector('#pl-contact').value.trim(),
    authNotes    : _container.querySelector('#pl-auth').value.trim(),
    defaultScanPolicyId: _container.querySelector('#pl-policy').value || null,
    tags         : _parseTags(_container.querySelector('#pl-tags').value),
    workspaceId  : 'ws_default',
  });

  const btn = _container.querySelector('#pl-new-submit');
  btn.disabled    = true;
  btn.textContent = '…';

  try {
    await state.saveProject(project);
    state.selectProject(project.id);
    // Reset form
    ['#pl-name','#pl-client','#pl-contact','#pl-auth','#pl-tags']
      .forEach(sel => { _container.querySelector(sel).value = ''; });
    _container.querySelector('#pl-policy').value = '';
    _toggleNewForm();
    _toast(`✓ Created: ${name}`, 'ok');
  } catch(e) {
    errEl.textContent = e.message || 'Failed to save project.';
  } finally {
    btn.disabled    = false;
    btn.textContent = '✓ Create Project';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
function _toggleNewForm() {
  if (!_container) return;
  const form = _container.querySelector('#pl-new-form');
  const open = form.style.display !== 'none';
  form.style.display = open ? 'none' : 'block';
  if (!open) _container.querySelector('#pl-name')?.focus();
}

function _parseTags(str) {
  return (str || '').split(',').map(t => t.trim()).filter(Boolean);
}

function _policyName(id) {
  if (!id) return '—';
  return scanPolicies.find(p => p.id === id)?.name || id;
}

function _riskBadge(score) {
  if (score === null || score === undefined) return '<span style="color:#475569;">—</span>';
  const n = Number(score);
  const [bg, fg, label] =
    n >= 67 ? ['#ef444418','#ef4444','HIGH'] :
    n >= 34 ? ['#f9731618','#f97316','MED']  :
              ['#3b82f618','#3b82f6','LOW'];
  return `<span style="background:${bg};color:${fg};border:1px solid ${fg}44;
    padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;">${label} ${n}</span>`;
}

function _emptyState() {
  return `
    <div style="text-align:center;padding:48px 24px;color:#475569;">
      <div style="font-size:32px;margin-bottom:8px;">🗂</div>
      <div style="font-size:14px;font-weight:600;color:#64748b;margin-bottom:4px;">
        No projects yet
      </div>
      <div style="font-size:12px;">
        Click <strong style="color:#38bdf8;">➕ New Project</strong> to get started.
      </div>
    </div>`;
}

function _emptyInner() {
  return 'padding:24px;text-align:center;font-size:12px;color:#475569;';
}

function _toast(msg, type = 'info') {
  if (window._wvcToast) { window._wvcToast(msg, type); return; }
  const t = document.createElement('div');
  t.textContent = msg;
  Object.assign(t.style, {
    position:'fixed', bottom:'20px', right:'20px', zIndex:9999,
    background: type==='ok' ? '#16a34a' : type==='warn' ? '#b45309' : '#1e293b',
    color:'#fff', padding:'8px 14px', borderRadius:'6px', fontSize:'12px',
    fontFamily:'monospace', boxShadow:'0 4px 12px rgba(0,0,0,.4)',
    transition:'opacity .3s',
  });
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 2500);
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

// ── Style helpers ──────────────────────────────────────────────────────────────
function _cardStyle() {
  return 'background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:16px;';
}
function _iStyle() {
  return 'width:100%;background:#020617;border:1px solid #1e293b;border-radius:5px;' +
    'color:#e2e8f0;font-size:12px;padding:7px 10px;outline:none;box-sizing:border-box;';
}
function _sStyle() {
  return 'width:100%;background:#0f172a;border:1px solid #1e293b;border-radius:5px;' +
    'color:#e2e8f0;font-size:12px;padding:6px 8px;outline:none;box-sizing:border-box;';
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
function _microBtn(bg, fg) {
  return `background:${bg};color:${fg};border:none;border-radius:4px;` +
    'padding:3px 9px;font-size:10px;font-weight:600;cursor:pointer;' +
    'white-space:nowrap;font-family:inherit;';
}
function _thStyle() {
  return 'text-align:left;padding:7px 10px;font-size:10px;text-transform:uppercase;' +
    'letter-spacing:.07em;color:#64748b;';
}
function _tagStyle() {
  return 'background:#1e293b;color:#94a3b8;padding:1px 6px;border-radius:4px;font-size:9px;';
}
