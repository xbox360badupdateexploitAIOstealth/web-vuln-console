/* =============================================================
   WebVulnConsole ⚡ payloads.js
   Payload Library Manager — full UI module
   Loaded by app.js via: loadPayloadPage() called from showPage()
   ============================================================= */
'use strict';

// ─── State ───────────────────────────────────────────────────────────────────
let _plState = {
  openListId:   null,
  openListName: '',
  payloads:     [],
  searchTimer:  null,
};

// ─── Helpers (re-use from app.js globals) ────────────────────────────────────
const _esc  = window.escHtml  || (s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'));
const _log  = window.clog     || console.log;
const _toast= window.toast    || ((m) => alert(m));
const _api  = window.apiFetch || (async (path, opts) => { const r = await fetch(path, opts); return { ok: r.ok, data: await r.json().catch(()=>null) }; });

// ─── Load payload lists page ─────────────────────────────────────────────────
async function loadPayloadPage() {
  closePayloadDetail();
  const wrap = document.getElementById('payload-lists-wrap');
  wrap.innerHTML = '<p style="opacity:.5;font-size:12px;">Loading…</p>';
  const r = await _api('/api/payloads/lists');
  if (!r.ok) {
    wrap.innerHTML = '<p style="opacity:.5;font-size:12px;">Backend offline or payloads API not available.</p>';
    return;
  }
  const lists = r.data.lists || [];
  if (!lists.length) {
    wrap.innerHTML = '<p style="opacity:.5;font-size:12px;">No payload lists yet. Create one to get started.</p>';
    return;
  }
  const CAT_COLORS = {
    sqli: '#ef4444', xss: '#f97316', traversal: '#eab308',
    redirect: '#3b82f6', lfi: '#8b5cf6', cmdi: '#ec4899',
    custom: '#22c55e', seclists: '#06b6d4',
  };
  wrap.innerHTML = lists.map(l => {
    const color = CAT_COLORS[l.category] || '#6b7280';
    return `
    <div class="job-card" style="cursor:pointer;" onclick="openPayloadList('${_esc(l.id)}','${_esc(l.name)}')"
         id="plcard-${_esc(l.id)}">
      <div style="flex:1;">
        <div class="job-desc" style="display:flex;align-items:center;gap:8px;">
          🧨 ${_esc(l.name)}
          <span style="font-size:10px;background:${color}20;color:${color};border:1px solid ${color}40;
            border-radius:4px;padding:1px 7px;font-family:monospace;">${_esc(l.category)}</span>
        </div>
        <div class="job-id">
          ${l.payloadCount} payload${l.payloadCount !== 1 ? 's' : ''} &nbsp;|&nbsp;
          ${l.description ? _esc(l.description) + ' &nbsp;|&nbsp;' : ''}
          Created ${new Date(l.created_at).toLocaleDateString()}
        </div>
      </div>
      <div style="display:flex;gap:6px;align-items:center;">
        <button class="btn btn-sm btn-primary" onclick="event.stopPropagation();openPayloadList('${_esc(l.id)}','${_esc(l.name)}')">Open</button>
        <button class="btn btn-sm btn-ghost"   onclick="event.stopPropagation();copyPayloadList('${_esc(l.id)}','${_esc(l.name)}')" title="Copy all payloads to clipboard">📋 Copy</button>
        <button class="btn btn-sm btn-danger"  onclick="event.stopPropagation();deletePayloadList('${_esc(l.id)}','${_esc(l.name)}')" title="Delete this list">✕</button>
      </div>
    </div>`;
  }).join('');
}
window.loadPayloadPage = loadPayloadPage;

// ─── Open a list (detail panel) ──────────────────────────────────────────────
async function openPayloadList(listId, listName) {
  _plState.openListId   = listId;
  _plState.openListName = listName;
  document.getElementById('payload-lists-wrap').style.display   = 'none';
  document.getElementById('payload-detail-panel').style.display = 'block';
  document.getElementById('payload-detail-name').textContent    = listName;
  document.getElementById('payload-export-link').href =
    `${(window.CFG && CFG.backendUrl) || 'http://127.0.0.1:8787'}/api/payloads/lists/${listId}/export`;
  document.getElementById('btn-delete-payload-list').onclick = () => deletePayloadList(listId, listName);
  document.getElementById('payload-search').value = '';
  await refreshPayloadTable(listId);
}
window.openPayloadList = openPayloadList;

function closePayloadDetail() {
  _plState.openListId = null;
  document.getElementById('payload-detail-panel').style.display  = 'none';
  document.getElementById('payload-lists-wrap').style.display    = '';
  loadPayloadPage();
}
window.closePayloadDetail = closePayloadDetail;

// ─── Render payload table ────────────────────────────────────────────────────
async function refreshPayloadTable(listId, search) {
  const wrap = document.getElementById('payload-table-wrap');
  wrap.innerHTML = '<p style="opacity:.5;font-size:12px;">Loading…</p>';
  const qs = search ? `?search=${encodeURIComponent(search)}&limit=500` : '?limit=500';
  const r  = await _api(`/api/payloads/lists/${listId}${qs}`);
  if (!r.ok) { wrap.innerHTML = '<p style="opacity:.5;">Error loading payloads.</p>'; return; }
  const items = r.data.payloads || [];
  _plState.payloads = items;
  document.getElementById('payload-detail-count').textContent = `${items.length} payload${items.length!==1?'s':''}`;
  if (!items.length) {
    wrap.innerHTML = '<p style="opacity:.5;font-size:12px;">No payloads yet. Import or add one above.</p>';
    return;
  }
  wrap.innerHTML = `
    <table class="findings-table">
      <thead><tr><th>#</th><th>Payload</th><th>Note</th><th></th></tr></thead>
      <tbody>
        ${items.map((p, i) => `
          <tr>
            <td style="opacity:.5;">${i+1}</td>
            <td><code style="font-size:11px;color:#e2e8f0;word-break:break-all;">${_esc(p.value)}</code></td>
            <td style="opacity:.6;font-size:11px;">${_esc(p.note||'')}</td>
            <td>
              <button class="btn btn-sm btn-ghost" onclick="navigator.clipboard?.writeText(${JSON.stringify(p.value)}).then(()=>_toast('Copied','ok'))" title="Copy payload">📋</button>
              <button class="btn btn-sm btn-danger" onclick="deletePayload('${_esc(p.id)}')" title="Delete">✕</button>
            </td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

window.searchPayloads = function(val) {
  clearTimeout(_plState.searchTimer);
  _plState.searchTimer = setTimeout(() => {
    if (_plState.openListId) refreshPayloadTable(_plState.openListId, val);
  }, 300);
};

// ─── Create new list ─────────────────────────────────────────────────────────
document.getElementById('btn-new-payload-list').addEventListener('click', async () => {
  const name = prompt('Payload list name:');
  if (!name?.trim()) return;
  const category = prompt('Category (sqli / xss / traversal / redirect / lfi / cmdi / custom / seclists):', 'custom') || 'custom';
  const description = prompt('Description (optional):') || '';
  const r = await _api('/api/payloads/lists', {
    method: 'POST',
    body: JSON.stringify({ name: name.trim(), category, description }),
  });
  if (r.ok) {
    _log(`Payload list created: ${name.trim()}`, 'ok');
    _toast(`List "${name.trim()}" created`, 'ok');
    loadPayloadPage();
  } else {
    _toast('Failed to create list', 'crit');
  }
});

// ─── Delete list ─────────────────────────────────────────────────────────────
async function deletePayloadList(listId, listName) {
  if (!confirm(`Delete list "${listName}" and ALL its payloads? This cannot be undone.`)) return;
  const r = await _api(`/api/payloads/lists/${listId}`, { method: 'DELETE' });
  if (r.ok) {
    _log(`Deleted payload list: ${listName}`, 'warn');
    _toast(`Deleted: ${listName}`, 'warn');
    closePayloadDetail();
  } else {
    _toast('Delete failed', 'crit');
  }
}
window.deletePayloadList = deletePayloadList;

// ─── Copy entire list to clipboard ───────────────────────────────────────────
async function copyPayloadList(listId, listName) {
  const r = await _api(`/api/payloads/lists/${listId}?limit=5000`);
  if (!r.ok) { _toast('Could not load list', 'crit'); return; }
  const text = (r.data.payloads || []).map(p => p.value).join('\n');
  navigator.clipboard?.writeText(text).then(() => {
    _toast(`Copied ${r.data.payloads.length} payloads from "${listName}"`, 'ok');
    _log(`Clipboard: ${r.data.payloads.length} payloads from ${listName}`, 'ok');
  });
}
window.copyPayloadList = copyPayloadList;

// ─── Add single payload ───────────────────────────────────────────────────────
document.getElementById('btn-add-single-payload').addEventListener('click', async () => {
  if (!_plState.openListId) return;
  const value = document.getElementById('payload-add-value').value.trim();
  const note  = document.getElementById('payload-add-note').value.trim();
  if (!value) { _toast('Enter a payload value', 'warn'); return; }
  const r = await _api(`/api/payloads/lists/${_plState.openListId}/payloads`, {
    method: 'POST',
    body: JSON.stringify({ value, note }),
  });
  if (r.ok) {
    document.getElementById('payload-add-value').value = '';
    document.getElementById('payload-add-note').value  = '';
    _toast('Payload added', 'ok');
    refreshPayloadTable(_plState.openListId);
  } else {
    _toast('Failed to add payload', 'crit');
  }
});

// ─── Delete single payload ────────────────────────────────────────────────────
async function deletePayload(payloadId) {
  const r = await _api(`/api/payloads/${payloadId}`, { method: 'DELETE' });
  if (r.ok) {
    refreshPayloadTable(_plState.openListId, document.getElementById('payload-search').value || '');
  } else {
    _toast('Delete failed', 'crit');
  }
}
window.deletePayload = deletePayload;

// ─── Import from URL ──────────────────────────────────────────────────────────
document.getElementById('btn-import-url').addEventListener('click', async () => {
  if (!_plState.openListId) return;
  const url     = document.getElementById('payload-import-url').value.trim();
  const replace = document.getElementById('payload-import-replace').checked;
  if (!url) { _toast('Enter a URL', 'warn'); return; }
  _log(`Importing from URL: ${url}`, 'info');
  _toast('Importing…', 'info');
  const r = await _api(`/api/payloads/lists/${_plState.openListId}/import`, {
    method: 'POST',
    body: JSON.stringify({ url, replace }),
  });
  if (r.ok) {
    const d = r.data;
    _log(`Import done: ${d.added} added (${d.parsed} parsed, capped at ${d.capped})`, 'ok');
    _toast(`✓ Imported ${d.added} payloads`, 'ok');
    document.getElementById('payload-import-url').value = '';
    refreshPayloadTable(_plState.openListId);
  } else {
    _log(`Import failed: ${r.data?.error || 'unknown'}`, 'crit');
    _toast(`Import failed: ${r.data?.error || 'error'}`, 'crit');
  }
});

// ─── Import from pasted text ──────────────────────────────────────────────────
document.getElementById('btn-import-text').addEventListener('click', async () => {
  if (!_plState.openListId) return;
  const text    = document.getElementById('payload-import-text').value;
  const replace = document.getElementById('payload-import-replace').checked;
  if (!text.trim()) { _toast('Paste some payloads first', 'warn'); return; }
  const r = await _api(`/api/payloads/lists/${_plState.openListId}/import`, {
    method: 'POST',
    body: JSON.stringify({ text, replace }),
  });
  if (r.ok) {
    const d = r.data;
    _log(`Paste import done: ${d.added} added`, 'ok');
    _toast(`✓ Imported ${d.added} payloads`, 'ok');
    document.getElementById('payload-import-text').value = '';
    refreshPayloadTable(_plState.openListId);
  } else {
    _log(`Import failed: ${r.data?.error || 'unknown'}`, 'crit');
    _toast(`Import failed: ${r.data?.error || 'error'}`, 'crit');
  }
});
