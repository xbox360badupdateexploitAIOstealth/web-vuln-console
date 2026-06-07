// src/ui/views/findingsListView.js
// TODO-11: Slide-in detail side-panel on row click.
//   - URL, evidence snippet, OWASP/CWE tags, remediation guidance
//   - Status changer (open → confirmed → mitigated → false_positive)
//   - Copy URL button
//   - Severity + category filter bar

import { getLastScanContext } from '../state.js';

// ── Constants ───────────────────────────────────────────────────────────────────────
const SEV_ORDER = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
const SEV_COLOR = {
  critical : '#ef4444',
  high     : '#f97316',
  medium   : '#eab308',
  low      : '#3b82f6',
  info     : '#6b7280',
};
const STATUS_NEXT = {
  open          : 'confirmed',
  confirmed     : 'mitigated',
  mitigated     : 'false_positive',
  false_positive: 'open',
};
const STATUS_LABEL = {
  open          : '● Open',
  confirmed     : '✓ Confirmed',
  mitigated     : '🛡 Mitigated',
  false_positive: '✗ False Positive',
};
const STATUS_COLOR = {
  open          : '#ef4444',
  confirmed     : '#f97316',
  mitigated     : '#22c55e',
  false_positive: '#6b7280',
};

const OWASP_MAP = {
  ENV_FILE        : 'A05:2021 – Security Misconfiguration',
  GIT_REPO        : 'A05:2021 – Security Misconfiguration',
  CONFIG_FILE     : 'A05:2021 – Security Misconfiguration',
  DB_DUMP         : 'A02:2021 – Cryptographic Failures',
  BACKUP          : 'A05:2021 – Security Misconfiguration',
  DEBUG           : 'A05:2021 – Security Misconfiguration',
  SQLI            : 'A03:2021 – Injection',
  XSS             : 'A03:2021 – Injection',
  PATH_TRAVERSAL  : 'A01:2021 – Broken Access Control',
  CMDI            : 'A03:2021 – Injection',
  SSTI            : 'A03:2021 – Injection',
  FILE_UPLOAD     : 'A04:2021 – Insecure Design',
  HEADERS         : 'A05:2021 – Security Misconfiguration',
  TLS             : 'A02:2021 – Cryptographic Failures',
  COOKIE          : 'A05:2021 – Security Misconfiguration',
  EXPOSURE        : 'A05:2021 – Security Misconfiguration',
  LEAK            : 'A02:2021 – Cryptographic Failures',
};
const CWE_MAP = {
  ENV_FILE       : 'CWE-538',
  GIT_REPO       : 'CWE-538',
  CONFIG_FILE    : 'CWE-312',
  DB_DUMP        : 'CWE-312',
  SQLI           : 'CWE-89',
  XSS            : 'CWE-79',
  PATH_TRAVERSAL : 'CWE-22',
  CMDI           : 'CWE-78',
  SSTI           : 'CWE-94',
  FILE_UPLOAD    : 'CWE-434',
  HEADERS        : 'CWE-693',
  TLS            : 'CWE-326',
  COOKIE         : 'CWE-614',
};
const REMEDIATION_MAP = {
  ENV_FILE       : 'Remove .env files from web root. Add .env to .gitignore. Inject secrets via runtime environment variables — never commit them.',
  GIT_REPO       : 'Block /.git access in web server config or delete the directory from the web root. Use a deployment pipeline that excludes repo metadata.',
  CONFIG_FILE    : 'Move config files outside the web root. Restrict file permissions. Never commit credentials.',
  DB_DUMP        : 'Delete SQL dump files immediately. Store backups off-server in private encrypted storage. Rotate all credentials found in the dump.',
  BACKUP         : 'Remove backup archives from web root. Store backups off-server. Rotate any credentials they may contain.',
  DEBUG          : 'Disable debug mode in production (APP_DEBUG=false, display_errors=Off). Remove phpinfo.php and test files.',
  SQLI           : 'Use parameterized queries / prepared statements. Never interpolate user input into SQL strings. Deploy a WAF.',
  XSS            : 'HTML-encode all user-supplied output. Implement a strong Content-Security-Policy header. Use framework-level auto-escaping.',
  PATH_TRAVERSAL : 'Validate and sanitize all file path inputs. Use allowlisted directory access. Ensure web server does not serve files outside the web root.',
  CMDI           : 'Never pass user input to shell commands. Use language-native APIs instead of shell invocation. Apply strict input allowlisting.',
  SSTI           : 'Disable untrusted template rendering. Sandbox template engines. Never pass raw user input into template strings.',
  FILE_UPLOAD    : 'Validate file types server-side (MIME + extension). Store uploads outside web root. Rename uploaded files. Never execute uploaded content.',
  HEADERS        : 'Add the missing security header in your web server or application config. Validate at securityheaders.com.',
  TLS            : 'Enable HTTPS, configure HSTS (max-age ≥ 31536000), disable weak cipher suites.',
  COOKIE         : 'Set HttpOnly, Secure, and SameSite=Strict flags on all session cookies.',
  EXPOSURE       : 'Restrict access to sensitive files. Ensure backups, logs, and config files are not web-accessible.',
  LEAK           : 'Remove .DS_Store files (add to .gitignore). They expose directory structure to attackers.',
};

// ── State for in-memory status overrides ────────────────────────────────────────
const _statusOverrides = {}; // { [findingId]: status }

// ─────────────────────────────────────────────────────────────────────────────
export function renderFindingsList(container) {
  const ctx = getLastScanContext();

  if (!ctx || !ctx.findings || !ctx.findings.length) {
    container.innerHTML = `
      <h1>Findings</h1>
      <p style="margin-top:6px;font-size:12px;opacity:.75;">
        No findings loaded. Run a scan from the Scan Jobs view first.
      </p>`;
    return;
  }

  const allFindings = [...ctx.findings].sort((a, b) => {
    const sa = SEV_ORDER[a.severity] || 99;
    const sb = SEV_ORDER[b.severity] || 99;
    return sa !== sb ? sa - sb : (a.title || '').localeCompare(b.title || '');
  });

  // Derive category list for filter
  const categories = [...new Set(allFindings.map(f => f.category).filter(Boolean))].sort();

  container.innerHTML = `
    <h1>Findings <span id="fl-count" style="font-size:13px;opacity:.5;"></span></h1>

    <!-- Filter bar -->
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 10px;align-items:center;">
      <select id="fl-filter-sev" style="${_selectStyle()}">
        <option value="">All Severities</option>
        ${['critical','high','medium','low','info'].map(s =>
          `<option value="${s}">${s.charAt(0).toUpperCase()+s.slice(1)}</option>`).join('')}
      </select>
      <select id="fl-filter-cat" style="${_selectStyle()}">
        <option value="">All Categories</option>
        ${categories.map(c => `<option value="${c}">${_esc(c)}</option>`).join('')}
      </select>
      <select id="fl-filter-status" style="${_selectStyle()}">
        <option value="">All Statuses</option>
        ${Object.keys(STATUS_LABEL).map(s =>
          `<option value="${s}">${STATUS_LABEL[s]}</option>`).join('')}
      </select>
      <input id="fl-search" type="text" placeholder="🔍 Search title / URL…"
        style="${_selectStyle()}flex:1;min-width:150px;" />
    </div>

    <!-- 2-column layout: table + slide-in panel -->
    <div style="display:grid;grid-template-columns:1fr;gap:10px;" id="fl-layout">

      <!-- Table -->
      <div style="overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;font-size:12px;" id="fl-table">
          <thead>
            <tr style="border-bottom:2px solid #1e293b;">
              <th style="${_thStyle()}width:90px;">Severity</th>
              <th style="${_thStyle()}">Title</th>
              <th style="${_thStyle()}width:120px;">Category</th>
              <th style="${_thStyle()}width:160px;">Target</th>
              <th style="${_thStyle()}width:90px;">Status</th>
            </tr>
          </thead>
          <tbody id="fl-tbody"></tbody>
        </table>
      </div>

      <!-- Detail panel (hidden until row click) -->
      <div id="fl-detail-panel" style="display:none;background:#0a0f1a;border:1px solid #1e293b;
        border-radius:8px;padding:16px;font-size:12px;position:relative;">

        <button id="fl-detail-close" title="Close panel"
          style="position:absolute;top:10px;right:10px;background:none;border:none;
            color:#64748b;font-size:16px;cursor:pointer;line-height:1;">✕</button>

        <!-- Severity + title -->
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap;">
          <span id="dp-sev-badge"></span>
          <span id="dp-cat-tag" style="font-size:10px;background:#1e293b;padding:2px 7px;
            border-radius:4px;color:#94a3b8;"></span>
        </div>
        <div id="dp-title" style="font-size:14px;font-weight:700;color:#f1f5f9;margin-bottom:12px;line-height:1.4;"></div>

        <!-- URL row -->
        <div style="margin-bottom:10px;">
          <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:3px;">URL</div>
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
            <a id="dp-url" href="#" target="_blank" rel="noopener"
              style="color:#38bdf8;word-break:break-all;font-size:11px;"></a>
            <button id="dp-copy-url"
              style="background:#1e293b;border:none;border-radius:4px;padding:2px 7px;
                color:#94a3b8;font-size:10px;cursor:pointer;white-space:nowrap;">
              📋 Copy
            </button>
          </div>
        </div>

        <!-- Meta row: HTTP status, module -->
        <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:10px;">
          <div>
            <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:2px;">HTTP Status</div>
            <span id="dp-http-status" style="font-family:monospace;"></span>
          </div>
          <div>
            <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:2px;">Module</div>
            <span id="dp-module" style="font-family:monospace;font-size:11px;"></span>
          </div>
        </div>

        <!-- OWASP + CWE tags -->
        <div id="dp-tags" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;"></div>

        <!-- Description -->
        <div id="dp-desc-wrap" style="margin-bottom:12px;">
          <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px;">Description</div>
          <div id="dp-desc" style="line-height:1.6;opacity:.85;"></div>
        </div>

        <!-- Evidence snippet -->
        <div id="dp-evidence-wrap" style="margin-bottom:12px;display:none;">
          <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px;">Evidence Snippet</div>
          <pre id="dp-evidence" style="background:#020617;border:1px solid #1e293b;border-radius:5px;
            padding:8px;font-size:11px;overflow:auto;max-height:140px;white-space:pre-wrap;
            word-break:break-all;"></pre>
        </div>

        <!-- Remediation -->
        <div id="dp-rem-wrap" style="margin-bottom:14px;">
          <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px;">Remediation</div>
          <div id="dp-rem" style="line-height:1.6;opacity:.85;"></div>
        </div>

        <!-- Status changer -->
        <div style="border-top:1px solid #1e293b;padding-top:12px;">
          <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px;">Status</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            ${Object.keys(STATUS_LABEL).map(s => `
              <button class="dp-status-btn" data-status="${s}"
                style="border-radius:5px;padding:4px 10px;font-size:11px;font-weight:600;
                  cursor:pointer;border:1px solid ${STATUS_COLOR[s]}44;
                  background:${STATUS_COLOR[s]}11;color:${STATUS_COLOR[s]};">
                ${STATUS_LABEL[s]}
              </button>`).join('')}
          </div>
        </div>
      </div>

    </div>
  `;

  // Wire filters + search
  const tbody      = container.querySelector('#fl-tbody');
  const countEl    = container.querySelector('#fl-count');
  const detailPanel= container.querySelector('#fl-detail-panel');
  const layout     = container.querySelector('#fl-layout');

  let activeIdx = null;

  function applyFilters() {
    const sevF    = container.querySelector('#fl-filter-sev').value;
    const catF    = container.querySelector('#fl-filter-cat').value;
    const statusF = container.querySelector('#fl-filter-status').value;
    const q       = container.querySelector('#fl-search').value.trim().toLowerCase();

    const visible = allFindings.filter(f => {
      const status = _statusOverrides[f.id] || f.status || 'open';
      if (sevF    && f.severity !== sevF)    return false;
      if (catF    && f.category !== catF)    return false;
      if (statusF && status !== statusF)     return false;
      if (q && !(f.title||'').toLowerCase().includes(q) &&
               !(f.url||'').toLowerCase().includes(q))   return false;
      return true;
    });

    countEl.textContent = `(${visible.length} of ${allFindings.length})`;
    _renderRows(tbody, visible, ctx, (f, idx) => _openPanel(container, detailPanel, layout, f, ctx, allFindings));
    if (activeIdx !== null) detailPanel.style.display = 'block';
  }

  ['#fl-filter-sev','#fl-filter-cat','#fl-filter-status'].forEach(sel =>
    container.querySelector(sel).addEventListener('change', applyFilters));
  container.querySelector('#fl-search').addEventListener('input', applyFilters);

  // Close button
  container.querySelector('#fl-detail-close').addEventListener('click', () => {
    detailPanel.style.display = 'none';
    layout.style.gridTemplateColumns = '1fr';
    activeIdx = null;
  });

  applyFilters();
}

// ── Render rows ────────────────────────────────────────────────────────────────────
function _renderRows(tbody, findings, ctx, onClickFn) {
  if (!findings.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="padding:16px;text-align:center;opacity:.5;">No findings match the current filters.</td></tr>`;
    return;
  }
  tbody.innerHTML = findings.map((f, idx) => {
    const col    = SEV_COLOR[f.severity] || '#6b7280';
    const status = _statusOverrides[f.id] || f.status || 'open';
    const sColor = STATUS_COLOR[status] || '#6b7280';
    const target = (ctx.targets || []).find(t => t.id === f.targetId)?.host || (f.target || '—');
    return `
      <tr data-idx="${idx}" style="cursor:pointer;border-bottom:1px solid #111827;
        transition:background .12s;"
        onmouseover="this.style.background='#0f172a'"
        onmouseout="this.style.background=''">
        <td style="padding:6px 8px;">
          <span style="background:${col}22;color:${col};border:1px solid ${col}55;
            padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;
            text-transform:uppercase;">${_esc(f.severity||'info')}</span>
        </td>
        <td style="padding:6px 8px;font-weight:500;color:#e2e8f0;">${_esc(f.title||'')}</td>
        <td style="padding:6px 8px;font-size:11px;color:#94a3b8;">${_esc(f.category||'—')}</td>
        <td style="padding:6px 8px;font-size:11px;font-family:monospace;color:#94a3b8;
          max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
          title="${_esc(target)}">${_esc(target)}</td>
        <td style="padding:6px 8px;">
          <span style="font-size:10px;font-weight:600;color:${sColor};">${STATUS_LABEL[status]||status}</span>
        </td>
      </tr>`;
  }).join('');

  tbody.querySelectorAll('tr[data-idx]').forEach(tr => {
    tr.addEventListener('click', () => {
      const f = findings[parseInt(tr.dataset.idx, 10)];
      if (f) onClickFn(f);
    });
  });
}

// ── Open detail panel ───────────────────────────────────────────────────────────────
function _openPanel(container, panel, layout, f, ctx) {
  const evidence = (ctx.evidences || []).find(ev => ev.findingId === f.id) || null;
  const catKey   = (f.category || '').toUpperCase().replace(/[^A-Z_]/g, '');
  const col      = SEV_COLOR[f.severity] || '#6b7280';
  const status   = _statusOverrides[f.id] || f.status || 'open';

  // Severity badge
  container.querySelector('#dp-sev-badge').innerHTML =
    `<span style="background:${col}22;color:${col};border:1px solid ${col}55;
      padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;
      text-transform:uppercase;">${_esc(f.severity||'info')}</span>`;

  container.querySelector('#dp-cat-tag').textContent  = f.category || '';
  container.querySelector('#dp-title').textContent    = f.title    || 'Finding Detail';

  // URL
  const urlEl = container.querySelector('#dp-url');
  const url   = f.url || (evidence?.url) || '';
  urlEl.textContent = url || '—';
  urlEl.href        = url || '#';

  container.querySelector('#dp-http-status').textContent = f.statusCode || evidence?.responseStatus || '—';
  container.querySelector('#dp-module').textContent      = f.moduleId   || '—';

  // OWASP + CWE tags
  const tagsEl = container.querySelector('#dp-tags');
  const owasp  = f.owaspTag  || OWASP_MAP[catKey] || '';
  const cwe    = f.cweTag    || CWE_MAP[catKey]   || '';
  const cve    = f.cveTag    || '';
  tagsEl.innerHTML = [
    owasp ? `<span style="${_tagStyle('#3b82f6')}">${_esc(owasp)}</span>` : '',
    cwe   ? `<span style="${_tagStyle('#8b5cf6')}">${_esc(cwe)}</span>`   : '',
    cve   ? `<span style="${_tagStyle('#f97316')}">${_esc(cve)}</span>`   : '',
  ].join('');

  // Description
  const desc = f.detailedDescription || f.shortDescription || f.description || '';
  const descWrap = container.querySelector('#dp-desc-wrap');
  descWrap.style.display = desc ? 'block' : 'none';
  container.querySelector('#dp-desc').textContent = desc;

  // Evidence snippet
  const snippet = evidence?.responseBodySnippet || f.evidence || f.bodySnippet || '';
  const evWrap  = container.querySelector('#dp-evidence-wrap');
  evWrap.style.display = snippet ? 'block' : 'none';
  container.querySelector('#dp-evidence').textContent = snippet.slice(0, 600);

  // Remediation
  const rem = f.remediation || REMEDIATION_MAP[catKey] ||
    'Review the finding and apply least-privilege access. Restrict exposure and rotate any leaked credentials.';
  container.querySelector('#dp-rem').textContent = rem;

  // Highlight active status button
  container.querySelectorAll('.dp-status-btn').forEach(btn => {
    const s   = btn.dataset.status;
    const col = STATUS_COLOR[s] || '#6b7280';
    const active = (s === status);
    btn.style.background = active ? `${col}33` : `${col}11`;
    btn.style.borderColor = active ? col : `${col}44`;
    btn.style.transform  = active ? 'scale(1.05)' : 'scale(1)';
  });

  // Copy URL handler
  container.querySelector('#dp-copy-url').onclick = () => {
    navigator.clipboard?.writeText(url).then(() => {
      const b = container.querySelector('#dp-copy-url');
      const orig = b.textContent;
      b.textContent = '✓ Copied!';
      setTimeout(() => { b.textContent = orig; }, 1400);
    });
  };

  // Status change handlers
  container.querySelectorAll('.dp-status-btn').forEach(btn => {
    btn.onclick = () => {
      const newStatus = btn.dataset.status;
      _statusOverrides[f.id] = newStatus;
      // Re-highlight buttons
      container.querySelectorAll('.dp-status-btn').forEach(b => {
        const s   = b.dataset.status;
        const c   = STATUS_COLOR[s] || '#6b7280';
        const act = (s === newStatus);
        b.style.background  = act ? `${c}33` : `${c}11`;
        b.style.borderColor = act ? c : `${c}44`;
        b.style.transform   = act ? 'scale(1.05)' : 'scale(1)';
      });
      // Try to persist via API if available
      const api = window.API_BASE || window.CFG?.backendUrl || '';
      if (f.id && api) {
        fetch(`${api}/api/findings/${f.id}/status`, {
          method : 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body   : JSON.stringify({ status: newStatus }),
        }).catch(() => {}); // silent fail if backend unreachable
      }
    };
  });

  // Show panel + switch to 2-column layout on wider viewports
  panel.style.display = 'block';
  if (window.innerWidth >= 900) {
    layout.style.gridTemplateColumns = 'minmax(0,1.4fr) minmax(0,1fr)';
  }
}

// ── Tiny helpers ───────────────────────────────────────────────────────────────────────
function _esc(s) {
  return String(s||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _thStyle() {
  return 'text-align:left;padding:6px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#64748b;';
}
function _selectStyle() {
  return 'background:#0f172a;border:1px solid #1e293b;border-radius:5px;color:#e2e8f0;font-size:11px;padding:5px 8px;outline:none;';
}
function _tagStyle(color) {
  return `background:${color}18;color:${color};border:1px solid ${color}44;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;`;
}
