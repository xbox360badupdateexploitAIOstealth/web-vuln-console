/* =================================================================
   WebVulnConsole ⚡ — Report Generator  (Task 7 / TODO-10)
   Generates a full pentest report from a project's findings.
   Exports (plain script globals, NOT ES modules):
   - loadReports()          called by app.js showPage('reports')
   - window._reportPreview(id)
   - window._reportExportHtml()
   - window._reportExportMd()
   - window._reportPreviewHtml()
   State bridge: reads window._wvcState (set by app.js at boot)
   Toasts/logs:  calls window._wvcToast / window._wvcClog
   ================================================================= */
'use strict';

// ─── Severity ordering ─────────────────────────────────────────────────
const SEV_ORDER  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_COLORS = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280' };

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escMd(s) {
  return String(s || '').replace(/([\\`*_{}[\]()#+\-.!|])/g, '\\$1');
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
  if (score > 0)   return 'LOW RISK';
  return 'NO FINDINGS';
}
function computeScore(findings) {
  if (!findings.length) return 0;
  const W = { critical:30, high:15, medium:6, low:2, info:0.5 };
  const raw = findings.reduce((a, f) => a + (W[f.severity] || 0), 0);
  const breadth = Math.min(new Set(findings.map(f => f.category)).size * 2, 20);
  return Math.min(Math.round(raw + breadth), 100);
}

// ─── Build report data from state ─────────────────────────────────────────
function buildReportData(projectId) {
  const st       = window._wvcState || {};
  const projects = st.projects || [];
  const project  = projects.find(p => p.id === projectId);
  if (!project) return null;

  const allFindings = (st.findings || []).filter(f => f.projectId === projectId);
  const sorted = [...allFindings].sort((a, b) =>
    (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  );

  const counts = { critical:0, high:0, medium:0, low:0, info:0 };
  sorted.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

  const targets  = (st.targets?.[projectId] || []);
  const score    = computeScore(sorted);
  const genDate  = new Date().toLocaleDateString('en-GB', { year:'numeric', month:'long', day:'numeric' });

  return { project, targets, findings: sorted, counts, score, genDate };
}

// ─── HTML Report ──────────────────────────────────────────────────────────────
function generateHtmlReport(data) {
  const { project, targets, findings, counts, score, genDate } = data;
  const col   = riskColor(score);
  const label = riskLabel(score);

  const findingRows = findings.map((f) => {
    const c = SEV_COLORS[f.severity] || '#6b7280';
    return `
      <tr>
        <td style="padding:10px 12px;font-weight:600;color:#1e293b;">${esc(f.title || 'Untitled')}</td>
        <td style="padding:10px 12px;">
          <span style="background:${c}22;color:${c};border:1px solid ${c}55;
            padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;">
            ${esc(f.severity)}
          </span>
        </td>
        <td style="padding:10px 12px;font-size:12px;color:#64748b;">${esc(f.category || '—')}</td>
        <td style="padding:10px 12px;font-size:12px;word-break:break-all;">
          <a href="${esc(f.url||'#')}" style="color:#2563eb;">${esc(f.url || '—')}</a>
        </td>
        <td style="padding:10px 12px;font-size:11px;color:#475569;">${esc(f.statusCode || '—')}</td>
      </tr>
      ${f.note || f.bodySnippet ? `
      <tr style="background:#f8fafc;">
        <td colspan="5" style="padding:8px 12px 12px 24px;font-size:12px;color:#475569;">
          ${f.note ? `<div><strong>Note:</strong> ${esc(f.note)}</div>` : ''}
          ${f.bodySnippet ? `<details><summary style="cursor:pointer;color:#64748b;font-size:11px;">Evidence snippet</summary><pre style="margin:6px 0 0;font-size:11px;background:#f1f5f9;padding:8px;border-radius:4px;overflow:auto;max-height:120px;">${esc(f.bodySnippet.slice(0,600))}</pre></details>` : ''}
        </td>
      </tr>` : ''}
    `;
  }).join('');

  const targetRows = targets.map(t =>
    `<tr><td style="padding:7px 12px;font-size:12px;">${esc(t.host || t.url || t)}</td>
         <td style="padding:7px 12px;font-size:12px;color:#64748b;">${esc(t.type || 'website')}</td>
         <td style="padding:7px 12px;font-size:12px;color:#64748b;">${esc(t.env || 'prod')}</td></tr>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Pentest Report — ${esc(project.name)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body   { font-family: 'Segoe UI', system-ui, sans-serif; font-size: 13px;
             background: #fff; color: #1e293b; line-height: 1.6; }
    .page  { max-width: 900px; margin: 0 auto; padding: 40px 32px; }
    h1     { font-size: 24px; font-weight: 800; color: #0f172a; margin-bottom: 4px; }
    h2     { font-size: 16px; font-weight: 700; color: #0f172a; margin: 32px 0 10px;
             padding-bottom: 6px; border-bottom: 2px solid #e2e8f0; }
    h3     { font-size: 13px; font-weight: 700; color: #334155; margin: 16px 0 6px; }
    p      { margin-bottom: 8px; color: #334155; }
    table  { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
    th     { background: #f1f5f9; text-align: left; padding: 8px 12px;
             font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
             color: #64748b; border-bottom: 2px solid #e2e8f0; }
    tr:nth-child(even) td { background: #f8fafc; }
    .badge { display:inline-block; padding:3px 9px; border-radius:4px;
             font-size:11px; font-weight:700; text-transform:uppercase; }
    .risk-block { border-left: 4px solid ${col}; padding: 12px 16px;
                  background: ${col}11; border-radius: 0 6px 6px 0; margin-bottom: 20px; }
    .stat-row  { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
    .stat-box  { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
                 padding: 12px 18px; min-width: 90px; flex: 1; }
    .stat-num  { font-size: 24px; font-weight: 800; }
    .stat-lbl  { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: .06em; }
    .footer    { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e2e8f0;
                 font-size: 11px; color: #94a3b8; text-align: center; }
    @media print {
      body { font-size: 12px; }
      .page { padding: 20px; }
      h2 { page-break-before: auto; }
    }
  </style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;flex-wrap:wrap;gap:12px;">
    <div>
      <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Web Application Security Assessment</div>
      <h1>${esc(project.name)}</h1>
      ${project.client ? `<div style="font-size:13px;color:#64748b;margin-top:4px;">Client: <strong>${esc(project.client)}</strong></div>` : ''}
      ${project.scope  ? `<div style="font-size:12px;color:#94a3b8;margin-top:2px;">Scope: ${esc(project.scope)}</div>` : ''}
    </div>
    <div style="text-align:right;font-size:11px;color:#94a3b8;">
      <div>Generated: ${esc(genDate)}</div>
      <div>Tool: WebVulnConsole ⚡</div>
      <div>Status: <strong style="color:#${project.status==='completed'?'22c55e':'f97316'}">${esc((project.status||'active').toUpperCase())}</strong></div>
    </div>
  </div>

  <!-- Risk banner -->
  <div class="risk-block">
    <div style="font-size:20px;font-weight:800;color:${col};">${label} — Score: ${score}/100</div>
    <div style="font-size:12px;color:#475569;margin-top:4px;">
      ${findings.length} finding${findings.length !== 1 ? 's' : ''} across ${targets.length} target${targets.length !== 1 ? 's' : ''}.
    </div>
  </div>

  <!-- Severity stats -->
  <div class="stat-row">
    ${Object.entries(counts).map(([sev, n]) => {
      const c = SEV_COLORS[sev] || '#6b7280';
      return `<div class="stat-box">
        <div class="stat-num" style="color:${c};">${n}</div>
        <div class="stat-lbl">${sev}</div>
      </div>`;
    }).join('')}
  </div>

  <!-- Executive Summary -->
  <h2>Executive Summary</h2>
  <p>This report documents the findings of a web application security assessment conducted using WebVulnConsole.
  The assessment covered ${targets.length} target${targets.length!==1?'s':''} under the scope of project
  <strong>${esc(project.name)}</strong>${project.client ? ` for <strong>${esc(project.client)}</strong>` : ''}.</p>
  <p>A total of <strong>${findings.length} security finding${findings.length!==1?'s were':' was'} identified</strong>,
  including ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium,
  ${counts.low} low, and ${counts.info} informational issues.
  The overall risk score is <strong style="color:${col};">${score}/100 (${label})</strong>.</p>
  ${findings.length === 0 ? '<p style="color:#22c55e;font-weight:600;">No vulnerabilities were detected during this assessment.</p>' : ''}

  <!-- Targets -->
  ${targets.length ? `
  <h2>Targets in Scope</h2>
  <table>
    <thead><tr><th>Host / URL</th><th>Type</th><th>Environment</th></tr></thead>
    <tbody>${targetRows}</tbody>
  </table>` : ''}

  <!-- Findings table -->
  ${findings.length ? `
  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th style="width:30%;">Title</th>
        <th style="width:10%;">Severity</th>
        <th style="width:14%;">Category</th>
        <th>URL</th>
        <th style="width:7%;">Status</th>
      </tr>
    </thead>
    <tbody>${findingRows}</tbody>
  </table>` : ''}

  <!-- Recommendations -->
  <h2>General Recommendations</h2>
  <ol style="padding-left:18px;line-height:2;">
    <li>Remediate all Critical and High findings before next deployment.</li>
    <li>Enforce HTTPS site-wide with HSTS (max-age ≥ 31536000).</li>
    <li>Add all missing security headers (CSP, X-Frame-Options, X-Content-Type-Options).</li>
    <li>Remove all backup files, .env files, and debug pages from web roots.</li>
    <li>Use parameterized queries for all database interactions.</li>
    <li>Implement a WAF and schedule regular automated security scans.</li>
    <li>Re-test all findings after remediation to verify closure.</li>
  </ol>

  <div class="footer">
    Generated by WebVulnConsole ⚡ &mdash; For authorized use only.
    This report is confidential and intended solely for the named client.
  </div>
</div>
</body>
</html>`;
}

// ─── Markdown Report ───────────────────────────────────────────────────────────
function generateMarkdownReport(data) {
  const { project, targets, findings, counts, score, genDate } = data;
  const label = riskLabel(score);
  const lines = [];

  lines.push(`# Pentest Report: ${escMd(project.name)}`);
  lines.push('');
  lines.push(`> **Generated:** ${genDate}  `);
  if (project.client) lines.push(`> **Client:** ${escMd(project.client)}  `);
  if (project.scope)  lines.push(`> **Scope:** ${escMd(project.scope)}  `);
  lines.push(`> **Risk Score:** ${score}/100 — ${label}  `);
  lines.push(`> **Tool:** WebVulnConsole ⚡`);
  lines.push('');

  lines.push('## Executive Summary');
  lines.push('');
  lines.push(`Total findings: **${findings.length}** across **${targets.length}** target${targets.length!==1?'s':''}.`);
  lines.push('');
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  Object.entries(counts).forEach(([sev, n]) => lines.push(`| ${sev.charAt(0).toUpperCase()+sev.slice(1)} | ${n} |`));
  lines.push('');

  if (targets.length) {
    lines.push('## Targets in Scope');
    lines.push('');
    lines.push('| Host / URL | Type | Environment |');
    lines.push('|------------|------|-------------|');
    targets.forEach(t =>
      lines.push(`| ${escMd(t.host||t.url||String(t))} | ${escMd(t.type||'website')} | ${escMd(t.env||'prod')} |`)
    );
    lines.push('');
  }

  if (findings.length) {
    lines.push('## Findings');
    lines.push('');
    findings.forEach((f, i) => {
      lines.push(`### ${i+1}. ${escMd(f.title || 'Untitled')}`);
      lines.push('');
      lines.push(`- **Severity:** ${f.severity || 'info'}`);
      lines.push(`- **Category:** ${f.category || '—'}`);
      lines.push(`- **URL:** ${f.url || '—'}`);
      lines.push(`- **HTTP Status:** ${f.statusCode || '—'}`);
      if (f.note)        lines.push(`- **Note:** ${escMd(f.note)}`);
      if (f.payload)     lines.push(`- **Payload:** \`${escMd(f.payload)}\``);
      if (f.bodySnippet) {
        lines.push('');
        lines.push('**Evidence:**');
        lines.push('```');
        lines.push(f.bodySnippet.slice(0, 400));
        lines.push('```');
      }
      lines.push('');
    });
  }

  lines.push('## General Recommendations');
  lines.push('');
  [
    'Remediate all Critical and High findings before next deployment.',
    'Enforce HTTPS site-wide with HSTS (max-age ≥ 31536000).',
    'Add all missing security headers (CSP, X-Frame-Options, X-Content-Type-Options).',
    'Remove all backup files, .env files, and debug pages from web roots.',
    'Use parameterized queries for all database interactions.',
    'Implement a WAF and schedule regular automated security scans.',
    'Re-test all findings after remediation to verify closure.',
  ].forEach((r, i) => lines.push(`${i+1}. ${r}`));
  lines.push('');
  lines.push('---');
  lines.push('*Generated by WebVulnConsole ⚡ — For authorized use only.*');

  return lines.join('\n');
}

// ─── Download helper ──────────────────────────────────────────────────────────
function download(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// ─── Reports page renderer ────────────────────────────────────────────────────
// NOTE: Plain global function — NOT an ES module export.
// app.js calls loadReports() directly via the nav loader map.
function loadReports() {
  const el = document.getElementById('page-reports');
  if (!el) return;

  const st       = window._wvcState || {};
  const projects = st.projects || [];
  const cur      = st.currentProject;

  if (!projects.length) {
    el.innerHTML = `<div style="padding:40px;text-align:center;color:#475569;">
      <div style="font-size:28px;margin-bottom:10px;">📄</div>
      <div style="font-size:13px;font-weight:600;color:#64748b;">No projects yet.</div>
      <div style="font-size:11px;margin-top:6px;">Create a project and run a scan first.</div>
    </div>`;
    return;
  }

  const projectOptions = projects.map(p =>
    `<option value="${esc(p.id)}" ${p.id === cur ? 'selected' : ''}>${esc(p.name)}</option>`
  ).join('');

  el.innerHTML = `
    <div style="max-width:680px;">
      <div style="display:flex;flex-direction:column;gap:14px;
        background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:20px;margin-bottom:16px;">

        <div style="font-size:13px;font-weight:700;color:#f1f5f9;">📄 Report Generator</div>

        <div style="display:flex;flex-direction:column;gap:5px;">
          <label style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;">Project</label>
          <select id="report-proj-select"
            style="background:#020617;border:1px solid #1e293b;border-radius:5px;color:#e2e8f0;
              font-family:monospace;font-size:12px;padding:8px 10px;outline:none;width:100%;"
            onchange="window._reportPreview(this.value)">
            ${projectOptions}
          </select>
        </div>

        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button onclick="window._reportExportHtml()"
            style="background:#38bdf8;color:#020617;border:none;font-family:monospace;
              font-size:12px;font-weight:700;padding:8px 16px;border-radius:5px;cursor:pointer;">
            💾 Export HTML
          </button>
          <button onclick="window._reportExportMd()"
            style="background:#1e293b;color:#94a3b8;border:1px solid #334155;font-family:monospace;
              font-size:12px;font-weight:600;padding:8px 16px;border-radius:5px;cursor:pointer;">
            📝 Export Markdown
          </button>
          <button onclick="window._reportPreviewHtml()"
            style="background:#1e293b;color:#94a3b8;border:1px solid #334155;font-family:monospace;
              font-size:12px;font-weight:600;padding:8px 16px;border-radius:5px;cursor:pointer;">
            👁 Preview in Tab
          </button>
        </div>
      </div>

      <div id="report-preview-card"></div>
    </div>
  `;

  const sel = document.getElementById('report-proj-select');
  if (sel) {
    sel.addEventListener('focus', () => sel.style.borderColor = '#38bdf8');
    sel.addEventListener('blur',  () => sel.style.borderColor = '#1e293b');
  }

  window._reportPreview(cur || projects[0]?.id);
}

// ─── Global handlers ──────────────────────────────────────────────────────────
window._reportPreview = function(projectId) {
  const card = document.getElementById('report-preview-card');
  if (!card || !projectId) return;

  const data = buildReportData(projectId);
  if (!data) { card.innerHTML = ''; return; }

  const { project, targets, findings, counts, score, genDate } = data;
  const col   = riskColor(score);
  const label = riskLabel(score);

  const pills = Object.entries(counts).map(([sev, n]) => {
    if (!n) return '';
    const c = SEV_COLORS[sev] || '#6b7280';
    return `<span style="background:${c}22;color:${c};border:1px solid ${c}44;
      padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;">${n} ${sev}</span>`;
  }).filter(Boolean).join('');

  card.innerHTML = `
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px;">
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px;">Report Preview</div>
      <div style="font-size:15px;font-weight:700;color:#f1f5f9;margin-bottom:4px;">${esc(project.name)}</div>
      ${project.client ? `<div style="font-size:11px;color:#64748b;margin-bottom:8px;">${esc(project.client)}</div>` : ''}
      <div style="display:flex;gap:16px;font-size:11px;color:#64748b;margin-bottom:12px;flex-wrap:wrap;">
        <span>🎯 ${targets.length} target${targets.length!==1?'s':''}</span>
        <span>📊 ${findings.length} finding${findings.length!==1?'s':''}</span>
        <span>📅 ${genDate}</span>
      </div>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
        <span style="font-size:18px;font-weight:800;color:${col};">${score}/100</span>
        <span style="font-size:11px;font-weight:700;color:${col};">${label}</span>
      </div>
      <div style="height:4px;background:#1e293b;border-radius:2px;overflow:hidden;margin-bottom:12px;">
        <div style="height:100%;width:${score}%;background:${col};border-radius:2px;"></div>
      </div>
      <div style="display:flex;gap:5px;flex-wrap:wrap;">${pills || '<span style="color:#475569;font-size:11px;">No findings</span>'}</div>
    </div>
  `;
};

window._reportExportHtml = function() {
  const id = document.getElementById('report-proj-select')?.value;
  if (!id) return;
  const data = buildReportData(id);
  if (!data) return;
  const html = generateHtmlReport(data);
  const slug = data.project.name.toLowerCase().replace(/[^a-z0-9]+/g,'-').slice(0,40);
  download(`wvc-report-${slug}-${Date.now()}.html`, html, 'text/html');
  window._wvcToast?.('HTML report downloaded ⚡', 'ok');
  window._wvcClog?.(`> report export html --project "${data.project.name}"`, 'cmd');
};

window._reportExportMd = function() {
  const id = document.getElementById('report-proj-select')?.value;
  if (!id) return;
  const data = buildReportData(id);
  if (!data) return;
  const md   = generateMarkdownReport(data);
  const slug = data.project.name.toLowerCase().replace(/[^a-z0-9]+/g,'-').slice(0,40);
  download(`wvc-report-${slug}-${Date.now()}.md`, md, 'text/markdown');
  window._wvcToast?.('Markdown report downloaded ⚡', 'ok');
  window._wvcClog?.(`> report export md --project "${data.project.name}"`, 'cmd');
};

window._reportPreviewHtml = function() {
  const id = document.getElementById('report-proj-select')?.value;
  if (!id) return;
  const data = buildReportData(id);
  if (!data) return;
  const html = generateHtmlReport(data);
  const win  = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); }
  window._wvcClog?.(`> report preview --project "${data.project.name}"`, 'cmd');
};
