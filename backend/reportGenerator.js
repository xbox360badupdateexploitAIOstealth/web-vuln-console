// backend/reportGenerator.js
// Generates a full HTML or Markdown pentest report from job results.

const { getJob, getJobResult } = require('./jobsStore');

const SEV_ORDER = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    return (SEV_ORDER[a.severity] || 9) - (SEV_ORDER[b.severity] || 9);
  });
}

function sevBadge(sev) {
  const colors = {
    critical: '#ef4444',
    high:     '#f97316',
    medium:   '#eab308',
    low:      '#22c55e',
    info:     '#3b82f6',
  };
  const color = colors[sev] || '#888';
  return `<span style="display:inline-block;padding:2px 8px;background:${color}20;color:${color};border:1px solid ${color}60;border-radius:999px;font-size:11px;text-transform:uppercase;">${sev}</span>`;
}

function generateHTMLReport(jobId) {
  const job = getJob(jobId);
  if (!job) return '<p>Job not found.</p>';
  const { findings, logs } = getJobResult(jobId);
  const sorted = sortFindings(findings);

  const critCount  = sorted.filter((f) => f.severity === 'critical').length;
  const highCount  = sorted.filter((f) => f.severity === 'high').length;
  const otherCount = sorted.filter((f) => !['critical', 'high'].includes(f.severity)).length;

  const targets = Array.isArray(job.targets)
    ? job.targets.map((t) => (typeof t === 'string' ? t : t.host || t.url)).join(', ')
    : '-';

  const findingRows = sorted
    .map((f, idx) => `
      <tr>
        <td style="padding:8px 10px;border-bottom:1px solid #1f2937;">${idx + 1}</td>
        <td style="padding:8px 10px;border-bottom:1px solid #1f2937;">${sevBadge(f.severity)}</td>
        <td style="padding:8px 10px;border-bottom:1px solid #1f2937;">${escHtml(f.category || '')}</td>
        <td style="padding:8px 10px;border-bottom:1px solid #1f2937;">${escHtml(f.title || '')}</td>
        <td style="padding:8px 10px;border-bottom:1px solid #1f2937;font-size:11px;"><a href="${escHtml(f.url || '')}" style="color:#60a5fa;word-break:break-all;">${escHtml(f.url || '')}</a></td>
        <td style="padding:8px 10px;border-bottom:1px solid #1f2937;font-size:10px;white-space:pre-wrap;max-width:300px;overflow:auto;">${escHtml((f.bodySnippet || '').slice(0, 200))}</td>
      </tr>
    `)
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Pentest Report – ${escHtml(job.description || job.projectId)}</title>
  <style>
    body { background:#030712; color:#e5e7eb; font-family:monospace; margin:0; padding:20px 30px; }
    h1 { font-size:20px; margin-bottom:4px; }
    h2 { font-size:14px; border-bottom:1px solid #1f2937; padding-bottom:6px; margin:24px 0 10px; }
    table { width:100%; border-collapse:collapse; font-size:12px; }
    th { text-align:left; padding:8px 10px; border-bottom:2px solid #1f2937; font-size:11px; opacity:.7; }
    .stats { display:flex; gap:16px; margin:12px 0 20px; }
    .stat-box { background:#0f172a; border:1px solid #1f2937; border-radius:6px; padding:10px 16px; }
    .stat-box .num { font-size:24px; font-weight:700; }
    .stat-box .lbl { font-size:11px; opacity:.7; margin-top:2px; }
  </style>
</head>
<body>
  <h1>Pentest Report</h1>
  <p style="font-size:12px;opacity:.7;">Project: ${escHtml(job.projectId)} &nbsp;|&nbsp; Job: ${escHtml(job.id)} &nbsp;|&nbsp; Generated: ${new Date().toISOString()}</p>
  <p style="font-size:12px;opacity:.7;">Targets: ${escHtml(targets)}</p>

  <div class="stats">
    <div class="stat-box"><div class="num" style="color:#ef4444;">${critCount}</div><div class="lbl">Critical</div></div>
    <div class="stat-box"><div class="num" style="color:#f97316;">${highCount}</div><div class="lbl">High</div></div>
    <div class="stat-box"><div class="num" style="color:#94a3b8;">${otherCount}</div><div class="lbl">Other</div></div>
    <div class="stat-box"><div class="num">${sorted.length}</div><div class="lbl">Total Findings</div></div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Severity</th>
        <th>Category</th>
        <th>Title</th>
        <th>URL</th>
        <th>Evidence snippet</th>
      </tr>
    </thead>
    <tbody>${findingRows}</tbody>
  </table>

  <h2>Scan Logs</h2>
  <pre style="background:#020617;border:1px solid #111827;padding:10px;border-radius:4px;font-size:11px;overflow:auto;max-height:400px;">${escHtml(logs.slice(0, 300).join('\n'))}</pre>

  <p style="font-size:10px;opacity:.4;margin-top:30px;">AUTHORIZED SECURITY TESTING ONLY. All targets tested with explicit written permission.</p>
</body>
</html>`;
}

function generateMarkdownReport(jobId) {
  const job = getJob(jobId);
  if (!job) return '# Job not found';
  const { findings, logs } = getJobResult(jobId);
  const sorted = sortFindings(findings);

  const lines = [
    `# Pentest Report`,
    ``,
    `**Project:** ${job.projectId}  `,
    `**Job ID:** ${job.id}  `,
    `**Date:** ${new Date().toISOString()}  `,
    `**Status:** ${job.status}  `,
    ``,
    `## Executive Summary`,
    ``,
    `| Severity | Count |`,
    `|---|---|`,
    `| Critical | ${sorted.filter((f) => f.severity === 'critical').length} |`,
    `| High | ${sorted.filter((f) => f.severity === 'high').length} |`,
    `| Medium | ${sorted.filter((f) => f.severity === 'medium').length} |`,
    `| Low | ${sorted.filter((f) => f.severity === 'low').length} |`,
    `| Info | ${sorted.filter((f) => f.severity === 'info').length} |`,
    ``,
    `## Findings`,
    ``,
  ];

  for (const [idx, f] of sorted.entries()) {
    lines.push(`### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title || ''}`);
    lines.push(``);
    lines.push(`- **Category:** ${f.category || ''}`);
    lines.push(`- **URL:** ${f.url || ''}`);
    lines.push(`- **HTTP Status:** ${f.statusCode || ''}`);
    if (f.bodySnippet) {
      lines.push(``);
      lines.push('```');
      lines.push(f.bodySnippet.slice(0, 300));
      lines.push('```');
    }
    lines.push(``);
  }

  lines.push(`## Logs`);
  lines.push(``);
  lines.push('```');
  lines.push(...logs.slice(0, 200));
  lines.push('```');
  lines.push(``);
  lines.push(`---`);
  lines.push(`*Authorized security testing only.*`);

  return lines.join('\n');
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

module.exports = { generateHTMLReport, generateMarkdownReport };
