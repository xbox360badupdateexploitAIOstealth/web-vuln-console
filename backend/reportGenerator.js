// backend/reportGenerator.js
// Generates full HTML or Markdown pentest reports from job results.
// Includes risk score, remediation, and payload evidence.

const { getJob, getJobResult } = require('./jobsStore');
const { computeRiskScore, sortFindingsBySeverity } = require('./utils/severityScore');

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;');
}

const SEV_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#3b82f6',
};

const REMEDIATION = {
  ENV_FILE:    'Remove .env and related config files from the web root. Use environment variables set at the server level, never committed or web-accessible.',
  GIT_REPO:    'Block access to /.git via server config (e.g., deny in Nginx/Apache). Never deploy to production from a directory containing a .git folder.',
  SVN_REPO:    'Block access to /.svn in server config. Remove version control metadata from production deployments.',
  HG_REPO:     'Block access to /.hg in server config. Remove Mercurial metadata from production deployments.',
  CONFIG_FILE: 'Move all config files outside the web root. Restrict access via server configuration. Never expose backup or .bak variants.',
  DB_DUMP:     'Remove all SQL dumps from public-facing directories immediately. Store backups outside the web root with strict access controls.',
  BACKUP:      'Remove all archive/backup files from public directories. Automate backups to off-site, access-controlled storage.',
  DEBUG:       'Disable debug/phpinfo endpoints in production. Set error_reporting=0 and display_errors=Off. Remove test/debug scripts.',
  ADMIN:       'Restrict admin directories with IP allowlisting, VPN access, or authentication. Avoid guessable admin paths.',
  LEAK:        'Remove metadata files (.DS_Store etc.) from production. Add to .gitignore and web server deny rules.',
  POLICY:      'Review crossdomain.xml / clientaccesspolicy.xml for overly permissive allow-access-from rules. Restrict to known origins only.',
  CLOUD_META:  'Restrict access to AWS/GCP metadata endpoints via VPC security groups. Never expose metadata to public internet.',
  ERROR_PAGE:  'Configure a custom error handler that returns generic error messages. Disable framework debug mode in production.',
  DEBUG_LEAK:  'Remove or disable debug output. Set framework to production mode. Implement a global exception handler that logs internally but returns generic user-facing errors.',
  SQLI:        'Use parameterized queries / prepared statements. Apply input validation and escaping. Deploy a WAF as defense-in-depth.',
  XSS:         'Encode all user-controlled output. Implement a strict Content-Security-Policy. Sanitize inputs server-side.',
  RECON:       'Review robots.txt for sensitive path disclosures. Consider not listing disallowed paths publicly. Ensure sitemap only includes intended public pages.',
};

function getRemediation(category) {
  return REMEDIATION[category] || 'Review the finding, assess exposure, and apply the principle of least privilege.';
}

function sevBadgeHtml(sev) {
  const c = SEV_COLORS[sev] || '#888';
  return `<span style="display:inline-block;padding:2px 8px;background:${c}22;color:${c};border:1px solid ${c}88;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;">${sev}</span>`;
}

function riskBarHtml(score) {
  const color = score >= 80 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 25 ? '#eab308' : '#22c55e';
  const label = score >= 80 ? 'CRITICAL RISK' : score >= 50 ? 'HIGH RISK' : score >= 25 ? 'MEDIUM RISK' : 'LOW RISK';
  return `
    <div style="margin:16px 0;">
      <div style="font-size:11px;opacity:.7;margin-bottom:4px;">OVERALL RISK SCORE</div>
      <div style="display:flex;align-items:center;gap:12px;">
        <div style="flex:1;height:10px;background:#0f172a;border-radius:5px;overflow:hidden;">
          <div style="height:100%;width:${score}%;background:${color};border-radius:5px;transition:width .6s ease;"></div>
        </div>
        <span style="font-size:20px;font-weight:700;color:${color};">${score}/100</span>
        <span style="font-size:12px;color:${color};font-weight:600;">${label}</span>
      </div>
    </div>
  `;
}

function generateHTMLReport(jobId) {
  const job = getJob(jobId);
  if (!job) return '<p>Job not found.</p>';
  const raw = getJobResult(jobId);
  const findings = raw.findings || [];
  const logs     = raw.logs     || [];
  const sorted   = sortFindingsBySeverity(findings);
  const score    = computeRiskScore(sorted);

  const targets = Array.isArray(job.targets)
    ? job.targets.map((t) => (typeof t === 'string' ? t : t.host || t.url || '')).join(', ')
    : '-';

  const counts = ['critical','high','medium','low','info'].map((sev) => ({
    sev,
    n: sorted.filter((f) => f.severity === sev).length,
    color: SEV_COLORS[sev],
  }));

  const statsHtml = counts
    .map((c) => `
      <div style="background:#0f172a;border:1px solid #1f2937;border-radius:8px;padding:12px 20px;">
        <div style="font-size:26px;font-weight:700;color:${c.color};">${c.n}</div>
        <div style="font-size:11px;opacity:.6;margin-top:2px;text-transform:uppercase;">${c.sev}</div>
      </div>`)
    .join('');

  const findingRows = sorted.map((f, idx) => `
    <tr id="finding-${idx+1}">
      <td style="padding:10px;border-bottom:1px solid #1f2937;opacity:.6;">${idx + 1}</td>
      <td style="padding:10px;border-bottom:1px solid #1f2937;">${sevBadgeHtml(f.severity)}</td>
      <td style="padding:10px;border-bottom:1px solid #1f2937;font-size:11px;opacity:.7;">${escHtml(f.category || '')}</td>
      <td style="padding:10px;border-bottom:1px solid #1f2937;">${escHtml(f.title || '')}</td>
      <td style="padding:10px;border-bottom:1px solid #1f2937;font-size:11px;"><a href="${escHtml(f.url || '')}" style="color:#60a5fa;word-break:break-all;">${escHtml(f.url || '')}</a></td>
      <td style="padding:10px;border-bottom:1px solid #1f2937;font-size:11px;">${f.statusCode || '-'}</td>
    </tr>
    ${f.bodySnippet || f.payload ? `
    <tr>
      <td colspan="6" style="padding:0 10px 10px;border-bottom:1px solid #1f2937;">
        ${f.payload ? `<div style="margin-bottom:4px;font-size:10px;color:#f97316;">Payload: <code>${escHtml(f.payload)}</code></div>` : ''}
        ${f.bodySnippet ? `<pre style="background:#020617;border:1px solid #111827;padding:8px;border-radius:4px;font-size:10px;overflow:auto;max-height:120px;margin:0;">${escHtml(f.bodySnippet.slice(0, 400))}</pre>` : ''}
        <div style="margin-top:6px;padding:6px 8px;background:#0f172a;border-left:3px solid #3b82f6;font-size:11px;"><strong style="color:#3b82f6;">Remediation:</strong> ${escHtml(getRemediation(f.category))}</div>
      </td>
    </tr>` : ''}
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Pentest Report – ${escHtml(job.projectId)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body  { background:#030712; color:#e5e7eb; font-family:'JetBrains Mono',monospace; margin:0; padding:30px 40px; font-size:13px; }
    h1    { font-size:22px; margin:0 0 4px; }
    h2    { font-size:14px; border-bottom:1px solid #1f2937; padding-bottom:6px; margin:28px 0 12px; color:#94a3b8; text-transform:uppercase; letter-spacing:.08em; }
    table { width:100%; border-collapse:collapse; }
    th    { text-align:left; padding:8px 10px; border-bottom:2px solid #1f2937; font-size:11px; opacity:.5; text-transform:uppercase; }
    a     { color:#60a5fa; }
    .meta { font-size:12px; opacity:.5; margin:4px 0; }
    .stats { display:flex; flex-wrap:wrap; gap:12px; margin:12px 0 20px; }
    @media print { body { background:#fff; color:#000; } h2 { color:#333; } .meta { color:#666; } }
  </style>
</head>
<body>
  <h1>⚡ Pentest Report</h1>
  <div class="meta">Project: <strong>${escHtml(job.projectId)}</strong></div>
  <div class="meta">Job ID: ${escHtml(job.id)}</div>
  <div class="meta">Generated: ${new Date().toISOString()}</div>
  <div class="meta">Targets: ${escHtml(targets)}</div>

  ${riskBarHtml(score)}

  <h2>Severity Summary</h2>
  <div class="stats">${statsHtml}</div>

  <h2>Findings (${sorted.length})</h2>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Category</th><th>Title</th><th>URL</th><th>HTTP</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>

  <h2>Scan Logs</h2>
  <pre style="background:#020617;border:1px solid #111827;padding:12px;border-radius:4px;font-size:11px;overflow:auto;max-height:400px;">${escHtml(logs.slice(0, 400).join('\n'))}</pre>

  <p style="font-size:10px;opacity:.3;margin-top:40px;border-top:1px solid #1f2937;padding-top:12px;">AUTHORIZED SECURITY TESTING ONLY. All targets were tested with explicit written permission from the asset owner.</p>
</body>
</html>`;
}

function generateMarkdownReport(jobId) {
  const job = getJob(jobId);
  if (!job) return '# Job not found';
  const raw    = getJobResult(jobId);
  const sorted = sortFindingsBySeverity(raw.findings || []);
  const logs   = raw.logs || [];
  const score  = computeRiskScore(sorted);
  const scoreLabel = score >= 80 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW';

  const lines = [
    `# ⚡ Pentest Report`,
    ``,
    `| Field | Value |`,
    `|---|---|`,
    `| **Project** | ${job.projectId} |`,
    `| **Job ID** | ${job.id} |`,
    `| **Status** | ${job.status} |`,
    `| **Generated** | ${new Date().toISOString()} |`,
    `| **Risk Score** | ${score}/100 – ${scoreLabel} RISK |`,
    ``,
    `## Executive Summary`,
    ``,
    `| Severity | Count |`,
    `|---|---|`,
    ...['critical','high','medium','low','info'].map((sev) =>
      `| ${sev.toUpperCase()} | ${sorted.filter((f) => f.severity === sev).length} |`
    ),
    `| **Total** | **${sorted.length}** |`,
    ``,
    `## Findings`,
    ``,
  ];

  for (const [idx, f] of sorted.entries()) {
    lines.push(`### ${idx + 1}. [${(f.severity || '').toUpperCase()}] ${f.title || ''}`);
    lines.push(``);
    lines.push(`- **Category:** ${f.category || ''}`);
    lines.push(`- **URL:** ${f.url || ''}`);
    lines.push(`- **HTTP Status:** ${f.statusCode || ''}`);
    if (f.payload)     lines.push(`- **Payload:** \`${f.payload}\``);
    if (f.bodySnippet) {
      lines.push(``);
      lines.push('**Evidence:**');
      lines.push('```');
      lines.push(f.bodySnippet.slice(0, 300));
      lines.push('```');
    }
    lines.push(``);
    lines.push(`> **Remediation:** ${getRemediation(f.category)}`);
    lines.push(``);
  }

  lines.push(`## Scan Logs`);
  lines.push(``);
  lines.push('```');
  lines.push(...logs.slice(0, 250));
  lines.push('```');
  lines.push(``);
  lines.push(`---`);
  lines.push(`*Authorized security testing only. All targets were scanned with explicit written permission.*`);

  return lines.join('\n');
}

module.exports = { generateHTMLReport, generateMarkdownReport };
