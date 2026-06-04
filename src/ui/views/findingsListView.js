// src/ui/views/findingsListView.js
import { getLastScanContext } from '../state.js';

const severityOrder = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  info: 5,
};

function severityClass(sev) {
  switch (sev) {
    case 'critical':
      return 'sev sev-critical';
    case 'high':
      return 'sev sev-high';
    case 'medium':
      return 'sev sev-medium';
    case 'low':
      return 'sev sev-low';
    default:
      return 'sev sev-info';
  }
}

export function renderFindingsList(container) {
  const ctx = getLastScanContext();

  if (!ctx || !ctx.findings || !ctx.findings.length) {
    container.innerHTML = `
      <h1>Findings</h1>
      <p style="margin-top: 6px; font-size: 12px; opacity: 0.75;">
        No findings loaded. Run a scan from the Scan Jobs view first.
      </p>
    `;
    return;
  }

  const findings = [...ctx.findings].sort((a, b) => {
    const sa = severityOrder[a.severity] || 99;
    const sb = severityOrder[b.severity] || 99;
    if (sa !== sb) return sa - sb;
    return (a.title || '').localeCompare(b.title || '');
  });

  const rows = findings
    .map((f, idx) => {
      const sevCls = severityClass(f.severity);
      const targetHost = (ctx.targets || []).find((t) => t.id === f.targetId)?.host || '-';

      return `
        <tr data-row-index="${idx}">
          <td style="padding: 4px 6px; border-bottom: 1px solid #111827;">
            <span class="${sevCls}">${f.severity || 'info'}</span>
          </td>
          <td style="padding: 4px 6px; border-bottom: 1px solid #111827;">${escapeHtml(
            f.title || ''
          )}</td>
          <td style="padding: 4px 6px; border-bottom: 1px solid #111827; font-size: 11px; opacity: 0.85;">${escapeHtml(
            f.moduleId || ''
          )}</td>
          <td style="padding: 4px 6px; border-bottom: 1px solid #111827; font-size: 11px; opacity: 0.85;">${escapeHtml(
            targetHost
          )}</td>
        </tr>`;
    })
    .join('');

  container.innerHTML = `
    <h1>Findings</h1>
    <p style="margin-top: 4px; font-size: 12px; opacity: 0.75;">
      Showing findings from the most recent scan in this browser session.
    </p>
    <div style="margin-top: 10px; display: grid; grid-template-columns: minmax(0, 2.1fr) minmax(0, 1.3fr); gap: 10px;">
      <div>
        <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
          <thead>
            <tr>
              <th style="text-align: left; padding: 4px 6px; border-bottom: 1px solid #1f2933; width: 90px;">Severity</th>
              <th style="text-align: left; padding: 4px 6px; border-bottom: 1px solid #1f2933;">Title</th>
              <th style="text-align: left; padding: 4px 6px; border-bottom: 1px solid #1f2933; width: 140px;">Module</th>
              <th style="text-align: left; padding: 4px 6px; border-bottom: 1px solid #1f2933; width: 180px;">Target</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
      <div id="finding-detail" style="font-size: 12px; border: 1px solid #111827; border-radius: 4px; padding: 8px; background: #020617; white-space: pre-wrap; overflow: auto; max-height: 320px;">
        <div style="opacity: 0.7;">Select a finding to see details.</div>
      </div>
    </div>
  `;

  const tbody = container.querySelector('tbody');
  const detailEl = container.querySelector('#finding-detail');

  tbody.addEventListener('click', (e) => {
    const tr = e.target.closest('tr');
    if (!tr) return;
    const idx = parseInt(tr.dataset.rowIndex, 10);
    if (Number.isNaN(idx)) return;

    const finding = findings[idx];
    const evidence = (ctx.evidences || []).find((ev) => ev.findingId === finding.id) || null;

    const lines = [];
    lines.push(`ID: ${finding.id}`);
    lines.push(`Severity: ${finding.severity}`);
    lines.push(`Module: ${finding.moduleId}`);
    lines.push(`Target ID: ${finding.targetId}`);
    lines.push('');
    lines.push(`Title: ${finding.title || ''}`);
    lines.push('');
    if (finding.shortDescription) {
      lines.push(`Short: ${finding.shortDescription}`);
      lines.push('');
    }
    if (finding.detailedDescription) {
      lines.push('Details:');
      lines.push(finding.detailedDescription);
      lines.push('');
    }
    if (evidence) {
      lines.push('Evidence URL: ' + (evidence.url || ''));
      lines.push('HTTP status: ' + (evidence.responseStatus || ''));
      lines.push('Matched: ' + (evidence.matchedPattern || ''));
      lines.push('');
      if (evidence.responseHeadersSnippet) {
        lines.push('Headers snippet:');
        lines.push(evidence.responseHeadersSnippet);
        lines.push('');
      }
      if (evidence.responseBodySnippet) {
        lines.push('Body snippet:');
        lines.push(evidence.responseBodySnippet);
        lines.push('');
      }
    }

    detailEl.textContent = lines.join('\n');
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
