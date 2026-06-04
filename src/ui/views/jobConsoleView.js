// src/ui/views/jobConsoleView.js
import { runScanJob, EngineConfig } from '../../core/engine.js';
import { Project, Target, ScanJob } from '../../core/models.js';

// Demo project/target for console scans.
const demoProject = new Project({
  workspaceId: 'ws_demo',
  name: 'Console Demo Project',
  clientName: 'Demo',
  authNotes: 'Demo-only scan from frontend.',
});

const demoTargets = [
  new Target({
    projectId: demoProject.id,
    host: 'https://example.com',
    type: 'web_site',
    env: 'lab',
  }),
];

function makeBrowserFetchAdapter() {
  return async ({ method, url, headers, body }) => {
    const res = await fetch(url, {
      method,
      headers,
      body,
      mode: 'cors',
    });
    const text = await res.text();
    const hdrs = {};
    res.headers.forEach((v, k) => {
      hdrs[k] = v;
    });
    return {
      status: res.status,
      headers: hdrs,
      body: text,
    };
  };
}

export async function renderJobConsole(container) {
  container.innerHTML = `
    <h1>Scan Console</h1>
    <p style="margin-top: 4px; font-size: 12px; opacity: 0.75;">
      This view runs a real passive exposure scan against a demo target using the current policy.
    </p>
    <div style="margin-top: 8px;">
      <label style="font-size: 12px;">Policy:
        <select id="policy-select" style="font-size: 12px; margin-left: 4px;">
          <option value="policy_normal">Normal</option>
          <option value="policy_aggressive">Aggressive</option>
          <option value="policy_extreme">Extreme</option>
        </select>
      </label>
    </div>
    <button id="run-scan-btn" style="margin-top: 10px; padding: 6px 10px; font-size: 12px;">Run Scan</button>
    <pre id="console-log" style="margin-top: 12px; font-size: 11px; background: #020617; border: 1px solid #111827; padding: 8px; border-radius: 4px; max-height: 320px; overflow: auto;"></pre>
  `;

  const btn = document.getElementById('run-scan-btn');
  const logEl = document.getElementById('console-log');
  const policySel = document.getElementById('policy-select');

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    logEl.textContent = '';

    const policyId = policySel.value;
    const job = new ScanJob({
      projectId: demoProject.id,
      policyId,
      targetIds: demoTargets.map((t) => t.id),
      initiatedBy: 'demo',
      initSource: 'ui',
    });

    const engineConfig = new EngineConfig({
      fetchAdapter: makeBrowserFetchAdapter(),
      baseUrlResolver: (target) => target.host,
    });

    try {
      const ctx = await runScanJob({
        jobInput: job,
        project: demoProject,
        targets: demoTargets,
        engineConfig,
      });
      logEl.textContent = ctx.logs.join('\n');
      if (ctx.findings.length) {
        logEl.textContent += `\n\nFindings (IDs/Titles):\n`;
        for (const f of ctx.findings) {
          logEl.textContent += ` - ${f.id}: ${f.title}\n`;
        }
      }
    } catch (err) {
      logEl.textContent = `Error: ${err.message || err}`;
    } finally {
      btn.disabled = false;
    }
  });
}
