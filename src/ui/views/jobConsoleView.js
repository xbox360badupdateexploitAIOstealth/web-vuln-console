// src/ui/views/jobConsoleView.js
import { runScanJobFake } from '../../core/engine.js';
import { Project, Target, ScanJob } from '../../core/models.js';

// Temporary in-memory demo project/target for the console.
const demoProject = new Project({
  workspaceId: 'ws_demo',
  name: 'Console Demo Project',
  clientName: 'Demo',
  authNotes: 'Demo-only fake scan.',
});

const demoTargets = [
  new Target({
    projectId: demoProject.id,
    host: 'https://example.com',
    type: 'web_site',
    env: 'lab',
  }),
];

export async function renderJobConsole(container) {
  container.innerHTML = `
    <h1>Scan Console (Fake Engine)</h1>
    <p style="margin-top: 4px; font-size: 12px; opacity: 0.75;">
      This view uses the fake scan runner to demonstrate job wiring and logging.
    </p>
    <button id="run-fake-scan-btn" style="margin-top: 10px; padding: 6px 10px; font-size: 12px;">Run Fake Scan</button>
    <pre id="console-log" style="margin-top: 12px; font-size: 11px; background: #020617; border: 1px solid #111827; padding: 8px; border-radius: 4px; max-height: 320px; overflow: auto;"></pre>
  `;

  const btn = document.getElementById('run-fake-scan-btn');
  const logEl = document.getElementById('console-log');

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    logEl.textContent = '';

    const job = new ScanJob({
      projectId: demoProject.id,
      policyId: 'policy_normal',
      targetIds: demoTargets.map((t) => t.id),
      initiatedBy: 'demo',
      initSource: 'ui',
    });

    const engineConfig = {
      fetchAdapter: async () => ({ status: 501, headers: {}, body: '' }),
      baseUrlResolver: (target) => target.host,
    };

    const ctx = await runScanJobFake({
      jobInput: job,
      project: demoProject,
      targets: demoTargets,
      engineConfig,
    });

    logEl.textContent = ctx.logs.join('\n');
    btn.disabled = false;
  });
}
