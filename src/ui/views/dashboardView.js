// src/ui/views/dashboardView.js
import { moduleDefs } from '../../core/moduleRegistry.js';
import { scanPolicies } from '../../core/policyRegistry.js';

/**
 * Simple dashboard renderer.
 * Later we can expand with stats from real projects / jobs.
 */
export function renderDashboard(container) {
  container.innerHTML = `
    <h1>Dashboard</h1>
    <p>Modules loaded: ${moduleDefs.length}</p>
    <p>Scan policies: ${scanPolicies.length}</p>
    <pre style="margin-top: 12px; font-size: 11px; opacity: 0.8; max-height: 280px; overflow: auto;">
Loaded module IDs:
${moduleDefs.map((m) => ` - ${m.id}`).join('\n')}
    </pre>
  `;
}
