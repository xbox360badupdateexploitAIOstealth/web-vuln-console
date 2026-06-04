// src/ui/app.js
import { moduleDefs } from '../core/moduleRegistry.js';
import { scanPolicies } from '../core/policyRegistry.js';

const viewContainer = document.getElementById('view-container');
const sidebar = document.querySelector('.sidebar');

function renderDashboard() {
  viewContainer.innerHTML = `
    <h1>Dashboard</h1>
    <p>Modules loaded: ${moduleDefs.length}</p>
    <p>Scan policies: ${scanPolicies.length}</p>
    <pre style="margin-top: 12px; font-size: 11px; opacity: 0.8;">
Loaded module IDs:
${moduleDefs.map((m) => ` - ${m.id}`).join('\n')}
    </pre>
  `;
}

function renderSimpleView(title) {
  viewContainer.innerHTML = `<h1>${title}</h1><p>View not implemented yet.</p>`;
}

function handleNavClick(e) {
  if (!(e.target instanceof HTMLButtonElement)) return;
  const view = e.target.dataset.view;
  switch (view) {
    case 'dashboard':
      renderDashboard();
      break;
    case 'projects':
      renderSimpleView('Projects');
      break;
    case 'jobs':
      renderSimpleView('Scan Jobs');
      break;
    case 'findings':
      renderSimpleView('Findings');
      break;
    case 'modules':
      renderSimpleView('Modules');
      break;
    case 'policies':
      renderSimpleView('Policies');
      break;
    case 'settings':
      renderSimpleView('Settings');
      break;
    default:
      renderDashboard();
      break;
  }
}

sidebar.addEventListener('click', handleNavClick);

renderDashboard();
