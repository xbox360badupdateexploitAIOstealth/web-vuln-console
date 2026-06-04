// src/ui/app.js
import { renderDashboard } from './views/dashboardView.js';
import { renderProjectList } from './views/projectListView.js';
import { renderJobConsole } from './views/jobConsoleView.js';

const viewContainer = document.getElementById('view-container');
const sidebar = document.querySelector('.sidebar');

function showView(view) {
  switch (view) {
    case 'dashboard':
      renderDashboard(viewContainer);
      break;
    case 'projects':
      renderProjectList(viewContainer);
      break;
    case 'jobs':
      renderJobConsole(viewContainer);
      break;
    case 'findings':
      viewContainer.innerHTML = '<h1>Findings</h1><p>View not implemented yet.</p>';
      break;
    case 'modules':
      viewContainer.innerHTML = '<h1>Modules</h1><p>View not implemented yet.</p>';
      break;
    case 'policies':
      viewContainer.innerHTML = '<h1>Policies</h1><p>View not implemented yet.</p>';
      break;
    case 'settings':
      viewContainer.innerHTML = '<h1>Settings</h1><p>View not implemented yet.</p>';
      break;
    default:
      renderDashboard(viewContainer);
      break;
  }
}

function handleNavClick(e) {
  if (!(e.target instanceof HTMLButtonElement)) return;
  const view = e.target.dataset.view;
  showView(view);
}

sidebar.addEventListener('click', handleNavClick);

// initial render
showView('dashboard');
