// src/ui/views/projectListView.js
import { Project } from '../../core/models.js';

// For now we keep an in-memory list of projects.
// Later this will be backed by Firestore/API.
const demoProjects = [
  new Project({
    workspaceId: 'ws_demo',
    name: 'Demo Client A',
    clientName: 'Client A',
    authNotes: 'Authorized for full testing in lab.',
    tags: ['demo', 'lab'],
  }),
  new Project({
    workspaceId: 'ws_demo',
    name: 'Demo Client B',
    clientName: 'Client B',
    authNotes: 'External perimeter only.',
    tags: ['demo', 'external'],
  }),
];

export function renderProjectList(container) {
  if (!demoProjects.length) {
    container.innerHTML = '<h1>Projects</h1><p>No projects yet.</p>';
    return;
  }

  const rows = demoProjects
    .map(
      (p) => `
      <tr>
        <td>${p.name}</td>
        <td>${p.clientName || '-'}</td>
        <td>${p.tags.join(', ') || '-'}</td>
        <td>${p.createdAt.toISOString().slice(0, 10)}</td>
      </tr>`
    )
    .join('');

  container.innerHTML = `
    <h1>Projects</h1>
    <table class="basic-table" style="margin-top: 12px; width: 100%; font-size: 12px; border-collapse: collapse;">
      <thead>
        <tr>
          <th style="text-align: left; padding: 4px 6px; border-bottom: 1px solid #1f2933;">Name</th>
          <th style="text-align: left; padding: 4px 6px; border-bottom: 1px solid #1f2933;">Client</th>
          <th style="text-align: left; padding: 4px 6px; border-bottom: 1px solid #1f2933;">Tags</th>
          <th style="text-align: left; padding: 4px 6px; border-bottom: 1px solid #1f2933;">Created</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;
}
