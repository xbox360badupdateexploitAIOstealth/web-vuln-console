/* =================================================================
   WebVulnConsole ⚡ — Projects Page HTML Injector  (Task 4)
   Builds the full Projects page DOM structure:
   - Top action bar: New Project + sort/filter controls
   - Search box (client-side filter)
   - Project list container (filled by projects.js renderProjectCards)
   - Empty state handled by renderProjectCards
   =================================================================
   USAGE: call buildProjectsPage() once after DOM ready,
   before initProjectsUI() from projects.js.
   ================================================================= */
'use strict';

export function buildProjectsPage() {
  const page = document.getElementById('page-projects');
  if (!page || page.dataset.built) return;
  page.dataset.built = '1';

  page.innerHTML = `
    <!-- Action bar -->
    <div style="display:flex;align-items:center;justify-content:space-between;
      gap:10px;flex-wrap:wrap;margin-bottom:14px;">

      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        <button id="btn-new-project"
          style="background:#38bdf8;color:#020617;border:none;font-family:monospace;
            font-size:12px;font-weight:700;padding:7px 15px;border-radius:5px;
            cursor:pointer;transition:opacity .15s;">
          + New Project
        </button>

        <input id="proj-search-box"
          type="text" placeholder="🔍  Filter projects..."
          style="background:#0f172a;border:1px solid #1e293b;border-radius:5px;
            color:#e2e8f0;font-family:monospace;font-size:12px;
            padding:6px 10px;outline:none;min-width:160px;"
          oninput="window._projFilterCards(this.value)" />
      </div>

      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.06em;">Sort</span>
        <select id="proj-sort-select"
          style="background:#0f172a;border:1px solid #1e293b;color:#e2e8f0;
            font-family:monospace;font-size:11px;padding:5px 7px;
            border-radius:5px;outline:none;"
          onchange="window._projSortCards(this.value)">
          <option value="created_desc">Newest first</option>
          <option value="created_asc">Oldest first</option>
          <option value="name_asc">Name A→Z</option>
          <option value="name_desc">Name Z→A</option>
          <option value="risk_desc">Risk (high first)</option>
        </select>
      </div>
    </div>

    <!-- Stats bar -->
    <div id="proj-stats-bar"
      style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
    </div>

    <!-- Project cards list -->
    <div id="project-list"></div>
  `;

  // Focus style for search
  const searchBox = document.getElementById('proj-search-box');
  if (searchBox) {
    searchBox.addEventListener('focus', () => searchBox.style.borderColor = '#38bdf8');
    searchBox.addEventListener('blur',  () => searchBox.style.borderColor = '#1e293b');
  }
}

// ─── Filter + Sort handlers ────────────────────────────────────────────────
let _filterStr  = '';
let _sortMode   = 'created_desc';

window._projFilterCards = function(val) {
  _filterStr = (val || '').toLowerCase();
  _applyProjectFilter();
};

window._projSortCards = function(val) {
  _sortMode = val;
  _applyProjectFilter();
};

function _applyProjectFilter() {
  const projects = (window._wvcState?.projects || []);
  const cur      = window._wvcState?.currentProject;

  // Filter
  let filtered = _filterStr
    ? projects.filter(p =>
        p.name.toLowerCase().includes(_filterStr) ||
        (p.client || '').toLowerCase().includes(_filterStr) ||
        p.id.toLowerCase().includes(_filterStr))
    : [...projects];

  // Sort
  const riskScoreFn = id => {
    const stats = window._projStatsCache?.[id];
    if (!stats) return 0;
    return Math.min(stats.crit*30 + stats.high*15 + stats.medium*6 + stats.low*2 + stats.info*0.5, 100);
  };
  filtered.sort((a, b) => {
    switch (_sortMode) {
      case 'created_asc':  return new Date(a.createdAt||0) - new Date(b.createdAt||0);
      case 'name_asc':     return a.name.localeCompare(b.name);
      case 'name_desc':    return b.name.localeCompare(a.name);
      case 'risk_desc':    return riskScoreFn(b.id) - riskScoreFn(a.id);
      default:             return new Date(b.createdAt||0) - new Date(a.createdAt||0);
    }
  });

  // Re-render into list
  const el = document.getElementById('project-list');
  if (!el) return;

  if (!filtered.length) {
    el.innerHTML = `<div style="padding:32px;text-align:center;color:#475569;font-size:12px;">
      No projects match <strong style="color:#64748b;">${_filterStr}</strong>.
    </div>`;
    return;
  }

  // Import renderProjectCards lazily so this file stays standalone
  import('./projects.js').then(({ renderProjectCards }) => {
    // Temporarily swap state to filtered list, render, then restore order
    const orig = window._wvcState.projects;
    window._wvcState.projects = filtered;
    renderProjectCards();
    window._wvcState.projects = orig;
  });
}

// ─── Stats bar (project count + risk summary) ───────────────────────────────
export function updateProjectStatsBar() {
  const bar      = document.getElementById('proj-stats-bar');
  if (!bar) return;
  const projects = window._wvcState?.projects || [];
  const total    = projects.length;
  const active   = window._wvcState?.currentProject ? 1 : 0;
  const allStats = Object.values(window._projStatsCache || {});
  const totalFindings = allStats.reduce((s, st) => s + (st?.total || 0), 0);
  const critProjects  = projects.filter(p => {
    const st = window._projStatsCache?.[p.id];
    if (!st) return false;
    const score = Math.min(st.crit*30 + st.high*15 + st.medium*6, 100);
    return score >= 70;
  }).length;

  const tiles = [
    { num: total,        lbl: 'Projects',     col: '#38bdf8' },
    { num: active,       lbl: 'Active',        col: '#22c55e' },
    { num: totalFindings,lbl: 'Total Findings',col: '#94a3b8' },
    { num: critProjects, lbl: 'Critical Risk', col: '#ef4444' },
  ];

  bar.innerHTML = tiles.map(t => `
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;
      padding:10px 16px;min-width:80px;flex:1;">
      <div style="font-size:20px;font-weight:800;color:${t.col};font-family:monospace;">${t.num}</div>
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;
        letter-spacing:.07em;margin-top:2px;">${t.lbl}</div>
    </div>`).join('');
}
