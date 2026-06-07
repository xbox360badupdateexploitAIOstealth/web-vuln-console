// src/ui/state.js
// Central UI state store.
//
// Holds:
//   lastScanContext    — most-recent EngineContext returned by a scan
//   currentProjectId  — which project is "active" (used by targets, job console, etc.)
//   currentProject    — the full Project object for the active project
//
// Change bus:
//   state.on(key, fn)   — subscribe to changes on a specific key
//   state.off(key, fn)  — unsubscribe
//   state.emit(key)     — internal; fires all listeners for that key
//
// Project helpers (db-backed):
//   state.loadProjects()        — load all projects from db → state._projects[]
//   state.saveProject(project)  — upsert project in db + refresh state._projects[]
//   state.deleteProject(id)     — remove project from db + refresh state._projects[]
//   state.selectProject(id)     — set currentProjectId + currentProject, emit 'project'
//
// All methods are on the singleton `state` export.

import { db, S } from '../core/db.js';
import { Project } from '../core/models.js';

class AppState {
  constructor() {
    // ── Raw values ────────────────────────────────────────────────────────
    this.lastScanContext   = null;
    this.currentProjectId  = null;
    this.currentProject    = null;
    this._projects         = [];   // Project[]

    // ── Listener map: key → Set<fn> ───────────────────────────────────────
    this._listeners = {};
  }

  // ─── Change bus ──────────────────────────────────────────────────────────────
  on(key, fn) {
    if (!this._listeners[key]) this._listeners[key] = new Set();
    this._listeners[key].add(fn);
  }

  off(key, fn) {
    this._listeners[key]?.delete(fn);
  }

  emit(key, payload) {
    this._listeners[key]?.forEach(fn => fn(payload));
  }

  // ─── lastScanContext ──────────────────────────────────────────────────────────
  setLastScanContext(ctx) {
    this.lastScanContext = ctx || null;
    this.emit('scanContext', this.lastScanContext);
  }

  getLastScanContext() {
    return this.lastScanContext;
  }

  // ─── currentProject ───────────────────────────────────────────────────────────
  selectProject(id) {
    this.currentProjectId = id || null;
    this.currentProject   = id
      ? (this._projects.find(p => p.id === id) || null)
      : null;
    // Persist selection across page reloads
    try {
      if (id) localStorage.setItem('wvc_current_project', id);
      else    localStorage.removeItem('wvc_current_project');
    } catch (_) {}
    this.emit('project', this.currentProject);
  }

  // ─── Projects (db-backed) ─────────────────────────────────────────────────────
  async loadProjects() {
    try {
      const rows = await db.getAll(S.PROJECTS);
      this._projects = rows.map(r => new Project(r));
    } catch (_) {
      this._projects = [];
    }

    // Re-hydrate current project if one was saved
    if (!this.currentProjectId) {
      try {
        const saved = localStorage.getItem('wvc_current_project');
        if (saved) this.currentProjectId = saved;
      } catch (_) {}
    }
    if (this.currentProjectId) {
      this.currentProject = this._projects.find(p => p.id === this.currentProjectId) || null;
    }

    this.emit('projects', this._projects);
    return this._projects;
  }

  async saveProject(projectOrPlain) {
    const project = projectOrPlain instanceof Project
      ? projectOrPlain
      : new Project(projectOrPlain);
    await db.put(S.PROJECTS, _plain(project));
    await this.loadProjects();
    return project;
  }

  async deleteProject(id) {
    await db.delete(S.PROJECTS, id);
    if (this.currentProjectId === id) this.selectProject(null);
    await this.loadProjects();
  }

  getProjects() {
    return this._projects;
  }
}

// ── Singleton ──────────────────────────────────────────────────────────────────
export const state = new AppState();

// ── Legacy named exports (keep old jobConsoleView / findingsListView working) ──
export function setLastScanContext(ctx) { state.setLastScanContext(ctx); }
export function getLastScanContext()    { return state.getLastScanContext(); }

// ── Internal ───────────────────────────────────────────────────────────────────
function _plain(obj) {
  return JSON.parse(JSON.stringify(obj));
}
