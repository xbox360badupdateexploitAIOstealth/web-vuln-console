// src/core/db.js
// Persistence layer for WVC.
//
// Uses IndexedDB (via the 'idb' helper) in browser environments.
// Falls back to an in-memory Map store (with optional JSON-file export hook)
// in Node / test environments where IndexedDB is not available.
//
// Object stores
// ─────────────
//   workspaces   — Workspace records
//   projects     — Project records
//   targets      — Target records
//   scanJobs     — ScanJob records (status, stats, timestamps)
//   findings     — Finding records  (indexed by scanJobId, projectId, severity)
//   evidences    — Evidence records  (indexed by findingId)
//   auditEvents  — AuditEvent records (indexed by scopeId)
//
// Public API
// ───────────
//   await db.put(store, record)         — upsert by record.id
//   await db.get(store, id)             — get by id
//   await db.getAll(store)              — get all records
//   await db.getAllByIndex(store, index, value)  — get records where index === value
//   await db.delete(store, id)          — delete by id
//   await db.clear(store)               — wipe a store
//   await db.bulkPut(store, records[])  — upsert many records in one transaction

const DB_NAME    = 'wvc-db';
const DB_VERSION = 1;

// Stores and their indexes
const SCHEMA = [
  { name: 'workspaces',  indexes: [] },
  { name: 'projects',    indexes: ['workspaceId'] },
  { name: 'targets',     indexes: ['projectId'] },
  {
    name: 'scanJobs',
    indexes: ['projectId', 'status'],
  },
  {
    name: 'findings',
    indexes: ['scanJobId', 'projectId', 'targetId', 'severity', 'status'],
  },
  {
    name: 'evidences',
    indexes: ['findingId'],
  },
  {
    name: 'auditEvents',
    indexes: ['scopeId', 'actor'],
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// IndexedDB backend (browser)
// ─────────────────────────────────────────────────────────────────────────────

function openIdb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (event) => {
      const idb = event.target.result;
      for (const store of SCHEMA) {
        let os;
        if (!idb.objectStoreNames.contains(store.name)) {
          os = idb.createObjectStore(store.name, { keyPath: 'id' });
        } else {
          os = event.target.transaction.objectStore(store.name);
        }
        for (const idx of store.indexes) {
          if (!os.indexNames.contains(idx)) {
            os.createIndex(idx, idx, { unique: false });
          }
        }
      }
    };

    req.onsuccess  = (e) => resolve(e.target.result);
    req.onerror    = (e) => reject(e.target.error);
    req.onblocked  = ()  => reject(new Error('IDB open blocked'));
  });
}

class IdbBackend {
  constructor() {
    this._db = null;
  }

  async _conn() {
    if (!this._db) this._db = await openIdb();
    return this._db;
  }

  async put(store, record) {
    const db = await this._conn();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(store, 'readwrite');
      const req = tx.objectStore(store).put(record);
      req.onsuccess = () => resolve(record);
      req.onerror   = (e) => reject(e.target.error);
    });
  }

  async get(store, id) {
    const db = await this._conn();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(store, 'readonly');
      const req = tx.objectStore(store).get(id);
      req.onsuccess = (e) => resolve(e.target.result ?? null);
      req.onerror   = (e) => reject(e.target.error);
    });
  }

  async getAll(store) {
    const db = await this._conn();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(store, 'readonly');
      const req = tx.objectStore(store).getAll();
      req.onsuccess = (e) => resolve(e.target.result);
      req.onerror   = (e) => reject(e.target.error);
    });
  }

  async getAllByIndex(store, index, value) {
    const db = await this._conn();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(store, 'readonly');
      const req = tx.objectStore(store).index(index).getAll(value);
      req.onsuccess = (e) => resolve(e.target.result);
      req.onerror   = (e) => reject(e.target.error);
    });
  }

  async delete(store, id) {
    const db = await this._conn();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(store, 'readwrite');
      const req = tx.objectStore(store).delete(id);
      req.onsuccess = () => resolve();
      req.onerror   = (e) => reject(e.target.error);
    });
  }

  async clear(store) {
    const db = await this._conn();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(store, 'readwrite');
      const req = tx.objectStore(store).clear();
      req.onsuccess = () => resolve();
      req.onerror   = (e) => reject(e.target.error);
    });
  }

  async bulkPut(store, records) {
    const db = await this._conn();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, 'readwrite');
      const os = tx.objectStore(store);
      for (const r of records) os.put(r);
      tx.oncomplete = () => resolve(records);
      tx.onerror    = (e) => reject(e.target.error);
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory fallback (Node / test / SSR)
// ─────────────────────────────────────────────────────────────────────────────

class MemoryBackend {
  constructor() {
    this._stores = {};
    for (const s of SCHEMA) this._stores[s.name] = new Map();
  }

  _store(name) {
    if (!this._stores[name]) this._stores[name] = new Map();
    return this._stores[name];
  }

  async put(store, record) {
    this._store(store).set(record.id, record);
    return record;
  }

  async get(store, id) {
    return this._store(store).get(id) ?? null;
  }

  async getAll(store) {
    return Array.from(this._store(store).values());
  }

  async getAllByIndex(store, index, value) {
    return Array.from(this._store(store).values()).filter(
      (r) => r[index] === value,
    );
  }

  async delete(store, id) {
    this._store(store).delete(id);
  }

  async clear(store) {
    this._store(store).clear();
  }

  async bulkPut(store, records) {
    for (const r of records) this._store(store).set(r.id, r);
    return records;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Export the right backend
// ─────────────────────────────────────────────────────────────────────────────

const hasIndexedDB = typeof indexedDB !== 'undefined';
export const db = hasIndexedDB ? new IdbBackend() : new MemoryBackend();

export const STORES = Object.freeze(
  Object.fromEntries(SCHEMA.map((s) => [s.name.toUpperCase().replace(/-/g, '_'), s.name]))
);
// STORES.SCAN_JOBS, STORES.FINDINGS, etc. → store name strings
// Also available as plain strings for convenience:
export const S = {
  WORKSPACES:  'workspaces',
  PROJECTS:    'projects',
  TARGETS:     'targets',
  SCAN_JOBS:   'scanJobs',
  FINDINGS:    'findings',
  EVIDENCES:   'evidences',
  AUDIT_EVENTS: 'auditEvents',
};
