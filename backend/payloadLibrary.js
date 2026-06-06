// backend/payloadLibrary.js
// Payload Library — SQLite-backed store for custom payload lists.
// Supports SecLists-compatible import (one payload per line, # comments stripped).
'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const { randomUUID } = require('crypto');

const DB_PATH = path.resolve(__dirname, 'data', 'scanner.db');

let _db;
function db() {
  if (!_db) {
    _db = new Database(DB_PATH);
    _db.pragma('journal_mode = WAL');
    _db.pragma('foreign_keys = ON');
    migrate(_db);
  }
  return _db;
}

function migrate(d) {
  d.exec(`
    CREATE TABLE IF NOT EXISTS payload_lists (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      category    TEXT NOT NULL DEFAULT 'custom',
      description TEXT NOT NULL DEFAULT '',
      created_at  TEXT NOT NULL,
      updated_at  TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS payloads (
      id          TEXT PRIMARY KEY,
      list_id     TEXT NOT NULL REFERENCES payload_lists(id) ON DELETE CASCADE,
      value       TEXT NOT NULL,
      note        TEXT NOT NULL DEFAULT '',
      created_at  TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_payloads_list_id ON payloads(list_id);
  `);
}

// ─── Lists ───────────────────────────────────────────────────────────────────

const lists = {
  create({ name, category = 'custom', description = '' }) {
    const now = new Date().toISOString();
    const id  = randomUUID();
    db().prepare(`
      INSERT INTO payload_lists (id,name,category,description,created_at,updated_at)
      VALUES (?,?,?,?,?,?)
    `).run(id, name, category, description, now, now);
    return this.get(id);
  },

  get(id) {
    const row = db().prepare('SELECT * FROM payload_lists WHERE id=?').get(id);
    if (!row) return null;
    const count = db().prepare('SELECT COUNT(*) AS n FROM payloads WHERE list_id=?').get(id);
    return { ...row, payloadCount: count.n };
  },

  list() {
    return db().prepare(`
      SELECT l.*, COUNT(p.id) AS payloadCount
      FROM payload_lists l
      LEFT JOIN payloads p ON p.list_id = l.id
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `).all();
  },

  update(id, { name, category, description }) {
    const now = new Date().toISOString();
    const set = [];
    const vals = [];
    if (name        !== undefined) { set.push('name=?');        vals.push(name); }
    if (category    !== undefined) { set.push('category=?');    vals.push(category); }
    if (description !== undefined) { set.push('description=?'); vals.push(description); }
    if (!set.length) return this.get(id);
    set.push('updated_at=?'); vals.push(now);
    vals.push(id);
    db().prepare(`UPDATE payload_lists SET ${set.join(',')} WHERE id=?`).run(...vals);
    return this.get(id);
  },

  delete(id) {
    const r = db().prepare('DELETE FROM payload_lists WHERE id=?').run(id);
    return r.changes > 0;
  },
};

// ─── Payloads ────────────────────────────────────────────────────────────────

const payloads = {
  add(listId, value, note = '') {
    const now = new Date().toISOString();
    const id  = randomUUID();
    db().prepare(`
      INSERT INTO payloads (id,list_id,value,note,created_at)
      VALUES (?,?,?,?,?)
    `).run(id, listId, String(value).slice(0, 2000), note, now);
    return db().prepare('SELECT * FROM payloads WHERE id=?').get(id);
  },

  bulkAdd(listId, values) {
    // values: string[] or {value,note}[]
    const now  = new Date().toISOString();
    const stmt = db().prepare(`
      INSERT OR IGNORE INTO payloads (id,list_id,value,note,created_at)
      VALUES (?,?,?,?,?)
    `);
    const tx = db().transaction((rows) => {
      let n = 0;
      for (const v of rows) {
        const val  = typeof v === 'string' ? v : v.value;
        const note = typeof v === 'string' ? '' : (v.note || '');
        if (!val || !val.trim()) continue;
        stmt.run(randomUUID(), listId, String(val).slice(0, 2000), note, now);
        n++;
      }
      return n;
    });
    return tx(values);
  },

  list(listId, { limit = 500, offset = 0, search = '' } = {}) {
    if (search) {
      return db().prepare(`
        SELECT * FROM payloads
        WHERE list_id=? AND value LIKE ?
        ORDER BY created_at ASC
        LIMIT ? OFFSET ?
      `).all(listId, `%${search}%`, limit, offset);
    }
    return db().prepare(`
      SELECT * FROM payloads
      WHERE list_id=?
      ORDER BY created_at ASC
      LIMIT ? OFFSET ?
    `).all(listId, limit, offset);
  },

  delete(id) {
    const r = db().prepare('DELETE FROM payloads WHERE id=?').run(id);
    return r.changes > 0;
  },

  deleteByList(listId) {
    const r = db().prepare('DELETE FROM payloads WHERE list_id=?').run(listId);
    return r.changes;
  },

  // Returns flat string array — used by engine modules
  valuesForList(listId) {
    return db().prepare('SELECT value FROM payloads WHERE list_id=? ORDER BY created_at ASC')
      .all(listId).map(r => r.value);
  },
};

// ─── SecLists import helper ──────────────────────────────────────────────────
// Parses raw text in SecLists format: one payload per line, # = comment, blank = skip
function parseSecListsText(text) {
  return text
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

module.exports = { lists, payloads, parseSecListsText };
