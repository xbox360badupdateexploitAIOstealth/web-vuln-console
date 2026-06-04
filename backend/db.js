// backend/db.js
// Full SQLite persistence layer for web-vuln-console.
// Stores projects, targets, findings, jobs, evidence, and audit logs.
// Uses better-sqlite3 (synchronous, zero-config, works on Termux + VPS).

'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const { config } = require('./config');

// ── Ensure data directory exists ──────────────────────────────────────────────
if (!fs.existsSync(config.dataDir)) {
  fs.mkdirSync(config.dataDir, { recursive: true });
}

const DB_PATH = path.join(config.dataDir, 'scanner.db');
const db = new Database(DB_PATH);

// ── Performance pragmas ───────────────────────────────────────────────────────
db.pragma('journal_mode = WAL');   // allows concurrent reads
db.pragma('foreign_keys = ON');    // enforce FK constraints
db.pragma('synchronous = NORMAL'); // fast but safe writes

// ─────────────────────────────────────────────────────────────────────────────
// SCHEMA
// ─────────────────────────────────────────────────────────────────────────────
db.exec(`
  -- ── Projects ──────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS projects (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    client       TEXT NOT NULL DEFAULT '',
    auth_note    TEXT NOT NULL DEFAULT '',
    contact      TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Targets ────────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS targets (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    type         TEXT NOT NULL DEFAULT 'domain',
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Scan Jobs ──────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    targets_json TEXT NOT NULL DEFAULT '[]',
    policy_id    TEXT NOT NULL DEFAULT 'policy_normal',
    description  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'queued',
    progress     INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at  TEXT
  );

  -- ── Findings ───────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    job_id          TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    project_id      TEXT NOT NULL,
    target          TEXT NOT NULL,
    rule_id         TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT '',
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    url             TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    owasp_tag       TEXT NOT NULL DEFAULT '',
    cwe_tag         TEXT NOT NULL DEFAULT '',
    cve_tag         TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open',
    false_positive  INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Raw Evidence / Logs ────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS job_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    level      TEXT NOT NULL DEFAULT 'info',
    message    TEXT NOT NULL,
    ts         TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Audit Trail ────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT NOT NULL,
    entity     TEXT NOT NULL DEFAULT '',
    entity_id  TEXT NOT NULL DEFAULT '',
    actor_ip   TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    ts         TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Indexes for common queries ─────────────────────────────────────────────
  CREATE INDEX IF NOT EXISTS idx_targets_project  ON targets(project_id);
  CREATE INDEX IF NOT EXISTS idx_jobs_project     ON jobs(project_id);
  CREATE INDEX IF NOT EXISTS idx_jobs_status      ON jobs(status);
  CREATE INDEX IF NOT EXISTS idx_findings_job     ON findings(job_id);
  CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
  CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings(severity);
  CREATE INDEX IF NOT EXISTS idx_joblogs_job      ON job_logs(job_id);
`);

// ─────────────────────────────────────────────────────────────────────────────
// PROJECT HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const _stmts = {};

function stmt(sql) {
  if (!_stmts[sql]) _stmts[sql] = db.prepare(sql);
  return _stmts[sql];
}

const projects = {
  create(p) {
    stmt(`INSERT INTO projects (id,name,client,auth_note,contact,status)
          VALUES (@id,@name,@client,@auth_note,@contact,@status)`).run({
      id: p.id, name: p.name,
      client: p.client || '', auth_note: p.auth_note || '',
      contact: p.contact || '', status: p.status || 'active',
    });
    return projects.get(p.id);
  },
  get(id) {
    return stmt(`SELECT * FROM projects WHERE id=?`).get(id) || null;
  },
  list() {
    return stmt(`SELECT * FROM projects ORDER BY created_at DESC`).all();
  },
  update(id, patch) {
    const allowed = ['name','client','auth_note','contact','status'];
    const sets = Object.keys(patch).filter(k => allowed.includes(k)).map(k => `${k}=@${k}`).join(',');
    if (!sets) return projects.get(id);
    stmt(`UPDATE projects SET ${sets}, updated_at=datetime('now') WHERE id=@id`).run({ ...patch, id });
    return projects.get(id);
  },
  delete(id) {
    return stmt(`DELETE FROM projects WHERE id=?`).run(id).changes > 0;
  },
  stats(id) {
    const targetCount  = stmt(`SELECT COUNT(*) as n FROM targets  WHERE project_id=?`).get(id)?.n || 0;
    const findingCount = stmt(`SELECT COUNT(*) as n FROM findings WHERE project_id=?`).get(id)?.n || 0;
    const critCount    = stmt(`SELECT COUNT(*) as n FROM findings WHERE project_id=? AND severity='critical'`).get(id)?.n || 0;
    const highCount    = stmt(`SELECT COUNT(*) as n FROM findings WHERE project_id=? AND severity='high'`).get(id)?.n || 0;
    const jobCount     = stmt(`SELECT COUNT(*) as n FROM jobs WHERE project_id=?`).get(id)?.n || 0;
    return { targetCount, findingCount, critCount, highCount, jobCount };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// TARGET HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const targets = {
  create(t) {
    stmt(`INSERT INTO targets (id,project_id,host,type,notes) VALUES (@id,@project_id,@host,@type,@notes)`).run({
      id: t.id, project_id: t.project_id, host: t.host,
      type: t.type || 'domain', notes: t.notes || '',
    });
    return targets.get(t.id);
  },
  get(id) {
    return stmt(`SELECT * FROM targets WHERE id=?`).get(id) || null;
  },
  listByProject(project_id) {
    return stmt(`SELECT * FROM targets WHERE project_id=? ORDER BY created_at ASC`).all(project_id);
  },
  delete(id) {
    return stmt(`DELETE FROM targets WHERE id=?`).run(id).changes > 0;
  },
  bulkCreate(rows) {
    const insert = stmt(`INSERT OR IGNORE INTO targets (id,project_id,host,type,notes) VALUES (@id,@project_id,@host,@type,@notes)`);
    const tx = db.transaction((items) => items.forEach(r => insert.run(r)));
    tx(rows.map(r => ({ id: r.id, project_id: r.project_id, host: r.host, type: r.type || 'domain', notes: r.notes || '' })));
    return rows.length;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// JOB HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const jobs = {
  create(j) {
    stmt(`INSERT INTO jobs (id,project_id,targets_json,policy_id,description,status)
          VALUES (@id,@project_id,@targets_json,@policy_id,@description,@status)`).run({
      id: j.id, project_id: j.projectId,
      targets_json: JSON.stringify(j.targets || []),
      policy_id: j.policyId || 'policy_normal',
      description: j.description || '', status: 'queued',
    });
    return jobs.get(j.id);
  },
  get(id) {
    const row = stmt(`SELECT * FROM jobs WHERE id=?`).get(id);
    if (!row) return null;
    return _hydrateJob(row);
  },
  list(filter = {}) {
    let sql = `SELECT * FROM jobs`;
    const params = [];
    if (filter.projectId) { sql += ` WHERE project_id=?`; params.push(filter.projectId); }
    sql += ` ORDER BY created_at DESC`;
    return stmt(sql).all(...params).map(_hydrateJob);
  },
  update(id, patch) {
    const allowed = ['status','progress','error','finished_at'];
    const sets = Object.keys(patch).filter(k => allowed.includes(k)).map(k => `${k}=@${k}`).join(',');
    if (!sets) return jobs.get(id);
    stmt(`UPDATE jobs SET ${sets}, updated_at=datetime('now') WHERE id=@id`).run({ ...patch, id });
    return jobs.get(id);
  },
  nextQueued() {
    const row = stmt(`SELECT * FROM jobs WHERE status='queued' ORDER BY created_at ASC LIMIT 1`).get();
    return row ? _hydrateJob(row) : null;
  },
  fixInterrupted() {
    stmt(`UPDATE jobs SET status='interrupted', updated_at=datetime('now') WHERE status='running'`).run();
  },
};

function _hydrateJob(row) {
  return {
    ...row,
    targets: (() => { try { return JSON.parse(row.targets_json); } catch { return []; } })(),
    projectId: row.project_id,
    policyId:  row.policy_id,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// FINDING HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const findings = {
  create(f) {
    stmt(`INSERT INTO findings
          (id,job_id,project_id,target,rule_id,category,title,severity,url,evidence,description,remediation,owasp_tag,cwe_tag,cve_tag,status)
          VALUES
          (@id,@job_id,@project_id,@target,@rule_id,@category,@title,@severity,@url,@evidence,@description,@remediation,@owasp_tag,@cwe_tag,@cve_tag,@status)`
    ).run({
      id: f.id, job_id: f.jobId, project_id: f.projectId,
      target: f.target || '', rule_id: f.ruleId || '',
      category: f.category || '', title: f.title || 'Finding',
      severity: f.severity || 'info', url: f.url || '',
      evidence: f.evidence || '', description: f.description || '',
      remediation: f.remediation || '', owasp_tag: f.owaspTag || '',
      cwe_tag: f.cweTag || '', cve_tag: f.cveTag || '',
      status: f.status || 'open',
    });
    return f.id;
  },
  bulkCreate(rows) {
    const insert = stmt(`INSERT OR IGNORE INTO findings
      (id,job_id,project_id,target,rule_id,category,title,severity,url,evidence,description,remediation,owasp_tag,cwe_tag,cve_tag,status)
      VALUES
      (@id,@job_id,@project_id,@target,@rule_id,@category,@title,@severity,@url,@evidence,@description,@remediation,@owasp_tag,@cwe_tag,@cve_tag,@status)`);
    const tx = db.transaction((items) => items.forEach(f => insert.run(f)));
    tx(rows.map(f => ({
      id: f.id, job_id: f.jobId, project_id: f.projectId,
      target: f.target || '', rule_id: f.ruleId || '',
      category: f.category || '', title: f.title || 'Finding',
      severity: f.severity || 'info', url: f.url || '',
      evidence: f.evidence || '', description: f.description || '',
      remediation: f.remediation || '', owasp_tag: f.owaspTag || '',
      cwe_tag: f.cweTag || '', cve_tag: f.cveTag || '',
      status: f.status || 'open',
    })));
  },
  listByJob(job_id) {
    return stmt(`SELECT * FROM findings WHERE job_id=? ORDER BY severity DESC, created_at ASC`).all(job_id);
  },
  listByProject(project_id, filters = {}) {
    let sql = `SELECT * FROM findings WHERE project_id=?`;
    const params = [project_id];
    if (filters.severity) { sql += ` AND severity=?`; params.push(filters.severity); }
    if (filters.status)   { sql += ` AND status=?`;   params.push(filters.status); }
    if (filters.category) { sql += ` AND category=?`; params.push(filters.category); }
    sql += ` ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at ASC`;
    return stmt(sql).all(...params);
  },
  updateStatus(id, status) {
    return stmt(`UPDATE findings SET status=? WHERE id=?`).run(status, id).changes > 0;
  },
  markFalsePositive(id, val = 1) {
    return stmt(`UPDATE findings SET false_positive=? WHERE id=?`).run(val ? 1 : 0, id).changes > 0;
  },
  severitySummary(project_id) {
    return stmt(`SELECT severity, COUNT(*) as count FROM findings WHERE project_id=? AND false_positive=0 GROUP BY severity`).all(project_id);
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// JOB LOGS
// ─────────────────────────────────────────────────────────────────────────────
const jobLogs = {
  append(job_id, level, message) {
    stmt(`INSERT INTO job_logs (job_id,level,message) VALUES (?,?,?)`).run(job_id, level, message);
  },
  getByJob(job_id, limit = 500) {
    return stmt(`SELECT * FROM job_logs WHERE job_id=? ORDER BY id ASC LIMIT ?`).all(job_id, limit);
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// AUDIT LOG
// ─────────────────────────────────────────────────────────────────────────────
const auditLog = {
  write(action, entity = '', entity_id = '', actor_ip = '', detail = '') {
    stmt(`INSERT INTO audit_log (action,entity,entity_id,actor_ip,detail) VALUES (?,?,?,?,?)`)
      .run(action, entity, entity_id, actor_ip, detail);
  },
  recent(limit = 100) {
    return stmt(`SELECT * FROM audit_log ORDER BY id DESC LIMIT ?`).all(limit);
  },
};

// Fix any jobs left in running state from a previous crash
jobs.fixInterrupted();

module.exports = { db, projects, targets, jobs, findings, jobLogs, auditLog };
