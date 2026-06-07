// backend/db.js
// Full SQLite persistence layer for web-vuln-console.
// Stores projects, targets, findings, jobs, evidence, and audit logs.
// Uses better-sqlite3 (synchronous, zero-config, works on Termux + VPS).

'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const { randomUUID } = require('crypto');
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
    env          TEXT NOT NULL DEFAULT 'prod',
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

// ── Migrate: add env column to targets if it doesn't exist (for existing DBs) ─
try {
  db.exec(`ALTER TABLE targets ADD COLUMN env TEXT NOT NULL DEFAULT 'prod'`);
} catch (_) { /* column already exists — safe to ignore */ }

// ─────────────────────────────────────────────────────────────────────────────
// PREPARED STATEMENT CACHE
// ─────────────────────────────────────────────────────────────────────────────
const _stmts = {};

function stmt(sql) {
  if (!_stmts[sql]) _stmts[sql] = db.prepare(sql);
  return _stmts[sql];
}

// ─────────────────────────────────────────────────────────────────────────────
// PROJECT HELPERS
// ─────────────────────────────────────────────────────────────────────────────
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
    stmt(`INSERT INTO targets (id,project_id,host,type,notes,env) VALUES (@id,@project_id,@host,@type,@notes,@env)`).run({
      id: t.id, project_id: t.project_id, host: t.host,
      type: t.type || 'domain', notes: t.notes || '', env: t.env || 'prod',
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
    const insert = stmt(`INSERT OR IGNORE INTO targets (id,project_id,host,type,notes,env) VALUES (@id,@project_id,@host,@type,@notes,@env)`);
    const tx = db.transaction((items) => {
      let count = 0;
      for (const r of items) {
        const result = insert.run({
          id: r.id, project_id: r.project_id, host: r.host,
          type: r.type || 'domain', notes: r.notes || '', env: r.env || 'prod',
        });
        count += result.changes;
      }
      return count;
    });
    return tx(rows);
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// JOB HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const jobs = {
  create(j) {
    const id = j.id || randomUUID();
    const targetsJson = Array.isArray(j.targets) ? JSON.stringify(j.targets) : (j.targets_json || '[]');
    stmt(`INSERT INTO jobs (id, project_id, targets_json, policy_id, description, status, progress)
          VALUES (@id, @project_id, @targets_json, @policy_id, @description, @status, @progress)`).run({
      id,
      project_id:   j.projectId   || j.project_id,
      targets_json: targetsJson,
      policy_id:    j.policyId    || j.policy_id    || 'policy_normal',
      description:  j.description || '',
      status:       j.status      || 'queued',
      progress:     j.progress    || 0,
    });
    return jobs.get(id);
  },

  get(id) {
    const row = stmt(`SELECT * FROM jobs WHERE id=?`).get(id);
    if (!row) return null;
    return _hydrateJob(row);
  },

  list(filter = {}) {
    let sql = `SELECT * FROM jobs`;
    const conditions = [];
    const params = {};

    if (filter.status) {
      conditions.push(`status = @status`);
      params.status = filter.status;
    }
    if (filter.projectId || filter.project_id) {
      conditions.push(`project_id = @project_id`);
      params.project_id = filter.projectId || filter.project_id;
    }

    if (conditions.length) sql += ` WHERE ` + conditions.join(' AND ');
    sql += ` ORDER BY created_at DESC`;

    return stmt(sql).all(params).map(_hydrateJob);
  },

  update(id, patch) {
    const allowed = ['status', 'progress', 'error', 'finished_at'];
    const sets = [];
    const params = { id };

    for (const key of allowed) {
      const camelKey = key.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
      if (patch[key] !== undefined) {
        sets.push(`${key} = @${key}`);
        params[key] = patch[key];
      } else if (patch[camelKey] !== undefined) {
        sets.push(`${key} = @${key}`);
        params[key] = patch[camelKey];
      }
    }

    // Map worker.js camelCase fields
    if (patch.startedAt) {
      sets.push(`updated_at = @updated_at`);
      params.updated_at = patch.startedAt;
    }
    if (patch.completedAt) {
      sets.push(`finished_at = @finished_at`);
      params.finished_at = patch.completedAt;
    }
    // findingCount is not stored — findings are counted live from findings table

    if (!sets.length) return jobs.get(id);

    sets.push(`updated_at = datetime('now')`);
    stmt(`UPDATE jobs SET ${sets.join(', ')} WHERE id = @id`).run(params);
    return jobs.get(id);
  },

  delete(id) {
    return stmt(`DELETE FROM jobs WHERE id=?`).run(id).changes > 0;
  },

  nextQueued() {
    const row = stmt(`SELECT * FROM jobs WHERE status='queued' ORDER BY created_at ASC LIMIT 1`).get();
    return row ? _hydrateJob(row) : null;
  },

  // Called at boot — resets any jobs stuck in 'running' state from a previous crash
  fixInterrupted() {
    stmt(`UPDATE jobs SET status='interrupted', updated_at=datetime('now') WHERE status='running'`).run();
  },
};

function _hydrateJob(row) {
  return {
    ...row,
    projectId: row.project_id,
    policyId:  row.policy_id,
    targets:   (() => { try { return JSON.parse(row.targets_json || '[]'); } catch { return []; } })(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// FINDINGS HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const findings = {
  create(f) {
    const id = f.id || randomUUID();
    stmt(`INSERT INTO findings
          (id, job_id, project_id, target, rule_id, category, title, severity, url, evidence, description, remediation, owasp_tag, cwe_tag, cve_tag, status)
          VALUES
          (@id, @job_id, @project_id, @target, @rule_id, @category, @title, @severity, @url, @evidence, @description, @remediation, @owasp_tag, @cwe_tag, @cve_tag, @status)`).run({
      id,
      job_id:      f.jobId      || f.job_id,
      project_id:  f.projectId  || f.project_id,
      target:      f.target     || f.url         || '',
      rule_id:     f.ruleId     || f.rule_id      || f.moduleId || '',
      category:    f.category   || '',
      title:       f.title      || '',
      severity:    f.severity   || 'info',
      url:         f.url        || '',
      evidence:    f.evidence   || f.bodySnippet  || '',
      description: f.description|| f.shortDescription || '',
      remediation: f.remediation|| '',
      owasp_tag:   f.owaspTag   || f.owasp_tag    || '',
      cwe_tag:     f.cweTag     || f.cwe_tag       || '',
      cve_tag:     f.cveTag     || f.cve_tag       || '',
      status:      f.status     || 'open',
    });
    return findings.get(id);
  },

  get(id) {
    return stmt(`SELECT * FROM findings WHERE id=?`).get(id) || null;
  },

  listByJob(jobId) {
    return stmt(`SELECT * FROM findings WHERE job_id=? ORDER BY
      CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'low'      THEN 4
        ELSE 5
      END, created_at DESC`).all(jobId);
  },

  listByProject(projectId, filters = {}) {
    let sql = `SELECT * FROM findings WHERE project_id=?`;
    const params = [projectId];
    if (filters.severity) { sql += ` AND severity=?`; params.push(filters.severity); }
    if (filters.status)   { sql += ` AND status=?`;   params.push(filters.status); }
    if (filters.category) { sql += ` AND category=?`; params.push(filters.category); }
    sql += ` ORDER BY CASE severity
      WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
      END, created_at DESC`;
    return stmt(sql).all(...params);
  },

  bulkCreate(rows) {
    const insert = stmt(`INSERT OR IGNORE INTO findings
      (id, job_id, project_id, target, rule_id, category, title, severity, url, evidence, description, remediation, owasp_tag, cwe_tag, cve_tag, status)
      VALUES
      (@id, @job_id, @project_id, @target, @rule_id, @category, @title, @severity, @url, @evidence, @description, @remediation, @owasp_tag, @cwe_tag, @cve_tag, @status)`);
    const tx = db.transaction((items) => {
      let count = 0;
      for (const f of items) {
        const result = insert.run({
          id:          f.id          || randomUUID(),
          job_id:      f.jobId       || f.job_id,
          project_id:  f.projectId   || f.project_id,
          target:      f.target      || f.url         || '',
          rule_id:     f.ruleId      || f.rule_id      || f.moduleId || '',
          category:    f.category    || '',
          title:       f.title       || '',
          severity:    f.severity    || 'info',
          url:         f.url         || '',
          evidence:    f.evidence    || f.bodySnippet  || '',
          description: f.description || f.shortDescription || '',
          remediation: f.remediation || '',
          owasp_tag:   f.owaspTag    || f.owasp_tag    || '',
          cwe_tag:     f.cweTag      || f.cwe_tag       || '',
          cve_tag:     f.cveTag      || f.cve_tag       || '',
          status:      f.status      || 'open',
        });
        count += result.changes;
      }
      return count;
    });
    return tx(rows);
  },

  updateStatus(id, status) {
    stmt(`UPDATE findings SET status=@status WHERE id=@id`).run({ id, status });
    return findings.get(id);
  },

  markFalsePositive(id, val = 1) {
    return stmt(`UPDATE findings SET false_positive=? WHERE id=?`).run(val ? 1 : 0, id).changes > 0;
  },

  severitySummary(projectId) {
    const rows = stmt(`SELECT severity, COUNT(*) as count FROM findings WHERE project_id=? AND false_positive=0 GROUP BY severity`).all(projectId);
    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const row of rows) {
      if (Object.prototype.hasOwnProperty.call(summary, row.severity)) {
        summary[row.severity] = row.count;
      }
    }
    return summary;
  },

  delete(id) {
    return stmt(`DELETE FROM findings WHERE id=?`).run(id).changes > 0;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// JOB LOGS
// ─────────────────────────────────────────────────────────────────────────────
const jobLogs = {
  append(jobId, level, message) {
    stmt(`INSERT INTO job_logs (job_id, level, message) VALUES (@job_id, @level, @message)`).run({
      job_id:  jobId,
      level:   level || 'info',
      message: String(message),
    });
  },

  // Returns plain message strings — used by getJobResult() API response
  getByJob(jobId) {
    return stmt(`SELECT message FROM job_logs WHERE job_id=? ORDER BY ts ASC`).all(jobId).map(r => r.message);
  },

  // Returns full rows with level + ts — used internally / debug
  getByJobFull(jobId) {
    return stmt(`SELECT * FROM job_logs WHERE job_id=? ORDER BY ts ASC`).all(jobId);
  },

  clear(jobId) {
    return stmt(`DELETE FROM job_logs WHERE job_id=?`).run(jobId).changes;
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
  listByEntity(entity, entityId) {
    return stmt(`SELECT * FROM audit_log WHERE entity=? AND entity_id=? ORDER BY ts DESC`).all(entity, entityId);
  },
};

// ── Boot: fix any jobs left running from a previous crash ─────────────────────
jobs.fixInterrupted();

module.exports = { db, projects, targets, jobs, findings, jobLogs, auditLog };
