// backend/jobsStore.js
// Job store — now backed by SQLite via db.js.
// Keeps the same public API so server.js and worker.js need zero changes.

'use strict';

const { jobs: dbJobs, findings: dbFindings, jobLogs } = require('./db');

// ── Public API (same shape as before) ─────────────────────────────────────────

function createJob(job) {
  return dbJobs.create(job);
}

function listJobs(filter = {}) {
  return dbJobs.list(filter);
}

function getJob(jobId) {
  return dbJobs.get(jobId);
}

function updateJob(jobId, patch) {
  return dbJobs.update(jobId, patch);
}

/**
 * Save all findings + logs from a completed scan job.
 * ctx = { findings: [...], evidences: [...], logs: [...] }
 */
function saveJobResult(jobId, ctx) {
  const job = dbJobs.get(jobId);
  if (!job) return;

  // Persist findings to DB
  if (Array.isArray(ctx.findings) && ctx.findings.length) {
    const rows = ctx.findings.map(f => ({
      ...f,
      jobId,
      projectId: job.projectId,
    }));
    dbFindings.bulkCreate(rows);
  }

  // Persist logs to DB
  if (Array.isArray(ctx.logs)) {
    ctx.logs.forEach(entry => {
      const level   = entry.level   || entry.type || 'info';
      const message = entry.message || entry.text || String(entry);
      jobLogs.append(jobId, level, message);
    });
  }
}

function getJobResult(jobId) {
  const findings  = dbFindings.listByJob(jobId);
  const logs      = jobLogs.getByJob(jobId);
  return { findings, evidences: [], logs };
}

function nextQueuedJob() {
  return dbJobs.nextQueued();
}

module.exports = {
  createJob,
  listJobs,
  getJob,
  updateJob,
  saveJobResult,
  getJobResult,
  nextQueuedJob,
};
