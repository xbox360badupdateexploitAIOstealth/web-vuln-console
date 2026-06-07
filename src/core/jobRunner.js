// src/core/jobRunner.js
// Wraps runScanJob() with full lifecycle management:
//   - persists job record as 'running' before scan starts
//   - updates job status, stats, startedAt, finishedAt on completion or error
//   - bulk-persists all findings and evidences produced by the scan
//   - emits AuditEvents for job start, completion, and error
//   - exposes an onProgress callback for live UI updates
//
// Usage:
//   import { runPersistedJob } from './jobRunner.js';
//
//   const ctx = await runPersistedJob({
//     jobInput,        // ScanJob | plain object
//     project,         // Project
//     targets,         // Target[]
//     engineConfig,    // EngineConfig
//     onProgress,      // optional (ctx) => void  — called after each target
//   });

import { runScanJob }           from './engine.js';
import { db, S }                from './db.js';
import { ScanJob, AuditEvent }  from './models.js';

/**
 * Run a scan job with full persistence lifecycle.
 *
 * @param {object} opts
 * @param {ScanJob|object} opts.jobInput
 * @param {object}         opts.project
 * @param {object[]}       opts.targets
 * @param {object}         opts.engineConfig
 * @param {Function}       [opts.onProgress]  called with (ctx) after each target completes
 * @returns {Promise<import('./engine.js').EngineContext>}
 */
export async function runPersistedJob({
  jobInput,
  project,
  targets,
  engineConfig,
  onProgress = null,
}) {
  const job = jobInput instanceof ScanJob ? jobInput : new ScanJob(jobInput);

  // ── 1. Persist job as 'running' ──────────────────────────────────────────────
  job.status    = 'running';
  job.startedAt = new Date();
  await db.put(S.SCAN_JOBS, _serializeJob(job));

  await _auditEvent({
    scopeId:   project.id,
    scopeType: 'project',
    actor:     job.initiatedBy || 'system',
    action:    'scan_job.started',
    details:   { jobId: job.id, policyId: job.policyId, targetCount: targets.length },
  });

  // ── 2. Run the scan ──────────────────────────────────────────────────────────────
  let ctx;
  try {
    // Wrap engine's scanTarget loop so we can call onProgress per target
    ctx = await runScanJob({
      jobInput: job,
      project,
      targets,
      engineConfig,
    });

    if (onProgress) onProgress(ctx);

    // ── 3a. Success ───────────────────────────────────────────────────────────────
    job.status     = 'done';
    job.finishedAt = new Date();
    job.stats      = {
      numRequests:     ctx.evidences.length,
      numFindings:     ctx.findings.length,
      numErrors:       0,
      modulesExecuted: 0, // populated from enabledModules count if needed
    };

    await _flushResults(job, ctx);

    await _auditEvent({
      scopeId:   project.id,
      scopeType: 'project',
      actor:     'system',
      action:    'scan_job.completed',
      details:   {
        jobId:       job.id,
        findings:    ctx.findings.length,
        evidences:   ctx.evidences.length,
        durationMs:  job.finishedAt - job.startedAt,
      },
    });

    return ctx;

  } catch (err) {
    // ── 3b. Error ───────────────────────────────────────────────────────────────
    job.status     = 'error';
    job.finishedAt = new Date();
    job.stats      = {
      numRequests:     ctx?.evidences?.length ?? 0,
      numFindings:     ctx?.findings?.length  ?? 0,
      numErrors:       1,
      modulesExecuted: 0,
    };

    await db.put(S.SCAN_JOBS, _serializeJob(job));

    // Persist partial results if any findings were collected before the crash
    if (ctx && (ctx.findings.length || ctx.evidences.length)) {
      await _flushResults(job, ctx);
    }

    await _auditEvent({
      scopeId:   project.id,
      scopeType: 'project',
      actor:     'system',
      action:    'scan_job.errored',
      details:   { jobId: job.id, error: err.message || String(err) },
    });

    throw err;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async function _flushResults(job, ctx) {
  // Persist job record with final status first
  await db.put(S.SCAN_JOBS, _serializeJob(job));

  // Bulk-write findings and evidences
  if (ctx.findings.length)  await db.bulkPut(S.FINDINGS,  ctx.findings.map(_serialize));
  if (ctx.evidences.length) await db.bulkPut(S.EVIDENCES, ctx.evidences.map(_serialize));
}

async function _auditEvent(opts) {
  try {
    await db.put(S.AUDIT_EVENTS, new AuditEvent(opts));
  } catch (_) {
    // Audit write failure must never crash the scan
  }
}

function _serialize(obj) {
  // Convert class instances to plain objects (for IDB structured clone)
  return JSON.parse(JSON.stringify(obj));
}

function _serializeJob(job) {
  const plain = _serialize(job);
  // Ensure Date objects survive serialization as ISO strings
  if (plain.createdAt  instanceof Date) plain.createdAt  = plain.createdAt.toISOString();
  if (plain.startedAt  instanceof Date) plain.startedAt  = plain.startedAt.toISOString();
  if (plain.finishedAt instanceof Date) plain.finishedAt = plain.finishedAt.toISOString();
  return plain;
}
