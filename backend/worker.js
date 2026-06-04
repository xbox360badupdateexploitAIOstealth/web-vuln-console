// backend/worker.js
// Scan job worker with concurrency queue.
// Picks up queued jobs every 3s, runs up to MAX_CONCURRENT scans at once.
// Streams progress back via job status in jobsStore.

'use strict';

const { listJobs, getJob, updateJob, saveJobResult } = require('./jobsStore');
const { runScanJobFromJobRecord }                    = require('./engine-bridge');

const POLL_INTERVAL_MS  = 3000;
const MAX_CONCURRENT    = 2; // Safe for Termux (Android). Bump to 4 on VPS.

let activeCount = 0;
let workerTimer = null;

function log(msg) { process.stdout.write(`[WORKER] ${msg}\n`); }

async function processJob(job) {
  activeCount++;
  log(`Starting job ${job.id} (project: ${job.projectId}, targets: ${job.targets?.length || 0})`);
  updateJob(job.id, { status: 'running', startedAt: new Date().toISOString() });

  try {
    const result = await runScanJobFromJobRecord(job, { maxParallelTargetsPerJob: 2 });
    updateJob(job.id, {
      status:      'completed',
      completedAt: new Date().toISOString(),
      findingCount: result.findings.length,
    });
    saveJobResult(job.id, result);
    log(`Job ${job.id} completed. Findings: ${result.findings.length}`);
  } catch (err) {
    log(`Job ${job.id} FAILED: ${err.message}`);
    updateJob(job.id, {
      status:      'failed',
      completedAt: new Date().toISOString(),
      error:       err.message,
    });
    saveJobResult(job.id, { findings: [], logs: [`Fatal error: ${err.message}`], evidences: [] });
  } finally {
    activeCount--;
  }
}

function tick() {
  if (activeCount >= MAX_CONCURRENT) return;

  const queued = listJobs({ status: 'queued' });
  if (!queued.length) return;

  const slots   = MAX_CONCURRENT - activeCount;
  const toStart = queued.slice(0, slots);

  for (const job of toStart) {
    processJob(job); // Fire-and-forget, managed via activeCount.
  }
}

function startWorker() {
  log(`Worker started. Max concurrent jobs: ${MAX_CONCURRENT}. Poll: ${POLL_INTERVAL_MS}ms.`);
  workerTimer = setInterval(tick, POLL_INTERVAL_MS);
  tick(); // Run immediately on boot.
}

function stopWorker() {
  if (workerTimer) { clearInterval(workerTimer); workerTimer = null; }
  log('Worker stopped.');
}

module.exports = { startWorker, stopWorker };
