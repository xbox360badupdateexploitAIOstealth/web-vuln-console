// backend/worker.js
// Background worker loop. Pulls queued jobs and runs the scan engine.

const { config } = require('./config');
const {
  nextQueuedJob,
  updateJob,
  saveJobResult,
} = require('./jobsStore');
const engine = require('./engine-bridge');

let activeJobs = 0;

async function workerLoop() {
  if (activeJobs >= config.maxConcurrentJobs) return;
  const job = nextQueuedJob();
  if (!job) return;

  activeJobs++;
  updateJob(job.id, { status: 'running', progress: 0, error: null });
  console.log(`[WORKER] Starting job ${job.id} (project: ${job.projectId}, targets: ${Array.isArray(job.targets) ? job.targets.length : 0})`);

  try {
    const ctx = await engine.runScanJobFromJobRecord(job, {
      maxParallelTargetsPerJob: config.maxParallelTargetsPerJob || 2,
    });
    saveJobResult(job.id, ctx);
    updateJob(job.id, { status: 'completed', progress: 100 });
    console.log(`[WORKER] Job ${job.id} completed. Findings: ${ctx.findings.length}`);
  } catch (err) {
    console.error(`[WORKER] Job ${job.id} FAILED:`, err);
    updateJob(job.id, {
      status: 'failed',
      error: String(err && err.stack ? err.stack : err),
    });
  } finally {
    activeJobs--;
  }
}

function startWorker() {
  console.log('[WORKER] Background scan worker started. Polling every 2s.');
  setInterval(workerLoop, 2000);
}

module.exports = { startWorker };
