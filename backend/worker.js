// backend/worker.js
// Background worker loop that pulls queued jobs from the store and runs scans.

const { config } = require('./config');
const {
  nextQueuedJob,
  updateJob,
  getJob,
  saveJobResult,
} = require('./jobsStore');

// Reuse the existing engine code compiled for Node via dynamic import.
const engine = require('../dist-node/engine-node.js');

let activeJobs = 0;

async function workerLoop() {
  if (activeJobs >= config.maxConcurrentJobs) return;

  const job = nextQueuedJob();
  if (!job) return;

  activeJobs++;
  updateJob(job.id, { status: 'running', progress: 0, error: null });

  try {
    const ctx = await engine.runScanJobFromJobRecord(job, {
      maxParallelTargetsPerJob: config.maxParallelTargetsPerJob,
    });

    saveJobResult(job.id, ctx);
    updateJob(job.id, { status: 'completed', progress: 100 });
  } catch (err) {
    console.error('Worker error for job', job.id, err);
    updateJob(job.id, {
      status: 'failed',
      error: String(err && err.stack ? err.stack : err),
    });
  } finally {
    activeJobs--;
  }
}

function startWorker() {
  // Run a tick every 2 seconds.
  setInterval(workerLoop, 2000);
}

module.exports = { startWorker };
