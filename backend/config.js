// backend/config.js
// Configuration for the scanner backend. Designed to work on Termux and VPS.

const path = require('path');

const config = {
  // HTTP port for the backend API server.
  port: parseInt(process.env.PORT || '8787', 10),

  // Directory where job metadata and results will be stored.
  dataDir: process.env.DATA_DIR || path.resolve(__dirname, 'data'),

  // Maximum number of scan jobs the worker should run in parallel.
  maxConcurrentJobs: parseInt(process.env.MAX_CONCURRENT_JOBS || '1', 10),

  // Maximum number of targets processed in parallel per job.
  maxParallelTargetsPerJob: parseInt(
    process.env.MAX_PARALLEL_TARGETS_PER_JOB || '3',
    10
  ),
};

module.exports = { config };
