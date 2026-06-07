// src/core/jobQueue.js
// Simple in-memory job queue that serialises concurrent scan jobs.
//
// Only ONE scan job runs at a time. Additional jobs are queued and
// run in FIFO order as soon as the current job completes.
//
// Usage:
//   import { jobQueue } from './jobQueue.js';
//
//   // Enqueue a job (returns a Promise that resolves when the job finishes)
//   const ctx = await jobQueue.enqueue({
//     jobInput,
//     project,
//     targets,
//     engineConfig,
//     onProgress,   // optional
//   });
//
//   // Check queue state
//   jobQueue.status()  // → { running: bool, queued: number }
//
//   // Cancel a queued (not yet running) job by its job id
//   jobQueue.cancel(jobId)  // → true if cancelled, false if already running/not found

import { runPersistedJob } from './jobRunner.js';
import { ScanJob }         from './models.js';

class JobQueue {
  constructor() {
    this._queue   = [];    // [{ jobId, opts, resolve, reject }]
    this._running = false;
  }

  /**
   * Enqueue a scan job.
   * @param {object} opts  Same options as runPersistedJob
   * @returns {Promise<import('./engine.js').EngineContext>}
   */
  enqueue(opts) {
    const job = opts.jobInput instanceof ScanJob
      ? opts.jobInput
      : new ScanJob(opts.jobInput || {});

    // Normalize jobInput so downstream always gets a ScanJob instance
    const normalizedOpts = { ...opts, jobInput: job };

    return new Promise((resolve, reject) => {
      this._queue.push({ jobId: job.id, opts: normalizedOpts, resolve, reject });
      this._tick();
    });
  }

  /**
   * Cancel a queued (not-yet-started) job.
   * @param {string} jobId
   * @returns {boolean}
   */
  cancel(jobId) {
    const idx = this._queue.findIndex((item) => item.jobId === jobId);
    if (idx === -1) return false;
    const [item] = this._queue.splice(idx, 1);
    item.reject(new Error(`Job ${jobId} was cancelled before it started.`));
    return true;
  }

  /**
   * Current queue state.
   * @returns {{ running: boolean, queued: number }}
   */
  status() {
    return {
      running: this._running,
      queued:  this._queue.length,
    };
  }

  // ── Private ───────────────────────────────────────────────────────────────

  _tick() {
    if (this._running || this._queue.length === 0) return;
    this._running = true;
    const item = this._queue.shift();
    this._run(item);
  }

  async _run({ opts, resolve, reject }) {
    try {
      const ctx = await runPersistedJob(opts);
      resolve(ctx);
    } catch (err) {
      reject(err);
    } finally {
      this._running = false;
      this._tick();
    }
  }
}

// Singleton — import { jobQueue } everywhere
export const jobQueue = new JobQueue();
