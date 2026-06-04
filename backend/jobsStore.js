// backend/jobsStore.js
// Simple JSON-file-based job store for Termux/VPS backend.

const fs = require('fs');
const path = require('path');
const { config } = require('./config');

const JOBS_FILE = path.join(config.dataDir, 'jobs.json');
const RESULTS_FILE = path.join(config.dataDir, 'results.json');

function ensureDataDir() {
  if (!fs.existsSync(config.dataDir)) {
    fs.mkdirSync(config.dataDir, { recursive: true });
  }
}

function readJsonSafe(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, 'utf8');
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch (e) {
    console.error('Error reading', file, e);
    return fallback;
  }
}

function writeJsonSafe(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error('Error writing', file, e);
  }
}

function loadState() {
  ensureDataDir();
  const jobs = readJsonSafe(JOBS_FILE, {});
  const results = readJsonSafe(RESULTS_FILE, {});
  // Normalize any jobs left in running state across restarts.
  for (const jobId of Object.keys(jobs)) {
    const job = jobs[jobId];
    if (job.status === 'running') {
      job.status = 'interrupted';
      job.updatedAt = new Date().toISOString();
    }
  }
  return { jobs, results };
}

let state = loadState();

function persist() {
  writeJsonSafe(JOBS_FILE, state.jobs);
  writeJsonSafe(RESULTS_FILE, state.results);
}

function createJob(job) {
  const now = new Date().toISOString();
  const id = job.id;
  state.jobs[id] = {
    ...job,
    status: 'queued',
    createdAt: now,
    updatedAt: now,
    progress: 0,
    error: null,
  };
  persist();
  return state.jobs[id];
}

function listJobs(filter = {}) {
  const out = [];
  for (const jobId of Object.keys(state.jobs)) {
    const job = state.jobs[jobId];
    if (filter.projectId && job.projectId !== filter.projectId) continue;
    out.push(job);
  }
  // Sort by createdAt desc.
  out.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  return out;
}

function getJob(jobId) {
  return state.jobs[jobId] || null;
}

function updateJob(jobId, patch) {
  const job = state.jobs[jobId];
  if (!job) return null;
  Object.assign(job, patch, { updatedAt: new Date().toISOString() });
  persist();
  return job;
}

function saveJobResult(jobId, ctx) {
  state.results[jobId] = {
    findings: ctx.findings || [],
    evidences: ctx.evidences || [],
    logs: ctx.logs || [],
  };
  persist();
}

function getJobResult(jobId) {
  return state.results[jobId] || { findings: [], evidences: [], logs: [] };
}

function nextQueuedJob() {
  const jobs = Object.values(state.jobs).filter((j) => j.status === 'queued');
  if (!jobs.length) return null;
  // Oldest first.
  jobs.sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
  return jobs[0];
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
