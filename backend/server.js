// backend/server.js
// HTTP API for managing scan jobs and retrieving results. Runs on Termux or VPS.

const express = require('express');
const bodyParser = require('body-parser');
const { randomUUID } = require('crypto');
const { config } = require('./config');
const {
  createJob,
  listJobs,
  getJob,
  updateJob,
  getJobResult,
} = require('./jobsStore');
const { startWorker } = require('./worker');

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

// Allow simple CORS from any origin for now (front-end console).
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Create a new scan job.
app.post('/api/scans', (req, res) => {
  const { projectId, targets, policyId, description } = req.body || {};
  if (!projectId || !Array.isArray(targets) || !targets.length) {
    return res.status(400).json({ error: 'projectId and non-empty targets[] are required' });
  }

  const jobId = randomUUID();
  const job = createJob({
    id: jobId,
    projectId,
    targets,
    policyId: policyId || 'policy_normal',
    description: description || '',
  });

  res.status(202)
    .location(`/api/scans/${jobId}`)
    .json({ jobId, status: job.status });
});

// List jobs (optionally filter by projectId).
app.get('/api/scans', (req, res) => {
  const { projectId } = req.query;
  const jobs = listJobs({ projectId });
  res.json({ jobs });
});

// Get single job status.
app.get('/api/scans/:jobId', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  res.json(job);
});

// Get job results.
app.get('/api/scans/:jobId/results', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  const result = getJobResult(req.params.jobId);
  res.json({ jobId: job.id, status: job.status, ...result });
});

// Optional: cancel a job.
app.post('/api/scans/:jobId/cancel', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  if (job.status === 'completed' || job.status === 'failed') {
    return res.status(400).json({ error: 'job already finished' });
  }
  updateJob(job.id, { status: 'canceled' });
  res.json({ ok: true });
});

app.listen(config.port, () => {
  console.log(`Scanner backend listening on port ${config.port}`);
});

startWorker();
