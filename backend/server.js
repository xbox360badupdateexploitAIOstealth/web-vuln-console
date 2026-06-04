// backend/server.js
// Full HTTP API for WebVulnConsole. Runs on Termux (Android) or any Linux VPS.

const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');
const { randomUUID } = require('crypto');
const { config } = require('./config');
const {
  createJob,
  listJobs,
  getJob,
  updateJob,
  getJobResult,
} = require('./jobsStore');
const { startWorker }     = require('./worker');
const dorksRoute          = require('./routes/dorksRoute');
const reportsRoute        = require('./routes/reportsRoute');

const app = express();

// ─── Middleware ────────────────────────────────────────────────────────────────

app.use(bodyParser.json({ limit: '1mb' }));

// CORS – allow all origins for local/LAN access from any browser.
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin',  '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Simple per-IP rate limiter – protects the phone from hammering itself.
const rateLimitMap = new Map();
app.use((req, res, next) => {
  const ip  = req.ip || 'unknown';
  const now = Date.now();
  const win = rateLimitMap.get(ip) || { count: 0, start: now };
  if (now - win.start > 60000) {
    win.count = 0;
    win.start = now;
  }
  win.count++;
  rateLimitMap.set(ip, win);
  if (win.count > 120) {
    return res.status(429).json({ error: 'Rate limit exceeded. Slow down.' });
  }
  next();
});

// Serve the frontend (index.html, style.css, app.js) at /.
app.use(express.static(path.resolve(__dirname, '../frontend')));

// ─── Health ────────────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({
    status:  'ok',
    time:    new Date().toISOString(),
    version: '1.0.0',
    port:    config.port,
  });
});

// ─── Scans ─────────────────────────────────────────────────────────────────────

// Create a new scan job.
app.post('/api/scans', (req, res) => {
  const { projectId, targets, policyId, description } = req.body || {};
  if (!projectId) {
    return res.status(400).json({ error: 'projectId is required' });
  }
  if (!Array.isArray(targets) || !targets.length) {
    return res.status(400).json({ error: 'targets must be a non-empty array' });
  }
  const jobId = randomUUID();
  const job = createJob({
    id:          jobId,
    projectId,
    targets,
    policyId:    policyId    || 'policy_normal',
    description: description || `Scan ${targets.length} target(s)`,
  });
  console.log(`[API] New scan job created: ${jobId} for project ${projectId}`);
  res.status(202)
    .location(`/api/scans/${jobId}`)
    .json({ jobId, status: job.status });
});

// List all jobs (optionally filter by projectId).
app.get('/api/scans', (req, res) => {
  const { projectId } = req.query;
  const jobs = listJobs(projectId ? { projectId } : {});
  res.json({ jobs });
});

// Get a single job status.
app.get('/api/scans/:jobId', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  res.json(job);
});

// Get job results (findings + logs).
app.get('/api/scans/:jobId/results', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  const result = getJobResult(req.params.jobId);
  res.json({ jobId: job.id, status: job.status, ...result });
});

// Cancel a queued or running job.
app.post('/api/scans/:jobId/cancel', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  if (['completed', 'failed', 'canceled'].includes(job.status)) {
    return res.status(400).json({ error: `Job already in terminal state: ${job.status}` });
  }
  updateJob(job.id, { status: 'canceled' });
  console.log(`[API] Job ${job.id} canceled.`);
  res.json({ ok: true });
});

// ─── Dorks ─────────────────────────────────────────────────────────────────────
app.use('/api/dorks', dorksRoute);

// ─── Reports ───────────────────────────────────────────────────────────────────
app.use('/api/scans/:jobId', reportsRoute);

// ─── 404 fallback ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `No route: ${req.method} ${req.path}` });
});

// ─── Start ─────────────────────────────────────────────────────────────────────
app.listen(config.port, '0.0.0.0', () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log(`  ║   WebVulnConsole Backend  v1.0.0         ║`);
  console.log(`  ║   Listening on  0.0.0.0:${config.port}            ║`);
  console.log(`  ║   Frontend:     http://127.0.0.1:${config.port}   ║`);
  console.log('  ╚══════════════════════════════════════════╝');
  console.log('');
});

startWorker();
