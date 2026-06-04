// backend/server.js
// Full HTTP API for WebVulnConsole. Runs on Termux (Android) or any Linux VPS.

const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');
const { randomUUID } = require('crypto');
const { config }          = require('./config');
const { createJob, listJobs, getJob, updateJob, getJobResult } = require('./jobsStore');
const { startWorker }     = require('./worker');
const { requestLogger }   = require('./middleware/requestLogger');
const { createRateLimiter } = require('./middleware/rateLimiter');
const dorksRoute          = require('./routes/dorksRoute');
const reportsRoute        = require('./routes/reportsRoute');

const app = express();

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(requestLogger);
app.use(bodyParser.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin',  '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use('/api/', createRateLimiter(120, 60000));
app.use(express.static(path.resolve(__dirname, '../frontend')));

// ─── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString(), version: '1.0.0', port: config.port });
});

// ─── Scans ─────────────────────────────────────────────────────────────────────
app.post('/api/scans', (req, res) => {
  const { projectId, targets, policyId, description } = req.body || {};
  if (!projectId)                              return res.status(400).json({ error: 'projectId is required' });
  if (!Array.isArray(targets) || !targets.length) return res.status(400).json({ error: 'targets must be a non-empty array' });
  const jobId = randomUUID();
  const job   = createJob({ id: jobId, projectId, targets, policyId: policyId || 'policy_normal', description: description || `Scan ${targets.length} target(s)` });
  console.log(`[API] New scan job: ${jobId} project=${projectId} targets=${targets.length}`);
  res.status(202).location(`/api/scans/${jobId}`).json({ jobId, status: job.status });
});

app.get('/api/scans', (req, res) => {
  const jobs = listJobs(req.query.projectId ? { projectId: req.query.projectId } : {});
  res.json({ jobs });
});

app.get('/api/scans/:jobId', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  res.json(job);
});

app.get('/api/scans/:jobId/results', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  res.json({ jobId: job.id, status: job.status, ...getJobResult(req.params.jobId) });
});

app.post('/api/scans/:jobId/cancel', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  if (['completed','failed','canceled'].includes(job.status)) return res.status(400).json({ error: `Job already in terminal state: ${job.status}` });
  updateJob(job.id, { status: 'canceled' });
  console.log(`[API] Job ${job.id} canceled.`);
  res.json({ ok: true });
});

// ─── Dorks / Reports ──────────────────────────────────────────────────────────
app.use('/api/dorks',        dorksRoute);
app.use('/api/scans/:jobId', reportsRoute);

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: `No route: ${req.method} ${req.path}` }));

// ─── Boot ─────────────────────────────────────────────────────────────────────
app.listen(config.port, '0.0.0.0', () => {
  const p = config.port;
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║   ⚡ WebVulnConsole Backend v1.0.0       ║');
  console.log(`  ║   API  → http://0.0.0.0:${p}             ║`);
  console.log(`  ║   UI   → http://127.0.0.1:${p}           ║`);
  console.log('  ║   AUTHORIZED SECURITY TESTING ONLY       ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log('');
});

startWorker();
