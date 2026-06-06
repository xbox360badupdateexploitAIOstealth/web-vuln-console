// backend/server.js
// Full HTTP API for WebVulnConsole. Runs on Termux (Android) or any Linux VPS.
// v2.1.0 — payload library manager added (TODO-26)

'use strict';

const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');
const { randomUUID } = require('crypto');

const { config }              = require('./config');
const { projects, targets, auditLog } = require('./db');
const { createJob, listJobs, getJob, updateJob, getJobResult } = require('./jobsStore');
const { startWorker }         = require('./worker');
const { requestLogger }       = require('./middleware/requestLogger');
const { createRateLimiter }   = require('./middleware/rateLimiter');
const dorksRoute              = require('./routes/dorksRoute');
const reportsRoute            = require('./routes/reportsRoute');
const payloadsRoute           = require('./routes/payloadsRoute');

const app = express();

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(requestLogger);
app.use(bodyParser.json({ limit: '2mb' }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin',  '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use('/api/', createRateLimiter(120, 60000));
app.use(express.static(path.resolve(__dirname, '../frontend')));

// ─── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString(), version: '2.1.0', port: config.port });
});

// ─── Global Stats ─────────────────────────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  try {
    const { findings: dbFindings } = require('./db');
    const allProjects = projects.list();
    const allJobs     = listJobs({});
    const totalTargets = allProjects.reduce((n, p) => n + (targets.listByProject(p.id) || []).length, 0);
    const running  = allJobs.filter(j => j.status === 'running').length;
    const queued   = allJobs.filter(j => j.status === 'queued').length;
    const completed= allJobs.filter(j => j.status === 'completed').length;
    const failed   = allJobs.filter(j => j.status === 'failed').length;
    let totalFindings = 0;
    const sevSummary  = { critical:0, high:0, medium:0, low:0, info:0 };
    allProjects.forEach(p => {
      const summary = dbFindings.severitySummary(p.id);
      Object.keys(sevSummary).forEach(k => { sevSummary[k] += (summary[k] || 0); });
      totalFindings += Object.values(summary).reduce((a, b) => a + b, 0);
    });
    res.json({
      projects:  allProjects.length,
      targets:   totalTargets,
      jobs:      { total: allJobs.length, running, queued, completed, failed },
      findings:  { total: totalFindings, ...sevSummary },
    });
  } catch (err) {
    res.status(500).json({ error: String(err.message) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PROJECTS
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/projects', (req, res) => {
  const list = projects.list().map(p => ({ ...p, ...projects.stats(p.id) }));
  res.json({ projects: list });
});

app.post('/api/projects', (req, res) => {
  const { name, client, auth_note, contact, scope, status } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  const project = projects.create({
    id: randomUUID(), name,
    client:    client    || '',
    auth_note: auth_note || '',
    contact:   contact   || '',
    scope:     scope     || '',
    status:    status    || 'active',
  });
  auditLog.write('project.create', 'project', project.id, req.ip, name);
  res.status(201).json(project);
});

app.get('/api/projects/:id', (req, res) => {
  const p = projects.get(req.params.id);
  if (!p) return res.status(404).json({ error: 'project not found' });
  res.json({ ...p, ...projects.stats(p.id) });
});

app.put('/api/projects/:id', (req, res) => {
  const p = projects.get(req.params.id);
  if (!p) return res.status(404).json({ error: 'project not found' });
  const updated = projects.update(req.params.id, req.body || {});
  auditLog.write('project.update', 'project', req.params.id, req.ip, JSON.stringify(req.body));
  res.json(updated);
});

app.patch('/api/projects/:id', (req, res) => {
  const p = projects.get(req.params.id);
  if (!p) return res.status(404).json({ error: 'project not found' });
  const updated = projects.update(req.params.id, req.body || {});
  auditLog.write('project.patch', 'project', req.params.id, req.ip, JSON.stringify(req.body));
  res.json(updated);
});

app.delete('/api/projects/:id', (req, res) => {
  const ok = projects.delete(req.params.id);
  if (!ok) return res.status(404).json({ error: 'project not found' });
  auditLog.write('project.delete', 'project', req.params.id, req.ip, '');
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// TARGETS
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/projects/:id/targets', (req, res) => {
  const p = projects.get(req.params.id);
  if (!p) return res.status(404).json({ error: 'project not found' });
  res.json({ targets: targets.listByProject(req.params.id) });
});

app.post('/api/projects/:id/targets', (req, res) => {
  const p = projects.get(req.params.id);
  if (!p) return res.status(404).json({ error: 'project not found' });
  const { host, type, notes, env } = req.body || {};
  if (!host) return res.status(400).json({ error: 'host is required' });
  const target = targets.create({
    id: randomUUID(), project_id: req.params.id,
    host, type: type || 'website', notes: notes || '', env: env || 'prod',
  });
  auditLog.write('target.create', 'target', target.id, req.ip, host);
  res.status(201).json(target);
});

app.post('/api/projects/:id/targets/bulk', (req, res) => {
  const p = projects.get(req.params.id);
  if (!p) return res.status(404).json({ error: 'project not found' });
  const { hosts } = req.body || {};
  if (!Array.isArray(hosts) || !hosts.length) return res.status(400).json({ error: 'hosts array required' });
  const rows = hosts.map(h => ({
    id: randomUUID(), project_id: req.params.id,
    host: h.host || h, type: h.type || 'website',
    notes: h.notes || '', env: h.env || 'prod',
  }));
  const count = targets.bulkCreate(rows);
  auditLog.write('target.bulk_create', 'project', req.params.id, req.ip, `${count} hosts`);
  res.status(201).json({ added: count });
});

app.delete('/api/targets/:targetId', (req, res) => {
  const ok = targets.delete(req.params.targetId);
  if (!ok) return res.status(404).json({ error: 'target not found' });
  auditLog.write('target.delete', 'target', req.params.targetId, req.ip, '');
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// SCANS
// ─────────────────────────────────────────────────────────────────────────────

app.post('/api/scans', (req, res) => {
  const { projectId, targets: scanTargets, policyId, description } = req.body || {};
  if (!projectId) return res.status(400).json({ error: 'projectId is required' });
  if (!Array.isArray(scanTargets) || !scanTargets.length)
    return res.status(400).json({ error: 'targets must be a non-empty array' });
  const jobId = randomUUID();
  const job   = createJob({
    id: jobId, projectId,
    targets:     scanTargets,
    policyId:    policyId    || 'policy_normal',
    description: description || `Scan ${scanTargets.length} target(s)`,
  });
  auditLog.write('scan.create', 'job', jobId, req.ip, `project=${projectId} targets=${scanTargets.length}`);
  res.status(202).location(`/api/scans/${jobId}`).json({ jobId, status: job.status });
});

app.get('/api/scans', (req, res) => {
  const filter = req.query.projectId ? { projectId: req.query.projectId } : {};
  const jobs   = listJobs(filter);
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
  if (['completed', 'failed', 'canceled'].includes(job.status))
    return res.status(400).json({ error: `Job already terminal: ${job.status}` });
  updateJob(job.id, { status: 'canceled' });
  auditLog.write('scan.cancel', 'job', job.id, req.ip, '');
  res.json({ ok: true });
});

app.post('/api/scans/:jobId/retry', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  if (!['failed', 'canceled'].includes(job.status))
    return res.status(400).json({ error: `Can only retry failed/canceled jobs (current: ${job.status})` });
  const newId  = randomUUID();
  const newJob = createJob({
    id: newId,
    projectId:   job.projectId,
    targets:     job.targets,
    policyId:    job.policyId    || 'policy_normal',
    description: `[Retry] ${job.description || ''}`.trim(),
  });
  auditLog.write('scan.retry', 'job', newId, req.ip, `original=${job.id}`);
  res.status(202).json({ jobId: newId, status: newJob.status, originalJobId: job.id });
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDINGS
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/projects/:id/findings', (req, res) => {
  const { findings: dbFindings } = require('./db');
  const { severity, status, category, limit, offset } = req.query;
  const list    = dbFindings.listByProject(req.params.id, { severity, status, category, limit, offset });
  const summary = dbFindings.severitySummary(req.params.id);
  res.json({ findings: list, summary, total: list.length });
});

app.put('/api/findings/:id/status', (req, res) => {
  const { findings: dbFindings } = require('./db');
  const { status } = req.body || {};
  if (!status) return res.status(400).json({ error: 'status required' });
  const ok = dbFindings.updateStatus(req.params.id, status);
  if (!ok) return res.status(404).json({ error: 'finding not found' });
  if (status === 'false_positive') dbFindings.markFalsePositive(req.params.id, 1);
  res.json({ ok: true });
});

// ─── Audit log ────────────────────────────────────────────────────────────────
app.get('/api/audit', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '100'), 500);
  res.json({ log: auditLog.recent(limit) });
});

// ─── Sub-routers ─────────────────────────────────────────────────────────────
app.use('/api/dorks',        dorksRoute);
app.use('/api/scans/:jobId', reportsRoute);
app.use('/api/payloads',     payloadsRoute);

// ─── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: `No route: ${req.method} ${req.path}` }));

// ─── Global error handler ─────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  res.status(500).json({ error: 'Internal server error', detail: err.message });
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
app.listen(config.port, '0.0.0.0', () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║   ⚡ WebVulnConsole Backend v2.1.0       ║');
  console.log(`  ║   API  → http://0.0.0.0:${config.port}             ║`);
  console.log(`  ║   UI   → http://127.0.0.1:${config.port}           ║`);
  console.log('  ║   DB   → SQLite (backend/data/scanner.db)║');
  console.log('  ║   AUTHORIZED SECURITY TESTING ONLY       ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log('');
});

startWorker();
