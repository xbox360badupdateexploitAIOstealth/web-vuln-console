// backend/routes/reportsRoute.js
// GET /api/scans/:jobId/report.html
// GET /api/scans/:jobId/report.md

const express = require('express');
const { getJob } = require('../jobsStore');
const { generateHTMLReport, generateMarkdownReport } = require('../reportGenerator');
const router = express.Router({ mergeParams: true });

router.get('/report.html', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).send('Job not found');
  const html = generateHTMLReport(req.params.jobId);
  res.header('Content-Type', 'text/html');
  res.send(html);
});

router.get('/report.md', (req, res) => {
  const job = getJob(req.params.jobId);
  if (!job) return res.status(404).send('Job not found');
  const md = generateMarkdownReport(req.params.jobId);
  res.header('Content-Type', 'text/plain');
  res.send(md);
});

module.exports = router;
