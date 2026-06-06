// backend/routes/payloadsRoute.js
// Full REST API for the payload library manager.
// Mounted at: /api/payloads in server.js
//
// ENDPOINTS:
//   GET    /api/payloads/lists                  — list all payload lists
//   POST   /api/payloads/lists                  — create new list
//   GET    /api/payloads/lists/:listId           — get list + payloads
//   PUT    /api/payloads/lists/:listId           — update list metadata
//   DELETE /api/payloads/lists/:listId           — delete list + all payloads
//   POST   /api/payloads/lists/:listId/payloads  — add single payload
//   POST   /api/payloads/lists/:listId/import    — bulk import (SecLists text or URL)
//   GET    /api/payloads/lists/:listId/export    — export as plain text
//   DELETE /api/payloads/:payloadId              — delete single payload

'use strict';

const express  = require('express');
const fetch    = require('node-fetch');
const { lists, payloads, parseSecListsText } = require('../payloadLibrary');

const router = express.Router();

// ─── List management ─────────────────────────────────────────────────────────

// GET /api/payloads/lists
router.get('/lists', (req, res) => {
  res.json({ lists: lists.list() });
});

// POST /api/payloads/lists
router.post('/lists', (req, res) => {
  const { name, category, description } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  const list = lists.create({ name, category: category || 'custom', description: description || '' });
  res.status(201).json(list);
});

// GET /api/payloads/lists/:listId
router.get('/lists/:listId', (req, res) => {
  const list = lists.get(req.params.listId);
  if (!list) return res.status(404).json({ error: 'list not found' });
  const { limit = 500, offset = 0, search = '' } = req.query;
  const items = payloads.list(req.params.listId, {
    limit:  Math.min(parseInt(limit)  || 500, 2000),
    offset: parseInt(offset) || 0,
    search,
  });
  res.json({ list, payloads: items });
});

// PUT /api/payloads/lists/:listId
router.put('/lists/:listId', (req, res) => {
  const list = lists.get(req.params.listId);
  if (!list) return res.status(404).json({ error: 'list not found' });
  const updated = lists.update(req.params.listId, req.body || {});
  res.json(updated);
});

// DELETE /api/payloads/lists/:listId
router.delete('/lists/:listId', (req, res) => {
  const ok = lists.delete(req.params.listId);
  if (!ok) return res.status(404).json({ error: 'list not found' });
  res.json({ ok: true });
});

// ─── Payload management ──────────────────────────────────────────────────────

// POST /api/payloads/lists/:listId/payloads — add single payload
router.post('/lists/:listId/payloads', (req, res) => {
  const list = lists.get(req.params.listId);
  if (!list) return res.status(404).json({ error: 'list not found' });
  const { value, note } = req.body || {};
  if (!value) return res.status(400).json({ error: 'value is required' });
  const p = payloads.add(req.params.listId, value, note || '');
  res.status(201).json(p);
});

// DELETE /api/payloads/:payloadId — delete a single payload
router.delete('/:payloadId', (req, res) => {
  const ok = payloads.delete(req.params.payloadId);
  if (!ok) return res.status(404).json({ error: 'payload not found' });
  res.json({ ok: true });
});

// ─── Bulk import ─────────────────────────────────────────────────────────────

// POST /api/payloads/lists/:listId/import
// Body: { text: "...raw SecLists text..." }   — direct paste
//    OR { url:  "https://..." }               — fetch from URL (SecLists raw GitHub etc)
//    OR { replace: true }                     — optionally wipe existing before import
router.post('/lists/:listId/import', async (req, res) => {
  const list = lists.get(req.params.listId);
  if (!list) return res.status(404).json({ error: 'list not found' });

  const { text, url, replace } = req.body || {};
  if (!text && !url) return res.status(400).json({ error: 'text or url is required' });

  let rawText = text || '';

  if (url) {
    try {
      // Security: only allow https:// GitHub/GitLab/raw URLs
      if (!/^https:\/\/(raw\.githubusercontent\.com|gitlab\.com|gist\.githubusercontent\.com)/i.test(url)) {
        return res.status(400).json({ error: 'URL must be a raw GitHub/GitLab URL (https://raw.githubusercontent.com/...)' });
      }
      const r = await fetch(url, {
        headers: { 'User-Agent': 'WebVulnConsole/2.0 SecLists-Import' },
        timeout: 15000,
      });
      if (!r.ok) return res.status(502).json({ error: `Fetch failed: HTTP ${r.status}` });
      rawText = await r.text();
    } catch (err) {
      return res.status(502).json({ error: `Fetch error: ${err.message}` });
    }
  }

  if (replace) {
    payloads.deleteByList(req.params.listId);
  }

  const parsed = parseSecListsText(rawText);
  if (!parsed.length) return res.status(400).json({ error: 'No valid payloads found in input' });

  // Cap at 10,000 per import to protect DB
  const capped  = parsed.slice(0, 10000);
  const added   = payloads.bulkAdd(req.params.listId, capped);

  res.json({
    ok:      true,
    parsed:  parsed.length,
    capped:  capped.length,
    added,
    listId:  req.params.listId,
  });
});

// ─── Export ──────────────────────────────────────────────────────────────────

// GET /api/payloads/lists/:listId/export — plain text (one per line, SecLists compatible)
router.get('/lists/:listId/export', (req, res) => {
  const list = lists.get(req.params.listId);
  if (!list) return res.status(404).json({ error: 'list not found' });
  const items = payloads.list(req.params.listId, { limit: 50000 });
  const filename = list.name.replace(/[^a-zA-Z0-9_-]/g, '_') + '.txt';
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(items.map(p => p.value).join('\n'));
});

module.exports = router;
