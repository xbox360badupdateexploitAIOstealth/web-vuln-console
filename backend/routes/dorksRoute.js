// backend/routes/dorksRoute.js
// GET /api/dorks?domain=example.com

const express = require('express');
const { generateDorks } = require('../dorkEngine');
const router = express.Router();

router.get('/', (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain query param required' });
  const dorks = generateDorks(domain);
  res.json(dorks);
});

module.exports = router;
