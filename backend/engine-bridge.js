// backend/engine-bridge.js
// Node-side engine bridge. Runs the scan engine logic using node-fetch and cheerio.
// This is the Node equivalent of what the browser engine does, but with no CORS constraints.

const fetch = require('node-fetch');
const cheerio = require('cheerio');
const { randomUUID } = require('crypto');

// ─── Utilities ────────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

async function httpGet(url, opts = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs || 12000);
  try {
    const res = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebVulnConsole/1.0)' },
    });
    const body = await res.text();
    const headers = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers, body };
  } catch (err) {
    return { status: 0, headers: {}, body: '', error: String(err) };
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeHost(raw) {
  try {
    const u = new URL(raw.startsWith('http') ? raw : `https://${raw}`);
    return u.origin;
  } catch {
    return null;
  }
}

function extractLinks($, baseUrl) {
  const links = new Set();
  $('a[href]').each((_, el) => {
    try {
      const href = $(el).attr('href');
      if (!href) return;
      const abs = new URL(href, baseUrl).href;
      if (abs.startsWith(baseUrl)) links.add(abs);
    } catch {}
  });
  return [...links];
}

function extractForms($, baseUrl) {
  const forms = [];
  $('form').each((_, el) => {
    const action = $(el).attr('action') || '';
    let actionUrl;
    try { actionUrl = new URL(action, baseUrl).href; } catch { actionUrl = baseUrl; }
    const method = ($(el).attr('method') || 'get').toLowerCase();
    const inputs = [];
    $(el).find('input[name],textarea[name],select[name]').each((__, inp) => {
      inputs.push($(inp).attr('name'));
    });
    if (inputs.length) forms.push({ actionUrl, method, inputs });
  });
  return forms;
}

// ─── Rules ────────────────────────────────────────────────────────────────────

const SENSITIVE_PATHS = [
  { path: '/.env',            severity: 'critical', category: 'ENV_FILE',   match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.local',      severity: 'critical', category: 'ENV_FILE',   match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.backup',     severity: 'critical', category: 'ENV_FILE',   match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.production', severity: 'critical', category: 'ENV_FILE',   match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.old',        severity: 'high',     category: 'ENV_FILE',   match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.git/HEAD',       severity: 'high',     category: 'GIT_REPO',   match: /^ref: refs\/|^[0-9a-f]{40}/m },
  { path: '/.git/config',     severity: 'high',     category: 'GIT_REPO',   match: /\[core\]/i },
  { path: '/.svn/entries',    severity: 'medium',   category: 'SVN_REPO',   match: /https?:\/\//i },
  { path: '/config.php',      severity: 'high',     category: 'CONFIG_FILE', match: /(?:DB_|password|hostname|username)/i },
  { path: '/config.php.bak',  severity: 'critical', category: 'CONFIG_FILE', match: /(?:DB_|password|hostname|username)/i },
  { path: '/wp-config.php',   severity: 'critical', category: 'CONFIG_FILE', match: /DB_PASSWORD/i },
  { path: '/config.json',     severity: 'high',     category: 'CONFIG_FILE', match: /(?:password|secret|token|apiKey)/i },
  { path: '/settings.json',   severity: 'medium',   category: 'CONFIG_FILE', match: /(?:password|secret|token)/i },
  { path: '/database.yml',    severity: 'high',     category: 'CONFIG_FILE', match: /(?:password|username|database)/i },
  { path: '/backup.sql',      severity: 'critical', category: 'DB_DUMP',    match: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/db-backup.sql',   severity: 'critical', category: 'DB_DUMP',    match: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/backup.zip',      severity: 'high',     category: 'BACKUP',     match: null },
  { path: '/backup.tar.gz',   severity: 'high',     category: 'BACKUP',     match: null },
  { path: '/robots.txt',      severity: 'info',     category: 'RECON',      match: null },
  { path: '/sitemap.xml',     severity: 'info',     category: 'RECON',      match: null },
  { path: '/phpinfo.php',     severity: 'high',     category: 'DEBUG',      match: /PHP Version/i },
  { path: '/debug.php',       severity: 'high',     category: 'DEBUG',      match: /debug/i },
  { path: '/admin/',          severity: 'medium',   category: 'ADMIN',      match: null },
  { path: '/private/',        severity: 'medium',   category: 'ADMIN',      match: null },
  { path: '/staging/',        severity: 'low',      category: 'ADMIN',      match: null },
  { path: '/.DS_Store',       severity: 'medium',   category: 'LEAK',       match: null },
  { path: '/crossdomain.xml', severity: 'low',      category: 'POLICY',     match: /allow-access-from/i },
];

const SQLI_PAYLOADS = ["'", "1' OR '1'='1", "1 AND 1=2--", "1; DROP TABLE users--"];
const XSS_PAYLOADS  = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'><svg/onload=alert(1)>"];
const SQLI_ERRORS   = /sql syntax|mysql_fetch|pg_query|ORA-[0-9]|sqlite_|unclosed quotation|syntax error in SQL/i;

// ─── Engine ───────────────────────────────────────────────────────────────────

async function scanTarget(origin, opts = {}) {
  const findings = [];
  const logs     = [];
  const log = (msg) => { logs.push(msg); process.stdout.write(msg + '\n'); };

  // 1. Passive path probing.
  for (const rule of SENSITIVE_PATHS) {
    const url = `${origin}${rule.path}`;
    log(`[PROBE] ${url}`);
    const r = await httpGet(url, { timeoutMs: 10000 });
    await sleep(opts.delayMs || 300);
    if (r.status === 200) {
      const matched = !rule.match || rule.match.test(r.body);
      if (matched || r.status === 200) {
        log(`[HIT] ${url} (${r.status} / ${rule.category})`);
        findings.push({
          id: randomUUID(),
          severity: rule.severity,
          category: rule.category,
          url,
          title: `${rule.category.replace('_', ' ')}: ${rule.path}`,
          statusCode: r.status,
          bodySnippet: r.body.slice(0, 400),
        });
      }
    }
  }

  // 2. Crawl root page, extract forms.
  const rootRes = await httpGet(origin);
  let forms = [];
  if (rootRes.status === 200) {
    try {
      const $ = cheerio.load(rootRes.body);
      forms = extractForms($, origin);
      log(`[CRAWL] Found ${forms.length} form(s) on ${origin}`);
    } catch (e) {
      log(`[CRAWL ERROR] ${e}`);
    }
  }

  // 3. Active injection probes on each form.
  for (const form of forms.slice(0, 5)) {
    for (const inputName of form.inputs.slice(0, 3)) {
      // SQLi
      for (const payload of SQLI_PAYLOADS.slice(0, 2)) {
        const url = `${form.actionUrl}?${inputName}=${encodeURIComponent(payload)}`;
        log(`[SQLI] ${url}`);
        const r = await httpGet(url, { timeoutMs: 8000 });
        await sleep(opts.delayMs || 400);
        if (r.status >= 500 || SQLI_ERRORS.test(r.body)) {
          log(`[SQLI HIT] ${url}`);
          findings.push({
            id: randomUUID(),
            severity: 'critical',
            category: 'SQLI',
            url,
            title: `Possible SQL Injection: ${form.actionUrl} [${inputName}]`,
            statusCode: r.status,
            bodySnippet: r.body.slice(0, 400),
          });
        }
      }
      // XSS
      for (const payload of XSS_PAYLOADS.slice(0, 1)) {
        const url = `${form.actionUrl}?${inputName}=${encodeURIComponent(payload)}`;
        log(`[XSS] ${url}`);
        const r = await httpGet(url, { timeoutMs: 8000 });
        await sleep(opts.delayMs || 400);
        if (r.status === 200 && r.body.includes(payload)) {
          log(`[XSS HIT] ${url}`);
          findings.push({
            id: randomUUID(),
            severity: 'high',
            category: 'XSS',
            url,
            title: `Reflected XSS: ${form.actionUrl} [${inputName}]`,
            statusCode: r.status,
            bodySnippet: r.body.slice(0, 400),
          });
        }
      }
    }
  }

  return { findings, logs };
}

// ─── Public API ───────────────────────────────────────────────────────────────

async function runScanJobFromJobRecord(job, opts = {}) {
  const allFindings = [];
  const allLogs     = [];

  const targets = Array.isArray(job.targets) ? job.targets : [];
  const maxParallel = opts.maxParallelTargetsPerJob || 2;

  // Batch targets.
  for (let i = 0; i < targets.length; i += maxParallel) {
    const batch = targets.slice(i, i + maxParallel);
    const results = await Promise.all(
      batch.map((t) => {
        const origin = normalizeHost(typeof t === 'string' ? t : t.host || t.url || '');
        if (!origin) return Promise.resolve({ findings: [], logs: [`[SKIP] Invalid target: ${JSON.stringify(t)}`] });
        return scanTarget(origin, { delayMs: 300 });
      })
    );
    for (const r of results) {
      allFindings.push(...r.findings);
      allLogs.push(...r.logs);
    }
  }

  return { findings: allFindings, evidences: [], logs: allLogs };
}

module.exports = { runScanJobFromJobRecord };
