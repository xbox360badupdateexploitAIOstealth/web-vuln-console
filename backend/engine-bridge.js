// backend/engine-bridge.js
// Full Node.js scan engine. No CORS constraints, runs on Termux or VPS.
// Uses retry, normalize, and severity utils.

const fetch           = require('node-fetch');
const cheerio         = require('cheerio');
const { randomUUID }  = require('crypto');
const { withRetry }   = require('./utils/retry');
const { normalizeTargets } = require('./utils/normalize');

// ─── HTTP helper ──────────────────────────────────────────────────────────────

async function httpGet(url, opts = {}) {
  return withRetry(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs || 12000);
    try {
      const res = await fetch(url, {
        method:  'GET',
        signal:  controller.signal,
        redirect: 'follow',
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebVulnConsole/1.0; Security-Audit)' },
      });
      const body = await res.text();
      const headers = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      return { status: res.status, headers, body, error: null };
    } catch (err) {
      // On abort (timeout) don't retry.
      if (err.name === 'AbortError') return { status: 0, headers: {}, body: '', error: 'timeout' };
      throw err; // Let withRetry handle network errors.
    } finally {
      clearTimeout(timer);
    }
  }, { maxAttempts: 3, baseDelayMs: 600, maxDelayMs: 6000 });
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ─── Sensitive path rules ─────────────────────────────────────────────────────

const SENSITIVE_PATHS = [
  // ENV files
  { path: '/.env',                severity: 'critical', category: 'ENV_FILE',    match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.local',          severity: 'critical', category: 'ENV_FILE',    match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.backup',         severity: 'critical', category: 'ENV_FILE',    match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.production',     severity: 'critical', category: 'ENV_FILE',    match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.staging',        severity: 'critical', category: 'ENV_FILE',    match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.old',            severity: 'high',     category: 'ENV_FILE',    match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.bak',            severity: 'high',     category: 'ENV_FILE',    match: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  // Git / VCS
  { path: '/.git/HEAD',           severity: 'high',     category: 'GIT_REPO',    match: /^ref: refs\/|^[0-9a-f]{40}/m },
  { path: '/.git/config',         severity: 'high',     category: 'GIT_REPO',    match: /\[core\]/i },
  { path: '/.git/COMMIT_EDITMSG', severity: 'medium',   category: 'GIT_REPO',    match: null },
  { path: '/.svn/entries',        severity: 'medium',   category: 'SVN_REPO',    match: /https?:\/\//i },
  { path: '/.hg/hgrc',            severity: 'medium',   category: 'HG_REPO',     match: null },
  // Config files
  { path: '/config.php',          severity: 'high',     category: 'CONFIG_FILE', match: /(?:DB_|password|hostname|username)/i },
  { path: '/config.php.bak',      severity: 'critical', category: 'CONFIG_FILE', match: null },
  { path: '/config.php.old',      severity: 'critical', category: 'CONFIG_FILE', match: null },
  { path: '/wp-config.php',       severity: 'critical', category: 'CONFIG_FILE', match: /DB_PASSWORD/i },
  { path: '/wp-config.php.bak',   severity: 'critical', category: 'CONFIG_FILE', match: null },
  { path: '/config.json',         severity: 'high',     category: 'CONFIG_FILE', match: /(?:password|secret|token|apiKey)/i },
  { path: '/settings.json',       severity: 'medium',   category: 'CONFIG_FILE', match: /(?:password|secret|token)/i },
  { path: '/database.yml',        severity: 'high',     category: 'CONFIG_FILE', match: /(?:password|username|database)/i },
  { path: '/application.yml',     severity: 'high',     category: 'CONFIG_FILE', match: /(?:password|secret|datasource)/i },
  { path: '/appsettings.json',    severity: 'high',     category: 'CONFIG_FILE', match: /(?:Password|Secret|ConnectionString)/i },
  // Backups / dumps
  { path: '/backup.sql',          severity: 'critical', category: 'DB_DUMP',     match: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/db-backup.sql',       severity: 'critical', category: 'DB_DUMP',     match: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/database.sql',        severity: 'critical', category: 'DB_DUMP',     match: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/dump.sql',            severity: 'critical', category: 'DB_DUMP',     match: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/backup.zip',          severity: 'high',     category: 'BACKUP',      match: null },
  { path: '/backup.tar.gz',       severity: 'high',     category: 'BACKUP',      match: null },
  { path: '/site-backup.zip',     severity: 'high',     category: 'BACKUP',      match: null },
  { path: '/www.zip',             severity: 'high',     category: 'BACKUP',      match: null },
  // Recon / info
  { path: '/robots.txt',          severity: 'info',     category: 'RECON',       match: null },
  { path: '/sitemap.xml',         severity: 'info',     category: 'RECON',       match: null },
  { path: '/.well-known/security.txt', severity: 'info', category: 'RECON',     match: null },
  // Debug / admin
  { path: '/phpinfo.php',         severity: 'high',     category: 'DEBUG',       match: /PHP Version/i },
  { path: '/debug.php',           severity: 'high',     category: 'DEBUG',       match: null },
  { path: '/test.php',            severity: 'medium',   category: 'DEBUG',       match: null },
  { path: '/info.php',            severity: 'high',     category: 'DEBUG',       match: /PHP Version/i },
  { path: '/admin/',              severity: 'medium',   category: 'ADMIN',       match: null },
  { path: '/admin/login',         severity: 'medium',   category: 'ADMIN',       match: null },
  { path: '/private/',            severity: 'medium',   category: 'ADMIN',       match: null },
  { path: '/staging/',            severity: 'low',      category: 'ADMIN',       match: null },
  { path: '/dev/',                severity: 'low',      category: 'ADMIN',       match: null },
  // Leaked files
  { path: '/.DS_Store',           severity: 'medium',   category: 'LEAK',        match: null },
  { path: '/crossdomain.xml',     severity: 'low',      category: 'POLICY',      match: /allow-access-from/i },
  { path: '/clientaccesspolicy.xml', severity: 'low',   category: 'POLICY',      match: null },
  // AWS / cloud metadata
  { path: '/latest/meta-data/',   severity: 'critical', category: 'CLOUD_META',  match: null },
];

const SQLI_PAYLOADS = [
  "'",
  "1' OR '1'='1",
  "1 AND 1=2--",
  "' OR 1=1--",
  "admin'--",
];

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "'><svg/onload=alert(1)>",
];

const SQLI_ERRORS = /sql syntax|mysql_fetch|pg_query|ORA-[0-9]{4}|sqlite_|unclosed quotation|syntax error in SQL|PDOException|SQLSTATE/i;

// ─── Crawler ──────────────────────────────────────────────────────────────────

function extractForms($, baseUrl) {
  const forms = [];
  $('form').each((_, el) => {
    let actionUrl;
    try { actionUrl = new URL($(el).attr('action') || '', baseUrl).href; } catch { actionUrl = baseUrl; }
    const method = ($(el).attr('method') || 'get').toLowerCase();
    const inputs = [];
    $(el).find('input[name],textarea[name],select[name]').each((__, inp) => inputs.push($(inp).attr('name')));
    if (inputs.length) forms.push({ actionUrl, method, inputs });
  });
  return forms;
}

// ─── Single target scan ───────────────────────────────────────────────────────

async function scanTarget(origin, opts = {}) {
  const findings = [];
  const logs     = [];
  const log = (msg) => { logs.push(msg); process.stdout.write(msg + '\n'); };
  const delay = opts.delayMs || 350;

  log(`[TARGET] Scanning: ${origin}`);

  // 1. Sensitive path probing.
  for (const rule of SENSITIVE_PATHS) {
    const url = `${origin}${rule.path}`;
    log(`[PROBE] ${url}`);
    const r = await httpGet(url, { timeoutMs: 10000 });
    await sleep(delay);

    if (r.status === 200) {
      const bodyMatched = !rule.match || rule.match.test(r.body);
      if (bodyMatched) {
        log(`[${rule.severity.toUpperCase()}] ${url} (${rule.category})`);
        findings.push({
          id:          randomUUID(),
          severity:    rule.severity,
          category:    rule.category,
          url,
          title:       `${rule.category.replace(/_/g, ' ')}: ${rule.path}`,
          statusCode:  r.status,
          bodySnippet: r.body.slice(0, 500),
          contentType: r.headers['content-type'] || '',
          contentLength: r.headers['content-length'] || r.body.length,
        });
      }
    } else if (r.status === 403) {
      // 403 on sensitive path = resource likely exists but access-controlled.
      log(`[INFO] 403 on ${url} (may exist but access-restricted)`);
      findings.push({
        id:         randomUUID(),
        severity:   'info',
        category:   rule.category,
        url,
        title:      `Access Restricted (403): ${rule.path}`,
        statusCode: 403,
        bodySnippet: '',
        note: 'Resource returned 403. May exist but is protected. Investigate further.',
      });
    }
  }

  // 2. Crawl root and extract forms for injection testing.
  log(`[CRAWL] Fetching root: ${origin}`);
  const rootRes = await httpGet(origin);
  let forms = [];
  if (rootRes.status === 200) {
    try {
      const $ = cheerio.load(rootRes.body);
      forms = extractForms($, origin);
      log(`[CRAWL] Found ${forms.length} form(s)`);
      // Check for verbose error/debug clues in root response.
      if (/stack trace|at Object\.|traceback \(|exception in|debug mode/i.test(rootRes.body)) {
        log(`[WARN] Debug/stack trace detected in root page response!`);
        findings.push({
          id:          randomUUID(),
          severity:    'medium',
          category:    'DEBUG_LEAK',
          url:         origin,
          title:       'Possible debug information leaked in root page',
          statusCode:  rootRes.status,
          bodySnippet: rootRes.body.slice(0, 500),
        });
      }
    } catch (e) {
      log(`[CRAWL ERROR] ${e}`);
    }
  }

  // 3. Injection probes on discovered forms.
  for (const form of forms.slice(0, 5)) {
    for (const inputName of form.inputs.slice(0, 4)) {
      // SQLi probes.
      for (const payload of SQLI_PAYLOADS.slice(0, 3)) {
        const url = `${form.actionUrl}?${inputName}=${encodeURIComponent(payload)}`;
        log(`[SQLI] ${url}`);
        const r = await httpGet(url, { timeoutMs: 8000 });
        await sleep(delay);
        if (r.status >= 500 || SQLI_ERRORS.test(r.body)) {
          log(`[CRITICAL] SQLi hit: ${url}`);
          findings.push({
            id:          randomUUID(),
            severity:    'critical',
            category:    'SQLI',
            url,
            title:       `Possible SQL Injection: ${form.actionUrl} [param: ${inputName}]`,
            statusCode:  r.status,
            bodySnippet: r.body.slice(0, 500),
            payload,
          });
        }
      }
      // XSS probes.
      for (const payload of XSS_PAYLOADS.slice(0, 2)) {
        const url = `${form.actionUrl}?${inputName}=${encodeURIComponent(payload)}`;
        log(`[XSS] ${url}`);
        const r = await httpGet(url, { timeoutMs: 8000 });
        await sleep(delay);
        if (r.status === 200 && r.body.includes(payload)) {
          log(`[HIGH] Reflected XSS hit: ${url}`);
          findings.push({
            id:          randomUUID(),
            severity:    'high',
            category:    'XSS',
            url,
            title:       `Reflected XSS: ${form.actionUrl} [param: ${inputName}]`,
            statusCode:  r.status,
            bodySnippet: r.body.slice(0, 500),
            payload,
          });
        }
      }
    }
  }

  // 4. Error stimulus – send junk paths to provoke verbose errors.
  const randPath = `/wvc-probe-${Math.random().toString(36).slice(2)}`;
  log(`[ERROR_PROBE] Sending invalid path: ${origin}${randPath}`);
  const errRes = await httpGet(`${origin}${randPath}?id='"<>`);
  if (errRes.status >= 400) {
    const body = errRes.body || '';
    const looksVerbose = /stack trace|traceback|exception|at Object\.|at Function\.|app\.js:[0-9]|vendor\/laravel|Symfony|Django|Rails|Whoops/i.test(body);
    if (looksVerbose) {
      log(`[MEDIUM] Verbose error page detected at ${origin}`);
      findings.push({
        id:          randomUUID(),
        severity:    'medium',
        category:    'ERROR_PAGE',
        url:         `${origin}${randPath}`,
        title:       'Verbose error page leaks framework/path info',
        statusCode:  errRes.status,
        bodySnippet: body.slice(0, 500),
      });
    }
  }

  log(`[TARGET] Done: ${origin}. Findings: ${findings.length}`);
  return { findings, logs };
}

// ─── Public API ───────────────────────────────────────────────────────────────

async function runScanJobFromJobRecord(job, opts = {}) {
  const allFindings = [];
  const allLogs     = [];
  const maxParallel = opts.maxParallelTargetsPerJob || 2;

  const rawTargets = Array.isArray(job.targets) ? job.targets : [];
  const { valid, invalid } = normalizeTargets(rawTargets);

  for (const inv of invalid) {
    allLogs.push(`[SKIP] Invalid/unresolvable target: ${inv}`);
  }

  allLogs.push(`[JOB] Scanning ${valid.length} valid target(s) (${invalid.length} skipped).`);

  // Process in batches of maxParallel.
  for (let i = 0; i < valid.length; i += maxParallel) {
    const batch = valid.slice(i, i + maxParallel);
    const results = await Promise.all(
      batch.map((origin) => scanTarget(origin, { delayMs: 350 }))
    );
    for (const r of results) {
      allFindings.push(...r.findings);
      allLogs.push(...r.logs);
    }
  }

  return { findings: allFindings, evidences: [], logs: allLogs };
}

module.exports = { runScanJobFromJobRecord };
