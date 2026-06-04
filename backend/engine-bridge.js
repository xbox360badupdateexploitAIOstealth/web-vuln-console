// backend/engine-bridge.js
// Full Node.js scan engine. Authorized security testing only.
// Modules: sensitive path probing, form injection (SQLi/XSS), error stimulus,
//          header analysis, CORS check, redirect chain, WordPress detection,
//          path traversal probes, open redirect probes.

'use strict';

const fetch          = require('node-fetch');
const cheerio        = require('cheerio');
const { randomUUID } = require('crypto');
const { withRetry }  = require('./utils/retry');
const { normalizeTargets } = require('./utils/normalize');

// ─── HTTP helper ──────────────────────────────────────────────────────────────

async function httpGet(url, opts = {}) {
  return withRetry(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs || 12000);
    try {
      const res = await fetch(url, {
        method:   'GET',
        signal:   controller.signal,
        redirect: opts.followRedirects === false ? 'manual' : 'follow',
        headers:  {
          'User-Agent': 'Mozilla/5.0 (compatible; WebVulnConsole/1.0; Security-Audit)',
          ...(opts.headers || {}),
        },
      });
      const body = await res.text();
      const headers = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      return { status: res.status, headers, body, url: res.url, error: null };
    } catch (err) {
      if (err.name === 'AbortError') return { status: 0, headers: {}, body: '', url, error: 'timeout' };
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }, { maxAttempts: 3, baseDelayMs: 600, maxDelayMs: 6000 });
}

async function httpHead(url, opts = {}) {
  return withRetry(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs || 8000);
    try {
      const res = await fetch(url, {
        method:   'HEAD',
        signal:   controller.signal,
        redirect: 'follow',
        headers:  { 'User-Agent': 'Mozilla/5.0 (compatible; WebVulnConsole/1.0; Security-Audit)' },
      });
      const headers = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      return { status: res.status, headers, url: res.url, error: null };
    } catch (err) {
      if (err.name === 'AbortError') return { status: 0, headers: {}, url, error: 'timeout' };
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }, { maxAttempts: 2, baseDelayMs: 400, maxDelayMs: 3000 });
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ─── Sensitive path rules ─────────────────────────────────────────────────────

const SENSITIVE_PATHS = [
  // ENV files
  { path: '/.env',                     sev: 'critical', cat: 'ENV_FILE',    rx: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.local',               sev: 'critical', cat: 'ENV_FILE',    rx: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.backup',              sev: 'critical', cat: 'ENV_FILE',    rx: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.production',          sev: 'critical', cat: 'ENV_FILE',    rx: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.staging',             sev: 'critical', cat: 'ENV_FILE',    rx: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.development',         sev: 'critical', cat: 'ENV_FILE',    rx: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.test',                sev: 'high',     cat: 'ENV_FILE',    rx: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.old',                 sev: 'high',     cat: 'ENV_FILE',    rx: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/.env.bak',                 sev: 'high',     cat: 'ENV_FILE',    rx: /(?:DB_|API_|AWS_|SECRET|PASSWORD|TOKEN|KEY)/i },
  { path: '/env.txt',                  sev: 'high',     cat: 'ENV_FILE',    rx: /(?:DB_|SECRET|PASSWORD|TOKEN|KEY)/i },
  // Git / VCS
  { path: '/.git/HEAD',                sev: 'high',     cat: 'GIT_REPO',    rx: /^ref: refs\/|^[0-9a-f]{40}/m },
  { path: '/.git/config',              sev: 'high',     cat: 'GIT_REPO',    rx: /\[core\]/i },
  { path: '/.git/COMMIT_EDITMSG',      sev: 'medium',   cat: 'GIT_REPO',    rx: null },
  { path: '/.git/logs/HEAD',           sev: 'medium',   cat: 'GIT_REPO',    rx: /commit/i },
  { path: '/.git/packed-refs',         sev: 'medium',   cat: 'GIT_REPO',    rx: /refs\/heads/i },
  { path: '/.svn/entries',             sev: 'medium',   cat: 'SVN_REPO',    rx: /https?:\/\//i },
  { path: '/.hg/hgrc',                 sev: 'medium',   cat: 'HG_REPO',     rx: null },
  // Config files
  { path: '/config.php',               sev: 'high',     cat: 'CONFIG_FILE', rx: /(?:DB_|password|hostname|username)/i },
  { path: '/config.php.bak',           sev: 'critical', cat: 'CONFIG_FILE', rx: null },
  { path: '/config.php.old',           sev: 'critical', cat: 'CONFIG_FILE', rx: null },
  { path: '/wp-config.php',            sev: 'critical', cat: 'CONFIG_FILE', rx: /DB_PASSWORD/i },
  { path: '/wp-config.php.bak',        sev: 'critical', cat: 'CONFIG_FILE', rx: null },
  { path: '/config.json',              sev: 'high',     cat: 'CONFIG_FILE', rx: /(?:password|secret|token|apiKey)/i },
  { path: '/settings.json',            sev: 'medium',   cat: 'CONFIG_FILE', rx: /(?:password|secret|token)/i },
  { path: '/config.yaml',              sev: 'high',     cat: 'CONFIG_FILE', rx: /(?:password|secret|token)/i },
  { path: '/database.yml',             sev: 'high',     cat: 'CONFIG_FILE', rx: /(?:password|username|database)/i },
  { path: '/application.yml',          sev: 'high',     cat: 'CONFIG_FILE', rx: /(?:password|secret|datasource)/i },
  { path: '/appsettings.json',         sev: 'high',     cat: 'CONFIG_FILE', rx: /(?:Password|Secret|ConnectionString)/i },
  { path: '/laravel.log',              sev: 'high',     cat: 'CONFIG_FILE', rx: /(?:Exception|Error|Stack trace)/i },
  { path: '/storage/logs/laravel.log', sev: 'high',     cat: 'CONFIG_FILE', rx: /Exception/i },
  // Backups
  { path: '/backup.sql',               sev: 'critical', cat: 'DB_DUMP',     rx: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/db-backup.sql',            sev: 'critical', cat: 'DB_DUMP',     rx: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/database.sql',             sev: 'critical', cat: 'DB_DUMP',     rx: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/dump.sql',                 sev: 'critical', cat: 'DB_DUMP',     rx: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/mysql.sql',                sev: 'critical', cat: 'DB_DUMP',     rx: /(?:INSERT INTO|CREATE TABLE)/i },
  { path: '/backup.zip',               sev: 'high',     cat: 'BACKUP',      rx: null },
  { path: '/backup.tar.gz',            sev: 'high',     cat: 'BACKUP',      rx: null },
  { path: '/site-backup.zip',          sev: 'high',     cat: 'BACKUP',      rx: null },
  { path: '/www.zip',                  sev: 'high',     cat: 'BACKUP',      rx: null },
  { path: '/public_html.zip',          sev: 'high',     cat: 'BACKUP',      rx: null },
  // Info
  { path: '/robots.txt',               sev: 'info',     cat: 'RECON',       rx: null },
  { path: '/sitemap.xml',              sev: 'info',     cat: 'RECON',       rx: null },
  { path: '/.well-known/security.txt', sev: 'info',     cat: 'RECON',       rx: null },
  // Debug
  { path: '/phpinfo.php',              sev: 'high',     cat: 'DEBUG',       rx: /PHP Version/i },
  { path: '/debug.php',                sev: 'high',     cat: 'DEBUG',       rx: null },
  { path: '/test.php',                 sev: 'medium',   cat: 'DEBUG',       rx: null },
  { path: '/info.php',                 sev: 'high',     cat: 'DEBUG',       rx: /PHP Version/i },
  { path: '/_profiler',                sev: 'high',     cat: 'DEBUG',       rx: /Symfony/i },
  { path: '/actuator',                 sev: 'high',     cat: 'DEBUG',       rx: null },
  { path: '/actuator/env',             sev: 'critical', cat: 'ENV_FILE',    rx: null },
  { path: '/actuator/health',          sev: 'info',     cat: 'DEBUG',       rx: null },
  // Admin
  { path: '/admin/',                   sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/admin/login',              sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/wp-admin/',                sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/wp-login.php',             sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/private/',                 sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/staging/',                 sev: 'low',      cat: 'ADMIN',       rx: null },
  { path: '/dev/',                     sev: 'low',      cat: 'ADMIN',       rx: null },
  { path: '/.htpasswd',                sev: 'critical', cat: 'CONFIG_FILE', rx: null },
  // Leaks
  { path: '/.DS_Store',                sev: 'medium',   cat: 'LEAK',        rx: null },
  { path: '/crossdomain.xml',          sev: 'low',      cat: 'POLICY',      rx: /allow-access-from/i },
  { path: '/clientaccesspolicy.xml',   sev: 'low',      cat: 'POLICY',      rx: null },
  // Cloud metadata (only relevant in misconfig edge cases)
  { path: '/latest/meta-data/',        sev: 'critical', cat: 'CLOUD_META',  rx: null },
];

const TRAVERSAL_PAYLOADS = [
  '/../../../etc/passwd',
  '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
  '/..%2F..%2F..%2Fetc%2Fpasswd',
  '/....//....//....//etc/passwd',
  '/%252e%252e/%252e%252e/etc/passwd',
];

const SQLI_PAYLOADS = [
  "'",
  "1' OR '1'='1",
  "1 AND 1=2--",
  "' OR 1=1--",
  "admin'--",
  "1; DROP TABLE users--",
];

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "'><svg/onload=alert(1)>",
  '<iframe src="javascript:alert(1)">',
];

const OPEN_REDIRECT_PAYLOADS = [
  'https://evil.com',
  '//evil.com',
  '/\\evil.com',
  'https:evil.com',
];

const SQLI_ERRORS = /sql syntax|mysql_fetch|pg_query|ORA-[0-9]{4}|sqlite_|unclosed quotation|syntax error in SQL|PDOException|SQLSTATE|Warning.*mysql_/i;

// ─── Header analysis ──────────────────────────────────────────────────────────

const SECURITY_HEADERS = [
  { name: 'strict-transport-security', title: 'Missing HSTS',                           sev: 'medium', note: 'No Strict-Transport-Security header. Site vulnerable to protocol downgrade.' },
  { name: 'x-content-type-options',    title: 'Missing X-Content-Type-Options',          sev: 'low',    note: 'No X-Content-Type-Options: nosniff. MIME-type sniffing attacks possible.' },
  { name: 'x-frame-options',           title: 'Missing X-Frame-Options',                sev: 'medium', note: 'No X-Frame-Options header. Site may be vulnerable to clickjacking.' },
  { name: 'content-security-policy',   title: 'Missing Content-Security-Policy',         sev: 'medium', note: 'No CSP header. XSS attacks are harder to mitigate without it.' },
  { name: 'permissions-policy',        title: 'Missing Permissions-Policy',             sev: 'low',    note: 'No Permissions-Policy header controlling browser feature access.' },
  { name: 'referrer-policy',           title: 'Missing Referrer-Policy',                sev: 'low',    note: 'No Referrer-Policy. Sensitive URL data may leak via Referer header.' },
];

const LEAKY_HEADERS = [
  { name: 'server',          rx: /Apache|nginx|IIS|LiteSpeed|PHP|Jetty|Tomcat|Caddy/i,  sev: 'info',   title: 'Server version disclosure' },
  { name: 'x-powered-by',   rx: /PHP|ASP\.NET|Express|Rails|Django/i,                  sev: 'low',    title: 'X-Powered-By header discloses technology' },
  { name: 'x-aspnet-version', rx: /.+/,                                                  sev: 'low',    title: 'ASP.NET version disclosed' },
  { name: 'x-generator',    rx: /WordPress|Drupal|Joomla|Ghost/i,                       sev: 'info',   title: 'CMS version disclosed via X-Generator' },
];

function analyzeHeaders(headers, origin) {
  const findings = [];

  for (const h of SECURITY_HEADERS) {
    if (!headers[h.name]) {
      findings.push({
        id: randomUUID(), severity: h.sev, category: 'HEADERS',
        url: origin, title: h.title, statusCode: null,
        bodySnippet: '', note: h.note,
      });
    }
  }

  for (const h of LEAKY_HEADERS) {
    const val = headers[h.name];
    if (val && h.rx.test(val)) {
      findings.push({
        id: randomUUID(), severity: h.sev, category: 'HEADERS',
        url: origin, title: `${h.title}: ${val}`,
        statusCode: null, bodySnippet: '',
      });
    }
  }

  return findings;
}

// ─── CORS misconfiguration check ──────────────────────────────────────────────

async function checkCORS(origin) {
  const findings = [];
  const r = await httpGet(origin, {
    headers: { 'Origin': 'https://evil.example.com' },
    timeoutMs: 8000,
  });
  const acao = r.headers['access-control-allow-origin'];
  const acac = r.headers['access-control-allow-credentials'];
  if (acao === '*') {
    findings.push({
      id: randomUUID(), severity: 'medium', category: 'CORS',
      url: origin, title: 'CORS: Wildcard Access-Control-Allow-Origin (*)',
      statusCode: r.status, bodySnippet: '',
      note: 'Any origin can make credentialless cross-origin requests.',
    });
  } else if (acao === 'https://evil.example.com') {
    const sev = acac === 'true' ? 'critical' : 'high';
    findings.push({
      id: randomUUID(), severity: sev, category: 'CORS',
      url: origin, title: `CORS: Reflects arbitrary Origin${acac === 'true' ? ' with credentials' : ''}`,
      statusCode: r.status, bodySnippet: '',
      note: `Server reflects attacker-controlled Origin. ACAO: ${acao}, ACAC: ${acac || 'not set'}.`,
    });
  }
  return findings;
}

// ─── Redirect chain analysis ──────────────────────────────────────────────────

async function checkRedirectChain(origin) {
  const findings = [];
  const r = await httpHead(origin, { timeoutMs: 8000 });
  if (r.url && r.url !== origin) {
    // If it redirected to http from https or vice versa, flag it.
    if (origin.startsWith('https://') && r.url.startsWith('http://')) {
      findings.push({
        id: randomUUID(), severity: 'medium', category: 'REDIRECT',
        url: origin, title: 'HTTPS to HTTP downgrade redirect',
        statusCode: r.status, bodySnippet: '',
        note: `Final URL: ${r.url}. Redirect may downgrade TLS.`,
      });
    }
  }
  return findings;
}

// ─── Open redirect probes ────────────────────────────────────────────────────

async function checkOpenRedirect(origin) {
  const findings = [];
  const paramNames = ['url', 'redirect', 'next', 'return', 'goto', 'dest', 'destination', 'redir', 'redirect_uri'];
  for (const param of paramNames.slice(0, 5)) {
    for (const payload of OPEN_REDIRECT_PAYLOADS.slice(0, 2)) {
      const testUrl = `${origin}/?${param}=${encodeURIComponent(payload)}`;
      const r = await httpGet(testUrl, { followRedirects: false, timeoutMs: 6000 });
      if ([301, 302, 303, 307, 308].includes(r.status)) {
        const loc = r.headers['location'] || '';
        if (loc.includes('evil.com')) {
          findings.push({
            id: randomUUID(), severity: 'high', category: 'OPEN_REDIRECT',
            url: testUrl, title: `Open Redirect: ?${param}= param`,
            statusCode: r.status, bodySnippet: '',
            payload, note: `Location header: ${loc}`,
          });
        }
      }
      await sleep(200);
    }
  }
  return findings;
}

// ─── Path traversal probes ────────────────────────────────────────────────────

async function checkPathTraversal(origin) {
  const findings = [];
  for (const payload of TRAVERSAL_PAYLOADS.slice(0, 3)) {
    const url = `${origin}${payload}`;
    const r   = await httpGet(url, { timeoutMs: 8000 });
    if (r.status === 200 && /root:x:|bin:x:|daemon:x:/i.test(r.body)) {
      findings.push({
        id: randomUUID(), severity: 'critical', category: 'PATH_TRAVERSAL',
        url, title: 'Path Traversal: /etc/passwd readable',
        statusCode: r.status, bodySnippet: r.body.slice(0, 300),
        payload,
      });
    }
    await sleep(250);
  }
  return findings;
}

// ─── WordPress detection ──────────────────────────────────────────────────────

async function checkWordPress(origin) {
  const findings = [];
  const r = await httpGet(origin, { timeoutMs: 10000 });
  if (r.status !== 200) return findings;

  const isWP = /wp-content|wp-includes|WordPress/i.test(r.body);
  if (!isWP) return findings;

  findings.push({
    id: randomUUID(), severity: 'info', category: 'WORDPRESS',
    url: origin, title: 'WordPress CMS detected',
    statusCode: r.status, bodySnippet: '',
    note: 'WordPress detected. Checking known vulnerable paths.',
  });

  const wpPaths = [
    { path: '/xmlrpc.php',           sev: 'medium', note: 'XMLRPC enabled. Brute-force amplification possible.' },
    { path: '/wp-json/wp/v2/users',  sev: 'medium', note: 'User enumeration via REST API.' },
    { path: '/wp-json/',             sev: 'info',   note: 'REST API exposed. Review endpoints.' },
    { path: '/?author=1',            sev: 'low',    note: 'User enumeration via author redirect.' },
    { path: '/wp-cron.php',          sev: 'low',    note: 'WP-Cron publicly accessible.' },
  ];

  for (const wp of wpPaths) {
    const url = `${origin}${wp.path}`;
    const wr  = await httpHead(url, { timeoutMs: 6000 });
    if (wr.status === 200) {
      findings.push({
        id: randomUUID(), severity: wp.sev, category: 'WORDPRESS',
        url, title: `WordPress: ${wp.path} accessible`,
        statusCode: wr.status, bodySnippet: '',
        note: wp.note,
      });
    }
    await sleep(200);
  }

  return findings;
}

// ─── Form extraction ──────────────────────────────────────────────────────────

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
  const delay    = opts.delayMs || 350;
  const push     = (f) => findings.push(f);
  const log      = (m) => { logs.push(m); process.stdout.write(m + '\n'); };

  log(`[TARGET] Scanning: ${origin}`);

  // ── 1. Sensitive path probing ────────────────────────────────────────────
  for (const rule of SENSITIVE_PATHS) {
    const url = `${origin}${rule.path}`;
    log(`[PROBE] ${url}`);
    const r = await httpGet(url, { timeoutMs: 10000 });
    await sleep(delay);
    if (r.status === 200) {
      const matched = !rule.rx || rule.rx.test(r.body);
      if (matched) {
        log(`[${rule.sev.toUpperCase()}] ${url} (${rule.cat})`);
        push({
          id: randomUUID(), severity: rule.sev, category: rule.cat,
          url, title: `${rule.cat.replace(/_/g, ' ')}: ${rule.path}`,
          statusCode: r.status, bodySnippet: r.body.slice(0, 500),
          contentType: r.headers['content-type'] || '',
        });
      }
    } else if (r.status === 403) {
      log(`[INFO] 403 on ${url} (access restricted, may exist)`);
      push({
        id: randomUUID(), severity: 'info', category: rule.cat,
        url, title: `Access Restricted (403): ${rule.path}`,
        statusCode: 403, bodySnippet: '',
        note: 'Resource returned 403. May exist but is access-controlled.',
      });
    }
  }

  // ── 2. Crawl root & form injection ──────────────────────────────────────
  log(`[CRAWL] Fetching root: ${origin}`);
  const rootRes = await httpGet(origin);
  let forms = [];
  if (rootRes.status === 200) {
    try {
      const $ = cheerio.load(rootRes.body);
      forms = extractForms($, origin);
      log(`[CRAWL] Found ${forms.length} form(s)`);
      if (/stack trace|at Object\.|traceback \(|exception in|debug mode/i.test(rootRes.body)) {
        push({
          id: randomUUID(), severity: 'medium', category: 'DEBUG_LEAK',
          url: origin, title: 'Debug/stack trace detected in root page',
          statusCode: rootRes.status, bodySnippet: rootRes.body.slice(0, 500),
        });
      }
    } catch (e) { log(`[CRAWL ERROR] ${e}`); }
  }

  for (const form of forms.slice(0, 5)) {
    for (const inputName of form.inputs.slice(0, 4)) {
      for (const payload of SQLI_PAYLOADS.slice(0, 3)) {
        const url = `${form.actionUrl}?${inputName}=${encodeURIComponent(payload)}`;
        log(`[SQLI] ${url}`);
        const r = await httpGet(url, { timeoutMs: 8000 });
        await sleep(delay);
        if (r.status >= 500 || SQLI_ERRORS.test(r.body)) {
          log(`[CRITICAL] SQLi: ${url}`);
          push({
            id: randomUUID(), severity: 'critical', category: 'SQLI',
            url, title: `Possible SQL Injection: ${form.actionUrl} [${inputName}]`,
            statusCode: r.status, bodySnippet: r.body.slice(0, 500), payload,
          });
        }
      }
      for (const payload of XSS_PAYLOADS.slice(0, 2)) {
        const url = `${form.actionUrl}?${inputName}=${encodeURIComponent(payload)}`;
        log(`[XSS] ${url}`);
        const r = await httpGet(url, { timeoutMs: 8000 });
        await sleep(delay);
        if (r.status === 200 && r.body.includes(payload)) {
          push({
            id: randomUUID(), severity: 'high', category: 'XSS',
            url, title: `Reflected XSS: ${form.actionUrl} [${inputName}]`,
            statusCode: r.status, bodySnippet: r.body.slice(0, 500), payload,
          });
        }
      }
    }
  }

  // ── 3. Error stimulus ────────────────────────────────────────────────────
  const randPath = `/wvc-probe-${Math.random().toString(36).slice(2)}`;
  const errRes   = await httpGet(`${origin}${randPath}?id='"<>`);
  if (errRes.status >= 400) {
    const body = errRes.body || '';
    if (/stack trace|traceback|exception|at Object\.|at Function\.|vendor\/laravel|Symfony|Django|Rails|Whoops|\bphp\b/i.test(body)) {
      push({
        id: randomUUID(), severity: 'medium', category: 'ERROR_PAGE',
        url: `${origin}${randPath}`, title: 'Verbose error page leaks framework/path info',
        statusCode: errRes.status, bodySnippet: body.slice(0, 500),
      });
    }
  }

  // ── 4. Header analysis ───────────────────────────────────────────────────
  log(`[HEADERS] Analyzing response headers: ${origin}`);
  const headRes = await httpHead(origin);
  if (!headRes.error) {
    const hFindings = analyzeHeaders(headRes.headers, origin);
    findings.push(...hFindings);
    log(`[HEADERS] ${hFindings.length} header finding(s)`);
  }

  // ── 5. CORS check ────────────────────────────────────────────────────────
  log(`[CORS] Checking: ${origin}`);
  const corsF = await checkCORS(origin);
  findings.push(...corsF);
  if (corsF.length) log(`[CORS] ${corsF.length} finding(s)`);

  // ── 6. WordPress detection ───────────────────────────────────────────────
  log(`[WP] Checking for WordPress: ${origin}`);
  const wpF = await checkWordPress(origin);
  findings.push(...wpF);
  if (wpF.length) log(`[WP] ${wpF.length} finding(s)`);

  // ── 7. Path traversal probes ─────────────────────────────────────────────
  log(`[TRAVERSAL] Probing: ${origin}`);
  const travF = await checkPathTraversal(origin);
  findings.push(...travF);
  if (travF.length) log(`[TRAVERSAL] ${travF.length} finding(s)`);

  // ── 8. Redirect chain ────────────────────────────────────────────────────
  log(`[REDIRECT] Checking redirect chain: ${origin}`);
  const redirF = await checkRedirectChain(origin);
  findings.push(...redirF);

  // ── 9. Open redirect probes ──────────────────────────────────────────────
  log(`[OPENREDIRECT] Probing common params: ${origin}`);
  const orF = await checkOpenRedirect(origin);
  findings.push(...orF);
  if (orF.length) log(`[OPENREDIRECT] ${orF.length} finding(s)`);

  log(`[TARGET] Done: ${origin}. Total findings: ${findings.length}`);
  return { findings, logs };
}

// ─── Job runner ───────────────────────────────────────────────────────────────

async function runScanJobFromJobRecord(job, opts = {}) {
  const allFindings = [];
  const allLogs     = [];
  const maxParallel = opts.maxParallelTargetsPerJob || 2;

  const rawTargets = Array.isArray(job.targets) ? job.targets : [];
  const { valid, invalid } = normalizeTargets(rawTargets);

  for (const inv of invalid) { allLogs.push(`[SKIP] Invalid target: ${inv}`); }
  allLogs.push(`[JOB] Scanning ${valid.length} target(s). ${invalid.length} skipped.`);

  for (let i = 0; i < valid.length; i += maxParallel) {
    const batch   = valid.slice(i, i + maxParallel);
    const results = await Promise.all(batch.map((o) => scanTarget(o, { delayMs: 350 })));
    for (const r of results) {
      allFindings.push(...r.findings);
      allLogs.push(...r.logs);
    }
  }

  return { findings: allFindings, evidences: [], logs: allLogs };
}

module.exports = { runScanJobFromJobRecord };
