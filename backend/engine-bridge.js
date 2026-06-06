// backend/engine-bridge.js
// Full Node.js scan engine v2. Authorized security testing only.
// Modules: sensitive path probing, form injection (SQLi/XSS), error stimulus,
//          header analysis, CORS check, redirect chain, WordPress detection,
//          path traversal probes, open redirect probes,
//          TLS/HTTPS check, cookie security, API key leak detector,
//          subdomain takeover probe, JWT exposure detector.

'use strict';

const fetch          = require('node-fetch');
const https          = require('https');
const cheerio        = require('cheerio');
const { randomUUID } = require('crypto');
const { withRetry }  = require('./utils/retry');
const { normalizeTargets } = require('./utils/normalize');

// ─── HTTP helpers ────────────────────────────────────────────────────────────────

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
          'User-Agent': 'Mozilla/5.0 (compatible; WebVulnConsole/2.0; Security-Audit)',
          ...(opts.headers || {}),
        },
      });
      const body = await res.text();
      const headers = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      // Capture Set-Cookie headers array
      const rawCookies = res.headers.raw?.()?.['set-cookie'] || [];
      return { status: res.status, headers, body, url: res.url, error: null, rawCookies };
    } catch (err) {
      if (err.name === 'AbortError') return { status: 0, headers: {}, body: '', url, error: 'timeout', rawCookies: [] };
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
        headers:  { 'User-Agent': 'Mozilla/5.0 (compatible; WebVulnConsole/2.0; Security-Audit)' },
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

// ─── Sensitive path rules ─────────────────────────────────────────────────────────

const SENSITIVE_PATHS = [
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
  { path: '/.git/HEAD',                sev: 'high',     cat: 'GIT_REPO',    rx: /^ref: refs\/|^[0-9a-f]{40}/m },
  { path: '/.git/config',              sev: 'high',     cat: 'GIT_REPO',    rx: /\[core\]/i },
  { path: '/.git/COMMIT_EDITMSG',      sev: 'medium',   cat: 'GIT_REPO',    rx: null },
  { path: '/.git/logs/HEAD',           sev: 'medium',   cat: 'GIT_REPO',    rx: /commit/i },
  { path: '/.git/packed-refs',         sev: 'medium',   cat: 'GIT_REPO',    rx: /refs\/heads/i },
  { path: '/.svn/entries',             sev: 'medium',   cat: 'SVN_REPO',    rx: /https?:\/\//i },
  { path: '/.hg/hgrc',                 sev: 'medium',   cat: 'HG_REPO',     rx: null },
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
  { path: '/robots.txt',               sev: 'info',     cat: 'RECON',       rx: null },
  { path: '/sitemap.xml',              sev: 'info',     cat: 'RECON',       rx: null },
  { path: '/.well-known/security.txt', sev: 'info',     cat: 'RECON',       rx: null },
  { path: '/phpinfo.php',              sev: 'high',     cat: 'DEBUG',       rx: /PHP Version/i },
  { path: '/debug.php',                sev: 'high',     cat: 'DEBUG',       rx: null },
  { path: '/test.php',                 sev: 'medium',   cat: 'DEBUG',       rx: null },
  { path: '/info.php',                 sev: 'high',     cat: 'DEBUG',       rx: /PHP Version/i },
  { path: '/_profiler',                sev: 'high',     cat: 'DEBUG',       rx: /Symfony/i },
  { path: '/actuator',                 sev: 'high',     cat: 'DEBUG',       rx: null },
  { path: '/actuator/env',             sev: 'critical', cat: 'ENV_FILE',    rx: null },
  { path: '/actuator/health',          sev: 'info',     cat: 'DEBUG',       rx: null },
  { path: '/admin/',                   sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/admin/login',              sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/wp-admin/',                sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/wp-login.php',             sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/private/',                 sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/staging/',                 sev: 'low',      cat: 'ADMIN',       rx: null },
  { path: '/dev/',                     sev: 'low',      cat: 'ADMIN',       rx: null },
  { path: '/.htpasswd',                sev: 'critical', cat: 'CONFIG_FILE', rx: null },
  { path: '/.DS_Store',                sev: 'medium',   cat: 'LEAK',        rx: null },
  { path: '/crossdomain.xml',          sev: 'low',      cat: 'POLICY',      rx: /allow-access-from/i },
  { path: '/clientaccesspolicy.xml',   sev: 'low',      cat: 'POLICY',      rx: null },
  { path: '/latest/meta-data/',        sev: 'critical', cat: 'CLOUD_META',  rx: null },
  // v2 additions
  { path: '/.npmrc',                   sev: 'critical', cat: 'CONFIG_FILE', rx: /(?:_authToken|password|registry)/i },
  { path: '/.docker/config.json',      sev: 'critical', cat: 'CONFIG_FILE', rx: /auth/i },
  { path: '/composer.json',            sev: 'info',     cat: 'RECON',       rx: null },
  { path: '/package.json',             sev: 'info',     cat: 'RECON',       rx: null },
  { path: '/Dockerfile',               sev: 'low',      cat: 'RECON',       rx: null },
  { path: '/.terraform',               sev: 'high',     cat: 'CONFIG_FILE', rx: null },
  { path: '/server-status',            sev: 'medium',   cat: 'DEBUG',       rx: /Apache Server Status/i },
  { path: '/server-info',              sev: 'medium',   cat: 'DEBUG',       rx: /Apache HTTP Server/i },
  { path: '/_cat/indices',             sev: 'critical', cat: 'DEBUG',       rx: /health|green|yellow|red/i },
  { path: '/v1/sys/health',            sev: 'medium',   cat: 'DEBUG',       rx: /initialized|sealed/i },
  { path: '/graphql',                  sev: 'medium',   cat: 'ADMIN',       rx: null },
  { path: '/graphiql',                 sev: 'high',     cat: 'ADMIN',       rx: null },
  { path: '/api/swagger.json',         sev: 'medium',   cat: 'RECON',       rx: /swagger/i },
  { path: '/swagger.json',             sev: 'medium',   cat: 'RECON',       rx: /swagger/i },
  { path: '/openapi.json',             sev: 'medium',   cat: 'RECON',       rx: /openapi/i },
  { path: '/api-docs',                 sev: 'medium',   cat: 'RECON',       rx: null },
];

// ─── Payloads ───────────────────────────────────────────────────────────────────────

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
  // v2: time-based blind
  "1' AND SLEEP(5)--",
  "1; WAITFOR DELAY '0:0:5'--",
  "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
  // v2: stacked / error-based
  "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
  "1 UNION SELECT NULL,NULL,NULL--",
  "' OR '1'='1' /*",
];

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "'><svg/onload=alert(1)>",
  '<iframe src="javascript:alert(1)">',
  // v2: attribute injection
  '" autofocus onfocus=alert(1) x="',
  // v2: JS-context escape
  "';alert(1)//",
  // v2: DOM-based
  '<img src=1 onerror=alert`1`>',
  // v2: polyglot
  'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e',
];

const OPEN_REDIRECT_PAYLOADS = [
  'https://evil.com',
  '//evil.com',
  '/\\evil.com',
  'https:evil.com',
  // v2 additions
  '%2F%2Fevil.com',
  'https%3A%2F%2Fevil.com',
];

const SQLI_ERRORS = /sql syntax|mysql_fetch|pg_query|ORA-[0-9]{4}|sqlite_|unclosed quotation|syntax error in SQL|PDOException|SQLSTATE|Warning.*mysql_/i;

// ─── API key / secret leak patterns ──────────────────────────────────────────────────

const API_KEY_PATTERNS = [
  { name: 'AWS Access Key',        rx: /AKIA[0-9A-Z]{16}/,                                          sev: 'critical' },
  { name: 'AWS Secret Key',        rx: /(?:aws_secret|AWS_SECRET)[^\n]{0,20}[=:][^\n]{0,40}/i,      sev: 'critical' },
  { name: 'GitHub Token',          rx: /gh[pousr]_[A-Za-z0-9_]{36,}/,                              sev: 'critical' },
  { name: 'Stripe Secret Key',     rx: /sk_live_[0-9a-zA-Z]{24,}/,                                 sev: 'critical' },
  { name: 'Stripe Publishable Key',rx: /pk_live_[0-9a-zA-Z]{24,}/,                                 sev: 'high'     },
  { name: 'Twilio Auth Token',     rx: /(?:AC[a-z0-9]{32}|SK[a-z0-9]{32})/,                        sev: 'critical' },
  { name: 'Slack Token',           rx: /xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/,           sev: 'critical' },
  { name: 'Google API Key',        rx: /AIza[0-9A-Za-z\-_]{35}/,                                   sev: 'high'     },
  { name: 'Firebase Key',          rx: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/,                  sev: 'high'     },
  { name: 'SendGrid Key',          rx: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/,                 sev: 'critical' },
  { name: 'Mailgun Key',           rx: /key-[0-9a-zA-Z]{32}/,                                      sev: 'high'     },
  { name: 'Heroku API Key',        rx: /[hH]eroku[^\n]{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/i, sev: 'critical' },
  { name: 'Private RSA Key',       rx: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,                  sev: 'critical' },
  { name: 'Generic Secret',        rx: /(?:secret|password|passwd|api_key|apikey|api_secret|access_token|auth_token)["'\s]*[:=]["'\s]*[A-Za-z0-9+\/=_\-]{16,}/i, sev: 'high' },
];

// ─── JWT exposure detector ───────────────────────────────────────────────────────────

const JWT_RX = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

function checkApiKeyLeaks(body, url) {
  const findings = [];
  for (const pat of API_KEY_PATTERNS) {
    if (pat.rx.test(body)) {
      findings.push({
        id: randomUUID(), severity: pat.sev, category: 'API_KEY_LEAK',
        url, title: `Exposed ${pat.name} in response body`,
        statusCode: null, bodySnippet: '',
        note: `Pattern matched: ${pat.name}. Rotate the credential immediately.`,
      });
    }
  }
  const jwts = body.match(JWT_RX) || [];
  if (jwts.length) {
    findings.push({
      id: randomUUID(), severity: 'high', category: 'JWT_EXPOSURE',
      url, title: `Exposed JWT token(s) in response body (${jwts.length} found)`,
      statusCode: null,
      bodySnippet: jwts[0].slice(0, 80) + '...',
      note: 'JWT tokens exposed in body. May allow session hijacking if valid.',
    });
  }
  return findings;
}

// ─── TLS / HTTPS check ──────────────────────────────────────────────────────────────

async function checkTLS(origin) {
  const findings = [];

  // 1. HTTP-only site
  if (origin.startsWith('http://')) {
    findings.push({
      id: randomUUID(), severity: 'high', category: 'TLS',
      url: origin, title: 'Site served over HTTP (no TLS)',
      statusCode: null, bodySnippet: '',
      note: 'All traffic is unencrypted. Upgrade to HTTPS immediately.',
    });
    return findings;
  }

  // 2. Check if HTTPS redirects back to HTTP
  try {
    const r = await httpHead(origin, { timeoutMs: 8000 });
    if (r.url && r.url.startsWith('http://')) {
      findings.push({
        id: randomUUID(), severity: 'high', category: 'TLS',
        url: origin, title: 'HTTPS redirects to HTTP (TLS downgrade)',
        statusCode: r.status, bodySnippet: '',
        note: `Final URL: ${r.url}`,
      });
    }
  } catch (_) { /* ignore */ }

  // 3. TLS certificate validity via Node https module
  await new Promise((resolve) => {
    try {
      const hostname = new URL(origin).hostname;
      const req = https.request({ hostname, port: 443, method: 'HEAD', path: '/', timeout: 8000 }, (res) => {
        const cert = res.socket?.getPeerCertificate?.();
        if (cert && cert.valid_to) {
          const expiry = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiry - Date.now()) / 86400000);
          if (daysLeft < 0) {
            findings.push({
              id: randomUUID(), severity: 'critical', category: 'TLS',
              url: origin, title: `TLS certificate EXPIRED (${cert.valid_to})`,
              statusCode: null, bodySnippet: '',
              note: `Certificate expired ${Math.abs(daysLeft)} day(s) ago.`,
            });
          } else if (daysLeft < 14) {
            findings.push({
              id: randomUUID(), severity: 'high', category: 'TLS',
              url: origin, title: `TLS certificate expires in ${daysLeft} day(s)`,
              statusCode: null, bodySnippet: '',
              note: `Certificate valid_to: ${cert.valid_to}. Renew urgently.`,
            });
          } else if (daysLeft < 30) {
            findings.push({
              id: randomUUID(), severity: 'medium', category: 'TLS',
              url: origin, title: `TLS certificate expires in ${daysLeft} day(s)`,
              statusCode: null, bodySnippet: '',
              note: `Certificate valid_to: ${cert.valid_to}. Plan renewal soon.`,
            });
          }
          // Check HSTS includeSubDomains
          const hstsHeader = res.headers?.['strict-transport-security'] || '';
          if (hstsHeader && !hstsHeader.includes('includeSubDomains')) {
            findings.push({
              id: randomUUID(), severity: 'low', category: 'TLS',
              url: origin, title: 'HSTS missing includeSubDomains directive',
              statusCode: null, bodySnippet: '',
              note: `Current HSTS: ${hstsHeader}. Add includeSubDomains to protect subdomains.`,
            });
          }
        }
        res.resume();
        resolve();
      });
      req.on('error', (err) => {
        if (err.code === 'CERT_HAS_EXPIRED' || err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code === 'SELF_SIGNED_CERT_IN_CHAIN') {
          findings.push({
            id: randomUUID(), severity: 'critical', category: 'TLS',
            url: origin, title: `TLS certificate error: ${err.code}`,
            statusCode: null, bodySnippet: '',
            note: err.message,
          });
        }
        resolve();
      });
      req.on('timeout', () => { req.destroy(); resolve(); });
      req.end();
    } catch (_) { resolve(); }
  });

  return findings;
}

// ─── Cookie security check ──────────────────────────────────────────────────────────

function checkCookieSecurity(rawCookies, url) {
  const findings = [];
  if (!rawCookies || !rawCookies.length) return findings;

  for (const cookie of rawCookies) {
    const lower = cookie.toLowerCase();
    const name  = cookie.split('=')[0].trim();
    const isSensitive = /sess|token|auth|jwt|id|user/i.test(name);

    if (!lower.includes('httponly')) {
      findings.push({
        id: randomUUID(), severity: isSensitive ? 'high' : 'medium', category: 'COOKIE',
        url, title: `Cookie missing HttpOnly flag: ${name}`,
        statusCode: null, bodySnippet: '',
        note: 'Without HttpOnly, the cookie is accessible via JavaScript (XSS risk).',
      });
    }
    if (!lower.includes('secure')) {
      findings.push({
        id: randomUUID(), severity: isSensitive ? 'high' : 'medium', category: 'COOKIE',
        url, title: `Cookie missing Secure flag: ${name}`,
        statusCode: null, bodySnippet: '',
        note: 'Without Secure flag, cookie may be transmitted over HTTP.',
      });
    }
    if (!lower.includes('samesite')) {
      findings.push({
        id: randomUUID(), severity: 'low', category: 'COOKIE',
        url, title: `Cookie missing SameSite attribute: ${name}`,
        statusCode: null, bodySnippet: '',
        note: 'Without SameSite, cookie is vulnerable to CSRF attacks.',
      });
    }
    // Flag SameSite=None without Secure
    if (lower.includes('samesite=none') && !lower.includes('secure')) {
      findings.push({
        id: randomUUID(), severity: 'high', category: 'COOKIE',
        url, title: `Cookie SameSite=None without Secure: ${name}`,
        statusCode: null, bodySnippet: '',
        note: 'SameSite=None requires Secure flag per browser spec.',
      });
    }
  }
  return findings;
}

// ─── Subdomain takeover probe ─────────────────────────────────────────────────────────

const TAKEOVER_FINGERPRINTS = [
  { service: 'GitHub Pages',    rx: /There isn't a GitHub Pages site here|For root URLs/i },
  { service: 'Heroku',          rx: /no such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { service: 'Netlify',         rx: /Not Found - Request ID|netlify\.com\/404/i },
  { service: 'Fastly',          rx: /Fastly error: unknown domain/i },
  { service: 'Shopify',         rx: /Sorry, this shop is currently unavailable/i },
  { service: 'Tumblr',          rx: /Whatever you were looking for doesn't live here/i },
  { service: 'Unbounce',        rx: /The requested URL was not found on this server/i },
  { service: 'HubSpot',         rx: /Domain not found/i },
  { service: 'Zendesk',         rx: /Help Center Closed/i },
  { service: 'Ghost',           rx: /The thing you were looking for is no longer here/i },
  { service: 'Surge',           rx: /project not found/i },
  { service: 'AWS S3',          rx: /The specified bucket does not exist|NoSuchBucket/i },
  { service: 'AWS CloudFront',  rx: /Bad request.*CloudFront|ERROR: The request could not be satisfied/i },
  { service: 'Azure',           rx: /This web app is stopped|404 Web Site not found/i },
  { service: 'Cargo',           rx: /404 Not Found/i },
];

async function checkSubdomainTakeover(origin) {
  const findings = [];
  try {
    const r = await httpGet(origin, { timeoutMs: 10000 });
    if ([404, 410, 421].includes(r.status) || r.error) {
      for (const fp of TAKEOVER_FINGERPRINTS) {
        if (fp.rx.test(r.body || '')) {
          findings.push({
            id: randomUUID(), severity: 'high', category: 'SUBDOMAIN_TAKEOVER',
            url: origin, title: `Possible subdomain takeover: ${fp.service} fingerprint detected`,
            statusCode: r.status, bodySnippet: r.body.slice(0, 300),
            note: `Service fingerprint matched: ${fp.service}. Dangling DNS CNAME may be claimable.`,
          });
          break;
        }
      }
    }
  } catch (_) { /* DNS failure = possibly dangling */ }
  return findings;
}

// ─── Header analysis ────────────────────────────────────────────────────────────────

const SECURITY_HEADERS = [
  { name: 'strict-transport-security', title: 'Missing HSTS',                    sev: 'medium', note: 'No Strict-Transport-Security header. Site vulnerable to protocol downgrade.' },
  { name: 'x-content-type-options',    title: 'Missing X-Content-Type-Options',  sev: 'low',    note: 'No X-Content-Type-Options: nosniff. MIME-type sniffing attacks possible.' },
  { name: 'x-frame-options',           title: 'Missing X-Frame-Options',         sev: 'medium', note: 'No X-Frame-Options header. Site may be vulnerable to clickjacking.' },
  { name: 'content-security-policy',   title: 'Missing Content-Security-Policy', sev: 'medium', note: 'No CSP header. XSS attacks are harder to mitigate without it.' },
  { name: 'permissions-policy',        title: 'Missing Permissions-Policy',      sev: 'low',    note: 'No Permissions-Policy header controlling browser feature access.' },
  { name: 'referrer-policy',           title: 'Missing Referrer-Policy',         sev: 'low',    note: 'No Referrer-Policy. Sensitive URL data may leak via Referer header.' },
  // v2 additions
  { name: 'cross-origin-opener-policy',  title: 'Missing Cross-Origin-Opener-Policy',   sev: 'low', note: 'No COOP header. Spectre-style attacks may be possible.' },
  { name: 'cross-origin-resource-policy',title: 'Missing Cross-Origin-Resource-Policy', sev: 'low', note: 'No CORP header. Resources may be read cross-origin.' },
];

const LEAKY_HEADERS = [
  { name: 'server',            rx: /Apache|nginx|IIS|LiteSpeed|PHP|Jetty|Tomcat|Caddy/i, sev: 'info', title: 'Server version disclosure' },
  { name: 'x-powered-by',     rx: /PHP|ASP\.NET|Express|Rails|Django/i,                  sev: 'low',  title: 'X-Powered-By header discloses technology' },
  { name: 'x-aspnet-version', rx: /.+/,                                                    sev: 'low',  title: 'ASP.NET version disclosed' },
  { name: 'x-generator',      rx: /WordPress|Drupal|Joomla|Ghost/i,                       sev: 'info', title: 'CMS version disclosed via X-Generator' },
  // v2 additions
  { name: 'x-debug-token',    rx: /.+/, sev: 'medium', title: 'Symfony debug token exposed in header' },
  { name: 'x-runtime',        rx: /.+/, sev: 'info',   title: 'Rails X-Runtime header discloses response time' },
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

// ─── CORS misconfiguration ────────────────────────────────────────────────────────────

async function checkCORS(origin) {
  const findings = [];
  const r = await httpGet(origin, { headers: { 'Origin': 'https://evil.example.com' }, timeoutMs: 8000 });
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

// ─── Redirect chain ───────────────────────────────────────────────────────────────────

async function checkRedirectChain(origin) {
  const findings = [];
  const r = await httpHead(origin, { timeoutMs: 8000 });
  if (r.url && r.url !== origin) {
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

// ─── Open redirect ─────────────────────────────────────────────────────────────────────

async function checkOpenRedirect(origin) {
  const findings = [];
  const paramNames = ['url', 'redirect', 'next', 'return', 'goto', 'dest', 'destination', 'redir', 'redirect_uri'];
  for (const param of paramNames.slice(0, 5)) {
    for (const payload of OPEN_REDIRECT_PAYLOADS.slice(0, 3)) {
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

// ─── Path traversal ────────────────────────────────────────────────────────────────────

async function checkPathTraversal(origin) {
  const findings = [];
  for (const payload of TRAVERSAL_PAYLOADS.slice(0, 3)) {
    const url = `${origin}${payload}`;
    const r   = await httpGet(url, { timeoutMs: 8000 });
    if (r.status === 200 && /root:x:|bin:x:|daemon:x:/i.test(r.body)) {
      findings.push({
        id: randomUUID(), severity: 'critical', category: 'PATH_TRAVERSAL',
        url, title: 'Path Traversal: /etc/passwd readable',
        statusCode: r.status, bodySnippet: r.body.slice(0, 300), payload,
      });
    }
    await sleep(250);
  }
  return findings;
}

// ─── WordPress detection ────────────────────────────────────────────────────────────

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
    { path: '/xmlrpc.php',          sev: 'medium', note: 'XMLRPC enabled. Brute-force amplification possible.' },
    { path: '/wp-json/wp/v2/users', sev: 'medium', note: 'User enumeration via REST API.' },
    { path: '/wp-json/',            sev: 'info',   note: 'REST API exposed. Review endpoints.' },
    { path: '/?author=1',           sev: 'low',    note: 'User enumeration via author redirect.' },
    { path: '/wp-cron.php',         sev: 'low',    note: 'WP-Cron publicly accessible.' },
  ];
  for (const wp of wpPaths) {
    const url = `${origin}${wp.path}`;
    const wr  = await httpHead(url, { timeoutMs: 6000 });
    if (wr.status === 200) {
      findings.push({
        id: randomUUID(), severity: wp.sev, category: 'WORDPRESS',
        url, title: `WordPress: ${wp.path} accessible`,
        statusCode: wr.status, bodySnippet: '', note: wp.note,
      });
    }
    await sleep(200);
  }
  return findings;
}

// ─── Form extraction ───────────────────────────────────────────────────────────────────

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

// ─── Single target scan ────────────────────────────────────────────────────────────

async function scanTarget(origin, opts = {}) {
  const findings = [];
  const logs     = [];
  const delay    = opts.delayMs || 350;
  const push     = (f) => findings.push(f);
  const log      = (m) => { logs.push(m); process.stdout.write(m + '\n'); };

  log(`[TARGET] Scanning: ${origin}`);

  // ─ 1. TLS check ──────────────────────────────────────────────────────────────────
  log(`[TLS] Checking: ${origin}`);
  const tlsF = await checkTLS(origin);
  findings.push(...tlsF);
  if (tlsF.length) log(`[TLS] ${tlsF.length} finding(s)`);

  // ─ 2. Sensitive path probing ───────────────────────────────────────────────────────
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
        // Run API key / JWT scan on every 200 response
        const leakF = checkApiKeyLeaks(r.body, url);
        findings.push(...leakF);
      }
    } else if (r.status === 403) {
      log(`[INFO] 403 on ${url}`);
      push({
        id: randomUUID(), severity: 'info', category: rule.cat,
        url, title: `Access Restricted (403): ${rule.path}`,
        statusCode: 403, bodySnippet: '',
        note: 'Resource returned 403. May exist but is access-controlled.',
      });
    }
  }

  // ─ 3. Crawl root, form injection, cookie check, API key scan ───────────────────
  log(`[CRAWL] Fetching root: ${origin}`);
  const rootRes = await httpGet(origin);
  let forms = [];
  if (rootRes.status === 200) {
    // Cookie security check
    const cookieF = checkCookieSecurity(rootRes.rawCookies || [], origin);
    findings.push(...cookieF);
    if (cookieF.length) log(`[COOKIE] ${cookieF.length} finding(s)`);

    // API key / JWT scan on root body
    const rootLeakF = checkApiKeyLeaks(rootRes.body, origin);
    findings.push(...rootLeakF);
    if (rootLeakF.length) log(`[LEAK] ${rootLeakF.length} API key/JWT finding(s) in root`);

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
      for (const payload of SQLI_PAYLOADS.slice(0, 6)) {
        const url = `${form.actionUrl}?${inputName}=${encodeURIComponent(payload)}`;
        log(`[SQLI] ${url}`);
        const r = await httpGet(url, { timeoutMs: 10000 });
        await sleep(delay);
        if (r.status >= 500 || SQLI_ERRORS.test(r.body)) {
          log(`[CRITICAL] SQLi: ${url}`);
          push({
            id: randomUUID(), severity: 'critical', category: 'SQLI',
            url, title: `Possible SQL Injection: ${form.actionUrl} [${inputName}]`,
            statusCode: r.status, bodySnippet: r.body.slice(0, 500), payload,
          });
        }
        // Time-based blind detection (>= 4.5s response for SLEEP payloads)
        if (/SLEEP|WAITFOR/i.test(payload)) {
          const t0 = Date.now();
          const tr = await httpGet(url, { timeoutMs: 12000 });
          const elapsed = Date.now() - t0;
          if (elapsed >= 4500 && tr.status === 200) {
            push({
              id: randomUUID(), severity: 'critical', category: 'SQLI',
              url, title: `Blind Time-Based SQLi: ${form.actionUrl} [${inputName}] (${elapsed}ms delay)`,
              statusCode: tr.status, bodySnippet: '', payload,
              note: `Response took ${elapsed}ms — consistent with SLEEP() injection.`,
            });
          }
        }
      }
      for (const payload of XSS_PAYLOADS.slice(0, 4)) {
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

  // ─ 4. Error stimulus ───────────────────────────────────────────────────────────────
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

  // ─ 5. Header analysis ────────────────────────────────────────────────────────────
  log(`[HEADERS] Analyzing response headers: ${origin}`);
  const headRes = await httpHead(origin);
  if (!headRes.error) {
    const hFindings = analyzeHeaders(headRes.headers, origin);
    findings.push(...hFindings);
    log(`[HEADERS] ${hFindings.length} finding(s)`);
  }

  // ─ 6. CORS ───────────────────────────────────────────────────────────────────────
  log(`[CORS] Checking: ${origin}`);
  const corsF = await checkCORS(origin);
  findings.push(...corsF);
  if (corsF.length) log(`[CORS] ${corsF.length} finding(s)`);

  // ─ 7. WordPress ──────────────────────────────────────────────────────────────────
  log(`[WP] Checking for WordPress: ${origin}`);
  const wpF = await checkWordPress(origin);
  findings.push(...wpF);
  if (wpF.length) log(`[WP] ${wpF.length} finding(s)`);

  // ─ 8. Path traversal ─────────────────────────────────────────────────────────────
  log(`[TRAVERSAL] Probing: ${origin}`);
  const travF = await checkPathTraversal(origin);
  findings.push(...travF);
  if (travF.length) log(`[TRAVERSAL] ${travF.length} finding(s)`);

  // ─ 9. Redirect chain ────────────────────────────────────────────────────────────
  log(`[REDIRECT] Checking redirect chain: ${origin}`);
  const redirF = await checkRedirectChain(origin);
  findings.push(...redirF);

  // ─ 10. Open redirect ───────────────────────────────────────────────────────────
  log(`[OPENREDIRECT] Probing common params: ${origin}`);
  const orF = await checkOpenRedirect(origin);
  findings.push(...orF);
  if (orF.length) log(`[OPENREDIRECT] ${orF.length} finding(s)`);

  // ─ 11. Subdomain takeover ─────────────────────────────────────────────────────────
  log(`[TAKEOVER] Checking subdomain takeover: ${origin}`);
  const takeoverF = await checkSubdomainTakeover(origin);
  findings.push(...takeoverF);
  if (takeoverF.length) log(`[TAKEOVER] ${takeoverF.length} finding(s)`);

  log(`[TARGET] Done: ${origin}. Total findings: ${findings.length}`);
  return { findings, logs };
}

// ─── Job runner ─────────────────────────────────────────────────────────────────────

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
