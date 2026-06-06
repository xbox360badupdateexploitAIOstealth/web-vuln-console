// src/core/checks/cvePassive.js
// TODO-06 — Additional CVE passive checks.
// All checks are GET-only, passive, no payloads, no state modification.
//
// Exports one top-level runner per module:
//   runPhpinfoCheck()        misconfig.phpinfo.exposed
//   runSvnHgCheck()          vcs.svn_hg.exposed
//   runViteBypassCheck()     exposure.cve.vite_bypass
//   runMauticEnvCheck()      exposure.cve.mautic_env
//   runMoodleListingCheck()  exposure.cve.moodle_listing
//   runCloudBucketsCheck()   exposure.cloud.open_bucket
//   runWpDebugCheck()        exposure.cms.wp_debug

import { Finding, Evidence } from '../models.js';

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function base(ctx, target) {
  return { projectId: ctx.project.id, scanJobId: ctx.job.id, targetId: target.id };
}

function rootUrl(baseUrl) {
  return baseUrl.replace(/\/$/, '');
}

async function probe({ fetchAdapter, url }) {
  try {
    return await fetchAdapter(url, {
      method: 'GET',
      redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; web-vuln-console/1.0)' },
    });
  } catch {
    return null;
  }
}

async function probeText({ fetchAdapter, url, maxBytes = 32768 }) {
  const res = await probe({ fetchAdapter, url });
  if (!res) return null;
  let body = '';
  try {
    const raw = await res.text();
    body = raw.slice(0, maxBytes);
  } catch {
    return null;
  }
  return { status: res.status, headers: Object.fromEntries(res.headers.entries()), body };
}

function emitFinding(ctx, target, fields) {
  const f = new Finding({ ...base(ctx, target), ...fields });
  ctx.addFinding(f);
  return f;
}

function emitEvidence(ctx, { findingId, url, status, headers, body, pattern }) {
  ctx.addEvidence(new Evidence({
    findingId,
    url,
    method:                  'GET',
    responseStatus:          status,
    responseHeadersSnippet:  JSON.stringify(headers || {}).slice(0, 512),
    responseBodySnippet:     (body || '').slice(0, 2048),
    matchedPattern:          pattern,
  }));
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. phpinfo / debug info pages
//    Module: misconfig.phpinfo.exposed
// ─────────────────────────────────────────────────────────────────────────────

const PHPINFO_PATHS = [
  '/phpinfo.php',
  '/info.php',
  '/php_info.php',
  '/phpinfo',
  '/debug',
  '/debug.php',
  '/_profiler',
  '/_profiler/phpinfo',
  '/server-info',
  '/server-status',
];

const PHPINFO_SIGS = [
  'phpinfo()',
  'PHP Version',
  'php.ini',
  'Configuration File',
  'Symfony Profiler',
  'symfony-profiler',
  'Server Software',
  'Apache Server Information',
  'Server Status',
];

export async function runPhpinfoCheck({ ctx, target, baseUrl, fetchAdapter }) {
  ctx.log('[phpinfo] Starting phpinfo/debug page check');
  const root = rootUrl(baseUrl);
  for (const p of PHPINFO_PATHS) {
    const url = root + p;
    ctx.log(`[phpinfo] Probing ${url}`);
    const res = await probeText({ fetchAdapter, url });
    if (!res || res.status !== 200) continue;
    const matched = PHPINFO_SIGS.find((s) => res.body.includes(s));
    if (!matched) continue;

    const isProfiler = p.includes('_profiler') || res.body.includes('Symfony Profiler');
    const isServerInfo = p.includes('server-info') || p.includes('server-status');

    const title = isProfiler
      ? 'Symfony Profiler Exposed'
      : isServerInfo
        ? 'Apache Server Info/Status Exposed'
        : 'PHP Info Page Exposed';

    const description = isProfiler
      ? 'The Symfony web profiler is publicly accessible. It exposes request details, environment variables, ' +
        'session data, database queries, and internal configuration — critical information disclosure.'
      : isServerInfo
        ? 'The Apache server-info or server-status page is publicly accessible, exposing server configuration, ' +
          'loaded modules, active request details, and internal network paths.'
        : 'A phpinfo() output page is publicly accessible. It exposes PHP configuration, loaded extensions, ' +
          'server environment variables (including secret keys), and filesystem paths.';

    ctx.log(`\uD83D\uDD34 CRITICAL: ${title} at ${url}`);
    const f = emitFinding(ctx, target, {
      moduleId: 'misconfig.phpinfo.exposed',
      title,
      shortDescription: `${title} at ${url}.`,
      detailedDescription: description,
      severity: 'critical',
      category: 'exposure',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag: 'CWE-200',
    });
    emitEvidence(ctx, { findingId: f.id, url, status: res.status, headers: res.headers, body: res.body, pattern: `phpinfo signature: "${matched}"` });
    break; // one finding per target is enough
  }
  ctx.log('[phpinfo] Done');
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SVN / Mercurial repository exposure
//    Module: vcs.svn_hg.exposed
// ─────────────────────────────────────────────────────────────────────────────

const SVN_HG_PATHS = [
  { path: '/.svn/entries',      sig: 'dir',           label: 'SVN entries file' },
  { path: '/.svn/wc.db',        sig: 'SQLite',        label: 'SVN wc.db (SQLite)' },
  { path: '/.svn/format',       sig: '',              label: 'SVN format file', statusOnly: true },
  { path: '/.hg/manifest',      sig: '',              label: 'Mercurial manifest', statusOnly: true },
  { path: '/.hg/store/data',    sig: '',              label: 'Mercurial store', statusOnly: true },
  { path: '/.hg/requires',      sig: 'revlogv1',      label: 'Mercurial requires' },
];

export async function runSvnHgCheck({ ctx, target, baseUrl, fetchAdapter }) {
  ctx.log('[svn_hg] Starting SVN/Hg repository exposure check');
  const root = rootUrl(baseUrl);
  for (const { path, sig, label, statusOnly } of SVN_HG_PATHS) {
    const url = root + path;
    ctx.log(`[svn_hg] Probing ${url}`);
    const res = await probeText({ fetchAdapter, url, maxBytes: 4096 });
    if (!res || res.status !== 200) continue;
    if (!statusOnly && sig && !res.body.includes(sig)) continue;

    ctx.log(`\uD83D\uDD34 CRITICAL: ${label} exposed at ${url}`);
    const f = emitFinding(ctx, target, {
      moduleId: 'vcs.svn_hg.exposed',
      title: 'Version Control Metadata Exposed (SVN/Hg)',
      shortDescription: `${label} is publicly accessible at ${url}.`,
      detailedDescription:
        'SVN or Mercurial repository metadata is accessible over HTTP. ' +
        'Attackers can reconstruct full source code, commit history, credentials stored in revision history, ' +
        'and internal project structure using tools like svn-extractor or hg-dumper.',
      severity: 'critical',
      category: 'exposure',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag: 'CWE-200',
    });
    emitEvidence(ctx, { findingId: f.id, url, status: res.status, headers: res.headers, body: res.body, pattern: label });
    break;
  }
  ctx.log('[svn_hg] Done');
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Vite dev server path bypass / LFI
//    Module: exposure.cve.vite_bypass
//    CVEs: CVE-2025-30208, CVE-2025-46565, CVE-2026-46565
// ─────────────────────────────────────────────────────────────────────────────

const VITE_FINGERPRINT_PATHS = [
  '/',
  '/index.html',
  '/vite.config.js',
  '/vite.config.ts',
];

const VITE_FINGERPRINT_SIGS = [
  'type="module"',
  'vite/dist/client',
  '@vite/client',
  '__vite_plugin',
  'Hot Module Replacement',
  'vite.config',
];

const VITE_BYPASS_PROBES = [
  { path: '/@fs/etc/passwd',                  sig: 'root:',  label: 'Vite @fs bypass → /etc/passwd' },
  { path: '/@fs/proc/self/environ',           sig: 'PATH=',  label: 'Vite @fs bypass → /proc/self/environ' },
  { path: '/@fs/../../../etc/passwd',         sig: 'root:',  label: 'Vite @fs traversal → /etc/passwd' },
  { path: '/@fs/c:/windows/win.ini',          sig: '[fonts]', label: 'Vite @fs bypass → win.ini (Windows)' },
  { path: '/?import&raw=/etc/passwd',         sig: 'root:',  label: 'Vite raw import bypass → /etc/passwd' },
  { path: '/?import&raw=/../../../etc/passwd', sig: 'root:', label: 'Vite raw import traversal → /etc/passwd' },
];

export async function runViteBypassCheck({ ctx, target, baseUrl, fetchAdapter }) {
  ctx.log('[vite_bypass] Starting Vite dev server LFI/bypass check');
  const root = rootUrl(baseUrl);

  // Step 1 — fingerprint Vite
  let isVite = false;
  for (const p of VITE_FINGERPRINT_PATHS) {
    const res = await probeText({ fetchAdapter, url: root + p, maxBytes: 16384 });
    if (!res || res.status !== 200) continue;
    if (VITE_FINGERPRINT_SIGS.some((s) => res.body.includes(s))) {
      isVite = true;
      break;
    }
  }

  if (!isVite) {
    ctx.log('[vite_bypass] No Vite fingerprint detected — skipping bypass probes');
    return;
  }
  ctx.log('[vite_bypass] Vite fingerprint confirmed — probing for @fs bypass');

  // Step 2 — probe bypass paths
  for (const { path, sig, label } of VITE_BYPASS_PROBES) {
    const url = root + path;
    ctx.log(`[vite_bypass] Probing ${url}`);
    const res = await probeText({ fetchAdapter, url, maxBytes: 4096 });
    if (!res || res.status !== 200) continue;
    if (sig && !res.body.includes(sig)) continue;

    ctx.log(`\uD83D\uDD34 CRITICAL: Vite @fs LFI confirmed at ${url}`);
    const f = emitFinding(ctx, target, {
      moduleId: 'exposure.cve.vite_bypass',
      title: 'Vite Dev Server Local File Read (@fs bypass)',
      shortDescription: `Vite @fs path bypass allows local file read — confirmed at ${url}.`,
      detailedDescription:
        'This Vite development server is publicly accessible and vulnerable to the @fs filesystem bypass ' +
        '(CVE-2025-30208 / CVE-2025-46565 / CVE-2026-46565). ' +
        'An unauthenticated attacker can read arbitrary files from the server filesystem via /@fs/ or ' +
        '/?import&raw= URL prefixes, bypassing the configured fs.allow restrictions. ' +
        'Impact: full server-side file read including .env files, private keys, and source code. ' +
        'Fix: never expose Vite dev server to the internet; upgrade to Vite >= 6.2.4.',
      severity: 'critical',
      category: 'exposure',
      owaspTag: 'A01-Broken-Access-Control',
      cweTag: 'CWE-22',
    });
    emitEvidence(ctx, { findingId: f.id, url, status: res.status, headers: res.headers, body: res.body, pattern: label });
    return; // one confirmed LFI is enough
  }

  // Step 3 — flag Vite exposed even if no file read confirmed
  ctx.log('\uD83D\uDFE0 HIGH: Vite dev server exposed (no confirmed LFI but @fs probes inconclusive)');
  const f = emitFinding(ctx, target, {
    moduleId: 'exposure.cve.vite_bypass',
    title: 'Vite Dev Server Publicly Exposed',
    shortDescription: 'A Vite development server is publicly accessible on this host.',
    detailedDescription:
      'A Vite.js development server was detected running on a publicly accessible host. ' +
      'Dev servers are not hardened for production use and may be vulnerable to @fs path bypass ' +
      '(CVE-2025-30208 / CVE-2025-46565). They also expose HMR WebSocket endpoints and raw source code.',
    severity: 'high',
    category: 'exposure',
    owaspTag: 'A05-Security-Misconfiguration',
    cweTag: 'CWE-200',
  });
  emitEvidence(ctx, { findingId: f.id, url: root + '/', status: 200, headers: {}, body: '', pattern: 'Vite dev server fingerprint' });
  ctx.log('[vite_bypass] Done');
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Mautic .env exposure
//    Module: exposure.cve.mautic_env
//    CVE: CVE-2024-47056 (Mautic unauthenticated .env disclosure)
// ─────────────────────────────────────────────────────────────────────────────

const MAUTIC_FINGERPRINT_PATHS = [
  '/s/login',
  '/index.php/s/login',
  '/mautic/s/login',
];

const MAUTIC_ENV_PATHS = [
  '/.env',
  '/app/.env',
  '/mautic/.env',
  '/.env.local',
];

export async function runMauticEnvCheck({ ctx, target, baseUrl, fetchAdapter }) {
  ctx.log('[mautic_env] Starting Mautic .env exposure check');
  const root = rootUrl(baseUrl);

  // Fingerprint Mautic
  let isMautic = false;
  for (const p of MAUTIC_FINGERPRINT_PATHS) {
    const res = await probeText({ fetchAdapter, url: root + p, maxBytes: 8192 });
    if (!res) continue;
    if (
      res.body.includes('Mautic') ||
      res.body.includes('mautic') ||
      (res.headers['x-powered-by'] || '').toLowerCase().includes('mautic')
    ) {
      isMautic = true;
      break;
    }
  }

  if (!isMautic) {
    ctx.log('[mautic_env] No Mautic fingerprint — skipping');
    return;
  }
  ctx.log('[mautic_env] Mautic fingerprint confirmed — probing .env paths');

  for (const p of MAUTIC_ENV_PATHS) {
    const url = root + p;
    ctx.log(`[mautic_env] Probing ${url}`);
    const res = await probeText({ fetchAdapter, url });
    if (!res || res.status !== 200) continue;

    // Check for dotenv-style content
    const kvLines = res.body.split(/\r?\n/).filter((l) => /^[A-Z0-9_]+=.+/.test(l));
    if (kvLines.length < 2) continue;

    // Extract key names only (no values in log)
    const keyNames = kvLines.map((l) => l.split('=')[0]).slice(0, 20).join(', ');
    ctx.log(`\uD83D\uDD34 CRITICAL: Mautic .env exposed at ${url} — keys: ${keyNames}`);

    const f = emitFinding(ctx, target, {
      moduleId: 'exposure.cve.mautic_env',
      title: 'Mautic .env File Exposed (CVE-2024-47056)',
      shortDescription: `Mautic dotenv configuration accessible at ${url}.`,
      detailedDescription:
        'A Mautic marketing automation instance is exposing its .env configuration file without authentication. ' +
        'CVE-2024-47056 describes unauthenticated .env disclosure in Mautic deployments where the webroot ' +
        'is not correctly isolated from the application root directory. ' +
        'The .env file contains database credentials (DB_PASSWORD, DATABASE_URL), ' +
        'Mautic secret key (MAUTIC_SECRET_KEY), mailer credentials, and integration API tokens. ' +
        'Fix: ensure web server document root is set to the /docroot or /public subdirectory, not the application root.',
      severity: 'critical',
      category: 'exposure',
      owaspTag: 'A02-Cryptographic-Failures',
      cweTag: 'CWE-312',
    });
    emitEvidence(ctx, { findingId: f.id, url, status: res.status, headers: res.headers, body: res.body, pattern: `dotenv ${kvLines.length} key=value lines` });
    break;
  }
  ctx.log('[mautic_env] Done');
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Moodle directory listing / r.php router exposure
//    Module: exposure.cve.moodle_listing
//    CVE: CVE-2025-62396 (Moodle unauthenticated path disclosure)
// ─────────────────────────────────────────────────────────────────────────────

const MOODLE_FINGERPRINT_PATHS = [
  '/',
  '/login/index.php',
  '/moodle/login/index.php',
];

const MOODLE_PROBE_PATHS = [
  '/r.php',
  '/moodle/r.php',
  '/lib/',
  '/moodle/lib/',
  '/dataroot/',
  '/moodledata/',
  '/filedir/',
];

export async function runMoodleListingCheck({ ctx, target, baseUrl, fetchAdapter }) {
  ctx.log('[moodle_listing] Starting Moodle directory listing check');
  const root = rootUrl(baseUrl);

  // Fingerprint Moodle
  let isMoodle = false;
  for (const p of MOODLE_FINGERPRINT_PATHS) {
    const res = await probeText({ fetchAdapter, url: root + p, maxBytes: 8192 });
    if (!res) continue;
    if (
      res.body.includes('Moodle') ||
      res.body.includes('moodledata') ||
      res.body.includes('sesskey') ||
      (res.headers['x-powered-by'] || '').toLowerCase().includes('moodle')
    ) {
      isMoodle = true;
      break;
    }
  }

  if (!isMoodle) {
    ctx.log('[moodle_listing] No Moodle fingerprint — skipping');
    return;
  }
  ctx.log('[moodle_listing] Moodle fingerprint confirmed — probing sensitive paths');

  for (const p of MOODLE_PROBE_PATHS) {
    const url = root + p;
    ctx.log(`[moodle_listing] Probing ${url}`);
    const res = await probeText({ fetchAdapter, url });
    if (!res || res.status !== 200) continue;

    const body = res.body.toLowerCase();
    const isDirListing = body.includes('index of /') || body.includes('parent directory') || body.includes('<title>index of');
    const isRphp       = p.endsWith('r.php') && (body.includes('moodle') || body.includes('redirect') || res.status === 200);

    if (!isDirListing && !isRphp) continue;

    const label = isDirListing ? 'Directory listing' : 'r.php router exposed';
    ctx.log(`\uD83D\uDFE0 HIGH: Moodle ${label} at ${url}`);

    const f = emitFinding(ctx, target, {
      moduleId: 'exposure.cve.moodle_listing',
      title: isDirListing ? 'Moodle Data Directory Listing Exposed' : 'Moodle r.php Router Exposed (CVE-2025-62396)',
      shortDescription: `Moodle ${label} accessible at ${url}.`,
      detailedDescription: isDirListing
        ? 'A Moodle installation is exposing a data directory listing. The moodledata / dataroot directory ' +
          'contains uploaded course files, user submissions, and potentially sensitive course content. ' +
          'Directory listing should be disabled via server configuration.'
        : 'The Moodle r.php router script is publicly accessible and may allow unauthenticated path ' +
          'disclosure or resource enumeration (CVE-2025-62396). ' +
          'r.php handles internal file redirects; exposure can reveal internal filesystem layout and ' +
          'may be chained with other vulnerabilities for file read access.',
      severity: isDirListing ? 'high' : 'medium',
      category: 'exposure',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag: isDirListing ? 'CWE-548' : 'CWE-200',
    });
    emitEvidence(ctx, { findingId: f.id, url, status: res.status, headers: res.headers, body: res.body, pattern: label });
  }
  ctx.log('[moodle_listing] Done');
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Cloud storage open bucket probe
//    Module: exposure.cloud.open_bucket
//    Covers: AWS S3, Azure Blob, GCP GCS
// ─────────────────────────────────────────────────────────────────────────────

// Extract candidate bucket names from target host, e.g.:
//   assets.example.com    → ['assets', 'example', 'assets-example', 'example-assets']
//   www.my-company.com    → ['my-company', 'mycompany']
function guessBucketNames(host) {
  const stripped = host
    .replace(/^www\./, '')
    .replace(/^api\./, '')
    .replace(/^assets\./, '')
    .replace(/^cdn\./, '')
    .replace(/\.[a-z]{2,6}$/, '')   // strip TLD
    .replace(/\.[a-z]{2,6}$/, '');  // strip second-level TLD if present (e.g. .co.uk)
  const parts = stripped.split(/[\-_.]/);
  const candidates = [
    stripped,
    parts.join('-'),
    parts.join(''),
    parts[0],
  ];
  // common suffixes
  const suffixes = ['-assets', '-media', '-static', '-uploads', '-backup', '-data', '-files', '-images', '-prod', '-dev'];
  for (const s of suffixes) {
    candidates.push(stripped + s);
    if (parts[0]) candidates.push(parts[0] + s);
  }
  return [...new Set(candidates.filter((c) => c && c.length >= 3))];
}

export async function runCloudBucketsCheck({ ctx, target, baseUrl, fetchAdapter }) {
  ctx.log('[cloud_buckets] Starting cloud storage open bucket probe');
  const bucketNames = guessBucketNames(target.host || '');
  ctx.log(`[cloud_buckets] Candidate bucket names: ${bucketNames.slice(0, 6).join(', ')}`);

  const probeTargets = [];
  for (const name of bucketNames.slice(0, 10)) {
    probeTargets.push(
      { url: `https://${name}.s3.amazonaws.com/`,          label: `AWS S3: ${name}`,          sig: ['ListBucketResult', '<Contents>', 'AmazonS3'] },
      { url: `https://s3.amazonaws.com/${name}/`,           label: `AWS S3 path: ${name}`,     sig: ['ListBucketResult', '<Contents>'] },
      { url: `https://${name}.blob.core.windows.net/${name}?restype=container&comp=list`, label: `Azure Blob: ${name}`, sig: ['EnumerationResults', '<Blobs>', 'BlobPrefix'] },
      { url: `https://storage.googleapis.com/${name}/`,    label: `GCS: ${name}`,             sig: ['ListBucketResult', '<Contents>', 'storage.googleapis.com'] },
    );
  }

  for (const { url, label, sig } of probeTargets) {
    ctx.log(`[cloud_buckets] Probing ${url}`);
    const res = await probeText({ fetchAdapter, url, maxBytes: 8192 });
    if (!res || res.status !== 200) continue;
    const matched = sig.find((s) => res.body.includes(s));
    if (!matched) continue;

    ctx.log(`\uD83D\uDD34 CRITICAL: Open cloud bucket confirmed — ${label}`);
    const f = emitFinding(ctx, target, {
      moduleId: 'exposure.cloud.open_bucket',
      title: 'Open Cloud Storage Bucket',
      shortDescription: `Publicly listable cloud bucket found: ${label} (${url}).`,
      detailedDescription:
        'A cloud storage bucket associated with this target is publicly accessible and listable. ' +
        'An unauthenticated attacker can enumerate and download all objects in the bucket. ' +
        'Buckets often contain backups, uploaded user files, database exports, logs, and credentials. ' +
        'Fix: set bucket ACL/policy to private; enable Block Public Access (AWS S3); ' +
        'disable anonymous access on Azure Blob / GCS.',
      severity: 'critical',
      category: 'exposure',
      owaspTag: 'A01-Broken-Access-Control',
      cweTag: 'CWE-284',
    });
    emitEvidence(ctx, { findingId: f.id, url, status: res.status, headers: res.headers, body: res.body, pattern: `${label} — matched: ${matched}` });
    // continue — may find multiple open buckets across providers
  }
  ctx.log('[cloud_buckets] Done');
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. WordPress debug artifacts
//    Module: exposure.cms.wp_debug
// ─────────────────────────────────────────────────────────────────────────────

const WP_FINGERPRINT_PATHS = [
  '/wp-login.php',
  '/wp-admin/',
  '/wp-includes/js/jquery/jquery.min.js',
];

const WP_DEBUG_PATHS = [
  {
    path: '/wp-content/debug.log',
    label: 'WordPress debug.log',
    sig: ['PHP', 'WordPress', '[error]', '[notice]', 'Fatal error', 'Warning:'],
    severity: 'high',
    description:
      'The WordPress debug.log file is publicly accessible. It contains PHP error messages, ' +
      'stack traces, deprecation notices, and can expose filesystem paths, plugin versions, ' +
      'database query details, and user-supplied data logged during errors.',
  },
  {
    path: '/wp-config.php.bak',
    label: 'wp-config.php.bak',
    sig: ['DB_NAME', 'DB_PASSWORD', 'DB_HOST', 'table_prefix', 'AUTH_KEY'],
    severity: 'critical',
    description:
      'A backup copy of wp-config.php is publicly accessible. ' +
      'wp-config.php contains the WordPress database credentials (DB_NAME, DB_USER, DB_PASSWORD, DB_HOST), ' +
      'secret authentication keys and salts (AUTH_KEY, SECURE_AUTH_KEY, etc.), ' +
      'and the database table prefix. Full database compromise is possible.',
  },
  {
    path: '/wp-config.php~',
    label: 'wp-config.php~ (editor backup)',
    sig: ['DB_NAME', 'DB_PASSWORD', 'DB_HOST', 'table_prefix'],
    severity: 'critical',
    description: 'An editor backup of wp-config.php (tilde file) is publicly accessible, exposing WordPress database credentials and secret keys.',
  },
  {
    path: '/wp-config.bak',
    label: 'wp-config.bak',
    sig: ['DB_NAME', 'DB_PASSWORD'],
    severity: 'critical',
    description: 'A backup of wp-config.php is publicly accessible, exposing WordPress database credentials and secret keys.',
  },
  {
    path: '/.wp-config.php.swp',
    label: 'wp-config.php.swp (vim swap)',
    sig: ['DB_NAME', 'DB_PASSWORD', 'b0VIM'],
    severity: 'critical',
    description: 'A vim swap file containing wp-config.php content is publicly accessible.',
  },
  {
    path: '/wp-content/uploads/.htaccess',
    label: 'wp-content/uploads/.htaccess missing (PHP execution possible)',
    sig: ['deny from all', 'php_flag', 'Options'],
    severity: 'medium',
    statusOnly: true,
    description:
      'The WordPress uploads directory .htaccess is accessible (or missing enforcement). ' +
      'If PHP execution is not blocked in the uploads directory, uploaded .php files could be executed.',
  },
];

export async function runWpDebugCheck({ ctx, target, baseUrl, fetchAdapter }) {
  ctx.log('[wp_debug] Starting WordPress debug artifacts check');
  const root = rootUrl(baseUrl);

  // Fingerprint WordPress
  let isWp = false;
  for (const p of WP_FINGERPRINT_PATHS) {
    const res = await probeText({ fetchAdapter, url: root + p, maxBytes: 4096 });
    if (!res) continue;
    if (res.status === 200 || res.status === 302) {
      isWp = true;
      break;
    }
  }

  if (!isWp) {
    ctx.log('[wp_debug] No WordPress fingerprint — skipping');
    return;
  }
  ctx.log('[wp_debug] WordPress fingerprint confirmed — probing debug artifacts');

  for (const { path, label, sig, severity, description, statusOnly } of WP_DEBUG_PATHS) {
    const url = root + path;
    ctx.log(`[wp_debug] Probing ${url}`);
    const res = await probeText({ fetchAdapter, url });
    if (!res || res.status !== 200) continue;
    if (!statusOnly) {
      const matched = sig.find((s) => res.body.includes(s));
      if (!matched) continue;
    }

    ctx.log(`${severity === 'critical' ? '\uD83D\uDD34 CRITICAL' : '\uD83D\uDFE0 HIGH'}: ${label} at ${url}`);
    const f = emitFinding(ctx, target, {
      moduleId: 'exposure.cms.wp_debug',
      title: `WordPress Debug Artifact Exposed: ${label}`,
      shortDescription: `${label} is publicly accessible at ${url}.`,
      detailedDescription: description,
      severity,
      category: 'exposure',
      owaspTag: severity === 'critical' ? 'A02-Cryptographic-Failures' : 'A05-Security-Misconfiguration',
      cweTag: severity === 'critical' ? 'CWE-312' : 'CWE-200',
    });
    emitEvidence(ctx, { findingId: f.id, url, status: res.status, headers: res.headers, body: res.body, pattern: label });
  }
  ctx.log('[wp_debug] Done');
}
