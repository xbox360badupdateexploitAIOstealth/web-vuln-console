// src/core/checks/phpInfoExposure.js
// Passive check: detect exposed phpinfo() pages.
//
// phpinfo() pages leak:
//   - PHP version (exact), loaded extensions, compiled flags
//   - Server paths (DOCUMENT_ROOT, SCRIPT_FILENAME, etc.)
//   - Environment variables (DB passwords, API keys if in env)
//   - PHP configuration (disable_functions, open_basedir, etc.)
//   - OS / kernel version
//
// Strategy:
//   1. Probe a list of common phpinfo paths
//   2. Confirm the response actually contains phpinfo() output
//      (not just a 200 on a generic page)
//   3. Attempt to extract the PHP version string for the finding title
//   4. If siteModel.techStack.language is already set (by techFingerprint),
//      use it to enrich the finding detail — otherwise set it from phpinfo.
//
// Wire-up (engine.js Phase 1b — after techFingerprint, before crawler):
//   import { runPhpInfoExposure } from './checks/phpInfoExposure.js';
//   if (moduleEnabled(enabledModules, 'exposure.phpinfo')) {
//     await runPhpInfoExposure({ ctx, target, baseUrl, siteModel, fetchAdapter });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// Candidate paths to probe
const PHPINFO_PATHS = [
  '/phpinfo.php',
  '/info.php',
  '/php-info.php',
  '/phpinfo',
  '/test.php',
  '/debug.php',
  '/_info.php',
  '/php_info.php',
  '/server-info.php',
  '/server-status.php',
  '/status.php',
  '/i.php',
  '/infophp.php',
  '/php.php',
  '/install.php',   // some installers call phpinfo()
];

// Strings that definitively identify real phpinfo() HTML output
const PHPINFO_SIGNATURES = [
  '<title>phpinfo()</title>',
  'PHP Version </td>',
  'PHP Version</td>',
  '<h1 class="p">PHP Version',
  'PHP Extension Build',
  'php_uname',
  'DOCUMENT_ROOT</td>',
  'disable_functions</td>',
];

// Regex to extract PHP version from phpinfo output
const PHP_VERSION_RE = /PHP\s+Version\s*[<\/]?\s*(?:<\/td>)?\s*([\d.]+(?:-[\w]+)?)/i;

// ── Main entry ──────────────────────────────────────────────────────────────

export async function runPhpInfoExposure({ ctx, target, baseUrl, siteModel, fetchAdapter }) {
  ctx.log('[phpInfo] Starting phpinfo() exposure check...');
  const base = baseUrl.replace(/\/$/, '');

  for (const path of PHPINFO_PATHS) {
    const url = base + path;
    ctx.log(`[phpInfo] Probing ${url}`);

    let res;
    try {
      res = await httpGetText({ fetchAdapter, url });
    } catch (e) {
      ctx.log(`[phpInfo] Fetch error at ${url}: ${e.message || e}`);
      continue;
    }

    if (res.status !== 200) continue;

    const body = res.body || '';
    if (!isPhpInfoPage(body)) continue;

    // Confirmed phpinfo() page
    const phpVersion = extractPhpVersion(body);
    const versionStr = phpVersion ? ` (PHP ${phpVersion})` : '';

    ctx.log(`\uD83D\uDD34 CRITICAL: phpinfo() exposed at ${url}${versionStr}`);

    // Enrich siteModel.techStack.language if not already set
    if (siteModel?.techStack) {
      if (!siteModel.techStack.language && phpVersion) {
        siteModel.techStack.language = `PHP/${phpVersion}`;
      }
    }

    // Build enriched detail using any existing techStack info
    const techContext = buildTechContext(siteModel);

    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'exposure.phpinfo',
      title:       `Exposed phpinfo() Page${versionStr}`,
      shortDescription:
        `A phpinfo() page is publicly accessible at ${url}.` +
        (phpVersion ? ` PHP version ${phpVersion} confirmed.` : ''),
      detailedDescription:
        'A phpinfo() output page is accessible without authentication. ' +
        'phpinfo() discloses highly sensitive server information including:\n' +
        '  • Exact PHP version and compiled flags (aids version-specific exploit selection)\n' +
        '  • Absolute server filesystem paths (DOCUMENT_ROOT, SCRIPT_FILENAME)\n' +
        '  • All loaded PHP extensions and their versions\n' +
        '  • PHP configuration values (disable_functions, open_basedir, allow_url_include)\n' +
        '  • Environment variables — may include DB credentials or API keys\n' +
        '  • OS details and kernel version\n' +
        (techContext ? `\nAdditional context from tech fingerprint:\n${techContext}\n` : '') +
        '\nRemediation: Remove phpinfo() calls from production. If needed for debugging, ' +
        'restrict access by IP at the web server level.',
      severity: 'critical',
      category: 'exposure',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag:   'CWE-200',
    });

    ctx.addFinding(finding);
    ctx.addEvidence(new Evidence({
      findingId:              finding.id,
      url,
      method:                 'GET',
      responseStatus:         res.status,
      responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
      responseBodySnippet:    body.slice(0, 2048),
      matchedPattern:         `phpinfo() signature confirmed${phpVersion ? ` — PHP ${phpVersion}` : ''}`,
    }));

    // Stop after first confirmed hit — no need to report duplicates
    break;
  }

  ctx.log('[phpInfo] Done.');
}

// ── Helpers ────────────────────────────────────────────────────────────────

function isPhpInfoPage(body) {
  const snippet = body.slice(0, 16384);
  return PHPINFO_SIGNATURES.some((sig) => snippet.includes(sig));
}

function extractPhpVersion(body) {
  const snippet = body.slice(0, 8192);
  const match   = snippet.match(PHP_VERSION_RE);
  return match ? match[1].trim() : null;
}

function buildTechContext(siteModel) {
  if (!siteModel?.techStack) return null;
  const ts   = siteModel.techStack;
  const lines = [];
  if (ts.server)            lines.push(`  • Server: ${ts.server}`);
  if (ts.cms)               lines.push(`  • CMS: ${ts.cms}`);
  if (ts.frameworks?.length) lines.push(`  • Frameworks: ${ts.frameworks.join(', ')}`);
  return lines.length ? lines.join('\n') : null;
}
