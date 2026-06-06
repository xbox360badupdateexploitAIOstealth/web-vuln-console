// src/core/checks/robotsTxtParse.js
// Passive recon: parse robots.txt and sitemap.xml for sensitive path disclosure.
//
// What it does:
//   1. Fetches /robots.txt — parses all Disallow: and Allow: entries
//      Flags any entry that looks sensitive (admin, backup, config, api, secret, etc.)
//   2. Fetches /sitemap.xml (and sitemap_index.xml) — extracts all <loc> URLs
//      Flags URLs in the sitemap that reveal interesting internal paths
//   3. Writes discovered paths to siteModel so the crawler can optionally follow them
//
// Wire-up (engine.js Phase 2.5c):
//   import { runRobotsTxtParse } from './checks/robotsTxtParse.js';
//   if (moduleEnabled(enabledModules, 'recon.robots_txt')) {
//     await runRobotsTxtParse({ ctx, target, baseUrl, siteModel, fetchAdapter });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// Patterns that indicate a Disallow/Allow entry is worth flagging
const SENSITIVE_PATH_PATTERNS = [
  /admin/i,       /backup/i,      /config/i,      /\.env/i,
  /secret/i,      /private/i,     /internal/i,    /api\//i,
  /\.git/i,       /logs?\//i,     /debug/i,       /test/i,
  /staging/i,     /dev\//i,       /database/i,    /db\//i,
  /upload/i,      /install/i,     /setup/i,       /password/i,
  /credential/i,  /token/i,       /auth/i,        /phpmyadmin/i,
  /wp-admin/i,    /cpanel/i,      /whm/i,         /panel/i,
  /console/i,     /manage/i,      /dashboard/i,
];

// ─────────────────────────────────────────────────────────────────────────────
// MAIN ENTRY
// ─────────────────────────────────────────────────────────────────────────────

export async function runRobotsTxtParse({ ctx, target, baseUrl, siteModel, fetchAdapter }) {
  ctx.log('[robotsTxt] Starting robots.txt + sitemap recon...');
  const base = baseUrl.replace(/\/$/, '');

  await checkRobotsTxt({ ctx, target, base, siteModel, fetchAdapter });
  await checkSitemap({ ctx, target, base, siteModel, fetchAdapter });

  ctx.log('[robotsTxt] Done.');
}

// ─────────────────────────────────────────────────────────────────────────────
// robots.txt
// ─────────────────────────────────────────────────────────────────────────────

async function checkRobotsTxt({ ctx, target, base, siteModel, fetchAdapter }) {
  const url = base + '/robots.txt';
  ctx.log(`[robotsTxt] Fetching ${url}`);

  let res;
  try {
    res = await httpGetText({ fetchAdapter, url });
  } catch (e) {
    ctx.log(`[robotsTxt] fetch error: ${e.message || e}`);
    return;
  }

  if (res.status !== 200 || !res.body) {
    ctx.log(`[robotsTxt] No robots.txt (status ${res.status})`);
    return;
  }

  const ct = (res.headers?.['content-type'] || '').toLowerCase();
  if (ct && !ct.includes('text') && !ct.includes('octet')) {
    ctx.log(`[robotsTxt] Unexpected content-type "${ct}" — skipping`);
    return;
  }

  ctx.log(`[robotsTxt] robots.txt found (${res.body.length} bytes)`);

  // Parse Disallow and Allow directives
  const lines = res.body.split(/\r?\n/);
  const sensitiveEntries = [];
  const allPaths = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const disallowMatch = line.match(/^(?:Disallow|Allow):\s*(.+)/i);
    if (!disallowMatch) continue;

    const path = disallowMatch[1].trim();
    if (!path || path === '/') continue;

    allPaths.push(path);

    if (SENSITIVE_PATH_PATTERNS.some((re) => re.test(path))) {
      sensitiveEntries.push(path);
    }
  }

  // Feed all discovered paths into siteModel for optional crawler follow-up
  if (siteModel?.addDiscoveredPath) {
    for (const p of allPaths) {
      siteModel.addDiscoveredPath(p);
    }
  }

  ctx.log(`[robotsTxt] ${allPaths.length} paths found, ${sensitiveEntries.length} sensitive`);

  if (sensitiveEntries.length === 0) return;

  const finding = new Finding({
    projectId:   ctx.project.id,
    scanJobId:   ctx.job.id,
    targetId:    target.id,
    moduleId:    'recon.robots_txt',
    title:       'Sensitive Paths Disclosed in robots.txt',
    shortDescription:
      `robots.txt discloses ${sensitiveEntries.length} potentially sensitive path(s): ` +
      sensitiveEntries.slice(0, 5).join(', ') +
      (sensitiveEntries.length > 5 ? ` (+${sensitiveEntries.length - 5} more)` : ''),
    detailedDescription:
      'The robots.txt file contains Disallow or Allow directives that reveal internal paths. ' +
      'While robots.txt is intended to guide search engines, it inadvertently acts as a reconnaissance ' +
      'map for attackers. Sensitive paths found:\n' +
      sensitiveEntries.map((p) => `  • ${p}`).join('\n') + '\n\n' +
      'Consider removing sensitive paths from robots.txt entirely. ' +
      'Use proper authentication and access controls instead of relying on crawler exclusion.',
    severity: sensitiveEntries.some((p) =>
      /admin|backup|config|credential|password|secret|token|auth|\.env|\.git/i.test(p)
    ) ? 'medium' : 'low',
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
    responseBodySnippet:    res.body.slice(0, 2048),
    matchedPattern:         `Sensitive Disallow/Allow entries: ${sensitiveEntries.slice(0, 10).join(', ')}`,
  }));

  ctx.log(`\uD83D\uDFE1 ${finding.severity.toUpperCase()}: sensitive paths in robots.txt — ${sensitiveEntries.slice(0, 3).join(', ')}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// sitemap.xml
// ─────────────────────────────────────────────────────────────────────────────

async function checkSitemap({ ctx, target, base, siteModel, fetchAdapter }) {
  const candidates = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.xml.gz'];

  for (const path of candidates) {
    const url = base + path;
    ctx.log(`[robotsTxt] Fetching ${url}`);

    let res;
    try {
      res = await httpGetText({ fetchAdapter, url });
    } catch (e) {
      ctx.log(`[robotsTxt] sitemap fetch error: ${e.message || e}`);
      continue;
    }

    if (res.status !== 200 || !res.body) continue;

    // Quick sanity check: should look like XML
    const body = res.body.trim();
    if (!body.startsWith('<') && !body.startsWith('\uFEFF<')) continue;

    // Extract all <loc> URLs
    const locs = [...body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map((m) => m[1].trim());
    if (locs.length === 0) continue;

    ctx.log(`[robotsTxt] sitemap at ${path}: ${locs.length} URLs found`);

    // Feed all loc URLs into siteModel
    if (siteModel?.addDiscoveredPath) {
      for (const loc of locs) {
        try {
          const parsed = new URL(loc);
          siteModel.addDiscoveredPath(parsed.pathname + parsed.search);
        } catch { /* absolute URLs that don’t parse — skip */ }
      }
    }

    // Flag sensitive-looking sitemap URLs
    const sensitiveUrls = locs.filter((loc) =>
      SENSITIVE_PATH_PATTERNS.some((re) => re.test(loc))
    );

    if (sensitiveUrls.length > 0) {
      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'recon.robots_txt',
        title:       'Sensitive URLs Disclosed in sitemap.xml',
        shortDescription:
          `sitemap.xml at ${path} discloses ${sensitiveUrls.length} sensitive URL(s): ` +
          sensitiveUrls.slice(0, 3).join(', '),
        detailedDescription:
          'The sitemap.xml file lists URLs that reveal internal or sensitive application paths. ' +
          'Attackers use sitemap files to enumerate endpoints without crawling. ' +
          'Sensitive URLs found:\n' +
          sensitiveUrls.slice(0, 20).map((u) => `  • ${u}`).join('\n'),
        severity: 'low',
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
        responseBodySnippet:    res.body.slice(0, 2048),
        matchedPattern:         `Sensitive <loc> entries: ${sensitiveUrls.slice(0, 5).join(', ')}`,
      }));

      ctx.log(`\uD83D\uDFE1 LOW: sensitive URLs in ${path} — ${sensitiveUrls.slice(0, 3).join(', ')}`);
    }

    // Only process the first sitemap that exists
    break;
  }
}
