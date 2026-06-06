// src/core/checks/corsMisconfig.js
// Passive CORS misconfiguration detection.
//
// Checks for three distinct CORS vulnerability classes:
//
//   Class A — CRITICAL: Origin reflection
//     Server echoes back whatever Origin header we send.
//     An attacker page at any domain can make credentialed requests.
//
//   Class B — HIGH: Wildcard + credentials
//     Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true
//     Browsers block this but some non-browser clients honour it.
//
//   Class C — MEDIUM: Null origin accepted
//     Server responds with Access-Control-Allow-Origin: null
//     Exploitable via sandboxed iframes or local file:// pages.
//
// Strategy:
//   1. Send three probes to the root URL (one per class)
//   2. Send Class A probe to up to MAX_ENDPOINTS parameterised endpoints
//      from the SiteModel (post-crawler) to catch API endpoints
//
// Wire-up (engine.js Phase 2.5c — after crawler, before injection):
//   import { runCorsMisconfig } from './checks/corsMisconfig.js';
//   if (moduleEnabled(enabledModules, 'misconfig.cors')) {
//     await runCorsMisconfig({ ctx, target, baseUrl, siteModel, fetchAdapter });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

const ATTACKER_ORIGIN  = 'https://evil.attacker-origin.com';
const MAX_ENDPOINTS    = 20;

// ── Main entry ─────────────────────────────────────────────────────────────

export async function runCorsMisconfig({ ctx, target, baseUrl, siteModel, fetchAdapter }) {
  ctx.log('[cors] Starting CORS misconfiguration checks...');
  const base = baseUrl.replace(/\/$/, '');

  // Always probe root
  await probeUrl({ ctx, target, url: base + '/', fetchAdapter });

  // Also probe discovered endpoints (post-crawler) up to cap
  const endpoints = siteModel?.getAllEndpoints?.() || [];
  const toProbe   = endpoints.slice(0, MAX_ENDPOINTS);

  if (toProbe.length > 0) {
    ctx.log(`[cors] Probing ${toProbe.length} siteModel endpoint(s) for CORS issues...`);
  }

  for (const ep of toProbe) {
    const url = base + ep.url;
    if (url === base + '/') continue; // already done above
    await probeUrl({ ctx, target, url, fetchAdapter });
  }

  ctx.log('[cors] Done.');
}

// ── Per-URL probe ─────────────────────────────────────────────────────────────

async function probeUrl({ ctx, target, url, fetchAdapter }) {
  // ─ Class A: attacker origin reflection
  await checkOriginReflection({ ctx, target, url, fetchAdapter });
  // ─ Class B: wildcard + credentials (root only to limit noise)
  await checkWildcardCredentials({ ctx, target, url, fetchAdapter });
  // ─ Class C: null origin
  await checkNullOrigin({ ctx, target, url, fetchAdapter });
}

// ── Class A: Origin reflection ────────────────────────────────────────────────────

async function checkOriginReflection({ ctx, target, url, fetchAdapter }) {
  ctx.log(`[cors] Class A probe (origin reflection): ${url}`);
  let res;
  try {
    res = await httpGetText({
      fetchAdapter,
      url,
      headers: { Origin: ATTACKER_ORIGIN },
    });
  } catch (e) {
    ctx.log(`[cors] Class A fetch error: ${e.message || e}`);
    return;
  }

  const acao = getHeader(res.headers, 'access-control-allow-origin');
  const acac = getHeader(res.headers, 'access-control-allow-credentials');

  if (!acao) return;

  // Reflection: server echoes our exact attacker origin
  if (acao === ATTACKER_ORIGIN || acao.includes('evil.attacker-origin.com')) {
    const withCreds = acac?.toLowerCase() === 'true';
    const severity  = withCreds ? 'critical' : 'high';

    ctx.log(`\uD83D\uDD34 ${severity.toUpperCase()}: CORS origin reflected${withCreds ? ' with credentials' : ''} at ${url}`);

    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'misconfig.cors',
      title:       withCreds
        ? 'CORS: Attacker Origin Reflected with Credentials Allowed'
        : 'CORS: Attacker Origin Reflected',
      shortDescription:
        `Server reflects arbitrary Origin header in Access-Control-Allow-Origin at ${url}` +
        (withCreds ? ' and sets Access-Control-Allow-Credentials: true.' : '.'),
      detailedDescription:
        'The server dynamically reflects any Origin value back in Access-Control-Allow-Origin. ' +
        (withCreds
          ? 'Combined with Access-Control-Allow-Credentials: true, this allows any website to make ' +
            'authenticated cross-origin requests on behalf of the victim, including reading responses. ' +
            'This is a complete CORS bypass and constitutes a critical vulnerability.'
          : 'An attacker can make cross-origin requests and read responses from any domain. ' +
            'If authentication cookies are present, this may allow session hijacking depending on browser behaviour.') +
        '\n\nRemediation: Maintain an explicit allowlist of trusted origins. ' +
        'Never reflect the request Origin directly. Only set Allow-Credentials on origins that require it.',
      severity,
      category: 'misconfig',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag:   'CWE-942',
    });
    ctx.addFinding(finding);
    ctx.addEvidence(new Evidence({
      findingId:              finding.id,
      url,
      method:                 'GET',
      responseStatus:         res.status,
      responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
      responseBodySnippet:    (res.body || '').slice(0, 512),
      matchedPattern:
        `Access-Control-Allow-Origin: ${acao}` +
        (withCreds ? ` | Access-Control-Allow-Credentials: ${acac}` : ''),
    }));
  }
}

// ── Class B: Wildcard + credentials ───────────────────────────────────────────────

async function checkWildcardCredentials({ ctx, target, url, fetchAdapter }) {
  ctx.log(`[cors] Class B probe (wildcard+creds): ${url}`);
  let res;
  try {
    res = await httpGetText({ fetchAdapter, url });
  } catch (e) {
    ctx.log(`[cors] Class B fetch error: ${e.message || e}`);
    return;
  }

  const acao = getHeader(res.headers, 'access-control-allow-origin');
  const acac = getHeader(res.headers, 'access-control-allow-credentials');

  if (acao === '*' && acac?.toLowerCase() === 'true') {
    ctx.log(`\uD83D\uDFE0 HIGH: CORS wildcard + credentials at ${url}`);

    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'misconfig.cors',
      title:       'CORS: Wildcard Origin with Credentials Allowed',
      shortDescription:
        `Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true at ${url}.`,
      detailedDescription:
        'The server sets both Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true. ' +
        'Modern browsers reject this combination per the CORS spec, but non-browser HTTP clients ' +
        '(curl, mobile apps, server-side SSRF) may honour it and send credentials. ' +
        'Remediation: Do not combine wildcard origin with credentials. ' +
        'Use an explicit origin allowlist if credentials are required.',
      severity: 'high',
      category: 'misconfig',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag:   'CWE-942',
    });
    ctx.addFinding(finding);
    ctx.addEvidence(new Evidence({
      findingId:              finding.id,
      url,
      method:                 'GET',
      responseStatus:         res.status,
      responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
      responseBodySnippet:    (res.body || '').slice(0, 512),
      matchedPattern:         'Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true',
    }));
  }
}

// ── Class C: Null origin ─────────────────────────────────────────────────────────────

async function checkNullOrigin({ ctx, target, url, fetchAdapter }) {
  ctx.log(`[cors] Class C probe (null origin): ${url}`);
  let res;
  try {
    res = await httpGetText({
      fetchAdapter,
      url,
      headers: { Origin: 'null' },
    });
  } catch (e) {
    ctx.log(`[cors] Class C fetch error: ${e.message || e}`);
    return;
  }

  const acao = getHeader(res.headers, 'access-control-allow-origin');
  if (acao === 'null') {
    ctx.log(`\uD83D\uDFE1 MEDIUM: CORS null origin accepted at ${url}`);

    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'misconfig.cors',
      title:       'CORS: Null Origin Accepted',
      shortDescription:
        `Server responds with Access-Control-Allow-Origin: null at ${url}.`,
      detailedDescription:
        'The server accepts the null Origin, which is sent by sandboxed iframes (sandbox attribute), ' +
        'local file:// pages, and some redirected requests. An attacker can craft an iframe to exploit ' +
        'this and make cross-origin requests that are allowed by the server. ' +
        'Remediation: Remove null from the CORS origin allowlist.',
      severity: 'medium',
      category: 'misconfig',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag:   'CWE-942',
    });
    ctx.addFinding(finding);
    ctx.addEvidence(new Evidence({
      findingId:              finding.id,
      url,
      method:                 'GET',
      responseStatus:         res.status,
      responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
      responseBodySnippet:    (res.body || '').slice(0, 512),
      matchedPattern:         'Access-Control-Allow-Origin: null',
    }));
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

function getHeader(headers, name) {
  if (!headers) return null;
  return headers[name] || headers[name.toLowerCase()] || null;
}
