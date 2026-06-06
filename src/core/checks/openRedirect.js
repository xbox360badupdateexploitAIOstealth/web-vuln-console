// src/core/checks/openRedirect.js
// Active check: detect open redirect vulnerabilities in parameterised endpoints.
//
// Open redirects allow attackers to craft legitimate-looking URLs on a trusted
// domain that redirect victims to attacker-controlled pages — used for
// phishing, OAuth token theft, and SSRF filter bypasses.
//
// Strategy:
//   1. Take parameterised endpoints from siteModel (populated by crawler)
//   2. For each URL parameter, inject open-redirect payloads one at a time
//   3. Detect via two methods:
//      a. 3xx redirect: check Location header points to injected domain
//      b. Meta-refresh / JS redirect: check body for redirect to injected domain
//   4. Stop after first confirmed hit per endpoint (dedup by endpoint)
//
// All payloads use a recognisable marker domain so false positives are minimal.
//
// Wire-up (engine.js Phase 3b — alongside other injection checks):
//   import { runOpenRedirect } from './checks/openRedirect.js';
//   if (moduleEnabled(enabledModules, 'injection.open_redirect')) {
//     await runOpenRedirect({ ctx, target, siteModel, enabledModules, engineConfig });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

const REDIRECT_DOMAIN  = 'evil-redirect-test.wvc-scan.internal';
const REDIRECT_PAYLOADS = [
  `https://${REDIRECT_DOMAIN}`,
  `http://${REDIRECT_DOMAIN}`,
  `//${REDIRECT_DOMAIN}`,
  `https://${REDIRECT_DOMAIN}/`,
  `\\\\${REDIRECT_DOMAIN}`,              // Windows UNC bypass
  `https:${REDIRECT_DOMAIN}`,            // scheme-relative bypass
  `/%09/${REDIRECT_DOMAIN}`,             // tab-encoded bypass
  `/%2F${REDIRECT_DOMAIN}`,              // double-slash bypass
  `https://${REDIRECT_DOMAIN}%23`,       // fragment bypass
  `https://${REDIRECT_DOMAIN}%3F`,       // query bypass
];

// Common parameter names that are redirect sinks
const REDIRECT_PARAM_HINTS = [
  'next', 'redirect', 'redirect_to', 'redirect_url', 'redirectUrl',
  'return', 'returnTo', 'return_to', 'return_url', 'returnUrl',
  'url', 'goto', 'destination', 'dest', 'target', 'to',
  'continue', 'callback', 'rurl', 'r', 'u', 'ref',
];

const MAX_ENDPOINTS = 50;
const MAX_PROBES    = 150;

// ── Main entry ─────────────────────────────────────────────────────────────

export async function runOpenRedirect({ ctx, target, siteModel, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const base = normalizeBase(target.host);

  ctx.log('[openRedirect] Starting open redirect checks...');

  const endpoints = siteModel.getParamEndpoints();
  if (endpoints.length === 0) {
    ctx.log('[openRedirect] No parameterised endpoints found — skipping.');
    return;
  }

  // Prioritise endpoints whose param names match known redirect sinks
  const sorted = sortByRedirectHint(endpoints);
  ctx.log(`[openRedirect] ${sorted.length} parameterised endpoint(s) to check.`);

  let totalProbes = 0;

  for (const ep of sorted.slice(0, MAX_ENDPOINTS)) {
    if (totalProbes >= MAX_PROBES) {
      ctx.log(`[openRedirect] Probe cap (${MAX_PROBES}) reached — stopping.`);
      break;
    }

    const urlBase = base.replace(/\/$/, '') + ep.url;
    const params  = ep.params.map((p) => p.name).filter(Boolean);

    let hitThisEndpoint = false;

    for (const paramName of params) {
      if (hitThisEndpoint || totalProbes >= MAX_PROBES) break;

      for (const payload of REDIRECT_PAYLOADS) {
        if (totalProbes >= MAX_PROBES) break;

        const url = injectQueryParam(urlBase, paramName, payload);
        ctx.log(`[openRedirect] Probe [${paramName}]: ${url}`);

        let res;
        try {
          res = await httpGetText({ fetchAdapter, url, followRedirects: false });
        } catch (e) {
          ctx.log(`[openRedirect] Fetch error: ${e.message || e}`);
          totalProbes++;
          continue;
        }

        totalProbes++;

        const confirmed = checkRedirectResponse(res, payload);
        if (!confirmed) continue;

        ctx.log(`\uD83D\uDFE0 HIGH: open redirect at ${urlBase} param="${paramName}" payload="${payload}"`);

        const finding = new Finding({
          projectId:   ctx.project.id,
          scanJobId:   ctx.job.id,
          targetId:    target.id,
          moduleId:    'injection.open_redirect',
          title:       'Open Redirect',
          shortDescription:
            `Open redirect via parameter "${paramName}" at ${urlBase}. ` +
            `Redirected to injected domain: ${REDIRECT_DOMAIN}.`,
          detailedDescription:
            `An open redirect vulnerability was confirmed in parameter "${paramName}" at ${urlBase}. ` +
            'The server redirected to an attacker-controlled domain when the redirect payload was injected. \n\n' +
            'Impact:\n' +
            '  • Phishing: craft trusted-domain URLs that redirect to attacker pages\n' +
            '  • OAuth token theft: abuse redirect_uri validation bypasses\n' +
            '  • SSRF filter bypass: some SSRF protections trust the initial URL domain\n' +
            '  • Open proxy: server may fetch attacker URLs server-side\n\n' +
            `Confirmed payload: ${payload}\n` +
            `Redirect destination: ${confirmed.location}\n\n` +
            'Remediation: Validate redirect targets against an explicit allowlist of trusted domains. ' +
            'Never accept full URLs from user input for redirects — use relative paths or opaque identifiers.',
          severity: 'high',
          category: 'injection',
          owaspTag: 'A01-Broken-Access-Control',
          cweTag:   'CWE-601',
        });
        ctx.addFinding(finding);
        ctx.addEvidence(new Evidence({
          findingId:              finding.id,
          url,
          method:                 'GET',
          responseStatus:         res.status,
          responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
          responseBodySnippet:    (res.body || '').slice(0, 1024),
          matchedPattern:
            `Redirect to injected domain confirmed — Location: ${confirmed.location} | payload: ${payload}`,
        }));

        hitThisEndpoint = true;
        break;
      }
    }
  }

  ctx.log(`[openRedirect] Done. Total probes: ${totalProbes}`);
}

// ── Redirect detection ────────────────────────────────────────────────────────────

function checkRedirectResponse(res, payload) {
  // Method A: 3xx redirect with Location pointing to our domain
  if (res.status >= 300 && res.status < 400) {
    const loc = getHeader(res.headers, 'location') || '';
    if (loc.includes(REDIRECT_DOMAIN)) {
      return { location: loc };
    }
  }

  // Method B: meta-refresh or JS redirect in body
  const body = (res.body || '').slice(0, 8192);
  const metaMatch = body.match(/<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^"']*url=([^"'\s>]+)/i);
  if (metaMatch && metaMatch[1].includes(REDIRECT_DOMAIN)) {
    return { location: metaMatch[1] };
  }

  const jsMatch = body.match(/(?:window\.location|location\.href|location\.replace)\s*=\s*["']([^"']+)/i);
  if (jsMatch && jsMatch[1].includes(REDIRECT_DOMAIN)) {
    return { location: jsMatch[1] };
  }

  return null;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function sortByRedirectHint(endpoints) {
  return [...endpoints].sort((a, b) => {
    const aScore = a.params.filter((p) => REDIRECT_PARAM_HINTS.includes(p.name)).length;
    const bScore = b.params.filter((p) => REDIRECT_PARAM_HINTS.includes(p.name)).length;
    return bScore - aScore;
  });
}

function normalizeBase(host) {
  if (!/^https?:\/\//i.test(host)) return `https://${host}`;
  return host;
}

function injectQueryParam(urlBase, paramName, payload) {
  try {
    const u = new URL(urlBase);
    u.searchParams.set(paramName, payload);
    return u.toString();
  } catch {
    const sep = urlBase.includes('?') ? '&' : '?';
    return `${urlBase}${sep}${encodeURIComponent(paramName)}=${encodeURIComponent(payload)}`;
  }
}

function getHeader(headers, name) {
  if (!headers) return null;
  return headers[name] || headers[name.toLowerCase()] || null;
}
