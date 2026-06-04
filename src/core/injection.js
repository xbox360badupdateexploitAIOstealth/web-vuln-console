// src/core/injection.js
// Active injection checks: SQLi, reflected XSS, and path traversal.
// Called from engine.js Phase 3 after crawler builds the SiteModel.

import { moduleDefById } from './moduleRegistry.js';
import { Finding, Evidence } from './models.js';
import { httpGetText } from './httpClient.js';

// ── Severity order for dedup: only report the worst hit per param per module ───
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Run all active injection checks against parameterized endpoints in the SiteModel.
 *
 * @param {Object} opts
 * @param {Object} opts.ctx            - EngineContext
 * @param {Object} opts.target         - Target instance
 * @param {import('./siteModel.js').SiteModel} opts.siteModel
 * @param {Array}  opts.enabledModules - list of ModuleDef
 * @param {Object} opts.engineConfig   - EngineConfig
 */
export async function runActiveInjectionChecks({ ctx, target, siteModel, enabledModules, engineConfig }) {
  const sqliEnabled     = moduleEnabled(enabledModules, 'injection.sqli.basic');
  const xssEnabled      = moduleEnabled(enabledModules, 'injection.xss.reflected_basic');
  const traversalEnabled = moduleEnabled(enabledModules, 'injection.path_traversal.basic');

  if (!sqliEnabled && !xssEnabled && !traversalEnabled) {
    ctx.log('Active injection: no injection modules enabled for this policy — skipping.');
    return;
  }

  const base = normalizeBase(target.host);

  // ── Endpoint-based probes (SQLi + XSS) ──────────────────────────────────────
  const endpoints = siteModel.getParamEndpoints();

  if ((sqliEnabled || xssEnabled) && endpoints.length === 0) {
    ctx.log('Active injection: crawler found no parameterized endpoints — skipping SQLi/XSS probes.');
    ctx.log('TIP: Try policy_aggressive on a target with forms or query-string pages.');
  }

  if (endpoints.length > 0) {
    ctx.log(`Active injection: ${endpoints.length} parameterized endpoint(s) to probe.`);
  }

  let totalProbes = 0;
  const MAX_PROBES = 100;

  for (const ep of endpoints) {
    if (totalProbes >= MAX_PROBES) {
      ctx.log(`Active injection: probe cap (${MAX_PROBES}) reached. Stopping endpoint probes.`);
      break;
    }

    const urlBase = base.replace(/\/$/, '') + ep.url;
    const paramNames = ep.params.map((p) => p.name).filter(Boolean);
    if (!paramNames.length) continue;

    if (sqliEnabled) {
      const count = await runSqliOnEndpoint({ ctx, target, urlBase, paramNames, engineConfig });
      totalProbes += count;
    }
    if (xssEnabled && totalProbes < MAX_PROBES) {
      const count = await runXssOnEndpoint({ ctx, target, urlBase, paramNames, engineConfig });
      totalProbes += count;
    }
  }

  // ── Path traversal (runs against the base URL directly, no params needed) ───
  if (traversalEnabled) {
    await runPathTraversal({ ctx, target, base, engineConfig });
  }

  ctx.log(`Active injection complete. Total probes sent: ${totalProbes}`);
}

// ── SQLi ──────────────────────────────────────────────────────────────────────
async function runSqliOnEndpoint({ ctx, target, urlBase, paramNames, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const mod = moduleDefById['injection.sqli.basic'];
  if (!mod) return 0;

  const config    = mod.configSchema?.properties || {};
  const payloads  = (config.payloads?.default     || ["'", '"', "' OR '1'='1", '") OR 1=1--']);
  const errPats   = (config.errorPatterns?.default || ['SQL syntax','mysql_fetch','mysqli','psql:','ORA-','ODBC','sqlite','syntax error']);

  let probes = 0;

  for (const paramName of paramNames) {
    let hitThisParam = false;

    for (const payload of payloads) {
      if (hitThisParam) break;
      const url = injectQueryParam(urlBase, paramName, payload);
      ctx.log(`SQLi probe [${paramName}]: ${url}`);

      try {
        const res = await httpGetText({ fetchAdapter, url });
        probes++;

        if (res.status >= 500 || looksLikeSqlError(res.body, errPats)) {
          const finding = new Finding({
            projectId:   ctx.project.id,
            scanJobId:   ctx.job.id,
            targetId:    target.id,
            moduleId:    'injection.sqli.basic',
            title:       'Possible SQL Injection (error-based)',
            shortDescription: `SQL-error-like response when injecting into parameter "${paramName}" at ${urlBase}.`,
            detailedDescription:
              'A SQL-like error response was observed after injecting test payloads into a query parameter. ' +
              'This indicates a likely SQL injection vulnerability. The database may be directly injectable. ' +
              'Validate manually and escalate to critical if confirmed.',
            severity:    'high',
            category:    'injection',
            owaspTag:    'A03-Injection',
            cweTag:      'CWE-89',
          });
          const evidence = new Evidence({
            findingId:              finding.id,
            url,
            method:                 'GET',
            responseStatus:        res.status,
            responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
            responseBodySnippet:   res.body.slice(0, 2048),
            matchedPattern:        `SQL error signature (payload: ${payload})`,
          });
          ctx.addFinding(finding);
          ctx.addEvidence(evidence);
          ctx.log(`🔴 HIGH: SQL injection indicated — param="${paramName}" url=${url}`);
          hitThisParam = true;
        }
      } catch (err) {
        ctx.log(`SQLi probe error: ${err.message || err}`);
        probes++;
      }
    }
  }

  return probes;
}

// ── Reflected XSS ─────────────────────────────────────────────────────────────
async function runXssOnEndpoint({ ctx, target, urlBase, paramNames, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const mod = moduleDefById['injection.xss.reflected_basic'];
  if (!mod) return 0;

  const config   = mod.configSchema?.properties || {};
  const payloads = (config.payloads?.default || ['<xss-test-123>', '"onmouseover="xss123()', '<script>alert(123)</script>']);

  let probes = 0;

  for (const paramName of paramNames) {
    let hitThisParam = false;

    for (const payload of payloads) {
      if (hitThisParam) break;
      const url = injectQueryParam(urlBase, paramName, payload);
      ctx.log(`XSS probe [${paramName}]: ${url}`);

      try {
        const res = await httpGetText({ fetchAdapter, url });
        probes++;

        // Check for raw reflection — payload appears unencoded in response body.
        const bodySlice = res.body.slice(0, 65536);
        if (res.status >= 200 && res.status < 500 && bodySlice.includes(payload)) {
          const finding = new Finding({
            projectId:   ctx.project.id,
            scanJobId:   ctx.job.id,
            targetId:    target.id,
            moduleId:    'injection.xss.reflected_basic',
            title:       'Possible Reflected XSS',
            shortDescription: `XSS probe payload reflected unencoded for parameter "${paramName}" at ${urlBase}.`,
            detailedDescription:
              'A reflected XSS test string was returned unencoded in the HTTP response when injected into a query parameter. ' +
              'This indicates a likely reflected cross-site scripting vulnerability. ' +
              'Validate manually — confirm the payload is not sanitized by a downstream filter.',
            severity:    'medium',
            category:    'injection',
            owaspTag:    'A03-Injection',
            cweTag:      'CWE-79',
          });
          const evidence = new Evidence({
            findingId:              finding.id,
            url,
            method:                 'GET',
            responseStatus:        res.status,
            responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
            responseBodySnippet:   bodySlice.slice(0, 2048),
            matchedPattern:        `Reflected payload: ${payload}`,
          });
          ctx.addFinding(finding);
          ctx.addEvidence(evidence);
          ctx.log(`🟠 MEDIUM: reflected XSS indicated — param="${paramName}" url=${url}`);
          hitThisParam = true;
        }
      } catch (err) {
        ctx.log(`XSS probe error: ${err.message || err}`);
        probes++;
      }
    }
  }

  return probes;
}

// ── Path Traversal ────────────────────────────────────────────────────────────
async function runPathTraversal({ ctx, target, base, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const mod = moduleDefById['injection.path_traversal.basic'];
  if (!mod) return;

  const config   = mod.configSchema?.properties || {};
  const payloads = config.payloads?.default || [];
  const windows  = config.windowsPayloads?.default || [];
  const sigs     = config.signatures?.default || [];
  const allPayloads = [...payloads, ...windows];

  ctx.log(`Path traversal: testing ${allPayloads.length} paths against ${base}`);

  let hit = false;

  for (const payload of allPayloads) {
    if (hit) break;
    const url = base.replace(/\/$/, '') + payload;
    ctx.log(`Path traversal probe: ${url}`);

    try {
      const res = await httpGetText({ fetchAdapter, url });

      if (res.status === 200 && looksLikePathTraversalHit(res.body, sigs)) {
        const finding = new Finding({
          projectId:   ctx.project.id,
          scanJobId:   ctx.job.id,
          targetId:    target.id,
          moduleId:    'injection.path_traversal.basic',
          title:       'Possible Path Traversal / Local File Read',
          shortDescription: `Path traversal test payload returned content matching sensitive file signatures at ${url}.`,
          detailedDescription:
            'A directory traversal payload returned a response body containing signatures consistent with sensitive OS files ' +
            '(e.g., /etc/passwd or Windows win.ini). This indicates a possible arbitrary file read vulnerability. ' +
            'Validate manually — confirm the response contains actual file content and is not a generic 200 page.',
          severity:    'critical',
          category:    'injection',
          owaspTag:    'A01-Broken-Access-Control',
          cweTag:      'CWE-22',
        });
        const evidence = new Evidence({
          findingId:              finding.id,
          url,
          method:                 'GET',
          responseStatus:        res.status,
          responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
          responseBodySnippet:   res.body.slice(0, 2048),
          matchedPattern:        `Path traversal file signature match`,
        });
        ctx.addFinding(finding);
        ctx.addEvidence(evidence);
        ctx.log(`🔴 CRITICAL: possible path traversal file read at ${url}`);
        hit = true;
      }
    } catch (err) {
      ctx.log(`Path traversal probe error: ${err.message || err}`);
    }
  }

  if (!hit) ctx.log('Path traversal: no hits detected.');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function moduleEnabled(enabledModules, id) {
  return enabledModules.some((m) => m.id === id);
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

function looksLikeSqlError(body, patterns) {
  const upper = body.slice(0, 4096).toUpperCase();
  return patterns.some((p) => upper.includes(p.toUpperCase()));
}

function looksLikePathTraversalHit(body, sigs) {
  const snippet = body.slice(0, 4096);
  return sigs.some((sig) => snippet.includes(sig));
}
