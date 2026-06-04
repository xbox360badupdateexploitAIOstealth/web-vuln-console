// src/core/injection.js
// Active injection checks (SQLi, reflected XSS) using SiteModel endpoints.

import { moduleDefById } from './moduleRegistry.js';
import { Finding, Evidence } from './models.js';
import { httpGetText } from './httpClient.js';

/**
 * Run active injection checks for enabled modules against endpoints in SiteModel.
 *
 * @param {Object} opts
 * @param {Object} opts.ctx - EngineContext
 * @param {Object} opts.target - Target instance
 * @param {import('./siteModel.js').SiteModel} opts.siteModel
 * @param {Array} opts.enabledModules - list of ModuleDef
 * @param {Object} opts.engineConfig - EngineConfig
 */
export async function runActiveInjectionChecks({ ctx, target, siteModel, enabledModules, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const base = normalizeBase(target.host);

  const sqliEnabled = enabledModules.some((m) => m.id === 'injection.sqli.basic');
  const xssEnabled = enabledModules.some((m) => m.id === 'injection.xss.reflected_basic');

  if (!sqliEnabled && !xssEnabled) {
    ctx.log('Active injection: no injection modules enabled for this policy.');
    return;
  }

  const endpoints = siteModel.getParamEndpoints();
  if (!endpoints.length) {
    ctx.log('Active injection: no parameterized endpoints discovered, skipping.');
    return;
  }

  ctx.log(`Active injection: ${endpoints.length} parameterized endpoints to probe.`);

  let totalProbes = 0;
  const maxProbes = 80; // simple safety cap per target for now

  for (const ep of endpoints) {
    if (totalProbes >= maxProbes) {
      ctx.log('Active injection: probe limit reached for this target, stopping.');
      break;
    }

    const urlBase = base.replace(/\/$/, '') + ep.url;

    const paramNames = ep.params.map((p) => p.name);
    if (!paramNames.length) continue;

    if (sqliEnabled) {
      totalProbes += await runSqlInjectionOnEndpoint({ ctx, target, urlBase, paramNames, engineConfig });
      if (totalProbes >= maxProbes) break;
    }

    if (xssEnabled) {
      totalProbes += await runXssOnEndpoint({ ctx, target, urlBase, paramNames, engineConfig });
      if (totalProbes >= maxProbes) break;
    }
  }

  ctx.log(`Active injection complete. Total probes sent: ${totalProbes}`);
}

async function runSqlInjectionOnEndpoint({ ctx, target, urlBase, paramNames, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const mod = moduleDefById['injection.sqli.basic'];
  if (!mod) return 0;
  const config = mod.configSchema?.properties || {};
  const payloads = (config.payloads?.default || []).slice(0, 3); // limit for now
  const errorPatterns = config.errorPatterns?.default || [];

  let probes = 0;

  for (const paramName of paramNames) {
    for (const payload of payloads) {
      const url = injectQueryParam(urlBase, paramName, payload);
      ctx.log(`SQLi probe: ${url}`);
      const res = await httpGetText({ fetchAdapter, url });
      probes++;

      if (res.status >= 500 || looksLikeSqlError(res.body, errorPatterns)) {
        const finding = new Finding({
          projectId: ctx.project.id,
          scanJobId: ctx.job.id,
          targetId: target.id,
          moduleId: 'injection.sqli.basic',
          title: 'Possible SQL injection (error-based)',
          shortDescription: `Error-like response when injecting into parameter "${paramName}" at ${urlBase}.`,
          detailedDescription:
            'A SQL-like error response was observed after injecting test payloads into a query parameter. This suggests a potential SQL injection vulnerability and should be manually validated.',
          severity: 'high',
          category: 'injection',
          owaspTag: 'A03-Injection',
        });
        const evidence = new Evidence({
          findingId: finding.id,
          url,
          method: 'GET',
          responseStatus: res.status,
          responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512),
          responseBodySnippet: res.body.slice(0, 2048),
          matchedPattern: 'SQL error signature',
        });
        ctx.addFinding(finding);
        ctx.addEvidence(evidence);
        ctx.log(`HIGH: possible SQL injection indicated at ${url}`);
        return probes; // one hit is enough at this endpoint for now
      }
    }
  }

  return probes;
}

async function runXssOnEndpoint({ ctx, target, urlBase, paramNames, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const mod = moduleDefById['injection.xss.reflected_basic'];
  if (!mod) return 0;
  const config = mod.configSchema?.properties || {};
  const payloads = (config.payloads?.default || []).slice(0, 2); // limit for now

  let probes = 0;

  for (const paramName of paramNames) {
    for (const payload of payloads) {
      const url = injectQueryParam(urlBase, paramName, payload);
      ctx.log(`XSS probe: ${url}`);
      const res = await httpGetText({ fetchAdapter, url });
      probes++;

      if (res.status >= 200 && res.status < 500 && res.body.includes(payload)) {
        const finding = new Finding({
          projectId: ctx.project.id,
          scanJobId: ctx.job.id,
          targetId: target.id,
          moduleId: 'injection.xss.reflected_basic',
          title: 'Possible reflected XSS',
          shortDescription: `Reflected XSS test payload echoed for parameter "${paramName}" at ${urlBase}.`,
          detailedDescription:
            'A reflected XSS test string was found unencoded in the HTTP response when injected into a query parameter. This suggests a possible reflected cross-site scripting vulnerability and should be manually validated.',
          severity: 'medium',
          category: 'injection',
          owaspTag: 'A03-Injection',
        });
        const evidence = new Evidence({
          findingId: finding.id,
          url,
          method: 'GET',
          responseStatus: res.status,
          responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512),
          responseBodySnippet: res.body.slice(0, 2048),
          matchedPattern: 'Reflected XSS payload',
        });
        ctx.addFinding(finding);
        ctx.addEvidence(evidence);
        ctx.log(`MEDIUM: possible reflected XSS indicated at ${url}`);
        return probes;
      }
    }
  }

  return probes;
}

function normalizeBase(host) {
  // host is expected to include scheme; if not, default to https.
  if (!/^https?:\/\//i.test(host)) {
    return `https://${host}`;
  }
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
