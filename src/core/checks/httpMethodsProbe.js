// src/core/checks/httpMethodsProbe.js
// Passive check: detect dangerous or misconfigured HTTP methods.
//
// Vulnerability classes:
//
//   TRACE/TRACK enabled — MEDIUM
//     Cross-Site Tracing (XST): allows attackers to read HttpOnly cookies
//     and Authorization headers reflected in TRACE responses, bypassing
//     browser protections.
//
//   PUT enabled on non-API paths — HIGH
//     Arbitrary file upload to the server. Classic WebDAV misconfiguration.
//
//   DELETE enabled on non-API paths — HIGH
//     Arbitrary file deletion from the server.
//
//   CONNECT enabled — MEDIUM
//     Server can be used as an HTTP tunnel proxy.
//
//   Excessively broad OPTIONS — LOW/INFO
//     Allow header lists overly permissive methods not needed for the app.
//
// Strategy:
//   1. Send OPTIONS to root — parse Allow / Public headers
//   2. Confirm TRACE by actually sending a TRACE request and checking reflection
//   3. Flag PUT/DELETE if present on non-API paths
//   4. Check a sample of siteModel endpoints for per-endpoint method exposure
//
// Wire-up (engine.js Phase 2.5d — after corsMisconfig, before injection):
//   import { runHttpMethodsProbe } from './checks/httpMethodsProbe.js';
//   if (moduleEnabled(enabledModules, 'misconfig.http_methods')) {
//     await runHttpMethodsProbe({ ctx, target, baseUrl, siteModel, fetchAdapter });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

const MAX_ENDPOINTS = 10;

// Methods we actively flag when found in Allow header
const DANGEROUS_METHODS = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT', 'PATCH', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'];
// WebDAV methods — subset of dangerous that indicate WebDAV is enabled
const WEBDAV_METHODS     = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'];

// ── Main entry ─────────────────────────────────────────────────────────────

export async function runHttpMethodsProbe({ ctx, target, baseUrl, siteModel, fetchAdapter }) {
  ctx.log('[httpMethods] Starting HTTP methods probe...');
  const base = baseUrl.replace(/\/$/, '');

  // Probe root
  await probeUrlMethods({ ctx, target, url: base + '/', base, fetchAdapter });

  // Probe a sample of siteModel endpoints
  const endpoints = siteModel?.getAllEndpoints?.() || [];
  for (const ep of endpoints.slice(0, MAX_ENDPOINTS)) {
    const url = base + ep.url;
    if (url === base + '/') continue;
    await probeUrlMethods({ ctx, target, url, base, fetchAdapter });
  }

  ctx.log('[httpMethods] Done.');
}

// ── Per-URL probe ─────────────────────────────────────────────────────────────

async function probeUrlMethods({ ctx, target, url, base, fetchAdapter }) {
  // Step 1: OPTIONS request
  ctx.log(`[httpMethods] OPTIONS ${url}`);
  let optionsRes;
  try {
    optionsRes = await httpGetText({ fetchAdapter, url, method: 'OPTIONS' });
  } catch (e) {
    ctx.log(`[httpMethods] OPTIONS error at ${url}: ${e.message || e}`);
    return;
  }

  const allowHeader  = getHeader(optionsRes.headers, 'allow') || getHeader(optionsRes.headers, 'public') || '';
  const allowMethods = parseMethodList(allowHeader);

  if (allowMethods.length > 0) {
    ctx.log(`[httpMethods] Allow header at ${url}: ${allowMethods.join(', ')}`);
  }

  // Check for TRACE/TRACK in Allow header, then confirm with real TRACE request
  const traceAllowed = allowMethods.some((m) => m === 'TRACE' || m === 'TRACK');
  if (traceAllowed) {
    await confirmTrace({ ctx, target, url, fetchAdapter });
  }

  // Check for PUT / DELETE
  const putAllowed    = allowMethods.includes('PUT');
  const deleteAllowed = allowMethods.includes('DELETE');
  const isApiPath     = /^\/api[\/\s]|graphql|rest|v\d+\//i.test(url);

  if (putAllowed && !isApiPath) {
    reportMethod({ ctx, target, url, method: 'PUT',
      title:    'HTTP PUT Method Enabled',
      shortDesc: `HTTP PUT is allowed at ${url} — may allow arbitrary file upload.`,
      detail:
        'The HTTP PUT method is enabled on a non-API path. In misconfigured web servers (particularly WebDAV), ' +
        'this allows attackers to upload arbitrary files to the server, potentially including web shells. ' +
        'Remediation: Disable PUT via web server config unless explicitly required for an API.',
      severity: 'high',
      cwe: 'CWE-434',
      allowHeader,
    });
  }

  if (deleteAllowed && !isApiPath) {
    reportMethod({ ctx, target, url, method: 'DELETE',
      title:    'HTTP DELETE Method Enabled',
      shortDesc: `HTTP DELETE is allowed at ${url} — may allow arbitrary file deletion.`,
      detail:
        'The HTTP DELETE method is enabled on a non-API path. This may allow attackers to delete arbitrary ' +
        'files from the server. Remediation: Disable DELETE via web server config unless explicitly required.',
      severity: 'high',
      cwe: 'CWE-650',
      allowHeader,
    });
  }

  // WebDAV methods
  const webdavFound = allowMethods.filter((m) => WEBDAV_METHODS.includes(m));
  if (webdavFound.length > 0) {
    reportMethod({ ctx, target, url, method: webdavFound.join(', '),
      title:    'WebDAV Methods Enabled',
      shortDesc: `WebDAV methods detected at ${url}: ${webdavFound.join(', ')}.`,
      detail:
        'WebDAV methods are enabled on this path. WebDAV allows filesystem-level operations over HTTP ' +
        '(copy, move, lock, property queries). If misconfigured, attackers can enumerate directory contents, ' +
        'upload files, or move/delete resources. Remediation: Disable WebDAV unless required.',
      severity: 'medium',
      cwe: 'CWE-16',
      allowHeader,
    });
  }

  // CONNECT
  if (allowMethods.includes('CONNECT')) {
    reportMethod({ ctx, target, url, method: 'CONNECT',
      title:    'HTTP CONNECT Method Enabled',
      shortDesc: `HTTP CONNECT is allowed at ${url} — server may function as an open proxy.`,
      detail:
        'The HTTP CONNECT method is enabled. This can allow the server to be used as an HTTP tunnel proxy, ' +
        'enabling attackers to proxy traffic through the server to reach internal network resources.',
      severity: 'medium',
      cwe: 'CWE-441',
      allowHeader,
    });
  }

  function reportMethod({ ctx, target, url, method, title, shortDesc, detail, severity, cwe, allowHeader }) {
    ctx.log(`\uD83D\uDFE0 ${severity.toUpperCase()}: ${title} at ${url}`);
    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'misconfig.http_methods',
      title,
      shortDescription:    shortDesc,
      detailedDescription: detail,
      severity,
      category: 'misconfig',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag:   cwe,
    });
    ctx.addFinding(finding);
    ctx.addEvidence(new Evidence({
      findingId:              finding.id,
      url,
      method:                 'OPTIONS',
      responseStatus:         optionsRes.status,
      responseHeadersSnippet: JSON.stringify(optionsRes.headers || {}).slice(0, 512),
      responseBodySnippet:    (optionsRes.body || '').slice(0, 512),
      matchedPattern:         `Allow: ${allowHeader} | Flagged: ${method}`,
    }));
  }
}

// ── TRACE confirmation ────────────────────────────────────────────────────────────

const TRACE_MARKER = 'X-WVC-Trace-Test';

async function confirmTrace({ ctx, target, url, fetchAdapter }) {
  ctx.log(`[httpMethods] Confirming TRACE at ${url}`);
  let res;
  try {
    res = await httpGetText({
      fetchAdapter,
      url,
      method:  'TRACE',
      headers: { [TRACE_MARKER]: 'probe-1234' },
    });
  } catch (e) {
    ctx.log(`[httpMethods] TRACE confirm error: ${e.message || e}`);
    return;
  }

  const body = res.body || '';
  // TRACE echoes the full request back — confirm by looking for our marker or TRACE in body
  const confirmed = body.includes(TRACE_MARKER) || body.toUpperCase().startsWith('TRACE ');

  if (!confirmed && res.status !== 200) return;

  ctx.log(`\uD83D\uDFE1 MEDIUM: HTTP TRACE confirmed at ${url}`);

  const finding = new Finding({
    projectId:   ctx.project.id,
    scanJobId:   ctx.job.id,
    targetId:    target.id,
    moduleId:    'misconfig.http_methods',
    title:       'HTTP TRACE Method Enabled (XST Risk)',
    shortDescription:
      `HTTP TRACE is enabled at ${url}. Enables Cross-Site Tracing (XST) attacks.`,
    detailedDescription:
      'The HTTP TRACE method is enabled. TRACE causes the server to echo the full request back to the client. ' +
      'Combined with Cross-Site Scripting (XSS), this enables Cross-Site Tracing (XST) attacks where an attacker ' +
      'can read HttpOnly cookies and Authorization headers that would otherwise be inaccessible to JavaScript. ' +
      'Remediation: Disable TRACE in web server configuration (Apache: TraceEnable Off, Nginx: default disabled).',
    severity: 'medium',
    category: 'misconfig',
    owaspTag: 'A05-Security-Misconfiguration',
    cweTag:   'CWE-693',
  });
  ctx.addFinding(finding);
  ctx.addEvidence(new Evidence({
    findingId:              finding.id,
    url,
    method:                 'TRACE',
    responseStatus:         res.status,
    responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
    responseBodySnippet:    body.slice(0, 1024),
    matchedPattern:         confirmed ? `TRACE response echoed request (marker: ${TRACE_MARKER})` : 'TRACE returned 200',
  }));
}

// ── Helpers ──────────────────────────────────────────────────────────────

function getHeader(headers, name) {
  if (!headers) return null;
  return headers[name] || headers[name.toLowerCase()] || null;
}

function parseMethodList(allow) {
  if (!allow) return [];
  return allow
    .split(/[,\s]+/)
    .map((m) => m.trim().toUpperCase())
    .filter((m) => m.length > 0 && DANGEROUS_METHODS.includes(m));
}
