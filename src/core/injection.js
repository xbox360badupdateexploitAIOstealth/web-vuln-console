// src/core/injection.js
// Active injection checks: SQLi, reflected XSS, path traversal, command injection, SSTI, file upload.
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
  const sqliEnabled       = moduleEnabled(enabledModules, 'injection.sqli.basic');
  const xssEnabled        = moduleEnabled(enabledModules, 'injection.xss.reflected_basic');
  const traversalEnabled  = moduleEnabled(enabledModules, 'injection.path_traversal.basic');
  const cmdiEnabled       = moduleEnabled(enabledModules, 'injection.cmdi.basic');
  const sstiEnabled       = moduleEnabled(enabledModules, 'injection.ssti.basic');
  const uploadEnabled     = moduleEnabled(enabledModules, 'injection.fileupload.detect');

  if (!sqliEnabled && !xssEnabled && !traversalEnabled && !cmdiEnabled && !sstiEnabled && !uploadEnabled) {
    ctx.log('Active injection: no injection modules enabled for this policy — skipping.');
    return;
  }

  const base = normalizeBase(target.host);

  // ── Endpoint-based probes (SQLi + XSS + CMDi + SSTI) ────────────────────────
  const endpoints = siteModel.getParamEndpoints();

  if ((sqliEnabled || xssEnabled || cmdiEnabled || sstiEnabled) && endpoints.length === 0) {
    ctx.log('Active injection: crawler found no parameterized endpoints — skipping param-based probes.');
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
    if (cmdiEnabled && totalProbes < MAX_PROBES) {
      const count = await runCommandInjection({ ctx, target, urlBase, paramNames, engineConfig });
      totalProbes += count;
    }
    if (sstiEnabled && totalProbes < MAX_PROBES) {
      const count = await runSstiChecks({ ctx, target, urlBase, paramNames, engineConfig });
      totalProbes += count;
    }
  }

  // ── Path traversal (runs against the base URL directly, no params needed) ───
  if (traversalEnabled) {
    await runPathTraversal({ ctx, target, base, engineConfig });
  }

  // ── File upload detection (form-based, uses SiteModel endpoints) ─────────────
  if (uploadEnabled) {
    await runFileUploadDetect({ ctx, target, base, siteModel, engineConfig });
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

// ── Command Injection ─────────────────────────────────────────────────────────
async function runCommandInjection({ ctx, target, urlBase, paramNames, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const mod = moduleDefById['injection.cmdi.basic'];
  if (!mod) return 0;

  const config   = mod.configSchema?.properties || {};
  const payloads = config.payloads?.default || [];
  const sigs     = config.signatures?.default || [];

  let probes = 0;

  for (const paramName of paramNames) {
    let hitThisParam = false;

    for (const payload of payloads) {
      if (hitThisParam) break;
      const url = injectQueryParam(urlBase, paramName, payload);
      ctx.log(`CMDi probe [${paramName}]: ${url}`);

      try {
        const res = await httpGetText({ fetchAdapter, url });
        probes++;

        const bodySlice = res.body.slice(0, 8192);
        if (res.status >= 200 && res.status < 500 && looksLikeCmdiHit(bodySlice, sigs)) {
          const finding = new Finding({
            projectId:   ctx.project.id,
            scanJobId:   ctx.job.id,
            targetId:    target.id,
            moduleId:    'injection.cmdi.basic',
            title:       'Possible OS Command Injection',
            shortDescription: `Command injection payload in parameter "${paramName}" produced OS-level output at ${urlBase}.`,
            detailedDescription:
              'A response body containing OS command execution output (uid=, root:, or similar) was observed ' +
              'after injecting OS command separator payloads into a query parameter. ' +
              'This indicates a potential OS command injection vulnerability (RCE). ' +
              'Validate manually — confirm output is not coincidental content from the application.',
            severity:    'critical',
            category:    'injection',
            owaspTag:    'A03-Injection',
            cweTag:      'CWE-78',
          });
          const evidence = new Evidence({
            findingId:              finding.id,
            url,
            method:                 'GET',
            responseStatus:        res.status,
            responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
            responseBodySnippet:   bodySlice.slice(0, 2048),
            matchedPattern:        `CMDi OS output signature (payload: ${payload})`,
          });
          ctx.addFinding(finding);
          ctx.addEvidence(evidence);
          ctx.log(`🔴 CRITICAL: OS command injection indicated — param="${paramName}" url=${url}`);
          hitThisParam = true;
        }
      } catch (err) {
        ctx.log(`CMDi probe error: ${err.message || err}`);
        probes++;
      }
    }
  }

  return probes;
}

// ── SSTI ──────────────────────────────────────────────────────────────────────
async function runSstiChecks({ ctx, target, urlBase, paramNames, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const mod = moduleDefById['injection.ssti.basic'];
  if (!mod) return 0;

  const config   = mod.configSchema?.properties || {};
  const payloads = config.payloads?.default || [];
  const errPats  = config.errorPatterns?.default || [];

  let probes = 0;

  for (const paramName of paramNames) {
    let hitThisParam = false;

    for (const { payload, expected } of payloads) {
      if (hitThisParam) break;
      const url = injectQueryParam(urlBase, paramName, payload);
      ctx.log(`SSTI probe [${paramName}]: ${url}`);

      try {
        const res = await httpGetText({ fetchAdapter, url });
        probes++;

        const bodySlice = res.body.slice(0, 16384);
        const mathHit   = expected && bodySlice.includes(expected);
        const errorHit  = errPats.some((p) => bodySlice.toLowerCase().includes(p.toLowerCase()));

        if (res.status >= 200 && res.status < 500 && (mathHit || errorHit)) {
          const matchNote = mathHit
            ? `Math result "${expected}" reflected (payload: ${payload})`
            : `Template engine error string matched (payload: ${payload})`;

          const finding = new Finding({
            projectId:   ctx.project.id,
            scanJobId:   ctx.job.id,
            targetId:    target.id,
            moduleId:    'injection.ssti.basic',
            title:       'Possible Server-Side Template Injection (SSTI)',
            shortDescription: `SSTI probe in parameter "${paramName}" produced template execution output at ${urlBase}.`,
            detailedDescription:
              'A template math expression or template engine error was detected in the response after injecting ' +
              'template syntax payloads into a query parameter. ' +
              'Server-side template injection can lead to remote code execution depending on the template engine. ' +
              'Validate manually — confirm the numeric result or error is from template evaluation, not coincidence.',
            severity:    'critical',
            category:    'injection',
            owaspTag:    'A03-Injection',
            cweTag:      'CWE-94',
          });
          const evidence = new Evidence({
            findingId:              finding.id,
            url,
            method:                 'GET',
            responseStatus:        res.status,
            responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
            responseBodySnippet:   bodySlice.slice(0, 2048),
            matchedPattern:        matchNote,
          });
          ctx.addFinding(finding);
          ctx.addEvidence(evidence);
          ctx.log(`🔴 CRITICAL: SSTI indicated — param="${paramName}" url=${url}`);
          hitThisParam = true;
        }
      } catch (err) {
        ctx.log(`SSTI probe error: ${err.message || err}`);
        probes++;
      }
    }
  }

  return probes;
}

// ── File Upload Detection ─────────────────────────────────────────────────────
async function runFileUploadDetect({ ctx, target, base, siteModel, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const mod = moduleDefById['injection.fileupload.detect'];
  if (!mod) return;

  // Collect all endpoints that have file-type input fields from the SiteModel.
  // siteModel.getUploadEndpoints() returns [{url, fieldName}] if available,
  // otherwise fall back to heuristic path list.
  const uploadEndpoints = typeof siteModel.getUploadEndpoints === 'function'
    ? siteModel.getUploadEndpoints()
    : [];

  const config        = mod.configSchema?.properties || {};
  const fallbackPaths = config.commonUploadPaths?.default || [];
  const testExtensions = config.testExtensions?.default || [];
  const dangerSigs    = config.dangerSignatures?.default || [];

  // If crawler found no upload forms, probe common upload endpoint paths.
  const targets = uploadEndpoints.length > 0
    ? uploadEndpoints.map((ep) => ({ url: base.replace(/\/$/, '') + ep.url, fieldName: ep.fieldName || 'file' }))
    : fallbackPaths.map((p) => ({ url: base.replace(/\/$/, '') + p, fieldName: 'file' }));

  if (targets.length === 0) {
    ctx.log('File upload detect: no upload endpoints or fallback paths to probe.');
    return;
  }

  ctx.log(`File upload detect: probing ${targets.length} endpoint(s).`);

  for (const { url, fieldName } of targets) {
    // Step 1: confirm endpoint is reachable (GET probe)
    let reachable = false;
    try {
      const res = await httpGetText({ fetchAdapter, url });
      reachable = res.status >= 200 && res.status < 500;
    } catch { /* unreachable */ }

    if (!reachable) continue;

    // Step 2: POST a benign .txt file via multipart/form-data
    let benignAccepted = false;
    const benignName   = `test-${Date.now()}.txt`;
    const benignBody   = '--BOUNDARY\r\nContent-Disposition: form-data; name="' + fieldName + '"; filename="' + benignName + '"\r\nContent-Type: text/plain\r\n\r\ntest\r\n--BOUNDARY--';

    try {
      const res = await (engineConfig.fetchAdapter || fetch)(url, {
        method:  'POST',
        headers: { 'Content-Type': 'multipart/form-data; boundary=BOUNDARY' },
        body:    benignBody,
        signal:  AbortSignal.timeout(8000),
      });
      const body = typeof res.text === 'function' ? await res.text() : '';
      benignAccepted = res.status >= 200 && res.status < 400 &&
        (body.toLowerCase().includes(benignName) || body.toLowerCase().includes('success') ||
         body.toLowerCase().includes('uploaded'));
    } catch { /* ignore */ }

    if (!benignAccepted) continue;
    ctx.log(`File upload detect: benign upload accepted at ${url}`);

    // Step 3: probe dangerous extension acceptance
    for (const ext of testExtensions) {
      const testName = `test-${Date.now()}${ext}`;
      const testBody = '--BOUNDARY\r\nContent-Disposition: form-data; name="' + fieldName + '"; filename="' + testName + '"\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo 1; ?>\r\n--BOUNDARY--';

      try {
        const res = await (engineConfig.fetchAdapter || fetch)(url, {
          method:  'POST',
          headers: { 'Content-Type': 'multipart/form-data; boundary=BOUNDARY' },
          body:    testBody,
          signal:  AbortSignal.timeout(8000),
        });
        const body = typeof res.text === 'function' ? await res.text() : '';
        const bodyLow = body.toLowerCase();

        // Hit: server accepted the dangerous extension (200-level, no rejection)
        const rejected = dangerSigs.some((sig) => bodyLow.includes(sig.toLowerCase()));
        const accepted = res.status >= 200 && res.status < 400 &&
          (bodyLow.includes(testName) || bodyLow.includes('success') || bodyLow.includes('uploaded'));

        if (accepted && !rejected) {
          const finding = new Finding({
            projectId:   ctx.project.id,
            scanJobId:   ctx.job.id,
            targetId:    target.id,
            moduleId:    'injection.fileupload.detect',
            title:       `Dangerous File Upload Accepted (${ext})`,
            shortDescription: `Upload endpoint at ${url} accepted a file with extension ${ext} without apparent rejection.`,
            detailedDescription:
              `The upload endpoint accepted a test file with the extension "${ext}" without returning an error or rejection message. ` +
              'If this extension is executable on the server (e.g., PHP, JSP, ASPX), an attacker may be able to upload a web shell and achieve remote code execution. ' +
              'Validate manually — attempt to access the uploaded file and confirm execution is possible.',
            severity:    'critical',
            category:    'injection',
            owaspTag:    'A03-Injection',
            cweTag:      'CWE-434',
          });
          const evidence = new Evidence({
            findingId:              finding.id,
            url,
            method:                 'POST',
            responseStatus:        res.status,
            responseHeadersSnippet: '',
            responseBodySnippet:   body.slice(0, 2048),
            matchedPattern:        `Extension ${ext} accepted without rejection`,
          });
          ctx.addFinding(finding);
          ctx.addEvidence(evidence);
          ctx.log(`🔴 CRITICAL: dangerous file extension accepted — ext=${ext} url=${url}`);
        }
      } catch { /* ignore */ }
    }
  }
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

function looksLikeCmdiHit(body, sigs) {
  const snippet = body.slice(0, 4096);
  return sigs.some((sig) => snippet.includes(sig));
}
