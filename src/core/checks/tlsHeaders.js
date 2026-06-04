// src/core/checks/tlsHeaders.js
// Task 3: Full TLS & Security Headers checker.
// Runs as part of Phase 1 passive checks for the tls.headers.basic module.
//
// Checks performed:
//  1. Plain HTTP access (TLS not enforced)
//  2. HSTS missing or weak
//  3. Missing security response headers (CSP, X-Frame-Options, etc.)
//  4. Server version banner leakage
//  5. Cookies without Secure / HttpOnly / SameSite flags

'use strict';
// NOTE: This file is loaded by the Node worker (CommonJS via engine shim).
// It uses require-style imports via the build pipeline.
import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';
import { moduleDefById }     from '../moduleRegistry.js';

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Run all TLS & security header checks for a target.
 *
 * @param {Object} opts
 * @param {Object}   opts.ctx           - EngineContext
 * @param {Object}   opts.target        - Target instance
 * @param {string}   opts.baseUrl       - https://... base URL
 * @param {Object}   opts.fetchAdapter
 */
export async function runTlsHeaderChecks({ ctx, target, baseUrl, fetchAdapter }) {
  const mod = moduleDefById['tls.headers.basic'];
  if (!mod) return;

  const requiredHeaders = mod.configSchema?.properties?.requiredHeaders?.default || [];

  ctx.log(`TLS/Headers: checking ${baseUrl}`);

  // Fetch the root once; all checks read from this single response.
  let res;
  try {
    res = await httpGetText({ fetchAdapter, url: baseUrl });
  } catch (err) {
    ctx.log(`TLS/Headers: failed to fetch ${baseUrl}: ${err.message || err}`);
    return;
  }

  const headers = res.headers; // already lower-cased by httpClient
  const headersSnippet = JSON.stringify(headers).slice(0, 1024);

  // ── 1. Plain HTTP downgrade check ─────────────────────────────────────────────
  if (/^http:\/\//i.test(baseUrl)) {
    const httpUrl = baseUrl;
    const httpsUrl = baseUrl.replace(/^http:\/\//i, 'https://');
    let redirectsToHttps = false;

    // Check if plain HTTP redirects to HTTPS.
    const redirectLoc = headers['location'] || '';
    if (res.status >= 300 && res.status < 400 && /^https:/i.test(redirectLoc)) {
      redirectsToHttps = true;
    }

    if (!redirectsToHttps) {
      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'tls.headers.basic',
        title:       'Site Accessible Over Plain HTTP (No HTTPS Redirect)',
        shortDescription: `${httpUrl} is accessible over unencrypted HTTP and does not redirect to HTTPS.`,
        detailedDescription:
          'The server responds to plain HTTP requests without redirecting the browser to the secure HTTPS version. ' +
          'Traffic sent over HTTP is transmitted in plaintext and is vulnerable to interception and tampering. ' +
          'Configure the server to return a 301 redirect from HTTP to HTTPS for all requests.',
        severity:  'high',
        category:  'tls',
        owaspTag:  'A02-Cryptographic-Failures',
        cweTag:    'CWE-319',
      });
      const evidence = new Evidence({
        findingId:              finding.id,
        url:                    httpUrl,
        method:                 'GET',
        responseStatus:        res.status,
        responseHeadersSnippet: headersSnippet,
        responseBodySnippet:   '',
        matchedPattern:        'HTTP 200 (no redirect to HTTPS)',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`🟠 HIGH: no HTTPS redirect at ${httpUrl}`);
    } else {
      ctx.log(`TLS: ${httpUrl} redirects to HTTPS ✓`);
    }
  }

  // ── 2. HSTS check ───────────────────────────────────────────────────────────────────
  const hsts = headers['strict-transport-security'] || '';
  if (!hsts) {
    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'tls.headers.basic',
      title:       'Missing Strict-Transport-Security (HSTS) Header',
      shortDescription: `The response at ${baseUrl} does not include a Strict-Transport-Security header.`,
      detailedDescription:
        'Without HSTS, browsers will not automatically upgrade HTTP connections to HTTPS after the first visit. ' +
        'This leaves users vulnerable to SSL stripping attacks. ' +
        'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      severity:  'medium',
      category:  'tls',
      owaspTag:  'A02-Cryptographic-Failures',
      cweTag:    'CWE-319',
    });
    const evidence = new Evidence({
      findingId:              finding.id,
      url:                    baseUrl,
      method:                 'GET',
      responseStatus:        res.status,
      responseHeadersSnippet: headersSnippet,
      responseBodySnippet:   '',
      matchedPattern:        'Strict-Transport-Security header absent',
    });
    ctx.addFinding(finding);
    ctx.addEvidence(evidence);
    ctx.log(`🟡 MEDIUM: HSTS header missing at ${baseUrl}`);
  } else {
    // Check max-age is adequate (recommend >= 1 year = 31536000)
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    if (maxAge < 31536000) {
      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'tls.headers.basic',
        title:       'Weak HSTS max-age (Less Than 1 Year)',
        shortDescription: `HSTS header present but max-age=${maxAge} is below the recommended minimum of 31536000 (1 year).`,
        detailedDescription:
          `The Strict-Transport-Security header is set with max-age=${maxAge}, which is below the OWASP-recommended minimum of 31,536,000 seconds (1 year). ` +
          'Short max-age values mean the HSTS protection expires quickly. Increase to at least 31536000 and add includeSubDomains.',
        severity:  'low',
        category:  'tls',
        owaspTag:  'A02-Cryptographic-Failures',
        cweTag:    'CWE-319',
      });
      const evidence = new Evidence({
        findingId:              finding.id,
        url:                    baseUrl,
        method:                 'GET',
        responseStatus:        res.status,
        responseHeadersSnippet: headersSnippet,
        responseBodySnippet:   '',
        matchedPattern:        `HSTS max-age=${maxAge} (too low)`,
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`🟡 LOW: weak HSTS max-age=${maxAge} at ${baseUrl}`);
    } else {
      ctx.log(`TLS: HSTS present and adequate (max-age=${maxAge}) ✓`);
    }
  }

  // ── 3. Missing security headers ──────────────────────────────────────────────────
  const HEADER_META = {
    'content-security-policy': {
      title:    'Missing Content-Security-Policy (CSP) Header',
      severity: 'medium',
      detail:
        'Without a Content-Security-Policy header the browser has no restriction on which scripts, styles, and resources can load. ' +
        'This significantly widens the attack surface for XSS. ' +
        'Add a strict CSP: Content-Security-Policy: default-src \'self\'; script-src \'self\'',
      cwe: 'CWE-1021',
    },
    'x-frame-options': {
      title:    'Missing X-Frame-Options Header (Clickjacking Risk)',
      severity: 'medium',
      detail:
        'Without X-Frame-Options or a frame-ancestors CSP directive the page can be embedded in an iframe on any origin. ' +
        'This enables clickjacking attacks. ' +
        'Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN',
      cwe: 'CWE-1021',
    },
    'x-content-type-options': {
      title:    'Missing X-Content-Type-Options Header',
      severity: 'low',
      detail:
        'Without X-Content-Type-Options: nosniff browsers may MIME-sniff responses away from the declared content-type. ' +
        'This can lead to script execution from non-script responses. ' +
        'Add: X-Content-Type-Options: nosniff',
      cwe: 'CWE-430',
    },
    'permissions-policy': {
      title:    'Missing Permissions-Policy Header',
      severity: 'info',
      detail:
        'The Permissions-Policy header (formerly Feature-Policy) is not present. ' +
        'This header lets you restrict browser features (camera, microphone, geolocation) per-origin. ' +
        'While not critical, it is a defence-in-depth best practice. ' +
        'Example: Permissions-Policy: camera=(), microphone=(), geolocation=()',
      cwe: 'CWE-693',
    },
    'referrer-policy': {
      title:    'Missing Referrer-Policy Header',
      severity: 'info',
      detail:
        'Without Referrer-Policy the browser may send the full URL (including query parameters) in the Referer header ' +
        'to third-party resources, potentially leaking sensitive data. ' +
        'Add: Referrer-Policy: strict-origin-when-cross-origin',
      cwe: 'CWE-116',
    },
  };

  for (const [headerKey, meta] of Object.entries(HEADER_META)) {
    // Skip HSTS — handled separately above.
    if (headerKey === 'strict-transport-security') continue;

    // Special case: X-Frame-Options may be replaced by CSP frame-ancestors.
    if (headerKey === 'x-frame-options') {
      const csp = headers['content-security-policy'] || '';
      if (csp.toLowerCase().includes('frame-ancestors')) {
        ctx.log(`TLS/Headers: X-Frame-Options absent but CSP frame-ancestors present ✓`);
        continue;
      }
    }

    if (!headers[headerKey]) {
      const url = baseUrl;
      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'tls.headers.basic',
        title:       meta.title,
        shortDescription: `The response at ${url} does not include the ${headerKey} header.`,
        detailedDescription: meta.detail,
        severity:    meta.severity,
        category:    'tls',
        owaspTag:    'A05-Security-Misconfiguration',
        cweTag:      meta.cwe,
      });
      const evidence = new Evidence({
        findingId:              finding.id,
        url,
        method:                 'GET',
        responseStatus:        res.status,
        responseHeadersSnippet: headersSnippet,
        responseBodySnippet:   '',
        matchedPattern:        `${headerKey} header absent`,
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`[${meta.severity.toUpperCase()}] missing header: ${headerKey} at ${url}`);
    } else {
      ctx.log(`TLS/Headers: ${headerKey} present ✓`);
    }
  }

  // ── 4. Server version banner leakage ───────────────────────────────────────────────
  const serverHeader   = headers['server']   || '';
  const poweredByHeader = headers['x-powered-by'] || '';

  const versionRe = /(\d+\.\d+[\.\d]*)/;

  if (serverHeader && versionRe.test(serverHeader)) {
    const ver = serverHeader.match(versionRe)?.[1];
    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'tls.headers.basic',
      title:       'Server Version Disclosed in HTTP Header',
      shortDescription: `Server header reveals version information: "${serverHeader}"`,
      detailedDescription:
        `The Server response header discloses the web server software name and version ("${serverHeader}"). ` +
        'Version disclosure helps attackers identify unpatched software and target known CVEs. ' +
        'Configure your web server to suppress or genericize the Server header.',
      severity:  'low',
      category:  'exposure',
      owaspTag:  'A05-Security-Misconfiguration',
      cweTag:    'CWE-200',
    });
    const evidence = new Evidence({
      findingId:              finding.id,
      url:                    baseUrl,
      method:                 'GET',
      responseStatus:        res.status,
      responseHeadersSnippet: headersSnippet,
      responseBodySnippet:   '',
      matchedPattern:        `Server: ${serverHeader}`,
    });
    ctx.addFinding(finding);
    ctx.addEvidence(evidence);
    ctx.log(`⚠️ LOW: server version banner disclosed: "${serverHeader}"`);
  }

  if (poweredByHeader) {
    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'tls.headers.basic',
      title:       'Technology Stack Disclosed via X-Powered-By Header',
      shortDescription: `X-Powered-By header reveals technology: "${poweredByHeader}"`,
      detailedDescription:
        `The X-Powered-By header discloses the application framework or runtime ("${poweredByHeader}"). ` +
        'This enables fingerprinting and targeted attacks against known framework vulnerabilities. ' +
        'Remove this header entirely. In Express.js: app.disable(\'x-powered-by\')',
      severity:  'info',
      category:  'exposure',
      owaspTag:  'A05-Security-Misconfiguration',
      cweTag:    'CWE-200',
    });
    const evidence = new Evidence({
      findingId:              finding.id,
      url:                    baseUrl,
      method:                 'GET',
      responseStatus:        res.status,
      responseHeadersSnippet: headersSnippet,
      responseBodySnippet:   '',
      matchedPattern:        `X-Powered-By: ${poweredByHeader}`,
    });
    ctx.addFinding(finding);
    ctx.addEvidence(evidence);
    ctx.log(`ℹ️ INFO: X-Powered-By disclosed: "${poweredByHeader}"`);
  }

  // ── 5. Cookie flag analysis ──────────────────────────────────────────────────────────
  // httpClient lowercases headers, so Set-Cookie becomes set-cookie.
  // node-fetch / fetch returns it as a single string or array depending on env.
  const rawCookieHeader = res.headers['set-cookie'] || res.headers['Set-Cookie'] || '';
  const cookieLines = Array.isArray(rawCookieHeader)
    ? rawCookieHeader
    : rawCookieHeader.split(/,(?=[^;]+=[^;]+)/)  // naive split on multi-cookie header
        .map((c) => c.trim())
        .filter(Boolean);

  for (const cookieLine of cookieLines) {
    const cookieName = cookieLine.split('=')[0]?.trim() || 'unknown';
    const upper = cookieLine.toUpperCase();
    const isSession = /sess|token|auth|jwt|sid|user/i.test(cookieName);
    const hasSecure   = upper.includes('SECURE');
    const hasHttpOnly = upper.includes('HTTPONLY');
    const hasSameSite = upper.includes('SAMESITE');

    if (!hasSecure) {
      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'tls.headers.basic',
        title:       `Cookie "${cookieName}" Missing Secure Flag`,
        shortDescription: `The cookie "${cookieName}" is set without the Secure flag, allowing it to be sent over HTTP.`,
        detailedDescription:
          `The Set-Cookie header sets "${cookieName}" without the Secure flag. ` +
          'Without Secure, the cookie is transmitted over unencrypted HTTP connections, exposing it to interception. ' +
          'Add the Secure flag to all cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict',
        severity:  isSession ? 'high' : 'medium',
        category:  'tls',
        owaspTag:  'A02-Cryptographic-Failures',
        cweTag:    'CWE-614',
      });
      const evidence = new Evidence({
        findingId:              finding.id,
        url:                    baseUrl,
        method:                 'GET',
        responseStatus:        res.status,
        responseHeadersSnippet: headersSnippet,
        responseBodySnippet:   '',
        matchedPattern:        `Set-Cookie: ${cookieLine.slice(0, 256)}`,
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`${isSession ? '🔴 HIGH' : '🟠 MEDIUM'}: cookie "${cookieName}" missing Secure flag`);
    }

    if (!hasHttpOnly && isSession) {
      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'tls.headers.basic',
        title:       `Session Cookie "${cookieName}" Missing HttpOnly Flag`,
        shortDescription: `The session cookie "${cookieName}" is readable by JavaScript (no HttpOnly flag).`,
        detailedDescription:
          `Session cookie "${cookieName}" is set without the HttpOnly flag. ` +
          'Cookies without HttpOnly can be read by JavaScript, making them vulnerable to theft via XSS. ' +
          'Add HttpOnly to all session cookies: Set-Cookie: sessionid=value; Secure; HttpOnly; SameSite=Strict',
        severity:  'medium',
        category:  'tls',
        owaspTag:  'A07-Identification-and-Authentication-Failures',
        cweTag:    'CWE-1004',
      });
      const evidence = new Evidence({
        findingId:              finding.id,
        url:                    baseUrl,
        method:                 'GET',
        responseStatus:        res.status,
        responseHeadersSnippet: headersSnippet,
        responseBodySnippet:   '',
        matchedPattern:        `Set-Cookie: ${cookieLine.slice(0, 256)}`,
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`🟠 MEDIUM: session cookie "${cookieName}" missing HttpOnly flag`);
    }

    if (!hasSameSite && isSession) {
      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'tls.headers.basic',
        title:       `Session Cookie "${cookieName}" Missing SameSite Attribute (CSRF Risk)`,
        shortDescription: `Session cookie "${cookieName}" has no SameSite attribute, increasing CSRF risk.`,
        detailedDescription:
          `Session cookie "${cookieName}" does not include the SameSite attribute. ` +
          'Without SameSite, the cookie is sent with cross-site requests, enabling CSRF attacks. ' +
          'Add SameSite=Strict or SameSite=Lax to all session cookies.',
        severity:  'medium',
        category:  'tls',
        owaspTag:  'A01-Broken-Access-Control',
        cweTag:    'CWE-352',
      });
      const evidence = new Evidence({
        findingId:              finding.id,
        url:                    baseUrl,
        method:                 'GET',
        responseStatus:        res.status,
        responseHeadersSnippet: headersSnippet,
        responseBodySnippet:   '',
        matchedPattern:        `Set-Cookie: ${cookieLine.slice(0, 256)}`,
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`🟠 MEDIUM: session cookie "${cookieName}" missing SameSite attribute`);
    }
  }

  ctx.log(`TLS/Headers: check complete for ${baseUrl}.`);
}
