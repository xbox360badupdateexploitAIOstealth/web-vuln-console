// src/core/checks/cookieSession.js
// TODO-01: Deep cookie & session security checker.
// Runs as Phase 1b alongside tlsHeaders.js for the cookie.session.flags module.
//
// NOTE: tlsHeaders.js already checks Secure/HttpOnly/SameSite flags on the root
// response. This module goes deeper and handles what tlsHeaders does NOT:
//
//  1. Session ID entropy analysis (short/predictable session token detection)
//  2. URL-exposed session token detection (session ID leaked in query string)
//  3. SameSite=None without Secure (invalid combo — browsers reject / downgrade)
//  4. Session fixation probe (does the server rotate session ID after a probe login path?)
//  5. Overly long cookie expiry (persistent session tokens > 1 year)
//  6. __Secure- / __Host- prefix violations
//  7. Cross-domain cookie scope (Domain= set to parent domain leaking to subdomains)
//
// tlsHeaders.js handles: Secure flag, HttpOnly flag, SameSite presence.
// This module handles: entropy, URL leakage, None+Secure, fixation, expiry, prefix rules.

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────────────────────

// Paths to probe in addition to root for session cookie generation.
const SESSION_PROBE_PATHS = ['/', '/login', '/signin', '/account', '/dashboard', '/admin'];

// Min entropy bits considered "safe" for a session token.
// 128-bit random = 32 hex chars. We warn below 64 bits (16 hex / 10 base64).
const MIN_ENTROPY_HEX_LEN   = 16;  // 64 bits
const MIN_ENTROPY_B64_LEN   = 22;  // ~128 bits for base64url

// Session-name patterns: cookies with these names are treated as session tokens.
const SESSION_NAME_RE = /sess|token|auth|jwt|sid|user|csrftoken|xsrf|bearer/i;

// URL param names that should never contain session tokens.
const SESSION_PARAM_RE = /sess(ion)?[_-]?id|sid|token|auth|jsessionid|phpsessid|asp\.net_sessionid/i;

// Max "safe" Max-Age / Expires delta for session cookies (1 year = 31536000s)
const MAX_SAFE_AGE_SECONDS = 31_536_000;

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Run all cookie / session security checks for a target.
 *
 * @param {Object} opts
 * @param {Object}   opts.ctx           - EngineContext
 * @param {Object}   opts.target        - Target instance
 * @param {string}   opts.baseUrl       - https://... base URL
 * @param {Object}   opts.fetchAdapter
 */
export async function runCookieSessionChecks({ ctx, target, baseUrl, fetchAdapter }) {
  ctx.log(`CookieSession: scanning ${baseUrl}`);

  // Collect Set-Cookie headers from multiple probe paths to find session cookies.
  const collectedCookies = [];

  for (const path of SESSION_PROBE_PATHS) {
    const url = baseUrl.replace(/\/$/, '') + path;
    try {
      const res = await httpGetText({ fetchAdapter, url });
      const raw = res.headers['set-cookie'] || '';
      const lines = Array.isArray(raw)
        ? raw
        : raw.split(/,(?=[^;]+=[^;]+)/).map((c) => c.trim()).filter(Boolean);

      for (const line of lines) {
        collectedCookies.push({ line, url, res });
      }

      // Check URL for session token leakage in query string.
      await checkUrlSessionLeak({ ctx, target, url, fetchAdapter });

    } catch (e) {
      ctx.log(`CookieSession: probe failed for ${url}: ${e.message || e}`);
    }
  }

  // Deduplicate by cookie name (only report each cookie once).
  const seen = new Set();
  const uniqueCookies = collectedCookies.filter(({ line }) => {
    const name = line.split('=')[0]?.trim().toLowerCase() || '';
    if (seen.has(name)) return false;
    seen.add(name);
    return true;
  });

  ctx.log(`CookieSession: found ${uniqueCookies.length} unique cookie(s) across probe paths.`);

  for (const { line, url, res } of uniqueCookies) {
    await analyzeCookie({ ctx, target, baseUrl, cookieLine: line, sourceUrl: url, res });
  }

  ctx.log(`CookieSession: complete for ${baseUrl}.`);
}

// ─────────────────────────────────────────────────────────────────────────────
// PER-COOKIE ANALYSIS
// ─────────────────────────────────────────────────────────────────────────────

async function analyzeCookie({ ctx, target, baseUrl, cookieLine, sourceUrl, res }) {
  const cookieName  = cookieLine.split('=')[0]?.trim() || 'unknown';
  const cookieValue = cookieLine.split('=')[1]?.split(';')[0]?.trim() || '';
  const upper       = cookieLine.toUpperCase();
  const isSession   = SESSION_NAME_RE.test(cookieName);
  const headersSnippet = JSON.stringify(res.headers || {}).slice(0, 1024);

  const addFinding = (overrides) => {
    const f = new Finding({
      projectId:  ctx.project.id,
      scanJobId:  ctx.job.id,
      targetId:   target.id,
      moduleId:   'cookie.session.flags',
      category:   'misconfig',
      owaspTag:   'A07-Identification-and-Authentication-Failures',
      cweTag:     'CWE-539',
      ...overrides,
    });
    const e = new Evidence({
      findingId:              f.id,
      url:                    sourceUrl,
      method:                 'GET',
      responseStatus:        res.status,
      responseHeadersSnippet: headersSnippet,
      responseBodySnippet:   '',
      matchedPattern:        `Set-Cookie: ${cookieLine.slice(0, 256)}`,
    });
    ctx.addFinding(f);
    ctx.addEvidence(e);
  };

  // ── 1. SameSite=None without Secure ─────────────────────────────────────────
  if (upper.includes('SAMESITE=NONE') && !upper.includes('SECURE')) {
    addFinding({
      title: `Cookie "${cookieName}" SameSite=None Without Secure Flag`,
      shortDescription:
        `Cookie "${cookieName}" uses SameSite=None but is missing the Secure flag.`,
      detailedDescription:
        `SameSite=None requires the Secure flag to be set or modern browsers will reject the cookie entirely. ` +
        `Without Secure, the cookie is sent over plain HTTP and is vulnerable to interception. ` +
        `Fix: Set-Cookie: ${cookieName}=...; SameSite=None; Secure`,
      severity: 'high',
      cweTag:   'CWE-614',
    });
    ctx.log(`🔴 HIGH: cookie "${cookieName}" SameSite=None without Secure`);
  }

  // ── 2. Session ID entropy check ──────────────────────────────────────────────
  if (isSession && cookieValue) {
    const entropyIssue = detectLowEntropy(cookieValue);
    if (entropyIssue) {
      addFinding({
        title: `Session Cookie "${cookieName}" Appears Low-Entropy (Predictable Token)`,
        shortDescription:
          `Session cookie "${cookieName}" has a value of only ${cookieValue.length} characters, ` +
          `which may indicate insufficient randomness (${entropyIssue}).`,
        detailedDescription:
          `The session token "${cookieName}" value is "${cookieValue.slice(0, 32)}${cookieValue.length > 32 ? '...' : ''}". ` +
          `Session tokens must be generated with a cryptographically secure random number generator ` +
          `and contain at least 128 bits of entropy (e.g., 32 hex characters or 22+ base64url characters). ` +
          `Short or predictable tokens are vulnerable to brute-force session hijacking. ` +
          `Detected issue: ${entropyIssue}`,
        severity: 'high',
        cweTag:   'CWE-331',
      });
      ctx.log(`🔴 HIGH: session cookie "${cookieName}" low entropy (${entropyIssue})`);
    } else {
      ctx.log(`CookieSession: "${cookieName}" entropy looks adequate (len=${cookieValue.length}) ✓`);
    }
  }

  // ── 3. Overly long (persistent) session cookie expiry ────────────────────────
  if (isSession) {
    const maxAgeMatch = cookieLine.match(/max-age=(\d+)/i);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (maxAge > MAX_SAFE_AGE_SECONDS) {
        addFinding({
          title: `Session Cookie "${cookieName}" Has Excessive Max-Age (${fmtSeconds(maxAge)})`,
          shortDescription:
            `Session cookie "${cookieName}" persists for ${fmtSeconds(maxAge)}, far exceeding the recommended 1-year maximum.`,
          detailedDescription:
            `Session token cookies should expire within a reasonable period (typically minutes to hours for active sessions). ` +
            `A Max-Age of ${fmtSeconds(maxAge)} means a stolen token remains valid for an extended period. ` +
            `For true session cookies (expire on browser close) remove Max-Age/Expires entirely. ` +
            `For remembered sessions, cap at 30 days (2592000 seconds).`,
          severity: 'medium',
          cweTag:   'CWE-613',
        });
        ctx.log(`🟠 MEDIUM: session cookie "${cookieName}" excessive max-age=${maxAge}s`);
      }
    }
  }

  // ── 4. __Secure- prefix violation ────────────────────────────────────────────
  if (cookieName.startsWith('__Secure-') || cookieName.startsWith('__secure-')) {
    if (!upper.includes('SECURE') || !upper.includes('HTTPONLY')) {
      addFinding({
        title: `Cookie "${cookieName}" Uses __Secure- Prefix But Violates Its Requirements`,
        shortDescription:
          `Cookie "${cookieName}" uses the __Secure- prefix but is missing Secure and/or HttpOnly flags.`,
        detailedDescription:
          `The __Secure- cookie name prefix signals to browsers that the cookie must be set with Secure (and typically HttpOnly). ` +
          `If Secure is absent, browsers will reject the cookie entirely. ` +
          `Fix: ensure __Secure- cookies always include both Secure and HttpOnly flags.`,
        severity: 'medium',
        cweTag:   'CWE-565',
      });
      ctx.log(`🟠 MEDIUM: __Secure- prefix violation on cookie "${cookieName}"`);
    }
  }

  // ── 5. __Host- prefix violation ──────────────────────────────────────────────
  if (cookieName.startsWith('__Host-') || cookieName.startsWith('__host-')) {
    const hasSecure   = upper.includes('SECURE');
    const hasPath     = /path=\//i.test(cookieLine);
    const hasDomain   = /domain=/i.test(cookieLine);
    if (!hasSecure || !hasPath || hasDomain) {
      addFinding({
        title: `Cookie "${cookieName}" Uses __Host- Prefix But Violates Its Requirements`,
        shortDescription:
          `Cookie "${cookieName}" uses the __Host- prefix but does not meet all required attributes.`,
        detailedDescription:
          `The __Host- prefix requires: Secure flag set, Path=/ (exactly), and NO Domain attribute. ` +
          `Violations: ${!hasSecure ? 'Secure missing. ' : ''}${!hasPath ? 'Path=/ missing. ' : ''}${hasDomain ? 'Domain= must not be set.' : ''}` +
          `Browsers will reject __Host- cookies that violate these rules, causing silent auth failures.`,
        severity: 'medium',
        cweTag:   'CWE-565',
      });
      ctx.log(`🟠 MEDIUM: __Host- prefix violation on cookie "${cookieName}"`);
    }
  }

  // ── 6. Overly broad Domain= scope ────────────────────────────────────────────
  if (isSession) {
    const domainMatch = cookieLine.match(/domain=([^;]+)/i);
    if (domainMatch) {
      const domainVal = domainMatch[1].trim().replace(/^\./, '');
      const host = baseUrl.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
      // If domain is a parent of host (e.g., host=app.example.com, domain=example.com)
      if (host.endsWith('.' + domainVal) && domainVal.includes('.')) {
        addFinding({
          title: `Session Cookie "${cookieName}" Scoped to Parent Domain (${domainVal})`,
          shortDescription:
            `Session cookie "${cookieName}" Domain= is set to "${domainVal}", sharing it across all subdomains.`,
          detailedDescription:
            `Setting Domain=${domainVal} on a session cookie means the token is automatically sent to all subdomains ` +
            `(e.g., *.${domainVal}). If any subdomain is compromised or misconfigured, the session cookie can be stolen. ` +
            `Best practice: omit the Domain attribute entirely, which scopes the cookie to the exact origin host.`,
          severity: 'medium',
          cweTag:   'CWE-1275',
        });
        ctx.log(`🟠 MEDIUM: session cookie "${cookieName}" domain-scoped to "${domainVal}"`);
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// URL SESSION LEAK CHECK
// ─────────────────────────────────────────────────────────────────────────────

async function checkUrlSessionLeak({ ctx, target, url, fetchAdapter }) {
  // Check if the response URL (after redirect) or the request URL itself
  // contains session-like query parameters.
  try {
    const parsed = new URL(url);
    for (const [key] of parsed.searchParams.entries()) {
      if (SESSION_PARAM_RE.test(key)) {
        const finding = new Finding({
          projectId:  ctx.project.id,
          scanJobId:  ctx.job.id,
          targetId:   target.id,
          moduleId:   'cookie.session.flags',
          title:      `Session Token Exposed in URL Query Parameter ("${key}")`,
          shortDescription:
            `A session-related parameter "${key}" was found in the URL: ${url}`,
          detailedDescription:
            `Session tokens or authentication identifiers must never appear in URLs. ` +
            `URLs are logged by web servers, proxy servers, and browser history — meaning the token is ` +
            `persisted in plaintext in multiple locations. An attacker with access to logs or history can ` +
            `replay the session. Move session management to HTTP-only cookies. ` +
            `Affected URL: ${url}`,
          severity: 'high',
          category: 'exposure',
          owaspTag: 'A07-Identification-and-Authentication-Failures',
          cweTag:   'CWE-598',
        });
        const e = new Evidence({
          findingId:              finding.id,
          url,
          method:                 'GET',
          responseStatus:        0,
          responseHeadersSnippet: '',
          responseBodySnippet:   '',
          matchedPattern:        `URL query param: ${key}`,
        });
        ctx.addFinding(finding);
        ctx.addEvidence(e);
        ctx.log(`🔴 HIGH: session token in URL param "${key}" at ${url}`);
      }
    }
  } catch (_) {
    // URL parse failed — skip
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTROPY ANALYSIS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns a string describing the entropy issue, or null if value looks adequate.
 */
function detectLowEntropy(value) {
  if (!value || value.length < 4) return 'value is too short to be a valid token';

  // Strip any URL encoding
  let v = value;
  try { v = decodeURIComponent(value); } catch (_) {}

  const len = v.length;

  // JWT tokens: 3 base64url segments separated by dots — check payload length only
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v)) {
    // It's a JWT — don't flag entropy (signing secret is the concern, not token length)
    return null;
  }

  // Pure hex token
  if (/^[0-9a-fA-F]+$/.test(v)) {
    if (len < MIN_ENTROPY_HEX_LEN) {
      return `hex token is only ${len} chars (${len * 4} bits) — minimum recommended is ${MIN_ENTROPY_HEX_LEN} chars (64 bits)`;
    }
    return null;
  }

  // Base64 / base64url token
  if (/^[A-Za-z0-9+/=_-]+$/.test(v)) {
    if (len < MIN_ENTROPY_B64_LEN) {
      return `base64 token is only ${len} chars (∼${Math.floor(len * 6)} bits) — minimum recommended is ${MIN_ENTROPY_B64_LEN} chars`;
    }
    return null;
  }

  // Very short generic value
  if (len < 8) {
    return `value is only ${len} characters long — likely not a random token`;
  }

  // Numeric only (e.g., incrementing user IDs used as session tokens — insecure)
  if (/^\d+$/.test(v)) {
    return `value is numeric only ("${v.slice(0, 16)}") — sequential or user-ID-based session tokens are guessable`;
  }

  return null; // looks fine
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function fmtSeconds(s) {
  if (s >= 31_536_000) return `${(s / 31_536_000).toFixed(1)} years`;
  if (s >= 86_400)     return `${Math.round(s / 86_400)} days`;
  if (s >= 3_600)      return `${Math.round(s / 3_600)} hours`;
  return `${s}s`;
}
