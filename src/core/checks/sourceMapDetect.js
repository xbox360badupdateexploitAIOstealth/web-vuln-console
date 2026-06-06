// src/core/checks/sourceMapDetect.js
// TODO-03: JavaScript source map exposure detector.
// Runs as Phase 2.5 alongside jsSecretScan.js for the exposure.sourcemap module.
//
// Modern JS bundlers (webpack, Vite, Parcel, esbuild, Rollup) optionally emit
// .map files alongside minified bundles. When these are deployed to production
// they expose the complete original unminified source code, directory structure,
// file names, and often internal comments/credentials to anyone who requests them.
//
// Detection strategy:
//  1. For every .js URL in the SiteModel, probe url + '.map'
//  2. Also check for inline //# sourceMappingURL= comments pointing to an
//     external .map file and probe that URL directly
//  3. Validate the response: must be JSON with a 'sources' array (real source map)
//  4. Extract and report the original source file list from 'sources[]'
//  5. Flag presence of internal paths (e.g. /home/user/, /var/www/, C:\\)
//     as an additional critical indicator
//
// Severity: critical — exposes full pre-minification source code

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// Max .map files to probe per target
const MAX_MAP_PROBES = 25;

// Max bytes to read per .map file (source maps can be huge)
const MAX_MAP_BYTES = 256_000; // 256 KB

// Patterns that indicate internal server paths leaked in source map 'sources'
const INTERNAL_PATH_RE = /(\/home\/[^"']+|\/var\/www\/[^"']+|\/srv\/[^"']+|C:\\\\[^"']+|\/Users\/[^"']+|\/root\/[^"']+)/i;

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Probe for exposed JavaScript source maps.
 *
 * @param {Object} opts
 * @param {Object}   opts.ctx           - EngineContext
 * @param {Object}   opts.target        - Target instance
 * @param {import('../siteModel.js').SiteModel} opts.siteModel
 * @param {string}   opts.baseUrl
 * @param {Object}   opts.fetchAdapter
 */
export async function runSourceMapDetect({ ctx, target, siteModel, baseUrl, fetchAdapter }) {
  const jsUrls = collectJsUrls(siteModel, baseUrl);

  if (jsUrls.length === 0) {
    ctx.log('SourceMapDetect: no JS assets in SiteModel — skipping.');
    return;
  }

  ctx.log(`SourceMapDetect: probing ${Math.min(jsUrls.length, MAX_MAP_PROBES)} JS file(s) for source maps.`);

  const probed  = new Set(); // avoid double-probing the same .map URL
  let probeCount = 0;

  for (const jsUrl of jsUrls) {
    if (probeCount >= MAX_MAP_PROBES) {
      ctx.log(`SourceMapDetect: probe cap (${MAX_MAP_PROBES}) reached.`);
      break;
    }

    // Strategy A: append .map to the JS URL
    const mapUrlA = jsUrl + '.map';
    if (!probed.has(mapUrlA)) {
      probed.add(mapUrlA);
      probeCount++;
      const hit = await probeMapUrl({ ctx, target, mapUrl: mapUrlA, jsUrl, fetchAdapter });
      if (hit) continue; // already found one for this JS file
    }

    // Strategy B: check for inline //# sourceMappingURL= comment
    const inlineUrl = await extractInlineSourceMappingUrl({ jsUrl, baseUrl, fetchAdapter, ctx });
    if (inlineUrl && !probed.has(inlineUrl)) {
      probed.add(inlineUrl);
      probeCount++;
      await probeMapUrl({ ctx, target, mapUrl: inlineUrl, jsUrl, fetchAdapter });
    }
  }

  ctx.log(`SourceMapDetect: complete. Probed ${probeCount} .map URL(s).`);
}

// ─────────────────────────────────────────────────────────────────────────────
// PROBE A SINGLE .MAP URL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch a candidate .map URL and validate it is a real source map.
 * Returns true if a finding was created.
 */
async function probeMapUrl({ ctx, target, mapUrl, jsUrl, fetchAdapter }) {
  ctx.log(`SourceMapDetect: probing ${mapUrl}`);
  try {
    const res = await httpGetText({ fetchAdapter, url: mapUrl });

    if (res.status !== 200) {
      ctx.log(`SourceMapDetect: ${mapUrl} → ${res.status} (not exposed)`);
      return false;
    }

    // Validate it is actually a source map JSON (not a generic 200 page)
    const body    = res.body.slice(0, MAX_MAP_BYTES);
    const mapData = parseSourceMap(body);

    if (!mapData) {
      ctx.log(`SourceMapDetect: ${mapUrl} returned 200 but is not valid source map JSON — skipping.`);
      return false;
    }

    // Extract source file list
    const sources    = mapData.sources || [];
    const sourceCount = sources.length;
    const sampleSources = sources.slice(0, 8).join(', ');

    // Check for internal server path leakage in sources
    const internalPaths = sources.filter((s) => INTERNAL_PATH_RE.test(s));
    const hasInternalPaths = internalPaths.length > 0;

    const severity = hasInternalPaths ? 'critical' : 'critical'; // always critical
    const headersSnippet = JSON.stringify(res.headers || {}).slice(0, 512);

    const finding = new Finding({
      projectId:        ctx.project.id,
      scanJobId:        ctx.job.id,
      targetId:         target.id,
      moduleId:         'exposure.sourcemap',
      title:            'JavaScript Source Map Publicly Exposed',
      shortDescription: `Source map file is accessible at ${mapUrl} (${sourceCount} source files).`,
      detailedDescription:
        `A JavaScript source map file (.map) is publicly accessible at ${mapUrl}. ` +
        `Source maps contain the complete original unminified source code of the application before bundling. ` +
        `This exposes business logic, internal API endpoints, credentials in comments, ` +
        `and the full directory structure of the application to anyone who requests the file.\n\n` +
        `Associated JS bundle: ${jsUrl}\n` +
        `Source files exposed (${sourceCount} total): ${sampleSources}${sourceCount > 8 ? ` ... and ${sourceCount - 8} more` : ''}` +
        (hasInternalPaths
          ? `\n\n⚠️ Internal server paths leaked: ${internalPaths.slice(0, 3).join(', ')}`
          : '') +
        `\n\nFix: configure your bundler or web server to block access to *.map files in production. ` +
        `In webpack: set devtool: false or devtool: 'hidden-source-map'. ` +
        `In Nginx: add location ~* \.map$ { deny all; }`,
      severity: 'critical',
      category: 'exposure',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag:   'CWE-540',
    });

    const evidence = new Evidence({
      findingId:              finding.id,
      url:                    mapUrl,
      method:                 'GET',
      responseStatus:        res.status,
      responseHeadersSnippet: headersSnippet,
      responseBodySnippet:   body.slice(0, 1024),
      matchedPattern:        `Valid source map JSON with ${sourceCount} source files`,
    });

    ctx.addFinding(finding);
    ctx.addEvidence(evidence);
    ctx.log(`🔴 CRITICAL: source map exposed at ${mapUrl} (${sourceCount} files${hasInternalPaths ? ', internal paths leaked' : ''})`);
    return true;

  } catch (e) {
    ctx.log(`SourceMapDetect: probe error for ${mapUrl}: ${e.message || e}`);
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// INLINE SOURCEMAPPINGURL EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch the JS file and look for //# sourceMappingURL=<url> at the end.
 * Returns the resolved absolute URL of the referenced .map file, or null.
 */
async function extractInlineSourceMappingUrl({ jsUrl, baseUrl, fetchAdapter, ctx }) {
  try {
    const res = await httpGetText({ fetchAdapter, url: jsUrl });
    if (res.status !== 200) return null;

    // sourceMappingURL comment is always near the end of the file
    const tail = res.body.slice(-512);
    const match = tail.match(/\/\/[#@]\s*sourceMappingURL=([^\s"']+)/);
    if (!match) return null;

    const ref = match[1].trim();

    // Skip data URIs (inline source maps — content already embedded, not a URL)
    if (ref.startsWith('data:')) return null;

    return resolveUrl(ref, jsUrl, baseUrl);
  } catch (_) {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Attempt to parse body as source map JSON.
 * A valid source map must be an object with a numeric 'version' and a 'sources' array.
 * Returns the parsed object or null.
 */
function parseSourceMap(body) {
  // Source maps sometimes start with )]}' (Closure Compiler XSSI prefix) — strip it
  const clean = body.replace(/^\)\]\}'\s*/, '').trim();
  if (!clean.startsWith('{')) return null;
  try {
    const obj = JSON.parse(clean);
    if (typeof obj !== 'object' || obj === null) return null;
    if (!Array.isArray(obj.sources))             return null;
    if (typeof obj.version !== 'number')         return null;
    return obj;
  } catch (_) {
    return null;
  }
}

function collectJsUrls(siteModel, baseUrl) {
  const urls = new Set();
  const base = baseUrl.replace(/\/$/, '');

  if (siteModel.assets) {
    for (const asset of siteModel.assets) {
      if (typeof asset === 'string' && asset.endsWith('.js')) {
        urls.add(resolveUrl(asset, null, base));
      } else if (asset?.url && asset.url.endsWith('.js')) {
        urls.add(resolveUrl(asset.url, null, base));
      }
    }
  }

  const endpoints = siteModel.getAllEndpoints?.() || [];
  for (const ep of endpoints) {
    const u = ep.url || ep;
    if (typeof u === 'string' && u.endsWith('.js')) {
      urls.add(resolveUrl(u, null, base));
    }
  }

  return [...urls];
}

/**
 * Resolve a URL reference relative to the JS file's URL or the base URL.
 * @param {string} ref     - The URL from sourceMappingURL or asset list
 * @param {string|null} jsUrl  - The URL of the .js file (for relative refs)
 * @param {string} baseUrl - The target base URL
 */
function resolveUrl(ref, jsUrl, baseUrl) {
  if (/^https?:\/\//i.test(ref)) return ref;
  if (ref.startsWith('//'))      return 'https:' + ref;

  // Relative to the JS file's directory
  if (jsUrl && ref.startsWith('.')) {
    const dir = jsUrl.replace(/\/[^/]+$/, '');
    return dir + '/' + ref.replace(/^\.?\//, '');
  }

  const base = baseUrl.replace(/\/$/, '');
  if (ref.startsWith('/')) return base + ref;
  return base + '/' + ref;
}
