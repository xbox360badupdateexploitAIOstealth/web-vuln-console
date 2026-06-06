// src/core/checks/sourceMapDetect.js
// TODO-03: JavaScript source map exposure detector. v2.
// Runs as Phase 2.5 alongside jsSecretScan.js for the exposure.sourcemap module.
//
// Modern JS bundlers (webpack, Vite, Parcel, esbuild, Rollup) emit .map files
// alongside minified bundles. When deployed to production these expose the
// complete original unminified source code, directory structure, file names,
// internal comments, and sometimes hardcoded credentials.
//
// Detection: THREE vectors per JS file
//
//  Vector A — Direct .map probe:
//    Append ".map" to each JS URL. Fastest, catches 90% of cases.
//    Example: /static/app.abc123.js → probe /static/app.abc123.js.map
//
//  Vector B — HTTP response headers:
//    Check X-SourceMap / SourceMap / X-Source-Map response headers on the
//    JS file itself. Some CDNs and servers set these explicitly.
//
//  Vector C — Inline sourceMappingURL comment:
//    Parse the last 512 bytes of the .js body for:
//      //# sourceMappingURL=<url>   (modern standard)
//      //@ sourceMappingURL=<url>   (legacy IE syntax)
//    Resolves relative, absolute-path, and protocol-relative URLs.
//    Skips data: URI inline maps (content is embedded, not a remote URL).
//
// Validation:
//    Response must be JSON with:
//      - "version": 3 (number)
//      - "sources": [...] (non-empty array)
//    Handles XSSI prefix stripping: )]}' or )]} at start.
//    Reports source count + sample paths + internal server path leakage.
//
// Severity: CRITICAL  (full pre-minification source code recoverable)
// OWASP:    A05-Security-Misconfiguration
// CWE:      CWE-540

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// Max JS files to probe per target
const MAX_JS_FILES = 30;

// Max bytes to read when scanning a JS body for Vector B/C
const MAX_JS_SCAN_BYTES = 65_536; // 64 KB — comment is always at the end

// Max bytes to read for .map validation
const MAX_MAP_BYTES = 256_000; // 256 KB

// Patterns indicating internal server paths leaked in sources[]
const INTERNAL_PATH_RE =
  /(\/home\/[^"',\s]+|\/var\/www\/[^"',\s]+|\/srv\/[^"',\s]+|\/root\/[^"',\s]+|\/Users\/[^"',\s]+|C:\\\\[^"',\s]+)/i;

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detect exposed JavaScript source maps for all .js assets in the SiteModel.
 *
 * @param {Object} opts
 * @param {Object}   opts.ctx          - EngineContext
 * @param {Object}   opts.target       - Target instance
 * @param {import('../siteModel.js').SiteModel} opts.siteModel
 * @param {string}   opts.baseUrl
 * @param {Object}   opts.fetchAdapter
 */
export async function runSourceMapDetect({ ctx, target, siteModel, baseUrl, fetchAdapter }) {
  const jsUrls = collectJsUrls(siteModel, baseUrl);

  if (jsUrls.length === 0) {
    ctx.log('SourceMapDetect: no JavaScript assets in SiteModel — skipping.');
    return;
  }

  const toCheck = jsUrls.slice(0, MAX_JS_FILES);
  ctx.log(`SourceMapDetect: checking ${toCheck.length} JS file(s) for source map exposure.`);

  // Track probed .map URLs to avoid duplicate findings
  const reportedMaps = new Set();

  for (const jsUrl of toCheck) {
    await checkJsFile({ ctx, target, jsUrl, baseUrl, reportedMaps, fetchAdapter });
  }

  ctx.log(`SourceMapDetect: complete. Maps reported: ${reportedMaps.size}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// PER-FILE CHECK — all three vectors
// ─────────────────────────────────────────────────────────────────────────────

async function checkJsFile({ ctx, target, jsUrl, baseUrl, reportedMaps, fetchAdapter }) {

  // ── Vector A: direct .map probe (no JS fetch needed) ─────────────────────────
  const directMap = jsUrl + '.map';
  if (!reportedMaps.has(directMap)) {
    const hit = await probeMap({ ctx, target, mapUrl: directMap, jsUrl, via: 'direct probe', fetchAdapter });
    if (hit) {
      reportedMaps.add(directMap);
      return; // found — no need to fetch JS body for B/C
    }
  }

  // ── Fetch JS file once for Vectors B and C ─────────────────────────────────
  let jsRes;
  try {
    jsRes = await httpGetText({ fetchAdapter, url: jsUrl });
  } catch (e) {
    ctx.log(`SourceMapDetect: JS fetch error ${jsUrl}: ${e.message || e}`);
    return;
  }
  if (jsRes.status !== 200) return;

  // ── Vector B: X-SourceMap / SourceMap response header ──────────────────────
  const headerRef =
    jsRes.headers['x-sourcemap']   ||
    jsRes.headers['sourcemap']     ||
    jsRes.headers['x-source-map'] || '';

  if (headerRef && !headerRef.startsWith('data:')) {
    const headerMapUrl = resolveUrl(headerRef.trim(), jsUrl, baseUrl);
    if (!reportedMaps.has(headerMapUrl)) {
      const hit = await probeMap({ ctx, target, mapUrl: headerMapUrl, jsUrl, via: 'X-SourceMap header', fetchAdapter });
      if (hit) reportedMaps.add(headerMapUrl);
    }
    return; // header takes precedence over comment
  }

  // ── Vector C: //# sourceMappingURL= comment ─────────────────────────────
  const body = jsRes.body.slice(0, MAX_JS_SCAN_BYTES);
  const tail = body.slice(Math.max(0, body.length - 512));
  const commentMatch = tail.match(/\/\/[#@]\s*sourceMappingURL=([^\s"'`]+)/);

  if (!commentMatch) {
    ctx.log(`SourceMapDetect: no source map ref found in ${jsUrl}`);
    return;
  }

  const commentRef = commentMatch[1].trim();
  if (commentRef.startsWith('data:')) {
    ctx.log(`SourceMapDetect: ${jsUrl} has inline data-URI map (not externally accessible)`);
    return;
  }

  const commentMapUrl = resolveUrl(commentRef, jsUrl, baseUrl);
  if (!reportedMaps.has(commentMapUrl)) {
    const hit = await probeMap({ ctx, target, mapUrl: commentMapUrl, jsUrl, via: 'sourceMappingURL comment', fetchAdapter });
    if (hit) reportedMaps.add(commentMapUrl);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROBE A SINGLE .MAP URL
// ─────────────────────────────────────────────────────────────────────────────

async function probeMap({ ctx, target, mapUrl, jsUrl, via, fetchAdapter }) {
  ctx.log(`SourceMapDetect: probing ${mapUrl} (via ${via})`);

  let res;
  try {
    res = await httpGetText({ fetchAdapter, url: mapUrl });
  } catch (e) {
    ctx.log(`SourceMapDetect: probe error ${mapUrl}: ${e.message || e}`);
    return false;
  }

  if (res.status !== 200) {
    ctx.log(`SourceMapDetect: ${mapUrl} → ${res.status} (not exposed)`);
    return false;
  }

  const body    = res.body.slice(0, MAX_MAP_BYTES);
  const mapData = parseSourceMap(body);

  if (!mapData) {
    ctx.log(`SourceMapDetect: ${mapUrl} returned 200 but is not valid source map JSON — skipping`);
    return false;
  }

  const sources       = mapData.sources || [];
  const sourceCount   = sources.length;
  const sampleSources = sources.slice(0, 8).join(', ');
  const internalPaths = sources.filter((s) => s && INTERNAL_PATH_RE.test(s));
  const headersSnippet = JSON.stringify(res.headers || {}).slice(0, 512);

  const finding = new Finding({
    projectId:        ctx.project.id,
    scanJobId:        ctx.job.id,
    targetId:         target.id,
    moduleId:         'exposure.sourcemap',
    title:            'JavaScript Source Map Publicly Exposed',
    shortDescription:
      `Source map accessible at ${mapUrl} — ${sourceCount} original source file(s) exposed.`,
    detailedDescription:
      `A JavaScript source map file (.map) is publicly accessible at ${mapUrl}. ` +
      `Source maps contain the complete original unminified source code of the application ` +
      `before bundling, including all file paths, variable names, business logic, and comments.\n\n` +
      `Discovery vector: ${via}\n` +
      `Associated JS bundle: ${jsUrl}\n` +
      `Source files exposed: ${sourceCount}\n` +
      `Sample paths: ${sampleSources || '(none parsed)'}${sourceCount > 8 ? ` ... +${sourceCount - 8} more` : ''}` +
      (internalPaths.length > 0
        ? `\n\n⚠️ Internal server paths leaked in sources[]: ${internalPaths.slice(0, 3).join(', ')}`
        : '') +
      `\n\nFix: remove .map files from production. ` +
      `webpack: set devtool: false or \'hidden-source-map\'. ` +
      `Nginx: location ~* \.map$ { deny all; }`,
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
    matchedPattern:
      `Valid source map JSON — ${sourceCount} sources, version ${mapData.version}, via ${via}`,
  });

  ctx.addFinding(finding);
  ctx.addEvidence(evidence);
  ctx.log(
    `🔴 CRITICAL: source map exposed at ${mapUrl} ` +
    `(${sourceCount} files${internalPaths.length > 0 ? ', INTERNAL PATHS LEAKED' : ''}, via ${via})`
  );
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// SOURCE MAP VALIDATION
// ─────────────────────────────────────────────────────────────────────────────

function parseSourceMap(body) {
  // Strip XSSI prefix: )]}' or )]} (used by Closure Compiler and some CDNs)
  const stripped = body.replace(/^\)\]\}[\s']*/, '').trim();
  if (!stripped.startsWith('{')) return null;
  try {
    const obj = JSON.parse(stripped.slice(0, 65_536));
    if (typeof obj !== 'object' || obj === null)     return null;
    if (!Array.isArray(obj.sources))                return null;
    if (obj.sources.length === 0)                   return null;
    // Must have version:3 OR mappings string OR sections array (index maps)
    const isValid =
      obj.version === 3 ||
      (typeof obj.mappings === 'string' && obj.mappings.length > 0) ||
      Array.isArray(obj.sections);
    if (!isValid) return null;
    return obj;
  } catch (_) {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

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

function resolveUrl(ref, jsUrl, baseUrl) {
  if (/^https?:\/\//i.test(ref)) return ref;
  if (ref.startsWith('//'))      return 'https:' + ref;

  if (ref.startsWith('/')) {
    try {
      return new URL(baseUrl).origin + ref;
    } catch (_) {
      return baseUrl.replace(/\/$/, '') + ref;
    }
  }

  // Relative ref — resolve against directory of the JS file
  if (jsUrl) {
    const dir = jsUrl.replace(/\/[^/]+$/, '');
    return dir + '/' + ref.replace(/^\.?\//, '');
  }

  return baseUrl.replace(/\/$/, '') + '/' + ref;
}
