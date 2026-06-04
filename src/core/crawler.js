// src/core/crawler.js
// Crawler that discovers internal links and forms to populate SiteModel.
// Works in both Node.js (via cheerio) and browser (via DOMParser).

import { httpGetText } from './httpClient.js';

// ── Try to load cheerio for Node.js environments ─────────────────────────────
let cheerio = null;
try {
  // Dynamic import so this file still loads cleanly in browser.
  // In Node the worker calls the CJS build path.
  if (typeof window === 'undefined') {
    // We're in Node — require cheerio synchronously via a wrapper trick.
    // cheerio is already in package.json dependencies.
    const mod = await import('cheerio').catch(() => null);
    cheerio = mod?.load ? mod : mod?.default ?? null;
  }
} catch (_) {
  cheerio = null;
}

/**
 * Crawl a target starting from its baseUrl, up to a limited depth and page count,
 * and populate the provided SiteModel with discovered endpoints and parameters.
 */
export async function crawlTargetAndBuildSiteModel({
  ctx,
  target,
  baseUrl,
  siteModel,
  engineConfig,
  maxDepth = 2,
  maxPages = 30,
}) {
  const { fetchAdapter } = engineConfig;
  const origin = getOrigin(baseUrl);
  const visited = new Set();
  const queue = [{ url: baseUrl, depth: 0 }];

  while (queue.length && visited.size < maxPages) {
    const { url, depth } = queue.shift();
    const key = normalizeUrlForVisit(url);
    if (visited.has(key)) continue;
    visited.add(key);

    ctx.log(`Crawler: fetching ${url} (depth ${depth})`);

    try {
      const res = await httpGetText({ fetchAdapter, url });
      const contentType = res.headers['content-type'] || res.headers['Content-Type'] || '';

      if (res.status >= 200 && res.status < 300 && /text\/html|application\/xhtml/i.test(contentType)) {
        const html = res.body || '';

        // Parse and record links/forms/params from this page.
        const { links, endpoints } = parsePage(html, url, origin);

        for (const ep of endpoints) {
          siteModel.addEndpoint(ep);
        }

        if (depth < maxDepth) {
          for (const link of links) {
            const lk = normalizeUrlForVisit(link);
            if (!visited.has(lk)) {
              queue.push({ url: link, depth: depth + 1 });
            }
          }
        }

        ctx.log(`Crawler: ${url} — found ${endpoints.length} endpoint(s), ${links.length} link(s).`);
      } else {
        ctx.log(`Crawler: skip non-HTML ${url} (status ${res.status}).`);
      }
    } catch (err) {
      ctx.log(`Crawler: error fetching ${url}: ${err.message || err}`);
    }
  }

  ctx.log(`Crawler done for ${target.host}. Pages visited: ${visited.size}. Param endpoints: ${siteModel.getParamEndpoints().length}`);
}

// ── Parser: tries cheerio (Node) then DOMParser (browser) ─────────────────────
function parsePage(html, pageUrl, origin) {
  if (cheerio && cheerio.load) {
    return parseWithCheerio(html, pageUrl, origin);
  }
  if (typeof DOMParser !== 'undefined') {
    return parseWithDOMParser(html, pageUrl, origin);
  }
  // Fallback: regex-based extraction for worst-case environments.
  return parseWithRegex(html, pageUrl, origin);
}

// ── Cheerio parser (Node.js) ───────────────────────────────────────────────────
function parseWithCheerio(html, pageUrl, origin) {
  const $ = cheerio.load(html);
  const base = safeNewUrl(pageUrl);
  const links = new Set();
  const endpoints = [];

  // Record the page itself.
  endpoints.push({ url: base.pathname + (base.search || ''), methods: ['GET'] });

  // Links — collect same-origin URLs and extract query params.
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    const resolved = resolveHref(href, base);
    if (!resolved) return;
    if (origin && resolved.origin !== origin) return;
    links.add(resolved.href);

    const params = [];
    resolved.searchParams.forEach((_, name) => {
      params.push({ name, location: 'query' });
    });
    if (params.length) {
      endpoints.push({
        url: resolved.pathname + (resolved.search || ''),
        methods: ['GET'],
        params,
      });
    }
  });

  // Forms — capture action, method, and all named fields.
  $('form').each((_, form) => {
    const method = ($(form).attr('method') || 'GET').toUpperCase();
    const actionAttr = $(form).attr('action') || (base.pathname + base.search);
    const actionUrl = resolveHref(actionAttr, base) || base;
    const endpointUrl = actionUrl.pathname + (actionUrl.search || '');

    const params = [];
    const fields = [];
    $(form).find('input[name], textarea[name], select[name]').each((_, el) => {
      const name = $(el).attr('name');
      if (!name) return;
      params.push({ name, location: method === 'GET' ? 'query' : 'body' });
      fields.push({ name });
    });

    endpoints.push({
      url: endpointUrl,
      methods: [method],
      params,
      forms: [{ method, action: endpointUrl, fields }],
    });
  });

  // Input fields that might carry query params (search boxes, etc.)
  $('input[name][type="text"], input[name][type="search"], input[name]:not([type])').each((_, el) => {
    const name = $(el).attr('name');
    if (!name) return;
    endpoints.push({
      url: base.pathname,
      methods: ['GET'],
      params: [{ name, location: 'query' }],
    });
  });

  return { links: Array.from(links), endpoints };
}

// ── DOMParser parser (browser) ─────────────────────────────────────────────────
function parseWithDOMParser(html, pageUrl, origin) {
  const base = safeNewUrl(pageUrl);
  const links = new Set();
  const endpoints = [];

  let doc;
  try {
    const parser = new DOMParser();
    doc = parser.parseFromString(html, 'text/html');
  } catch {
    return { links: [], endpoints: [] };
  }

  endpoints.push({ url: base.pathname + (base.search || ''), methods: ['GET'] });

  doc.querySelectorAll('a[href]').forEach((a) => {
    const resolved = resolveHref(a.getAttribute('href'), base);
    if (!resolved || (origin && resolved.origin !== origin)) return;
    links.add(resolved.href);
    const params = [];
    resolved.searchParams.forEach((_, name) => params.push({ name, location: 'query' }));
    if (params.length) {
      endpoints.push({ url: resolved.pathname + (resolved.search || ''), methods: ['GET'], params });
    }
  });

  doc.querySelectorAll('form').forEach((form) => {
    const method = (form.getAttribute('method') || 'GET').toUpperCase();
    const actionUrl = resolveHref(form.getAttribute('action') || '', base) || base;
    const endpointUrl = actionUrl.pathname + (actionUrl.search || '');
    const params = [];
    const fields = [];
    form.querySelectorAll('input[name], textarea[name], select[name]').forEach((el) => {
      const name = el.getAttribute('name');
      if (!name) return;
      params.push({ name, location: method === 'GET' ? 'query' : 'body' });
      fields.push({ name });
    });
    endpoints.push({ url: endpointUrl, methods: [method], params, forms: [{ method, action: endpointUrl, fields }] });
  });

  return { links: Array.from(links), endpoints };
}

// ── Regex fallback (worst case: no DOM available) ──────────────────────────────
function parseWithRegex(html, pageUrl, origin) {
  const base = safeNewUrl(pageUrl);
  const links = new Set();
  const endpoints = [];

  endpoints.push({ url: base.pathname + (base.search || ''), methods: ['GET'] });

  // Extract hrefs.
  const hrefRe = /href=["']([^"']+)["']/gi;
  let m;
  while ((m = hrefRe.exec(html)) !== null) {
    const resolved = resolveHref(m[1], base);
    if (!resolved || (origin && resolved.origin !== origin)) continue;
    links.add(resolved.href);
    const params = [];
    resolved.searchParams.forEach((_, name) => params.push({ name, location: 'query' }));
    if (params.length) {
      endpoints.push({ url: resolved.pathname + (resolved.search || ''), methods: ['GET'], params });
    }
  }

  // Extract form inputs using simple regex.
  const inputRe = /name=["']([^"']+)["']/gi;
  while ((m = inputRe.exec(html)) !== null) {
    endpoints.push({
      url: base.pathname,
      methods: ['GET', 'POST'],
      params: [{ name: m[1], location: 'query' }],
    });
  }

  return { links: Array.from(links), endpoints };
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function getOrigin(url) {
  try { return new URL(url).origin; } catch { return null; }
}

function normalizeUrlForVisit(url) {
  try {
    const u = new URL(url);
    return u.origin + u.pathname + (u.search || '');
  } catch { return url; }
}

function safeNewUrl(url) {
  try { return new URL(url); }
  catch { return { pathname: '/', search: '', origin: null, href: url, searchParams: new URLSearchParams() }; }
}

function resolveHref(href, baseUrlObj) {
  if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('javascript:')) return null;
  try { return new URL(href, baseUrlObj.href || baseUrlObj); }
  catch { return null; }
}
