// src/core/crawler.js
// Simple crawler that discovers internal links and forms to populate SiteModel.
// Designed to run in the browser (DOMParser available) or in Node with a DOM shim later.

import { httpGetText } from './httpClient.js';

/**
 * Crawl a target starting from its baseUrl, up to a limited depth and page count,
 * and populate the provided SiteModel with discovered endpoints and parameters.
 *
 * @param {Object} opts
 * @param {Object} opts.ctx - EngineContext (for logging)
 * @param {Object} opts.target - Target instance
 * @param {string} opts.baseUrl
 * @param {import('./siteModel.js').SiteModel} opts.siteModel
 * @param {Object} opts.engineConfig - EngineConfig instance
 * @param {number} [opts.maxDepth]
 * @param {number} [opts.maxPages]
 */
export async function crawlTargetAndBuildSiteModel({
  ctx,
  target,
  baseUrl,
  siteModel,
  engineConfig,
  maxDepth = 1,
  maxPages = 20,
}) {
  const { fetchAdapter } = engineConfig;
  const origin = getOrigin(baseUrl);
  const visited = new Set();
  const queue = [];

  // Start with base URL path.
  queue.push({ url: baseUrl, depth: 0 });

  while (queue.length && visited.size < maxPages) {
    const { url, depth } = queue.shift();
    const key = normalizeUrlForVisit(url);
    if (visited.has(key)) continue;
    visited.add(key);

    ctx.log(`Crawler: fetching ${url} (depth ${depth})`);

    try {
      const res = await httpGetText({ fetchAdapter, url });
      // Only parse HTML-ish content.
      const contentType = res.headers['content-type'] || '';
      if (res.status >= 200 && res.status < 300 && /text\/html|application\/xhtml\+xml/i.test(contentType)) {
        const html = res.body || '';
        const doc = parseHtml(html);
        if (doc) {
          recordLinksAndForms({ ctx, target, siteModel, doc, origin, baseUrl });

          if (depth < maxDepth) {
            const newLinks = extractLinks(doc, origin, baseUrl);
            for (const link of newLinks) {
              const lk = normalizeUrlForVisit(link);
              if (!visited.has(lk)) {
                queue.push({ url: link, depth: depth + 1 });
              }
            }
          }
        }
      } else {
        ctx.log(`Crawler: skipping non-HTML or error response from ${url} (status ${res.status}).`);
      }
    } catch (err) {
      ctx.log(`Crawler: error fetching ${url}: ${err.message || err}`);
    }
  }

  ctx.log(`Crawler: finished for ${target.host}. Pages visited: ${visited.size}`);
}

function getOrigin(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

function normalizeUrlForVisit(url) {
  try {
    const u = new URL(url);
    return u.origin + u.pathname + (u.search || '');
  } catch {
    return url;
  }
}

function parseHtml(html) {
  if (typeof DOMParser !== 'undefined') {
    try {
      const parser = new DOMParser();
      return parser.parseFromString(html, 'text/html');
    } catch {
      return null;
    }
  }
  // Node environment: we can plug in a DOM shim later.
  return null;
}

function extractLinks(doc, origin, baseUrl) {
  const links = new Set();
  const base = safeNewUrl(baseUrl);
  const as = doc.querySelectorAll('a[href]');
  as.forEach((a) => {
    const href = a.getAttribute('href');
    const resolved = resolveHref(href, base);
    if (!resolved) return;
    // Keep only same-origin URLs.
    if (origin && resolved.origin !== origin) return;
    links.add(resolved.href);
  });
  return Array.from(links);
}

function recordLinksAndForms({ ctx, target, siteModel, doc, origin, baseUrl }) {
  const base = safeNewUrl(baseUrl);

  // Record the current page itself as an endpoint.
  siteModel.addEndpoint({ url: base.pathname + (base.search || ''), methods: ['GET'] });

  // Forms.
  const forms = doc.querySelectorAll('form');
  forms.forEach((form) => {
    const method = (form.getAttribute('method') || 'GET').toUpperCase();
    const actionAttr = form.getAttribute('action') || base.pathname + base.search;
    const actionUrlObj = resolveHref(actionAttr, base) || base;
    const endpointUrl = actionUrlObj.pathname + (actionUrlObj.search || '');

    const fields = [];
    form.querySelectorAll('input[name], textarea[name], select[name]').forEach((el) => {
      const name = el.getAttribute('name');
      if (!name) return;
      fields.push({ name });
    });

    siteModel.addEndpoint({
      url: endpointUrl,
      methods: [method],
      params: fields.map((f) => ({ name: f.name, location: method === 'GET' ? 'query' : 'body' })),
      forms: [
        {
          method,
          action: endpointUrl,
          fields,
        },
      ],
    });
  });

  // Query parameters on anchor links.
  const as = doc.querySelectorAll('a[href]');
  as.forEach((a) => {
    const href = a.getAttribute('href');
    const resolved = resolveHref(href, base);
    if (!resolved) return;
    if (origin && resolved.origin !== origin) return;
    const epUrl = resolved.pathname + (resolved.search || '');

    const params = [];
    if (resolved.searchParams) {
      for (const [name] of resolved.searchParams.entries()) {
        params.push({ name, location: 'query' });
      }
    }
    siteModel.addEndpoint({ url: epUrl, methods: ['GET'], params });
  });
}

function safeNewUrl(url) {
  try {
    return new URL(url);
  } catch {
    return { pathname: '/', search: '', origin: null };
  }
}

function resolveHref(href, baseUrlObj) {
  if (!href) return null;
  try {
    return new URL(href, baseUrlObj.href || baseUrlObj);
  } catch {
    return null;
  }
}
