// src/core/siteModel.js

/**
 * SiteModel represents the discovered structure of a target web app.
 * It stores URLs, HTTP methods, parameters, forms, and simple metadata,
 * so modules can reason about the application without re-crawling.
 *
 * v1.1.0 — added techStack + addDiscoveredPath()
 */
export class SiteModel {
  constructor({ targetId }) {
    this.targetId = targetId;

    // Map<string, Endpoint>
    this.endpoints = new Map();

    // Set<string> of discovered paths not yet promoted to full endpoints
    // (populated by robotsTxtParse, techFingerprint, etc.)
    this._discoveredPaths = new Set();

    // Tech fingerprint result — populated by techFingerprint.js (Phase 1a)
    // Shape: { cms, server, language, frameworks: [], rawHeaders: {} }
    this.techStack = {
      cms:        null,   // e.g. 'WordPress 6.4', 'Drupal', 'Joomla'
      server:     null,   // e.g. 'Apache/2.4.51', 'nginx/1.25.3', 'cloudflare'
      language:   null,   // e.g. 'PHP/8.1.2', 'Node.js', 'Python'
      frameworks: [],     // e.g. ['Laravel', 'Next.js', 'Livewire']
      rawHeaders: {},     // full set of fingerprint-related headers from root response
    };
  }

  // ────────────────────────────────────────────────────────────────
  // ENDPOINTS
  // ────────────────────────────────────────────────────────────────

  /**
   * Add or update an endpoint description.
   * @param {Object} data
   * @param {string} data.url
   * @param {string[]} [data.methods]
   * @param {Object[]} [data.params]  - { name, location: 'query'|'body'|'header' }
   * @param {Object[]} [data.forms]   - { method, action, fields[] }
   */
  addEndpoint({ url, methods = ['GET'], params = [], forms = [] }) {
    const key      = normalizeUrl(url);
    const existing = this.endpoints.get(key) || {
      url:    key,
      methods: new Set(),
      params:  new Map(), // name -> Set(locations)
      forms:   [],
    };

    for (const m of methods) existing.methods.add(m.toUpperCase());

    for (const p of params) {
      const name = p.name;
      const loc  = p.location || 'query';
      if (!existing.params.has(name)) existing.params.set(name, new Set());
      existing.params.get(name).add(loc);
    }

    if (forms.length) existing.forms.push(...forms);

    this.endpoints.set(key, existing);
  }

  /**
   * Add a discovered path (from robots.txt, sitemaps, headers, etc.) that
   * isn't yet a full endpoint. The crawler can optionally visit these.
   * Safe to call with any string — silently ignores blank/invalid values.
   */
  addDiscoveredPath(path) {
    if (!path || typeof path !== 'string') return;
    const normalized = normalizeUrl(path);
    if (normalized) this._discoveredPaths.add(normalized);
  }

  /**
   * Returns all discovered paths not yet in the endpoint map.
   * Useful for the crawler to visit after robots.txt / sitemap parsing.
   */
  getDiscoveredPaths() {
    const existing = new Set(this.endpoints.keys());
    return [...this._discoveredPaths].filter((p) => !existing.has(p));
  }

  // ────────────────────────────────────────────────────────────────
  // SERIALIZATION
  // ────────────────────────────────────────────────────────────────

  /**
   * Returns array of endpoint objects with friendly structures
   * (methods: string[], params: { name, locations[] }).
   */
  getAllEndpoints() {
    const out = [];
    for (const ep of this.endpoints.values()) {
      out.push({
        url:     ep.url,
        methods: Array.from(ep.methods),
        params:  Array.from(ep.params.entries()).map(([name, locSet]) => ({
          name,
          locations: Array.from(locSet),
        })),
        forms: ep.forms,
      });
    }
    return out;
  }

  /**
   * Convenience: get endpoints that have any parameters (for injection).
   */
  getParamEndpoints() {
    return this.getAllEndpoints().filter((ep) => ep.params.length > 0);
  }
}

function normalizeUrl(url) {
  try {
    if (/^https?:\/\//i.test(url)) {
      const u = new URL(url);
      return u.pathname + (u.search || '');
    }
    return url.startsWith('/') ? url : `/${url}`;
  } catch {
    return url;
  }
}
