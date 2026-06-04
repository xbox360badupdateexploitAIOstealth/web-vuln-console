// src/core/siteModel.js

/**
 * SiteModel represents the discovered structure of a target web app.
 * It stores URLs, HTTP methods, parameters, forms, and simple metadata,
 * so modules can reason about the application without re-crawling.
 */
export class SiteModel {
  constructor({ targetId }) {
    this.targetId = targetId;
    // Map<string, Endpoint>
    this.endpoints = new Map();
  }

  /**
   * Add or update an endpoint description.
   * @param {Object} data
   * @param {string} data.url
   * @param {string[]} [data.methods]
   * @param {Object[]} [data.params] - { name, location: 'query'|'body'|'header' }
   * @param {Object[]} [data.forms] - { method, action, fields[] }
   */
  addEndpoint({ url, methods = ['GET'], params = [], forms = [] }) {
    const key = normalizeUrl(url);
    const existing = this.endpoints.get(key) || {
      url: key,
      methods: new Set(),
      params: new Map(), // name -> Set(locations)
      forms: [],
    };

    for (const m of methods) existing.methods.add(m.toUpperCase());

    for (const p of params) {
      const name = p.name;
      const loc = p.location || 'query';
      if (!existing.params.has(name)) {
        existing.params.set(name, new Set());
      }
      existing.params.get(name).add(loc);
    }

    if (forms.length) {
      existing.forms.push(...forms);
    }

    this.endpoints.set(key, existing);
  }

  /**
   * Returns array of endpoint objects with friendly structures
   * (methods: string[], params: { name, locations[] }).
   */
  getAllEndpoints() {
    const out = [];
    for (const ep of this.endpoints.values()) {
      out.push({
        url: ep.url,
        methods: Array.from(ep.methods),
        params: Array.from(ep.params.entries()).map(([name, locSet]) => ({
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
    // If full URL, normalize; if path only, just ensure leading slash
    if (/^https?:\/\//i.test(url)) {
      const u = new URL(url);
      // We keep path + search only for key; host is stored at target level.
      return u.pathname + (u.search || '');
    }
    return url.startsWith('/') ? url : `/${url}`;
  } catch (e) {
    return url;
  }
}
