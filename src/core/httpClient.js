// src/core/httpClient.js
// Thin HTTP client wrapper that uses an injected fetchAdapter.
// This allows the engine to run in browser, Node, or via a backend proxy.

/**
 * @typedef {Object} HttpResponse
 * @property {number} status
 * @property {Object.<string,string>} headers
 * @property {string} body
 */

/**
 * Perform an HTTP request using the provided adapter.
 * @param {Object} cfg
 * @param {Function} cfg.fetchAdapter - async ({ method, url, headers, body }) => HttpResponse
 * @param {string} cfg.method
 * @param {string} cfg.url
 * @param {Object.<string,string>} [cfg.headers]
 * @param {string|null} [cfg.body]
 * @returns {Promise<HttpResponse>}
 */
export async function httpRequest({ fetchAdapter, method = 'GET', url, headers = {}, body = null }) {
  return await fetchAdapter({ method, url, headers, body });
}

/**
 * Convenience wrapper to fetch text with sane defaults.
 */
export async function httpGetText({ fetchAdapter, url }) {
  const res = await httpRequest({ fetchAdapter, method: 'GET', url });
  // Normalize header keys to lower-case for easier lookup.
  const lowered = {};
  for (const [k, v] of Object.entries(res.headers || {})) {
    lowered[k.toLowerCase()] = v;
  }
  return {
    status: res.status,
    headers: lowered,
    body: res.body || '',
  };
}
