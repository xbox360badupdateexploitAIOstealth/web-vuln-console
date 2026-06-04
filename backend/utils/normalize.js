// backend/utils/normalize.js
// Target normalization and validation utilities.

/**
 * normalizeTarget(raw)
 * Takes a raw string (domain, URL, or IP) and returns a normalized origin URL.
 * Returns null if the input is not resolvable.
 */
function normalizeTarget(raw) {
  if (!raw || typeof raw !== 'string') return null;
  raw = raw.trim();
  if (!raw) return null;

  // Already a full URL.
  try {
    const u = new URL(raw);
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      return u.origin;
    }
  } catch {}

  // Bare domain or IP – prepend https://
  try {
    const u = new URL(`https://${raw}`);
    return u.origin;
  } catch {}

  return null;
}

/**
 * normalizeTargets(rawList)
 * Normalizes an array of raw target strings.
 * Returns { valid: string[], invalid: string[] }
 */
function normalizeTargets(rawList) {
  const valid   = [];
  const invalid = [];
  const seen    = new Set();

  for (const raw of rawList) {
    const normalized = normalizeTarget(typeof raw === 'string' ? raw : (raw.host || raw.url || ''));
    if (!normalized) {
      invalid.push(String(raw));
    } else if (!seen.has(normalized)) {
      seen.add(normalized);
      valid.push(normalized);
    }
  }
  return { valid, invalid };
}

module.exports = { normalizeTarget, normalizeTargets };
