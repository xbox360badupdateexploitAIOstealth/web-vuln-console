// backend/utils/retry.js
// Retry helper with exponential backoff.
// Used by the engine for flaky network conditions on Android/Termux.

/**
 * withRetry(fn, options)
 * Calls fn() up to maxAttempts times with exponential backoff.
 * Returns the resolved value or throws the last error.
 */
async function withRetry(fn, options = {}) {
  const maxAttempts = options.maxAttempts || 3;
  const baseDelayMs = options.baseDelayMs || 500;
  const maxDelayMs  = options.maxDelayMs  || 8000;

  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt === maxAttempts) break;
      const delay = Math.min(baseDelayMs * Math.pow(2, attempt - 1), maxDelayMs);
      const jitter = Math.floor(Math.random() * 200);
      console.warn(`[RETRY] Attempt ${attempt} failed. Retrying in ${delay + jitter}ms... (${String(err).slice(0, 80)})`);
      await new Promise((res) => setTimeout(res, delay + jitter));
    }
  }
  throw lastErr;
}

module.exports = { withRetry };
