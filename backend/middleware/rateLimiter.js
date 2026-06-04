// backend/middleware/rateLimiter.js
// Simple in-memory sliding-window rate limiter.
// Protects the backend when running on low-power hardware (Android/Termux).

const windows = new Map();

/**
 * createRateLimiter(maxRequests, windowMs)
 * Returns Express middleware that allows up to maxRequests per windowMs per IP.
 */
function createRateLimiter(maxRequests = 120, windowMs = 60000) {
  return function rateLimiter(req, res, next) {
    const ip  = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    let   win = windows.get(ip);

    if (!win || now - win.start > windowMs) {
      win = { count: 0, start: now };
    }

    win.count++;
    windows.set(ip, win);

    res.setHeader('X-RateLimit-Limit',     maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - win.count));

    if (win.count > maxRequests) {
      return res.status(429).json({
        error: 'Too many requests. Slow down – this is running on a phone, not AWS. 😅',
        retryAfterMs: windowMs - (now - win.start),
      });
    }
    next();
  };
}

module.exports = { createRateLimiter };
