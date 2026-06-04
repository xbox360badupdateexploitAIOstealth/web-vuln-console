// backend/middleware/requestLogger.js
// Minimal request logger for Termux console output.

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const ms    = Date.now() - start;
    const color = res.statusCode >= 500 ? '\x1b[31m'
                : res.statusCode >= 400 ? '\x1b[33m'
                : res.statusCode >= 300 ? '\x1b[36m'
                :                         '\x1b[32m';
    const reset = '\x1b[0m';
    console.log(`${color}[${res.statusCode}]${reset} ${req.method} ${req.path} – ${ms}ms`);
  });
  next();
}

module.exports = { requestLogger };
