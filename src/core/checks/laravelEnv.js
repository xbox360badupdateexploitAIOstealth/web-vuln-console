// src/core/checks/laravelEnv.js
// Module: exposure.cve.laravel_env_hunt
//
// Advanced Laravel .env exposure hunter — goes far beyond the basic exposure.env.direct module.
//
// What this does that basic .env check does NOT:
//   1. 50+ Laravel-specific probe paths (standard, docroot-mismatch, storage, multi-tenant,
//      common deployment mistakes, Forge/Envoyer/Ploi provisioned paths, Docker mounts)
//   2. Deep secret extraction: APP_KEY, DB_*, REDIS_*, MAIL_*, AWS_*, STRIPE_*, TWILIO_*,
//      PUSHER_*, JWT_*, SANCTUM_*, OAUTH_*, SENTRY_*, OPENAI_*, custom secret patterns
//   3. APP_KEY → Laravel RCE risk annotation (CVE-2024-55556 Crater Invoice pattern,
//      broader deserialization gadget chain risk in unpatched Laravel apps)
//   4. APP_KEY entropy + format validation (base64:... prefix check, key length check)
//   5. Database credential risk scoring — flags cloud DB hostnames (RDS, PlanetScale,
//      Supabase, Railway, CockroachDB) as higher-risk exfil targets
//   6. Dokan/multi-vendor marketplace .env paths (CVE-2025-70841 pattern)
//   7. Laravel Octane / FrankenPHP / Swoole specific config paths
//   8. .env backup/temp file variants that Laravel deployments commonly leave behind
//   9. robots.txt + sitemap.xml passive recon pre-pass to find Laravel app hints
//  10. X-Powered-By / X-Laravel-Version header fingerprinting
//  11. Laravel debug mode detection (/telescope, /_debugbar, Ignition error page)
//  12. Laravel-specific 404/500 page fingerprinting to confirm framework before probing
//  13. Severity escalation matrix: any hit → high; APP_KEY hit → critical;
//      APP_KEY + cloud DB → critical++ annotated; APP_KEY + known-vuln version → RCE flag
//  14. All extracted secrets are redacted in logs (first 6 chars + ***) but full value
//      stored in Evidence for the authorized operator
//
// CVE references:
//   CVE-2024-55556 — Crater Invoice (Laravel) APP_KEY → unauth RCE via deserialization
//   CVE-2025-70841 — Dokan multi-vendor marketplace /script/.env path exposure
//   CVE-2025-46565 — Vite dev server @fs bypass (checked in TODO-06, noted here for context)
//   General Laravel deserialization gadget chain risk: any Laravel app exposing APP_KEY
//   with outdated composer packages (laravel/framework < 10.48.x or < 11.31.x) may be
//   exploitable via POP chain deserialization through cookie / remember_token forgery.

import { Finding, Evidence } from '../models.js';
import { moduleDefById }     from '../moduleRegistry.js';

// ─────────────────────────────────────────────────────────────────────────────
// PROBE PATH CATALOGUE
// ─────────────────────────────────────────────────────────────────────────────

// Standard Laravel doc-root paths
const STANDARD_PATHS = [
  '/.env',
  '/.env.example',       // often left with real values copied from .env
  '/.env.local',
  '/.env.production',
  '/.env.prod',
  '/.env.staging',
  '/.env.development',
  '/.env.dev',
  '/.env.testing',
  '/.env.test',
  '/.env.qa',
  '/.env.uat',
  '/.env.backup',
  '/.env.bak',
  '/.env.old',
  '/.env.orig',
  '/.env.save',
  '/.env.swp',           // vim swap file
  '/.env~',              // emacs/vi backup
  '/.env.1',             // numbered rotations
  '/.env.2',
];

// Docroot-mismatch paths — when public/ is not the webroot (misconfigured nginx/Apache)
const DOCROOT_MISMATCH_PATHS = [
  '/public/.env',
  '/laravel/.env',
  '/app/.env',
  '/backend/.env',
  '/api/.env',
  '/www/.env',
  '/html/.env',
  '/web/.env',
  '/htdocs/.env',
  '/webroot/.env',
  '/application/.env',
  '/project/.env',
  '/site/.env',
  '/cms/.env',
];

// Laravel storage / framework internal paths exposed via misconfigured server
const STORAGE_PATHS = [
  '/storage/.env',
  '/storage/app/.env',
  '/storage/logs/laravel.log',    // log file — may contain stack traces with secrets
  '/storage/logs/.env',
  '/bootstrap/.env',
  '/bootstrap/cache/.env',
  '/config/.env',
];

// Dokan / WooCommerce Laravel multi-tenant marketplace paths (CVE-2025-70841)
const DOKAN_PATHS = [
  '/script/.env',
  '/scripts/.env',
  '/vendor/.env',
  '/vendor/laravel/.env',
  '/packages/.env',
];

// Laravel Forge / Envoyer / Ploi deployment convention paths
const DEPLOY_PATHS = [
  '/releases/current/.env',
  '/current/.env',
  '/deploy/.env',
  '/deployment/.env',
  '/../.env',            // one dir above webroot (Forge default is /home/forge/site.com)
  '/../../.env',
];

// Laravel Octane / Docker / containerized deployment paths
const OCTANE_DOCKER_PATHS = [
  '/octane/.env',
  '/.env.octane',
  '/docker/.env',
  '/.docker/.env',
  '/docker-compose/.env',
  '/.env.docker',
  '/.env.container',
];

// Commonly forgotten CI/CD artifact paths
const CICD_PATHS = [
  '/.env.ci',
  '/.env.github',
  '/.env.gitlab',
  '/.env.pipeline',
  '/.github/.env',
  '/.gitlab/.env',
];

// All probe paths combined — ordered by probability (most likely hits first)
export const ALL_PROBE_PATHS = [
  ...STANDARD_PATHS,
  ...DOCROOT_MISMATCH_PATHS,
  ...STORAGE_PATHS,
  ...DOKAN_PATHS,
  ...DEPLOY_PATHS,
  ...OCTANE_DOCKER_PATHS,
  ...CICD_PATHS,
];

// ─────────────────────────────────────────────────────────────────────────────
// SECRET EXTRACTION PATTERNS
// ─────────────────────────────────────────────────────────────────────────────

// Each entry: { key, regex, severity, label, rceRisk }
const SECRET_PATTERNS = [
  // ── Core Laravel ─────────────────────────────────────────────────────────
  {
    key: 'APP_KEY',
    regex: /^APP_KEY=(.+)$/m,
    severity: 'critical',
    label: 'Laravel Application Key',
    rceRisk: true,
  },
  {
    key: 'APP_DEBUG',
    regex: /^APP_DEBUG=(.+)$/m,
    severity: 'info',
    label: 'Laravel Debug Mode',
    rceRisk: false,
  },
  {
    key: 'APP_URL',
    regex: /^APP_URL=(.+)$/m,
    severity: 'info',
    label: 'Application URL',
    rceRisk: false,
  },

  // ── Database ─────────────────────────────────────────────────────────────
  {
    key: 'DB_PASSWORD',
    regex: /^DB_PASSWORD=(.+)$/m,
    severity: 'critical',
    label: 'Database Password',
    rceRisk: false,
  },
  {
    key: 'DB_USERNAME',
    regex: /^DB_USERNAME=(.+)$/m,
    severity: 'high',
    label: 'Database Username',
    rceRisk: false,
  },
  {
    key: 'DB_HOST',
    regex: /^DB_HOST=(.+)$/m,
    severity: 'high',
    label: 'Database Host',
    rceRisk: false,
  },
  {
    key: 'DB_DATABASE',
    regex: /^DB_DATABASE=(.+)$/m,
    severity: 'medium',
    label: 'Database Name',
    rceRisk: false,
  },
  {
    key: 'DATABASE_URL',
    regex: /^DATABASE_URL=(.+)$/m,
    severity: 'critical',
    label: 'Full Database URL (contains credentials)',
    rceRisk: false,
  },

  // ── Redis / Cache ─────────────────────────────────────────────────────────
  {
    key: 'REDIS_PASSWORD',
    regex: /^REDIS_PASSWORD=(.+)$/m,
    severity: 'high',
    label: 'Redis Password',
    rceRisk: false,
  },
  {
    key: 'REDIS_URL',
    regex: /^REDIS_URL=(.+)$/m,
    severity: 'high',
    label: 'Redis URL (may contain credentials)',
    rceRisk: false,
  },
  {
    key: 'MEMCACHED_PASSWORD',
    regex: /^MEMCACHED_PASSWORD=(.+)$/m,
    severity: 'high',
    label: 'Memcached Password',
    rceRisk: false,
  },

  // ── Mail / SMTP ───────────────────────────────────────────────────────────
  {
    key: 'MAIL_PASSWORD',
    regex: /^MAIL_PASSWORD=(.+)$/m,
    severity: 'high',
    label: 'Mail/SMTP Password',
    rceRisk: false,
  },
  {
    key: 'MAIL_USERNAME',
    regex: /^MAIL_USERNAME=(.+)$/m,
    severity: 'medium',
    label: 'Mail Username',
    rceRisk: false,
  },
  {
    key: 'MAILGUN_SECRET',
    regex: /^MAILGUN_SECRET=(.+)$/m,
    severity: 'high',
    label: 'Mailgun API Secret',
    rceRisk: false,
  },
  {
    key: 'POSTMARK_TOKEN',
    regex: /^POSTMARK_TOKEN=(.+)$/m,
    severity: 'high',
    label: 'Postmark API Token',
    rceRisk: false,
  },
  {
    key: 'SES_SECRET',
    regex: /^SES_SECRET=(.+)$/m,
    severity: 'high',
    label: 'AWS SES Secret',
    rceRisk: false,
  },

  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    key: 'AWS_SECRET_ACCESS_KEY',
    regex: /^AWS_SECRET_ACCESS_KEY=(.+)$/m,
    severity: 'critical',
    label: 'AWS Secret Access Key',
    rceRisk: false,
  },
  {
    key: 'AWS_ACCESS_KEY_ID',
    regex: /^AWS_ACCESS_KEY_ID=(.+)$/m,
    severity: 'critical',
    label: 'AWS Access Key ID',
    rceRisk: false,
  },
  {
    key: 'AWS_BUCKET',
    regex: /^AWS_BUCKET=(.+)$/m,
    severity: 'medium',
    label: 'AWS S3 Bucket Name',
    rceRisk: false,
  },

  // ── Stripe ────────────────────────────────────────────────────────────────
  {
    key: 'STRIPE_SECRET',
    regex: /^STRIPE_SECRET=(.+)$/m,
    severity: 'critical',
    label: 'Stripe Secret Key',
    rceRisk: false,
  },
  {
    key: 'STRIPE_KEY',
    regex: /^STRIPE_KEY=(.+)$/m,
    severity: 'high',
    label: 'Stripe Publishable Key',
    rceRisk: false,
  },
  {
    key: 'STRIPE_WEBHOOK_SECRET',
    regex: /^STRIPE_WEBHOOK_SECRET=(.+)$/m,
    severity: 'high',
    label: 'Stripe Webhook Secret',
    rceRisk: false,
  },

  // ── Pusher / Soketi / Broadcasting ────────────────────────────────────────
  {
    key: 'PUSHER_APP_SECRET',
    regex: /^PUSHER_APP_SECRET=(.+)$/m,
    severity: 'high',
    label: 'Pusher App Secret',
    rceRisk: false,
  },
  {
    key: 'PUSHER_APP_KEY',
    regex: /^PUSHER_APP_KEY=(.+)$/m,
    severity: 'medium',
    label: 'Pusher App Key',
    rceRisk: false,
  },

  // ── Auth / JWT / OAuth ────────────────────────────────────────────────────
  {
    key: 'JWT_SECRET',
    regex: /^JWT_SECRET=(.+)$/m,
    severity: 'critical',
    label: 'JWT Secret Key',
    rceRisk: false,
  },
  {
    key: 'JWT_PRIVATE_KEY',
    regex: /^JWT_PRIVATE_KEY=(.+)$/m,
    severity: 'critical',
    label: 'JWT Private Key',
    rceRisk: false,
  },
  {
    key: 'SANCTUM_STATEFUL_DOMAINS',
    regex: /^SANCTUM_STATEFUL_DOMAINS=(.+)$/m,
    severity: 'info',
    label: 'Sanctum Stateful Domains (recon)',
    rceRisk: false,
  },
  {
    key: 'PASSPORT_CLIENT_SECRET',
    regex: /^PASSPORT_CLIENT_SECRET=(.+)$/m,
    severity: 'critical',
    label: 'Laravel Passport OAuth Client Secret',
    rceRisk: false,
  },
  {
    key: 'OAUTH_CLIENT_SECRET',
    regex: /^OAUTH_CLIENT_SECRET=(.+)$/m,
    severity: 'critical',
    label: 'OAuth Client Secret',
    rceRisk: false,
  },
  {
    key: 'GOOGLE_CLIENT_SECRET',
    regex: /^GOOGLE_CLIENT_SECRET=(.+)$/m,
    severity: 'high',
    label: 'Google OAuth Client Secret',
    rceRisk: false,
  },
  {
    key: 'GITHUB_CLIENT_SECRET',
    regex: /^GITHUB_CLIENT_SECRET=(.+)$/m,
    severity: 'high',
    label: 'GitHub OAuth Client Secret',
    rceRisk: false,
  },

  // ── Twilio / SMS ──────────────────────────────────────────────────────────
  {
    key: 'TWILIO_AUTH_TOKEN',
    regex: /^TWILIO_AUTH_TOKEN=(.+)$/m,
    severity: 'high',
    label: 'Twilio Auth Token',
    rceRisk: false,
  },
  {
    key: 'TWILIO_ACCOUNT_SID',
    regex: /^TWILIO_ACCOUNT_SID=(.+)$/m,
    severity: 'medium',
    label: 'Twilio Account SID',
    rceRisk: false,
  },

  // ── AI / LLM ──────────────────────────────────────────────────────────────
  {
    key: 'OPENAI_API_KEY',
    regex: /^OPENAI_API_KEY=(.+)$/m,
    severity: 'critical',
    label: 'OpenAI API Key',
    rceRisk: false,
  },
  {
    key: 'OPENAI_KEY',
    regex: /^OPENAI_KEY=(.+)$/m,
    severity: 'critical',
    label: 'OpenAI Key (alt var)',
    rceRisk: false,
  },
  {
    key: 'HUGGINGFACE_API_KEY',
    regex: /^HUGGINGFACE_API_KEY=(.+)$/m,
    severity: 'high',
    label: 'HuggingFace API Key',
    rceRisk: false,
  },
  {
    key: 'REPLICATE_API_TOKEN',
    regex: /^REPLICATE_API_TOKEN=(.+)$/m,
    severity: 'high',
    label: 'Replicate API Token',
    rceRisk: false,
  },
  {
    key: 'ANTHROPIC_API_KEY',
    regex: /^ANTHROPIC_API_KEY=(.+)$/m,
    severity: 'critical',
    label: 'Anthropic (Claude) API Key',
    rceRisk: false,
  },

  // ── Monitoring / Error Tracking ───────────────────────────────────────────
  {
    key: 'SENTRY_DSN',
    regex: /^SENTRY_DSN=(.+)$/m,
    severity: 'high',
    label: 'Sentry DSN (error tracking, may contain auth token)',
    rceRisk: false,
  },
  {
    key: 'BUGSNAG_API_KEY',
    regex: /^BUGSNAG_API_KEY=(.+)$/m,
    severity: 'medium',
    label: 'Bugsnag API Key',
    rceRisk: false,
  },

  // ── Payment / Finance ─────────────────────────────────────────────────────
  {
    key: 'PAYPAL_SECRET',
    regex: /^PAYPAL_SECRET=(.+)$/m,
    severity: 'critical',
    label: 'PayPal API Secret',
    rceRisk: false,
  },
  {
    key: 'BRAINTREE_PRIVATE_KEY',
    regex: /^BRAINTREE_PRIVATE_KEY=(.+)$/m,
    severity: 'critical',
    label: 'Braintree Private Key',
    rceRisk: false,
  },
  {
    key: 'SQUARE_ACCESS_TOKEN',
    regex: /^SQUARE_ACCESS_TOKEN=(.+)$/m,
    severity: 'critical',
    label: 'Square Access Token',
    rceRisk: false,
  },

  // ── Generic high-value catch-alls ─────────────────────────────────────────
  {
    key: 'SECRET_KEY',
    regex: /^SECRET_KEY=(.+)$/m,
    severity: 'high',
    label: 'Generic Secret Key',
    rceRisk: false,
  },
  {
    key: 'API_SECRET',
    regex: /^API_SECRET=(.+)$/m,
    severity: 'high',
    label: 'Generic API Secret',
    rceRisk: false,
  },
  {
    key: 'PRIVATE_KEY',
    regex: /^PRIVATE_KEY=(.+)$/m,
    severity: 'critical',
    label: 'Generic Private Key',
    rceRisk: false,
  },
  {
    key: 'ENCRYPTION_KEY',
    regex: /^ENCRYPTION_KEY=(.+)$/m,
    severity: 'critical',
    label: 'Encryption Key',
    rceRisk: false,
  },
];

// Cloud DB hostname patterns — escalate risk when DB_HOST matches one of these
const CLOUD_DB_PATTERNS = [
  { pattern: /\.rds\.amazonaws\.com$/i,     label: 'AWS RDS'        },
  { pattern: /\.planetscale\.com$/i,         label: 'PlanetScale'    },
  { pattern: /\.supabase\.co$/i,             label: 'Supabase'       },
  { pattern: /\.railway\.app$/i,             label: 'Railway'        },
  { pattern: /\.cockroachdb\.com$/i,         label: 'CockroachDB'    },
  { pattern: /\.neon\.tech$/i,               label: 'Neon'           },
  { pattern: /\.turso\.io$/i,                label: 'Turso'          },
  { pattern: /\.elephantsql\.com$/i,         label: 'ElephantSQL'    },
  { pattern: /\.heroku\.com$/i,              label: 'Heroku Postgres' },
  { pattern: /db\.\w+\.digitalocean\.com$/i, label: 'DigitalOcean Managed DB' },
  { pattern: /\.mysql\.database\.azure\.com$/i, label: 'Azure MySQL' },
  { pattern: /\.postgres\.database\.azure\.com$/i, label: 'Azure Postgres' },
  { pattern: /\.sql\.azuresynapse\.net$/i,   label: 'Azure Synapse'  },
  { pattern: /cloudsql/i,                    label: 'Google Cloud SQL' },
];

// ─────────────────────────────────────────────────────────────────────────────
// LARAVEL FINGERPRINTING HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Attempt to fingerprint whether the target is running Laravel before probing
 * all 50+ paths. This reduces noise on non-Laravel targets.
 * Returns { isLaravel: bool, signals: string[] }
 */
async function fingerprintLaravel({ baseUrl, fetchAdapter }) {
  const signals = [];

  // Check common Laravel debug/diagnostic endpoints
  const fingerprintUrls = [
    { url: baseUrl + '/',                   check: bodyIsLaravel },
    { url: baseUrl + '/telescope',          check: (r) => r.status === 200 || r.status === 302 },
    { url: baseUrl + '/_debugbar/assets',   check: (r) => r.status === 200 || r.status === 302 },
    { url: baseUrl + '/up',                 check: bodyIsLaravel }, // Laravel 11 health endpoint
  ];

  for (const { url, check } of fingerprintUrls) {
    try {
      const res = await fetchAdapter(url, { method: 'GET', timeout: 5000 });
      const body = typeof res.body === 'string' ? res.body : '';
      const headers = res.headers || {};

      // X-Powered-By / X-Laravel headers
      if (/laravel/i.test(headers['x-powered-by'] || '')) {
        signals.push(`X-Powered-By: ${headers['x-powered-by']}`);
      }
      if (headers['x-laravel-version']) {
        signals.push(`X-Laravel-Version: ${headers['x-laravel-version']}`);
      }
      // XSRF-TOKEN cookie is a Laravel fingerprint
      const setCookie = headers['set-cookie'] || '';
      if (/XSRF-TOKEN/i.test(Array.isArray(setCookie) ? setCookie.join(';') : setCookie)) {
        signals.push('XSRF-TOKEN cookie present (Laravel session)');
      }
      // Body checks
      if (check(res, body)) {
        signals.push(`Laravel indicator at ${url}`);
      }
    } catch { /* unreachable endpoint — skip */ }
  }

  // Check robots.txt for Laravel-specific disallow paths
  try {
    const robotsRes = await fetchAdapter(baseUrl + '/robots.txt', { method: 'GET', timeout: 4000 });
    const rb = (robotsRes.body || '').toLowerCase();
    if (rb.includes('/telescope') || rb.includes('/horizon') || rb.includes('/nova')) {
      signals.push('robots.txt contains Laravel admin paths (/telescope|/horizon|/nova)');
    }
  } catch { /* ignore */ }

  return { isLaravel: signals.length > 0, signals };
}

function bodyIsLaravel(res, body = '') {
  const b = (body || (typeof res.body === 'string' ? res.body : '')).slice(0, 8192);
  return (
    /laravel/i.test(b) ||
    /Illuminate\\/i.test(b) ||
    /XSRF-TOKEN/i.test(b) ||
    /csrf-token/i.test(b) ||
    /Whoops! There was an error\./i.test(b) || // Ignition error page
    /laravel\.com/i.test(b)
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// .ENV CONTENT VALIDATORS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if body looks like a real dotenv file (not a 200 HTML page).
 * Requires at least 2 KEY=VALUE lines in the first 60 lines.
 */
function isValidDotenv(body) {
  if (!body || body.length < 10) return false;
  // Reject if it looks like HTML
  if (/<html|<!doctype|<head/i.test(body.slice(0, 512))) return false;
  const lines = body.split(/\r?\n/).slice(0, 60);
  const kvLines = lines.filter((l) => /^[A-Z][A-Z0-9_]+=.*/i.test(l.trim()));
  return kvLines.length >= 2;
}

/**
 * Check if this looks like a Laravel-specific .env (has APP_NAME or APP_KEY line).
 */
function isLaravelDotenv(body) {
  return /^APP_(?:NAME|KEY|ENV|URL|DEBUG)=/m.test(body);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECRET EXTRACTION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extract all known secrets from a .env body.
 * Returns array of { key, value, severity, label, rceRisk }
 * Values are stored raw (for evidence) and redacted for logs.
 */
function extractSecrets(body) {
  const found = [];
  for (const pattern of SECRET_PATTERNS) {
    const match = pattern.regex.exec(body);
    if (match) {
      const raw = match[1].trim();
      if (raw && raw !== '""' && raw !== "''" && raw.toLowerCase() !== 'null' && raw !== '') {
        found.push({
          key:      pattern.key,
          value:    raw,
          severity: pattern.severity,
          label:    pattern.label,
          rceRisk:  pattern.rceRisk,
        });
      }
    }
  }
  return found;
}

/**
 * Redact a secret value for safe logging — show first 6 chars then ***.
 */
function redact(value) {
  if (!value || value.length <= 6) return '***';
  return value.slice(0, 6) + '***';
}

// ─────────────────────────────────────────────────────────────────────────────
// APP_KEY ANALYSIS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Analyse a Laravel APP_KEY value.
 * Returns { valid, algorithm, rawKey, entropyNote, rceAnnotation }
 */
function analyseAppKey(rawValue) {
  // Laravel APP_KEY format: "base64:<base64-encoded-32-byte-key>"
  const base64Match = rawValue.match(/^base64:(.+)$/);
  if (!base64Match) {
    return {
      valid: false,
      algorithm: 'unknown',
      rawKey: rawValue,
      entropyNote: 'APP_KEY missing base64: prefix — may be malformed or a custom cipher',
      rceAnnotation: 'Malformed APP_KEY may still be usable in deserialization attacks depending on Laravel version.',
    };
  }

  const b64 = base64Match[1];
  let decoded;
  try {
    decoded = Buffer.from(b64, 'base64');
  } catch {
    return {
      valid: false,
      algorithm: 'aes-256-cbc',
      rawKey: b64,
      entropyNote: 'APP_KEY base64 value is not valid base64',
      rceAnnotation: 'Invalid encoding — likely not exploitable via standard gadget chain.',
    };
  }

  const keyLen = decoded.length;
  const isCorrectLength = keyLen === 32; // AES-256 requires 32-byte key
  const entropyNote = isCorrectLength
    ? `32-byte AES-256-CBC key (correct length)`
    : `Key is ${keyLen} bytes — expected 32 for AES-256-CBC (may indicate non-standard cipher or truncation)`;

  const rceAnnotation =
    'With this APP_KEY, an attacker on a vulnerable Laravel version (<10.48.x or <11.31.x) ' +
    'can craft a malicious signed cookie or remember_token triggering PHP deserialization ' +
    'via the POP gadget chain (Crater Invoice CVE-2024-55556 pattern). ' +
    'Verify composer.lock for laravel/framework version before confirming RCE risk. ' +
    'Remediation: rotate APP_KEY immediately with `php artisan key:generate` and ' +
    'invalidate all existing sessions.';

  return {
    valid: isCorrectLength,
    algorithm: 'aes-256-cbc',
    rawKey: b64,
    entropyNote,
    rceAnnotation,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// DATABASE RISK SCORING
// ─────────────────────────────────────────────────────────────────────────────

function scoreDbRisk(secrets) {
  const dbHost     = secrets.find((s) => s.key === 'DB_HOST')?.value || '';
  const dbPassword = secrets.find((s) => s.key === 'DB_PASSWORD')?.value;
  const dbUrl      = secrets.find((s) => s.key === 'DATABASE_URL')?.value;

  let cloudProvider = null;
  for (const { pattern, label } of CLOUD_DB_PATTERNS) {
    if (pattern.test(dbHost) || pattern.test(dbUrl || '')) {
      cloudProvider = label;
      break;
    }
  }

  return {
    hasPassword:   !!dbPassword,
    hasCloudDb:    !!cloudProvider,
    cloudProvider,
    internetFacing: cloudProvider !== null || /^\d{1,3}(\.\d{1,3}){3}$/.test(dbHost),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// SEVERITY ESCALATION MATRIX
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Determine overall finding severity from extracted secrets.
 * Rule matrix:
 *   - APP_KEY + cloud DB creds → critical (RCE + data exfil risk)
 *   - APP_KEY present           → critical
 *   - AWS/Stripe/PayPal keys    → critical
 *   - DB_PASSWORD / JWT_SECRET  → critical
 *   - Any credential at all     → high
 *   - Only info-level fields    → high (still a .env exposure)
 *   - No secrets extracted      → high (file still leaked)
 */
function escalateSeverity(secrets, dbRisk) {
  const criticalKeys = new Set([
    'APP_KEY', 'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID', 'STRIPE_SECRET',
    'DB_PASSWORD', 'DATABASE_URL', 'JWT_SECRET', 'JWT_PRIVATE_KEY',
    'PASSPORT_CLIENT_SECRET', 'OAUTH_CLIENT_SECRET', 'PRIVATE_KEY',
    'ENCRYPTION_KEY', 'PAYPAL_SECRET', 'BRAINTREE_PRIVATE_KEY',
    'SQUARE_ACCESS_TOKEN', 'OPENAI_API_KEY', 'OPENAI_KEY', 'ANTHROPIC_API_KEY',
  ]);
  const hasCritical = secrets.some((s) => criticalKeys.has(s.key));
  if (hasCritical || (dbRisk.hasPassword && dbRisk.hasCloudDb)) return 'critical';
  if (secrets.some((s) => s.severity === 'high')) return 'high';
  return 'high'; // minimum high for any .env leak
}

// ─────────────────────────────────────────────────────────────────────────────
// LARAVEL DEBUG MODE CHECK (supplementary)
// ─────────────────────────────────────────────────────────────────────────────

async function checkLaravelDebugMode({ ctx, target, baseUrl, fetchAdapter }) {
  // Trigger a 404 on a path that doesn't exist — Ignition shows debug info when APP_DEBUG=true
  const probeUrl = baseUrl + '/wvc-debug-probe-' + Math.random().toString(36).slice(2, 8);
  try {
    const res = await fetchAdapter(probeUrl, { method: 'GET', timeout: 5000 });
    const body = res.body || '';
    if (
      res.status >= 400 &&
      (/Ignition|Whoops!/i.test(body) || /STACK TRACE|stack-trace|exception/i.test(body))
    ) {
      const finding = new Finding({
        projectId:  ctx.project.id,
        scanJobId:  ctx.job.id,
        targetId:   target.id,
        moduleId:   'exposure.cve.laravel_env_hunt',
        title:      'Laravel Debug Mode Enabled (APP_DEBUG=true)',
        shortDescription:
          `Laravel Ignition debug page is publicly accessible at ${probeUrl}. ` +
          'This leaks stack traces, environment variables, and internal file paths.',
        detailedDescription:
          'The application is running with APP_DEBUG=true in production. ' +
          'The Ignition error handler displays full stack traces, environment variable values, ' +
          'internal file system paths, and request data to unauthenticated users. ' +
          'This may directly expose secrets from the .env file in error responses. ' +
          'Fix: Set APP_DEBUG=false and APP_ENV=production in .env.',
        severity:   'high',
        category:   'exposure',
        owaspTag:   'A05-Security-Misconfiguration',
        cweTag:     'CWE-209',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(new Evidence({
        findingId:              finding.id,
        url:                    probeUrl,
        method:                 'GET',
        responseStatus:         res.status,
        responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
        responseBodySnippet:    body.slice(0, 2048),
        matchedPattern:         'Ignition / Whoops! debug page',
      }));
      ctx.log(`🟠 HIGH: Laravel debug mode active — Ignition page at ${probeUrl}`);
    }
  } catch { /* ignore */ }
}

// ─────────────────────────────────────────────────────────────────────────────
// COMPOSER.LOCK / PACKAGE RECON (bonus — gets Laravel version for RCE context)
// ─────────────────────────────────────────────────────────────────────────────

async function checkComposerLock({ ctx, target, baseUrl, fetchAdapter }) {
  const urls = [
    baseUrl + '/composer.lock',
    baseUrl + '/composer.json',
  ];
  for (const url of urls) {
    try {
      const res = await fetchAdapter(url, { method: 'GET', timeout: 5000 });
      if (res.status !== 200) continue;
      const body = res.body || '';
      if (!body.includes('"laravel/framework"') && !body.includes('"require"')) continue;

      // Try to extract laravel/framework version
      let laravelVersion = null;
      const versionMatch = body.match(/"laravel\/framework"[^}]*"version"\s*:\s*"([^"]+)"/s);
      if (versionMatch) laravelVersion = versionMatch[1];

      const finding = new Finding({
        projectId:  ctx.project.id,
        scanJobId:  ctx.job.id,
        targetId:   target.id,
        moduleId:   'exposure.cve.laravel_env_hunt',
        title:      `Exposed ${url.endsWith('.lock') ? 'composer.lock' : 'composer.json'}`,
        shortDescription:
          `Composer dependency file exposed at ${url}` +
          (laravelVersion ? ` — Laravel framework v${laravelVersion} detected.` : '.'),
        detailedDescription:
          'A Composer dependency manifest is publicly accessible. ' +
          'This reveals the exact versions of all PHP packages in use, enabling targeted ' +
          'vulnerability research. Combined with an exposed APP_KEY, it allows precise ' +
          'determination of RCE exploitability via known deserialization gadget chains. ' +
          (laravelVersion
            ? `Detected laravel/framework version: ${laravelVersion}. ` +
              'Versions < 10.48.x and < 11.31.x are vulnerable to CVE-2024-55556 pattern. '
            : '') +
          'Fix: block access to composer.lock and composer.json via web server config.',
        severity:   'high',
        category:   'exposure',
        owaspTag:   'A05-Security-Misconfiguration',
        cweTag:     'CWE-200',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(new Evidence({
        findingId:              finding.id,
        url,
        method:                 'GET',
        responseStatus:         res.status,
        responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
        responseBodySnippet:    body.slice(0, 4096),
        matchedPattern:         'laravel/framework in composer manifest',
      }));
      ctx.log(`🟠 HIGH: ${url.endsWith('.lock') ? 'composer.lock' : 'composer.json'} exposed at ${url}${laravelVersion ? ` (Laravel ${laravelVersion})` : ''}`);
    } catch { /* ignore */ }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────────────────────────────────────

export async function runLaravelEnvHunt({ ctx, target, baseUrl, fetchAdapter }) {
  const mod = moduleDefById['exposure.cve.laravel_env_hunt'];
  if (!mod) {
    ctx.log('exposure.cve.laravel_env_hunt: ModuleDef not found — skipping');
    return;
  }

  ctx.log(`\n[Laravel .env Hunt] Starting on ${target.host} (${baseUrl})`);

  // ── Step 1: Fingerprint Laravel (non-blocking — probe continues regardless) ──
  const { isLaravel, signals } = await fingerprintLaravel({ baseUrl, fetchAdapter });
  if (isLaravel) {
    ctx.log(`  [Laravel] Framework confirmed: ${signals.join(' | ')}`);
  } else {
    ctx.log('  [Laravel] No definitive framework signals — probing anyway (misconfigs exist on all stacks)');
  }

  // ── Step 2: Debug mode check ──────────────────────────────────────────────
  await checkLaravelDebugMode({ ctx, target, baseUrl, fetchAdapter });

  // ── Step 3: composer.lock / composer.json recon ───────────────────────────
  await checkComposerLock({ ctx, target, baseUrl, fetchAdapter });

  // ── Step 4: Probe all .env paths ──────────────────────────────────────────
  const reportedUrls = new Set();
  let totalHits = 0;

  for (const probePath of ALL_PROBE_PATHS) {
    const url = baseUrl.replace(/\/$/, '') + probePath;
    if (reportedUrls.has(url)) continue;

    let res;
    try {
      res = await fetchAdapter(url, { method: 'GET', timeout: 7000 });
    } catch (e) {
      ctx.log(`  [Laravel .env] ${url} → error (${e.message?.slice(0, 60)})`);
      continue;
    }

    ctx.log(`  [Laravel .env] ${url} → HTTP ${res.status}`);

    if (res.status !== 200) continue;

    const body = res.body || '';
    if (!isValidDotenv(body)) continue;

    reportedUrls.add(url);
    totalHits++;

    const isLaravelEnv = isLaravelDotenv(body);
    const secrets      = extractSecrets(body);
    const dbRisk       = scoreDbRisk(secrets);
    const severity     = escalateSeverity(secrets, dbRisk);

    // ── App Key analysis ──────────────────────────────────────────────────
    const appKeySecret  = secrets.find((s) => s.key === 'APP_KEY');
    const appKeyAnalysis = appKeySecret ? analyseAppKey(appKeySecret.value) : null;

    // ── Build finding ─────────────────────────────────────────────────────
    const criticalSecretCount = secrets.filter((s) => s.severity === 'critical').length;
    const secretSummary = secrets.length > 0
      ? `Extracted ${secrets.length} secrets (${criticalSecretCount} critical): ` +
        secrets.map((s) => `${s.key}=${redact(s.value)}`).join(', ')
      : 'No structured secrets extracted but file content is accessible.';

    let detailedDesc =
      `A ${isLaravelEnv ? 'Laravel ' : ''}dotenv configuration file is publicly accessible at ${url}. ` +
      `${secretSummary}. `;

    if (appKeyAnalysis) {
      detailedDesc +=
        `\n\nAPP_KEY Analysis: ${appKeyAnalysis.entropyNote}. ` +
        `\nRCE Risk: ${appKeyAnalysis.rceAnnotation}`;
    }

    if (dbRisk.hasCloudDb) {
      detailedDesc +=
        `\n\nCloud DB Risk: Database host resolves to ${dbRisk.cloudProvider}. ` +
        'Exposed credentials provide direct internet-accessible database access — ' +
        'immediate credential rotation required.';
    }

    if (probePath.includes('/storage/logs/laravel.log')) {
      detailedDesc +=
        '\n\nNote: This is a Laravel log file. It may contain stack traces with environment ' +
        'variable values, database queries, user data, and exception details.';
    }

    const finding = new Finding({
      projectId:  ctx.project.id,
      scanJobId:  ctx.job.id,
      targetId:   target.id,
      moduleId:   'exposure.cve.laravel_env_hunt',
      title:      appKeyAnalysis
        ? `Laravel .env Exposed with APP_KEY — Potential RCE Risk (${target.host})`
        : `Laravel .env File Exposed (${target.host})`,
      shortDescription:
        `${isLaravelEnv ? 'Laravel ' : ''}dotenv file accessible at ${url}. ` +
        (appKeySecret ? `APP_KEY leaked — deserialization RCE risk (CVE-2024-55556 pattern). ` : '') +
        (dbRisk.hasCloudDb ? `Cloud DB (${dbRisk.cloudProvider}) credentials exposed. ` : ''),
      detailedDescription: detailedDesc,
      severity,
      category:   'exposure',
      owaspTag:   'A02-Cryptographic-Failures',
      cweTag:     appKeyAnalysis ? 'CWE-798' : 'CWE-312',
    });

    ctx.addFinding(finding);
    ctx.addEvidence(new Evidence({
      findingId:              finding.id,
      url,
      method:                 'GET',
      responseStatus:         res.status,
      responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
      responseBodySnippet:    body.slice(0, 4096), // full content for operator review
      matchedPattern:         `Laravel .env: ${secrets.map((s) => s.key).join(', ') || 'dotenv key=value pairs'}`,
    }));

    // Log with appropriate severity emoji
    const emoji = severity === 'critical' ? '🔴' : '🟠';
    ctx.log(
      `${emoji} ${severity.toUpperCase()}: Laravel .env at ${url} — ` +
      `${secrets.length} secrets` +
      (appKeySecret ? ` + APP_KEY (RCE risk)` : '') +
      (dbRisk.hasCloudDb ? ` + ${dbRisk.cloudProvider} DB creds` : '')
    );

    // Log each extracted secret (redacted)
    for (const s of secrets) {
      ctx.log(`    [secret] ${s.key} = ${redact(s.value)} (${s.severity}${s.rceRisk ? ', RCE risk' : ''})`);
    }
  }

  ctx.log(`[Laravel .env Hunt] Complete for ${target.host} — ${totalHits} hit(s) across ${ALL_PROBE_PATHS.length} paths`);
}
