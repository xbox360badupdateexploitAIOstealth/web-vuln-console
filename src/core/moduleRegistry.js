// src/core/moduleRegistry.js
import { ModuleDef } from './models.js';

export const moduleDefs = [
  // ── Passive: Exposure ──────────────────────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'exposure.env.direct',
    name: 'Direct .env Exposure',
    description: 'Checks for accessible /.env at web root and tests content for dotenv-style secrets.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A02-Cryptographic-Failures'],
    cweTags: ['CWE-359'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        maxBytes:   { type: 'number',  default: 65536 },
        sampleOnly: { type: 'boolean', default: true  },
      },
    },
  }),
  new ModuleDef({
    id: 'exposure.env.variants',
    name: '.env Variant Exposure',
    description: 'Checks for common .env variants (.env.local, .env.backup, .env.bak, .env.old, /script/.env).',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A02-Cryptographic-Failures'],
    cweTags: ['CWE-359'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        paths: {
          type: 'array',
          default: [
            '/.env.local', '/.env.backup', '/.env.bak',
            '/.env.old',   '/script/.env', '/.env.prod',
            '/.env.staging', '/.env.development',
          ],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'exposure.backup.db_dumps',
    name: 'Database Backup Files',
    description: 'Searches for exposed SQL dump files (backup.sql, db.sql, dump.sql, etc.).',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A01-Broken-Access-Control'],
    cweTags: ['CWE-200'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        candidateNames: {
          type: 'array',
          default: [
            '/backup.sql', '/db.sql', '/dump.sql',
            '/database.sql', '/db_backup.sql',
            '/backup.sql.gz', '/database.sql.gz',
          ],
        },
        maxBytes: { type: 'number', default: 32768 },
      },
    },
  }),
  new ModuleDef({
    id: 'exposure.backup.archives',
    name: 'Archive Backup Files',
    description: 'Detects zip/tar archives in web-accessible paths.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'high',
    stackFilters: ['any'],
    owaspTags: ['A01-Broken-Access-Control'],
    cweTags: ['CWE-530'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        candidateNames: {
          type: 'array',
          default: [
            '/backup.zip', '/backup.tar.gz', '/site.zip',
            '/site-backup.zip', '/site-backup.tar.gz', '/www-backup.zip',
          ],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'misconfig.dirlisting.generic',
    name: 'Directory Listing Detection',
    description: 'Detects HTTP responses that expose directory listings.',
    category: 'misconfig',
    clazz: 'passive',
    severityDefault: 'medium',
    stackFilters: ['any'],
    owaspTags: ['A05-Security-Misconfiguration'],
    cweTags: ['CWE-548'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        paths: {
          type: 'array',
          default: ['/', '/backup/', '/logs/', '/old/', '/test/', '/private/'],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'vcs.git.exposed',
    name: 'Exposed .git Repository',
    description: 'Checks for accessible /.git/HEAD and /.git/config.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'high',
    stackFilters: ['any'],
    owaspTags: ['A05-Security-Misconfiguration'],
    cweTags: ['CWE-200'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        checkPaths: {
          type: 'array',
          default: ['/.git/HEAD', '/.git/config'],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'debug.stacktraces',
    name: 'Verbose Error & Stack Trace Detection',
    description: 'Detects stack traces, framework error pages, and detailed error messages.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'medium',
    stackFilters: ['any'],
    owaspTags: ['A05-Security-Misconfiguration'],
    cweTags: ['CWE-209'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        maxBytes: { type: 'number', default: 8192 },
      },
    },
  }),
  // ── Passive: JS Secret Scan ──────────────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'exposure.js.secrets',
    name: 'JavaScript Asset Secret Scanner',
    description:
      'Fetches all .js assets discovered by the crawler and scans them for hardcoded secrets: ' +
      'AWS keys, Stripe live keys, Google API keys, Firebase config, GitHub PATs, Slack tokens, ' +
      'OpenAI/HuggingFace/Replicate API keys, Bearer tokens, PEM private keys, and secret variable assignments.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A02-Cryptographic-Failures'],
    cweTags: ['CWE-312', 'CWE-798'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        maxJsFiles: { type: 'number',  default: 30     },
        maxBytes:   { type: 'number',  default: 524288 },
      },
    },
  }),
  // ── Passive: Source Map Detection ──────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'exposure.sourcemap',
    name: 'JavaScript Source Map Exposure',
    description:
      'Detects publicly accessible JavaScript source map (.map) files. ' +
      'Checks three vectors per JS asset: (A) direct .map probe, ' +
      '(B) X-SourceMap / SourceMap HTTP response headers, ' +
      '(C) //# sourceMappingURL= comments in the JS body. ' +
      'Validates response is real source map JSON (version:3, sources[] non-empty). ' +
      'Also flags internal server path leakage in sources[] entries.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A05-Security-Misconfiguration'],
    cweTags: ['CWE-540'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        maxJsFiles:  { type: 'number', default: 30      },
        maxMapBytes: { type: 'number', default: 262144  },
      },
    },
  }),
  // ── Passive: Cookie & Session ─────────────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'cookie.session.flags',
    name: 'Cookie & Session Security Checks',
    description:
      'Deep cookie and session security analysis. Covers: SameSite=None without Secure, ' +
      'session ID entropy (short/numeric/predictable tokens), overly long Max-Age on session cookies, ' +
      '__Secure- and __Host- prefix requirement violations, broad Domain= scope leaking tokens ' +
      'to subdomains, and session tokens exposed in URL query parameters.',
    category: 'misconfig',
    clazz: 'passive',
    severityDefault: 'high',
    stackFilters: ['any'],
    owaspTags: ['A07-Identification-and-Authentication-Failures'],
    cweTags: ['CWE-539', 'CWE-331', 'CWE-613', 'CWE-598'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        probePaths: {
          type: 'array',
          default: ['/', '/login', '/signin', '/account', '/dashboard', '/admin'],
        },
      },
    },
  }),
  // ── CVE: cPanel/WHM Exposure ──────────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'exposure.cve.cpanel_whm',
    name: 'cPanel & WHM Panel Exposure (CVE-2026-41940)',
    description:
      'Probes IP addresses and hostnames for exposed cPanel & WHM admin panels on ports 2082, 2083, 2086, 2087, 8080, 8443. ' +
      'Fingerprints via X-cPanel-Version header, X-Powered-By: cpsrvd, Server: cpsrvd, and login page body signatures. ' +
      'Attempts unauthenticated metadata enumeration via /json-api/version and /xml-api/version (CVE-2026-41940 vectors). ' +
      'Flags installations running cPanel & WHM < 120.0.6 as potentially vulnerable to CVE-2026-41940 ' +
      '(unauthenticated info disclosure / session token enumeration, CVSS 9.1 Critical). ' +
      'Ideal for IP range sweeps of datacenter hosting environments.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A05-Security-Misconfiguration'],
    cweTags: ['CWE-200'],
    cveExamples: ['CVE-2026-41940'],
    configSchema: {
      type: 'object',
      properties: {
        ports: {
          type: 'array',
          default: [2083, 2087, 2082, 2086, 8443, 8080],
        },
        connectionTimeoutMs: { type: 'number', default: 6000 },
      },
    },
  }),
  // ── CVE: Laravel .env Hunt ────────────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'exposure.cve.laravel_env_hunt',
    name: 'Laravel .env Exposure & Secret Extraction (CVE-2024-55556 / CVE-2025-70841)',
    description:
      'Advanced Laravel dotenv hunter. Probes 56 paths across 7 categories: standard .env variants, ' +
      'docroot-mismatch paths (public/, laravel/, backend/, api/), storage/bootstrap internals including laravel.log, ' +
      'Dokan multi-vendor marketplace paths (CVE-2025-70841: /script/.env), ' +
      'Laravel Forge/Envoyer/Ploi deployment paths (/../.env, /releases/current/.env), ' +
      'Octane/Docker container paths (.env.docker, .docker/.env), ' +
      'and CI/CD artifact paths (.env.ci, .env.github, .env.gitlab). ' +
      'On any hit: extracts 50+ secret patterns (APP_KEY, DB_PASSWORD, DATABASE_URL, REDIS_PASSWORD, ' +
      'MAIL_PASSWORD, AWS_SECRET_ACCESS_KEY, STRIPE_SECRET, STRIPE_WEBHOOK_SECRET, JWT_SECRET, ' +
      'PASSPORT_CLIENT_SECRET, OAUTH_CLIENT_SECRET, OPENAI_API_KEY, ANTHROPIC_API_KEY, ' +
      'PAYPAL_SECRET, BRAINTREE_PRIVATE_KEY, SENTRY_DSN, ENCRYPTION_KEY, and more). ' +
      'APP_KEY analysis: validates base64: prefix, checks 32-byte AES-256 key length, ' +
      'annotates deserialization RCE risk (CVE-2024-55556 Crater Invoice / Laravel gadget chain pattern). ' +
      'Cloud DB risk scoring: flags DB_HOST matching 14 cloud providers (RDS, PlanetScale, Supabase, ' +
      'Neon, Railway, CockroachDB, Turso, Azure MySQL/Postgres, GCP CloudSQL, DigitalOcean, etc.). ' +
      'Supplementary checks: Laravel Ignition debug mode probe, composer.lock/composer.json exposure ' +
      '(extracts laravel/framework version to confirm CVE-2024-55556 RCE exploitability). ' +
      'Laravel fingerprinting via XSRF-TOKEN cookie, X-Laravel-Version header, robots.txt Telescope/Horizon paths. ' +
      'Severity escalation: critical on APP_KEY, AWS keys, Stripe secret, DB_PASSWORD + cloud host, JWT_SECRET; ' +
      'minimum high for any .env hit. Secrets redacted in logs (first6***), full value in Evidence for operator.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A02-Cryptographic-Failures', 'A05-Security-Misconfiguration'],
    cweTags: ['CWE-312', 'CWE-798', 'CWE-359', 'CWE-209'],
    cveExamples: ['CVE-2024-55556', 'CVE-2025-70841'],
    configSchema: {
      type: 'object',
      properties: {
        skipFingerprintGate: {
          type: 'boolean',
          default: false,
          description: 'If true, probe all paths even when no Laravel signals are detected (default: probe anyway).',
        },
        maxBodyBytes: {
          type: 'number',
          default: 131072,
          description: 'Max bytes to read from each .env response.',
        },
        connectionTimeoutMs: {
          type: 'number',
          default: 7000,
        },
      },
    },
  }),
  // ── CVE: Framework & Product Fingerprints (Phase 1e) ─────────────────────────────────────
  new ModuleDef({
    id: 'cve.fingerprints',
    name: 'CVE Fingerprint Checks (2025–2026)',
    description:
      'Passive HTTP fingerprint checks for 15 high-impact 2025–2026 CVEs. ' +
      'Detects: Nginx UI unauth API (CVE-2026-27944/33032), Craft CMS RCE (CVE-2025-32432), ' +
      'Laravel Livewire SSTI (CVE-2025-54068), Next.js RSC (CVE-2025-55182), ' +
      'n8n unauth settings (CVE-2026-25049), Langflow RCE API (CVE-2026-33017), ' +
      'FortiGate auth bypass (CVE-2026-24858), Ivanti path traversal (CVE-2026-1603), ' +
      'HPE Aruba unauth REST (CVE-2026-23813), Vite dev server LFI (CVE-2025-30208/CVE-2026-46565), ' +
      'MindsDB path traversal (CVE-2026-27483), SharePoint deserialization (CVE-2026-20963), ' +
      'Oracle WebLogic RCE (CVE-2026-21962), Cisco FMC RCE (CVE-2026-20131), ' +
      'Modular DS WordPress auth bypass (CVE-2026-23550). ' +
      'All probes are GET-only, no payloads, no state modification.',
    category: 'cve',
    clazz: 'passive',
    severityDefault: 'high',
    stackFilters: ['any'],
    owaspTags: [
      'A01-Broken-Access-Control',
      'A05-Security-Misconfiguration',
      'A07-Identification-and-Authentication-Failures',
      'A08-Software-and-Data-Integrity-Failures',
    ],
    cweTags: ['CWE-306', 'CWE-287', 'CWE-502', 'CWE-22', 'CWE-94'],
    cveExamples: [
      'CVE-2026-27944', 'CVE-2026-33032', 'CVE-2025-32432', 'CVE-2025-54068',
      'CVE-2025-55182', 'CVE-2026-25049', 'CVE-2026-33017', 'CVE-2026-24858',
      'CVE-2026-1603',  'CVE-2026-23813', 'CVE-2025-30208', 'CVE-2026-46565',
      'CVE-2026-27483', 'CVE-2026-20963', 'CVE-2026-21962', 'CVE-2026-20131',
      'CVE-2026-23550',
    ],
    configSchema: {
      type: 'object',
      properties: {},
    },
  }),
  // ── CVE Passive: TODO-06 (Phase 1g) ───────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'misconfig.phpinfo.exposed',
    name: 'PHP Info / Debug Page Exposed',
    description:
      'Probes 10 paths for exposed phpinfo() pages, Symfony web profiler, and Apache server-info/status pages. ' +
      'Paths: /phpinfo.php, /info.php, /php_info.php, /phpinfo, /debug, /debug.php, ' +
      '/_profiler, /_profiler/phpinfo, /server-info, /server-status. ' +
      'Detection: body signature matching (phpinfo(), PHP Version, php.ini, Symfony Profiler, ' +
      'Apache Server Information, Server Status). ' +
      'All three variants produce distinct finding titles for accurate reporting.',
    category: 'misconfig',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A05-Security-Misconfiguration'],
    cweTags: ['CWE-200'],
    cveExamples: [],
    configSchema: { type: 'object', properties: {} },
  }),
  new ModuleDef({
    id: 'vcs.svn_hg.exposed',
    name: 'SVN / Mercurial Repository Exposure',
    description:
      'Checks for exposed Subversion and Mercurial repository metadata files. ' +
      'Probes: /.svn/entries (dir signature), /.svn/wc.db (SQLite signature), /.svn/format (status-only), ' +
      '/.hg/manifest, /.hg/store/data, /.hg/requires (revlogv1 signature). ' +
      'A hit allows full source code reconstruction using svn-extractor or hg-dumper.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A05-Security-Misconfiguration'],
    cweTags: ['CWE-200'],
    cveExamples: [],
    configSchema: { type: 'object', properties: {} },
  }),
  new ModuleDef({
    id: 'exposure.cve.vite_bypass',
    name: 'Vite Dev Server Exposed / @fs LFI Bypass (CVE-2025-30208 / CVE-2025-46565)',
    description:
      'Fingerprints Vite dev servers via @vite/client, vite/dist/client, __vite_plugin, ' +
      'type="module" script tags, and HMR WebSocket patterns. ' +
      'On fingerprint confirmation: probes 6 @fs bypass and ?import&raw= LFI vectors ' +
      'to confirm unauthenticated arbitrary file read (CVE-2025-30208 / CVE-2025-46565 / CVE-2026-46565). ' +
      'Confirms hit if /etc/passwd (root:) or /proc/self/environ (PATH=) content is returned. ' +
      'Emits critical on confirmed LFI, high on exposed-but-unconfirmed dev server. ' +
      'Fix: never expose Vite dev server publicly; upgrade to Vite >= 6.2.4.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A01-Broken-Access-Control'],
    cweTags: ['CWE-22', 'CWE-200'],
    cveExamples: ['CVE-2025-30208', 'CVE-2025-46565', 'CVE-2026-46565'],
    configSchema: { type: 'object', properties: {} },
  }),
  new ModuleDef({
    id: 'exposure.cve.mautic_env',
    name: 'Mautic .env Disclosure (CVE-2024-47056)',
    description:
      'Fingerprints Mautic marketing automation via /s/login login page. ' +
      'On confirmation: probes /.env, /app/.env, /mautic/.env, /.env.local for ' +
      'accessible dotenv files containing MAUTIC_SECRET_KEY, DB_PASSWORD, DATABASE_URL, ' +
      'and mailer/integration credentials. ' +
      'CVE-2024-47056: Mautic .env exposed when webroot not isolated from application root. ' +
      'Key names logged only — values stored in Evidence for operator.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A02-Cryptographic-Failures'],
    cweTags: ['CWE-312', 'CWE-359'],
    cveExamples: ['CVE-2024-47056'],
    configSchema: { type: 'object', properties: {} },
  }),
  new ModuleDef({
    id: 'exposure.cve.moodle_listing',
    name: 'Moodle Data Directory / r.php Exposure (CVE-2025-62396)',
    description:
      'Fingerprints Moodle LMS via /login/index.php (sesskey, moodledata body signatures). ' +
      'On confirmation: probes /r.php, /lib/, /dataroot/, /moodledata/, /filedir/ ' +
      'for directory listings (Index of /, Parent Directory) and r.php router exposure. ' +
      'CVE-2025-62396: unauthenticated path disclosure via Moodle r.php router. ' +
      'Directory listing on moodledata exposes student submissions and course content.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'high',
    stackFilters: ['any'],
    owaspTags: ['A05-Security-Misconfiguration'],
    cweTags: ['CWE-548', 'CWE-200'],
    cveExamples: ['CVE-2025-62396'],
    configSchema: { type: 'object', properties: {} },
  }),
  new ModuleDef({
    id: 'exposure.cloud.open_bucket',
    name: 'Open Cloud Storage Bucket (S3 / Azure / GCS)',
    description:
      'Derives candidate bucket names from the target hostname (strips www/api/cdn/TLD, ' +
      'generates -assets/-media/-static/-uploads/-backup/-data/-files/-images/-prod/-dev variants). ' +
      'Probes up to 10 candidate names × 4 cloud providers: ' +
      'AWS S3 (virtual-hosted + path-style), Azure Blob Storage (container list), GCP GCS. ' +
      'Validates responses via XML signature: ListBucketResult, <Contents>, EnumerationResults, <Blobs>. ' +
      'A confirmed hit means full unauthenticated object enumeration and download.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A01-Broken-Access-Control'],
    cweTags: ['CWE-284', 'CWE-200'],
    cveExamples: [],
    configSchema: { type: 'object', properties: {} },
  }),
  new ModuleDef({
    id: 'exposure.cms.wp_debug',
    name: 'WordPress Debug Artifacts Exposed',
    description:
      'Fingerprints WordPress via /wp-login.php, /wp-admin/, /wp-includes/js/jquery/jquery.min.js. ' +
      'On confirmation: probes 6 debug artifact paths: ' +
      '/wp-content/debug.log (PHP errors + stack traces), ' +
      '/wp-config.php.bak (DB creds + secret keys — critical), ' +
      '/wp-config.php~ (vim tilde backup — critical), ' +
      '/wp-config.bak (critical), ' +
      '/.wp-config.php.swp (vim swap file — critical), ' +
      '/wp-content/uploads/.htaccess (PHP execution guard check — medium). ' +
      'Each artifact produces an individual finding with appropriate severity.',
    category: 'exposure',
    clazz: 'passive',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A02-Cryptographic-Failures', 'A05-Security-Misconfiguration'],
    cweTags: ['CWE-312', 'CWE-200'],
    cveExamples: [],
    configSchema: { type: 'object', properties: {} },
  }),
  // ── Active: Injection ──────────────────────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'injection.sqli.basic',
    name: 'Basic SQL Injection Probes',
    description: 'Sends simple SQLi payloads to parameterized endpoints and looks for database error signatures.',
    category: 'injection',
    clazz: 'active',
    severityDefault: 'high',
    stackFilters: ['any'],
    owaspTags: ['A03-Injection'],
    cweTags: ['CWE-89'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        errorPatterns: {
          type: 'array',
          default: [
            'SQL syntax', 'mysql_fetch', 'mysqli', 'psql:', 'ORA-',
            'ODBC', 'sqlite', 'syntax error', 'pg_query', 'SQLSTATE',
            'DB2 SQL error', 'Microsoft OLE DB', 'Unclosed quotation',
          ],
        },
        payloads: {
          type: 'array',
          default: [`'`, '"', `' OR '1'='1`, '") OR 1=1--', `' AND 1=1--`, `'; DROP TABLE--`],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'injection.xss.reflected_basic',
    name: 'Reflected XSS Probes',
    description: 'Injects XSS test strings into parameters and checks for unencoded reflection.',
    category: 'injection',
    clazz: 'active',
    severityDefault: 'medium',
    stackFilters: ['any'],
    owaspTags: ['A03-Injection'],
    cweTags: ['CWE-79'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        payloads: {
          type: 'array',
          default: [
            '<xss-test-123>',
            '"onmouseover="xss123()',
            "<img src=x onerror=alert(1)>",
            '<script>alert(123)</script>',
          ],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'injection.path_traversal.basic',
    name: 'Path Traversal / Local File Read',
    description: 'Tests for directory traversal vulnerabilities by probing common OS file paths.',
    category: 'injection',
    clazz: 'active',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A01-Broken-Access-Control'],
    cweTags: ['CWE-22'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        payloads: {
          type: 'array',
          default: [
            '/../../etc/passwd',
            '/../../../etc/passwd',
            '/../../../../etc/passwd',
            '/%2e%2e/%2e%2e/etc/passwd',
            '/..%2F..%2Fetc%2Fpasswd',
            '/....//....//etc/passwd',
          ],
        },
        windowsPayloads: {
          type: 'array',
          default: [
            '/../../windows/win.ini',
            '/../../../windows/win.ini',
            '/%2e%2e/%2e%2e/windows/win.ini',
          ],
        },
        signatures: {
          type: 'array',
          default: [
            'root:x:',
            'root:0:0',
            '/bin/bash',
            '/bin/sh',
            '[fonts]',
            'for 16-bit app support',
          ],
        },
      },
    },
  }),
  // ── Active: Injection (TODO-07) ────────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'injection.cmdi.basic',
    name: 'OS Command Injection Probes',
    description:
      'Injects OS command separator payloads into query parameters and checks for system-level output. ' +
      'Payloads: ; id, & whoami, | id, `id`, $(id), ; id #, | whoami #, & id &. ' +
      'Detection signatures: uid=, gid=, root:, /bin/, /usr/, /home/, ' +
      'Administrator, WINDOWS, Volume Serial output patterns. ' +
      'A confirmed hit indicates Remote Code Execution via command injection (CVSS 9.8+). ' +
      'Only runs on parameterized endpoints discovered by the crawler.',
    category: 'injection',
    clazz: 'active',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A03-Injection'],
    cweTags: ['CWE-78'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        payloads: {
          type: 'array',
          default: [
            '; id',
            '& whoami',
            '| id',
            '`id`',
            '$(id)',
            '; id #',
            '| whoami #',
            '& id &',
          ],
        },
        signatures: {
          type: 'array',
          default: [
            'uid=',
            'gid=',
            'root:',
            '/bin/',
            '/usr/',
            '/home/',
            'Administrator',
            'WINDOWS',
            'Volume Serial',
          ],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'injection.ssti.basic',
    name: 'Server-Side Template Injection (SSTI) Probes',
    description:
      'Injects template expression payloads into query parameters and checks for math evaluation or engine errors. ' +
      'Payload pairs (input → expected): {{7*7}} → 49, ${7*7} → 49, #{7*7} → 49, ' +
      '<%= 7*7 %> → 49, ${{7*7}} → 49, {{7*"7"}} → 7777777 (Jinja2 string mul). ' +
      'Error patterns: TemplateSyntaxError, Twig_Error, RenderError, JinjaUndefined, ' +
      'freemarker.template, velocity, Smarty parse error, template rendering. ' +
      'A math-result hit strongly indicates SSTI — potential RCE via template sandbox escape. ' +
      'Only runs on parameterized endpoints discovered by the crawler.',
    category: 'injection',
    clazz: 'active',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A03-Injection'],
    cweTags: ['CWE-94'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        payloads: {
          type: 'array',
          default: [
            { payload: '{{7*7}}',      expected: '49'      },
            { payload: '${7*7}',       expected: '49'      },
            { payload: '#{7*7}',       expected: '49'      },
            { payload: '<%= 7*7 %>',   expected: '49'      },
            { payload: '${{7*7}}',     expected: '49'      },
            { payload: '{{7*"7"}}',    expected: '7777777' },
          ],
        },
        errorPatterns: {
          type: 'array',
          default: [
            'TemplateSyntaxError',
            'Twig_Error',
            'RenderError',
            'JinjaUndefined',
            'freemarker.template',
            'org.apache.velocity',
            'Smarty parse error',
            'template rendering',
            'TemplateException',
          ],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'injection.fileupload.detect',
    name: 'Dangerous File Upload Detection',
    description:
      'Detects file upload endpoints and tests whether dangerous file extensions are accepted. ' +
      'Step 1: Probe reachability of upload endpoints (from SiteModel or common fallback paths). ' +
      'Step 2: POST a benign .txt file via multipart/form-data to confirm uploads are accepted. ' +
      'Step 3: POST files with dangerous extensions (.php, .php5, .phtml, .jsp, .aspx, .shtml, .phar) — ' +
      'if accepted without rejection, flag as critical (potential web shell upload / RCE). ' +
      'Rejection detection: checks response body for "not allowed", "invalid type", ' +
      '"file type", "extension", "only", "blocked". ' +
      'Common fallback upload paths: /upload, /uploads, /file-upload, /api/upload, /media/upload, ' +
      '/assets/upload, /image-upload, /avatar, /profile/avatar, /document-upload.',
    category: 'injection',
    clazz: 'active',
    severityDefault: 'critical',
    stackFilters: ['any'],
    owaspTags: ['A03-Injection'],
    cweTags: ['CWE-434'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        commonUploadPaths: {
          type: 'array',
          default: [
            '/upload', '/uploads', '/file-upload', '/api/upload',
            '/media/upload', '/assets/upload', '/image-upload',
            '/avatar', '/profile/avatar', '/document-upload',
          ],
        },
        testExtensions: {
          type: 'array',
          default: ['.php', '.php5', '.phtml', '.jsp', '.aspx', '.shtml', '.phar'],
        },
        dangerSignatures: {
          type: 'array',
          default: [
            'not allowed', 'invalid type', 'file type',
            'extension', 'only', 'blocked',
          ],
        },
      },
    },
  }),
  // ── Passive: TLS & Headers ──────────────────────────────────────────────────────────────────
  new ModuleDef({
    id: 'tls.headers.basic',
    name: 'TLS & Security Header Check',
    description: 'Analyzes responses for missing security headers and plain HTTP usage.',
    category: 'tls',
    clazz: 'passive',
    severityDefault: 'info',
    stackFilters: ['any'],
    owaspTags: ['A02-Cryptographic-Failures', 'A05-Security-Misconfiguration'],
    cweTags: ['CWE-319', 'CWE-693'],
    cveExamples: [],
    configSchema: {
      type: 'object',
      properties: {
        requiredHeaders: {
          type: 'array',
          default: [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Permissions-Policy',
            'Referrer-Policy',
          ],
        },
      },
    },
  }),
];

export const moduleDefById = moduleDefs.reduce((acc, m) => {
  acc[m.id] = m;
  return acc;
}, {});
