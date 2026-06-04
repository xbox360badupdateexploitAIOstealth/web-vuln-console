// src/core/moduleRegistry.js
import { ModuleDef } from './models.js';

export const moduleDefs = [
  // ── Passive: Exposure ──────────────────────────────────────────────────────
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
  // ── Active: Injection ──────────────────────────────────────────────────────
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
  // ── Passive: TLS & Headers ─────────────────────────────────────────────────
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
