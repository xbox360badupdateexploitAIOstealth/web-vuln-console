// src/core/moduleRegistry.js
import { ModuleDef } from './models.js';

export const moduleDefs = [
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
        maxBytes: { type: 'number', default: 65536 },
        sampleOnly: { type: 'boolean', default: true },
      },
    },
  }),
  new ModuleDef({
    id: 'exposure.env.variants',
    name: '.env Variant Exposure',
    description: 'Checks for common .env variants and backup files (.env.local, .env.backup, .env.bak, .env.old, /script/.env).',
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
            '/.env.local',
            '/.env.backup',
            '/.env.bak',
            '/.env.old',
            '/script/.env',
          ],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'exposure.backup.db_dumps',
    name: 'Database Backup Files',
    description: 'Searches for exposed SQL dump files (backup.sql, db.sql, dump.sql, *.sql.gz).',
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
            '/backup.sql',
            '/db.sql',
            '/dump.sql',
            '/database.sql',
            '/db_backup.sql',
            '/backup.sql.gz',
            '/database.sql.gz',
          ],
        },
        maxBytes: { type: 'number', default: 32768 },
      },
    },
  }),
  new ModuleDef({
    id: 'exposure.backup.archives',
    name: 'Archive Backup Files',
    description: 'Detects archives like backup.zip, site-backup.tar.gz, db-backup.zip in web-accessible paths.',
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
            '/backup.zip',
            '/backup.tar.gz',
            '/site.zip',
            '/site-backup.zip',
            '/site-backup.tar.gz',
            '/www-backup.zip',
          ],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'misconfig.dirlisting.generic',
    name: 'Directory Listing Detection',
    description: 'Detects HTTP responses that expose directory listings for common paths.',
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
    description: 'Detects stack traces, framework error pages, and overly detailed error messages.',
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
  new ModuleDef({
    id: 'injection.sqli.basic',
    name: 'Basic SQL Injection Probes',
    description: 'Sends simple SQLi payloads to parameters and looks for database error signatures.',
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
            'SQL syntax',
            'mysql_fetch',
            'mysqli',
            'psql:',
            'ORA-',
            'ODBC',
          ],
        },
        payloads: {
          type: 'array',
          default: [`'`, '"', `' OR '1'='1`, '") OR 1=1--'],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'injection.xss.reflected_basic',
    name: 'Reflected XSS Probes',
    description: 'Injects harmless reflective XSS test strings into parameters and checks for reflection.',
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
            '<script>alert(123)</script>',
          ],
        },
      },
    },
  }),
  new ModuleDef({
    id: 'tls.headers.basic',
    name: 'TLS & Security Header Check',
    description: 'Analyzes responses for security headers and TLS usage.',
    category: 'tls',
    clazz: 'passive',
    severityDefault: 'info',
    stackFilters: ['any'],
    owaspTags: ['A02-Cryptographic-Failures'],
    cweTags: ['CWE-319'],
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
