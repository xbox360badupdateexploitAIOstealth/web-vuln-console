// src/core/checks/adminPanelDetect.js
// Passive check: detect exposed admin panels, management UIs, and login pages.
//
// Two-tier approach:
//   Tier 1 — CRITICAL: unauthenticated panel (no login prompt, direct access)
//   Tier 2 — MEDIUM:   login page present (access controlled, but location known)
//
// Each path entry has:
//   - path: URL to probe
//   - fingerprints: strings that confirm the page is actually the expected panel
//   - name: human-readable panel name for the finding title
//
// Uses siteModel.techStack.cms (set by techFingerprint) to skip probing
// CMS-specific paths if that CMS is NOT detected — reduces noise significantly.
//
// Wire-up (engine.js Phase 1c — after phpInfoExposure, before crawler):
//   import { runAdminPanelDetect } from './checks/adminPanelDetect.js';
//   if (moduleEnabled(enabledModules, 'exposure.admin_panels')) {
//     await runAdminPanelDetect({ ctx, target, baseUrl, siteModel, fetchAdapter });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// ── Panel definitions ────────────────────────────────────────────────────────────
// cmsHint: if set, only probe when siteModel.techStack.cms matches this string
// loginFingerprints: body strings that indicate a login wall is present
// openFingerprints:  body strings that indicate direct unauthenticated access

const PANEL_DEFS = [
  // ── WordPress
  {
    name:     'WordPress Admin',
    path:     '/wp-admin/',
    cmsHint:  'WordPress',
    loginFingerprints: ['wp-login', 'user_login', 'Log In', 'WordPress'],
    openFingerprints:  ['Dashboard', 'wp-admin-bar', 'Howdy,'],
  },
  {
    name:     'WordPress Login',
    path:     '/wp-login.php',
    cmsHint:  'WordPress',
    loginFingerprints: ['user_login', 'Log In', 'WordPress'],
    openFingerprints:  [],
  },

  // ── Joomla
  {
    name:     'Joomla Administrator',
    path:     '/administrator/',
    cmsHint:  'Joomla',
    loginFingerprints: ['Joomla', 'mod-login', 'Administrator'],
    openFingerprints:  ['Control Panel', 'com_cpanel'],
  },

  // ── Drupal
  {
    name:     'Drupal Admin',
    path:     '/admin/',
    cmsHint:  'Drupal',
    loginFingerprints: ['Drupal', 'user-login-form'],
    openFingerprints:  ['toolbar-administration', 'admin-menu'],
  },

  // ── Generic admin paths (no CMS hint — always probed)
  {
    name:    'Generic Admin Panel',
    path:    '/admin',
    loginFingerprints: ['login', 'password', 'username', 'sign in', 'admin'],
    openFingerprints:  ['dashboard', 'control panel', 'logout', 'administrator'],
  },
  {
    name:    'Generic Admin Panel',
    path:    '/admin/login',
    loginFingerprints: ['login', 'password', 'username'],
    openFingerprints:  ['dashboard', 'logout'],
  },
  {
    name:    'Management Panel',
    path:    '/manage',
    loginFingerprints: ['login', 'password', 'sign in'],
    openFingerprints:  ['dashboard', 'logout', 'management'],
  },
  {
    name:    'Control Panel',
    path:    '/panel',
    loginFingerprints: ['login', 'password'],
    openFingerprints:  ['dashboard', 'logout'],
  },
  {
    name:    'Dashboard',
    path:    '/dashboard',
    loginFingerprints: ['login', 'password', 'sign in'],
    openFingerprints:  ['logout', 'settings', 'overview'],
  },

  // ── phpMyAdmin
  {
    name:    'phpMyAdmin',
    path:    '/phpmyadmin/',
    loginFingerprints: ['phpMyAdmin', 'pma_', 'phpmyadmin'],
    openFingerprints:  ['pma_navigation', 'db_structure', 'Server choice'],
  },
  {
    name:    'phpMyAdmin',
    path:    '/pma/',
    loginFingerprints: ['phpMyAdmin', 'pma_'],
    openFingerprints:  ['pma_navigation', 'Server choice'],
  },
  {
    name:    'phpMyAdmin',
    path:    '/mysql/',
    loginFingerprints: ['phpMyAdmin', 'pma_'],
    openFingerprints:  ['pma_navigation'],
  },

  // ── Adminer
  {
    name:    'Adminer DB Manager',
    path:    '/adminer.php',
    loginFingerprints: ['Adminer', 'adminer'],
    openFingerprints:  ['logout', 'Create table', 'SQL command'],
  },
  {
    name:    'Adminer DB Manager',
    path:    '/adminer/',
    loginFingerprints: ['Adminer'],
    openFingerprints:  ['Create table', 'SQL command'],
  },

  // ── Monitoring / DevOps
  {
    name:    'Grafana',
    path:    '/grafana/',
    loginFingerprints: ['Grafana', 'grafana'],
    openFingerprints:  ['dashboards', 'datasource', 'Explore'],
  },
  {
    name:    'Grafana',
    path:    '/grafana/login',
    loginFingerprints: ['Grafana'],
    openFingerprints:  [],
  },
  {
    name:    'Kibana',
    path:    '/kibana/',
    loginFingerprints: ['Kibana', 'elastic'],
    openFingerprints:  ['Discover', 'Dashboard', 'Management'],
  },
  {
    name:    'Jenkins CI',
    path:    '/jenkins/',
    loginFingerprints: ['Jenkins', 'hudson'],
    openFingerprints:  ['Build History', 'Manage Jenkins', 'New Item'],
  },
  {
    name:    'Jenkins CI',
    path:    '/',
    loginFingerprints: [],
    openFingerprints:  ['Build History', 'Manage Jenkins', 'New Item', 'hudson'],
  },
  {
    name:    'SonarQube',
    path:    '/sonarqube/',
    loginFingerprints: ['SonarQube'],
    openFingerprints:  ['Projects', 'Issues', 'SonarQube'],
  },
  {
    name:    'Portainer',
    path:    '/portainer/',
    loginFingerprints: ['Portainer'],
    openFingerprints:  ['Containers', 'Images', 'Portainer'],
  },
  {
    name:    'Traefik Dashboard',
    path:    '/dashboard/',
    loginFingerprints: [],
    openFingerprints:  ['Traefik', 'routers', 'middlewares', 'services'],
  },
  {
    name:    'HashiCorp Vault',
    path:    '/ui/',
    loginFingerprints: ['Vault', 'hashicorp'],
    openFingerprints:  ['Secrets Engines', 'Auth Methods'],
  },
  {
    name:    'RabbitMQ Management',
    path:    '/#/',
    loginFingerprints: ['RabbitMQ'],
    openFingerprints:  ['Queues', 'Exchanges', 'RabbitMQ'],
  },
  {
    name:    'Kubernetes Dashboard',
    path:    '/kubernetes-dashboard/',
    loginFingerprints: ['Kubernetes Dashboard'],
    openFingerprints:  ['Namespaces', 'Deployments'],
  },

  // ── Hosting panels
  {
    name:    'cPanel',
    path:    ':2082/',
    isPort:  true,
    loginFingerprints: ['cPanel', 'cpanel'],
    openFingerprints:  ['File Manager', 'Email Accounts'],
  },
  {
    name:    'WHM',
    path:    ':2086/',
    isPort:  true,
    loginFingerprints: ['WebHost Manager', 'WHM'],
    openFingerprints:  ['Account Functions', 'Server Configuration'],
  },
];

// ── Main entry ─────────────────────────────────────────────────────────────

export async function runAdminPanelDetect({ ctx, target, baseUrl, siteModel, fetchAdapter }) {
  ctx.log('[adminPanel] Starting admin panel detection...');
  const base      = baseUrl.replace(/\/$/, '');
  const cms       = siteModel?.techStack?.cms || null;
  const hostOnly  = extractHost(baseUrl);

  // Track already-reported paths to avoid duplicate findings
  const reported = new Set();

  for (const def of PANEL_DEFS) {
    // Skip CMS-specific panels if that CMS wasn’t detected
    if (def.cmsHint && cms && !cms.toLowerCase().includes(def.cmsHint.toLowerCase())) {
      ctx.log(`[adminPanel] Skipping ${def.path} (CMS hint: ${def.cmsHint}, detected: ${cms})`);
      continue;
    }

    // Build URL — port-based panels use host:port format
    const url = def.isPort
      ? `http://${hostOnly}${def.path}`
      : base + def.path;

    if (reported.has(url)) continue;

    ctx.log(`[adminPanel] Probing ${url}`);

    let res;
    try {
      res = await httpGetText({ fetchAdapter, url });
    } catch (e) {
      ctx.log(`[adminPanel] Fetch error at ${url}: ${e.message || e}`);
      continue;
    }

    // Only care about 200 and soft-redirect 401/403 (access controlled)
    if (![200, 401, 403].includes(res.status)) continue;

    const body    = (res.body || '').slice(0, 32768);
    const bodyLow = body.toLowerCase();

    const isOpen  = def.openFingerprints.some((fp)  => bodyLow.includes(fp.toLowerCase()));
    const isLogin = def.loginFingerprints.some((fp) => bodyLow.includes(fp.toLowerCase()));

    if (!isOpen && !isLogin) continue;

    reported.add(url);

    if (isOpen && res.status === 200) {
      // Tier 1: unauthenticated direct access
      ctx.log(`\uD83D\uDD34 CRITICAL: unauthenticated ${def.name} at ${url}`);

      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'exposure.admin_panels',
        title:       `Unauthenticated ${def.name} Exposed`,
        shortDescription:
          `${def.name} is accessible without authentication at ${url}.`,
        detailedDescription:
          `The ${def.name} interface is directly accessible without requiring authentication. ` +
          'This gives any visitor full administrative access to the application or infrastructure. ' +
          'Immediate remediation required: restrict access by IP, add authentication, or take the panel offline.\n\n' +
          buildTechContext(siteModel),
        severity: 'critical',
        category: 'exposure',
        owaspTag: 'A01-Broken-Access-Control',
        cweTag:   'CWE-306',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(new Evidence({
        findingId:              finding.id,
        url,
        method:                 'GET',
        responseStatus:         res.status,
        responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
        responseBodySnippet:    body.slice(0, 2048),
        matchedPattern:         `Open panel fingerprints matched: ${def.openFingerprints.filter((fp) => bodyLow.includes(fp.toLowerCase())).slice(0, 3).join(', ')}`,
      }));
    } else if (isLogin || res.status === 401 || res.status === 403) {
      // Tier 2: login page found — panel location known
      ctx.log(`\uD83D\uDFE1 MEDIUM: ${def.name} login page at ${url}`);

      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'exposure.admin_panels',
        title:       `${def.name} Login Page Exposed`,
        shortDescription:
          `${def.name} login page is reachable at ${url}. Access is controlled but location is disclosed.`,
        detailedDescription:
          `The ${def.name} login interface is publicly reachable. While it requires authentication, ` +
          'exposing the login page allows attackers to attempt brute-force or credential stuffing attacks, ' +
          'and leaks the presence of this administrative tool. ' +
          'Best practice: restrict access to this path by IP allowlist at the web server or firewall level.\n\n' +
          buildTechContext(siteModel),
        severity: 'medium',
        category: 'exposure',
        owaspTag: 'A05-Security-Misconfiguration',
        cweTag:   'CWE-200',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(new Evidence({
        findingId:              finding.id,
        url,
        method:                 'GET',
        responseStatus:         res.status,
        responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
        responseBodySnippet:    body.slice(0, 2048),
        matchedPattern:         `Login fingerprints matched at status ${res.status}`,
      }));
    }
  }

  ctx.log('[adminPanel] Done.');
}

// ── Helpers ───────────────────────────────────────────────────────────────

function extractHost(baseUrl) {
  try {
    return new URL(baseUrl).host; // includes port if present
  } catch {
    return baseUrl.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  }
}

function buildTechContext(siteModel) {
  if (!siteModel?.techStack) return '';
  const ts    = siteModel.techStack;
  const lines = [];
  if (ts.server)             lines.push(`Server: ${ts.server}`);
  if (ts.cms)                lines.push(`CMS: ${ts.cms}`);
  if (ts.language)           lines.push(`Language: ${ts.language}`);
  if (ts.frameworks?.length) lines.push(`Frameworks: ${ts.frameworks.join(', ')}`);
  return lines.length ? 'Tech context:\n' + lines.map((l) => `  • ${l}`).join('\n') : '';
}
