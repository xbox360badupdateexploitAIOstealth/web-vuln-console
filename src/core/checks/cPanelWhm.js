// src/core/checks/cPanelWhm.js
// Module: exposure.cve.cpanel_whm
// Probes IP addresses (and hostnames) for exposed cPanel / WHM admin panels.
//
// Detection strategy:
//   For each host × each candidate port × each probe path:
//     1. HTTP GET the probe URL (with short timeout).
//     2. Check response headers for cPanel fingerprints:
//        - X-cPanel-Version
//        - X-Powered-By: cpsrvd
//        - Server: cpsrvd
//     3. Check response body for cPanel login / WHM UI signatures.
//     4. If confirmed, flag finding with CVE-2026-41940 context.
//
// CVE-2026-41940 context:
//   Unauthenticated information disclosure in cPanel & WHM allows a remote
//   attacker to enumerate server metadata (cPanel version, hostname, internal
//   paths) via the /json-api/version and /xml-api/version endpoints without
//   authentication, and in some configurations enumerate session token
//   patterns through the /cpsess* redirect path. Severity: Critical (CVSS 9.1).
//   Affected versions: cPanel & WHM < 120.0.6 (June 2026 advisory).
//   Fix: Upgrade to cPanel & WHM >= 120.0.6 or restrict port access via firewall.
//
// ⚠️  NOTE: CVE-2026-41940 was under embargo at dev.txt writing time.
//           Validate against NVD / SentinelOne advisory before using in reports.

import { Finding, Evidence } from '../models.js';
import { moduleDefById }     from '../moduleRegistry.js';

// cPanel/WHM listens on distinct ports depending on access mode:
// 2082 HTTP cPanel, 2083 HTTPS cPanel, 2086 HTTP WHM, 2087 HTTPS WHM
// 8080 / 8443 used by some hardened or managed hosting setups.
const CPANEL_PORTS = [2083, 2087, 2082, 2086, 8443, 8080];

const PROBE_PATHS = [
  '/login',
  '/cpanel',
  '/whm',
  '/json-api/version',   // unauthenticated info endpoint — CVE-2026-41940 vector
  '/xml-api/version',    // same
  '/cpsess0/cgi/cpanel.php',
  '/',
];

// Body signatures that strongly indicate cPanel or WHM UI
const BODY_SIGNATURES = [
  /cPanel &amp; WHM/i,
  /cPanel.*login/i,
  /WebHost Manager/i,
  /cp_login_token/i,
  /"cpanelversion"/i,        // json-api/version response key
  /<title>.*cPanel/i,
  /<title>.*WHM/i,
  /cpsrvd/i,
  /cPanel, L\.L\.C\./i,
];

// Response header signatures
function headerIndicatesCPanel(headers) {
  const server    = (headers['server']         || '').toLowerCase();
  const powered   = (headers['x-powered-by']   || '').toLowerCase();
  const cpVersion = (headers['x-cpanel-version'] || '');
  return (
    server.includes('cpsrvd') ||
    powered.includes('cpsrvd') ||
    cpVersion.length > 0
  );
}

function bodyIndicatesCPanel(body) {
  return BODY_SIGNATURES.some((re) => re.test(body));
}

/**
 * Extract cPanel version from json-api/version or x-cpanel-version header.
 * Returns version string or null.
 */
function extractVersion(body, headers) {
  // Header first
  if (headers['x-cpanel-version']) return headers['x-cpanel-version'].trim();

  // json-api/version → {"version":"120.0.4"} or {"data":{"version":"..."}}
  try {
    const parsed = JSON.parse(body);
    if (parsed.version) return String(parsed.version);
    if (parsed.data?.version) return String(parsed.data.version);
  } catch { /* not JSON */ }

  // xml-api/version fallback — look for <version> tag
  const xmlMatch = body.match(/<version>([^<]+)<\/version>/i);
  if (xmlMatch) return xmlMatch[1].trim();

  return null;
}

/**
 * Check whether a detected version is vulnerable to CVE-2026-41940.
 * Vulnerable: < 120.0.6 (approximately — check NVD for exact boundary).
 */
function isVulnerableVersion(version) {
  if (!version) return null; // unknown — treat as potentially vulnerable
  // Parse "MAJOR.MINOR.PATCH" e.g. "120.0.4"
  const parts = version.split('.').map(Number);
  const [major, minor, patch] = [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
  if (major < 120) return true;
  if (major === 120 && minor === 0 && patch < 6) return true;
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
export async function runCPanelWhmScan({ ctx, target, fetchAdapter }) {
  const mod = moduleDefById['exposure.cve.cpanel_whm'];
  if (!mod) {
    ctx.log('exposure.cve.cpanel_whm: ModuleDef not found — skipping');
    return;
  }

  ctx.log(`\n[cPanel/WHM] Scanning ${target.host} across ${CPANEL_PORTS.length} ports...`);

  const reportedHosts = new Set();

  for (const port of CPANEL_PORTS) {
    // Try HTTPS first (2083, 2087, 8443) — use HTTP for plain ports
    const scheme = [2083, 2087, 8443].includes(port) ? 'https' : 'http';
    const baseUrl = `${scheme}://${target.host}:${port}`;

    let portReachable = false;

    for (const probePath of PROBE_PATHS) {
      const url = baseUrl + probePath;

      let res;
      try {
        res = await fetchAdapter(url, {
          method: 'GET',
          timeout: 6000,
          rejectUnauthorized: false, // many cPanel installs use self-signed certs
          headers: { 'User-Agent': 'Mozilla/5.0 (web-vuln-console/1.0) SecurityAudit' },
        });
      } catch (e) {
        // Connection refused / timeout = port not open; skip remaining paths
        ctx.log(`  [cPanel] ${url} → unreachable (${e.message?.slice(0, 60)})`);
        break;
      }

      portReachable = true;
      ctx.log(`  [cPanel] ${url} → HTTP ${res.status}`);

      const isCPanel = headerIndicatesCPanel(res.headers) || bodyIndicatesCPanel(res.body || '');
      if (!isCPanel) continue;

      const hostKey = `${target.host}:${port}`;
      if (reportedHosts.has(hostKey)) break; // one finding per host:port
      reportedHosts.add(hostKey);

      const version      = extractVersion(res.body || '', res.headers);
      const vulnStatus   = isVulnerableVersion(version);
      const versionLabel = version ? `v${version}` : 'version unknown';
      const cvePart      = vulnStatus !== false
        ? ' Potentially vulnerable to CVE-2026-41940 (unauthenticated info disclosure).'
        : ' Version appears patched for CVE-2026-41940, but panel exposure is still a risk.';

      const finding = new Finding({
        projectId:  ctx.project.id,
        scanJobId:  ctx.job.id,
        targetId:   target.id,
        moduleId:   'exposure.cve.cpanel_whm',
        title:      `Exposed cPanel/WHM Admin Panel — ${target.host}:${port}`,
        shortDescription:
          `cPanel/WHM admin panel (${versionLabel}) is accessible at ${url} on port ${port}.${cvePart}`,
        detailedDescription:
          `A cPanel & WHM control panel was detected on ${target.host} port ${port} (${scheme.toUpperCase()}). ` +
          `Exposure of admin panels to the public internet drastically increases the attack surface. ` +
          (vulnStatus !== false
            ? `This installation (${versionLabel}) may be vulnerable to CVE-2026-41940, which allows an unauthenticated ` +
              `remote attacker to enumerate server metadata (hostname, cPanel version, internal paths) via ` +
              `/json-api/version and /xml-api/version, and may expose session token patterns through cpsess redirects. ` +
              `CVSS 9.1 (Critical). Fix: upgrade to cPanel & WHM >= 120.0.6 and restrict panel ports via firewall.`
            : `Version ${versionLabel} appears to be >= 120.0.6 (CVE-2026-41940 patched), but ` +
              `the panel should still be restricted to management IP ranges.`),
        severity:   'critical',
        category:   'exposure',
        owaspTag:   'A05-Security-Misconfiguration',
        cweTag:     'CWE-200',
      });

      ctx.addFinding(finding);
      ctx.addEvidence(new Evidence({
        findingId:               finding.id,
        url,
        method:                  'GET',
        responseStatus:          res.status,
        responseHeadersSnippet:  JSON.stringify(res.headers).slice(0, 512),
        responseBodySnippet:     (res.body || '').slice(0, 2048),
        matchedPattern:          'cPanel/WHM header or body fingerprint',
      }));

      ctx.log(`🔴 CRITICAL: cPanel/WHM exposed at ${url} (${versionLabel})`);
      break; // found on this port — move to next port
    }

    if (!portReachable) {
      ctx.log(`  [cPanel] Port ${port} closed/filtered on ${target.host}`);
    }
  }

  ctx.log(`[cPanel/WHM] Scan complete for ${target.host}`);
}
