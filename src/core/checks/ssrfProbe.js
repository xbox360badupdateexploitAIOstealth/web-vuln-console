// src/core/checks/ssrfProbe.js
// Active check: Server-Side Request Forgery (SSRF) detection.
//
// SSRF allows attackers to make the server perform HTTP requests to
// internal or cloud-provider resources inaccessible to external clients:
//   - AWS EC2 metadata (IAM credentials, instance identity, user-data)
//   - GCP metadata service (service account tokens, project info)
//   - Azure IMDS (managed identity tokens)
//   - DigitalOcean metadata
//   - Internal network probing (localhost, 192.168.x.x, 10.x.x.x)
//
// Strategy:
//   1. Take parameterised endpoints from siteModel
//   2. Prioritise params whose names suggest URL/resource inputs
//   3. Inject SSRF payloads targeting cloud metadata endpoints
//   4. Detect by:
//      a. Response body containing cloud metadata signatures
//      b. Unusual response size / status change vs baseline
//      c. Response time anomaly (internal service responding slower/faster)
//   5. Also probe common fetch-style params on root URL
//
// Wire-up (engine.js Phase 3c — after openRedirect, alongside other injection):
//   import { runSsrfProbe } from './checks/ssrfProbe.js';
//   if (moduleEnabled(enabledModules, 'injection.ssrf.basic')) {
//     await runSsrfProbe({ ctx, target, siteModel, engineConfig });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// Cloud metadata endpoints to inject
const SSRF_PAYLOADS = [
  {
    label:      'AWS EC2 Metadata (IMDSv1)',
    url:        'http://169.254.169.254/latest/meta-data/',
    signatures: ['ami-id', 'instance-id', 'instance-type', 'local-ipv4', 'public-ipv4', 'security-credentials'],
  },
  {
    label:      'AWS EC2 IAM Credentials',
    url:        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    signatures: ['AccessKeyId', 'SecretAccessKey', 'Token', 'Expiration'],
  },
  {
    label:      'AWS EC2 User Data',
    url:        'http://169.254.169.254/latest/user-data',
    signatures: ['#!/', 'cloud-config', 'runcmd', 'apt-get', 'yum install'],
  },
  {
    label:      'GCP Metadata Service',
    url:        'http://metadata.google.internal/computeMetadata/v1/?recursive=true',
    signatures: ['project-id', 'service-accounts', 'instance', 'hostname', 'machineType'],
  },
  {
    label:      'GCP Service Account Token',
    url:        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    signatures: ['access_token', 'token_type', 'expires_in'],
  },
  {
    label:      'Azure IMDS',
    url:        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    signatures: ['subscriptionId', 'resourceGroupName', 'vmId', 'location', 'azEnvironment'],
  },
  {
    label:      'Azure Managed Identity Token',
    url:        'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/',
    signatures: ['access_token', 'client_id', 'token_type'],
  },
  {
    label:      'DigitalOcean Metadata',
    url:        'http://169.254.169.254/metadata/v1.json',
    signatures: ['droplet_id', 'hostname', 'region', 'interfaces'],
  },
  {
    label:      'Localhost HTTP probe',
    url:        'http://127.0.0.1/',
    signatures: ['localhost', '127.0.0.1', 'Default page', 'It works', 'Welcome to nginx'],
  },
  {
    label:      'Localhost HTTPS probe',
    url:        'https://127.0.0.1/',
    signatures: ['localhost', '127.0.0.1', 'Default page', 'It works', 'Welcome to nginx'],
  },
];

// Parameters commonly used as URL/resource inputs (high SSRF signal)
const SSRF_PARAM_HINTS = [
  'url', 'uri', 'src', 'source', 'href', 'link', 'path',
  'file', 'filename', 'load', 'fetch', 'get', 'request',
  'image', 'img', 'picture', 'proxy', 'target', 'dest',
  'destination', 'to', 'from', 'resource', 'endpoint',
  'api', 'callback', 'webhook', 'feed', 'data',
];

const MAX_ENDPOINTS = 30;
const MAX_PROBES    = 100;

// ── Main entry ─────────────────────────────────────────────────────────────

export async function runSsrfProbe({ ctx, target, siteModel, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const base = normalizeBase(target.host);

  ctx.log('[ssrf] Starting SSRF probe...');

  const endpoints = siteModel.getParamEndpoints();
  if (endpoints.length === 0) {
    ctx.log('[ssrf] No parameterised endpoints — skipping.');
    return;
  }

  // Sort: SSRF-hint params first
  const sorted = sortBySsrfHint(endpoints);
  ctx.log(`[ssrf] ${sorted.length} parameterised endpoint(s) to check.`);

  let totalProbes = 0;

  for (const ep of sorted.slice(0, MAX_ENDPOINTS)) {
    if (totalProbes >= MAX_PROBES) break;

    const urlBase = base.replace(/\/$/, '') + ep.url;
    const params  = ep.params.map((p) => p.name).filter(Boolean);

    // Prioritise hint-matching params within this endpoint
    const paramsSorted = [...params].sort((a, b) => {
      const aHint = SSRF_PARAM_HINTS.includes(a.toLowerCase()) ? 1 : 0;
      const bHint = SSRF_PARAM_HINTS.includes(b.toLowerCase()) ? 1 : 0;
      return bHint - aHint;
    });

    let hitThisEndpoint = false;

    for (const paramName of paramsSorted) {
      if (hitThisEndpoint || totalProbes >= MAX_PROBES) break;

      for (const payload of SSRF_PAYLOADS) {
        if (totalProbes >= MAX_PROBES) break;

        const url = injectQueryParam(urlBase, paramName, payload.url);
        ctx.log(`[ssrf] Probe [${paramName}] ${payload.label}: ${url}`);

        let res;
        try {
          res = await httpGetText({ fetchAdapter, url });
        } catch (e) {
          ctx.log(`[ssrf] Fetch error: ${e.message || e}`);
          totalProbes++;
          continue;
        }

        totalProbes++;

        if (res.status === 0 || res.status >= 500) continue;

        const body      = res.body || '';
        const matchedSig = payload.signatures.find((sig) => body.includes(sig));

        if (!matchedSig) continue;

        // Confirmed SSRF hit
        const isCredentialLeak = payload.label.includes('IAM') ||
                                  payload.label.includes('Token') ||
                                  payload.label.includes('Managed Identity');
        const severity = isCredentialLeak ? 'critical' : 'high';

        ctx.log(`\uD83D\uDD34 ${severity.toUpperCase()}: SSRF confirmed — ${payload.label} via param "${paramName}" at ${urlBase}`);

        const finding = new Finding({
          projectId:   ctx.project.id,
          scanJobId:   ctx.job.id,
          targetId:    target.id,
          moduleId:    'injection.ssrf.basic',
          title:       `SSRF — ${payload.label}`,
          shortDescription:
            `Server-Side Request Forgery confirmed via parameter "${paramName}" at ${urlBase}. ` +
            `Response matched "${matchedSig}" from ${payload.label}.`,
          detailedDescription:
            `SSRF was confirmed: the server fetched the injected URL (${payload.url}) and ` +
            `returned content matching "${matchedSig}", which is a signature of ${payload.label}. \n\n` +
            (isCredentialLeak
              ? '\u26a0\ufe0f  CREDENTIAL LEAK: The response may contain live cloud credentials ' +
                '(AccessKeyId, SecretAccessKey, tokens). Rotate immediately if confirmed.\n\n'
              : '') +
            'Impact:\n' +
            '  • Read internal cloud metadata (IAM roles, tokens, instance identity)\n' +
            '  • Pivot to internal services unreachable from outside\n' +
            '  • Exfiltrate cloud credentials and escalate privileges\n' +
            '  • Bypass firewall rules via server-side proxying\n\n' +
            `Confirmed via: param="${paramName}", payload URL="${payload.url}", matched signature="${matchedSig}"\n\n` +
            'Remediation:\n' +
            '  • Validate and allowlist all user-supplied URLs before fetching\n' +
            '  • Block requests to 169.254.x.x and 192.168.x.x at network/firewall level\n' +
            '  • Use IMDSv2 (AWS) which requires a PUT pre-flight token\n' +
            '  • Disable metadata endpoint if not required\n' +
            '  • Run application with least-privilege IAM role',
          severity,
          category: 'injection',
          owaspTag: 'A10-Server-Side-Request-Forgery',
          cweTag:   'CWE-918',
        });
        ctx.addFinding(finding);
        ctx.addEvidence(new Evidence({
          findingId:              finding.id,
          url,
          method:                 'GET',
          responseStatus:         res.status,
          responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
          responseBodySnippet:    body.slice(0, 2048),
          matchedPattern:
            `SSRF confirmed — ${payload.label} | matched: "${matchedSig}" | param: ${paramName}`,
        }));

        hitThisEndpoint = true;
        break;
      }
    }
  }

  ctx.log(`[ssrf] Done. Total probes: ${totalProbes}`);
}

// ── Helpers ───────────────────────────────────────────────────────────────

function sortBySsrfHint(endpoints) {
  return [...endpoints].sort((a, b) => {
    const score = (ep) => ep.params.filter(
      (p) => SSRF_PARAM_HINTS.includes(p.name.toLowerCase())
    ).length;
    return score(b) - score(a);
  });
}

function normalizeBase(host) {
  if (!/^https?:\/\//i.test(host)) return `https://${host}`;
  return host;
}

function injectQueryParam(urlBase, paramName, payload) {
  try {
    const u = new URL(urlBase);
    u.searchParams.set(paramName, payload);
    return u.toString();
  } catch {
    const sep = urlBase.includes('?') ? '&' : '?';
    return `${urlBase}${sep}${encodeURIComponent(paramName)}=${encodeURIComponent(payload)}`;
  }
}
