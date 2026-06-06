// src/core/checks/techFingerprint.js
// Passive tech-stack fingerprinting.
//
// Runs BEFORE the crawler (engine.js Phase 1a) so that all later modules
// (cveFingerprints, adminPanelDetect, corsMisconfig, etc.) can read
// siteModel.techStack and make smarter decisions.
//
// What it detects (all from a single GET / request + HTML body):
//   - Server header  → siteModel.techStack.server
//   - X-Powered-By  → siteModel.techStack.language
//   - CMS (WordPress, Drupal, Joomla, Ghost, Magento, …) via headers + HTML meta
//   - Frameworks (Laravel, Django, Rails, Next.js, Nuxt, Livewire, …)
//   - CDN / edge layer (Cloudflare, Fastly, Akamai, Vercel, AWS CF)
//   - Raw fingerprint headers stored in siteModel.techStack.rawHeaders
//
// Wire-up (engine.js Phase 1a — before all other phases):
//   import { runTechFingerprint } from './checks/techFingerprint.js';
//   if (moduleEnabled(enabledModules, 'recon.tech_fingerprint')) {
//     await runTechFingerprint({ ctx, target, baseUrl, siteModel, fetchAdapter });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// ── Detection tables ──────────────────────────────────────────────────────────

// Headers whose value we capture verbatim
const CAPTURE_HEADERS = [
  'server',
  'x-powered-by',
  'x-generator',
  'x-drupal-cache',
  'x-drupal-dynamic-cache',
  'x-wordpress-login',
  'x-magento-cache-debug',
  'x-magento-tags',
  'x-shopify-stage',
  'x-ghost-cache-status',
  'x-joomla-item-id',
  'x-laravel-version',
  'x-runtime',        // Rails
  'x-vercel-id',
  'cf-ray',           // Cloudflare
  'x-amz-cf-id',      // AWS CloudFront
  'x-fastly-request-id',
  'x-akamai-transformed',
  'via',
];

// CMS fingerprints: each entry has a list of signals to match
// signal: { type: 'header'|'body', key?, pattern }
const CMS_FINGERPRINTS = [
  {
    name: 'WordPress',
    signals: [
      { type: 'header', key: 'x-wordpress-login', pattern: /./ },
      { type: 'body',   pattern: /wp-content\//i },
      { type: 'body',   pattern: /wp-includes\//i },
      { type: 'body',   pattern: /<meta[^>]+generator[^>]+WordPress/i },
    ],
  },
  {
    name: 'Drupal',
    signals: [
      { type: 'header', key: 'x-drupal-cache',         pattern: /./ },
      { type: 'header', key: 'x-drupal-dynamic-cache',  pattern: /./ },
      { type: 'body',   pattern: /<meta[^>]+generator[^>]+Drupal/i },
      { type: 'body',   pattern: /\/sites\/default\/files\//i },
      { type: 'body',   pattern: /Drupal\.settings/i },
    ],
  },
  {
    name: 'Joomla',
    signals: [
      { type: 'header', key: 'x-joomla-item-id', pattern: /./ },
      { type: 'body',   pattern: /<meta[^>]+generator[^>]+Joomla/i },
      { type: 'body',   pattern: /\/components\/com_/i },
      { type: 'body',   pattern: /\/media\/jui\//i },
    ],
  },
  {
    name: 'Magento',
    signals: [
      { type: 'header', key: 'x-magento-cache-debug', pattern: /./ },
      { type: 'header', key: 'x-magento-tags',        pattern: /./ },
      { type: 'body',   pattern: /Mage\.Cookies/i },
      { type: 'body',   pattern: /\/skin\/frontend\//i },
    ],
  },
  {
    name: 'Shopify',
    signals: [
      { type: 'header', key: 'x-shopify-stage', pattern: /./ },
      { type: 'body',   pattern: /cdn\.shopify\.com/i },
      { type: 'body',   pattern: /Shopify\.theme/i },
    ],
  },
  {
    name: 'Ghost',
    signals: [
      { type: 'header', key: 'x-ghost-cache-status', pattern: /./ },
      { type: 'body',   pattern: /<meta[^>]+generator[^>]+Ghost/i },
      { type: 'body',   pattern: /ghost\/core/i },
    ],
  },
  {
    name: 'TYPO3',
    signals: [
      { type: 'body', pattern: /<meta[^>]+generator[^>]+TYPO3/i },
      { type: 'body', pattern: /typo3\/sysext\//i },
    ],
  },
  {
    name: 'OpenCart',
    signals: [
      { type: 'body', pattern: /route=common\/home/i },
      { type: 'body', pattern: /catalog\/view\/theme\//i },
    ],
  },
];

// Framework fingerprints
const FRAMEWORK_FINGERPRINTS = [
  {
    name: 'Laravel',
    signals: [
      { type: 'header', key: 'x-laravel-version', pattern: /./ },
      { type: 'body',   pattern: /laravel_session|XSRF-TOKEN/i },
      { type: 'body',   pattern: /laravel\/framework/i },
    ],
  },
  {
    name: 'Django',
    signals: [
      { type: 'header', key: 'x-powered-by', pattern: /django/i },
      { type: 'body',   pattern: /csrfmiddlewaretoken/i },
      { type: 'body',   pattern: /__django/i },
    ],
  },
  {
    name: 'Ruby on Rails',
    signals: [
      { type: 'header', key: 'x-runtime', pattern: /^\d+\.\d+$/ },
      { type: 'header', key: 'x-powered-by', pattern: /phusion passenger/i },
      { type: 'body',   pattern: /authenticity_token/i },
    ],
  },
  {
    name: 'Next.js',
    signals: [
      { type: 'header', key: 'x-powered-by', pattern: /Next\.js/i },
      { type: 'body',   pattern: /__NEXT_DATA__/i },
      { type: 'body',   pattern: /_next\/static\//i },
    ],
  },
  {
    name: 'Nuxt.js',
    signals: [
      { type: 'body', pattern: /__nuxt/i },
      { type: 'body', pattern: /_nuxt\//i },
    ],
  },
  {
    name: 'Angular',
    signals: [
      { type: 'body', pattern: /ng-version=/i },
      { type: 'body', pattern: /angular\.min\.js/i },
    ],
  },
  {
    name: 'React',
    signals: [
      { type: 'body', pattern: /react\.development\.js|react\.production\.min\.js/i },
      { type: 'body', pattern: /data-reactroot/i },
    ],
  },
  {
    name: 'Vue.js',
    signals: [
      { type: 'body', pattern: /vue\.min\.js|vue\.esm/i },
      { type: 'body', pattern: /data-v-[a-f0-9]{6,}/i },
    ],
  },
  {
    name: 'ASP.NET',
    signals: [
      { type: 'header', key: 'x-powered-by', pattern: /ASP\.NET/i },
      { type: 'header', key: 'x-aspnet-version', pattern: /./ },
      { type: 'body',   pattern: /__VIEWSTATE/i },
    ],
  },
  {
    name: 'Livewire',
    signals: [
      { type: 'body', pattern: /livewire\/livewire\.js/i },
      { type: 'body', pattern: /wire:id=/i },
    ],
  },
];

// CDN / edge layer fingerprints (presence → logged but not a finding)
const CDN_FINGERPRINTS = [
  { name: 'Cloudflare',  signals: [{ type: 'header', key: 'cf-ray', pattern: /./ }] },
  { name: 'Vercel',      signals: [{ type: 'header', key: 'x-vercel-id', pattern: /./ }] },
  { name: 'AWS CloudFront', signals: [{ type: 'header', key: 'x-amz-cf-id', pattern: /./ }] },
  { name: 'Fastly',      signals: [{ type: 'header', key: 'x-fastly-request-id', pattern: /./ }] },
  { name: 'Akamai',      signals: [{ type: 'header', key: 'x-akamai-transformed', pattern: /./ }] },
  { name: 'Nginx',       signals: [{ type: 'header', key: 'server', pattern: /nginx/i }] },
  { name: 'Apache',      signals: [{ type: 'header', key: 'server', pattern: /apache/i }] },
  { name: 'IIS',         signals: [{ type: 'header', key: 'server', pattern: /IIS/i }] },
  { name: 'LiteSpeed',   signals: [{ type: 'header', key: 'server', pattern: /LiteSpeed/i }] },
];

// ── Main entry ────────────────────────────────────────────────────────────────

export async function runTechFingerprint({ ctx, target, baseUrl, siteModel, fetchAdapter }) {
  ctx.log('[techFingerprint] Starting passive tech-stack fingerprint...');
  const base = baseUrl.replace(/\/$/, '');
  const url  = base + '/';

  let res;
  try {
    res = await httpGetText({ fetchAdapter, url });
  } catch (e) {
    ctx.log(`[techFingerprint] Root fetch error: ${e.message || e}`);
    return;
  }

  if (!res || res.status === 0) {
    ctx.log('[techFingerprint] No response from root — skipping.');
    return;
  }

  const headers = res.headers || {};
  const body    = res.body    || '';

  // 1. Capture raw fingerprint headers
  for (const h of CAPTURE_HEADERS) {
    const val = headers[h] || headers[h.toLowerCase()];
    if (val) siteModel.techStack.rawHeaders[h] = val;
  }

  // 2. Server header
  const serverVal = headers['server'] || headers['Server'];
  if (serverVal) {
    siteModel.techStack.server = serverVal;
    ctx.log(`[techFingerprint] Server: ${serverVal}`);
  }

  // 3. Language from X-Powered-By
  const poweredBy = headers['x-powered-by'] || headers['X-Powered-By'];
  if (poweredBy) {
    siteModel.techStack.language = poweredBy;
    ctx.log(`[techFingerprint] X-Powered-By: ${poweredBy}`);
  }

  // 4. CMS detection
  let cmsDetected = null;
  for (const fp of CMS_FINGERPRINTS) {
    if (matchesAnySignal(fp.signals, headers, body)) {
      cmsDetected = fp.name;
      siteModel.techStack.cms = fp.name;
      ctx.log(`[techFingerprint] CMS detected: ${fp.name}`);
      break;
    }
  }

  // 5. Framework detection (can be multiple)
  const frameworksDetected = [];
  for (const fp of FRAMEWORK_FINGERPRINTS) {
    if (matchesAnySignal(fp.signals, headers, body)) {
      frameworksDetected.push(fp.name);
      ctx.log(`[techFingerprint] Framework detected: ${fp.name}`);
    }
  }
  if (frameworksDetected.length) {
    siteModel.techStack.frameworks = frameworksDetected;
  }

  // 6. CDN / edge layer (log only, not a finding)
  const cdnsDetected = [];
  for (const fp of CDN_FINGERPRINTS) {
    if (matchesAnySignal(fp.signals, headers, body)) {
      cdnsDetected.push(fp.name);
    }
  }
  if (cdnsDetected.length) {
    ctx.log(`[techFingerprint] CDN/Server layer: ${cdnsDetected.join(', ')}`);
  }

  // 7. Version extraction from <meta name="generator">
  const generatorMatch = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)
                      || body.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i);
  if (generatorMatch) {
    const gen = generatorMatch[1].trim();
    ctx.log(`[techFingerprint] <meta generator>: ${gen}`);
    // If CMS not set yet, use generator
    if (!siteModel.techStack.cms && gen) {
      siteModel.techStack.cms = gen;
    }
  }

  // 8. Emit info finding if we detected anything
  const detectedItems = [
    siteModel.techStack.server   ? `Server: ${siteModel.techStack.server}`     : null,
    siteModel.techStack.language ? `Language: ${siteModel.techStack.language}` : null,
    siteModel.techStack.cms      ? `CMS: ${siteModel.techStack.cms}`           : null,
    ...siteModel.techStack.frameworks.map((f) => `Framework: ${f}`),
    ...cdnsDetected.map((c) => `CDN/Edge: ${c}`),
  ].filter(Boolean);

  if (detectedItems.length > 0) {
    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'recon.tech_fingerprint',
      title:       'Technology Stack Fingerprinted',
      shortDescription:
        `Detected: ${detectedItems.slice(0, 4).join(' | ')}` +
        (detectedItems.length > 4 ? ` (+${detectedItems.length - 4} more)` : ''),
      detailedDescription:
        'Passive fingerprinting identified the following technologies in use:\n' +
        detectedItems.map((i) => `  • ${i}`).join('\n') + '\n\n' +
        'This information is used internally to improve accuracy of other scan modules. ' +
        'Exposing version details in HTTP headers or HTML also helps attackers select targeted exploits. ' +
        'Consider removing or genericising Server, X-Powered-By, and generator meta tags in production.',
      severity: 'info',
      category: 'recon',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag:   'CWE-200',
    });

    ctx.addFinding(finding);
    ctx.addEvidence(new Evidence({
      findingId:              finding.id,
      url,
      method:                 'GET',
      responseStatus:         res.status,
      responseHeadersSnippet: JSON.stringify(headers).slice(0, 512),
      responseBodySnippet:    body.slice(0, 1024),
      matchedPattern:         detectedItems.join(' | '),
    }));

    ctx.log(`\u2139\uFE0F INFO: tech fingerprint — ${detectedItems.slice(0, 3).join(', ')}`);
  } else {
    ctx.log('[techFingerprint] No technology signals detected from root response.');
  }

  ctx.log('[techFingerprint] Done.');
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function matchesAnySignal(signals, headers, body) {
  for (const sig of signals) {
    if (sig.type === 'header') {
      const val = headers[sig.key] || headers[sig.key?.toLowerCase()] || '';
      if (val && sig.pattern.test(val)) return true;
    } else if (sig.type === 'body') {
      if (sig.pattern.test(body)) return true;
    }
  }
  return false;
}
