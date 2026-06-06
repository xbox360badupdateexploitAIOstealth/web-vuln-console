// src/core/checks/jsSecretScan.js
// TODO-02: JavaScript asset secret scanner.
// Runs as Phase 2.5 (after crawl, before active injection) for the exposure.js.secrets module.
//
// For every .js asset URL discovered by the crawler in the SiteModel,
// this module fetches the content and scans it for hardcoded secrets using
// a prioritized regex library covering the most common credential patterns.
//
// Detection patterns (in severity order):
//  1. AWS Access Key ID + Secret Access Key pairs
//  2. Stripe live secret keys (sk-live-...)
//  3. Stripe restricted keys (rk_live_...)
//  4. Google API keys (AIza...)
//  5. Firebase config objects (apiKey: "AIza...")
//  6. GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_)
//  7. GitHub fine-grained tokens (github_pat_...)
//  8. Slack bot/app tokens (xoxb-, xoxp-, xoxa-, xoxr-)
//  9. OpenAI API keys (sk-... 48-char)
// 10. HuggingFace tokens (hf_...)
// 11. Replicate tokens (r8_...)
// 12. Generic Bearer token literals in JS strings
// 13. Private key PEM blocks
// 14. Generic high-entropy strings assigned to secret-named variables

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// ─────────────────────────────────────────────────────────────────────────────
// SECRET PATTERNS
// Each entry: { id, name, pattern, severity, detail, cwe }
// Patterns are applied to the full JS file body.
// ─────────────────────────────────────────────────────────────────────────────

const SECRET_PATTERNS = [
  {
    id:       'aws.access_key',
    name:     'AWS Access Key ID',
    pattern:  /(?<![A-Z0-9])(AKIA|ABIA|ACCA|AIDA|AIPA|AKIA|AKID)[A-Z0-9]{16}(?![A-Z0-9])/g,
    severity: 'critical',
    cwe:      'CWE-312',
    detail:   'An AWS Access Key ID was found in a JavaScript file. These keys provide programmatic access to AWS services. Rotate immediately via the AWS IAM console.',
  },
  {
    id:       'aws.secret_key',
    name:     'AWS Secret Access Key',
    // 40-char base64-like string following common assignment patterns
    pattern:  /(?:aws_secret(?:_access)?_key|AWS_SECRET(?:_ACCESS)?_KEY)["'\s]*[:=]["'\s]*([A-Za-z0-9/+]{40})/gi,
    severity: 'critical',
    cwe:      'CWE-312',
    detail:   'An AWS Secret Access Key assignment was found in a JavaScript file. Combined with an Access Key ID this grants full AWS API access. Rotate immediately.',
  },
  {
    id:       'stripe.secret_live',
    name:     'Stripe Live Secret Key',
    pattern:  /sk_live_[A-Za-z0-9]{20,}/g,
    severity: 'critical',
    cwe:      'CWE-312',
    detail:   'A Stripe live secret key (sk_live_...) was found. This key has full API access to a live Stripe account including charges, refunds, and payouts. Revoke immediately in the Stripe dashboard.',
  },
  {
    id:       'stripe.restricted_live',
    name:     'Stripe Live Restricted Key',
    pattern:  /rk_live_[A-Za-z0-9]{20,}/g,
    severity: 'critical',
    cwe:      'CWE-312',
    detail:   'A Stripe live restricted key (rk_live_...) was found. While scoped, live restricted keys still access real payment data. Revoke and audit access scope.',
  },
  {
    id:       'google.api_key',
    name:     'Google API Key',
    pattern:  /AIza[A-Za-z0-9\-_]{35}/g,
    severity: 'high',
    cwe:      'CWE-312',
    detail:   'A Google API key (AIza...) was found. Depending on enabled APIs this may allow unauthorized Maps, Translate, Vision, or other billable API calls. Restrict key scopes and rotate in Google Cloud Console.',
  },
  {
    id:       'firebase.config',
    name:     'Firebase Config Object',
    // Matches apiKey inside a Firebase initializeApp config block
    pattern:  /apiKey["'\s]*:["'\s]*(AIza[A-Za-z0-9\-_]{35})/g,
    severity: 'high',
    cwe:      'CWE-312',
    detail:   'A Firebase config object with an API key was found in client-side JavaScript. If Firebase Security Rules are misconfigured, this can allow unauthorized read/write to Firestore or Realtime Database. Audit Firebase Security Rules immediately.',
  },
  {
    id:       'github.pat_classic',
    name:     'GitHub Personal Access Token (Classic)',
    pattern:  /gh[pousr]_[A-Za-z0-9]{36,}/g,
    severity: 'critical',
    cwe:      'CWE-312',
    detail:   'A GitHub personal access token was found (ghp_/gho_/ghu_/ghs_/ghr_ prefix). Depending on scopes this may allow repo access, code read/write, or org-level operations. Revoke immediately at github.com/settings/tokens.',
  },
  {
    id:       'github.fine_grained',
    name:     'GitHub Fine-Grained Personal Access Token',
    pattern:  /github_pat_[A-Za-z0-9_]{80,}/g,
    severity: 'critical',
    cwe:      'CWE-312',
    detail:   'A GitHub fine-grained personal access token was found. These tokens have explicit repo and org permission scopes. Revoke immediately at github.com/settings/tokens.',
  },
  {
    id:       'slack.token',
    name:     'Slack API Token',
    pattern:  /xox[bparo]-[A-Za-z0-9\-]{10,}/g,
    severity: 'high',
    cwe:      'CWE-312',
    detail:   'A Slack API token was found (xoxb-/xoxp-/xoxa-/xoxr- prefix). This may allow reading messages, posting to channels, or accessing workspace data. Revoke at api.slack.com/apps.',
  },
  {
    id:       'openai.key',
    name:     'OpenAI API Key',
    pattern:  /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,
    severity: 'high',
    cwe:      'CWE-312',
    detail:   'An OpenAI API key was found. This enables unauthorized calls to GPT/Embeddings/Whisper APIs and incurs billing charges. Revoke at platform.openai.com/api-keys.',
  },
  {
    id:       'openai.key_v2',
    name:     'OpenAI API Key (new format)',
    // New format introduced 2024: sk-proj-... or sk-svcacct-...
    pattern:  /sk-(?:proj|svcacct)-[A-Za-z0-9\-_]{40,}/g,
    severity: 'high',
    cwe:      'CWE-312',
    detail:   'An OpenAI API key (new project/service-account format) was found. Revoke at platform.openai.com/api-keys.',
  },
  {
    id:       'huggingface.token',
    name:     'HuggingFace API Token',
    pattern:  /hf_[A-Za-z0-9]{30,}/g,
    severity: 'high',
    cwe:      'CWE-312',
    detail:   'A HuggingFace API token was found. This may allow model downloads, dataset access, or inference API calls. Revoke at huggingface.co/settings/tokens.',
  },
  {
    id:       'replicate.token',
    name:     'Replicate API Token',
    pattern:  /r8_[A-Za-z0-9]{36,}/g,
    severity: 'high',
    cwe:      'CWE-312',
    detail:   'A Replicate API token was found. This enables unauthorized model inference calls billed to the account owner. Revoke at replicate.com/account/api-tokens.',
  },
  {
    id:       'generic.bearer',
    name:     'Hardcoded Bearer Token in JS',
    // Matches Bearer <token> inside JS string literals (quotes around it)
    pattern:  /["'`]Bearer\s+([A-Za-z0-9\-._~+/]{20,})["'`]/g,
    severity: 'high',
    cwe:      'CWE-798',
    detail:   'A hardcoded Bearer token was found inside a JavaScript string literal. Hardcoded tokens are exposed to anyone who views the source. Move to server-side auth flows.',
  },
  {
    id:       'generic.pem_private_key',
    name:     'Private Key (PEM Block)',
    pattern:  /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
    cwe:      'CWE-321',
    detail:   'A PEM private key block header was found in a JavaScript file. Private keys must never be client-side. Revoke and regenerate the key pair immediately.',
  },
  {
    id:       'generic.secret_assignment',
    name:     'Hardcoded Secret Variable Assignment',
    // Matches: const/let/var SECRET_KEY = "...<long value>..."
    // Variable names containing: secret, password, passwd, api_key, apikey, token, auth
    pattern:  /(?:const|let|var)\s+[A-Za-z0-9_]*(?:secret|password|passwd|api_key|apikey|auth_token|access_token)[A-Za-z0-9_]*\s*=\s*["'`]([A-Za-z0-9\-._~+/=]{16,})["'`]/gi,
    severity: 'high',
    cwe:      'CWE-798',
    detail:   'A JavaScript variable with a security-sensitive name is assigned a hardcoded string value. Hardcoded credentials are exposed to all users who can access the JavaScript file.',
  },
];

// Max bytes to read per JS file (avoid reading 10MB bundles in full)
const MAX_JS_BYTES = 512_000; // 512 KB

// Max number of JS files to scan per target (avoid runaway on huge SPAs)
const MAX_JS_FILES = 30;

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Scan all .js assets discovered in the SiteModel for hardcoded secrets.
 *
 * @param {Object} opts
 * @param {Object}   opts.ctx           - EngineContext
 * @param {Object}   opts.target        - Target instance
 * @param {import('../siteModel.js').SiteModel} opts.siteModel
 * @param {string}   opts.baseUrl
 * @param {Object}   opts.fetchAdapter
 */
export async function runJsSecretScan({ ctx, target, siteModel, baseUrl, fetchAdapter }) {
  // Collect all JS URLs from SiteModel assets + any .js endpoints
  const jsUrls = collectJsUrls(siteModel, baseUrl);

  if (jsUrls.length === 0) {
    ctx.log('JsSecretScan: no JavaScript assets found in SiteModel — skipping.');
    return;
  }

  const toScan = jsUrls.slice(0, MAX_JS_FILES);
  ctx.log(`JsSecretScan: scanning ${toScan.length} JS file(s) (capped at ${MAX_JS_FILES}).`);

  // Track which (pattern id + url) pairs already fired to avoid duplicate findings
  const fired = new Set();

  for (const jsUrl of toScan) {
    await scanJsFile({ ctx, target, jsUrl, fired, fetchAdapter });
  }

  ctx.log(`JsSecretScan: complete. Unique findings: ${[...fired].length}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// SCAN A SINGLE JS FILE
// ─────────────────────────────────────────────────────────────────────────────

async function scanJsFile({ ctx, target, jsUrl, fired, fetchAdapter }) {
  ctx.log(`JsSecretScan: fetching ${jsUrl}`);

  let body;
  try {
    const res = await httpGetText({ fetchAdapter, url: jsUrl });
    if (res.status !== 200) {
      ctx.log(`JsSecretScan: skipping ${jsUrl} (status ${res.status})`);
      return;
    }
    // Truncate to MAX_JS_BYTES to avoid scanning 5MB webpack bundles in full
    body = res.body.slice(0, MAX_JS_BYTES);
  } catch (e) {
    ctx.log(`JsSecretScan: fetch error for ${jsUrl}: ${e.message || e}`);
    return;
  }

  for (const rule of SECRET_PATTERNS) {
    const key = `${rule.id}::${jsUrl}`;
    if (fired.has(key)) continue;

    // Reset lastIndex for global regex between files
    rule.pattern.lastIndex = 0;
    const match = rule.pattern.exec(body);
    if (!match) continue;

    fired.add(key);

    // Redact the matched value — show first 6 chars then ****
    const rawMatch  = match[0];
    const redacted  = rawMatch.slice(0, 6) + '****[redacted]';
    const lineNum   = getLineNumber(body, match.index);
    const snippet   = getSnippet(body, match.index);

    const finding = new Finding({
      projectId:        ctx.project.id,
      scanJobId:        ctx.job.id,
      targetId:         target.id,
      moduleId:         'exposure.js.secrets',
      title:            `Hardcoded ${rule.name} Found in JavaScript Asset`,
      shortDescription: `Pattern "${rule.id}" matched in ${jsUrl} at line ~${lineNum}: ${redacted}`,
      detailedDescription:
        `${rule.detail}\n\n` +
        `File: ${jsUrl}\n` +
        `Approximate line: ${lineNum}\n` +
        `Matched pattern: ${rule.id}\n` +
        `Redacted match: ${redacted}`,
      severity: rule.severity,
      category: 'exposure',
      owaspTag: 'A02-Cryptographic-Failures',
      cweTag:   rule.cwe,
    });

    const evidence = new Evidence({
      findingId:              finding.id,
      url:                    jsUrl,
      method:                 'GET',
      responseStatus:        200,
      responseHeadersSnippet: '',
      responseBodySnippet:   snippet,
      matchedPattern:        `${rule.id}: ${redacted} (line ~${lineNum})`,
    });

    ctx.addFinding(finding);
    ctx.addEvidence(evidence);
    ctx.log(`🔴 ${rule.severity.toUpperCase()}: ${rule.name} in ${jsUrl} (line ~${lineNum})`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// JS URL COLLECTION
// ─────────────────────────────────────────────────────────────────────────────

function collectJsUrls(siteModel, baseUrl) {
  const urls = new Set();
  const base = baseUrl.replace(/\/$/, '');

  // Pull from SiteModel assets (script src tags found by crawler)
  if (siteModel.assets) {
    for (const asset of siteModel.assets) {
      if (typeof asset === 'string' && asset.endsWith('.js')) {
        urls.add(resolveUrl(asset, base));
      } else if (asset?.url && asset.url.endsWith('.js')) {
        urls.add(resolveUrl(asset.url, base));
      }
    }
  }

  // Also check endpoints that look like JS files
  const endpoints = siteModel.getAllEndpoints?.() || [];
  for (const ep of endpoints) {
    const u = ep.url || ep;
    if (typeof u === 'string' && u.endsWith('.js')) {
      urls.add(resolveUrl(u, base));
    }
  }

  return [...urls];
}

function resolveUrl(url, base) {
  if (/^https?:\/\//i.test(url)) return url;
  if (url.startsWith('//')) return 'https:' + url;
  if (url.startsWith('/')) return base + url;
  return base + '/' + url;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function getLineNumber(body, index) {
  return body.slice(0, index).split('\n').length;
}

function getSnippet(body, index) {
  const start = Math.max(0, index - 80);
  const end   = Math.min(body.length, index + 160);
  return body.slice(start, end).replace(/\r?\n/g, ' ');
}
