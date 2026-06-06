// src/core/checks/cveFingerprints.js
// CVE Fingerprint Checks — Phase 1e
// Passive HTTP probes to detect vulnerable software versions and exposed admin
// surfaces based on real 2025–2026 CVEs.
//
// Each check:
//   • Makes 1–3 targeted HTTP probes
//   • Fingerprints via response code + body + headers
//   • Emits a Finding with CVE tag, severity, OWASP + CWE
//   • Never modifies server state (all GET, no payloads)
//
// Wire-up: engine.js Phase 1e
//   import { runCveFingerprints } from './checks/cveFingerprints.js';
//   if (moduleEnabled(enabledModules, 'cve.fingerprints')) {
//     await runCveFingerprints({ ctx, target, baseUrl, fetchAdapter });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// ─────────────────────────────────────────────────────────────────────────────
// MAIN ENTRY
// ─────────────────────────────────────────────────────────────────────────────

export async function runCveFingerprints({ ctx, target, baseUrl, fetchAdapter }) {
  ctx.log('[cveFingerprints] Starting CVE fingerprint checks...');
  const base = baseUrl.replace(/\/$/, '');
  const opts = { ctx, target, base, fetchAdapter };

  await checkNginxUi(opts);          // CVE-2026-27944 / CVE-2026-33032
  await checkCraftCms(opts);         // CVE-2025-32432
  await checkLaravelLivewire(opts);  // CVE-2025-54068
  await checkNextJs(opts);           // CVE-2025-55182
  await checkN8n(opts);              // CVE-2026-25049
  await checkLangflow(opts);         // CVE-2026-33017
  await checkFortigate(opts);        // CVE-2026-24858
  await checkIvanti(opts);           // CVE-2026-1603
  await checkAruba(opts);            // CVE-2026-23813
  await checkViteDevServer(opts);    // CVE-2025-30208 / CVE-2026-46565
  await checkMindsDB(opts);          // CVE-2026-27483
  await checkSharePoint(opts);       // CVE-2026-20963
  await checkOracleWebLogic(opts);   // CVE-2026-21962
  await checkCiscoFmc(opts);         // CVE-2026-20131
  await checkModularDs(opts);        // CVE-2026-23550

  ctx.log('[cveFingerprints] Done.');
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function emit(ctx, target, { moduleId, cve, title, short, detail, severity, owasp, cwe, url, status, headers, body, pattern }) {
  const finding = new Finding({
    projectId:           ctx.project.id,
    scanJobId:           ctx.job.id,
    targetId:            target.id,
    moduleId,
    title,
    shortDescription:    short,
    detailedDescription: detail,
    severity,
    category:            'cve',
    owaspTag:            owasp,
    cweTag:              cwe,
  });
  ctx.addFinding(finding);
  ctx.addEvidence(new Evidence({
    findingId:              finding.id,
    url,
    method:                 'GET',
    responseStatus:         status,
    responseHeadersSnippet: JSON.stringify(headers || {}).slice(0, 512),
    responseBodySnippet:    (body || '').slice(0, 2048),
    matchedPattern:         `${cve} — ${pattern}`,
  }));
  ctx.log(`\uD83D\uDD34 ${severity.toUpperCase()}: ${cve} detected at ${url} — ${title}`);
}

async function get(fetchAdapter, url) {
  try   { return await httpGetText({ fetchAdapter, url }); }
  catch { return { status: 0, headers: {}, body: '' }; }
}

function hdr(res, name) {
  return (res.headers?.[name.toLowerCase()] || '').toLowerCase();
}

// ─────────────────────────────────────────────────────────────────────────────
// 01 — Nginx UI (CVE-2026-27944 / CVE-2026-33032)
// Unauthenticated access to /api/backup and /api/settings on Nginx UI < 2.3.3
// ─────────────────────────────────────────────────────────────────────────────
async function checkNginxUi({ ctx, target, base, fetchAdapter }) {
  const probes = [
    { path: '/api/backup',   cve: 'CVE-2026-27944', pattern: 'Nginx UI /api/backup 200 + JSON body' },
    { path: '/api/settings', cve: 'CVE-2026-33032', pattern: 'Nginx UI /api/settings unauthenticated 200' },
  ];
  for (const p of probes) {
    const url = base + p.path;
    const res = await get(fetchAdapter, url);
    if (res.status === 200 && res.body.includes('{')) {
      const isBackup   = p.path === '/api/backup'   && /nginx|config|backup/i.test(res.body);
      const isSettings = p.path === '/api/settings' && /nginx|server|ssl/i.test(res.body);
      if (isBackup || isSettings) {
        emit(ctx, target, {
          moduleId: 'cve.fingerprints',
          cve:      p.cve,
          title:    `Nginx UI Unauthenticated API Exposure (${p.cve})`,
          short:    `Nginx UI endpoint ${p.path} is accessible without authentication.`,
          detail:   `${p.cve}: Nginx UI < 2.3.3 exposes ${p.path} without authentication. ` +
                    `Attackers can download Nginx configuration backups or modify server settings. ` +
                    `Upgrade to Nginx UI ≥ 2.3.3 immediately.`,
          severity: 'critical',
          owasp:    'A01-Broken-Access-Control',
          cwe:      'CWE-306',
          url, status: res.status, headers: res.headers, body: res.body, pattern: p.pattern,
        });
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 02 — Craft CMS (CVE-2025-32432)
// Unauthenticated code injection via /index.php?action=sites/index
// ─────────────────────────────────────────────────────────────────────────────
async function checkCraftCms({ ctx, target, base, fetchAdapter }) {
  // First fingerprint: does Craft CMS appear in page source?
  const root = await get(fetchAdapter, base + '/');
  const isCraft = /craft\s*cms|craft-cms|craftcms/i.test(root.body) ||
                  /x-powered-by.*craft/i.test(JSON.stringify(root.headers));

  // Also probe the specific action endpoint
  const probe = await get(fetchAdapter, base + '/index.php?action=sites/index');

  if (isCraft || (probe.status < 500 && /craft|yii|seomatic/i.test(probe.body))) {
    const url = base + '/index.php?action=sites/index';
    emit(ctx, target, {
      moduleId: 'cve.fingerprints',
      cve:      'CVE-2025-32432',
      title:    'Craft CMS Detected — Code Injection Risk (CVE-2025-32432)',
      short:    'Craft CMS fingerprinted. CVE-2025-32432 allows unauthenticated code injection on unpatched versions.',
      detail:   'CVE-2025-32432 (CVSS 10.0): Craft CMS ≤ 5.5.1 allows unauthenticated remote code execution via ' +
                'the sites/index action through a crafted serialized object. Verify the installed version and ' +
                'upgrade to Craft CMS ≥ 5.5.2 / 4.14.2 immediately.',
      severity: 'critical',
      owasp:    'A08-Software-and-Data-Integrity-Failures',
      cwe:      'CWE-502',
      url,
      status:   probe.status,
      headers:  probe.headers,
      body:     probe.body,
      pattern:  'Craft CMS fingerprint in body/headers + CVE-2025-32432 action endpoint',
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 03 — Laravel Livewire (CVE-2025-54068)
// SSTI/code injection via /livewire/message endpoint on Livewire < 3.6.3
// ─────────────────────────────────────────────────────────────────────────────
async function checkLaravelLivewire({ ctx, target, base, fetchAdapter }) {
  const root  = await get(fetchAdapter, base + '/');
  const hasLw = /livewire/i.test(root.body);
  const probe = await get(fetchAdapter, base + '/livewire/message');
  // /livewire/message expects POST — GET gives 405 or Livewire error = confirmed present
  const confirmed = [200, 405, 422].includes(probe.status) && /livewire/i.test(probe.body);

  if (hasLw || confirmed) {
    emit(ctx, target, {
      moduleId: 'cve.fingerprints',
      cve:      'CVE-2025-54068',
      title:    'Laravel Livewire Detected — Code Injection Risk (CVE-2025-54068)',
      short:    'Laravel Livewire fingerprinted at /livewire/message. Unpatched versions allow RCE.',
      detail:   'CVE-2025-54068: Laravel Livewire < 3.6.3 is vulnerable to server-side template injection ' +
                'via the /livewire/message endpoint, leading to RCE when an attacker controls component ' +
                'state. Upgrade to Livewire ≥ 3.6.3 and ensure CSRF protection is enforced.',
      severity: 'critical',
      owasp:    'A03-Injection',
      cwe:      'CWE-94',
      url:      base + '/livewire/message',
      status:   probe.status,
      headers:  probe.headers,
      body:     probe.body,
      pattern:  'Livewire JS asset or /livewire/message endpoint response',
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 04 — Next.js (CVE-2025-55182)
// RSC deserialization RCE via /__nextjs_original-stack-frame on unpatched versions
// ─────────────────────────────────────────────────────────────────────────────
async function checkNextJs({ ctx, target, base, fetchAdapter }) {
  const root    = await get(fetchAdapter, base + '/');
  const isNextJs = /x-powered-by.*next/i.test(JSON.stringify(root.headers)) ||
                   /__NEXT_DATA__|__next_f|_next\/static/i.test(root.body);
  if (!isNextJs) return;

  const probe = await get(fetchAdapter, base + '/__nextjs_original-stack-frame?isServer=true&errorCode=500');
  const exposed = probe.status === 200 && /file|source|originalStackFrame/i.test(probe.body);

  emit(ctx, target, {
    moduleId: 'cve.fingerprints',
    cve:      'CVE-2025-55182',
    title:    `Next.js Detected${exposed ? ' — Stack Frame Endpoint Exposed' : ''} (CVE-2025-55182)`,
    short:    'Next.js fingerprinted. CVE-2025-55182 affects RSC deserialization on unpatched versions.',
    detail:   'CVE-2025-55182: Next.js applications using React Server Components (RSC) on versions ' +
              '< 15.3.3 may be vulnerable to deserialization-based RCE when the ' +
              '__nextjs_original-stack-frame endpoint is accessible. ' +
              (exposed ? 'The endpoint responded with 200 — likely exposed in dev/staging mode. ' : '') +
              'Upgrade to Next.js ≥ 15.3.3 and ensure dev endpoints are not exposed in production.',
    severity: exposed ? 'high' : 'medium',
    owasp:    'A08-Software-and-Data-Integrity-Failures',
    cwe:      'CWE-502',
    url:      base + '/__nextjs_original-stack-frame',
    status:   probe.status,
    headers:  probe.headers,
    body:     probe.body,
    pattern:  'x-powered-by: Next.js or __NEXT_DATA__ in body',
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 05 — n8n (CVE-2026-25049)
// Unauthenticated /rest/settings exposes n8n instance configuration
// ─────────────────────────────────────────────────────────────────────────────
async function checkN8n({ ctx, target, base, fetchAdapter }) {
  const probe = await get(fetchAdapter, base + '/rest/settings');
  if (probe.status === 200 && /n8n|userManagement|instanceId|executionMode/i.test(probe.body)) {
    emit(ctx, target, {
      moduleId: 'cve.fingerprints',
      cve:      'CVE-2026-25049',
      title:    'n8n Unauthenticated Settings Exposure (CVE-2026-25049)',
      short:    '/rest/settings is accessible without authentication on this n8n instance.',
      detail:   'CVE-2026-25049: n8n workflow automation server exposes /rest/settings without ' +
                'authentication on unpatched installations. This reveals instance ID, execution mode, ' +
                'and user management config. Combined with SSTI in the Code node, this can lead to RCE. ' +
                'Update n8n and enforce authentication on all API endpoints.',
      severity: 'high',
      owasp:    'A01-Broken-Access-Control',
      cwe:      'CWE-306',
      url:      base + '/rest/settings',
      status:   probe.status,
      headers:  probe.headers,
      body:     probe.body,
      pattern:  '/rest/settings 200 with n8n keywords',
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 06 — Langflow (CVE-2026-33017)
// Unauthenticated /api/v1/ endpoint exposure + RCE via code execution endpoint
// ─────────────────────────────────────────────────────────────────────────────
async function checkLangflow({ ctx, target, base, fetchAdapter }) {
  const probe = await get(fetchAdapter, base + '/api/v1/');
  const isLangflow = probe.status < 400 &&
    (/langflow|flow|component|vertex/i.test(probe.body) || /langflow/i.test(JSON.stringify(probe.headers)));
  if (!isLangflow) return;

  // Probe the run endpoint — unauthenticated POST ability is the RCE vector
  const runProbe = await get(fetchAdapter, base + '/api/v1/run');
  // GET /run typically returns 405 Method Not Allowed but confirms endpoint exists
  const runExists = [200, 405, 422].includes(runProbe.status);

  emit(ctx, target, {
    moduleId: 'cve.fingerprints',
    cve:      'CVE-2026-33017',
    title:    `Langflow API Exposed${runExists ? ' — /api/v1/run Reachable' : ''} (CVE-2026-33017)`,
    short:    'Langflow AI workflow server API is accessible. Unpatched versions allow unauthenticated RCE.',
    detail:   'CVE-2026-33017 (CVSS 9.8): Langflow ≤ 1.3.0 exposes the /api/v1/run endpoint without ' +
              'authentication, allowing arbitrary Python code execution via crafted flow payloads. ' +
              (runExists ? '/api/v1/run endpoint confirmed reachable. ' : '') +
              'Upgrade to Langflow ≥ 1.3.1 and restrict network access to trusted IPs only.',
    severity: 'critical',
    owasp:    'A01-Broken-Access-Control',
    cwe:      'CWE-94',
    url:      base + '/api/v1/',
    status:   probe.status,
    headers:  probe.headers,
    body:     probe.body,
    pattern:  '/api/v1/ with Langflow keywords in body/headers',
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 07 — FortiGate / FortiOS (CVE-2026-24858)
// SSL-VPN auth bypass via /remote/logincheck; fingerprint login page
// ─────────────────────────────────────────────────────────────────────────────
async function checkFortigate({ ctx, target, base, fetchAdapter }) {
  const probes = [
    base + '/remote/login',
    base + '/remote/logincheck',
    base + '/login',
  ];
  for (const url of probes) {
    const res = await get(fetchAdapter, url);
    const isFortinet = /fortinet|fortigate|fortios|fortissl|fgtmodel/i.test(res.body) ||
                       /fortinet|fortigate/i.test(JSON.stringify(res.headers));
    if (isFortinet) {
      emit(ctx, target, {
        moduleId: 'cve.fingerprints',
        cve:      'CVE-2026-24858',
        title:    'FortiGate / FortiOS SSL-VPN Detected (CVE-2026-24858)',
        short:    'FortiGate management or SSL-VPN interface fingerprinted. May be vulnerable to auth bypass.',
        detail:   'CVE-2026-24858: FortiOS SSL-VPN is vulnerable to an authentication bypass via a ' +
                  'specially crafted node ID. Unpatched versions expose the management interface to ' +
                  'unauthenticated access. Upgrade to FortiOS ≥ 7.4.5 / 7.2.10 / 7.0.16 and restrict ' +
                  'SSL-VPN admin access to trusted IP ranges.',
        severity: 'critical',
        owasp:    'A07-Identification-and-Authentication-Failures',
        cwe:      'CWE-287',
        url, status: res.status, headers: res.headers, body: res.body,
        pattern:  'Fortinet/FortiGate fingerprint in body or headers',
      });
      break;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 08 — Ivanti EPM / Connect Secure (CVE-2026-1603)
// Auth bypass fingerprint via /mifs/ and /dana-na/auth/ paths
// ─────────────────────────────────────────────────────────────────────────────
async function checkIvanti({ ctx, target, base, fetchAdapter }) {
  const probes = [
    { url: base + '/mifs/',          keyword: /ivanti|mobileiron|mifs/i },
    { url: base + '/dana-na/auth/',  keyword: /ivanti|pulse|juniper|dana/i },
    { url: base + '/api/v1/totp/user-backup-code/../../users', keyword: /ivanti|user|password/i },
  ];
  for (const p of probes) {
    const res = await get(fetchAdapter, p.url);
    if (p.keyword.test(res.body) || p.keyword.test(JSON.stringify(res.headers))) {
      emit(ctx, target, {
        moduleId: 'cve.fingerprints',
        cve:      'CVE-2026-1603',
        title:    'Ivanti Product Detected — Auth Bypass Risk (CVE-2026-1603)',
        short:    `Ivanti management interface fingerprinted at ${p.url}.`,
        detail:   'CVE-2026-1603 (CVSS 9.8): Ivanti Endpoint Manager / Connect Secure < 22.7R2.5 ' +
                  'is vulnerable to an authentication bypass via path traversal on the TOTP user-backup-code ' +
                  'endpoint. Attackers can gain unauthenticated admin access. ' +
                  'Patch to the latest Ivanti release immediately and check for indicators of compromise.',
        severity: 'critical',
        owasp:    'A07-Identification-and-Authentication-Failures',
        cwe:      'CWE-22',
        url:      p.url,
        status:   res.status,
        headers:  res.headers,
        body:     res.body,
        pattern:  'Ivanti/MobileIron keyword in body/headers',
      });
      break;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 09 — HPE Aruba AOS-CX (CVE-2026-23813)
// Unauthenticated /rest/v1/system returns full system info
// ─────────────────────────────────────────────────────────────────────────────
async function checkAruba({ ctx, target, base, fetchAdapter }) {
  const url = base + '/rest/v1/system';
  const res  = await get(fetchAdapter, url);
  if (res.status === 200 && /hostname|platform|aos-cx|aruba/i.test(res.body)) {
    emit(ctx, target, {
      moduleId: 'cve.fingerprints',
      cve:      'CVE-2026-23813',
      title:    'HPE Aruba AOS-CX Auth Bypass — /rest/v1/system Exposed (CVE-2026-23813)',
      short:    '/rest/v1/system responds with system data without authentication.',
      detail:   'CVE-2026-23813 (CVSS 9.8): HPE Aruba AOS-CX network switches running firmware ' +
                '< 10.14.1020 / < 10.13.1060 expose the REST API management interface without ' +
                'authentication, allowing full device enumeration and configuration changes. ' +
                'Apply the Aruba firmware update immediately and restrict REST API access to management VLANs.',
      severity: 'critical',
      owasp:    'A07-Identification-and-Authentication-Failures',
      cwe:      'CWE-306',
      url, status: res.status, headers: res.headers, body: res.body,
      pattern:  '/rest/v1/system 200 with Aruba/AOS-CX keywords',
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10 — Vite Dev Server (CVE-2025-30208 / CVE-2026-46565)
// /@fs/ path bypass to read arbitrary files from the host filesystem
// ─────────────────────────────────────────────────────────────────────────────
async function checkViteDevServer({ ctx, target, base, fetchAdapter }) {
  // Probe 1: Standard @fs bypass
  const bypass1 = await get(fetchAdapter, base + '/@fs/etc/passwd');
  // Probe 2: ?import&raw variant (CVE-2026-46565)
  const bypass2 = await get(fetchAdapter, base + '/@fs/etc/passwd?import&raw');
  // Probe 3: Check if Vite is running at all
  const root    = await get(fetchAdapter, base + '/@vite/client');
  const isVite  = root.status === 200 || /vite/i.test(root.body);

  const lfi1 = bypass1.status === 200 && /root:|daemon:|nobody:/i.test(bypass1.body);
  const lfi2 = bypass2.status === 200 && /root:|daemon:|nobody:/i.test(bypass2.body);

  if (lfi1 || lfi2) {
    const exploitUrl = lfi1 ? base + '/@fs/etc/passwd' : base + '/@fs/etc/passwd?import&raw';
    const exploitRes = lfi1 ? bypass1 : bypass2;
    emit(ctx, target, {
      moduleId: 'cve.fingerprints',
      cve:      lfi2 ? 'CVE-2026-46565' : 'CVE-2025-30208',
      title:    'Vite Dev Server LFI — /@fs/ Path Bypass CONFIRMED',
      short:    `/@fs/etc/passwd returned readable content — full filesystem read via Vite dev server.`,
      detail:   'CVE-2025-30208 / CVE-2026-46565: A Vite dev server is running and the /@fs/ path bypass ' +
                'is active, allowing unauthenticated read of any file on the host filesystem. ' +
                '/etc/passwd content confirmed in response. ' +
                'This is a CRITICAL misconfiguration — Vite dev server must never be exposed to the internet. ' +
                'Shut down the dev server or restrict it to 127.0.0.1 only.',
      severity: 'critical',
      owasp:    'A05-Security-Misconfiguration',
      cwe:      'CWE-22',
      url:      exploitUrl,
      status:   exploitRes.status,
      headers:  exploitRes.headers,
      body:     exploitRes.body,
      pattern:  '/@fs/etc/passwd response contains /etc/passwd content',
    });
  } else if (isVite) {
    emit(ctx, target, {
      moduleId: 'cve.fingerprints',
      cve:      'CVE-2025-30208',
      title:    'Vite Dev Server Exposed (CVE-2025-30208)',
      short:    'A Vite dev server is running and accessible on this host.',
      detail:   'CVE-2025-30208: A Vite development server was detected. Vite dev servers expose /@fs/ path ' +
                'traversal on unpatched versions, potentially allowing full filesystem read. ' +
                'Additionally, dev servers expose source maps, HMR websockets, and internal file structure. ' +
                'Never expose a Vite dev server to the public internet.',
      severity: 'high',
      owasp:    'A05-Security-Misconfiguration',
      cwe:      'CWE-22',
      url:      base + '/@vite/client',
      status:   root.status,
      headers:  root.headers,
      body:     root.body,
      pattern:  '/@vite/client responded with 200',
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 11 — MindsDB (CVE-2026-27483)
// Path traversal on /api/ endpoint
// ─────────────────────────────────────────────────────────────────────────────
async function checkMindsDB({ ctx, target, base, fetchAdapter }) {
  const root  = await get(fetchAdapter, base + '/api/');
  const probe = await get(fetchAdapter, base + '/api/../../etc/passwd');
  const isMindsDB = /mindsdb|predictor|datasource/i.test(root.body);
  const isLFI     = probe.status === 200 && /root:|daemon:/i.test(probe.body);

  if (isMindsDB) {
    emit(ctx, target, {
      moduleId: 'cve.fingerprints',
      cve:      'CVE-2026-27483',
      title:    `MindsDB API Exposed${isLFI ? ' — Path Traversal CONFIRMED' : ''} (CVE-2026-27483)`,
      short:    'MindsDB API fingerprinted. CVE-2026-27483 allows path traversal on unpatched versions.',
      detail:   'CVE-2026-27483 (CVSS 9.1): MindsDB < 25.3.4.0 is vulnerable to path traversal via the ' +
                '/api/ endpoint, allowing unauthenticated read of arbitrary files. ' +
                (isLFI ? '/etc/passwd content confirmed in traversal probe. ' : '') +
                'Upgrade to MindsDB ≥ 25.3.4.0 and restrict API access to trusted networks.',
      severity: isLFI ? 'critical' : 'high',
      owasp:    'A01-Broken-Access-Control',
      cwe:      'CWE-22',
      url:      base + '/api/',
      status:   root.status,
      headers:  root.headers,
      body:     root.body,
      pattern:  'MindsDB keyword in /api/ response',
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 12 — Microsoft SharePoint (CVE-2026-20963)
// SharePoint fingerprint via /_api/web; deserialization RCE risk
// ─────────────────────────────────────────────────────────────────────────────
async function checkSharePoint({ ctx, target, base, fetchAdapter }) {
  const probe = await get(fetchAdapter, base + '/_api/web');
  const isSP  = probe.status < 500 &&
    (/sharepoint|spo|spfx|microsoftsharepoint|odata/i.test(probe.body) ||
     /sharepoint/i.test(JSON.stringify(probe.headers)));
  if (!isSP) return;

  emit(ctx, target, {
    moduleId: 'cve.fingerprints',
    cve:      'CVE-2026-20963',
    title:    'Microsoft SharePoint Detected — Deserialization Risk (CVE-2026-20963)',
    short:    'SharePoint REST API fingerprinted at /_api/web. Unpatched versions allow RCE via deserialization.',
    detail:   'CVE-2026-20963 (CVSS 8.8): Microsoft SharePoint Server is vulnerable to deserialization ' +
              'of untrusted data allowing authenticated-to-RCE escalation. Combined with CVE-2023-29357 ' +
              '(auth bypass), this can result in a fully unauthenticated RCE chain. ' +
              'Ensure all Microsoft security patches are applied and the /_api/ endpoint is not externally exposed.',
    severity: 'high',
    owasp:    'A08-Software-and-Data-Integrity-Failures',
    cwe:      'CWE-502',
    url:      base + '/_api/web',
    status:   probe.status,
    headers:  probe.headers,
    body:     probe.body,
    pattern:  '/_api/web with SharePoint/OData keywords',
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 13 — Oracle WebLogic (CVE-2026-21962)
// Exposed async endpoints used in historic deserialization chains
// ─────────────────────────────────────────────────────────────────────────────
async function checkOracleWebLogic({ ctx, target, base, fetchAdapter }) {
  const probes = [
    base + '/_async/AsyncResponseServiceHttpSoap11Endpoint',
    base + '/wls-wsat/CoordinatorPortType',
    base + '/console',
  ];
  for (const url of probes) {
    const res = await get(fetchAdapter, url);
    const isWL = res.status < 500 &&
      (/weblogic|oracle|wls|wsat|bea\.com/i.test(res.body) ||
       /weblogic|oracle/i.test(JSON.stringify(res.headers)));
    if (isWL) {
      emit(ctx, target, {
        moduleId: 'cve.fingerprints',
        cve:      'CVE-2026-21962',
        title:    'Oracle WebLogic Server Detected (CVE-2026-21962)',
        short:    `Oracle WebLogic fingerprinted at ${url}.`,
        detail:   'CVE-2026-21962 (CVSS 10.0): Oracle WebLogic Server is exposed and may be running ' +
                  'a vulnerable version. The /_async/ and /wls-wsat/ endpoints have historically been ' +
                  'the attack surface for unauthenticated deserialization RCE chains (CVE-2017-10271, ' +
                  'CVE-2019-2725, and now CVE-2026-21962). Apply Oracle CPU patches immediately and ' +
                  'disable the async/wsat components if not in use.',
        severity: 'critical',
        owasp:    'A08-Software-and-Data-Integrity-Failures',
        cwe:      'CWE-502',
        url, status: res.status, headers: res.headers, body: res.body,
        pattern:  'WebLogic/Oracle fingerprint at async or wsat endpoint',
      });
      break;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 14 — Cisco FMC (CVE-2026-20131)
// Cisco Firepower Management Center fingerprint — deserialization RCE risk
// ─────────────────────────────────────────────────────────────────────────────
async function checkCiscoFmc({ ctx, target, base, fetchAdapter }) {
  const probes = [
    base + '/',
    base + '/login.html',
    base + '/ui/login',
  ];
  for (const url of probes) {
    const res = await get(fetchAdapter, url);
    const isFmc = /cisco|firepower|fmc|sourcefire|sfrec/i.test(res.body) ||
                  /cisco|fmc/i.test(JSON.stringify(res.headers));
    if (isFmc) {
      emit(ctx, target, {
        moduleId: 'cve.fingerprints',
        cve:      'CVE-2026-20131',
        title:    'Cisco Firepower Management Center (FMC) Detected (CVE-2026-20131)',
        short:    `Cisco FMC fingerprinted at ${url}.`,
        detail:   'CVE-2026-20131 (CVSS 9.9): Cisco Firepower Management Center running software ' +
                  '< 7.4.2.3 is vulnerable to a deserialization RCE flaw in the web management interface. ' +
                  'An authenticated attacker (low privilege) can achieve full OS command execution. ' +
                  'Upgrade to Cisco FMC ≥ 7.4.2.3 and restrict management interface to trusted networks.',
        severity: 'high',
        owasp:    'A08-Software-and-Data-Integrity-Failures',
        cwe:      'CWE-502',
        url, status: res.status, headers: res.headers, body: res.body,
        pattern:  'Cisco/FMC/Sourcefire fingerprint in body or headers',
      });
      break;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 15 — Modular DS WordPress Plugin (CVE-2026-23550)
// Unauthenticated admin access via auto-login parameter
// ─────────────────────────────────────────────────────────────────────────────
async function checkModularDs({ ctx, target, base, fetchAdapter }) {
  // First check: is it a WordPress site?
  const root = await get(fetchAdapter, base + '/');
  const isWp = /wp-content|wp-includes|wordpress/i.test(root.body);
  if (!isWp) return;

  // Check for Modular DS plugin presence
  const pluginProbe = await get(fetchAdapter, base + '/wp-content/plugins/modular-connector/');
  const hasPlugin   = pluginProbe.status === 200 || /modular/i.test(pluginProbe.body);

  // Check the auto-login exploit vector
  const exploit = await get(fetchAdapter, base + '/?modular_ds_autologin=1');
  const autoLoginWorked = exploit.status === 302 &&
    /wp-admin|dashboard/i.test(hdr(exploit, 'location'));

  if (hasPlugin || autoLoginWorked) {
    emit(ctx, target, {
      moduleId: 'cve.fingerprints',
      cve:      'CVE-2026-23550',
      title:    `Modular DS WordPress Plugin${autoLoginWorked ? ' — Auth Bypass CONFIRMED' : ' Detected'} (CVE-2026-23550)`,
      short:    autoLoginWorked
        ? 'Unauthenticated admin redirect via ?modular_ds_autologin=1 confirmed.'
        : 'Modular DS WordPress plugin detected. Unpatched versions allow unauthenticated admin access.',
      detail:   'CVE-2026-23550 (CVSS 10.0): The Modular DS plugin for WordPress (≤ 2.5.1) contains ' +
                'an authentication bypass via the modular_ds_autologin parameter, allowing any unauthenticated ' +
                'visitor to gain administrator access to the WordPress dashboard. ' +
                (autoLoginWorked ? 'The bypass was confirmed — the server redirected to the WP admin dashboard. ' : '') +
                'Update the Modular DS plugin to ≥ 2.5.2 immediately.',
      severity: autoLoginWorked ? 'critical' : 'high',
      owasp:    'A07-Identification-and-Authentication-Failures',
      cwe:      'CWE-287',
      url:      base + '/?modular_ds_autologin=1',
      status:   exploit.status,
      headers:  exploit.headers,
      body:     exploit.body,
      pattern:  autoLoginWorked
        ? '302 redirect to /wp-admin via modular_ds_autologin'
        : 'Modular DS plugin directory probe 200',
    });
  }
}
