// src/core/policyRegistry.js
import { ScanPolicy } from './models.js';
import { moduleDefs } from './moduleRegistry.js';

function baseOverrides() {
  const overrides = {};
  for (const m of moduleDefs) {
    overrides[m.id] = { enabled: false, aggressiveness: 0, configOverride: null };
  }
  return overrides;
}

function cloneOverrides(o) {
  return JSON.parse(JSON.stringify(o));
}

// ── Normal: passive-only ────────────────────────────────────────────────────────────
const overridesNormal = baseOverrides();
[
  'exposure.env.direct',
  'exposure.env.variants',
  'exposure.backup.db_dumps',
  'exposure.backup.archives',
  'misconfig.dirlisting.generic',
  'vcs.git.exposed',
  'debug.stacktraces',
  'tls.headers.basic',
  'cookie.session.flags',
  'exposure.js.secrets',
  'exposure.sourcemap',
  'cve.fingerprints',
].forEach((id) => {
  if (overridesNormal[id]) {
    overridesNormal[id].enabled       = true;
    overridesNormal[id].aggressiveness = 1;
  }
});

// ── Aggressive: passive + full injection suite ────────────────────────────────────
const overridesAggressive = cloneOverrides(overridesNormal);
[
  'injection.sqli.basic',
  'injection.xss.reflected_basic',
  'injection.path_traversal.basic',
  'injection.cmdi.basic',
  'injection.ssti.basic',
  'injection.fileupload.detect',
].forEach((id) => {
  if (overridesAggressive[id]) {
    overridesAggressive[id].enabled       = true;
    overridesAggressive[id].aggressiveness = 1;
  }
});

// ── Extreme: all modules — full active suite ───────────────────────────────────────
const overridesExtreme = baseOverrides();
for (const m of moduleDefs) {
  overridesExtreme[m.id].enabled       = true;
  overridesExtreme[m.id].aggressiveness = m.clazz === 'active' ? 2 : 1;
}

export const scanPolicies = [
  new ScanPolicy({
    id: 'policy_normal',
    name: 'Normal (Passive Only)',
    description:
      'Low-impact passive scanning: exposed files, backups, .git, directory listings, TLS headers, ' +
      'cookie/session flags, JS secret scan, source map detection, and CVE fingerprints (2025–2026). ' +
      'Zero active probes — safe for production systems.',
    moduleOverrides: overridesNormal,
    globalLimits: {
      maxRequestsPerSecond:   3,
      maxParallelTargets:     2,
      maxScanDurationSeconds: 1200,
    },
  }),
  new ScanPolicy({
    id: 'policy_aggressive',
    name: 'Aggressive (Passive + Full Injection Suite)',
    description:
      'All passive checks (including CVE fingerprints) plus the full active injection suite: ' +
      'SQLi, reflected XSS, path traversal, OS command injection, SSTI, and dangerous file upload detection. ' +
      'Only use on systems you are authorized to test actively.',
    moduleOverrides: overridesAggressive,
    globalLimits: {
      maxRequestsPerSecond:   5,
      maxParallelTargets:     3,
      maxScanDurationSeconds: 2400,
    },
  }),
  new ScanPolicy({
    id: 'policy_extreme',
    name: 'Extreme (Full Suite — All Modules)',
    description:
      'Enables every module including path traversal, active fuzzing, deep injection, and all CVE fingerprints. ' +
      'Intended ONLY for authorized lab or dedicated pentest environments.',
    moduleOverrides: overridesExtreme,
    globalLimits: {
      maxRequestsPerSecond:   10,
      maxParallelTargets:     5,
      maxScanDurationSeconds: 7200,
    },
  }),
];

export const scanPolicyById = scanPolicies.reduce((acc, p) => {
  acc[p.id] = p;
  return acc;
}, {});
