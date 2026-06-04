// src/core/policyRegistry.js
import { ScanPolicy } from './models.js';
import { moduleDefs } from './moduleRegistry.js';

function baseOverrides() {
  const overrides = {};
  for (const m of moduleDefs) {
    overrides[m.id] = {
      enabled: false,
      aggressiveness: 0,
      configOverride: null,
    };
  }
  return overrides;
}

function cloneOverrides(overrides) {
  return JSON.parse(JSON.stringify(overrides));
}

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
].forEach((id) => {
  if (overridesNormal[id]) {
    overridesNormal[id].enabled = true;
    overridesNormal[id].aggressiveness = 1;
  }
});

const overridesAggressive = cloneOverrides(overridesNormal);
[
  'injection.sqli.basic',
  'injection.xss.reflected_basic',
].forEach((id) => {
  if (overridesAggressive[id]) {
    overridesAggressive[id].enabled = true;
    overridesAggressive[id].aggressiveness = 1;
  }
});

const overridesExtreme = baseOverrides();
for (const m of moduleDefs) {
  overridesExtreme[m.id].enabled = true;
  overridesExtreme[m.id].aggressiveness = m.clazz === 'active' ? 2 : 1;
}

export const scanPolicies = [
  new ScanPolicy({
    id: 'policy_normal',
    name: 'Normal (Passive Exposure)',
    description:
      'Low-impact scanning focused on exposed files, directory listings, debug pages, and TLS/headers.',
    moduleOverrides: overridesNormal,
    globalLimits: {
      maxRequestsPerSecond: 3,
      maxParallelTargets: 2,
      maxScanDurationSeconds: 1200,
    },
  }),
  new ScanPolicy({
    id: 'policy_aggressive',
    name: 'Aggressive (Exposure + Basic Injection)',
    description:
      'Adds basic SQLi and reflected XSS probes on top of passive exposure checks.',
    moduleOverrides: overridesAggressive,
    globalLimits: {
      maxRequestsPerSecond: 5,
      maxParallelTargets: 3,
      maxScanDurationSeconds: 2400,
    },
  }),
  new ScanPolicy({
    id: 'policy_extreme',
    name: 'Extreme (Full Suite)',
    description:
      'Enables all modules, including active fuzzing; intended only for fully authorized environments.',
    moduleOverrides: overridesExtreme,
    globalLimits: {
      maxRequestsPerSecond: 10,
      maxParallelTargets: 5,
      maxScanDurationSeconds: 7200,
    },
  }),
];

export const scanPolicyById = scanPolicies.reduce((acc, p) => {
  acc[p.id] = p;
  return acc;
}, {});
