// src/core/engine.js
// High-level scan engine orchestration.

import { ScanJob, Finding, Evidence } from './models.js';
import { moduleDefById } from './moduleRegistry.js';
import { scanPolicyById } from './policyRegistry.js';
import { SiteModel } from './siteModel.js';

/**
 * EngineConfig configures how the engine performs HTTP requests.
 * For now we inject a simple fetchAdapter so we can later swap
 * between browser fetch, Node, or a backend API.
 */
export class EngineConfig {
  constructor({ fetchAdapter, baseUrlResolver }) {
    this.fetchAdapter = fetchAdapter; // async ({ method, url, headers, body }) => { status, headers, body }
    this.baseUrlResolver = baseUrlResolver; // (target) => base URL string
  }
}

/**
 * EngineContext holds all state for a running scan job.
 */
export class EngineContext {
  constructor({ job, project, targets }) {
    this.job = job;
    this.project = project;
    this.targets = targets;
    this.siteModels = new Map(); // targetId -> SiteModel
    this.findings = [];
    this.evidences = [];
    this.logs = [];
  }

  log(message) {
    const ts = new Date().toISOString();
    const line = `[${ts}] ${message}`;
    this.logs.push(line);
    // Later: emit to UI via event emitter / callback
    console.log(line);
  }

  getOrCreateSiteModel(targetId) {
    if (!this.siteModels.has(targetId)) {
      this.siteModels.set(targetId, new SiteModel({ targetId }));
    }
    return this.siteModels.get(targetId);
  }

  addFinding(finding) {
    this.findings.push(finding);
  }

  addEvidence(evidence) {
    this.evidences.push(evidence);
  }
}

/**
 * Fake scan runner: initial implementation that demonstrates
 * how modules will be selected and executed without doing
 * real HTTP crawling or fuzzing yet.
 *
 * This lets us wire up UI + persistence before we implement
 * the full active/passive logic.
 */
export async function runScanJobFake({ jobInput, project, targets, engineConfig }) {
  const job = jobInput instanceof ScanJob ? jobInput : new ScanJob(jobInput);
  const policy = scanPolicyById[job.policyId];
  if (!policy) {
    throw new Error(`Unknown policy: ${job.policyId}`);
  }

  const ctx = new EngineContext({ job, project, targets });
  ctx.log(`Starting FAKE scan job ${job.id} with policy ${policy.name}`);

  // For now we just simulate running modules by logging which ones
  // WOULD run for each target under this policy.
  for (const target of targets) {
    ctx.log(`Target: ${target.host} [${target.type}/${target.env}]`);

    // Select enabled modules for this policy.
    const enabledModules = Object.entries(policy.moduleOverrides)
      .filter(([, cfg]) => cfg.enabled)
      .map(([id]) => moduleDefById[id])
      .filter(Boolean);

    ctx.log(`Enabled modules for this target: ${enabledModules.map((m) => m.id).join(', ') || '(none)'}`);

    // Create an empty SiteModel for now.
    const siteModel = ctx.getOrCreateSiteModel(target.id);
    ctx.log(`Initialized SiteModel for ${target.host} (0 endpoints discovered in fake mode).`);

    // FAKE: create a synthetic Finding to prove plumbing works.
    const demoFinding = new Finding({
      projectId: project.id,
      scanJobId: job.id,
      targetId: target.id,
      moduleId: 'debug.stacktraces',
      title: `FAKE finding for ${target.host}`,
      shortDescription: 'This is a placeholder finding from the fake engine runner.',
      detailedDescription:
        'In real engine mode, this would represent a detected issue based on HTTP responses and module logic.',
      severity: 'info',
      category: 'exposure',
    });
    ctx.addFinding(demoFinding);

    ctx.log(`FAKE: added 1 synthetic finding for target ${target.host}.`);
  }

  ctx.log(`FAKE scan job ${job.id} complete. Findings: ${ctx.findings.length}`);

  // For now we just return context; later we will persist to backend.
  return ctx;
}
