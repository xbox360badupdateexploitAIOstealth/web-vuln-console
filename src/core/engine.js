// src/core/engine.js
// Scan engine: passive exposure + TLS/headers + cookie/session + HTML crawl +
// JS secret scan + source map detect + active injection.
// v1.4.0 — Phase 2.5 sourceMapDetect wired (TODO-03).

import { ScanJob, Finding, Evidence } from './models.js';
import { moduleDefById }               from './moduleRegistry.js';
import { scanPolicyById }              from './policyRegistry.js';
import { SiteModel }                   from './siteModel.js';
import { httpGetText }                 from './httpClient.js';
import { crawlTargetAndBuildSiteModel } from './crawler.js';
import { runActiveInjectionChecks }    from './injection.js';
import { runTlsHeaderChecks }          from './checks/tlsHeaders.js';
import { runCookieSessionChecks }      from './checks/cookieSession.js';
import { runJsSecretScan }             from './checks/jsSecretScan.js';
import { runSourceMapDetect }          from './checks/sourceMapDetect.js';

export class EngineConfig {
  constructor({ fetchAdapter, baseUrlResolver }) {
    this.fetchAdapter    = fetchAdapter;
    this.baseUrlResolver = baseUrlResolver;
  }
}

export class EngineContext {
  constructor({ job, project, targets }) {
    this.job        = job;
    this.project    = project;
    this.targets    = targets;
    this.siteModels = new Map();
    this.findings   = [];
    this.evidences  = [];
    this.logs       = [];
  }

  log(message) {
    const ts   = new Date().toISOString();
    const line = `[${ts}] ${message}`;
    this.logs.push(line);
    console.log(line);
  }

  getOrCreateSiteModel(targetId) {
    if (!this.siteModels.has(targetId)) {
      this.siteModels.set(targetId, new SiteModel({ targetId }));
    }
    return this.siteModels.get(targetId);
  }

  addFinding(finding)   { this.findings.push(finding); }
  addEvidence(evidence) { this.evidences.push(evidence); }
}

// ─────────────────────────────────────────────────────────────────────────────
export async function runScanJob({ jobInput, project, targets, engineConfig }) {
  const job    = jobInput instanceof ScanJob ? jobInput : new ScanJob(jobInput);
  const policy = scanPolicyById[job.policyId];
  if (!policy) throw new Error(`Unknown policy: ${job.policyId}`);

  const ctx = new EngineContext({ job, project, targets });
  ctx.log(`Starting scan job ${job.id} with policy "${policy.name}"`);

  const enabledModules = Object.entries(policy.moduleOverrides)
    .filter(([, cfg]) => cfg.enabled)
    .map(([id]) => moduleDefById[id])
    .filter(Boolean);

  ctx.log(`Enabled modules (${enabledModules.length}): ${enabledModules.map((m) => m.id).join(', ') || '(none)'}`);

  for (const target of targets) {
    await scanTarget({ ctx, target, enabledModules, engineConfig });
  }

  ctx.log(`Scan job ${job.id} complete. Findings: ${ctx.findings.length}`);
  return ctx;
}

async function scanTarget({ ctx, target, enabledModules, engineConfig }) {
  const baseUrl = engineConfig.baseUrlResolver(target);
  ctx.log(`\n--- Scanning target: ${target.host} (${baseUrl}) ---`);
  const siteModel = ctx.getOrCreateSiteModel(target.id);

  // ── Phase 1: Passive exposure checks ──────────────────────────────────────────────
  await runPassiveExposureChecks({ ctx, target, baseUrl, siteModel, enabledModules, engineConfig });

  // ── Phase 1b: TLS & security headers ───────────────────────────────────────────
  if (moduleEnabled(enabledModules, 'tls.headers.basic')) {
    await runTlsHeaderChecks({
      ctx,
      target,
      baseUrl,
      fetchAdapter: engineConfig.fetchAdapter,
    });
  }

  // ── Phase 1c: Cookie & session security ───────────────────────────────────────
  if (moduleEnabled(enabledModules, 'cookie.session.flags')) {
    await runCookieSessionChecks({
      ctx,
      target,
      baseUrl,
      fetchAdapter: engineConfig.fetchAdapter,
    });
  }

  // ── Phase 2: HTML crawl to discover endpoints & parameters ────────────────────
  await crawlTargetAndBuildSiteModel({
    ctx,
    target,
    baseUrl,
    siteModel,
    engineConfig,
    maxDepth: 2,
    maxPages: 30,
  });

  const paramEps = siteModel.getParamEndpoints().length;
  const allEps   = siteModel.getAllEndpoints().length;
  ctx.log(`SiteModel: ${allEps} endpoints total, ${paramEps} with parameters.`);

  // ── Phase 2.5a: JS asset secret scan ──────────────────────────────────────────
  if (moduleEnabled(enabledModules, 'exposure.js.secrets')) {
    await runJsSecretScan({
      ctx,
      target,
      siteModel,
      baseUrl,
      fetchAdapter: engineConfig.fetchAdapter,
    });
  }

  // ── Phase 2.5b: JS source map detection ───────────────────────────────────────
  if (moduleEnabled(enabledModules, 'exposure.sourcemap')) {
    await runSourceMapDetect({
      ctx,
      target,
      siteModel,
      baseUrl,
      fetchAdapter: engineConfig.fetchAdapter,
    });
  }

  // ── Phase 3: Active injection checks ─────────────────────────────────────────
  await runActiveInjectionChecks({
    ctx,
    target,
    siteModel,
    enabledModules,
    engineConfig,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// PASSIVE EXPOSURE CHECKS
// ─────────────────────────────────────────────────────────────────────────────

async function runPassiveExposureChecks({ ctx, target, baseUrl, siteModel, enabledModules, engineConfig }) {
  const { fetchAdapter } = engineConfig;

  if (moduleEnabled(enabledModules, 'exposure.env.direct'))          await checkEnvDirect    ({ ctx, target, baseUrl, fetchAdapter });
  if (moduleEnabled(enabledModules, 'exposure.env.variants'))        await checkEnvVariants  ({ ctx, target, baseUrl, fetchAdapter });
  if (moduleEnabled(enabledModules, 'exposure.backup.db_dumps'))     await checkDbDumps     ({ ctx, target, baseUrl, fetchAdapter });
  if (moduleEnabled(enabledModules, 'exposure.backup.archives'))     await checkArchives    ({ ctx, target, baseUrl, fetchAdapter });
  if (moduleEnabled(enabledModules, 'misconfig.dirlisting.generic')) await checkDirListing  ({ ctx, target, baseUrl, fetchAdapter });
  if (moduleEnabled(enabledModules, 'vcs.git.exposed'))              await checkGitExposed  ({ ctx, target, baseUrl, fetchAdapter });
  if (moduleEnabled(enabledModules, 'debug.stacktraces'))            await checkDebugErrors ({ ctx, target, baseUrl, fetchAdapter });
}

function moduleEnabled(mods, id) {
  return mods.some((m) => m.id === id);
}

// ── .env direct ──────────────────────────────────────────────────────────────────────────
async function checkEnvDirect({ ctx, target, baseUrl, fetchAdapter }) {
  const url = baseUrl.replace(/\/$/, '') + '/.env';
  ctx.log(`Checking direct .env exposure: ${url}`);
  try {
    const res = await httpGetText({ fetchAdapter, url });
    if (res.status === 200 && looksLikeDotenv(res.body)) {
      const finding = new Finding({
        projectId: ctx.project.id, scanJobId: ctx.job.id, targetId: target.id,
        moduleId: 'exposure.env.direct',
        title: 'Exposed .env File',
        shortDescription: `The .env file is accessible at ${url}.`,
        detailedDescription:
          'The application\'s dotenv configuration file (.env) is publicly accessible. ' +
          'It often contains database credentials, API keys, and other secrets in plaintext.',
        severity: 'critical', category: 'exposure',
        owaspTag: 'A02-Cryptographic-Failures', cweTag: 'CWE-359',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(new Evidence({ findingId: finding.id, url, method: 'GET', responseStatus: res.status, responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512), responseBodySnippet: res.body.slice(0, 2048), matchedPattern: 'dotenv key=value pairs' }));
      ctx.log(`🔴 CRITICAL: .env exposed at ${url}`);
    } else {
      ctx.log(`No .env exposure at ${url} (status ${res.status})`);
    }
  } catch (e) { ctx.log(`checkEnvDirect error: ${e.message || e}`); }
}

// ── .env variants ────────────────────────────────────────────────────────────────────────
async function checkEnvVariants({ ctx, target, baseUrl, fetchAdapter }) {
  const mod   = moduleDefById['exposure.env.variants'];
  const paths = mod?.configSchema?.properties?.paths?.default || [];
  for (const p of paths) {
    const url = baseUrl.replace(/\/$/, '') + p;
    ctx.log(`Checking .env variant: ${url}`);
    try {
      const res = await httpGetText({ fetchAdapter, url });
      if (res.status === 200 && looksLikeDotenv(res.body)) {
        const finding = new Finding({
          projectId: ctx.project.id, scanJobId: ctx.job.id, targetId: target.id,
          moduleId: 'exposure.env.variants',
          title: 'Exposed .env Variant File',
          shortDescription: `A dotenv variant file is accessible at ${url}.`,
          detailedDescription: 'A dotenv configuration variant is publicly accessible and likely contains sensitive secrets.',
          severity: 'critical', category: 'exposure',
          owaspTag: 'A02-Cryptographic-Failures', cweTag: 'CWE-359',
        });
        ctx.addFinding(finding);
        ctx.addEvidence(new Evidence({ findingId: finding.id, url, method: 'GET', responseStatus: res.status, responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512), responseBodySnippet: res.body.slice(0, 2048), matchedPattern: 'dotenv key=value pairs' }));
        ctx.log(`🔴 CRITICAL: .env variant exposed at ${url}`);
      }
    } catch (e) { ctx.log(`checkEnvVariants error: ${e.message || e}`); }
  }
}

// ── DB dumps ──────────────────────────────────────────────────────────────────────────
async function checkDbDumps({ ctx, target, baseUrl, fetchAdapter }) {
  const mod   = moduleDefById['exposure.backup.db_dumps'];
  const paths = mod?.configSchema?.properties?.candidateNames?.default || [];
  for (const p of paths) {
    const url = baseUrl.replace(/\/$/, '') + p;
    ctx.log(`Checking DB dump: ${url}`);
    try {
      const res = await httpGetText({ fetchAdapter, url });
      if (res.status === 200 && looksLikeSqlDump(res.body)) {
        const finding = new Finding({
          projectId: ctx.project.id, scanJobId: ctx.job.id, targetId: target.id,
          moduleId: 'exposure.backup.db_dumps',
          title: 'Exposed Database Dump',
          shortDescription: `A probable SQL dump is accessible at ${url}.`,
          detailedDescription: 'A SQL database backup file is accessible over HTTP. May contain full application data including user records and credentials.',
          severity: 'critical', category: 'exposure',
          owaspTag: 'A01-Broken-Access-Control', cweTag: 'CWE-200',
        });
        ctx.addFinding(finding);
        ctx.addEvidence(new Evidence({ findingId: finding.id, url, method: 'GET', responseStatus: res.status, responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512), responseBodySnippet: res.body.slice(0, 2048), matchedPattern: 'SQL dump (CREATE TABLE / INSERT INTO)' }));
        ctx.log(`🔴 CRITICAL: DB dump exposed at ${url}`);
      }
    } catch (e) { ctx.log(`checkDbDumps error: ${e.message || e}`); }
  }
}

// ── Archives ──────────────────────────────────────────────────────────────────────────
async function checkArchives({ ctx, target, baseUrl, fetchAdapter }) {
  const mod   = moduleDefById['exposure.backup.archives'];
  const paths = mod?.configSchema?.properties?.candidateNames?.default || [];
  for (const p of paths) {
    const url = baseUrl.replace(/\/$/, '') + p;
    ctx.log(`Checking archive: ${url}`);
    try {
      const res = await httpGetText({ fetchAdapter, url });
      if (res.status === 200 && looksLikeBinaryArchive(res.headers)) {
        const finding = new Finding({
          projectId: ctx.project.id, scanJobId: ctx.job.id, targetId: target.id,
          moduleId: 'exposure.backup.archives',
          title: 'Exposed Backup Archive',
          shortDescription: `A probable backup archive is accessible at ${url}.`,
          detailedDescription: 'A ZIP/TAR archive is accessible — may contain site backups, source code, or database exports.',
          severity: 'high', category: 'exposure',
          owaspTag: 'A01-Broken-Access-Control', cweTag: 'CWE-530',
        });
        ctx.addFinding(finding);
        ctx.addEvidence(new Evidence({ findingId: finding.id, url, method: 'GET', responseStatus: res.status, responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512), responseBodySnippet: '', matchedPattern: 'Archive content-type' }));
        ctx.log(`🟠 HIGH: backup archive exposed at ${url}`);
      }
    } catch (e) { ctx.log(`checkArchives error: ${e.message || e}`); }
  }
}

// ── Directory listing ────────────────────────────────────────────────────────────────────
async function checkDirListing({ ctx, target, baseUrl, fetchAdapter }) {
  const mod   = moduleDefById['misconfig.dirlisting.generic'];
  const paths = mod?.configSchema?.properties?.paths?.default || [];
  for (const p of paths) {
    const url = baseUrl.replace(/\/$/, '') + p;
    ctx.log(`Checking dir listing: ${url}`);
    try {
      const res = await httpGetText({ fetchAdapter, url });
      if (looksLikeDirListing(res)) {
        const finding = new Finding({
          projectId: ctx.project.id, scanJobId: ctx.job.id, targetId: target.id,
          moduleId: 'misconfig.dirlisting.generic',
          title: 'Directory Listing Enabled',
          shortDescription: `Directory listing appears enabled at ${url}.`,
          detailedDescription: 'The server returns a directory index for this path, potentially exposing internal files.',
          severity: 'medium', category: 'misconfig',
          owaspTag: 'A05-Security-Misconfiguration', cweTag: 'CWE-548',
        });
        ctx.addFinding(finding);
        ctx.addEvidence(new Evidence({ findingId: finding.id, url, method: 'GET', responseStatus: res.status, responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512), responseBodySnippet: res.body.slice(0, 2048), matchedPattern: 'Index of / listing' }));
        ctx.log(`🟡 MEDIUM: directory listing at ${url}`);
      }
    } catch (e) { ctx.log(`checkDirListing error: ${e.message || e}`); }
  }
}

// ── .git exposed ─────────────────────────────────────────────────────────────────────────
async function checkGitExposed({ ctx, target, baseUrl, fetchAdapter }) {
  const mod   = moduleDefById['vcs.git.exposed'];
  const paths = mod?.configSchema?.properties?.checkPaths?.default || [];
  for (const p of paths) {
    const url = baseUrl.replace(/\/$/, '') + p;
    ctx.log(`Checking .git component: ${url}`);
    try {
      const res = await httpGetText({ fetchAdapter, url });
      if (res.status === 200 && res.body.length > 0) {
        const finding = new Finding({
          projectId: ctx.project.id, scanJobId: ctx.job.id, targetId: target.id,
          moduleId: 'vcs.git.exposed',
          title: 'Exposed .git Repository Components',
          shortDescription: `One or more .git files are publicly accessible (e.g., ${url}).`,
          detailedDescription: 'Parts of the .git directory are accessible. Attackers can reconstruct the repository and recover source code and secrets.',
          severity: 'high', category: 'exposure',
          owaspTag: 'A05-Security-Misconfiguration', cweTag: 'CWE-200',
        });
        ctx.addFinding(finding);
        ctx.addEvidence(new Evidence({ findingId: finding.id, url, method: 'GET', responseStatus: res.status, responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512), responseBodySnippet: res.body.slice(0, 2048), matchedPattern: '.git file content' }));
        ctx.log(`🟠 HIGH: .git exposed at ${url}`);
        break;
      }
    } catch (e) { ctx.log(`checkGitExposed error: ${e.message || e}`); }
  }
}

// ── Debug errors / stack traces ─────────────────────────────────────────────────────────
async function checkDebugErrors({ ctx, target, baseUrl, fetchAdapter }) {
  const url = baseUrl.replace(/\/$/, '') + '/this-path-should-not-exist-probe-wvc';
  ctx.log(`Probing debug error page: ${url}`);
  try {
    const res = await httpGetText({ fetchAdapter, url });
    if (res.status >= 500 && looksLikeStackTrace(res.body)) {
      const finding = new Finding({
        projectId: ctx.project.id, scanJobId: ctx.job.id, targetId: target.id,
        moduleId: 'debug.stacktraces',
        title: 'Verbose Error / Stack Trace Leakage',
        shortDescription: 'The application returns detailed error pages containing stack traces.',
        detailedDescription: 'A request to an invalid path triggered a detailed error response containing stack traces. This leaks sensitive information about the application internals.',
        severity: 'medium', category: 'exposure',
        owaspTag: 'A05-Security-Misconfiguration', cweTag: 'CWE-209',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(new Evidence({ findingId: finding.id, url, method: 'GET', responseStatus: res.status, responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512), responseBodySnippet: res.body.slice(0, 2048), matchedPattern: 'Stack trace markers' }));
      ctx.log(`🟡 MEDIUM: stack trace leakage at ${url}`);
    } else {
      ctx.log(`No debug errors at ${url} (status ${res.status})`);
    }
  } catch (e) { ctx.log(`checkDebugErrors error: ${e.message || e}`); }
}

// ── Content detectors ──────────────────────────────────────────────────────────────────────

function looksLikeDotenv(body) {
  return body.split(/\r?\n/).slice(0, 40).filter((l) => /^[A-Z0-9_]+=.+/.test(l)).length >= 3;
}

function looksLikeSqlDump(body) {
  const s = body.slice(0, 4096).toUpperCase();
  return s.includes('CREATE TABLE') || s.includes('INSERT INTO');
}

function looksLikeBinaryArchive(headers) {
  return /zip|tar|gzip|octet-stream/i.test(headers['content-type'] || '');
}

function looksLikeDirListing(res) {
  if (res.status !== 200) return false;
  const s = res.body.slice(0, 4096).toLowerCase();
  return s.includes('<title>index of /') || s.includes('<h1>index of /') || s.includes('parent directory');
}

function looksLikeStackTrace(body) {
  const s = body.slice(0, 4096);
  return (
    /exception in thread|stack trace|traceback \(most recent call last\)/i.test(s) ||
    /java\.lang\./i.test(s) ||
    /at [\w$.]+\([\w$.]+:\d+\)/.test(s)
  );
}
