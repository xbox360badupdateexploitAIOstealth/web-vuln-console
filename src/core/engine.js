// src/core/engine.js
// Real scan engine: basic implementation of passive exposure checks
// and simple active tests using the module definitions and policies.

import { ScanJob, Finding, Evidence } from './models.js';
import { moduleDefById } from './moduleRegistry.js';
import { scanPolicyById } from './policyRegistry.js';
import { SiteModel } from './siteModel.js';
import { httpGetText } from './httpClient.js';

export class EngineConfig {
  constructor({ fetchAdapter, baseUrlResolver }) {
    this.fetchAdapter = fetchAdapter;
    this.baseUrlResolver = baseUrlResolver;
  }
}

export class EngineContext {
  constructor({ job, project, targets }) {
    this.job = job;
    this.project = project;
    this.targets = targets;
    this.siteModels = new Map();
    this.findings = [];
    this.evidences = [];
    this.logs = [];
  }

  log(message) {
    const ts = new Date().toISOString();
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

  addFinding(finding) {
    this.findings.push(finding);
  }

  addEvidence(evidence) {
    this.evidences.push(evidence);
  }
}

export async function runScanJob({ jobInput, project, targets, engineConfig }) {
  const job = jobInput instanceof ScanJob ? jobInput : new ScanJob(jobInput);
  const policy = scanPolicyById[job.policyId];
  if (!policy) {
    throw new Error(`Unknown policy: ${job.policyId}`);
  }

  const ctx = new EngineContext({ job, project, targets });
  ctx.log(`Starting scan job ${job.id} with policy ${policy.name}`);

  const enabledModules = Object.entries(policy.moduleOverrides)
    .filter(([, cfg]) => cfg.enabled)
    .map(([id]) => moduleDefById[id])
    .filter(Boolean);

  ctx.log(`Enabled modules: ${enabledModules.map((m) => m.id).join(', ') || '(none)'}`);

  for (const target of targets) {
    await scanTarget({ ctx, target, enabledModules, engineConfig });
  }

  ctx.log(`Scan job ${job.id} complete. Findings: ${ctx.findings.length}`);
  return ctx;
}

async function scanTarget({ ctx, target, enabledModules, engineConfig }) {
  const baseUrl = engineConfig.baseUrlResolver(target);
  ctx.log(`Scanning target ${target.host} (base URL: ${baseUrl})`);
  const siteModel = ctx.getOrCreateSiteModel(target.id);

  // Phase 1: passive exposure checks (env, backups, dirlisting, git, debug, TLS)
  await runPassiveExposureChecks({ ctx, target, baseUrl, siteModel, enabledModules, engineConfig });

  // Phase 2: (later) crawl & injective tests based on siteModel.
  // For now, we stop after exposure checks.
}

async function runPassiveExposureChecks({ ctx, target, baseUrl, siteModel, enabledModules, engineConfig }) {
  const { fetchAdapter } = engineConfig;
  const expEnvDirect = moduleEnabled(enabledModules, 'exposure.env.direct');
  const expEnvVariants = moduleEnabled(enabledModules, 'exposure.env.variants');
  const expDbDumps = moduleEnabled(enabledModules, 'exposure.backup.db_dumps');
  const expArchives = moduleEnabled(enabledModules, 'exposure.backup.archives');
  const expDirListing = moduleEnabled(enabledModules, 'misconfig.dirlisting.generic');
  const expGit = moduleEnabled(enabledModules, 'vcs.git.exposed');
  const expDebug = moduleEnabled(enabledModules, 'debug.stacktraces');

  if (expEnvDirect) {
    await checkEnvDirect({ ctx, target, baseUrl, fetchAdapter });
  }
  if (expEnvVariants) {
    await checkEnvVariants({ ctx, target, baseUrl, fetchAdapter });
  }
  if (expDbDumps) {
    await checkDbDumps({ ctx, target, baseUrl, fetchAdapter });
  }
  if (expArchives) {
    await checkArchives({ ctx, target, baseUrl, fetchAdapter });
  }
  if (expDirListing) {
    await checkDirListing({ ctx, target, baseUrl, fetchAdapter });
  }
  if (expGit) {
    await checkGitExposed({ ctx, target, baseUrl, fetchAdapter });
  }
  if (expDebug) {
    await checkDebugErrors({ ctx, target, baseUrl, fetchAdapter });
  }

  // TLS headers & security headers module is better run on any fetched response;
  // for now we just reuse responses we already pulled where relevant.
}

function moduleEnabled(enabledModules, moduleId) {
  return enabledModules.some((m) => m.id === moduleId);
}

async function checkEnvDirect({ ctx, target, baseUrl, fetchAdapter }) {
  const url = baseUrl.replace(/\/$/, '') + '/.env';
  ctx.log(`Checking direct .env exposure at ${url}`);
  const res = await httpGetText({ fetchAdapter, url });
  if (res.status === 200 && looksLikeDotenv(res.body)) {
    const finding = new Finding({
      projectId: ctx.project.id,
      scanJobId: ctx.job.id,
      targetId: target.id,
      moduleId: 'exposure.env.direct',
      title: 'Exposed .env file',
      shortDescription: `The .env file is accessible at ${url}.`,
      detailedDescription:
        'The application exposes its dotenv configuration file (.env), which often contains database credentials, API keys, and other secrets.',
      severity: 'critical',
      category: 'exposure',
      owaspTag: 'A02-Cryptographic-Failures',
    });
    const evidence = new Evidence({
      findingId: finding.id,
      url,
      method: 'GET',
      responseStatus: res.status,
      responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512),
      responseBodySnippet: res.body.slice(0, 2048),
      matchedPattern: 'dotenv-style key=value pairs',
    });
    ctx.addFinding(finding);
    ctx.addEvidence(evidence);
    ctx.log(`CRITICAL: .env exposed at ${url}`);
  } else {
    ctx.log(`No direct .env exposure at ${url} (status ${res.status}).`);
  }
}

async function checkEnvVariants({ ctx, target, baseUrl, fetchAdapter }) {
  const mod = moduleDefById['exposure.env.variants'];
  const paths = (mod.configSchema?.properties?.paths?.default) || [];
  for (const path of paths) {
    const url = baseUrl.replace(/\/$/, '') + path;
    ctx.log(`Checking .env variant at ${url}`);
    const res = await httpGetText({ fetchAdapter, url });
    if (res.status === 200 && looksLikeDotenv(res.body)) {
      const finding = new Finding({
        projectId: ctx.project.id,
        scanJobId: ctx.job.id,
        targetId: target.id,
        moduleId: 'exposure.env.variants',
        title: 'Exposed .env variant file',
        shortDescription: `A dotenv-style variant file is accessible at ${url}.`,
        detailedDescription:
          'A dotenv configuration variant (.env.local, .env.backup, etc.) is exposed and likely contains sensitive configuration secrets.',
        severity: 'critical',
        category: 'exposure',
        owaspTag: 'A02-Cryptographic-Failures',
      });
      const evidence = new Evidence({
        findingId: finding.id,
        url,
        method: 'GET',
        responseStatus: res.status,
        responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512),
        responseBodySnippet: res.body.slice(0, 2048),
        matchedPattern: 'dotenv-style key=value pairs',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`CRITICAL: .env variant exposed at ${url}`);
    }
  }
}

async function checkDbDumps({ ctx, target, baseUrl, fetchAdapter }) {
  const mod = moduleDefById['exposure.backup.db_dumps'];
  const paths = (mod.configSchema?.properties?.candidateNames?.default) || [];
  for (const path of paths) {
    const url = baseUrl.replace(/\/$/, '') + path;
    ctx.log(`Checking DB dump candidate at ${url}`);
    const res = await httpGetText({ fetchAdapter, url });
    if (res.status === 200 && looksLikeSqlDump(res.body)) {
      const finding = new Finding({
        projectId: ctx.project.id,
        scanJobId: ctx.job.id,
        targetId: target.id,
        moduleId: 'exposure.backup.db_dumps',
        title: 'Exposed database dump',
        shortDescription: `A probable SQL dump file is accessible at ${url}.`,
        detailedDescription:
          'A file that appears to be a SQL database backup is accessible over HTTP. This may contain full application data, including user records and credentials.',
        severity: 'critical',
        category: 'exposure',
        owaspTag: 'A01-Broken-Access-Control',
      });
      const evidence = new Evidence({
        findingId: finding.id,
        url,
        method: 'GET',
        responseStatus: res.status,
        responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512),
        responseBodySnippet: res.body.slice(0, 2048),
        matchedPattern: 'SQL dump signature (CREATE TABLE / INSERT INTO)',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`CRITICAL: probable DB dump exposed at ${url}`);
    }
  }
}

async function checkArchives({ ctx, target, baseUrl, fetchAdapter }) {
  const mod = moduleDefById['exposure.backup.archives'];
  const paths = (mod.configSchema?.properties?.candidateNames?.default) || [];
  for (const path of paths) {
    const url = baseUrl.replace(/\/$/, '') + path;
    ctx.log(`Checking archive backup at ${url}`);
    const res = await httpGetText({ fetchAdapter, url });
    if (res.status === 200 && looksLikeBinaryArchive(res.headers)) {
      const finding = new Finding({
        projectId: ctx.project.id,
        scanJobId: ctx.job.id,
        targetId: target.id,
        moduleId: 'exposure.backup.archives',
        title: 'Exposed backup archive',
        shortDescription: `A probable backup archive is accessible at ${url}.`,
        detailedDescription:
          'A ZIP/TAR archive appears to be accessible, likely containing site or database backups. This can leak full source code or data.',
        severity: 'high',
        category: 'exposure',
        owaspTag: 'A01-Broken-Access-Control',
      });
      const evidence = new Evidence({
        findingId: finding.id,
        url,
        method: 'GET',
        responseStatus: res.status,
        responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512),
        responseBodySnippet: '',
        matchedPattern: 'Backup archive content-type',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`HIGH: probable backup archive exposed at ${url}`);
    }
  }
}

async function checkDirListing({ ctx, target, baseUrl, fetchAdapter }) {
  const mod = moduleDefById['misconfig.dirlisting.generic'];
  const paths = (mod.configSchema?.properties?.paths?.default) || [];
  for (const path of paths) {
    const url = baseUrl.replace(/\/$/, '') + path;
    ctx.log(`Checking directory listing at ${url}`);
    const res = await httpGetText({ fetchAdapter, url });
    if (looksLikeDirListing(res)) {
      const finding = new Finding({
        projectId: ctx.project.id,
        scanJobId: ctx.job.id,
        targetId: target.id,
        moduleId: 'misconfig.dirlisting.generic',
        title: 'Directory listing enabled',
        shortDescription: `Directory listing appears to be enabled at ${url}.`,
        detailedDescription:
          'The web server is returning a directory index for this path, which can expose internal files such as backups, configuration, or code.',
        severity: 'medium',
        category: 'misconfig',
        owaspTag: 'A05-Security-Misconfiguration',
      });
      const evidence = new Evidence({
        findingId: finding.id,
        url,
        method: 'GET',
        responseStatus: res.status,
        responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512),
        responseBodySnippet: res.body.slice(0, 2048),
        matchedPattern: 'Index of / style listing',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`MEDIUM: directory listing detected at ${url}`);
    }
  }
}

async function checkGitExposed({ ctx, target, baseUrl, fetchAdapter }) {
  const mod = moduleDefById['vcs.git.exposed'];
  const paths = (mod.configSchema?.properties?.checkPaths?.default) || [];
  let any = false;
  for (const path of paths) {
    const url = baseUrl.replace(/\/$/, '') + path;
    ctx.log(`Checking .git component at ${url}`);
    const res = await httpGetText({ fetchAdapter, url });
    if (res.status === 200 && res.body.length > 0) {
      any = true;
      const finding = new Finding({
        projectId: ctx.project.id,
        scanJobId: ctx.job.id,
        targetId: target.id,
        moduleId: 'vcs.git.exposed',
        title: 'Exposed .git repository components',
        shortDescription: `One or more .git files are accessible (e.g., ${url}).`,
        detailedDescription:
          'Parts of the .git directory are accessible over HTTP. Attackers can often reconstruct the entire repository and recover source code and secrets.',
        severity: 'high',
        category: 'exposure',
        owaspTag: 'A05-Security-Misconfiguration',
      });
      const evidence = new Evidence({
        findingId: finding.id,
        url,
        method: 'GET',
        responseStatus: res.status,
        responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512),
        responseBodySnippet: res.body.slice(0, 2048),
        matchedPattern: '.git file content',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(evidence);
      ctx.log(`HIGH: .git component exposed at ${url}`);
      break; // one is enough to report
    }
  }
  if (!any) {
    ctx.log('No exposed .git components detected.');
  }
}

async function checkDebugErrors({ ctx, target, baseUrl, fetchAdapter }) {
  const weirdPath = '/this-path-should-not-exist-engine-probe';
  const url = baseUrl.replace(/\/$/, '') + weirdPath;
  ctx.log(`Requesting invalid path for debug error detection: ${url}`);
  const res = await httpGetText({ fetchAdapter, url });
  if (res.status >= 500 && looksLikeStackTrace(res.body)) {
    const finding = new Finding({
      projectId: ctx.project.id,
      scanJobId: ctx.job.id,
      targetId: target.id,
      moduleId: 'debug.stacktraces',
      title: 'Verbose error / stack trace leakage',
      shortDescription: 'The application returns detailed error messages or stack traces for invalid requests.',
      detailedDescription:
        'A request to an invalid path triggered a detailed error response that appears to contain stack traces or framework internals. This can leak sensitive information about the application and environment.',
      severity: 'medium',
      category: 'exposure',
      owaspTag: 'A05-Security-Misconfiguration',
    });
    const evidence = new Evidence({
      findingId: finding.id,
      url,
      method: 'GET',
      responseStatus: res.status,
      responseHeadersSnippet: JSON.stringify(res.headers).slice(0, 512),
      responseBodySnippet: res.body.slice(0, 2048),
      matchedPattern: 'Stack trace markers',
    });
    ctx.addFinding(finding);
    ctx.addEvidence(evidence);
    ctx.log('MEDIUM: verbose error / stack trace leakage detected.');
  } else {
    ctx.log(`No verbose debug error detected at ${url} (status ${res.status}).`);
  }
}

function looksLikeDotenv(body) {
  const lines = body.split(/\r?\n/).slice(0, 40);
  let pairs = 0;
  for (const line of lines) {
    if (/^[A-Z0-9_]+\s*=\s*.+/.test(line)) pairs++;
  }
  return pairs >= 3;
}

function looksLikeSqlDump(body) {
  const snippet = body.slice(0, 4096).toUpperCase();
  return snippet.includes('CREATE TABLE') || snippet.includes('INSERT INTO');
}

function looksLikeBinaryArchive(headers) {
  const ct = headers['content-type'] || headers['content-type'.toLowerCase()] || '';
  return /zip|tar|gzip|octet-stream/i.test(ct);
}

function looksLikeDirListing(res) {
  if (res.status !== 200) return false;
  const snippet = res.body.slice(0, 4096).toLowerCase();
  return snippet.includes('<title>index of /') || snippet.includes('<h1>index of /') || snippet.includes('parent directory');
}

function looksLikeStackTrace(body) {
  const snippet = body.slice(0, 4096);
  return (
    /exception in thread|stack trace|traceback \(most recent call last\)/i.test(snippet) ||
    /java\.lang\./i.test(snippet) ||
    /at [\w$.]+\([\w$.]+:\d+\)/.test(snippet)
  );
}
