// src/core/models.js

export function genId(prefix = 'id') {
  return `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`;
}

export class Workspace {
  constructor({
    id = genId('ws'),
    name,
    description = '',
    createdAt = new Date(),
    createdBy = 'local',
  }) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.createdAt = createdAt;
    this.createdBy = createdBy;
  }
}

export class Project {
  constructor({
    id = genId('proj'),
    workspaceId,
    name,
    clientName = '',
    clientContact = '',
    authNotes = '',
    defaultScanPolicyId = null,
    tags = [],
    createdAt = new Date(),
    lastScanAt = null,
    riskScore = null,
  }) {
    this.id = id;
    this.workspaceId = workspaceId;
    this.name = name;
    this.clientName = clientName;
    this.clientContact = clientContact;
    this.authNotes = authNotes;
    this.defaultScanPolicyId = defaultScanPolicyId;
    this.tags = tags;
    this.createdAt = createdAt;
    this.lastScanAt = lastScanAt;
    this.riskScore = riskScore;
  }
}

export class Target {
  constructor({
    id = genId('tgt'),
    projectId,
    host,
    type = 'web_site',
    env = 'prod',
    stackGuess = [],
    discoverySource = 'manual',
    notes = '',
  }) {
    this.id = id;
    this.projectId = projectId;
    this.host = host;
    this.type = type;
    this.env = env;
    this.stackGuess = stackGuess;
    this.discoverySource = discoverySource;
    this.notes = notes;
  }
}

export class ModuleDef {
  constructor({
    id,
    name,
    description = '',
    category = 'exposure',
    clazz = 'passive',
    severityDefault = 'medium',
    stackFilters = [],
    owaspTags = [],
    cweTags = [],
    cveExamples = [],
    configSchema = null,
  }) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.category = category;
    this.clazz = clazz;
    this.severityDefault = severityDefault;
    this.stackFilters = stackFilters;
    this.owaspTags = owaspTags;
    this.cweTags = cweTags;
    this.cveExamples = cveExamples;
    this.configSchema = configSchema;
  }
}

export class ScanPolicy {
  constructor({
    id = genId('pol'),
    name,
    description = '',
    moduleOverrides = {},
    globalLimits = {
      maxRequestsPerSecond: 5,
      maxParallelTargets: 2,
      maxScanDurationSeconds: 1800,
    },
  }) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.moduleOverrides = moduleOverrides;
    this.globalLimits = globalLimits;
  }
}

export class ScanJob {
  constructor({
    id = genId('job'),
    projectId,
    policyId,
    targetIds = [],
    status = 'queued',
    createdAt = new Date(),
    startedAt = null,
    finishedAt = null,
    initiatedBy = 'local',
    initSource = 'ui',
    stats = {
      numRequests: 0,
      numFindings: 0,
      numErrors: 0,
      modulesExecuted: 0,
    },
  }) {
    this.id = id;
    this.projectId = projectId;
    this.policyId = policyId;
    this.targetIds = targetIds;
    this.status = status;
    this.createdAt = createdAt;
    this.startedAt = startedAt;
    this.finishedAt = finishedAt;
    this.initiatedBy = initiatedBy;
    this.initSource = initSource;
    this.stats = stats;
  }
}

export class Finding {
  constructor({
    id = genId('find'),
    projectId,
    scanJobId,
    targetId,
    moduleId,
    title,
    shortDescription = '',
    detailedDescription = '',
    severity = 'medium',
    status = 'open',
    category = 'exposure',
    owaspTag = null,
    cweId = null,
    cveRefs = [],
    firstSeenAt = new Date(),
    lastSeenAt = new Date(),
    occurrenceCount = 1,
    evidenceIds = [],
    correlatedGroupId = null,
  }) {
    this.id = id;
    this.projectId = projectId;
    this.scanJobId = scanJobId;
    this.targetId = targetId;
    this.moduleId = moduleId;
    this.title = title;
    this.shortDescription = shortDescription;
    this.detailedDescription = detailedDescription;
    this.severity = severity;
    this.status = status;
    this.category = category;
    this.owaspTag = owaspTag;
    this.cweId = cweId;
    this.cveRefs = cveRefs;
    this.firstSeenAt = firstSeenAt;
    this.lastSeenAt = lastSeenAt;
    this.occurrenceCount = occurrenceCount;
    this.evidenceIds = evidenceIds;
    this.correlatedGroupId = correlatedGroupId;
  }
}

export class Evidence {
  constructor({
    id = genId('ev'),
    findingId,
    url,
    method = 'GET',
    requestHeadersSnippet = '',
    requestBodySnippet = '',
    responseStatus = 0,
    responseHeadersSnippet = '',
    responseBodySnippet = '',
    matchedPattern = '',
    responseHash = '',
    createdAt = new Date(),
  }) {
    this.id = id;
    this.findingId = findingId;
    this.url = url;
    this.method = method;
    this.requestHeadersSnippet = requestHeadersSnippet;
    this.requestBodySnippet = requestBodySnippet;
    this.responseStatus = responseStatus;
    this.responseHeadersSnippet = responseHeadersSnippet;
    this.responseBodySnippet = responseBodySnippet;
    this.matchedPattern = matchedPattern;
    this.responseHash = responseHash;
    this.createdAt = createdAt;
  }
}

export class AuditEvent {
  constructor({
    id = genId('audit'),
    scopeId = null,
    scopeType = 'project',
    actor = 'system',
    ip = '',
    userAgent = '',
    action,
    details = {},
    timestamp = new Date(),
  }) {
    this.id = id;
    this.scopeId = scopeId;
    this.scopeType = scopeType;
    this.actor = actor;
    this.ip = ip;
    this.userAgent = userAgent;
    this.action = action;
    this.details = details;
    this.timestamp = timestamp;
  }
}
