// src/core/checks/apiKeyExposure.js
// Passive check: detect exposed API documentation, Swagger/OpenAPI UIs,
// and unauthenticated GraphQL introspection endpoints.
//
// Vulnerability classes:
//
//   Swagger / OpenAPI UI exposed — MEDIUM
//     Full API documentation publicly accessible: endpoint list, parameters,
//     auth schemes, example requests. Massively aids enumeration.
//
//   OpenAPI JSON/YAML spec exposed — MEDIUM
//     Raw machine-readable spec: even worse than the UI — can be parsed
//     automatically to discover every endpoint and parameter.
//
//   GraphQL introspection enabled — HIGH
//     Unauthenticated introspection returns the full schema: every type,
//     query, mutation, field, argument, and relationship in the API.
//     Equivalent to handing an attacker the entire data model.
//
//   GraphQL endpoint exposed (no introspection) — LOW
//     GraphQL is present but introspection is disabled — still worth noting.
//
// Wire-up (engine.js Phase 2.5e — after httpMethodsProbe, before injection):
//   import { runApiKeyExposure } from './checks/apiKeyExposure.js';
//   if (moduleEnabled(enabledModules, 'exposure.api_endpoints')) {
//     await runApiKeyExposure({ ctx, target, baseUrl, siteModel, fetchAdapter });
//   }

import { Finding, Evidence } from '../models.js';
import { httpGetText }       from '../httpClient.js';

// ── Swagger / OpenAPI paths ────────────────────────────────────────────────────────

const SWAGGER_UI_PATHS = [
  '/swagger-ui/',
  '/swagger-ui/index.html',
  '/swagger/',
  '/api-docs',
  '/api-docs/',
  '/api/docs',
  '/api/swagger',
  '/swagger-ui.html',
  '/swagger/index.html',
  '/docs/',
  '/redoc',
  '/redoc/',
  '/api/redoc',
];

const OPENAPI_SPEC_PATHS = [
  '/openapi.json',
  '/openapi.yaml',
  '/openapi.yml',
  '/api/openapi.json',
  '/api/openapi.yaml',
  '/swagger.json',
  '/swagger.yaml',
  '/api/swagger.json',
  '/api/swagger.yaml',
  '/api/v1/openapi.json',
  '/api/v2/openapi.json',
  '/api/v3/openapi.json',
  '/.well-known/openapi',
  '/v1/api-docs',
  '/v2/api-docs',
  '/v3/api-docs',
];

// Signatures confirming the page is actually Swagger UI
const SWAGGER_UI_SIGNATURES = [
  'swagger-ui',
  'SwaggerUIBundle',
  'swagger-ui-bundle',
  'Swagger UI',
  'ReDoc',
  'redoc-standalone',
];

// Signatures confirming the response is an OpenAPI spec
const OPENAPI_SPEC_SIGNATURES = [
  '"openapi"',
  '"swagger"',
  'openapi:',
  'swagger:',
  '"paths"',
  'paths:',
];

// ── GraphQL paths ─────────────────────────────────────────────────────────────────

const GRAPHQL_PATHS = [
  '/graphql',
  '/graphql/',
  '/api/graphql',
  '/api/graphql/',
  '/gql',
  '/query',
  '/graphiql',
  '/api/graphiql',
  '/playground',
  '/api/playground',
  '/v1/graphql',
  '/v2/graphql',
];

// Introspection query — minimal to just confirm schema is accessible
const INTROSPECTION_QUERY = JSON.stringify({
  query: '{ __schema { queryType { name } types { name kind } } }',
});

// ── Main entry ─────────────────────────────────────────────────────────────

export async function runApiKeyExposure({ ctx, target, baseUrl, siteModel, fetchAdapter }) {
  ctx.log('[apiExposure] Starting API/Swagger/GraphQL exposure checks...');
  const base = baseUrl.replace(/\/$/, '');

  await checkSwaggerUi({ ctx, target, base, fetchAdapter });
  await checkOpenApiSpec({ ctx, target, base, fetchAdapter });
  await checkGraphQL({ ctx, target, base, fetchAdapter });

  ctx.log('[apiExposure] Done.');
}

// ── Swagger UI ──────────────────────────────────────────────────────────────────

async function checkSwaggerUi({ ctx, target, base, fetchAdapter }) {
  for (const path of SWAGGER_UI_PATHS) {
    const url = base + path;
    ctx.log(`[apiExposure] Probing Swagger UI: ${url}`);

    let res;
    try {
      res = await httpGetText({ fetchAdapter, url });
    } catch (e) {
      ctx.log(`[apiExposure] Swagger fetch error: ${e.message || e}`);
      continue;
    }

    if (res.status !== 200) continue;

    const body    = res.body || '';
    const bodyLow = body.toLowerCase();

    if (!SWAGGER_UI_SIGNATURES.some((s) => bodyLow.includes(s.toLowerCase()))) continue;

    ctx.log(`\uD83D\uDFE1 MEDIUM: Swagger/API docs exposed at ${url}`);

    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'exposure.api_endpoints',
      title:       'API Documentation (Swagger/OpenAPI UI) Exposed',
      shortDescription:
        `Swagger/OpenAPI documentation UI is publicly accessible at ${url}.`,
      detailedDescription:
        'An API documentation interface (Swagger UI or ReDoc) is publicly accessible. ' +
        'This exposes the complete list of API endpoints, HTTP methods, request/response schemas, ' +
        'authentication requirements, and example payloads. ' +
        'Attackers can use this to enumerate every attack surface in the API without crawling. ' +
        'Remediation: Restrict API docs to internal networks or authenticated users in production. ' +
        'If public docs are needed, consider disabling the "Try it out" feature.',
      severity: 'medium',
      category: 'exposure',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag:   'CWE-200',
    });
    ctx.addFinding(finding);
    ctx.addEvidence(new Evidence({
      findingId:              finding.id,
      url,
      method:                 'GET',
      responseStatus:         res.status,
      responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
      responseBodySnippet:    body.slice(0, 2048),
      matchedPattern:         `Swagger/OpenAPI UI signature found at ${url}`,
    }));

    break; // First hit is enough
  }
}

// ── OpenAPI spec (JSON/YAML) ─────────────────────────────────────────────────────────

async function checkOpenApiSpec({ ctx, target, base, fetchAdapter }) {
  for (const path of OPENAPI_SPEC_PATHS) {
    const url = base + path;
    ctx.log(`[apiExposure] Probing OpenAPI spec: ${url}`);

    let res;
    try {
      res = await httpGetText({ fetchAdapter, url });
    } catch (e) {
      ctx.log(`[apiExposure] OpenAPI spec fetch error: ${e.message || e}`);
      continue;
    }

    if (res.status !== 200) continue;

    const body = res.body || '';
    if (!OPENAPI_SPEC_SIGNATURES.some((s) => body.includes(s))) continue;

    // Try to extract title/version from spec
    const titleMatch   = body.match(/["']?title["']?\s*:\s*["']([^"'\n]+)["']/i);
    const versionMatch = body.match(/["']?version["']?\s*:\s*["']([^"'\n]+)["']/i);
    const specTitle    = titleMatch?.[1]   || 'Unknown';
    const specVersion  = versionMatch?.[1] || 'Unknown';

    ctx.log(`\uD83D\uDFE1 MEDIUM: OpenAPI spec exposed at ${url} ("${specTitle}" v${specVersion})`);

    const finding = new Finding({
      projectId:   ctx.project.id,
      scanJobId:   ctx.job.id,
      targetId:    target.id,
      moduleId:    'exposure.api_endpoints',
      title:       `OpenAPI Spec Exposed: "${specTitle}" v${specVersion}`,
      shortDescription:
        `Machine-readable OpenAPI spec is publicly accessible at ${url}.`,
      detailedDescription:
        'A raw OpenAPI/Swagger specification file (JSON or YAML) is publicly accessible. ' +
        'This is worse than the UI alone — the spec can be parsed automatically to discover every endpoint, ' +
        'parameter name, data type, authentication scheme, and server URL. ' +
        'Tools like Postman, Burp Suite, and nuclei can import this directly and begin automated testing. ' +
        `Spec title: "${specTitle}", version: ${specVersion}. ` +
        'Remediation: Remove spec files from production or restrict access by authentication/IP.',
      severity: 'medium',
      category: 'exposure',
      owaspTag: 'A05-Security-Misconfiguration',
      cweTag:   'CWE-200',
    });
    ctx.addFinding(finding);
    ctx.addEvidence(new Evidence({
      findingId:              finding.id,
      url,
      method:                 'GET',
      responseStatus:         res.status,
      responseHeadersSnippet: JSON.stringify(res.headers || {}).slice(0, 512),
      responseBodySnippet:    body.slice(0, 2048),
      matchedPattern:         `OpenAPI spec signature — title: ${specTitle}, version: ${specVersion}`,
    }));

    break;
  }
}

// ── GraphQL ───────────────────────────────────────────────────────────────────────

async function checkGraphQL({ ctx, target, base, fetchAdapter }) {
  for (const path of GRAPHQL_PATHS) {
    const url = base + path;
    ctx.log(`[apiExposure] Probing GraphQL: ${url}`);

    // First: GET probe to see if endpoint exists at all
    let getRes;
    try {
      getRes = await httpGetText({ fetchAdapter, url });
    } catch (e) {
      ctx.log(`[apiExposure] GraphQL GET error: ${e.message || e}`);
      continue;
    }

    // GraphQL usually returns 400 on GET without query, or 200 with error JSON
    const getBody    = getRes.body || '';
    const looksLikeGql = getBody.includes('GraphQL') ||
                         getBody.includes('"errors"') ||
                         getBody.includes('Must provide query string') ||
                         getBody.includes('GET query missing');

    if (getRes.status === 404 && !looksLikeGql) continue;
    if (getRes.status >= 500) continue;

    // Endpoint exists or looks like GraphQL — try introspection via POST
    ctx.log(`[apiExposure] GraphQL endpoint found at ${url} — trying introspection...`);

    let introspectRes;
    try {
      introspectRes = await httpGetText({
        fetchAdapter,
        url,
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    INTROSPECTION_QUERY,
      });
    } catch (e) {
      ctx.log(`[apiExposure] GraphQL introspection error: ${e.message || e}`);
      continue;
    }

    const introspectBody = introspectRes.body || '';
    const introspectionEnabled =
      introspectBody.includes('__schema') &&
      introspectBody.includes('queryType') &&
      !introspectBody.includes('IntrospectionDisabled') &&
      !introspectBody.includes('introspection is disabled');

    if (introspectionEnabled) {
      // Count types for detail
      const typeMatches = introspectBody.match(/"name"\s*:/g);
      const typeCount   = typeMatches ? typeMatches.length : 'unknown';

      ctx.log(`\uD83D\uDFE0 HIGH: GraphQL introspection enabled at ${url} (~${typeCount} types)`);

      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'exposure.api_endpoints',
        title:       'GraphQL Introspection Enabled',
        shortDescription:
          `GraphQL introspection is unauthenticated at ${url}. Full schema is accessible (~${typeCount} types).`,
        detailedDescription:
          'GraphQL introspection is enabled without authentication. ' +
          'This exposes the complete API schema: every query, mutation, subscription, type, field, ' +
          'argument, and relationship. Attackers can use this to map the entire data model and identify ' +
          'dangerous operations (e.g., admin mutations, bulk data queries). ' +
          `Approximately ${typeCount} type name entries found in introspection response. ` +
          'Remediation: Disable introspection in production ' +
          '(Apollo Server: introspection: false, GraphQL Yoga: disableIntrospection plugin). ' +
          'If needed for development, restrict to authenticated users or internal IPs only.',
        severity: 'high',
        category: 'exposure',
        owaspTag: 'A05-Security-Misconfiguration',
        cweTag:   'CWE-200',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(new Evidence({
        findingId:              finding.id,
        url,
        method:                 'POST',
        responseStatus:         introspectRes.status,
        responseHeadersSnippet: JSON.stringify(introspectRes.headers || {}).slice(0, 512),
        responseBodySnippet:    introspectBody.slice(0, 2048),
        matchedPattern:         `GraphQL introspection response contains __schema + queryType`,
      }));
    } else if (looksLikeGql || getRes.status !== 404) {
      // GraphQL endpoint exists but introspection is disabled
      ctx.log(`\uD83D\uDFE1 LOW: GraphQL endpoint found (introspection disabled) at ${url}`);

      const finding = new Finding({
        projectId:   ctx.project.id,
        scanJobId:   ctx.job.id,
        targetId:    target.id,
        moduleId:    'exposure.api_endpoints',
        title:       'GraphQL Endpoint Exposed (Introspection Disabled)',
        shortDescription:
          `GraphQL endpoint detected at ${url}. Introspection is disabled.`,
        detailedDescription:
          'A GraphQL endpoint was detected. Introspection is disabled, which is good practice for production. ' +
          'However, the endpoint\'s existence and approximate structure may still be discoverable ' +
          'through field guessing, error messages, or tooling like Clairvoyance. ' +
          'Ensure authentication is enforced on all GraphQL operations.',
        severity: 'low',
        category: 'exposure',
        owaspTag: 'A05-Security-Misconfiguration',
        cweTag:   'CWE-200',
      });
      ctx.addFinding(finding);
      ctx.addEvidence(new Evidence({
        findingId:              finding.id,
        url,
        method:                 'GET',
        responseStatus:         getRes.status,
        responseHeadersSnippet: JSON.stringify(getRes.headers || {}).slice(0, 512),
        responseBodySnippet:    getBody.slice(0, 1024),
        matchedPattern:         'GraphQL endpoint detected (introspection disabled)',
      }));
    }

    break; // Report first hit only
  }
}
