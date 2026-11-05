import type { ManagedSandboxSession } from '@opencyber/sandbox-runner';
import {
  type AuditTombstone,
  AuditTombstoneSchema,
  type CanonicalEndpoint,
  type FindingCategory,
  type FindingReport,
  FindingReportSchema,
  type Severity,
  sha256Hex,
  type TrafficEvidencePointer,
} from '@opencyber/shared';
import { z } from 'zod';
import type { StructuredLlmClient } from './groq-client.js';
import { PromptGuardSanitizer } from './prompt-guard.js';
import type { GovernedRequestOptions, GovernedResponse, HttpFetcher } from './types.js';

export interface AuditEndpointPostureOptions {
  taskId: string;
  findingSeq: number;
  endpoint: CanonicalEndpoint;
  baseUrl: string;
  fetcher: HttpFetcher;
  sandbox?: ManagedSandboxSession;
  llmClient?: StructuredLlmClient;
  groqClient?: StructuredLlmClient;
  promptGuard?: PromptGuardSanitizer;
  availableAuthProfiles?: string[];
}

export type AuditEndpointPostureResult =
  | {
      outcome: 'FINDING';
      finding: FindingReport;
      verificationPythonScript: string;
      verificationPassed: boolean;
    }
  | {
      outcome: 'COMPLIANT';
      tombstone: AuditTombstone;
    };

const PROBE_UNTRUSTED_ORIGIN = 'https://external-untrusted.example';

const PRIVILEGED_PATH_RE =
  /\/(?:admin|org\/settings|internal|audit|billing|secrets|roles|permissions)(?:\/|$)/i;

const PRIVILEGED_JSON_KEYS = new Set<string>([
  'admin',
  'apikey',
  'api_key',
  'auditlogs',
  'audit_logs',
  'billing',
  'credentials',
  'internal',
  'members',
  'orgsettings',
  'org_settings',
  'permissions',
  'roles',
  'secret',
  'secrets',
  'sso',
  'tokens',
  'users',
]);

const SubagentFindingDraftSchema = z.object({
  title: z.string().min(5),
  summary: z.string().min(15),
  architecturalAnalysis: z.string().min(15),
  remediation: z.string().min(15),
});

interface RecordedProbe {
  method: 'GET' | 'HEAD' | 'OPTIONS';
  url: string;
  authProfile?: string;
  status: number;
  lowerHeaders: Record<string, string>;
  bodyText: string;
  pointer: TrafficEvidencePointer;
}

interface DetectedPostureIssue {
  category: FindingCategory;
  severity: Severity;
  slugHint: string;
  defaultTitle: string;
  defaultSummary: string;
  defaultArchitecturalAnalysis: string;
  defaultRemediation: string;
  observedMetadataForLlm: string;
  verificationPayload: Record<string, unknown>;
  evidenceProbes: RecordedProbe[];
}

function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (typeof v === 'string') {
      out[k.toLowerCase()] = v.trim();
    }
  }
  return out;
}

function buildConcreteTargetUrl(baseUrl: string, endpoint: CanonicalEndpoint): string {
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const concreteCandidate = endpoint.observedRawPaths.find(
    (p) => p.startsWith('/') && !p.includes('{param}') && !p.includes(':param'),
  );
  const pathTemplate = concreteCandidate ?? endpoint.canonicalPath;
  const materializedPath = pathTemplate
    .replace(/\{[^}/]+\}/g, '1')
    .replace(/:[A-Za-z_][A-Za-z0-9_]*/g, '1');
  const normalizedPath = materializedPath.startsWith('/')
    ? materializedPath
    : `/${materializedPath}`;
  return `${cleanBase}${normalizedPath}`;
}

function extractTopLevelJsonKeys(bodyText: string): string[] {
  try {
    const parsed: unknown = JSON.parse(bodyText);
    if (Array.isArray(parsed)) {
      const firstObj = parsed.find(
        (item): item is Record<string, unknown> =>
          typeof item === 'object' && item !== null && !Array.isArray(item),
      );
      return firstObj ? Object.keys(firstObj).sort() : [];
    }
    if (typeof parsed === 'object' && parsed !== null) {
      return Object.keys(parsed as Record<string, unknown>).sort();
    }
    return [];
  } catch {
    return [];
  }
}

function buildPythonVerificationScript(payload: Record<string, unknown>): string {
  // Double-stringify produces a 100% safe ASCII/UTF-8 Python string literal for json.loads(...)
  const safeJsonLiteral = JSON.stringify(JSON.stringify(payload)).replace(/\\\//g, '/');

  return [
    'import json',
    'import sys',
    '',
    `OBSERVED = json.loads(${safeJsonLiteral})`,
    'category = OBSERVED.get("category")',
    'confirmed = False',
    '',
    'if category == "PERMISSIVE_CORS":',
    '    headers = {k.lower(): str(v).strip() for k, v in OBSERVED.get("headers", {}).items()}',
    '    acao = headers.get("access-control-allow-origin", "")',
    '    acac = headers.get("access-control-allow-credentials", "").lower() == "true"',
    '    probe_origin = OBSERVED.get("probeOrigin", "https://external-untrusted.example")',
    '    auth_context = bool(OBSERVED.get("authenticatedSurface", False))',
    '    confirmed = ((acao == probe_origin or acao == "*") and acac) or (acao == probe_origin and auth_context)',
    'elif category == "AUTHZ_SCHEMA_DRIFT":',
    '    low_status = int(OBSERVED.get("lowPrivilegeStatus", 0))',
    '    low_keys = set(OBSERVED.get("lowPrivilegeKeys", []))',
    '    high_keys = set(OBSERVED.get("highPrivilegeKeys", []))',
    '    privileged_path = bool(OBSERVED.get("privilegedPath", False))',
    '    confirmed = low_status == 200 and (privileged_path or (len(high_keys) > 0 and len(low_keys & high_keys) > 0))',
    'elif category == "MISSING_SECURITY_HEADERS":',
    '    status = int(OBSERVED.get("status", 0))',
    '    headers = {k.lower(): str(v).strip() for k, v in OBSERVED.get("headers", {}).items()}',
    '    has_hsts = bool(headers.get("strict-transport-security"))',
    '    has_csp = bool(headers.get("content-security-policy"))',
    '    has_nosniff = bool(headers.get("x-content-type-options"))',
    '    confirmed = status == 200 and (not has_hsts) and (not has_csp) and (not has_nosniff)',
    '',
    'print(json.dumps({"category": category, "confirmed": confirmed}))',
    'sys.exit(0 if confirmed else 1)',
  ].join('\n');
}

function buildFindingId(findingSeq: number, slugSource: string): string {
  const cleanSlug =
    slugSource
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 42)
      .replace(/-+$/, '') || 'posture-issue';

  return `AUD-${String(findingSeq).padStart(3, '0')}-${cleanSlug}`;
}

export async function auditEndpointPosture(
  opts: AuditEndpointPostureOptions,
): Promise<AuditEndpointPostureResult> {
  const targetUrl = buildConcreteTargetUrl(opts.baseUrl, opts.endpoint);
  const isReadOnlyMethod =
    opts.endpoint.method === 'GET' ||
    opts.endpoint.method === 'HEAD' ||
    opts.endpoint.method === 'OPTIONS';

  const recordedProbes: RecordedProbe[] = [];

  const performGovernedProbe = async (
    method: 'GET' | 'HEAD' | 'OPTIONS',
    reqOpts?: Omit<GovernedRequestOptions, 'method'>,
  ): Promise<RecordedProbe> => {
    const res: GovernedResponse = await opts.fetcher.request(targetUrl, {
      method,
      ...(reqOpts?.headers ? { headers: reqOpts.headers } : {}),
      ...(reqOpts?.authProfile ? { authProfile: reqOpts.authProfile } : {}),
    });

    const lowerHeaders = normalizeHeaders(res.headers);
    const capturedAt = new Date().toISOString();
    const effectiveSha =
      res.harSha256 && res.harSha256.length >= 16
        ? res.harSha256
        : sha256Hex(
            JSON.stringify({
              method,
              targetUrl,
              authProfile: reqOpts?.authProfile ?? null,
              status: res.status,
              headers: lowerHeaders,
              bodyPreview: res.bodyText.slice(0, 2048),
            }),
          );

    const pointer: TrafficEvidencePointer = {
      sha256: effectiveSha,
      blobPath: `evidence/blobs/${effectiveSha.slice(0, 2)}/${effectiveSha}.har.json`,
      requestUrl: targetUrl,
      method,
      statusCode: res.status,
      capturedAt,
      ...(reqOpts?.authProfile ? { authProfileUsed: reqOpts.authProfile } : {}),
    };

    const probe: RecordedProbe = {
      method,
      url: targetUrl,
      ...(reqOpts?.authProfile ? { authProfile: reqOpts.authProfile } : {}),
      status: res.status,
      lowerHeaders,
      bodyText: res.bodyText,
      pointer,
    };
    recordedProbes.push(probe);
    return probe;
  };

  // 1. Safe OPTIONS CORS preflight check (always read-only, safe for all HTTP methods)
  const optionsProbe = await performGovernedProbe('OPTIONS', {
    headers: {
      Origin: PROBE_UNTRUSTED_ORIGIN,
      'Access-Control-Request-Method': opts.endpoint.method,
    },
  });

  // 2. If endpoint is read-only (GET / HEAD), perform baseline read-only request with Origin header
  let baselineReadProbe: RecordedProbe | undefined;
  if (isReadOnlyMethod && opts.endpoint.method !== 'OPTIONS') {
    const readMethod: 'GET' | 'HEAD' = opts.endpoint.method === 'HEAD' ? 'HEAD' : 'GET';
    baselineReadProbe = await performGovernedProbe(readMethod, {
      headers: { Origin: PROBE_UNTRUSTED_ORIGIN },
    });
  }

  const profiles = opts.availableAuthProfiles ?? [];
  const authenticatedSurface = opts.endpoint.authRequired === true || profiles.length > 0;

  let detected: DetectedPostureIssue | undefined;

  // --- CHECK 1: PERMISSIVE_CORS (HIGH) ---
  const corsCandidates = baselineReadProbe ? [optionsProbe, baselineReadProbe] : [optionsProbe];
  for (const cand of corsCandidates) {
    const acao = cand.lowerHeaders['access-control-allow-origin'] ?? '';
    const acac = cand.lowerHeaders['access-control-allow-credentials']?.toLowerCase() === 'true';

    const credentialedLeak = (acao === PROBE_UNTRUSTED_ORIGIN || acao === '*') && acac;
    const untrustedReflectionOnAuthApi = acao === PROBE_UNTRUSTED_ORIGIN && authenticatedSurface;

    if (credentialedLeak || untrustedReflectionOnAuthApi) {
      detected = {
        category: 'PERMISSIVE_CORS',
        severity: 'HIGH',
        slugHint: `cors-${opts.endpoint.host}-${opts.endpoint.canonicalPath}`,
        defaultTitle: `Permissive CORS Origin Trust on ${opts.endpoint.method} ${opts.endpoint.canonicalPath}`,
        defaultSummary: `Endpoint ${opts.endpoint.endpointId} returned Access-Control-Allow-Origin: "${acao}"${acac ? ' with Access-Control-Allow-Credentials: true' : ''} when probed with untrusted Origin "${PROBE_UNTRUSTED_ORIGIN}".`,
        defaultArchitecturalAnalysis: `Allowing arbitrary cross-origin origins${acac ? ' alongside credentialed requests' : ' on an authenticated API surface'} weakens the browser Same-Origin Policy boundary on ${opts.endpoint.host} and permits untrusted origins to read cross-origin API responses.`,
        defaultRemediation: `Configure strict explicit origin allowlisting on ${opts.endpoint.host} for ${opts.endpoint.canonicalPath}, never reflect arbitrary Origin headers dynamically, and avoid pairing wildcard or untrusted origins with Access-Control-Allow-Credentials: true.`,
        observedMetadataForLlm: JSON.stringify(
          {
            endpointId: opts.endpoint.endpointId,
            probeMethod: cand.method,
            status: cand.status,
            probeOrigin: PROBE_UNTRUSTED_ORIGIN,
            responseHeaders: cand.lowerHeaders,
          },
          null,
          2,
        ),
        verificationPayload: {
          category: 'PERMISSIVE_CORS',
          status: cand.status,
          probeOrigin: PROBE_UNTRUSTED_ORIGIN,
          authenticatedSurface,
          headers: cand.lowerHeaders,
        },
        evidenceProbes: [cand],
      };
      break;
    }
  }

  // --- CHECK 2: AUTHZ_SCHEMA_DRIFT (HIGH) ---
  if (!detected && isReadOnlyMethod && opts.endpoint.method === 'GET') {
    const highProfile = profiles.find((p) => /admin|owner|super/i.test(p));
    const lowProfile =
      profiles.find((p) => /viewer|guest|readonly|member|user/i.test(p) && p !== highProfile) ??
      profiles.find((p) => p !== highProfile);
    const isPrivilegedPath = PRIVILEGED_PATH_RE.test(opts.endpoint.canonicalPath);

    if (highProfile && lowProfile) {
      const [highProbe, lowProbe] = await Promise.all([
        performGovernedProbe('GET', { authProfile: highProfile }),
        performGovernedProbe('GET', { authProfile: lowProfile }),
      ]);

      const highKeys = extractTopLevelJsonKeys(highProbe.bodyText);
      const lowKeys = extractTopLevelJsonKeys(lowProbe.bodyText);
      const sharedKeys = lowKeys.filter((k) => highKeys.includes(k));
      const hasPrivilegedSchemaKeys = lowKeys.some((k) =>
        PRIVILEGED_JSON_KEYS.has(k.toLowerCase()),
      );

      if (
        lowProbe.status === 200 &&
        highProbe.status === 200 &&
        (isPrivilegedPath ||
          (sharedKeys.length > 0 && (hasPrivilegedSchemaKeys || opts.endpoint.authRequired)))
      ) {
        detected = {
          category: 'AUTHZ_SCHEMA_DRIFT',
          severity: 'HIGH',
          slugHint: `authz-drift-${opts.endpoint.host}-${opts.endpoint.canonicalPath}`,
          defaultTitle: `Authorization Boundary Drift on ${opts.endpoint.canonicalPath} (${lowProfile} vs ${highProfile})`,
          defaultSummary: `Lower-privilege profile "${lowProfile}" received HTTP 200 on ${opts.endpoint.endpointId} with top-level JSON schema [${lowKeys.join(', ')}] matching privileged "${highProfile}" response.`,
          defaultArchitecturalAnalysis: `Role-based access control middleware on ${opts.endpoint.host} fails to enforce privilege separation on ${opts.endpoint.canonicalPath}, allowing "${lowProfile}" callers to read administrative or tenant-sensitive schema fields.`,
          defaultRemediation: `Enforce explicit server-side role authorization guards on ${opts.endpoint.canonicalPath} so non-administrative profiles such as "${lowProfile}" receive HTTP 403 Forbidden and sensitive fields are filtered by role.`,
          observedMetadataForLlm: JSON.stringify(
            {
              endpointId: opts.endpoint.endpointId,
              lowProfile,
              lowPrivilegeStatus: lowProbe.status,
              lowPrivilegeKeys: lowKeys,
              highProfile,
              highPrivilegeStatus: highProbe.status,
              highPrivilegeKeys: highKeys,
            },
            null,
            2,
          ),
          verificationPayload: {
            category: 'AUTHZ_SCHEMA_DRIFT',
            lowPrivilegeStatus: lowProbe.status,
            lowPrivilegeKeys: lowKeys,
            highPrivilegeKeys: highKeys.length > 0 ? highKeys : lowKeys,
            privilegedPath: isPrivilegedPath,
          },
          evidenceProbes: [highProbe, lowProbe],
        };
      }
    } else if (isPrivilegedPath && baselineReadProbe && baselineReadProbe.status === 200) {
      const unauthKeys = extractTopLevelJsonKeys(baselineReadProbe.bodyText);
      let adminKeys = unauthKeys;
      const probesForEvidence: RecordedProbe[] = [baselineReadProbe];

      if (highProfile) {
        const highProbe = await performGovernedProbe('GET', { authProfile: highProfile });
        adminKeys = extractTopLevelJsonKeys(highProbe.bodyText);
        probesForEvidence.push(highProbe);
      }

      if (unauthKeys.length > 0 || baselineReadProbe.bodyText.trim().length > 0) {
        detected = {
          category: 'AUTHZ_SCHEMA_DRIFT',
          severity: 'HIGH',
          slugHint: `unauth-admin-${opts.endpoint.host}-${opts.endpoint.canonicalPath}`,
          defaultTitle: `Unauthenticated Access to Privileged Endpoint ${opts.endpoint.canonicalPath}`,
          defaultSummary: `Unauthenticated GET request to privileged endpoint ${opts.endpoint.endpointId} returned HTTP 200 with schema keys [${unauthKeys.join(', ')}].`,
          defaultArchitecturalAnalysis: `Administrative or internal configuration route ${opts.endpoint.canonicalPath} on ${opts.endpoint.host} is exposed without authentication enforcement at the gateway or controller layer.`,
          defaultRemediation: `Require authenticated session/token verification and administrative role authorization middleware on ${opts.endpoint.canonicalPath}, returning HTTP 401/403 to unauthenticated callers.`,
          observedMetadataForLlm: JSON.stringify(
            {
              endpointId: opts.endpoint.endpointId,
              unauthenticatedStatus: baselineReadProbe.status,
              unauthenticatedKeys: unauthKeys,
              privilegedPath: true,
            },
            null,
            2,
          ),
          verificationPayload: {
            category: 'AUTHZ_SCHEMA_DRIFT',
            lowPrivilegeStatus: baselineReadProbe.status,
            lowPrivilegeKeys: unauthKeys,
            highPrivilegeKeys: adminKeys,
            privilegedPath: true,
          },
          evidenceProbes: probesForEvidence,
        };
      }
    }
  }

  // --- CHECK 3: MISSING_SECURITY_HEADERS (MEDIUM) ---
  if (!detected && baselineReadProbe && baselineReadProbe.status === 200) {
    const hdrs = baselineReadProbe.lowerHeaders;
    const hasHsts = Boolean(hdrs['strict-transport-security']);
    const hasCsp = Boolean(hdrs['content-security-policy']);
    const hasNosniff = Boolean(hdrs['x-content-type-options']);

    if (!hasHsts && !hasCsp && !hasNosniff) {
      detected = {
        category: 'MISSING_SECURITY_HEADERS',
        severity: 'MEDIUM',
        slugHint: `missing-headers-${opts.endpoint.host}-${opts.endpoint.canonicalPath}`,
        defaultTitle: `Missing Critical HTTP Security Headers on ${opts.endpoint.canonicalPath}`,
        defaultSummary: `HTTP 200 response from ${opts.endpoint.endpointId} omits Strict-Transport-Security, Content-Security-Policy, and X-Content-Type-Options defensive headers.`,
        defaultArchitecturalAnalysis: `Omitting transport and browser defensive response headers across ${opts.endpoint.host} leaves responses without HSTS downgrade protection, CSP framing/script restrictions, and MIME-sniffing mitigations.`,
        defaultRemediation: `Configure gateway or application response middleware on ${opts.endpoint.host} to emit Strict-Transport-Security (max-age=63072000; includeSubDomains), a restrictive Content-Security-Policy, and X-Content-Type-Options: nosniff.`,
        observedMetadataForLlm: JSON.stringify(
          {
            endpointId: opts.endpoint.endpointId,
            status: baselineReadProbe.status,
            responseHeaders: hdrs,
          },
          null,
          2,
        ),
        verificationPayload: {
          category: 'MISSING_SECURITY_HEADERS',
          status: baselineReadProbe.status,
          headers: hdrs,
        },
        evidenceProbes: [baselineReadProbe],
      };
    }
  }

  // If no posture defect was detected, return a validated COMPLIANT AuditTombstone
  if (!detected) {
    const tombstone = AuditTombstoneSchema.parse({
      endpointId: opts.endpoint.endpointId,
      host: opts.endpoint.host,
      method: opts.endpoint.method,
      canonicalPath: opts.endpoint.canonicalPath,
      evaluatedAt: new Date().toISOString(),
      evaluatedByTask: opts.taskId,
      status: 'COMPLIANT',
      notes: `Evaluated ${recordedProbes.length} read-only posture check(s); CORS, authorization boundaries, and defensive headers are compliant.`,
    });

    return {
      outcome: 'COMPLIANT',
      tombstone,
    };
  }

  // Build deterministic Python verification script and optionally execute inside sandbox
  const verificationPythonScript = buildPythonVerificationScript(detected.verificationPayload);
  let verificationPassed = true;
  if (opts.sandbox) {
    const sandboxResult = await opts.sandbox.runPythonVerification(verificationPythonScript);
    verificationPassed = sandboxResult.passed;
  }

  let title = detected.defaultTitle;
  let summary = detected.defaultSummary;
  let architecturalAnalysis = detected.defaultArchitecturalAnalysis;
  let remediation = detected.defaultRemediation;

  const client = opts.llmClient ?? opts.groqClient;
  if (client) {
    const guard =
      opts.promptGuard ?? new PromptGuardSanitizer({ llmClient: client });
    const sanitizedMeta = await guard.inspectAndSanitize(detected.observedMetadataForLlm);

    try {
      const enriched = await client.completeJson({
        tier: 'SUBAGENT',
        systemPrompt: [
          'You are an OpenCyber defensive security posture auditor drafting a concise, accurate FindingReport in JSON format.',
          'Never invent exploit steps; focus strictly on defensive configuration posture, root architectural cause, and actionable remediation.',
          'Return ONLY a JSON object with exact string fields: "title", "summary", "architecturalAnalysis", "remediation" (each at least 20 characters).',
        ].join(' '),
        userPrompt: [
          `Category: ${detected.category}`,
          `Severity: ${detected.severity}`,
          `Host: ${opts.endpoint.host}`,
          `Endpoint: ${opts.endpoint.method} ${opts.endpoint.canonicalPath}`,
          `Sandbox Verification Passed: ${verificationPassed}`,
          'Sanitized Observed HTTP Metadata:',
          sanitizedMeta.sanitizedText,
        ].join('\n'),
        schema: SubagentFindingDraftSchema,
        temperature: 0.1,
      });

      title = enriched.title;
      summary = enriched.summary;
      architecturalAnalysis = enriched.architecturalAnalysis;
      remediation = enriched.remediation;
    } catch {
      // Retain deterministic posture report text if subagent LLM is unreachable
    }
  }

  const finding = FindingReportSchema.parse({
    findingId: buildFindingId(opts.findingSeq, detected.slugHint),
    title,
    category: detected.category,
    severity: detected.severity,
    host: opts.endpoint.host,
    endpointId: opts.endpoint.endpointId,
    summary,
    architecturalAnalysis,
    remediation,
    reproducibleCheckFile: 'checks/verify_posture.py',
    evidencePointers: detected.evidenceProbes.map((p) => p.pointer),
    status: 'PENDING_HUMAN_REVIEW',
    createdAt: new Date().toISOString(),
  });

  return {
    outcome: 'FINDING',
    finding,
    verificationPythonScript,
    verificationPassed,
  };
}
