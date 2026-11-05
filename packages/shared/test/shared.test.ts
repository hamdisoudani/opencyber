import { describe, expect, it } from 'vitest';
import {
  AuditTombstoneSchema,
  buildEndpointKey,
  CanonicalEndpointSchema,
  canonicalizeRoutePath,
  evaluateTargetScope,
  FindingReportSchema,
  isHostAuthorized,
  isPathExcluded,
  normalizeHostname,
  normalizeUrlPath,
  OrchestratorReviewVerdictSchema,
  parseScopeYaml,
  RouteObservationBatchSchema,
  serializeScopeYaml,
  sha256Hex,
  signTaskProxyToken,
  TrafficLedgerEntrySchema,
  verifyTaskProxyToken,
} from '../src/index.js';

describe('scope configuration & target scope evaluation', () => {
  const sampleScopeYaml = `
engagementId: eng-2026-acme
programName: Acme Internal Bug Bounty
authorizedDomains:
  - portal.acme.com
  - "*.acme.internal"
excludedPaths:
  - /admin/destruct/**
  - /auth/logout
maxRpsPerHost: 10
complianceHeaders:
  X-Bug-Bounty: opencyber-aegis
authProfiles:
  viewer:
    description: Read-only viewer session
    headerNames:
      - Authorization
`;

  it('parses and serializes scope YAML with schema defaults', () => {
    const scope = parseScopeYaml(sampleScopeYaml);
    expect(scope.engagementId).toBe('eng-2026-acme');
    expect(scope.programName).toBe('Acme Internal Bug Bounty');
    expect(scope.strictReadOnly).toBe(true);
    expect(scope.maxRpsPerHost).toBe(10);
    expect(scope.authProfiles.viewer?.allowedMethods).toEqual([
      'GET',
      'HEAD',
      'OPTIONS',
    ]);

    const roundTripped = parseScopeYaml(serializeScopeYaml(scope));
    expect(roundTripped).toEqual(scope);
  });

  it('normalizes hostnames including ports, trailing dots, and IPv6', () => {
    expect(normalizeHostname('  API.Acme.Internal:8443 ')).toBe(
      'api.acme.internal',
    );
    expect(normalizeHostname('portal.acme.com.')).toBe('portal.acme.com');
    expect(normalizeHostname('portal.acme.com.:443')).toBe('portal.acme.com');
    expect(normalizeHostname('[::1]:8080')).toBe('[::1]');
    expect(normalizeHostname('[::1]')).toBe('[::1]');
    expect(normalizeHostname('::1')).toBe('::1');
    expect(normalizeHostname('')).toBe('');
  });

  it('enforces exact domain and strict *.domain wildcard matching', () => {
    const scope = parseScopeYaml(sampleScopeYaml);

    // Exact match
    expect(
      evaluateTargetScope('https://portal.acme.com/v1/profile', scope),
    ).toEqual({
      allowed: true,
      normalizedHost: 'portal.acme.com',
      normalizedPath: '/v1/profile',
    });

    // Subdomain wildcard matches
    expect(
      evaluateTargetScope('https://api.acme.internal:8443/v1/health', scope),
    ).toEqual({
      allowed: true,
      normalizedHost: 'api.acme.internal',
      normalizedPath: '/v1/health',
    });
    expect(
      evaluateTargetScope('https://a.b.acme.internal/status', scope).allowed,
    ).toBe(true);

    // Apex of wildcard domain is NOT matched unless explicitly listed
    expect(
      evaluateTargetScope('https://acme.internal/v1/health', scope),
    ).toMatchObject({
      allowed: false,
      reason: 'OUT_OF_SCOPE_HOST',
      normalizedHost: 'acme.internal',
    });

    // Suffix-confusion and subdomain-takeover lookalikes rejected
    expect(
      evaluateTargetScope('https://evilacme.internal/v1/health', scope),
    ).toMatchObject({
      allowed: false,
      reason: 'OUT_OF_SCOPE_HOST',
    });
    expect(
      evaluateTargetScope(
        'https://api.acme.internal.evil.com/v1/health',
        scope,
      ),
    ).toMatchObject({
      allowed: false,
      reason: 'OUT_OF_SCOPE_HOST',
    });

    expect(isHostAuthorized('', scope.authorizedDomains)).toBe(false);
    expect(isHostAuthorized('*.acme.internal', scope.authorizedDomains)).toBe(
      false,
    );
  });

  it('enforces excludedHosts overrides inside wildcard authorizedDomains', () => {
    const scopeWithExclusions = parseScopeYaml(`
engagementId: eng-bugcrowd-001
programName: Bugcrowd Target Brief
authorizedDomains:
  - "*.acme.internal"
  - acme.internal
excludedHosts:
  - blog.acme.internal
  - "*.marketing.acme.internal"
`);

    expect(
      evaluateTargetScope('https://api.acme.internal/v1/status', scopeWithExclusions),
    ).toMatchObject({
      allowed: true,
      normalizedHost: 'api.acme.internal',
    });

    expect(
      evaluateTargetScope('https://blog.acme.internal/posts', scopeWithExclusions),
    ).toMatchObject({
      allowed: false,
      reason: 'EXCLUDED_HOST',
      normalizedHost: 'blog.acme.internal',
    });

    expect(
      evaluateTargetScope(
        'https://promo.marketing.acme.internal/landing',
        scopeWithExclusions,
      ),
    ).toMatchObject({
      allowed: false,
      reason: 'EXCLUDED_HOST',
      normalizedHost: 'promo.marketing.acme.internal',
    });
  });

  it('prevents path traversal and percent-encoded bypasses on excludedPaths', () => {
    const scope = parseScopeYaml(sampleScopeYaml);

    // Direct excluded path and exact base directory
    expect(
      evaluateTargetScope('https://api.acme.internal/admin/destruct/db', scope),
    ).toMatchObject({
      allowed: false,
      reason: 'EXCLUDED_PATH',
      normalizedPath: '/admin/destruct/db',
    });
    expect(
      evaluateTargetScope('https://api.acme.internal/admin/destruct', scope),
    ).toMatchObject({
      allowed: false,
      reason: 'EXCLUDED_PATH',
      normalizedPath: '/admin/destruct',
    });

    // Dot-segment path traversal
    expect(
      evaluateTargetScope(
        'https://api.acme.internal/public/../../admin/destruct/db',
        scope,
      ),
    ).toMatchObject({
      allowed: false,
      reason: 'EXCLUDED_PATH',
      normalizedPath: '/admin/destruct/db',
    });

    // Percent-encoded %2e%2e and %2f traversal
    expect(
      evaluateTargetScope(
        'https://api.acme.internal/public/%2e%2e/%2e%2e/admin/destruct/db',
        scope,
      ),
    ).toMatchObject({
      allowed: false,
      reason: 'EXCLUDED_PATH',
      normalizedPath: '/admin/destruct/db',
    });
    expect(
      evaluateTargetScope(
        'https://api.acme.internal/admin%2fpublic%2f..%2fdestruct%2frun',
        scope,
      ),
    ).toMatchObject({
      allowed: false,
      reason: 'EXCLUDED_PATH',
      normalizedPath: '/admin/destruct/run',
    });

    // Scheme-relative double-slash path normalization safety
    expect(normalizeUrlPath('//admin/destruct/run')).toBe(
      '/admin/destruct/run',
    );
    expect(isPathExcluded('//admin/destruct/run', scope.excludedPaths)).toBe(
      true,
    );

    // Malformed percent-encoding does not throw
    expect(normalizeUrlPath('/v1/%E0%A4%A/items//list')).toBe(
      '/v1/%E0%A4%A/items/list',
    );
  });

  it('rejects non-http(s) protocols and invalid URLs', () => {
    const scope = parseScopeYaml(sampleScopeYaml);

    expect(
      evaluateTargetScope('ftp://portal.acme.com/pub/file.txt', scope),
    ).toEqual({
      allowed: false,
      reason: 'INVALID_URL',
      normalizedHost: '',
      normalizedPath: '',
    });

    expect(evaluateTargetScope('file:///etc/passwd', scope)).toEqual({
      allowed: false,
      reason: 'INVALID_URL',
      normalizedHost: '',
      normalizedPath: '',
    });

    expect(evaluateTargetScope('not a valid url', scope)).toEqual({
      allowed: false,
      reason: 'INVALID_URL',
      normalizedHost: '',
      normalizedPath: '',
    });
  });
});

describe('route canonicalization & deterministic endpoint keys', () => {
  it('collapses numeric, Express, OpenAPI, UUID, Next.js, Flask, and hex dynamic segments to identical endpointId and fileName', () => {
    const kNumeric = buildEndpointKey(
      'api.acme.internal',
      'GET',
      '/v1/users/42/roles',
    );
    const kExpress = buildEndpointKey(
      'API.Acme.Internal:443',
      'get',
      '/v1/users/:userId/roles?include=permissions#top',
    );
    const kOpenApi = buildEndpointKey(
      'api.acme.internal',
      'GET',
      '/v1/users/{id}/roles/',
    );
    const kUuid = buildEndpointKey(
      'api.acme.internal',
      'GET',
      '/v1/users/550e8400-e29b-41d4-a716-446655440000/roles',
    );
    const kNextJs = buildEndpointKey(
      'api.acme.internal',
      'GET',
      '/v1/users/[userId]/roles',
    );
    const kFlask = buildEndpointKey(
      'api.acme.internal',
      'GET',
      '/v1/users/<int:user_id>/roles',
    );
    const kHexId = buildEndpointKey(
      'api.acme.internal',
      'GET',
      '/v1/users/507f1f77bcf86cd799439011/roles',
    );

    expect(kNumeric.canonicalPath).toBe('/v1/users/{param}/roles');
    expect(kNumeric.endpointId).toBe(
      'api.acme.internal:GET:/v1/users/{param}/roles',
    );

    for (const candidate of [
      kExpress,
      kOpenApi,
      kUuid,
      kNextJs,
      kFlask,
      kHexId,
    ]) {
      expect(candidate.endpointId).toBe(kNumeric.endpointId);
      expect(candidate.fileName).toBe(kNumeric.fileName);
      expect(candidate.repoRelativePath).toBe(kNumeric.repoRelativePath);
    }

    expect(kNumeric.repoRelativePath).toMatch(
      /^surface\/hosts\/api\.acme\.internal\/endpoints\/GET_v1_users_param_roles_[0-9a-f]{8}\.yaml$/,
    );
  });

  it('produces distinct fileNames for /v1/org_settings vs /v1/org/settings via hash8', () => {
    const underscoreKey = buildEndpointKey(
      'api.acme.internal',
      'GET',
      '/v1/org_settings',
    );
    const slashKey = buildEndpointKey(
      'api.acme.internal',
      'GET',
      '/v1/org/settings',
    );

    expect(underscoreKey.endpointId).not.toBe(slashKey.endpointId);
    expect(underscoreKey.fileName).not.toBe(slashKey.fileName);
  });

  it('handles root path and counts multiple dynamic parameters accurately', () => {
    expect(canonicalizeRoutePath('/')).toEqual({
      canonicalPath: '/',
      paramCount: 0,
    });

    const rootKey = buildEndpointKey('api.acme.internal', 'GET', '/');
    expect(rootKey.fileName).toMatch(/^GET_root_[0-9a-f]{8}\.yaml$/);

    expect(
      canonicalizeRoutePath('/orgs/:orgId/projects/{projectId}/runs/99'),
    ).toEqual({
      canonicalPath: '/orgs/{param}/projects/{param}/runs/{param}',
      paramCount: 3,
    });
  });
});

describe('SHA-256 & HMAC task proxy tokens', () => {
  const testSecret = 'test-hmac-signing-key-at-least-16-bytes';

  it('computes deterministic sha256Hex for strings and Uint8Array', () => {
    const strHash = sha256Hex('opencyber');
    const bufHash = sha256Hex(new TextEncoder().encode('opencyber'));
    expect(strHash).toBe(bufHash);
    expect(strHash).toHaveLength(64);
  });

  it('signs and verifies valid tokens, and rejects tampered, wrong-secret, or expired tokens', () => {
    const nowMs = 1_750_000_000_000;
    const payload = {
      taskId: 'task-audit-001',
      engagementId: 'eng-2026-acme',
      fencingToken: 7,
      allowedAuthProfiles: ['viewer'],
      expiresAtMs: nowMs + 60_000,
    };

    const token = signTaskProxyToken(payload, testSecret);
    const verified = verifyTaskProxyToken(token, testSecret, nowMs);
    expect(verified).toEqual({ valid: true, payload });

    // Tampered payload
    const [, sig] = token.split('.');
    const tamperedPayload = Buffer.from(
      JSON.stringify({ ...payload, fencingToken: 99 }),
      'utf8',
    ).toString('base64url');
    const tamperedResult = verifyTaskProxyToken(
      `${tamperedPayload}.${sig}`,
      testSecret,
      nowMs,
    );
    expect(tamperedResult).toEqual({
      valid: false,
      reason: 'INVALID_SIGNATURE',
    });

    // Wrong secret
    const wrongSecretResult = verifyTaskProxyToken(
      token,
      'different-signing-key-at-least-16-bytes',
      nowMs,
    );
    expect(wrongSecretResult).toEqual({
      valid: false,
      reason: 'INVALID_SIGNATURE',
    });

    // Expired token (exact boundary and past boundary)
    expect(verifyTaskProxyToken(token, testSecret, nowMs + 60_000)).toEqual({
      valid: false,
      reason: 'TOKEN_EXPIRED',
    });
    expect(verifyTaskProxyToken(token, testSecret, nowMs + 120_000)).toEqual({
      valid: false,
      reason: 'TOKEN_EXPIRED',
    });

    // Short secret handling
    expect(() => signTaskProxyToken(payload, 'short')).toThrow();
    expect(verifyTaskProxyToken(token, 'short', nowMs)).toEqual({
      valid: false,
      reason: 'INVALID_SECRET',
    });

    // Malformed token strings
    expect(verifyTaskProxyToken('no-dot-separator', testSecret, nowMs)).toEqual(
      {
        valid: false,
        reason: 'MALFORMED_TOKEN',
      },
    );
    expect(verifyTaskProxyToken('a.b.c', testSecret, nowMs)).toEqual({
      valid: false,
      reason: 'MALFORMED_TOKEN',
    });
  });
});

describe('entity Zod schemas', () => {
  it('validates FindingReportSchema and enforces findingId format', () => {
    const validFinding = FindingReportSchema.parse({
      findingId: 'AUD-001-missing-csp-header',
      title: 'Missing Content-Security-Policy on API portal',
      category: 'MISSING_SECURITY_HEADERS',
      severity: 'MEDIUM',
      host: 'portal.acme.com',
      endpointId: 'portal.acme.com:GET:/v1/profile',
      summary: 'Portal responses omit Content-Security-Policy headers.',
      architecturalAnalysis:
        'Gateway reverse proxy does not inject baseline response headers.',
      remediation:
        'Configure strict Content-Security-Policy headers at the edge proxy.',
      createdAt: '2026-11-05T00:00:00.000Z',
    });

    expect(validFinding.status).toBe('PENDING_HUMAN_REVIEW');
    expect(validFinding.evidencePointers).toEqual([]);

    expect(() =>
      FindingReportSchema.parse({
        ...validFinding,
        findingId: 'INVALID-ID',
      }),
    ).toThrow();
  });

  it('validates RouteObservationBatchSchema, OrchestratorReviewVerdictSchema, and supporting entities', () => {
    const batch = RouteObservationBatchSchema.parse({
      runId: 'run-101',
      agentRole: 'STATIC_JS_AST',
      createdAt: '2026-11-05T00:00:00.000Z',
      hosts: [
        {
          hostname: 'api.acme.internal',
          discoveredAt: '2026-11-05T00:00:00.000Z',
        },
      ],
      endpoints: [
        {
          host: 'api.acme.internal',
          method: 'GET',
          rawPath: '/v1/users/:id',
          source: 'bundle-main.js',
        },
      ],
    });
    expect(batch.endpoints[0]?.parameters).toEqual([]);
    expect(batch.hosts[0]?.securityHeaders).toEqual({});

    const verdict = OrchestratorReviewVerdictSchema.parse({
      decision: 'APPROVE_MERGE',
      confidence: 0.94,
      rationale: 'Verified deterministic evidence blob matches header posture.',
    });
    expect(verdict.decision).toBe('APPROVE_MERGE');

    expect(() =>
      OrchestratorReviewVerdictSchema.parse({
        decision: 'APPROVE_MERGE',
        confidence: 1.5,
        rationale: 'Confidence out of range',
      }),
    ).toThrow();

    const canonicalEndpoint = CanonicalEndpointSchema.parse({
      endpointId: 'api.acme.internal:GET:/v1/users/{param}',
      host: 'api.acme.internal',
      method: 'GET',
      canonicalPath: '/v1/users/{param}',
      firstSeenAt: '2026-11-05T00:00:00.000Z',
      lastUpdatedAt: '2026-11-05T00:00:00.000Z',
    });
    expect(canonicalEndpoint.observedRawPaths).toEqual([]);

    const tombstone = AuditTombstoneSchema.parse({
      endpointId: 'api.acme.internal:GET:/v1/health',
      host: 'api.acme.internal',
      method: 'GET',
      canonicalPath: '/v1/health',
      evaluatedAt: '2026-11-05T00:00:00.000Z',
      evaluatedByTask: 'task-001',
      status: 'COMPLIANT',
    });
    expect(tombstone.notes).toBe('');

    const ledgerEntry = TrafficLedgerEntrySchema.parse({
      id: 'req-001',
      timestamp: '2026-11-05T00:00:00.000Z',
      engagementId: 'eng-2026-acme',
      taskId: 'task-001',
      fencingToken: 1,
      method: 'GET',
      url: 'https://api.acme.internal/v1/health',
      host: 'api.acme.internal',
      pathname: '/v1/health',
      decision: 'ALLOWED',
      upstreamStatus: 200,
      durationMs: 14.2,
    });
    expect(ledgerEntry.decision).toBe('ALLOWED');
  });
});
