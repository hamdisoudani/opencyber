import { randomUUID } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  ScopeConfigSchema,
  TrafficEvidencePointerSchema,
  TrafficLedgerEntrySchema,
  sha256Hex,
  signTaskProxyToken,
  type ScopeConfig,
  type TrafficEvidencePointer,
  type TrafficLedgerEntry,
} from '@opencyber/shared';
import {
  EgressGateway,
  GovernedHttpClient,
  REDACTED_BY_SESSION_VAULT,
  SessionVault,
} from '../src/index.js';

interface RecordedUpstreamRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
}

describe('@opencyber/egress-gateway', () => {
  let upstreamServer: http.Server;
  let upstreamUrl: string;
  let upstreamRequests: RecordedUpstreamRequest[];
  let gateway: EgressGateway | null = null;

  const hmacSecret = `hmac-test-key-${randomUUID()}`;
  const syntheticViewerCookieVal = `viewer_sid_${randomUUID()}`;
  const syntheticAdminCookieVal = `admin_sid_${randomUUID()}`;
  const syntheticUpstreamSetCookie = `rotated_sid_${randomUUID()}; HttpOnly; Secure`;

  function buildScope(overrides?: Partial<ScopeConfig>): ScopeConfig {
    return ScopeConfigSchema.parse({
      engagementId: 'eng-acme-2026',
      programName: 'Acme Bug Bounty Read-Only Audit',
      authorizedDomains: ['api.acme.internal', '*.acme.internal'],
      excludedPaths: ['/admin/destruct/**', '/internal/billing/**'],
      maxRpsPerHost: 20,
      complianceHeaders: {
        'X-Aegis-Researcher': 'aegis-audit-bot@acme.example',
      },
      authProfiles: {
        role_viewer: {
          description: 'Read-only organization viewer',
          allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
          headerNames: ['Cookie'],
        },
        role_admin: {
          description: 'Organization administrator',
          allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
          headerNames: ['Cookie'],
        },
        role_head_only: {
          description: 'HEAD-only probe profile',
          allowedMethods: ['HEAD'],
          headerNames: ['X-Custom-Probe-Token'],
        },
      },
      strictReadOnly: true,
      ...overrides,
    });
  }

  beforeEach(async () => {
    upstreamRequests = [];
    upstreamServer = http.createServer((req, res) => {
      upstreamRequests.push({
        method: req.method ?? 'GET',
        url: req.url ?? '/',
        headers: { ...req.headers },
      });

      req.resume();
      const payload = JSON.stringify({
        ok: true,
        path: req.url,
        hostHeader: req.headers.host,
      });

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': syntheticUpstreamSetCookie,
        'X-Upstream-Server': 'acme-mock-1',
      });
      if (req.method === 'HEAD') {
        res.end();
      } else {
        res.end(payload);
      }
    });

    await new Promise<void>((resolve) => {
      upstreamServer.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = upstreamServer.address() as AddressInfo;
    upstreamUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterEach(async () => {
    if (gateway) {
      await gateway.stop();
      gateway = null;
    }
    upstreamServer.closeIdleConnections?.();
    await new Promise<void>((resolve, reject) => {
      upstreamServer.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it('SessionVault isolates profile headers and redacts default & custom sensitive headers', () => {
    const vault = new SessionVault();
    const customHeaderVal = `custom_secret_${randomUUID()}`;
    const inputHeaders = {
      'X-Custom-Session': customHeaderVal,
    };

    vault.registerProfile('custom_role', inputHeaders);
    inputHeaders['X-Custom-Session'] = 'mutated-externally';

    expect(vault.hasProfile('custom_role')).toBe(true);
    expect(vault.hasProfile('nonexistent')).toBe(false);

    const injected = vault.getInjectedHeaders('custom_role');
    expect(injected['X-Custom-Session']).toBe(customHeaderVal);
    injected['X-Custom-Session'] = 'mutated-copy';
    expect(vault.getInjectedHeaders('custom_role')['X-Custom-Session']).toBe(
      customHeaderVal,
    );

    const redacted = vault.redactHeaders({
      Accept: 'application/json',
      authorization: `Bearer tok_${randomUUID()}`,
      Cookie: `sid=${syntheticViewerCookieVal}`,
      'Set-Cookie': syntheticUpstreamSetCookie,
      'X-API-Key': `key_${randomUUID()}`,
      'x-custom-session': customHeaderVal,
    });

    expect(redacted).toEqual({
      Accept: 'application/json',
      authorization: REDACTED_BY_SESSION_VAULT,
      Cookie: REDACTED_BY_SESSION_VAULT,
      'Set-Cookie': REDACTED_BY_SESSION_VAULT,
      'X-API-Key': REDACTED_BY_SESSION_VAULT,
      'x-custom-session': REDACTED_BY_SESSION_VAULT,
    });
  });

  it('1. Allows valid in-scope GET, injects compliance + SessionVault headers upstream, and redacts secrets in HAR', async () => {
    const vault = new SessionVault();
    vault.registerProfile('role_viewer', {
      Cookie: `session=${syntheticViewerCookieVal}`,
    });

    const capturedLedger: TrafficLedgerEntry[] = [];
    const capturedPointers: TrafficEvidencePointer[] = [];

    gateway = new EgressGateway({
      scope: buildScope(),
      hmacSecret,
      vault,
      hostMapping: {
        'api.acme.internal': upstreamUrl,
      },
      onTrafficEntry: (entry) => {
        capturedLedger.push(TrafficLedgerEntrySchema.parse(entry));
      },
      onHarCaptured: (_sha, _harJson, pointer) => {
        capturedPointers.push(TrafficEvidencePointerSchema.parse(pointer));
      },
    });

    const { url: gatewayUrl } = await gateway.start();

    const taskToken = signTaskProxyToken(
      {
        taskId: 'task-recon-01',
        engagementId: 'eng-acme-2026',
        fencingToken: 7,
        allowedAuthProfiles: ['role_viewer'],
        expiresAtMs: Date.now() + 60_000,
      },
      hmacSecret,
    );

    const client = new GovernedHttpClient({
      gatewayUrl,
      taskToken,
      defaultAuthProfile: 'role_viewer',
    });

    const res = await client.request('http://api.acme.internal/v1/health?verbose=1', {
      headers: {
        Accept: 'application/json',
        'X-Aegis-Researcher': 'spoofed-by-untrusted-caller',
      },
    });

    expect(res.status).toBe(200);
    expect(res.harSha256).toBeDefined();
    expect(JSON.parse(res.bodyText)).toEqual({
      ok: true,
      path: '/v1/health?verbose=1',
      hostHeader: 'api.acme.internal',
    });

    // Verify upstream received compliance header, vault cookie, logical Host, and zero internal x-aegis-* control headers
    expect(upstreamRequests).toHaveLength(1);
    const upReq = upstreamRequests[0]!;
    expect(upReq.method).toBe('GET');
    expect(upReq.url).toBe('/v1/health?verbose=1');
    expect(upReq.headers['x-aegis-researcher']).toBe(
      'aegis-audit-bot@acme.example',
    );
    expect(upReq.headers.cookie).toBe(`session=${syntheticViewerCookieVal}`);
    expect(upReq.headers.host).toBe('api.acme.internal');
    expect(upReq.headers['x-forwarded-host']).toBe('api.acme.internal');
    expect(upReq.headers['x-aegis-task-token']).toBeUndefined();
    expect(upReq.headers['x-aegis-target-url']).toBeUndefined();
    expect(upReq.headers['x-aegis-auth-profile']).toBeUndefined();

    // Verify HAR capture integrity and strict secret redaction
    const harSha = res.harSha256!;
    const harJson = gateway.getHarCapture(harSha);
    expect(harJson).toBeDefined();
    expect(gateway.getHarBySha256(harSha)).toBe(harJson);
    expect(sha256Hex(harJson!)).toBe(harSha);

    expect(harJson).not.toContain(syntheticViewerCookieVal);
    expect(harJson).not.toContain(syntheticUpstreamSetCookie);
    expect(harJson).toContain(REDACTED_BY_SESSION_VAULT);

    const parsedHar = JSON.parse(harJson!) as {
      log: {
        entries: Array<{
          request: { headersMap: Record<string, string> };
          response: { headersMap: Record<string, string>; status: number };
        }>;
      };
    };
    const harEntry = parsedHar.log.entries[0]!;
    expect(harEntry.request.headersMap.Cookie).toBe(REDACTED_BY_SESSION_VAULT);
    expect(harEntry.request.headersMap['X-Aegis-Researcher']).toBe(
      'aegis-audit-bot@acme.example',
    );
    expect(harEntry.response.headersMap['set-cookie']).toBe(
      REDACTED_BY_SESSION_VAULT,
    );
    expect(harEntry.response.status).toBe(200);

    // Verify ledger & evidence pointer callbacks
    expect(capturedPointers).toHaveLength(1);
    expect(capturedPointers[0]?.sha256).toBe(harSha);
    expect(capturedPointers[0]?.authProfileUsed).toBe('role_viewer');

    expect(capturedLedger).toHaveLength(1);
    expect(capturedLedger[0]?.decision).toBe('ALLOWED');
    expect(capturedLedger[0]?.upstreamStatus).toBe(200);
    expect(capturedLedger[0]?.harBlobSha256).toBe(harSha);
    expect(gateway.getLedger()).toHaveLength(1);
  });

  it('2. Rejects out-of-scope domain http://evil.attacker.org/steal with 451 (BLOCKED_SCOPE_451) and hits zero upstreams', async () => {
    gateway = new EgressGateway({
      scope: buildScope(),
      hmacSecret,
      hostMapping: {
        'api.acme.internal': upstreamUrl,
        'evil.attacker.org': upstreamUrl,
      },
    });
    const { url: gatewayUrl } = await gateway.start();

    const taskToken = signTaskProxyToken(
      {
        taskId: 'task-scope-02',
        engagementId: 'eng-acme-2026',
        fencingToken: 1,
        allowedAuthProfiles: [],
        expiresAtMs: Date.now() + 60_000,
      },
      hmacSecret,
    );

    const client = new GovernedHttpClient({ gatewayUrl, taskToken });
    const res = await client.request('http://evil.attacker.org/steal');

    expect(res.status).toBe(451);
    const body = JSON.parse(res.bodyText) as Record<string, unknown>;
    expect(body.error).toBe('OUT_OF_SCOPE');
    expect(body.reason).toBe('OUT_OF_SCOPE_HOST');
    expect(upstreamRequests).toHaveLength(0);

    const ledger = gateway.getLedger();
    expect(ledger).toHaveLength(1);
    expect(ledger[0]?.decision).toBe('BLOCKED_SCOPE_451');
    expect(ledger[0]?.host).toBe('evil.attacker.org');
  });

  it('3. Rejects excluded path traversal http://api.acme.internal/v1/../../admin/destruct/wipe with 451 (BLOCKED_SCOPE_451)', async () => {
    gateway = new EgressGateway({
      scope: buildScope(),
      hmacSecret,
      hostMapping: { 'api.acme.internal': upstreamUrl },
    });
    const { url: gatewayUrl } = await gateway.start();

    const taskToken = signTaskProxyToken(
      {
        taskId: 'task-traversal-03',
        engagementId: 'eng-acme-2026',
        fencingToken: 2,
        allowedAuthProfiles: [],
        expiresAtMs: Date.now() + 60_000,
      },
      hmacSecret,
    );

    const client = new GovernedHttpClient({ gatewayUrl, taskToken });

    const resRawTraversal = await client.request(
      'http://api.acme.internal/v1/../../admin/destruct/wipe',
    );
    expect(resRawTraversal.status).toBe(451);
    expect(JSON.parse(resRawTraversal.bodyText)).toMatchObject({
      error: 'OUT_OF_SCOPE',
      reason: 'EXCLUDED_PATH',
    });

    const resEncodedTraversal = await client.request(
      'http://api.acme.internal/v1/%2e%2e/%2e%2e/admin/destruct/wipe',
    );
    expect(resEncodedTraversal.status).toBe(451);

    expect(upstreamRequests).toHaveLength(0);
    const ledger = gateway.getLedger();
    expect(ledger).toHaveLength(2);
    expect(ledger.every((e) => e.decision === 'BLOCKED_SCOPE_451')).toBe(true);
  });

  it('4. Rejects POST when strictReadOnly: true with 405 (BLOCKED_METHOD_405)', async () => {
    gateway = new EgressGateway({
      scope: buildScope({ strictReadOnly: true }),
      hmacSecret,
      hostMapping: { 'api.acme.internal': upstreamUrl },
    });
    const { url: gatewayUrl } = await gateway.start();

    const taskToken = signTaskProxyToken(
      {
        taskId: 'task-method-04',
        engagementId: 'eng-acme-2026',
        fencingToken: 3,
        allowedAuthProfiles: [],
        expiresAtMs: Date.now() + 60_000,
      },
      hmacSecret,
    );

    const postRes = await fetch(
      `${gatewayUrl}/__aegis_forward?url=${encodeURIComponent('http://api.acme.internal/v1/org/settings')}`,
      {
        method: 'POST',
        headers: {
          'x-aegis-task-token': taskToken,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ mutate: true }),
      },
    );

    expect(postRes.status).toBe(405);
    const errPayload = (await postRes.json()) as Record<string, unknown>;
    expect(errPayload).toEqual({
      error: 'METHOD_NOT_ALLOWED_READ_ONLY',
      method: 'POST',
    });

    expect(upstreamRequests).toHaveLength(0);
    const ledger = gateway.getLedger();
    expect(ledger).toHaveLength(1);
    expect(ledger[0]?.decision).toBe('BLOCKED_METHOD_405');
    expect(ledger[0]?.method).toBe('POST');
  });

  it('5. Rejects unauthorized authProfile with 403 (BLOCKED_AUTH_403) and enforces profile allowedMethods with 405', async () => {
    const vault = new SessionVault();
    vault.registerProfile('role_viewer', {
      Cookie: `session=${syntheticViewerCookieVal}`,
    });
    vault.registerProfile('role_admin', {
      Cookie: `session=${syntheticAdminCookieVal}`,
    });
    vault.registerProfile('role_head_only', {
      'X-Custom-Probe-Token': `probe_${randomUUID()}`,
    });

    gateway = new EgressGateway({
      scope: buildScope(),
      hmacSecret,
      vault,
      hostMapping: { 'api.acme.internal': upstreamUrl },
    });
    const { url: gatewayUrl } = await gateway.start();

    const viewerOnlyToken = signTaskProxyToken(
      {
        taskId: 'task-auth-05',
        engagementId: 'eng-acme-2026',
        fencingToken: 4,
        allowedAuthProfiles: ['role_viewer', 'role_head_only'],
        expiresAtMs: Date.now() + 60_000,
      },
      hmacSecret,
    );

    const client = new GovernedHttpClient({
      gatewayUrl,
      taskToken: viewerOnlyToken,
    });

    // Attempt elevation to role_admin -> 403
    const adminAttempt = await client.request(
      'http://api.acme.internal/v1/admin-panel',
      { authProfile: 'role_admin' },
    );
    expect(adminAttempt.status).toBe(403);
    expect(JSON.parse(adminAttempt.bodyText)).toEqual({
      error: 'FORBIDDEN_AUTH_PROFILE',
      authProfile: 'role_admin',
    });

    // Attempt GET with a profile restricted to HEAD only -> 405
    const methodAttempt = await client.request(
      'http://api.acme.internal/v1/health',
      { method: 'GET', authProfile: 'role_head_only' },
    );
    expect(methodAttempt.status).toBe(405);

    expect(upstreamRequests).toHaveLength(0);
    const ledger = gateway.getLedger();
    expect(ledger).toHaveLength(2);
    expect(ledger[0]?.decision).toBe('BLOCKED_AUTH_403');
    expect(ledger[1]?.decision).toBe('BLOCKED_METHOD_405');
  });

  it('6. Rejects missing, tampered, or expired x-aegis-task-token with 401', async () => {
    gateway = new EgressGateway({
      scope: buildScope(),
      hmacSecret,
      hostMapping: { 'api.acme.internal': upstreamUrl },
    });
    const { url: gatewayUrl } = await gateway.start();

    const validToken = signTaskProxyToken(
      {
        taskId: 'task-token-06',
        engagementId: 'eng-acme-2026',
        fencingToken: 5,
        allowedAuthProfiles: [],
        expiresAtMs: Date.now() + 60_000,
      },
      hmacSecret,
    );
    const tamperedToken = `${validToken.slice(0, -4)}AAAA`;

    const expiredToken = signTaskProxyToken(
      {
        taskId: 'task-token-expired',
        engagementId: 'eng-acme-2026',
        fencingToken: 5,
        allowedAuthProfiles: [],
        expiresAtMs: Date.now() - 5_000,
      },
      hmacSecret,
    );

    const tamperedClient = new GovernedHttpClient({
      gatewayUrl,
      taskToken: tamperedToken,
    });
    const tamperedRes = await tamperedClient.request(
      'http://api.acme.internal/v1/health',
    );
    expect(tamperedRes.status).toBe(401);
    expect(JSON.parse(tamperedRes.bodyText)).toMatchObject({
      error: 'UNAUTHORIZED_TASK_TOKEN',
      reason: 'INVALID_SIGNATURE',
    });

    const expiredClient = new GovernedHttpClient({
      gatewayUrl,
      taskToken: expiredToken,
    });
    const expiredRes = await expiredClient.request(
      'http://api.acme.internal/v1/health',
    );
    expect(expiredRes.status).toBe(401);
    expect(JSON.parse(expiredRes.bodyText)).toMatchObject({
      error: 'UNAUTHORIZED_TASK_TOKEN',
      reason: 'TOKEN_EXPIRED',
    });

    const missingRes = await fetch(
      `${gatewayUrl}/__aegis_forward?url=${encodeURIComponent('http://api.acme.internal/v1/health')}`,
    );
    expect(missingRes.status).toBe(401);

    expect(upstreamRequests).toHaveLength(0);
    expect(gateway.getLedger()).toHaveLength(0);
  });

  it('7. Enforces maxRpsPerHost: 2 — firing 5 rapid requests yields at least 2 429 (BLOCKED_RPS_429) responses', async () => {
    gateway = new EgressGateway({
      scope: buildScope({ maxRpsPerHost: 2 }),
      hmacSecret,
      hostMapping: { 'api.acme.internal': upstreamUrl },
    });
    const { url: gatewayUrl } = await gateway.start();

    const taskToken = signTaskProxyToken(
      {
        taskId: 'task-rps-07',
        engagementId: 'eng-acme-2026',
        fencingToken: 6,
        allowedAuthProfiles: [],
        expiresAtMs: Date.now() + 60_000,
      },
      hmacSecret,
    );

    const client = new GovernedHttpClient({ gatewayUrl, taskToken });

    const responses = await Promise.all(
      Array.from({ length: 5 }, (_, idx) =>
        client.request(`http://api.acme.internal/v1/item/${idx}`),
      ),
    );

    const count429 = responses.filter((r) => r.status === 429).length;
    const count200 = responses.filter((r) => r.status === 200).length;

    expect(count429).toBeGreaterThanOrEqual(2);
    expect(count200).toBeLessThanOrEqual(2);
    expect(count429 + count200).toBe(5);

    const ledger429 = gateway
      .getLedger()
      .filter((entry) => entry.decision === 'BLOCKED_RPS_429');
    expect(ledger429.length).toBe(count429);
  });

  it('supports standard absolute-URI HTTP proxy requests and dynamic updateHostMapping', async () => {
    gateway = new EgressGateway({
      scope: buildScope(),
      hmacSecret,
    });
    gateway.updateHostMapping({
      'sub.acme.internal': upstreamUrl,
    });

    const { port: gatewayPort } = await gateway.start();

    const taskToken = signTaskProxyToken(
      {
        taskId: 'task-proxy-abs',
        engagementId: 'eng-acme-2026',
        fencingToken: 8,
        allowedAuthProfiles: [],
        expiresAtMs: Date.now() + 60_000,
      },
      hmacSecret,
    );

    const proxyResponse = await new Promise<{ status: number; body: string }>(
      (resolve, reject) => {
        const req = http.request(
          {
            hostname: '127.0.0.1',
            port: gatewayPort,
            method: 'GET',
            path: 'http://sub.acme.internal/v1/status',
            headers: {
              Host: 'sub.acme.internal',
              'x-aegis-task-token': taskToken,
            },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c: Buffer) => chunks.push(c));
            res.on('end', () =>
              resolve({
                status: res.statusCode ?? 0,
                body: Buffer.concat(chunks).toString('utf8'),
              }),
            );
          },
        );
        req.on('error', reject);
        req.end();
      },
    );

    expect(proxyResponse.status).toBe(200);
    expect(JSON.parse(proxyResponse.body)).toEqual({
      ok: true,
      path: '/v1/status',
      hostHeader: 'sub.acme.internal',
    });
  });

  it('8. Supports live updateScope (including excludedHosts 451) and custom upstreamDispatcher', async () => {
    const dispatchedUrls: Array<{ url: string; headers: Record<string, string> }> = [];
    gateway = new EgressGateway({
      scope: buildScope({
        excludedHosts: ['blog.acme.internal'],
        complianceHeaders: { 'X-Bug-Bounty': 'Bugcrowd-researcher-01' },
      }),
      hmacSecret,
      upstreamDispatcher: async (req) => {
        dispatchedUrls.push({ url: req.url, headers: { ...req.headers } });
        return {
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          body: Buffer.from(JSON.stringify({ dispatched: true }), 'utf8'),
        };
      },
    });

    const { url: gatewayUrl } = await gateway.start();
    const taskToken = signTaskProxyToken(
      {
        taskId: 'task-dispatch-08',
        engagementId: 'eng-acme-2026',
        fencingToken: 9,
        allowedAuthProfiles: [],
        expiresAtMs: Date.now() + 60_000,
      },
      hmacSecret,
    );
    const client = new GovernedHttpClient({ gatewayUrl, taskToken });

    // Excluded host inside *.acme.internal wildcard -> 451 before dispatcher runs
    const blockedRes = await client.request('https://blog.acme.internal/posts');
    expect(blockedRes.status).toBe(451);
    expect(dispatchedUrls).toHaveLength(0);

    // Allowed host without hostMapping -> uses upstreamDispatcher with injected compliance header
    const allowedRes = await client.request('https://portal-ext.acme.internal/v1/meta');
    expect(allowedRes.status).toBe(200);
    expect(JSON.parse(allowedRes.bodyText)).toEqual({ dispatched: true });
    expect(dispatchedUrls).toHaveLength(1);
    expect(dispatchedUrls[0]?.headers['X-Bug-Bounty']).toBe('Bugcrowd-researcher-01');

    // Dynamic scope update via updateScope adds newly authorized domain
    gateway.updateScope(
      buildScope({
        authorizedDomains: ['*.newprog.example'],
        complianceHeaders: { 'X-Bug-Bounty': 'Updated-Header' },
      }),
    );
    const updatedRes = await client.request('https://api.newprog.example/health');
    expect(updatedRes.status).toBe(200);
    expect(dispatchedUrls[1]?.headers['X-Bug-Bounty']).toBe('Updated-Header');
  });
});
