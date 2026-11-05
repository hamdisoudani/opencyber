import { randomUUID } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import {
  evaluateTargetScope,
  normalizeHostname,
  sha256Hex,
  verifyTaskProxyToken,
  type ScopeConfig,
  type TaskProxyTokenPayload,
  type TrafficDecision,
  type TrafficEvidencePointer,
  type TrafficLedgerEntry,
} from '@opencyber/shared';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { SessionVault } from './vault.js';

export type UpstreamDispatcher = (req: {
  url: string;
  method: string;
  headers: Record<string, string>;
}) => Promise<{
  status: number;
  statusText?: string;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}>;

export interface EgressGatewayOptions {
  scope: ScopeConfig;
  hmacSecret: string;
  vault?: SessionVault;
  /**
   * Optional logical-host -> upstream origin override for safe local testing/mocking,
   * e.g. { "api.acme.internal": "http://127.0.0.1:19081" }.
   * Scope & RPS rules are STILL evaluated against the logical target URL ("http://api.acme.internal/...")!
   */
  hostMapping?: Record<string, string>;
  /**
   * Optional custom upstream transport (e.g. governed read-only fetch inside an E2B Cloud Sandbox
   * when the control-plane VM proxy restricts direct external outbound HTTP).
   * Invoked ONLY after token auth (401), scope/exclusion checks (451), read-only method guard (405),
   * auth-profile checks (403), and per-host RPS limits (429) have passed.
   */
  upstreamDispatcher?: UpstreamDispatcher;
  onTrafficEntry?: (entry: TrafficLedgerEntry) => void | Promise<void>;
  onHarCaptured?: (
    sha256: string,
    harJson: string,
    pointer: TrafficEvidencePointer,
  ) => void | Promise<void>;
}

const READ_ONLY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const STRIPPED_REQUEST_HEADERS = new Set([
  'host',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'accept-encoding',
]);

const STRIPPED_RESPONSE_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 15_000;

function getSingleHeader(
  value: string | string[] | undefined,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const raw = Array.isArray(value) ? value[0] : value;
  const trimmed = raw?.trim();
  return trimmed ? trimmed : undefined;
}

function setHeaderCaseInsensitive(
  headers: Record<string, string>,
  name: string,
  value: string,
): void {
  const lower = name.toLowerCase();
  for (const existingKey of Object.keys(headers)) {
    if (existingKey.toLowerCase() === lower) {
      delete headers[existingKey];
    }
  }
  headers[name] = value;
}

function formatHostForUrl(host: string): string {
  if (host.includes(':') && !host.startsWith('[')) {
    return `[${host}]`;
  }
  return host;
}

function sendJson(
  res: http.ServerResponse,
  statusCode: number,
  payload: Record<string, unknown>,
): void {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': String(body.byteLength),
  });
  res.end(body);
}

function extractTargetUrl(req: http.IncomingMessage): string {
  const headerTarget = getSingleHeader(req.headers['x-aegis-target-url']);
  if (headerTarget) {
    return headerTarget;
  }

  const rawReqUrl = (req.url ?? '').trim();
  if (/^https?:\/\//i.test(rawReqUrl)) {
    return rawReqUrl;
  }

  if (rawReqUrl.startsWith('/')) {
    try {
      const parsedLocal = new URL(rawReqUrl, 'http://127.0.0.1');
      if (
        parsedLocal.pathname === '/__aegis_forward' ||
        parsedLocal.pathname === '/'
      ) {
        const queryUrl = parsedLocal.searchParams.get('url');
        if (queryUrl !== null) {
          return queryUrl.trim();
        }
      }
    } catch {
      // Fall through and return rawReqUrl so evaluateTargetScope rejects INVALID_URL
    }
  }

  return rawReqUrl;
}

function readRequestBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;

    req.on('data', (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buf.byteLength;
      if (totalBytes > MAX_REQUEST_BODY_BYTES) {
        req.destroy(new Error('Request body exceeds maximum allowed size'));
        return;
      }
      chunks.push(buf);
    });

    req.on('end', () => {
      resolve(Buffer.concat(chunks));
    });

    req.on('error', (err) => {
      reject(err);
    });
  });
}

interface UpstreamResult {
  status: number;
  statusText: string;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

/**
 * Deterministic HTTP Egress Governance Gateway.
 * Enforces task token authentication, scope.yaml domain/path boundaries,
 * read-only method governance, auth profile permissions, per-host token-bucket
 * rate limits, compliance & vault credential injection, and redacted HAR capture.
 */
export class EgressGateway {
  private readonly options: EgressGatewayOptions;
  private readonly vault: SessionVault;
  private rateLimiter: RateLimiterMemory;
  private upstreamDispatcher?: UpstreamDispatcher;
  private readonly hostMapping = new Map<string, string>();
  private readonly ledger: TrafficLedgerEntry[] = [];
  private readonly harCaptures = new Map<string, string>();
  private server: http.Server | null = null;

  public constructor(options: EgressGatewayOptions) {
    this.options = options;
    this.vault = options.vault ?? new SessionVault();
    this.upstreamDispatcher = options.upstreamDispatcher;

    for (const profileConfig of Object.values(options.scope.authProfiles)) {
      if (profileConfig.headerNames.length > 0) {
        this.vault.registerSensitiveHeaderNames(profileConfig.headerNames);
      }
    }

    this.rateLimiter = new RateLimiterMemory({
      points: Math.max(1, Math.ceil(options.scope.maxRpsPerHost)),
      duration: 1,
    });

    if (options.hostMapping) {
      this.updateHostMapping(options.hostMapping);
    }
  }

  public getScope(): ScopeConfig {
    return this.options.scope;
  }

  public updateScope(scope: ScopeConfig): void {
    this.options.scope = scope;
    for (const profileConfig of Object.values(scope.authProfiles)) {
      if (profileConfig.headerNames.length > 0) {
        this.vault.registerSensitiveHeaderNames(profileConfig.headerNames);
      }
    }
    this.rateLimiter = new RateLimiterMemory({
      points: Math.max(1, Math.ceil(scope.maxRpsPerHost)),
      duration: 1,
    });
  }

  public setUpstreamDispatcher(dispatcher?: UpstreamDispatcher): void {
    this.upstreamDispatcher = dispatcher;
  }

  public updateHostMapping(mapping: Record<string, string>): void {
    this.hostMapping.clear();
    for (const [logicalHost, upstreamOrigin] of Object.entries(mapping)) {
      const normalized = normalizeHostname(logicalHost);
      if (normalized && upstreamOrigin) {
        this.hostMapping.set(normalized, upstreamOrigin);
      }
    }
  }

  public getLedger(): TrafficLedgerEntry[] {
    return this.ledger.map((entry) => ({ ...entry }));
  }

  public getHarCapture(sha256: string): string | undefined {
    return this.harCaptures.get(sha256);
  }

  public getHarBySha256(sha256: string): string | undefined {
    return this.harCaptures.get(sha256);
  }

  public async start(
    port: number = 0,
    host: string = '127.0.0.1',
  ): Promise<{ port: number; url: string }> {
    if (this.server) {
      const existingAddr = this.server.address() as AddressInfo;
      return {
        port: existingAddr.port,
        url: `http://${formatHostForUrl(host)}:${existingAddr.port}`,
      };
    }

    const server = http.createServer((req, res) => {
      void this.handleRequest(req, res).catch((err: unknown) => {
        if (!res.headersSent) {
          const message =
            err instanceof Error ? err.message : 'Internal gateway error';
          sendJson(res, 500, { error: 'GATEWAY_INTERNAL_ERROR', reason: message });
        } else {
          res.end();
        }
      });
    });

    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error): void => {
        server.removeListener('listening', onListening);
        reject(err);
      };
      const onListening = (): void => {
        server.removeListener('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(port, host);
    });

    this.server = server;
    const bound = server.address() as AddressInfo;
    return {
      port: bound.port,
      url: `http://${formatHostForUrl(host)}:${bound.port}`,
    };
  }

  public async stop(): Promise<void> {
    const server = this.server;
    if (!server) {
      return;
    }
    this.server = null;

    server.closeIdleConnections?.();
    await new Promise<void>((resolve, reject) => {
      server.close((err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  }

  private async recordTrafficEntry(params: {
    tokenPayload: TaskProxyTokenPayload;
    method: string;
    url: string;
    host: string;
    pathname: string;
    authProfile?: string;
    decision: TrafficDecision;
    upstreamStatus?: number;
    startMs: number;
    harBlobSha256?: string;
  }): Promise<TrafficLedgerEntry> {
    const entry: TrafficLedgerEntry = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      engagementId: this.options.scope.engagementId,
      taskId: params.tokenPayload.taskId,
      fencingToken: params.tokenPayload.fencingToken,
      method: params.method,
      url: params.url || '<missing>',
      host: params.host || '<invalid-host>',
      pathname: params.pathname || '/',
      ...(params.authProfile ? { authProfile: params.authProfile } : {}),
      decision: params.decision,
      ...(params.upstreamStatus !== undefined
        ? { upstreamStatus: params.upstreamStatus }
        : {}),
      durationMs: Math.max(0, Date.now() - params.startMs),
      ...(params.harBlobSha256 ? { harBlobSha256: params.harBlobSha256 } : {}),
    };

    this.ledger.push(entry);
    if (this.options.onTrafficEntry) {
      await this.options.onTrafficEntry(entry);
    }
    return entry;
  }

  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const startMs = Date.now();
    const startedIso = new Date(startMs).toISOString();

    // 1. Authenticate Task Token
    const rawToken = getSingleHeader(req.headers['x-aegis-task-token']);
    const tokenVerification = rawToken
      ? verifyTaskProxyToken(rawToken, this.options.hmacSecret)
      : ({ valid: false, reason: 'MISSING_TASK_TOKEN' } as const);

    if (!tokenVerification.valid) {
      req.resume();
      sendJson(res, 401, {
        error: 'UNAUTHORIZED_TASK_TOKEN',
        reason: tokenVerification.reason,
      });
      return;
    }

    const tokenPayload = tokenVerification.payload;
    const targetUrl = extractTargetUrl(req);
    const method = (req.method || 'GET').toUpperCase();
    const authProfile = getSingleHeader(req.headers['x-aegis-auth-profile']);

    // 2. Parse Target URL & Evaluate Scope (scope.yaml)
    const evalResult = evaluateTargetScope(targetUrl, this.options.scope);
    if (!evalResult.allowed) {
      req.resume();
      await this.recordTrafficEntry({
        tokenPayload,
        method,
        url: targetUrl,
        host: evalResult.normalizedHost,
        pathname: evalResult.normalizedPath,
        authProfile,
        decision: 'BLOCKED_SCOPE_451',
        startMs,
      });
      sendJson(res, 451, {
        error: 'OUT_OF_SCOPE',
        reason: evalResult.reason ?? 'OUT_OF_SCOPE',
        url: targetUrl,
      });
      return;
    }

    // 3. Validate HTTP Method (Read-Only Governance)
    if (this.options.scope.strictReadOnly && !READ_ONLY_METHODS.has(method)) {
      req.resume();
      await this.recordTrafficEntry({
        tokenPayload,
        method,
        url: targetUrl,
        host: evalResult.normalizedHost,
        pathname: evalResult.normalizedPath,
        authProfile,
        decision: 'BLOCKED_METHOD_405',
        startMs,
      });
      sendJson(res, 405, {
        error: 'METHOD_NOT_ALLOWED_READ_ONLY',
        method,
      });
      return;
    }

    // 4. Validate Auth Profile & Method Permission
    if (authProfile) {
      const scopeProfile = this.options.scope.authProfiles[authProfile];
      const profileExists =
        Boolean(scopeProfile) || this.vault.hasProfile(authProfile);
      const profileAllowedForTask =
        tokenPayload.allowedAuthProfiles.includes(authProfile) && profileExists;

      if (!profileAllowedForTask) {
        req.resume();
        await this.recordTrafficEntry({
          tokenPayload,
          method,
          url: targetUrl,
          host: evalResult.normalizedHost,
          pathname: evalResult.normalizedPath,
          authProfile,
          decision: 'BLOCKED_AUTH_403',
          startMs,
        });
        sendJson(res, 403, {
          error: 'FORBIDDEN_AUTH_PROFILE',
          authProfile,
        });
        return;
      }

      if (
        scopeProfile?.allowedMethods &&
        !(scopeProfile.allowedMethods as readonly string[]).includes(method)
      ) {
        req.resume();
        await this.recordTrafficEntry({
          tokenPayload,
          method,
          url: targetUrl,
          host: evalResult.normalizedHost,
          pathname: evalResult.normalizedPath,
          authProfile,
          decision: 'BLOCKED_METHOD_405',
          startMs,
        });
        sendJson(res, 405, {
          error: 'METHOD_NOT_ALLOWED_READ_ONLY',
          method,
          authProfile,
        });
        return;
      }
    }

    // 5. Token-Bucket Rate Limiting (rate-limiter-flexible)
    const rateLimitKey = `${this.options.scope.engagementId}:${evalResult.normalizedHost}`;
    try {
      await this.rateLimiter.consume(rateLimitKey, 1);
    } catch {
      req.resume();
      await this.recordTrafficEntry({
        tokenPayload,
        method,
        url: targetUrl,
        host: evalResult.normalizedHost,
        pathname: evalResult.normalizedPath,
        authProfile,
        decision: 'BLOCKED_RPS_429',
        startMs,
      });
      sendJson(res, 429, {
        error: 'RATE_LIMIT_EXCEEDED',
        maxRpsPerHost: this.options.scope.maxRpsPerHost,
      });
      return;
    }

    // 6. Upstream Dispatch + Compliance & Credential Injection
    const reqBody = await readRequestBody(req);
    const parsedTarget = new URL(targetUrl);

    const outgoingHeaders: Record<string, string> = {};
    for (const [rawKey, rawValue] of Object.entries(req.headers)) {
      if (rawValue === undefined) {
        continue;
      }
      const lower = rawKey.toLowerCase();
      if (STRIPPED_REQUEST_HEADERS.has(lower) || lower.startsWith('x-aegis-')) {
        continue;
      }
      const headerValue = Array.isArray(rawValue)
        ? rawValue.join(', ')
        : rawValue;
      setHeaderCaseInsensitive(outgoingHeaders, rawKey, headerValue);
    }

    for (const [compName, compValue] of Object.entries(
      this.options.scope.complianceHeaders,
    )) {
      setHeaderCaseInsensitive(outgoingHeaders, compName, compValue);
    }

    if (authProfile) {
      const injectedSecrets = this.vault.getInjectedHeaders(authProfile);
      for (const [secName, secValue] of Object.entries(injectedSecrets)) {
        setHeaderCaseInsensitive(outgoingHeaders, secName, secValue);
      }
    }

    const mappedOrigin = this.hostMapping.get(evalResult.normalizedHost);
    let connectProtocol: string;
    let connectHostname: string;
    let connectPort: number;
    let connectPath: string;

    if (mappedOrigin) {
      const parsedMapped = new URL(mappedOrigin);
      connectProtocol = parsedMapped.protocol;
      connectHostname = parsedMapped.hostname.replace(/^\[|\]$/g, '');
      connectPort = parsedMapped.port
        ? Number(parsedMapped.port)
        : connectProtocol === 'https:'
          ? 443
          : 80;
      const basePrefix =
        parsedMapped.pathname === '/'
          ? ''
          : parsedMapped.pathname.replace(/\/+$/, '');
      connectPath = `${basePrefix}${parsedTarget.pathname}${parsedTarget.search}`;

      setHeaderCaseInsensitive(
        outgoingHeaders,
        'Host',
        evalResult.normalizedHost,
      );
      setHeaderCaseInsensitive(
        outgoingHeaders,
        'X-Forwarded-Host',
        evalResult.normalizedHost,
      );
    } else {
      connectProtocol = parsedTarget.protocol;
      connectHostname = parsedTarget.hostname.replace(/^\[|\]$/g, '');
      connectPort = parsedTarget.port
        ? Number(parsedTarget.port)
        : connectProtocol === 'https:'
          ? 443
          : 80;
      connectPath = `${parsedTarget.pathname}${parsedTarget.search}`;

      setHeaderCaseInsensitive(
        outgoingHeaders,
        'Host',
        parsedTarget.host || evalResult.normalizedHost,
      );
    }

    const shouldForwardBody =
      reqBody.byteLength > 0 && method !== 'GET' && method !== 'HEAD';
    if (shouldForwardBody) {
      setHeaderCaseInsensitive(
        outgoingHeaders,
        'Content-Length',
        String(reqBody.byteLength),
      );
    }

    let upstreamResult: UpstreamResult;
    try {
      if (!mappedOrigin && this.upstreamDispatcher) {
        const dispatched = await this.upstreamDispatcher({
          url: targetUrl,
          method,
          headers: outgoingHeaders,
        });
        const normalizedHeaders: http.IncomingHttpHeaders = {};
        for (const [hdrKey, hdrVal] of Object.entries(dispatched.headers)) {
          normalizedHeaders[hdrKey.toLowerCase()] = hdrVal;
        }
        upstreamResult = {
          status: dispatched.status,
          statusText: dispatched.statusText ?? 'OK',
          headers: normalizedHeaders,
          body: dispatched.body,
        };
      } else {
        upstreamResult = await this.forwardToUpstream({
          protocol: connectProtocol,
          hostname: connectHostname,
          port: connectPort,
          method,
          path: connectPath,
          headers: outgoingHeaders,
          body: shouldForwardBody ? reqBody : undefined,
        });
      }
    } catch (err: unknown) {
      const reason =
        err instanceof Error ? err.message : 'Upstream connection failed';
      await this.recordTrafficEntry({
        tokenPayload,
        method,
        url: targetUrl,
        host: evalResult.normalizedHost,
        pathname: evalResult.normalizedPath,
        authProfile,
        decision: 'ALLOWED',
        upstreamStatus: 502,
        startMs,
      });
      sendJson(res, 502, {
        error: 'BAD_GATEWAY',
        reason,
      });
      return;
    }

    const flatResponseHeaders: Record<string, string> = {};
    for (const [resKey, resVal] of Object.entries(upstreamResult.headers)) {
      if (resVal === undefined) {
        continue;
      }
      flatResponseHeaders[resKey] = Array.isArray(resVal)
        ? resVal.join('; ')
        : resVal;
    }

    const redactedReqHeaders = this.vault.redactHeaders(outgoingHeaders);
    const redactedResHeaders = this.vault.redactHeaders(flatResponseHeaders);
    const responseMimeType =
      getSingleHeader(upstreamResult.headers['content-type']) ??
      'application/octet-stream';
    const durationMs = Math.max(0, Date.now() - startMs);

    const harRecord = {
      log: {
        version: '1.2',
        creator: {
          name: '@opencyber/egress-gateway',
          version: '0.1.0',
        },
        entries: [
          {
            startedDateTime: startedIso,
            time: durationMs,
            aegisMetadata: {
              engagementId: this.options.scope.engagementId,
              taskId: tokenPayload.taskId,
              fencingToken: tokenPayload.fencingToken,
              ...(authProfile ? { authProfile } : {}),
            },
            request: {
              method,
              url: targetUrl,
              httpVersion: 'HTTP/1.1',
              headers: Object.entries(redactedReqHeaders).map(
                ([name, value]) => ({ name, value }),
              ),
              headersMap: redactedReqHeaders,
              queryString: Array.from(parsedTarget.searchParams.entries()).map(
                ([name, value]) => ({ name, value }),
              ),
              bodySize: shouldForwardBody ? reqBody.byteLength : 0,
            },
            response: {
              status: upstreamResult.status,
              statusText: upstreamResult.statusText,
              httpVersion: 'HTTP/1.1',
              headers: Object.entries(redactedResHeaders).map(
                ([name, value]) => ({ name, value }),
              ),
              headersMap: redactedResHeaders,
              content: {
                size: upstreamResult.body.byteLength,
                mimeType: responseMimeType,
                text: upstreamResult.body.toString('utf8'),
              },
              bodySize: upstreamResult.body.byteLength,
            },
          },
        ],
      },
    };

    const harJson = JSON.stringify(harRecord, null, 2);
    const harSha256 = sha256Hex(harJson);
    this.harCaptures.set(harSha256, harJson);

    const evidencePointer: TrafficEvidencePointer = {
      sha256: harSha256,
      blobPath: `evidence/har/${harSha256}.har.json`,
      requestUrl: targetUrl,
      method,
      statusCode: upstreamResult.status,
      capturedAt: startedIso,
      ...(authProfile ? { authProfileUsed: authProfile } : {}),
    };

    if (this.options.onHarCaptured) {
      await this.options.onHarCaptured(harSha256, harJson, evidencePointer);
    }

    await this.recordTrafficEntry({
      tokenPayload,
      method,
      url: targetUrl,
      host: evalResult.normalizedHost,
      pathname: evalResult.normalizedPath,
      authProfile,
      decision: 'ALLOWED',
      upstreamStatus: upstreamResult.status,
      startMs,
      harBlobSha256: harSha256,
    });

    const clientResponseHeaders: http.OutgoingHttpHeaders = {};
    for (const [resKey, resVal] of Object.entries(upstreamResult.headers)) {
      if (resVal === undefined) {
        continue;
      }
      const lower = resKey.toLowerCase();
      if (STRIPPED_RESPONSE_HEADERS.has(lower)) {
        continue;
      }
      if (lower === 'content-length' && method !== 'HEAD') {
        continue;
      }
      clientResponseHeaders[resKey] = resVal;
    }

    if (method !== 'HEAD') {
      clientResponseHeaders['content-length'] = String(
        upstreamResult.body.byteLength,
      );
    }
    clientResponseHeaders['x-aegis-har-sha256'] = harSha256;

    res.writeHead(upstreamResult.status, clientResponseHeaders);
    if (method === 'HEAD') {
      res.end();
    } else {
      res.end(upstreamResult.body);
    }
  }

  private forwardToUpstream(params: {
    protocol: string;
    hostname: string;
    port: number;
    method: string;
    path: string;
    headers: Record<string, string>;
    body?: Buffer;
  }): Promise<UpstreamResult> {
    const requestFn =
      params.protocol === 'https:' ? https.request : http.request;

    return new Promise<UpstreamResult>((resolve, reject) => {
      const upstreamReq = requestFn(
        {
          protocol: params.protocol,
          hostname: params.hostname,
          port: params.port,
          method: params.method,
          path: params.path,
          headers: params.headers,
        },
        (upstreamRes) => {
          const chunks: Buffer[] = [];
          upstreamRes.on('data', (chunk: Buffer | string) => {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          });
          upstreamRes.on('end', () => {
            resolve({
              status: upstreamRes.statusCode ?? 502,
              statusText: upstreamRes.statusMessage ?? '',
              headers: upstreamRes.headers,
              body: Buffer.concat(chunks),
            });
          });
          upstreamRes.on('error', (err) => {
            reject(err);
          });
        },
      );

      upstreamReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
        upstreamReq.destroy(
          new Error(`Upstream request timed out after ${UPSTREAM_TIMEOUT_MS}ms`),
        );
      });

      upstreamReq.on('error', (err) => {
        reject(err);
      });

      if (params.body && params.body.byteLength > 0) {
        upstreamReq.write(params.body);
      }
      upstreamReq.end();
    });
  }
}
