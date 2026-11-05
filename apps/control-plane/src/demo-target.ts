import http from 'node:http';
import type { AddressInfo } from 'node:net';

const PORTAL_INDEX_HTML =
  '<!doctype html><html><body><script src="/static/app.bundle.js"></script></body></html>';

const PORTAL_APP_BUNDLE_JS = [
  '// Acme Enterprise Portal SPA Bundle (v2.4.0)',
  'export async function loadEnterpriseWorkspace(userId, token, axios) {',
  '  const rolesResponse = await fetch(`http://api.acme.internal/v1/users/${userId}/roles`, {',
  '    headers: { Authorization: token },',
  '  });',
  "  const orgSettings = await axios.get('http://api.acme.internal/v1/org/settings');",
  "  const profile = await axios.get('http://api.acme.internal/v1/profile');",
  "  const exportTask = await axios.post('http://api.acme.internal/v1/reports/export');",
  '  return { rolesResponse, orgSettings, profile, exportTask };',
  '}',
  '',
].join('\n');

const PORTAL_ROBOTS_TXT = 'User-agent: *\nDisallow: /admin/destruct/\n';

const API_OPENAPI_SPEC = {
  openapi: '3.0.3',
  info: {
    title: 'Acme Enterprise Core API',
    version: '2.4.0',
  },
  servers: [{ url: 'http://api.acme.internal' }],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
      },
    },
  },
  paths: {
    '/v1/profile': {
      get: {
        summary: 'Retrieve current caller profile',
        responses: {
          '200': {
            description: 'Caller profile record',
            content: {
              'application/json': {
                schema: { type: 'object' },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
          },
        },
      },
    },
    '/v1/users/{id}/roles': {
      get: {
        summary: 'Inspect role assignments for a user',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          '200': {
            description: 'User role bindings',
            content: {
              'application/json': {
                schema: { type: 'object' },
              },
            },
          },
        },
      },
    },
    '/v1/org/settings': {
      get: {
        summary: 'Inspect organization SSO & security settings',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'Organization configuration',
            content: {
              'application/json': {
                schema: { type: 'object' },
              },
            },
          },
        },
      },
    },
  },
};

const PORTAL_STRICT_HEADERS: Readonly<Record<string, string>> = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  Server: 'acme-portal-edge/1.4',
};

const API_STRICT_HEADERS: Readonly<Record<string, string>> = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
  'Content-Security-Policy': "default-src 'none'",
  'X-Content-Type-Options': 'nosniff',
  Server: 'acme-api-gateway/2.4',
};

const USERS_ROLES_PATH_RE = /^\/v1\/users\/[^/]+\/roles$/;

function sendResponse(
  res: http.ServerResponse,
  method: string,
  statusCode: number,
  headers: Record<string, string>,
  body: string = '',
): void {
  const payload = Buffer.from(body, 'utf8');
  const outHeaders: Record<string, string> = {
    ...headers,
  };
  if (statusCode !== 204 && method !== 'HEAD') {
    outHeaders['Content-Length'] = String(payload.byteLength);
  }
  res.writeHead(statusCode, outHeaders);
  if (method === 'HEAD' || statusCode === 204) {
    res.end();
  } else {
    res.end(payload);
  }
}

function sendJson(
  res: http.ServerResponse,
  method: string,
  statusCode: number,
  headers: Record<string, string>,
  data: unknown,
): void {
  sendResponse(
    res,
    method,
    statusCode,
    {
      ...headers,
      'Content-Type': 'application/json; charset=utf-8',
    },
    JSON.stringify(data),
  );
}

function extractLogicalHost(req: http.IncomingMessage): string {
  const forwarded = req.headers['x-forwarded-host'];
  const rawHeader = Array.isArray(forwarded)
    ? forwarded[0]
    : forwarded || req.headers.host || '';
  return String(rawHeader).split(':')[0]?.trim().toLowerCase() ?? '';
}

function extractSingleHeader(
  value: string | string[] | undefined,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const raw = Array.isArray(value) ? value[0] : value;
  const trimmed = raw?.trim();
  return trimmed ? trimmed : undefined;
}

/**
 * Local loopback multi-host enterprise simulation target (`portal.acme.internal` + `api.acme.internal`).
 * Binds strictly to `127.0.0.1` so zero external targets are ever contacted.
 */
export class DemoEnterpriseTargetServer {
  private server: http.Server | null = null;
  private boundOrigin: string | null = null;
  private boundPort: number | null = null;

  public get origin(): string | null {
    return this.boundOrigin;
  }

  public get port(): number | null {
    return this.boundPort;
  }

  public async start(
    port: number = 0,
  ): Promise<{ port: number; origin: string }> {
    if (this.server && this.boundPort !== null && this.boundOrigin !== null) {
      return { port: this.boundPort, origin: this.boundOrigin };
    }

    const server = http.createServer((req, res) => {
      req.resume();
      this.handleRequest(req, res);
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
      server.listen(port, '127.0.0.1');
    });

    this.server = server;
    const addr = server.address() as AddressInfo;
    this.boundPort = addr.port;
    this.boundOrigin = `http://127.0.0.1:${addr.port}`;

    return {
      port: this.boundPort,
      origin: this.boundOrigin,
    };
  }

  public async stop(): Promise<void> {
    const server = this.server;
    if (!server) {
      return;
    }
    this.server = null;
    this.boundOrigin = null;
    this.boundPort = null;

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

  private handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): void {
    const host = extractLogicalHost(req);
    const method = (req.method || 'GET').toUpperCase();
    let pathname = '/';
    try {
      const rawUrl = new URL(req.url || '/', 'http://127.0.0.1');
      pathname = rawUrl.pathname || '/';
      if (pathname.length > 1 && pathname.endsWith('/')) {
        pathname = pathname.slice(0, -1);
      }
      try {
        pathname = decodeURIComponent(pathname);
      } catch {
        // Retain raw pathname if malformed percent-encoding
      }
    } catch {
      pathname = '/';
    }

    if (host === 'portal.acme.internal') {
      this.handlePortalHost(method, pathname, res);
      return;
    }

    if (host === 'api.acme.internal') {
      this.handleApiHost(req, method, pathname, res);
      return;
    }

    sendJson(res, method, 404, { ...API_STRICT_HEADERS }, {
      error: 'unknown_virtual_host',
      host,
    });
  }

  private handlePortalHost(
    method: string,
    pathname: string,
    res: http.ServerResponse,
  ): void {
    if (method === 'OPTIONS') {
      sendResponse(res, method, 204, {
        ...PORTAL_STRICT_HEADERS,
        'Access-Control-Allow-Origin': 'https://portal.acme.internal',
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      });
      return;
    }

    if (method !== 'GET' && method !== 'HEAD') {
      sendJson(res, method, 405, { ...PORTAL_STRICT_HEADERS }, {
        error: 'method_not_allowed',
      });
      return;
    }

    if (pathname === '/') {
      sendResponse(
        res,
        method,
        200,
        {
          ...PORTAL_STRICT_HEADERS,
          'Content-Type': 'text/html; charset=utf-8',
        },
        PORTAL_INDEX_HTML,
      );
      return;
    }

    if (pathname === '/static/app.bundle.js') {
      sendResponse(
        res,
        method,
        200,
        {
          ...PORTAL_STRICT_HEADERS,
          'Content-Type': 'application/javascript; charset=utf-8',
        },
        PORTAL_APP_BUNDLE_JS,
      );
      return;
    }

    if (pathname === '/robots.txt') {
      sendResponse(
        res,
        method,
        200,
        {
          ...PORTAL_STRICT_HEADERS,
          'Content-Type': 'text/plain; charset=utf-8',
        },
        PORTAL_ROBOTS_TXT,
      );
      return;
    }

    sendJson(res, method, 404, { ...PORTAL_STRICT_HEADERS }, {
      error: 'not_found',
    });
  }

  private handleApiHost(
    req: http.IncomingMessage,
    method: string,
    pathname: string,
    res: http.ServerResponse,
  ): void {
    // 1. Root service metadata
    if (pathname === '/' && (method === 'GET' || method === 'HEAD')) {
      sendJson(res, method, 200, { ...API_STRICT_HEADERS }, {
        service: 'acme-api',
        version: '2.4.0',
      });
      return;
    }

    // 2. OpenAPI 3.0 specification
    if (pathname === '/openapi.json' && (method === 'GET' || method === 'HEAD')) {
      sendJson(res, method, 200, { ...API_STRICT_HEADERS }, API_OPENAPI_SPEC);
      return;
    }

    // 3. COMPLIANT ENDPOINT: /v1/profile
    if (
      pathname === '/v1/profile' &&
      (method === 'GET' || method === 'HEAD' || method === 'OPTIONS')
    ) {
      const compliantHeaders: Record<string, string> = {
        'Strict-Transport-Security': 'max-age=63072000',
        'Content-Security-Policy': "default-src 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Access-Control-Allow-Origin': 'https://portal.acme.internal',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
      };

      if (method === 'OPTIONS') {
        sendResponse(res, method, 204, compliantHeaders);
        return;
      }

      const role = extractSingleHeader(req.headers['x-session-role'])?.toLowerCase();
      if (!role) {
        sendJson(res, method, 401, compliantHeaders, {
          error: 'unauthorized',
        });
        return;
      }

      if (role === 'viewer') {
        sendJson(res, method, 200, compliantHeaders, {
          userId: 'u-10',
          tier: 'viewer',
        });
        return;
      }

      if (role === 'admin') {
        sendJson(res, method, 200, compliantHeaders, {
          userId: 'u-1',
          tier: 'admin',
        });
        return;
      }

      sendJson(res, method, 403, compliantHeaders, {
        error: 'forbidden',
      });
      return;
    }

    // 4. POSTURE FINDING (PERMISSIVE_CORS): /v1/org/settings
    if (
      pathname === '/v1/org/settings' &&
      (method === 'GET' || method === 'HEAD' || method === 'OPTIONS')
    ) {
      const reflectedOrigin = String(req.headers.origin || '*');
      const corsHeaders: Record<string, string> = {
        ...API_STRICT_HEADERS,
        'Access-Control-Allow-Origin': reflectedOrigin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        Vary: 'Origin',
      };

      sendJson(res, method, 200, corsHeaders, {
        orgId: 'acme-prod',
        ssoEnabled: true,
      });
      return;
    }

    // 5. POSTURE FINDING (AUTHZ_SCHEMA_DRIFT): /v1/users/:id/roles
    if (
      USERS_ROLES_PATH_RE.test(pathname) &&
      (method === 'GET' || method === 'HEAD' || method === 'OPTIONS')
    ) {
      const cleanCorsHeaders: Record<string, string> = {
        ...API_STRICT_HEADERS,
        'Access-Control-Allow-Origin': 'https://portal.acme.internal',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
      };

      if (method === 'OPTIONS') {
        sendResponse(res, method, 204, cleanCorsHeaders);
        return;
      }

      sendJson(res, method, 200, cleanCorsHeaders, {
        roles: ['admin'],
        isAdmin: true,
        permissions: ['org:admin', 'secrets:read'],
        ssoSigningKeyId: 'key-prod-01',
      });
      return;
    }

    // 6. State-changing endpoint audited strictly via OPTIONS: /v1/reports/export
    if (pathname === '/v1/reports/export' && method === 'OPTIONS') {
      sendResponse(res, method, 204, {
        ...API_STRICT_HEADERS,
        'Access-Control-Allow-Origin': 'https://portal.acme.internal',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
      });
      return;
    }

    sendJson(res, method, 404, { ...API_STRICT_HEADERS }, {
      error: 'not_found',
    });
  }
}
