import http from 'node:http';
import https from 'node:https';

export interface GovernedHttpClientOptions {
  gatewayUrl: string;
  taskToken: string;
  defaultAuthProfile?: string;
}

export interface GovernedRequestOptions {
  method?: 'GET' | 'HEAD' | 'OPTIONS';
  headers?: Record<string, string>;
  authProfile?: string;
}

export interface GovernedHttpResponse {
  status: number;
  headers: Record<string, string>;
  bodyText: string;
  harSha256?: string;
}

/**
 * HTTP client for subagents that routes all requests through EgressGateway
 * with task token authentication and optional named authProfile elevation.
 */
export class GovernedHttpClient {
  private readonly gatewayUrl: string;
  private readonly taskToken: string;
  private readonly defaultAuthProfile?: string;

  public constructor(opts: GovernedHttpClientOptions) {
    this.gatewayUrl = opts.gatewayUrl.replace(/\/+$/, '');
    this.taskToken = opts.taskToken;
    this.defaultAuthProfile = opts.defaultAuthProfile;
  }

  public request(
    targetUrl: string,
    opts?: GovernedRequestOptions,
  ): Promise<GovernedHttpResponse> {
    const method = (opts?.method ?? 'GET').toUpperCase();
    const parsedGateway = new URL(this.gatewayUrl);
    const basePath =
      parsedGateway.pathname === '/'
        ? ''
        : parsedGateway.pathname.replace(/\/+$/, '');
    const requestPath = `${basePath}/__aegis_forward?url=${encodeURIComponent(targetUrl)}`;

    const outgoingHeaders: Record<string, string> = {};
    if (opts?.headers) {
      for (const [k, v] of Object.entries(opts.headers)) {
        outgoingHeaders[k] = v;
      }
    }

    outgoingHeaders['x-aegis-target-url'] = targetUrl;
    outgoingHeaders['x-aegis-task-token'] = this.taskToken;

    const effectiveAuthProfile =
      opts?.authProfile !== undefined
        ? opts.authProfile
        : this.defaultAuthProfile;
    if (effectiveAuthProfile) {
      outgoingHeaders['x-aegis-auth-profile'] = effectiveAuthProfile;
    }

    const requestFn =
      parsedGateway.protocol === 'https:' ? https.request : http.request;
    const hostname = parsedGateway.hostname.replace(/^\[|\]$/g, '');
    const port = parsedGateway.port
      ? Number(parsedGateway.port)
      : parsedGateway.protocol === 'https:'
        ? 443
        : 80;

    return new Promise<GovernedHttpResponse>((resolve, reject) => {
      const req = requestFn(
        {
          protocol: parsedGateway.protocol,
          hostname,
          port,
          method,
          path: requestPath,
          headers: outgoingHeaders,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer | string) => {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          });
          res.on('end', () => {
            const responseHeaders: Record<string, string> = {};
            for (const [key, val] of Object.entries(res.headers)) {
              if (val === undefined) {
                continue;
              }
              responseHeaders[key.toLowerCase()] = Array.isArray(val)
                ? val.join(', ')
                : val;
            }

            const harSha256 = responseHeaders['x-aegis-har-sha256'];
            resolve({
              status: res.statusCode ?? 0,
              headers: responseHeaders,
              bodyText: Buffer.concat(chunks).toString('utf8'),
              ...(harSha256 ? { harSha256 } : {}),
            });
          });
          res.on('error', (err) => {
            reject(err);
          });
        },
      );

      req.on('error', (err) => {
        reject(err);
      });

      req.end();
    });
  }
}
