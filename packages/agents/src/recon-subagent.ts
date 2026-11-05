import {
  type HostEntity,
  normalizeHostname,
  type ObservedEndpointItem,
  type RouteObservationBatch,
  RouteObservationBatchSchema,
} from '@opencyber/shared';
import type { HttpFetcher } from './types.js';

export interface ReconSeedTarget {
  host: string;
  baseUrl: string;
}

export interface RunReconSubagentOptions {
  runId: string;
  seedTargets: ReconSeedTarget[];
  fetcher: HttpFetcher;
  maxRequests?: number;
}

export interface ReconSubagentResult {
  batch: RouteObservationBatch;
  discoveredBundles: Array<{ host: string; bundleUrl: string }>;
  discoveredOpenApiUrls: Array<{ host: string; specUrl: string }>;
}

const SECURITY_HEADER_KEYS = new Set<string>([
  'strict-transport-security',
  'content-security-policy',
  'content-security-policy-report-only',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cross-origin-embedder-policy',
  'access-control-allow-origin',
  'access-control-allow-credentials',
]);

function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, val] of Object.entries(headers)) {
    if (typeof val === 'string') {
      out[key.toLowerCase()] = val.trim();
    }
  }
  return out;
}

function extractStackFingerprints(
  lowerHeaders: Record<string, string>,
  bodyText: string,
): string[] {
  const fingerprints = new Set<string>();

  if (lowerHeaders.server) {
    fingerprints.add(`server:${lowerHeaders.server}`);
  }
  if (lowerHeaders['x-powered-by']) {
    fingerprints.add(`x-powered-by:${lowerHeaders['x-powered-by']}`);
  }
  if (lowerHeaders.via) {
    fingerprints.add(`via:${lowerHeaders.via}`);
  }
  if (lowerHeaders['cf-ray']) {
    fingerprints.add('cdn:cloudflare');
  }

  if (/__NEXT_DATA__|_next\/static/i.test(bodyText)) {
    fingerprints.add('framework:nextjs');
  }
  if (/id=["']root["']|data-reactroot/i.test(bodyText)) {
    fingerprints.add('frontend:react');
  }
  if (/\/@vite\/|assets\/index-[a-z0-9_-]+\.js/i.test(bodyText)) {
    fingerprints.add('bundler:vite');
  }

  return Array.from(fingerprints);
}

function extractScriptSrcUrls(html: string, baseUrl: string): string[] {
  const found = new Set<string>();
  const scriptRegex = /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>"']+))[^>]*>/gi;

  let match: RegExpExecArray | null;
  while ((match = scriptRegex.exec(html)) !== null) {
    const rawSrc = (match[1] ?? match[2] ?? match[3] ?? '').trim();
    if (!rawSrc || /^(?:data:|javascript:|blob:)/i.test(rawSrc)) {
      continue;
    }
    try {
      const resolved = new URL(rawSrc, `${baseUrl.replace(/\/+$/, '')}/`).toString();
      found.add(resolved);
    } catch {
      // Ignore malformed script src attributes
    }
  }

  return Array.from(found);
}

function isValidOpenApiJson(bodyText: string): boolean {
  try {
    const parsed: unknown = JSON.parse(bodyText);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return false;
    }
    const obj = parsed as Record<string, unknown>;
    return (
      typeof obj.openapi === 'string' ||
      typeof obj.swagger === 'string' ||
      (typeof obj.paths === 'object' && obj.paths !== null)
    );
  } catch {
    return false;
  }
}

function extractRobotsRoutes(robotsText: string): string[] {
  const routes = new Set<string>();
  for (const rawLine of robotsText.split(/\r?\n/)) {
    const line = rawLine.split('#')[0]?.trim() ?? '';
    const directiveMatch = line.match(/^(?:Allow|Disallow)\s*:\s*(\/\S*)/i);
    if (directiveMatch && directiveMatch[1]) {
      const candidate = directiveMatch[1].replace(/\*.*$/, '').replace(/\$+$/, '').trim();
      if (candidate.startsWith('/') && candidate.length > 1) {
        routes.add(candidate);
      }
    }
  }
  return Array.from(routes);
}

export async function runReconSubagent(
  opts: RunReconSubagentOptions,
): Promise<ReconSubagentResult> {
  const maxRequests = opts.maxRequests ?? 10;
  const nowIso = new Date().toISOString();
  let requestsUsed = 0;

  const hostMap = new Map<string, HostEntity>();
  const endpointMap = new Map<string, ObservedEndpointItem>();
  const bundleSet = new Set<string>();
  const discoveredBundles: Array<{ host: string; bundleUrl: string }> = [];
  const openApiSet = new Set<string>();
  const discoveredOpenApiUrls: Array<{ host: string; specUrl: string }> = [];

  const probePaths = ['/', '/openapi.json', '/robots.txt'] as const;

  for (const seed of opts.seedTargets) {
    if (requestsUsed >= maxRequests) {
      break;
    }

    const host = normalizeHostname(seed.host);
    const cleanBaseUrl = seed.baseUrl.replace(/\/+$/, '');

    let hostEntity = hostMap.get(host);
    if (!hostEntity) {
      hostEntity = {
        hostname: host,
        discoveredAt: nowIso,
        sources: ['recon-probe'],
        securityHeaders: {},
        fingerprints: [],
      };
      hostMap.set(host, hostEntity);
    }

    for (const probePath of probePaths) {
      if (requestsUsed >= maxRequests) {
        break;
      }

      requestsUsed += 1;
      const targetUrl = `${cleanBaseUrl}${probePath}`;

      let res;
      let effectiveUrl = targetUrl;
      try {
        res = await opts.fetcher.request(targetUrl, { method: 'GET' });
        const initialHeaders = normalizeHeaders(res.headers);
        if (
          (res.status === 301 ||
            res.status === 302 ||
            res.status === 307 ||
            res.status === 308) &&
          initialHeaders.location &&
          requestsUsed < maxRequests
        ) {
          try {
            const redirectUrl = new URL(initialHeaders.location, targetUrl).toString();
            requestsUsed += 1;
            const followed = await opts.fetcher.request(redirectUrl, { method: 'GET' });
            if (followed.status !== 451) {
              res = followed;
              effectiveUrl = redirectUrl;
            }
          } catch {
            // Keep initial redirect response if Location is malformed
          }
        }
      } catch {
        continue;
      }

      const lowerHeaders = normalizeHeaders(res.headers);

      if (probePath === '/' || hostEntity.statusCode === undefined) {
        hostEntity.statusCode = res.status;
      }
      if (lowerHeaders.server && !hostEntity.serverHeader) {
        hostEntity.serverHeader = lowerHeaders.server;
      }

      for (const [hKey, hVal] of Object.entries(lowerHeaders)) {
        if (SECURITY_HEADER_KEYS.has(hKey)) {
          hostEntity.securityHeaders[hKey] = hVal;
        }
      }

      const discoveredFp = extractStackFingerprints(lowerHeaders, res.bodyText);
      hostEntity.fingerprints = Array.from(
        new Set([...hostEntity.fingerprints, ...discoveredFp]),
      );

      // Record reachable probe endpoints (exclude 404/451/405 misses)
      if (res.status >= 200 && res.status < 404) {
        const epKey = `${host}|GET|${probePath}`;
        endpointMap.set(epKey, {
          host,
          method: 'GET',
          rawPath: probePath,
          source: 'recon-probe',
          parameters: [],
          ...(res.status === 401 || res.status === 403 ? { authRequired: true } : {}),
          ...(lowerHeaders['content-type']
            ? { responseContentType: lowerHeaders['content-type'] }
            : {}),
        });
      }

      if (probePath === '/' && res.status >= 200 && res.status < 400) {
        const effectiveOrigin = (() => {
          try {
            const u = new URL(effectiveUrl);
            return `${u.protocol}//${u.host}`;
          } catch {
            return cleanBaseUrl;
          }
        })();
        const scripts = extractScriptSrcUrls(res.bodyText, effectiveOrigin);
        for (const bundleUrl of scripts) {
          const bundleKey = `${host}|${bundleUrl}`;
          if (!bundleSet.has(bundleKey)) {
            bundleSet.add(bundleKey);
            discoveredBundles.push({ host, bundleUrl });
          }
        }
      }

      if (probePath === '/openapi.json' && res.status >= 200 && res.status < 300) {
        if (isValidOpenApiJson(res.bodyText)) {
          const specKey = `${host}|${targetUrl}`;
          if (!openApiSet.has(specKey)) {
            openApiSet.add(specKey);
            discoveredOpenApiUrls.push({ host, specUrl: targetUrl });
          }
        }
      }

      if (probePath === '/robots.txt' && res.status === 200) {
        for (const hintedPath of extractRobotsRoutes(res.bodyText)) {
          const epKey = `${host}|GET|${hintedPath}`;
          if (!endpointMap.has(epKey)) {
            endpointMap.set(epKey, {
              host,
              method: 'GET',
              rawPath: hintedPath,
              source: 'robots-txt',
              parameters: [],
            });
          }
        }
      }
    }
  }

  const batch = RouteObservationBatchSchema.parse({
    runId: opts.runId,
    agentRole: 'RECON',
    createdAt: nowIso,
    hosts: Array.from(hostMap.values()),
    endpoints: Array.from(endpointMap.values()),
  });

  return {
    batch,
    discoveredBundles,
    discoveredOpenApiUrls,
  };
}
