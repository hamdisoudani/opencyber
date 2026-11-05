import { z } from 'zod';
import { normalizeHostname } from './scope.js';
import { sha256Hex } from './tokens.js';

export const HttpMethodSchema = z.enum([
  'GET',
  'HEAD',
  'OPTIONS',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
]);

export type HttpMethod = z.infer<typeof HttpMethodSchema>;

const DYNAMIC_SEGMENT_PATTERNS: readonly RegExp[] = [
  /^:[a-zA-Z_][a-zA-Z0-9_]*$/,
  /^\{[^/]+\}$/,
  /^\[.*\]$/,
  /^<[^>]+>$/,
  /^\d+$/,
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  /^[0-9a-f]{16,}$/i,
];

function isDynamicSegment(segment: string): boolean {
  return DYNAMIC_SEGMENT_PATTERNS.some((re) => re.test(segment));
}

export function canonicalizeRoutePath(rawPath: string): {
  canonicalPath: string;
  paramCount: number;
} {
  let path = rawPath.trim().replace(/[?#].*$/, '');
  path = path.startsWith('/') ? path : `/${path}`;
  path = path.replace(/\/+/g, '/');

  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }

  if (path === '/') {
    return { canonicalPath: '/', paramCount: 0 };
  }

  const rawSegments = path.slice(1).split('/');
  let paramCount = 0;

  const canonicalSegments = rawSegments.map((seg) => {
    if (isDynamicSegment(seg)) {
      paramCount += 1;
      return '{param}';
    }
    return seg;
  });

  return {
    canonicalPath: `/${canonicalSegments.join('/')}`,
    paramCount,
  };
}

export interface EndpointKey {
  endpointId: string;
  host: string;
  method: string;
  canonicalPath: string;
  fileName: string;
  repoRelativePath: string;
}

export function buildEndpointKey(
  host: string,
  method: string,
  rawPath: string,
): EndpointKey {
  const normalizedHost = normalizeHostname(host);
  const normalizedMethod = method.trim().toUpperCase();
  const { canonicalPath } = canonicalizeRoutePath(rawPath);

  const endpointId = `${normalizedHost}:${normalizedMethod}:${canonicalPath}`;
  const hash8 = sha256Hex(endpointId).slice(0, 8);

  let slug = canonicalPath
    .replaceAll('{param}', 'param')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');

  if (!slug) {
    slug = 'root';
  }

  slug = slug.slice(0, 48).replace(/_+$/, '');
  if (!slug) {
    slug = 'root';
  }

  const fileName = `${normalizedMethod}_${slug}_${hash8}.yaml`;
  const repoRelativePath = `surface/hosts/${normalizedHost}/endpoints/${fileName}`;

  return {
    endpointId,
    host: normalizedHost,
    method: normalizedMethod,
    canonicalPath,
    fileName,
    repoRelativePath,
  };
}
