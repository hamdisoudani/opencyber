import picomatch from 'picomatch';
import { parse, stringify } from 'yaml';
import { z } from 'zod';

export const AuthProfileConfigSchema = z.object({
  description: z.string().optional(),
  allowedMethods: z
    .array(z.enum(['GET', 'HEAD', 'OPTIONS']))
    .default(['GET', 'HEAD', 'OPTIONS']),
  headerNames: z.array(z.string()).default([]),
});

export type AuthProfileConfig = z.infer<typeof AuthProfileConfigSchema>;

export const ScopeConfigSchema = z.object({
  engagementId: z.string().min(1),
  programName: z.string().min(1),
  authorizedDomains: z.array(z.string().min(1)).min(1),
  excludedHosts: z.array(z.string()).default([]),
  excludedPaths: z.array(z.string()).default([]),
  maxRpsPerHost: z.number().positive().default(5),
  complianceHeaders: z.record(z.string(), z.string()).default({}),
  authProfiles: z.record(z.string(), AuthProfileConfigSchema).default({}),
  strictReadOnly: z.boolean().default(true),
});

export type ScopeConfig = z.infer<typeof ScopeConfigSchema>;

export interface ScopeEvaluationResult {
  allowed: boolean;
  reason?: string;
  normalizedHost: string;
  normalizedPath: string;
}

export function parseScopeYaml(yamlContent: string): ScopeConfig {
  const raw: unknown = parse(yamlContent);
  return ScopeConfigSchema.parse(raw);
}

export function serializeScopeYaml(config: ScopeConfig): string {
  const validated = ScopeConfigSchema.parse(config);
  return stringify(validated);
}

export function normalizeHostname(rawHost: string): string {
  let host = rawHost.trim().toLowerCase();
  if (!host) {
    return '';
  }

  if (host.startsWith('[')) {
    const closeBracketIdx = host.indexOf(']');
    if (closeBracketIdx !== -1) {
      if (host[closeBracketIdx + 1] === ':') {
        host = host.slice(0, closeBracketIdx + 1);
      }
      return host;
    }
  } else {
    const firstColon = host.indexOf(':');
    const lastColon = host.lastIndexOf(':');
    if (firstColon !== -1 && firstColon === lastColon) {
      host = host.slice(0, firstColon);
    }
  }

  host = host.replace(/\.+$/, '');
  return host;
}

export function isHostAuthorized(
  hostname: string,
  authorizedDomains: string[],
): boolean {
  const normalizedHost = normalizeHostname(hostname);
  if (
    !normalizedHost ||
    normalizedHost.includes('*') ||
    normalizedHost.startsWith('.')
  ) {
    return false;
  }

  for (const rawDomain of authorizedDomains) {
    const pattern = normalizeHostname(rawDomain);
    if (!pattern) {
      continue;
    }

    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(2);
      if (!suffix) {
        continue;
      }
      if (
        normalizedHost.endsWith(`.${suffix}`) &&
        normalizedHost.length > suffix.length + 1
      ) {
        return true;
      }
    } else if (normalizedHost === pattern) {
      return true;
    }
  }

  return false;
}

export function normalizeUrlPath(rawPath: string): string {
  const trimmed = rawPath.trim();
  const withoutQueryOrHash = trimmed.split(/[?#]/)[0] ?? '/';

  let decoded = withoutQueryOrHash;
  try {
    decoded = decodeURIComponent(withoutQueryOrHash);
  } catch {
    decoded = withoutQueryOrHash;
  }

  // Normalize backslashes and collapse leading slashes so '//host/...' cannot
  // be parsed as a scheme-relative URL with host 'host'.
  const slashNormalized = decoded.replace(/\\/g, '/');
  const withLeadingSlash = (
    slashNormalized.startsWith('/') ? slashNormalized : `/${slashNormalized}`
  ).replace(/\/+/g, '/');

  // Escape any '?' or '#' introduced by percent-decoding so new URL() keeps
  // the entire path inside pathname during '..' dot-segment resolution.
  const safeRelativeUrl = withLeadingSlash
    .replace(/\?/g, '%3F')
    .replace(/#/g, '%23');

  const resolvedPathname = new URL(safeRelativeUrl, 'http://localhost').pathname;
  let reDecoded = resolvedPathname;
  try {
    reDecoded = decodeURIComponent(resolvedPathname);
  } catch {
    reDecoded = resolvedPathname;
  }

  return reDecoded.replace(/\/+/g, '/') || '/';
}

export function isPathExcluded(
  rawPath: string,
  excludedPaths: string[],
): boolean {
  if (excludedPaths.length === 0) {
    return false;
  }

  const normalizedPath = normalizeUrlPath(rawPath);
  const trimmedTrailingSlash =
    normalizedPath.length > 1 && normalizedPath.endsWith('/')
      ? normalizedPath.slice(0, -1)
      : normalizedPath;

  const matcher = picomatch(excludedPaths, { dot: true });
  if (matcher(normalizedPath) || matcher(trimmedTrailingSlash)) {
    return true;
  }

  for (const pattern of excludedPaths) {
    if (pattern.endsWith('/**')) {
      const baseDir = pattern.slice(0, -3) || '/';
      if (normalizedPath === baseDir || trimmedTrailingSlash === baseDir) {
        return true;
      }
    }
  }

  return false;
}

export function evaluateTargetScope(
  urlInput: string,
  scope: ScopeConfig,
): ScopeEvaluationResult {
  let parsed: URL;
  try {
    parsed = new URL(urlInput);
  } catch {
    return {
      allowed: false,
      reason: 'INVALID_URL',
      normalizedHost: '',
      normalizedPath: '',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      allowed: false,
      reason: 'INVALID_URL',
      normalizedHost: '',
      normalizedPath: '',
    };
  }

  const normalizedHost = normalizeHostname(parsed.hostname);
  const normalizedPath = normalizeUrlPath(parsed.pathname);

  if (!normalizedHost) {
    return {
      allowed: false,
      reason: 'INVALID_URL',
      normalizedHost: '',
      normalizedPath: '',
    };
  }

  if (!isHostAuthorized(normalizedHost, scope.authorizedDomains)) {
    return {
      allowed: false,
      reason: 'OUT_OF_SCOPE_HOST',
      normalizedHost,
      normalizedPath,
    };
  }

  if (
    scope.excludedHosts.length > 0 &&
    isHostAuthorized(normalizedHost, scope.excludedHosts)
  ) {
    return {
      allowed: false,
      reason: 'EXCLUDED_HOST',
      normalizedHost,
      normalizedPath,
    };
  }

  if (isPathExcluded(parsed.pathname, scope.excludedPaths)) {
    return {
      allowed: false,
      reason: 'EXCLUDED_PATH',
      normalizedHost,
      normalizedPath,
    };
  }

  return {
    allowed: true,
    normalizedHost,
    normalizedPath,
  };
}
