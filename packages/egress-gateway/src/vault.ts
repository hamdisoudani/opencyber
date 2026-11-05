export const REDACTED_BY_SESSION_VAULT = '[REDACTED_BY_SESSION_VAULT]';

const DEFAULT_SENSITIVE_HEADERS = [
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
] as const;

/**
 * Isolated credential store for EgressGateway.
 * Injects secret session headers onto authorized outbound requests so subagents
 * never handle raw credentials, and redacts sensitive headers from HAR captures.
 */
export class SessionVault {
  private readonly profiles = new Map<string, Record<string, string>>();
  private readonly sensitiveHeaderNames = new Set<string>(
    DEFAULT_SENSITIVE_HEADERS,
  );

  public registerProfile(
    profileName: string,
    headers: Record<string, string>,
  ): void {
    const normalizedProfile = profileName.trim();
    if (!normalizedProfile) {
      throw new Error('SessionVault profileName must be a non-empty string');
    }

    const storedHeaders: Record<string, string> = {};
    for (const [headerName, headerValue] of Object.entries(headers)) {
      storedHeaders[headerName] = headerValue;
      const lower = headerName.trim().toLowerCase();
      if (lower) {
        this.sensitiveHeaderNames.add(lower);
      }
    }

    this.profiles.set(normalizedProfile, storedHeaders);
  }

  public registerSensitiveHeaderNames(headerNames: Iterable<string>): void {
    for (const headerName of headerNames) {
      const lower = headerName.trim().toLowerCase();
      if (lower) {
        this.sensitiveHeaderNames.add(lower);
      }
    }
  }

  public hasProfile(profileName: string): boolean {
    return this.profiles.has(profileName);
  }

  public getInjectedHeaders(profileName: string): Record<string, string> {
    const stored = this.profiles.get(profileName);
    if (!stored) {
      return {};
    }
    return { ...stored };
  }

  public redactHeaders(headers: Record<string, string>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (this.sensitiveHeaderNames.has(key.trim().toLowerCase())) {
        sanitized[key] = REDACTED_BY_SESSION_VAULT;
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }
}
