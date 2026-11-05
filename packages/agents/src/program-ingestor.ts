import {
  evaluateTargetScope,
  type FindingReport,
  isHostAuthorized,
  normalizeHostname,
  type ScopeConfig,
  ScopeConfigSchema,
} from '@opencyber/shared';
import { z } from 'zod';
import type { ChatTurnMessage, StructuredLlmClient } from './groq-client.js';
import type { ReconSeedTarget } from './recon-subagent.js';

export const ProgramChatActionSchema = z.enum([
  'INITIALIZE_OR_UPDATE_SCOPE_AND_SCAN',
  'RESCAN_CURRENT_SCOPE',
  'ANSWER_QUESTION',
]);

export type ProgramChatAction = z.infer<typeof ProgramChatActionSchema>;

export const ParsedProgramIntentSchema = z.object({
  action: ProgramChatActionSchema,
  programName: z.string().min(1),
  authorizedDomains: z.array(z.string()).default([]),
  excludedHosts: z.array(z.string()).default([]),
  excludedPaths: z.array(z.string()).default([]),
  maxRpsPerHost: z.number().min(1).max(50).default(5),
  complianceHeaders: z.record(z.string(), z.string()).default({}),
  explicitSeedUrls: z.array(z.string()).default([]),
  focusSummary: z.string().default(''),
});

export type ParsedProgramIntent = z.infer<typeof ParsedProgramIntentSchema>;

export interface HeuristicBriefSignals {
  action: ProgramChatAction;
  programName: string;
  authorizedDomains: string[];
  excludedHosts: string[];
  excludedPaths: string[];
  maxRpsPerHost: number;
  hasExplicitRps: boolean;
  hasExplicitScopeSection: boolean;
  complianceHeaders: Record<string, string>;
  explicitSeedUrls: string[];
}

export interface ParseBugcrowdBriefOptions {
  userMessage: string;
  existingScope?: ScopeConfig;
  conversationHistory?: ChatTurnMessage[];
  llmClient?: StructuredLlmClient;
}

export interface BuildProgramScopeOptions {
  engagementId: string;
  intent: ParsedProgramIntent;
  existingScope?: ScopeConfig;
}

export interface OrchestratorRunSummary {
  runId: string;
  sandboxProvider: string;
  hostsDiscovered: number;
  canonicalEndpoints: number;
  compliantTombstones: number;
  mergedFindings: string[];
  blockedScope451: number;
}

export interface StreamOrchestratorReplyOptions {
  userMessage: string;
  intent: ParsedProgramIntent;
  scope: ScopeConfig;
  runSummary?: OrchestratorRunSummary;
  findings?: FindingReport[];
  telemetryContext?: string;
  conversationHistory?: ChatTurnMessage[];
  llmClient?: StructuredLlmClient;
  onDelta: (delta: string) => void | Promise<void>;
}

const BOUNTY_PLATFORM_METADATA_HOSTS = new Set<string>([
  'bugcrowd.com',
  'www.bugcrowd.com',
  'hackerone.com',
  'www.hackerone.com',
  'intigriti.com',
  'app.intigriti.com',
  'yeswehack.com',
  'www.yeswehack.com',
  'immunefi.com',
  'www.immunefi.com',
]);

function isBountyPlatformMetadataHost(
  domainPattern: string,
  programNameHint: string,
): boolean {
  const clean = normalizeHostname(domainPattern.replace(/^\*\./, ''));
  if (!BOUNTY_PLATFORM_METADATA_HOSTS.has(clean)) {
    return false;
  }
  const baseLabel = clean.replace(/^www\./, '').replace(/^app\./, '').split('.')[0] ?? '';
  const lowerTitle = programNameHint.toLowerCase();
  if (
    baseLabel &&
    new RegExp(`^\\s*${baseLabel}\\b`, 'i').test(lowerTitle)
  ) {
    return false;
  }
  return true;
}

const NON_TLD_FILE_EXTENSIONS = new Set<string>([
  'json',
  'yaml',
  'yml',
  'js',
  'mjs',
  'cjs',
  'ts',
  'tsx',
  'jsx',
  'py',
  'rb',
  'php',
  'html',
  'htm',
  'css',
  'scss',
  'txt',
  'md',
  'csv',
  'xml',
  'pdf',
  'png',
  'jpg',
  'jpeg',
  'gif',
  'svg',
  'ico',
  'woff',
  'woff2',
  'map',
  'lock',
  'env',
  'sql',
  'log',
  'conf',
  'ini',
  'toml',
  'tar',
  'gz',
]);

const IGNORED_RESPONSE_SECURITY_HEADERS = new Set<string>([
  'x-content-type-options',
  'x-frame-options',
  'x-xss-protection',
  'x-powered-by',
  'x-request-id',
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
  'x-envoy-upstream-service-time',
]);

const GENERIC_HEADING_NOISE_RE =
  /^(?:in[\s-]*scope|out[\s-]*of[\s-]*scope|targets?|scope|authorized(?:\s+targets?|\s+scope)?|excluded(?:\s+targets?)?|exclusions?|rules(?:\s+of\s+engagement)?|program\s+rules|testing\s+(?:rules|requirements|guidelines)|rate\s+limit(?:s|ing)?|safe\s+harbor|overview|summary|focus\s+areas?|rewards?|bount(?:y|ies)|credentials?)$/i;

function isValidIpv4(candidate: string): boolean {
  const parts = candidate.split('.');
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) {
      return false;
    }
    const n = Number.parseInt(p, 10);
    return n >= 0 && n <= 255;
  });
}

export function sanitizeDomainPattern(raw: string): string | null {
  let cleaned = raw
    .trim()
    .replace(/^[`'"([<]+|[`'")\]>.,;]+$/g, '')
    .trim()
    .toLowerCase();

  if (!cleaned || cleaned.includes('@') || cleaned.includes('_')) {
    return null;
  }

  let isWildcard = false;
  if (/^https?:\/\/\*\./i.test(cleaned)) {
    cleaned = cleaned.replace(/^https?:\/\/\*\./i, '');
    isWildcard = true;
  } else if (/^https?:\/\//i.test(cleaned)) {
    try {
      const parsed = new URL(cleaned);
      cleaned = normalizeHostname(parsed.hostname);
    } catch {
      return null;
    }
  } else if (cleaned.startsWith('*.')) {
    isWildcard = true;
    cleaned = cleaned.slice(2);
  }

  const slashIdx = cleaned.indexOf('/');
  if (slashIdx !== -1) {
    cleaned = cleaned.slice(0, slashIdx);
  }

  cleaned = normalizeHostname(cleaned);
  if (!cleaned) {
    return null;
  }

  if (!isWildcard && (cleaned === 'localhost' || isValidIpv4(cleaned))) {
    return cleaned;
  }

  const labels = cleaned.split('.');
  if (labels.length < 2) {
    return null;
  }

  const labelRegex = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  if (!labels.every((lbl) => labelRegex.test(lbl))) {
    return null;
  }

  const tld = labels[labels.length - 1] ?? '';
  if (!/^[a-z]{2,24}$/.test(tld) || NON_TLD_FILE_EXTENSIONS.has(tld)) {
    return null;
  }

  return isWildcard ? `*.${cleaned}` : cleaned;
}

function sanitizeExcludedPath(raw: string): string | null {
  let cleaned = raw
    .trim()
    .replace(/^[`'"([<]+|[`'")\]>.,;]+$/g, '')
    .trim();

  if (!cleaned) {
    return null;
  }

  if (/^https?:\/\//i.test(cleaned)) {
    try {
      const parsed = new URL(cleaned);
      cleaned = parsed.pathname;
    } catch {
      return null;
    }
  }

  const queryIdx = cleaned.search(/[?#]/);
  if (queryIdx !== -1) {
    cleaned = cleaned.slice(0, queryIdx);
  }

  if (!cleaned.startsWith('/') || cleaned === '/' || cleaned.startsWith('//')) {
    return null;
  }

  return cleaned;
}

function sanitizeExplicitUrl(raw: string): string | null {
  const cleaned = raw
    .trim()
    .replace(/^[`'"([<]+|[`'")\]>.,;]+$/g, '')
    .trim();

  if (!/^https?:\/\//i.test(cleaned) || cleaned.includes('*')) {
    return null;
  }

  try {
    const parsed = new URL(cleaned);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    const host = sanitizeDomainPattern(parsed.hostname);
    if (!host || host.startsWith('*.')) {
      return null;
    }
    parsed.hash = '';
    return parsed.toString().replace(/\/$/, parsed.pathname === '/' ? '' : '/');
  } catch {
    return null;
  }
}

function derivePrimaryDomainLabel(domains: string[]): string | undefined {
  for (const d of domains) {
    const stripped = d.startsWith('*.') ? d.slice(2) : d;
    if (stripped) {
      return stripped;
    }
  }
  return undefined;
}

function inferScheme(host: string): 'http' | 'https' {
  const normalized = normalizeHostname(host);
  if (
    normalized === 'localhost' ||
    normalized === '127.0.0.1' ||
    normalized === '[::1]' ||
    normalized.endsWith('.internal') ||
    normalized.endsWith('.local') ||
    normalized.endsWith('.test')
  ) {
    return 'http';
  }
  return 'https';
}

type BriefSectionMode = 'NEUTRAL' | 'IN_SCOPE' | 'OUT_OF_SCOPE';

function extractSegmentTargets(
  segment: string,
  mode: BriefSectionMode,
  authorizedSet: Set<string>,
  excludedHostSet: Set<string>,
  excludedPathSet: Set<string>,
  explicitSeedUrlSet: Set<string>,
): void {
  let working = segment;

  // 1. Extract explicit http(s):// URLs (including wildcard URLs like https://*.example.com)
  const urlRegex = /https?:\/\/[^\s<>'")\]`,;]+/gi;
  working = working.replace(urlRegex, (rawMatch) => {
    const trimmedUrl = rawMatch.replace(/[.,;)\]`'"]+$/, '');
    if (/^https?:\/\/\*\./i.test(trimmedUrl)) {
      const wildcardDomain = sanitizeDomainPattern(trimmedUrl);
      if (wildcardDomain) {
        if (mode === 'OUT_OF_SCOPE') {
          excludedHostSet.add(wildcardDomain);
        } else {
          authorizedSet.add(wildcardDomain);
        }
      }
      return ' ';
    }

    try {
      const parsed = new URL(trimmedUrl);
      const hostPattern = sanitizeDomainPattern(parsed.hostname);
      if (!hostPattern) {
        return ' ';
      }

      if (mode === 'OUT_OF_SCOPE') {
        const cleanPath = sanitizeExcludedPath(parsed.pathname);
        if (cleanPath) {
          excludedPathSet.add(cleanPath);
        } else {
          excludedHostSet.add(hostPattern);
        }
      } else {
        authorizedSet.add(hostPattern);
        const cleanSeed = sanitizeExplicitUrl(trimmedUrl);
        if (cleanSeed) {
          explicitSeedUrlSet.add(cleanSeed);
        }
      }
    } catch {
      // Ignore malformed URLs
    }
    return ' ';
  });

  // 2. Extract wildcard domains (*.example.com)
  const wildcardRegex =
    /(?<![A-Za-z0-9@/])(\*\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)/gi;
  working = working.replace(wildcardRegex, (_full, candidate: string) => {
    const pattern = sanitizeDomainPattern(candidate);
    if (pattern) {
      if (mode === 'OUT_OF_SCOPE') {
        excludedHostSet.add(pattern);
      } else {
        authorizedSet.add(pattern);
      }
    }
    return ' ';
  });

  // 3. Extract bare domains/subdomains (with optional port or path suffix)
  const bareDomainRegex =
    /(?<![A-Za-z0-9@*./_-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?::\d{1,5})?(\/[^\s`'"([,;)\]]*)?/gi;
  working = working.replace(
    bareDomainRegex,
    (fullMatch, hostPart: string, pathPart: string | undefined) => {
      const pattern = sanitizeDomainPattern(hostPart);
      if (!pattern) {
        return fullMatch;
      }

      if (mode === 'OUT_OF_SCOPE') {
        const cleanPath = pathPart ? sanitizeExcludedPath(pathPart) : null;
        if (cleanPath) {
          excludedPathSet.add(cleanPath);
        } else {
          excludedHostSet.add(pattern);
        }
      } else {
        authorizedSet.add(pattern);
      }
      return ' ';
    },
  );

  // 4. Extract standalone excluded path globs (/admin/destruct/**, /logout) when in OUT_OF_SCOPE mode
  if (mode === 'OUT_OF_SCOPE') {
    const pathRegex = /(?:^|[\s`'"([,;|])(\/[A-Za-z0-9_.*~/-]+)/g;
    let pathMatch: RegExpExecArray | null;
    while ((pathMatch = pathRegex.exec(working)) !== null) {
      const rawPath = pathMatch[1];
      if (rawPath) {
        const cleanPath = sanitizeExcludedPath(rawPath);
        if (cleanPath) {
          excludedPathSet.add(cleanPath);
        }
      }
    }
  }
}

export function extractHeuristicBriefSignals(
  text: string,
  existingScope?: ScopeConfig,
): HeuristicBriefSignals {
  const inScopeAuthorizedSet = new Set<string>();
  const neutralAuthorizedSet = new Set<string>();
  const excludedHostSet = new Set<string>();
  const excludedPathSet = new Set<string>();
  const explicitSeedUrlSet = new Set<string>();
  const complianceHeaders: Record<string, string> = {};

  let explicitProgramName: string | undefined;
  let headingProgramCandidate: string | undefined;
  let hasExplicitRps = false;
  let extractedRps = existingScope?.maxRpsPerHost ?? 5;
  let hasExplicitScopeSection = false;
  let currentSection: BriefSectionMode = 'NEUTRAL';

  // Extract rate limit across the message
  const rpsPatterns = [
    /\b(?:max(?:imum)?(?:\s+of)?\s*)?(\d+(?:\.\d+)?)\s*(?:rps|req(?:uests?)?\s*(?:\/|per)\s*s(?:ec(?:ond)?)?)\b/i,
    /\brate[\s-]*limit(?:\s*(?:is|of|:))?\s*(?:max(?:imum)?(?:\s+of)?\s*)?(\d+(?:\.\d+)?)\b/i,
  ];
  for (const rpsRe of rpsPatterns) {
    const match = text.match(rpsRe);
    if (match && match[1]) {
      const parsed = Number.parseFloat(match[1]);
      if (Number.isFinite(parsed) && parsed > 0) {
        extractedRps = Math.max(1, Math.min(25, Math.floor(parsed)));
        hasExplicitRps = true;
        break;
      }
    }
  }

  const lines = text.split(/\r?\n/);

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) {
      continue;
    }

    // Check explicit "Program: <Name>" metadata line
    const programLabelMatch = trimmed.match(
      /^(?:[-*•]\s*)?(?:\*\*)?(?:program(?:\s+name)?|engagement(?:\s+name)?|bounty\s+program)(?:\*\*)?\s*:\s*(.+)$/i,
    );
    if (programLabelMatch && programLabelMatch[1] && !explicitProgramName) {
      const candidate = programLabelMatch[1]
        .replace(/[*`#]+/g, '')
        .trim();
      if (candidate.length >= 2 && !GENERIC_HEADING_NOISE_RE.test(candidate)) {
        explicitProgramName = candidate;
      }
    }

    // Check Markdown H1/H2 heading for program title candidate
    const mdHeadingMatch = trimmed.match(/^(#{1,6})\s+(.+)$/);
    if (mdHeadingMatch && mdHeadingMatch[2]) {
      const headingLevel = mdHeadingMatch[1]?.length ?? 1;
      const headingText = mdHeadingMatch[2]
        .replace(/[*`#]+/g, '')
        .replace(/:+$/, '')
        .trim();

      if (
        headingLevel <= 2 &&
        !headingProgramCandidate &&
        headingText.length >= 2 &&
        !GENERIC_HEADING_NOISE_RE.test(headingText) &&
        !/\b(?:out[\s-]*of[\s-]*scope|in[\s-]*scope)\b/i.test(headingText)
      ) {
        headingProgramCandidate = headingText;
      }
    }

    // Extract custom compliance headers (e.g. `X-Bug-Bounty: Bugcrowd-...` or X-Researcher: foo)
    let lineWithoutHeaders = trimmed;
    const delimitedHeaderRegex = /[`'"](X-[A-Za-z0-9-]+)\s*:\s*([^`'"]+)[`'"]/gi;
    lineWithoutHeaders = lineWithoutHeaders.replace(
      delimitedHeaderRegex,
      (_m, rawKey: string, rawVal: string) => {
        const key = rawKey.trim();
        const val = rawVal.trim();
        if (val && !IGNORED_RESPONSE_SECURITY_HEADERS.has(key.toLowerCase())) {
          complianceHeaders[key] = val;
        }
        return ' ';
      },
    );

    const inlineHeaderRegex = /\b(X-[A-Za-z0-9-]+)\s*:\s*([A-Za-z0-9._@/-]+)/gi;
    lineWithoutHeaders = lineWithoutHeaders.replace(
      inlineHeaderRegex,
      (full, rawKey: string, rawVal: string) => {
        const key = rawKey.trim();
        const val = rawVal.trim();
        if (val && !IGNORED_RESPONSE_SECURITY_HEADERS.has(key.toLowerCase())) {
          if (complianceHeaders[key] === undefined) {
            complianceHeaders[key] = val;
          }
          return ' ';
        }
        return full;
      },
    );

    // Strip markdown heading/bullet decorations for section classification
    const plainHeadingCandidate = trimmed
      .replace(/^[#>*•_\-\s]+/, '')
      .replace(/[*_`]+/g, '')
      .trim();

    // Standalone Out-of-Scope heading (with optional inline colon items)
    const outSectionHeaderMatch = plainHeadingCandidate.match(
      /^(?:out[\s-]*of[\s-]*scope(?:\s+targets?|\s+assets?|\s+domains?|\s+hosts?)?|excluded(?:\s+targets?|\s+assets?|\s+domains?|\s+hosts?|\s+paths?)?|exclusions?|prohibited(?:\s+targets?)?|do\s+not\s+test)(?:\s*:(.*))?$/i,
    );
    if (outSectionHeaderMatch) {
      currentSection = 'OUT_OF_SCOPE';
      hasExplicitScopeSection = true;
      const remainder = outSectionHeaderMatch[1]?.trim();
      if (remainder) {
        extractSegmentTargets(
          remainder,
          'OUT_OF_SCOPE',
          inScopeAuthorizedSet,
          excludedHostSet,
          excludedPathSet,
          explicitSeedUrlSet,
        );
      }
      continue;
    }

    // Standalone In-Scope heading (with optional inline colon items)
    const inSectionHeaderMatch = plainHeadingCandidate.match(
      /^(?:in[\s-]*scope(?:\s+targets?|\s+assets?|\s+domains?|\s+hosts?)?|authorized(?:\s+targets?|\s+assets?|\s+domains?|\s+scope)?|targets?(?:\s+in[\s-]*scope)?|scope)(?:\s*:(.*))?$/i,
    );
    if (inSectionHeaderMatch) {
      currentSection = 'IN_SCOPE';
      hasExplicitScopeSection = true;
      const remainder = inSectionHeaderMatch[1]?.trim();
      if (remainder) {
        extractSegmentTargets(
          remainder,
          'IN_SCOPE',
          inScopeAuthorizedSet,
          excludedHostSet,
          excludedPathSet,
          explicitSeedUrlSet,
        );
      }
      continue;
    }

    // Reset section to NEUTRAL on non-scope headings (e.g., "## Rules of Engagement", "Rate Limiting")
    if (mdHeadingMatch || GENERIC_HEADING_NOISE_RE.test(plainHeadingCandidate.replace(/:+$/, ''))) {
      currentSection = 'NEUTRAL';
      continue;
    }

    // Check inline exclusion clause within a single line (e.g. "Audit *.acme.com, exclude blog.acme.com and /logout")
    const inlineExclusionSplit = lineWithoutHeaders.match(
      /^(.*?)\b(?:out[\s-]*of[\s-]*scope|exclud(?:e|ed|ing)|except(?:\s+for)?|prohibited|do\s+not\s+(?:test|touch|scan|hit))\b[:\s-]*(.+)$/i,
    );
    if (inlineExclusionSplit) {
      const beforeClause = inlineExclusionSplit[1]?.trim() ?? '';
      const afterClause = inlineExclusionSplit[2]?.trim() ?? '';
      if (beforeClause) {
        extractSegmentTargets(
          beforeClause,
          currentSection === 'OUT_OF_SCOPE' ? 'OUT_OF_SCOPE' : 'IN_SCOPE',
          inScopeAuthorizedSet,
          excludedHostSet,
          excludedPathSet,
          explicitSeedUrlSet,
        );
      }
      if (afterClause) {
        extractSegmentTargets(
          afterClause,
          'OUT_OF_SCOPE',
          inScopeAuthorizedSet,
          excludedHostSet,
          excludedPathSet,
          explicitSeedUrlSet,
        );
      }
      continue;
    }

    extractSegmentTargets(
      lineWithoutHeaders,
      currentSection,
      currentSection === 'IN_SCOPE' ? inScopeAuthorizedSet : neutralAuthorizedSet,
      excludedHostSet,
      excludedPathSet,
      explicitSeedUrlSet,
    );
  }

  const candidateNameHint =
    explicitProgramName ||
    headingProgramCandidate ||
    existingScope?.programName ||
    '';

  const rawAuthorizedPool = Array.from(
    inScopeAuthorizedSet.size > 0 ? inScopeAuthorizedSet : neutralAuthorizedSet,
  );
  const hasNonPlatformAuthorized = rawAuthorizedPool.some(
    (d) => !isBountyPlatformMetadataHost(d, candidateNameHint),
  );

  const excludedHosts = Array.from(excludedHostSet);
  // Ensure explicitly excluded hosts and bounty-platform metadata URLs are never left in authorizedDomains
  const authorizedDomains = rawAuthorizedPool.filter((domain) => {
    if (hasNonPlatformAuthorized && isBountyPlatformMetadataHost(domain, candidateNameHint)) {
      return false;
    }
    if (excludedHostSet.has(domain)) {
      return false;
    }
    if (!domain.startsWith('*.') && excludedHosts.length > 0) {
      if (isHostAuthorized(domain, excludedHosts)) {
        return false;
      }
    }
    return true;
  });

  const excludedPaths = Array.from(excludedPathSet);
  const explicitSeedUrls = Array.from(explicitSeedUrlSet).filter((seedUrl) => {
    if (!hasNonPlatformAuthorized) {
      return true;
    }
    try {
      const host = new URL(seedUrl).hostname;
      return !isBountyPlatformMetadataHost(host, candidateNameHint);
    } catch {
      return false;
    }
  });

  // Determine sensible programName
  const primaryDomain = derivePrimaryDomainLabel(
    authorizedDomains.length > 0
      ? authorizedDomains
      : existingScope?.authorizedDomains ?? [],
  );
  const programName =
    explicitProgramName ||
    headingProgramCandidate ||
    (authorizedDomains.length === 0 && existingScope?.programName
      ? existingScope.programName
      : undefined) ||
    (primaryDomain ? `Target (${primaryDomain})` : existingScope?.programName ?? 'Bugcrowd Engagement');

  // Determine default action
  let action: ProgramChatAction = 'INITIALIZE_OR_UPDATE_SCOPE_AND_SCAN';
  if (existingScope) {
    const hasNewAuthorizedDomain = authorizedDomains.some(
      (d) =>
        !existingScope.authorizedDomains.includes(d) &&
        (d.startsWith('*.') || !isHostAuthorized(d, existingScope.authorizedDomains)),
    );
    const hasNewExcludedHost = excludedHosts.some(
      (h) => !existingScope.excludedHosts.includes(h),
    );
    const hasNewExcludedPath = excludedPaths.some(
      (p) => !existingScope.excludedPaths.includes(p),
    );
    const hasNewComplianceHeader = Object.entries(complianceHeaders).some(
      ([k, v]) => existingScope.complianceHeaders[k] !== v,
    );
    const hasChangedRps = hasExplicitRps && extractedRps !== existingScope.maxRpsPerHost;

    const introducesScopeUpdate =
      hasExplicitScopeSection ||
      hasNewAuthorizedDomain ||
      hasNewExcludedHost ||
      hasNewExcludedPath ||
      hasNewComplianceHeader ||
      hasChangedRps;

    const asksForRescan =
      /\b(?:rescan|re-scan|run\s+(?:a\s+)?scan|scan\s+again|recheck|re-check|start\s+assessment|audit\s+now|rerun|re-run)\b/i.test(
        text,
      );

    if (introducesScopeUpdate) {
      action = 'INITIALIZE_OR_UPDATE_SCOPE_AND_SCAN';
    } else if (asksForRescan) {
      action = 'RESCAN_CURRENT_SCOPE';
    } else {
      action = 'ANSWER_QUESTION';
    }
  }

  return {
    action,
    programName,
    authorizedDomains,
    excludedHosts,
    excludedPaths,
    maxRpsPerHost: extractedRps,
    hasExplicitRps,
    hasExplicitScopeSection,
    complianceHeaders,
    explicitSeedUrls,
  };
}

export async function parseBugcrowdBriefMessage(
  opts: ParseBugcrowdBriefOptions,
): Promise<ParsedProgramIntent> {
  const heuristics = extractHeuristicBriefSignals(opts.userMessage, opts.existingScope);

  let llmIntent: ParsedProgramIntent | undefined;
  if (opts.llmClient) {
    const existingScopeSummary = opts.existingScope
      ? JSON.stringify({
          programName: opts.existingScope.programName,
          authorizedDomains: opts.existingScope.authorizedDomains,
          excludedHosts: opts.existingScope.excludedHosts,
          excludedPaths: opts.existingScope.excludedPaths,
          maxRpsPerHost: opts.existingScope.maxRpsPerHost,
          complianceHeaders: Object.keys(opts.existingScope.complianceHeaders),
        })
      : 'NONE (no scope configured yet)';

    const recentTurns = (opts.conversationHistory ?? [])
      .slice(-6)
      .map((t) => `${t.role.toUpperCase()}: ${t.content.slice(0, 500)}`)
      .join('\n');

    const systemPrompt = [
      'You are the OpenCyber Aegis-GitOps Lead Security Orchestrator.',
      'Parse the user message (which may be a pasted Bugcrowd program brief, a scope update, a rescan request, or a follow-up question about findings) into a strict JSON object.',
      'Rules:',
      '- action: "INITIALIZE_OR_UPDATE_SCOPE_AND_SCAN" when setting/updating scope or pasting a program brief; "RESCAN_CURRENT_SCOPE" when re-running assessment on existing scope; "ANSWER_QUESTION" when asking about findings, endpoints, or posture without changing scope.',
      '- authorizedDomains: ONLY in-scope hostnames or wildcard patterns (e.g. "*.acme.internal", "api.acme.internal"). Lowercase, no http(s):// schemes or paths. NEVER put Out-of-Scope domains or bug-bounty platform hosting URLs (such as bugcrowd.com, hackerone.com, intigriti.com, yeswehack.com) here.',
      '- excludedHosts: ONLY hostnames or wildcard patterns explicitly marked Out-of-Scope / Excluded / Do-Not-Test (e.g. "blog.acme.internal").',
      '- excludedPaths: URL path patterns explicitly marked Out-of-Scope (e.g. "/admin/destruct/**", "/logout").',
      '- maxRpsPerHost: requests-per-second cap between 1 and 50 (default 5 if unspecified).',
      '- complianceHeaders: required custom HTTP headers such as {"X-Bug-Bounty": "Bugcrowd-researcher"}.',
      '- explicitSeedUrls: full http:// or https:// in-scope target URLs mentioned in the message (exclude bugcrowd.com/engagements/... or hackerone.com/... program listing URLs).',
      '- focusSummary: concise 1-sentence summary of the user request or program focus.',
    ].join('\n');

    const userPrompt = [
      `Existing Active Scope: ${existingScopeSummary}`,
      ...(recentTurns ? [`Recent Conversation:\n${recentTurns}`] : []),
      `Current User Message:\n${opts.userMessage}`,
    ].join('\n\n');

    try {
      llmIntent = await opts.llmClient.completeJson({
        tier: 'ORCHESTRATOR',
        systemPrompt,
        userPrompt,
        schema: ParsedProgramIntentSchema,
        temperature: 0.1,
      });
    } catch {
      llmIntent = undefined;
    }
  }

  // Resolve action safely
  let resolvedAction: ProgramChatAction = llmIntent?.action ?? heuristics.action;
  if (!opts.existingScope || heuristics.hasExplicitScopeSection) {
    if (
      heuristics.authorizedDomains.length > 0 ||
      (llmIntent?.authorizedDomains.length ?? 0) > 0 ||
      !opts.existingScope
    ) {
      resolvedAction = 'INITIALIZE_OR_UPDATE_SCOPE_AND_SCAN';
    }
  }

  const preserveExistingScope =
    Boolean(opts.existingScope) && resolvedAction !== 'INITIALIZE_OR_UPDATE_SCOPE_AND_SCAN';

  // Resolve programName early so platform-metadata filtering can inspect it
  let resolvedProgramName = heuristics.programName;
  if (preserveExistingScope && opts.existingScope) {
    resolvedProgramName = opts.existingScope.programName;
  } else if (llmIntent?.programName && llmIntent.programName.trim().length > 0) {
    const llmName = llmIntent.programName.trim();
    if (!GENERIC_HEADING_NOISE_RE.test(llmName)) {
      resolvedProgramName = llmName;
    }
  }

  // Merge excludedHosts (never drop heuristic Out-of-Scope detections)
  const mergedExcludedHostSet = new Set<string>();
  if (preserveExistingScope && opts.existingScope) {
    for (const h of opts.existingScope.excludedHosts) {
      const clean = sanitizeDomainPattern(h);
      if (clean) {
        mergedExcludedHostSet.add(clean);
      }
    }
  }
  for (const h of llmIntent?.excludedHosts ?? []) {
    const clean = sanitizeDomainPattern(h);
    if (clean) {
      mergedExcludedHostSet.add(clean);
    }
  }
  for (const h of heuristics.excludedHosts) {
    const clean = sanitizeDomainPattern(h);
    if (clean) {
      mergedExcludedHostSet.add(clean);
    }
  }
  const mergedExcludedHosts = Array.from(mergedExcludedHostSet);

  // Merge authorizedDomains and filter out anything explicitly in excludedHosts or bounty-platform URLs
  const rawAuthorizedCandidates: string[] = [];
  if (preserveExistingScope && opts.existingScope) {
    rawAuthorizedCandidates.push(...opts.existingScope.authorizedDomains);
  } else {
    rawAuthorizedCandidates.push(
      ...(llmIntent?.authorizedDomains ?? []),
      ...heuristics.authorizedDomains,
    );
    if (rawAuthorizedCandidates.length === 0 && opts.existingScope) {
      rawAuthorizedCandidates.push(...opts.existingScope.authorizedDomains);
    }
  }

  const sanitizedAuthorizedCandidates = rawAuthorizedCandidates
    .map((d) => sanitizeDomainPattern(d))
    .filter((d): d is string => Boolean(d));
  const hasNonPlatformMergedTarget = sanitizedAuthorizedCandidates.some(
    (d) => !isBountyPlatformMetadataHost(d, resolvedProgramName),
  );

  const mergedAuthorizedSet = new Set<string>();
  for (const clean of sanitizedAuthorizedCandidates) {
    if (hasNonPlatformMergedTarget && isBountyPlatformMetadataHost(clean, resolvedProgramName)) {
      continue;
    }
    if (mergedExcludedHostSet.has(clean)) {
      continue;
    }
    if (!clean.startsWith('*.') && mergedExcludedHosts.length > 0) {
      if (isHostAuthorized(clean, mergedExcludedHosts)) {
        continue;
      }
    }
    mergedAuthorizedSet.add(clean);
  }
  const mergedAuthorizedDomains = Array.from(mergedAuthorizedSet);

  // Merge excludedPaths
  const mergedExcludedPathSet = new Set<string>();
  if (preserveExistingScope && opts.existingScope) {
    for (const p of opts.existingScope.excludedPaths) {
      const clean = sanitizeExcludedPath(p);
      if (clean) {
        mergedExcludedPathSet.add(clean);
      }
    }
  }
  for (const p of [...(llmIntent?.excludedPaths ?? []), ...heuristics.excludedPaths]) {
    const clean = sanitizeExcludedPath(p);
    if (clean) {
      mergedExcludedPathSet.add(clean);
    }
  }
  const mergedExcludedPaths = Array.from(mergedExcludedPathSet);

  // Merge complianceHeaders
  const mergedComplianceHeaders: Record<string, string> = {
    ...(preserveExistingScope && opts.existingScope
      ? opts.existingScope.complianceHeaders
      : {}),
    ...heuristics.complianceHeaders,
  };
  if (llmIntent?.complianceHeaders) {
    for (const [rawKey, rawVal] of Object.entries(llmIntent.complianceHeaders)) {
      const key = rawKey.trim();
      const val = rawVal.trim();
      if (key && val && !IGNORED_RESPONSE_SECURITY_HEADERS.has(key.toLowerCase())) {
        mergedComplianceHeaders[key] = val;
      }
    }
  }

  // Merge maxRpsPerHost
  let mergedRps = heuristics.maxRpsPerHost;
  if (llmIntent?.maxRpsPerHost !== undefined) {
    if (heuristics.hasExplicitRps && llmIntent.maxRpsPerHost === 5 && heuristics.maxRpsPerHost !== 5) {
      mergedRps = heuristics.maxRpsPerHost;
    } else {
      mergedRps = Math.max(1, Math.min(50, Math.round(llmIntent.maxRpsPerHost)));
    }
  } else if (preserveExistingScope && opts.existingScope && !heuristics.hasExplicitRps) {
    mergedRps = opts.existingScope.maxRpsPerHost;
  }

  // Merge explicitSeedUrls
  const mergedSeedUrlSet = new Set<string>();
  for (const u of [...heuristics.explicitSeedUrls, ...(llmIntent?.explicitSeedUrls ?? [])]) {
    const clean = sanitizeExplicitUrl(u);
    if (clean) {
      if (hasNonPlatformMergedTarget) {
        try {
          const seedHost = new URL(clean).hostname;
          if (isBountyPlatformMetadataHost(seedHost, resolvedProgramName)) {
            continue;
          }
        } catch {
          continue;
        }
      }
      mergedSeedUrlSet.add(clean);
    }
  }

  const focusSummary =
    llmIntent?.focusSummary?.trim() ||
    (resolvedAction === 'ANSWER_QUESTION'
      ? 'Answer follow-up security posture question on active Bugcrowd scope.'
      : resolvedAction === 'RESCAN_CURRENT_SCOPE'
        ? `Re-run passive & read-only posture verification for ${resolvedProgramName}.`
        : `Initialize governed read-only scope and verify posture for ${resolvedProgramName}.`);

  return ParsedProgramIntentSchema.parse({
    action: resolvedAction,
    programName: resolvedProgramName,
    authorizedDomains: mergedAuthorizedDomains,
    excludedHosts: mergedExcludedHosts,
    excludedPaths: mergedExcludedPaths,
    maxRpsPerHost: mergedRps,
    complianceHeaders: mergedComplianceHeaders,
    explicitSeedUrls: Array.from(mergedSeedUrlSet),
    focusSummary,
  });
}

export function buildProgramScopeAndSeeds(opts: BuildProgramScopeOptions): {
  scope: ScopeConfig;
  seedTargets: ReconSeedTarget[];
} {
  const candidateDomains =
    opts.intent.authorizedDomains.length > 0
      ? opts.intent.authorizedDomains
      : opts.existingScope?.authorizedDomains ?? [];

  if (candidateDomains.length === 0) {
    throw new Error(
      'No authorized target domains found in message. Paste a Bugcrowd brief or target domain (e.g. *.example.com) to start.',
    );
  }

  const hasExistingAuthProfiles =
    opts.existingScope && Object.keys(opts.existingScope.authProfiles).length > 0;

  const allLocalDemoDomains = candidateDomains.every((d) => {
    const clean = normalizeHostname(d.replace(/^\*\./, ''));
    return (
      clean.endsWith('.internal') ||
      clean.endsWith('.local') ||
      clean.endsWith('.test') ||
      clean === 'localhost' ||
      clean === '127.0.0.1'
    );
  });

  const authProfiles = hasExistingAuthProfiles
    ? opts.existingScope!.authProfiles
    : allLocalDemoDomains
      ? {
          role_viewer: {
            description: 'Read-only low-privilege viewer profile for differential posture checks',
            allowedMethods: ['GET', 'HEAD', 'OPTIONS'] as ('GET' | 'HEAD' | 'OPTIONS')[],
            headerNames: ['Authorization'],
          },
          role_admin: {
            description: 'Read-only administrative profile for differential posture checks',
            allowedMethods: ['GET', 'HEAD', 'OPTIONS'] as ('GET' | 'HEAD' | 'OPTIONS')[],
            headerNames: ['Authorization'],
          },
        }
      : {};

  const scope = ScopeConfigSchema.parse({
    engagementId: opts.engagementId,
    programName: opts.intent.programName,
    authorizedDomains: candidateDomains,
    excludedHosts: opts.intent.excludedHosts,
    excludedPaths: opts.intent.excludedPaths,
    maxRpsPerHost: opts.intent.maxRpsPerHost,
    complianceHeaders: opts.intent.complianceHeaders,
    authProfiles,
    strictReadOnly: true,
  });

  const seedTargets: ReconSeedTarget[] = [];
  const seenHosts = new Set<string>();
  const MAX_SEEDS = 4;

  const tryAddSeed = (host: string, baseUrl: string): void => {
    if (seedTargets.length >= MAX_SEEDS) {
      return;
    }
    const normalizedHost = normalizeHostname(host);
    if (!normalizedHost || seenHosts.has(normalizedHost)) {
      return;
    }
    const cleanBase = baseUrl.replace(/\/+$/, '');
    const check = evaluateTargetScope(`${cleanBase}/`, scope);
    if (!check.allowed) {
      return;
    }
    seenHosts.add(normalizedHost);
    seedTargets.push({
      host: normalizedHost,
      baseUrl: cleanBase,
    });
  };

  // 1. Explicit seed URLs that pass evaluateTargetScope
  for (const rawSeedUrl of opts.intent.explicitSeedUrls) {
    if (seedTargets.length >= MAX_SEEDS) {
      break;
    }
    const urlCheck = evaluateTargetScope(rawSeedUrl, scope);
    if (!urlCheck.allowed) {
      continue;
    }
    try {
      const parsed = new URL(rawSeedUrl);
      tryAddSeed(parsed.hostname, `${parsed.protocol}//${parsed.host}`);
    } catch {
      // Skip invalid URL
    }
  }

  // 2. Concrete non-wildcard hosts in scope.authorizedDomains
  for (const domainPattern of scope.authorizedDomains) {
    if (seedTargets.length >= MAX_SEEDS) {
      break;
    }
    if (domainPattern.startsWith('*.')) {
      continue;
    }
    const host = normalizeHostname(domainPattern);
    if (!host) {
      continue;
    }
    const scheme = inferScheme(host);
    tryAddSeed(host, `${scheme}://${host}`);
  }

  // 3. Wildcard fallbacks if no concrete subdomain for that suffix is present yet
  for (const domainPattern of scope.authorizedDomains) {
    if (seedTargets.length >= MAX_SEEDS) {
      break;
    }
    if (!domainPattern.startsWith('*.')) {
      continue;
    }
    const suffix = normalizeHostname(domainPattern.slice(2));
    if (!suffix) {
      continue;
    }

    const alreadyHasMatchingSubdomain = seedTargets.some((t) =>
      t.host.endsWith(`.${suffix}`),
    );
    if (alreadyHasMatchingSubdomain) {
      continue;
    }

    const isLocalOrInternal =
      suffix.endsWith('.internal') ||
      suffix.endsWith('.local') ||
      suffix.endsWith('.test');

    if (isLocalOrInternal) {
      for (const subPrefix of ['portal', 'api']) {
        const candidateHost = `${subPrefix}.${suffix}`;
        tryAddSeed(candidateHost, `${inferScheme(candidateHost)}://${candidateHost}`);
      }
    } else {
      for (const subPrefix of ['api', 'www']) {
        const candidateHost = `${subPrefix}.${suffix}`;
        tryAddSeed(candidateHost, `https://${candidateHost}`);
      }
    }
  }

  return {
    scope,
    seedTargets: seedTargets.slice(0, MAX_SEEDS),
  };
}

function formatSafeComplianceHeaderSummary(headers: Record<string, string>): string {
  const entries = Object.entries(headers);
  if (entries.length === 0) {
    return 'none';
  }
  return entries
    .map(([k, v]) =>
      /authorization|token|secret|key|cookie|password/i.test(k)
        ? `${k}: [REDACTED]`
        : `${k}: ${v}`,
    )
    .join(', ');
}

function buildDeterministicOrchestratorMarkdown(
  opts: StreamOrchestratorReplyOptions,
): string {
  const { scope, intent, runSummary, findings = [] } = opts;
  const lines: string[] = [];

  lines.push(`### ${scope.programName} — Governed Posture Summary`);
  lines.push('');
  lines.push(
    `- **Authorized Scope**: ${scope.authorizedDomains.map((d) => `\`${d}\``).join(', ')}`,
  );
  if (scope.excludedHosts.length > 0) {
    lines.push(
      `- **Excluded Hosts**: ${scope.excludedHosts.map((h) => `\`${h}\``).join(', ')}`,
    );
  }
  if (scope.excludedPaths.length > 0) {
    lines.push(
      `- **Excluded Paths**: ${scope.excludedPaths.map((p) => `\`${p}\``).join(', ')}`,
    );
  }
  lines.push(
    `- **Governance**: \`${scope.maxRpsPerHost} req/sec\` cap, \`strictReadOnly=${String(scope.strictReadOnly)}\`, Headers: \`${formatSafeComplianceHeaderSummary(scope.complianceHeaders)}\``,
  );

  if (runSummary) {
    lines.push('');
    lines.push(`#### Pipeline Execution (\`${runSummary.runId}\`)`);
    lines.push(
      `- **Surface Mapped**: ${runSummary.hostsDiscovered} host(s), ${runSummary.canonicalEndpoints} canonical endpoint(s) (Sandbox: \`${runSummary.sandboxProvider}\`)`,
    );
    lines.push(
      `- **Stage 3/4 Verification**: ${runSummary.mergedFindings.length} merged finding(s), ${runSummary.compliantTombstones} compliant tombstone(s), ${runSummary.blockedScope451} out-of-scope \`451\` block(s)`,
    );
  } else {
    lines.push(`- **Action**: \`${intent.action}\``);
  }

  lines.push('');
  if (findings.length > 0) {
    lines.push(`#### Verified Findings (${findings.length})`);
    for (const f of findings) {
      lines.push(
        `- **\`${f.findingId}\`** [${f.severity}] **${f.title}** on \`${f.host}\` (\`${f.endpointId}\`, status: \`${f.status}\`) — ${f.summary}`,
      );
    }
  } else {
    lines.push(
      'No posture drift or security misconfigurations were flagged across the evaluated in-scope endpoints.',
    );
  }

  return lines.join('\n');
}

export async function streamOrchestratorReply(
  opts: StreamOrchestratorReplyOptions,
): Promise<string> {
  const { scope, intent, runSummary, findings = [] } = opts;

  const findingsContext =
    findings.length > 0
      ? findings
          .map(
            (f) =>
              `- ${f.findingId} | severity=${f.severity} | category=${f.category} | status=${f.status} | host=${f.host} | endpoint=${f.endpointId}\n  Title: ${f.title}\n  Summary: ${f.summary}\n  Remediation: ${f.remediation}`,
          )
          .join('\n')
      : 'None (0 findings flagged; evaluated endpoints recorded compliant tombstones or no scan has found issues yet).';

  const runSummaryContext = runSummary
    ? [
        `Run ID: ${runSummary.runId}`,
        `Sandbox Provider: ${runSummary.sandboxProvider}`,
        `Hosts Discovered: ${runSummary.hostsDiscovered}`,
        `Canonical Endpoints Mapped: ${runSummary.canonicalEndpoints}`,
        `Compliant Tombstones: ${runSummary.compliantTombstones}`,
        `Stage 4 Merged Findings: ${runSummary.mergedFindings.join(', ') || 'none'}`,
        `Out-of-Scope HTTP 451 Blocks Enforced: ${runSummary.blockedScope451}`,
      ].join('\n')
    : 'No new scan executed on this turn (answering from current engagement state).';

  const systemPrompt = [
    'You are the Lead Security Orchestrator for OpenCyber (Aegis-GitOps), a governed read-only security posture verification platform.',
    'Respond directly to the researcher in concise, high-signal Markdown.',
    'Strict Rules:',
    '- Output clean Markdown ONLY. Do NOT wrap your entire reply in a JSON object or ```markdown``` fence, and do NOT emit <think> tags.',
    '- Ground every statement strictly in the active Bugcrowd program scope, Stage 1-4 GitOps pipeline metrics, subagent delegation logs, canonical endpoints, and verified findings below.',
    '- Never fabricate unverified vulnerabilities, exploit payloads, or out-of-scope targets.',
    '',
    '=== ACTIVE BUGCROWD PROGRAM SCOPE ===',
    `Program Name: ${scope.programName} (Engagement: ${scope.engagementId})`,
    `Action Performed: ${intent.action}`,
    `Authorized Domains: ${scope.authorizedDomains.join(', ')}`,
    `Excluded Hosts: ${scope.excludedHosts.join(', ') || 'none'}`,
    `Excluded Paths: ${scope.excludedPaths.join(', ') || 'none'}`,
    `Rate Limit: ${scope.maxRpsPerHost} req/sec per host (strictReadOnly=${String(scope.strictReadOnly)})`,
    `Compliance Headers: ${formatSafeComplianceHeaderSummary(scope.complianceHeaders)}`,
    '',
    '=== LATEST PIPELINE EXECUTION SUMMARY ===',
    runSummaryContext,
    ...(opts.telemetryContext
      ? [
          '',
          '=== SUBAGENT DELEGATION, GITOPS & EGRESS TELEMETRY ===',
          opts.telemetryContext,
        ]
      : []),
    '',
    '=== VERIFIED FINDINGS ===',
    findingsContext,
  ].join('\n');

  const priorTurns = (opts.conversationHistory ?? [])
    .filter((m) => m.content.trim().length > 0)
    .slice(-8);

  const lastTurn = priorTurns[priorTurns.length - 1];
  const messages: ChatTurnMessage[] =
    lastTurn &&
    lastTurn.role === 'user' &&
    lastTurn.content.trim() === opts.userMessage.trim()
      ? [...priorTurns]
      : [...priorTurns, { role: 'user', content: opts.userMessage }];

  if (opts.llmClient?.streamText) {
    let emittedText = '';
    try {
      const fullReply = await opts.llmClient.streamText({
        tier: 'ORCHESTRATOR',
        systemPrompt,
        messages,
        temperature: 0.2,
        onDelta: async (delta) => {
          emittedText += delta;
          await opts.onDelta(delta);
        },
      });

      if (fullReply.trim().length > 0) {
        return fullReply;
      }
    } catch {
      if (emittedText.trim().length > 0) {
        return emittedText;
      }
    }
  }

  const fallbackMarkdown = buildDeterministicOrchestratorMarkdown(opts);
  await opts.onDelta(fallbackMarkdown);
  return fallbackMarkdown;
}
