import type {
  GitOpsHistoryResponse,
  OverviewResponse,
  SquadRunState,
  SurfaceGraphResponse,
} from './types';

export const EMPTY_SURFACE_GRAPH: SurfaceGraphResponse = {
  nodes: [],
  edges: [],
};

export const EMPTY_GITOPS_HISTORY: GitOpsHistoryResponse = {
  branches: [],
  commits: [],
  reviews: [],
};

export function createEmptyOverview(
  programId = '',
  programName = 'No Active Engagement',
  useCloudSandbox = true,
  pipelineRunning = false,
): OverviewResponse {
  return {
    engagement: {
      engagementId: programId,
      programName,
      authorizedDomains: [],
      excludedHosts: [],
      excludedPaths: [],
      maxRpsPerHost: 3,
      strictReadOnly: true,
      complianceHeaders: {},
    },
    runtime: {
      sandboxProvider: useCloudSandbox ? 'e2b' : 'local',
      orchestratorProvider: 'openrouter',
      orchestratorModel: 'stealth/crouton-alpha',
      subagentProvider: 'groq',
      subagentModel: 'qwen/qwen3.8-27b',
      promptGuardModel: 'meta-llama/llama-prompt-guard-2-86m',
      pipelineRunning,
    },
    metrics: {
      hostsDiscovered: 0,
      canonicalEndpoints: 0,
      compliantTombstones: 0,
      pendingFindings: 0,
      approvedFindings: 0,
      allowedRequests: 0,
      blockedScope451: 0,
      blockedRps429: 0,
    },
  };
}

export function createEmptySquadRunState(
  programId = '',
  running = false,
): SquadRunState {
  return {
    programId,
    runId: '',
    status: running ? 'running' : 'idle',
    startedAt: running ? new Date().toISOString() : '',
    agents: [],
    hypotheses: [],
    threatModel: null,
    coverage: [],
    timeline: [],
  };
}

// ---------------------------------------------------------------------------
// Real Bugcrowd VDP Briefs (Safe Harbor) — Quick-Fill Templates ONLY
// Never pre-populated as fake completed runs.
// ---------------------------------------------------------------------------

export const FIRECRAWL_VDP_BRIEF = `# Program: Firecrawl Vulnerability Disclosure Program (Safe Harbor)
Engagement URL: https://bugcrowd.com/engagements/firecrawl-vdp-ess

## In-Scope Targets
- *.firecrawl.dev
- firecrawl.dev (https://firecrawl.dev — API Testing, NodeJS, NextJS, JavaScript, MCP server)

## Out-of-Scope Targets
- community.firecrawl.dev
- docs.firecrawl.dev
- status.firecrawl.dev
- trust.firecrawl.dev

## Rules of Engagement
- Safe Harbor authorized under Bugcrowd VDP terms
- Strict throttling: max 3 RPS per host
- Exclude P5 scanner noise & volumetric testing
- Strictly read-only GET, HEAD, and OPTIONS posture & surface assessment`;

export const CANDID_VDP_BRIEF = `# Program: Candid Vulnerability Disclosure Program (Safe Harbor)
Engagement URL: https://bugcrowd.com/engagements/candid-vdppro

## In-Scope Targets
- candid.org (https://candid.org)
- api.candid.org (https://api.candid.org)
- app.candid.org (https://app.candid.org)

## Out-of-Scope Targets
- Any subdomain not listed above is out-of-scope

## Rules of Engagement
- Safe Harbor authorized under Bugcrowd VDP terms
- Strict throttling: max 2 RPS per host
- Exclude P5 scanner noise & volumetric testing
- Strictly read-only GET, HEAD, and OPTIONS posture & surface assessment`;
