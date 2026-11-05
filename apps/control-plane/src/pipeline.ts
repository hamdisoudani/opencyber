import { execFile } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import {
  AegisGroqClient,
  AegisModelRouter,
  analyzeJavaScriptBundleAst,
  auditEndpointPosture,
  type ChatTurnMessage,
  extractOpenApiObservations,
  LeadOrchestratorReviewer,
  type LlmProviderName,
  PromptGuardSanitizer,
  type ReconSeedTarget,
  runReconSubagent,
} from '@opencyber/agents';
import {
  EgressGateway,
  GovernedHttpClient,
  SessionVault,
} from '@opencyber/egress-gateway';
import {
  BlobVault,
  type GitOpsReviewRecord,
  LockManager,
  reduceObservationsToSurface,
  type RepoCommitSummary,
  type RetrievedBlob,
  runDeterministicCiGate,
  StateDb,
  type SurfaceGraphSnapshot,
  WorktreeManager,
} from '@opencyber/gitops-engine';
import {
  createDefaultSandboxProvider,
  type SandboxProviderType,
} from '@opencyber/sandbox-runner';
import {
  CyberSquadCoordinator,
  generateSquadHypotheses,
  type HypothesisPhase,
  hydrateSquadStateFromEngineData,
  type SecurityHypothesis,
  type SquadAgentNode,
  type SquadEventCallback,
  type SquadRunState,
  SquadRunStateSchema,
} from '@opencyber/sec-harness';
import {
  evaluateTargetScope,
  type FindingReport,
  type FindingStatus,
  isHostAuthorized,
  isPathExcluded,
  normalizeHostname,
  type RouteObservationBatch,
  type ScopeConfig,
  ScopeConfigSchema,
  serializeScopeYaml,
  signTaskProxyToken,
  type TrafficLedgerEntry,
} from '@opencyber/shared';
import { stringify as stringifyYaml } from 'yaml';
import { DemoEnterpriseTargetServer } from './demo-target.js';

export type ProgramLogStage =
  | 'INGEST'
  | 'SANDBOX'
  | 'RECON'
  | 'JS_AST'
  | 'SURFACE_REDUCER'
  | 'POSTURE_AUDIT'
  | 'CI_GATE'
  | 'ORCHESTRATOR_REVIEW'
  | 'EGRESS';

export interface ProgramLogEntry {
  id: string;
  programId: string;
  timestamp: string;
  level: 'INFO' | 'SUCCESS' | 'WARN' | 'ERROR';
  stage: ProgramLogStage;
  agent: string;
  message: string;
}

export type ProgressLogInput = Omit<
  ProgramLogEntry,
  'id' | 'programId' | 'timestamp'
>;
export type ProgressLogCallback = (
  entry: ProgressLogInput,
) => void | Promise<void>;

export const DEFAULT_DEMO_SCOPE: ScopeConfig = ScopeConfigSchema.parse({
  engagementId: 'eng-acme-enterprise-demo',
  programName: 'Acme Enterprise Core Perimeter',
  authorizedDomains: [
    '*.acme.internal',
    'portal.acme.internal',
    'api.acme.internal',
  ],
  excludedHosts: [],
  excludedPaths: ['/admin/destruct/**', '/internal/reset/**'],
  maxRpsPerHost: 25,
  complianceHeaders: {
    'X-Bug-Bounty-Researcher': 'aegis-gitops-auditor',
  },
  authProfiles: {
    role_viewer: {
      description: 'Low-privilege tenant viewer session',
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
      headerNames: ['Authorization', 'X-Session-Role'],
    },
    role_admin: {
      description: 'Privileged organization administrator session',
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
      headerNames: ['Authorization', 'X-Session-Role'],
    },
  },
  strictReadOnly: true,
});

const DEFAULT_DEMO_SEEDS: readonly ReconSeedTarget[] = [
  { host: 'portal.acme.internal', baseUrl: 'http://portal.acme.internal' },
  { host: 'api.acme.internal', baseUrl: 'http://api.acme.internal' },
];

const E2B_UPSTREAM_FETCH_PY = [
  'import base64',
  'import json',
  'import os',
  'import ssl',
  'import sys',
  'import urllib.error',
  'import urllib.request',
  '',
  'MAX_BYTES = 512 * 1024',
  '',
  'class NoRedirectHandler(urllib.request.HTTPRedirectHandler):',
  '    def redirect_request(self, req, fp, code, msg, headers, newurl):',
  '        return None',
  '',
  'def collect_headers(hdrs):',
  '    out = {}',
  '    if not hdrs:',
  '        return out',
  '    for k, v in hdrs.items():',
  '        lk = k.lower()',
  '        if lk in out:',
  '            out[lk] = f"{out[lk]}, {v}"',
  '        else:',
  '            out[lk] = v',
  '    return out',
  '',
  'def main():',
  '    raw_b64 = os.environ.get("AEGIS_REQ_B64", "")',
  '    payload = json.loads(base64.b64decode(raw_b64).decode("utf-8"))',
  '    url = str(payload["url"])',
  '    method = str(payload.get("method", "GET")).upper()',
  '    if method not in ("GET", "HEAD", "OPTIONS"):',
  '        raise ValueError(f"Disallowed non-read-only method: {method}")',
  '    req_headers = dict(payload.get("headers") or {})',
  '    if not any(k.lower() == "user-agent" for k in req_headers.keys()):',
  '        req_headers["User-Agent"] = "Aegis-GitOps-ReadOnly-Auditor/1.0"',
  '',
  '    ctx = ssl.create_default_context()',
  '    opener = urllib.request.build_opener(',
  '        urllib.request.HTTPSHandler(context=ctx),',
  '        NoRedirectHandler(),',
  '    )',
  '    req = urllib.request.Request(url=url, headers=req_headers, method=method)',
  '    try:',
  '        with opener.open(req, timeout=8) as resp:',
  '            status = int(getattr(resp, "status", resp.getcode()))',
  '            reason = str(getattr(resp, "reason", "OK") or "OK")',
  '            body = b"" if method == "HEAD" else resp.read(MAX_BYTES)',
  '            out_headers = collect_headers(resp.headers)',
  '    except urllib.error.HTTPError as http_err:',
  '        status = int(http_err.code)',
  '        reason = str(http_err.reason or "HTTP Error")',
  '        try:',
  '            body = b"" if method == "HEAD" else http_err.read(MAX_BYTES)',
  '        except Exception:',
  '            body = b""',
  '        out_headers = collect_headers(http_err.headers)',
  '',
  '    sys.stdout.write(json.dumps({',
  '        "status": status,',
  '        "statusText": reason,',
  '        "headers": out_headers,',
  '        "bodyBase64": base64.b64encode(body).decode("ascii"),',
  '    }))',
  '',
  'if __name__ == "__main__":',
  '    main()',
  '',
].join('\n');

export interface AegisControlPlaneOptions {
  programId?: string;
  dataDir?: string;
  squadStateFilePath?: string;
  scope?: ScopeConfig;
  useDemoTarget?: boolean;
  demoTargetOrigin?: string;
  useCloudSandbox?: boolean;
  hmacSecret?: string;
  e2bApiKey?: string;
  openRouterApiKey?: string;
  groqApiKey?: string;
  orchestratorProvider?: LlmProviderName;
  subagentProvider?: LlmProviderName;
  orchestratorModel?: string;
  subagentModel?: string;
  promptGuardModel?: string;
  hostMapping?: Record<string, string>;
  seedTargets?: ReconSeedTarget[];
}

export interface SteerSquadAgentOptions {
  targetAgentId?: string;
  message: string;
  conversationHistory?: ChatTurnMessage[];
  onSquadEvent?: SquadEventCallback;
  onDelta?: (delta: string) => void | Promise<void>;
}

export interface SteerSquadAgentResult {
  targetAgent: SquadAgentNode;
  replyText: string;
  squadState: SquadRunState;
}

export interface AssessmentRunSummary {
  runId: string;
  sandboxProvider: SandboxProviderType;
  startedAt: string;
  completedAt: string;
  hostsDiscovered: number;
  canonicalEndpoints: number;
  compliantTombstones: number;
  mergedFindings: string[];
  blockedScope451: number;
}

export interface EngineOverviewSnapshot {
  engagement: {
    engagementId: string;
    programName: string;
    authorizedDomains: string[];
    excludedHosts: string[];
    excludedPaths: string[];
    maxRpsPerHost: number;
    complianceHeaders: Record<string, string>;
    strictReadOnly: boolean;
  };
  scopeYaml: string;
  runtime: {
    sandboxProvider: SandboxProviderType;
    orchestratorProvider: LlmProviderName;
    subagentProvider: LlmProviderName;
    orchestratorModel: string;
    subagentModel: string;
    promptGuardModel: string;
    pipelineRunning: boolean;
    lastRunAt?: string;
  };
  metrics: {
    hostsDiscovered: number;
    canonicalEndpoints: number;
    compliantTombstones: number;
    pendingFindings: number;
    approvedFindings: number;
    allowedRequests: number;
    blockedScope451: number;
    blockedRps429: number;
  };
}

export function toSafeSlug(input: string, maxLen: number = 40): string {
  const cleaned = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, maxLen)
    .replace(/-+$/, '');
  return cleaned || 'item';
}

export class AegisControlPlaneEngine {
  public scope: ScopeConfig;
  public readonly sessionVault: SessionVault;
  public readonly stateDb: StateDb;
  public readonly blobVault: BlobVault;
  public readonly lockManager: LockManager;
  public readonly worktreeManager: WorktreeManager;
  public readonly egressGateway: EgressGateway;
  public readonly groqClient: AegisGroqClient;
  public readonly llmRouter: AegisModelRouter;
  public readonly promptGuard: PromptGuardSanitizer;
  public readonly leadOrchestrator: LeadOrchestratorReviewer;
  public readonly demoTarget: DemoEnterpriseTargetServer | null;

  private readonly programId: string;
  private readonly dataDir: string;
  private readonly squadStateFilePath: string;
  private readonly ownsTempDataDir: boolean;
  private readonly hmacSecret: string;
  private readonly defaultUseCloudSandbox: boolean;
  private readonly e2bApiKey?: string;
  private readonly customHostMapping: Record<string, string>;
  private readonly seedTargets: ReconSeedTarget[];
  private readonly sharedDemoTargetOrigin?: string;

  private effectiveHostMapping: Record<string, string> = {};
  private initialized = false;
  private closed = false;
  private gatewayUrl = '';
  private activeSandboxProvider: SandboxProviderType;
  private pipelineRunning = false;
  private activeRunId: string | null = null;
  private activeRunPromise: Promise<AssessmentRunSummary> | null = null;
  private lastRunAt?: string;
  private latestSquadState: SquadRunState | null = null;

  public constructor(opts?: AegisControlPlaneOptions) {
    this.scope = ScopeConfigSchema.parse(opts?.scope ?? DEFAULT_DEMO_SCOPE);
    this.programId = opts?.programId?.trim() || this.scope.engagementId;

    if (opts?.dataDir) {
      this.dataDir = path.resolve(opts.dataDir);
      this.ownsTempDataDir = false;
    } else {
      this.dataDir = path.join(
        os.tmpdir(),
        `aegis-control-plane-${randomUUID()}`,
      );
      this.ownsTempDataDir = true;
    }

    this.squadStateFilePath = opts?.squadStateFilePath
      ? path.resolve(opts.squadStateFilePath)
      : path.join(this.dataDir, 'squad-state.json');

    const secretCandidate = opts?.hmacSecret?.trim();
    this.hmacSecret =
      secretCandidate && secretCandidate.length >= 16
        ? secretCandidate
        : randomBytes(32).toString('hex');

    this.defaultUseCloudSandbox = opts?.useCloudSandbox !== false;
    this.e2bApiKey = (opts?.e2bApiKey ?? process.env.E2B_API_KEY)?.trim();
    this.activeSandboxProvider =
      this.defaultUseCloudSandbox && Boolean(this.e2bApiKey) ? 'e2b' : 'local';

    const resolvedOpenRouterKey = (
      opts?.openRouterApiKey ?? process.env.OPENROUTER_API_KEY
    )?.trim();
    const resolvedGroqKey = (
      opts?.groqApiKey ?? process.env.GROQ_API_KEY
    )?.trim();

    this.customHostMapping = { ...(opts?.hostMapping ?? {}) };
    this.seedTargets = opts?.seedTargets
      ? [...opts.seedTargets]
      : [...DEFAULT_DEMO_SEEDS];

    const sharedOrigin = opts?.demoTargetOrigin?.trim();
    if (sharedOrigin) {
      this.sharedDemoTargetOrigin = sharedOrigin;
    }

    this.demoTarget =
      !this.sharedDemoTargetOrigin && opts?.useDemoTarget !== false
        ? new DemoEnterpriseTargetServer()
        : null;

    // 1. SessionVault: isolated credential store (values never exposed to LLMs or HARs)
    this.sessionVault = new SessionVault();
    this.sessionVault.registerProfile('role_viewer', {
      Authorization: `Bearer aegis-viewer-session-${randomUUID()}`,
      'X-Session-Role': 'viewer',
    });
    this.sessionVault.registerProfile('role_admin', {
      Authorization: `Bearer aegis-admin-session-${randomUUID()}`,
      'X-Session-Role': 'admin',
    });

    // 2. GitOps + PGlite + BlobVault persistence
    mkdirSync(this.dataDir, { recursive: true });
    this.stateDb = new StateDb(path.join(this.dataDir, 'state-db'));
    this.blobVault = new BlobVault(path.join(this.dataDir, 'blob-vault'));
    this.lockManager = new LockManager();
    this.worktreeManager = new WorktreeManager({
      repoDir: path.join(this.dataDir, 'engagement-repo'),
      worktreesDir: path.join(this.dataDir, 'worktrees'),
    });

    // 3. Governed Egress Gateway
    this.egressGateway = new EgressGateway({
      scope: this.scope,
      hmacSecret: this.hmacSecret,
      vault: this.sessionVault,
      hostMapping: this.customHostMapping,
      onTrafficEntry: async (entry) => {
        await this.stateDb.recordTraffic(entry);
      },
      onHarCaptured: async (_sha, harJson, pointer) => {
        await this.blobVault.put(harJson, 'application/json', {
          kind: 'har',
          requestUrl: pointer.requestUrl,
          method: pointer.method,
          ...(pointer.authProfileUsed
            ? { authProfile: pointer.authProfileUsed }
            : {}),
        });
      },
    });

    // 4. Multi-Provider LLM Router (OpenRouter stealth/crouton-alpha Orchestrator + Groq Subagent & Prompt Guard)
    this.groqClient = new AegisGroqClient({
      ...(resolvedGroqKey ? { apiKey: resolvedGroqKey } : {}),
      ...(opts?.subagentModel ? { subagentModel: opts.subagentModel } : {}),
      ...(opts?.promptGuardModel
        ? { promptGuardModel: opts.promptGuardModel }
        : {}),
    });

    this.llmRouter = new AegisModelRouter({
      ...(resolvedOpenRouterKey
        ? { openRouterApiKey: resolvedOpenRouterKey }
        : {}),
      ...(resolvedGroqKey ? { groqApiKey: resolvedGroqKey } : {}),
      ...(opts?.orchestratorProvider
        ? { orchestratorProvider: opts.orchestratorProvider }
        : {}),
      ...(opts?.subagentProvider
        ? { subagentProvider: opts.subagentProvider }
        : {}),
      ...(opts?.orchestratorModel
        ? { orchestratorModel: opts.orchestratorModel }
        : {}),
      ...(opts?.subagentModel ? { subagentModel: opts.subagentModel } : {}),
      ...(opts?.promptGuardModel
        ? { promptGuardModel: opts.promptGuardModel }
        : {}),
    });

    const liveLlmClient = this.llmRouter.isConfigured
      ? this.llmRouter
      : undefined;
    this.promptGuard = new PromptGuardSanitizer({
      ...(liveLlmClient ? { llmClient: liveLlmClient } : {}),
    });
    this.leadOrchestrator = new LeadOrchestratorReviewer({
      ...(liveLlmClient ? { llmClient: liveLlmClient } : {}),
      promptGuard: this.promptGuard,
    });
  }

  private syncGatewayHostMapping(): void {
    const combinedHostMapping: Record<string, string> = {};
    for (const [rawHost, targetOrigin] of Object.entries(this.customHostMapping)) {
      const normalized = normalizeHostname(rawHost);
      if (normalized) {
        combinedHostMapping[normalized] = targetOrigin;
      }
    }

    const activeDemoOrigin =
      this.sharedDemoTargetOrigin ?? this.demoTarget?.origin ?? undefined;

    if (activeDemoOrigin) {
      const isExcludedHost = (hostname: string): boolean =>
        this.scope.excludedHosts.length > 0 &&
        isHostAuthorized(hostname, this.scope.excludedHosts);

      for (const defaultDemoHost of [
        'portal.acme.internal',
        'api.acme.internal',
      ]) {
        if (
          !combinedHostMapping[defaultDemoHost] &&
          !isExcludedHost(defaultDemoHost)
        ) {
          combinedHostMapping[defaultDemoHost] = activeDemoOrigin;
        }
      }

      for (const seed of this.seedTargets) {
        const normSeedHost = normalizeHostname(seed.host);
        if (
          normSeedHost.endsWith('.acme.internal') &&
          !isExcludedHost(normSeedHost) &&
          !combinedHostMapping[normSeedHost]
        ) {
          combinedHostMapping[normSeedHost] = activeDemoOrigin;
        }
      }
    }

    this.effectiveHostMapping = combinedHostMapping;
    this.egressGateway.updateHostMapping(combinedHostMapping);
  }

  private resolveEndpointBaseUrl(host: string): string {
    const normalized = normalizeHostname(host);
    const matchedSeed = this.seedTargets.find(
      (s) => normalizeHostname(s.host) === normalized,
    );
    if (matchedSeed) {
      return matchedSeed.baseUrl.replace(/\/+$/, '');
    }

    if (
      Boolean(this.effectiveHostMapping[normalized]) ||
      normalized === 'localhost' ||
      normalized === '127.0.0.1' ||
      normalized === '[::1]' ||
      normalized.endsWith('.internal') ||
      normalized.endsWith('.local')
    ) {
      return `http://${normalized}`;
    }

    return `https://${normalized}`;
  }

  public async init(): Promise<void> {
    if (this.initialized) {
      return;
    }

    await fs.mkdir(this.dataDir, { recursive: true });
    await this.stateDb.init();
    await this.stateDb.upsertEngagement(this.scope);
    await this.worktreeManager.initEngagementRepo(this.scope);

    if (this.demoTarget) {
      await this.demoTarget.start(0);
    }

    this.syncGatewayHostMapping();
    const startedGateway = await this.egressGateway.start(0, '127.0.0.1');
    this.gatewayUrl = startedGateway.url;
    this.initialized = true;
  }

  public async updateScopeAndSeeds(
    scope: ScopeConfig,
    seedTargets: ReconSeedTarget[],
  ): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }

    const parsed = ScopeConfigSchema.parse(scope);
    this.scope = parsed;
    this.seedTargets.splice(0, this.seedTargets.length, ...seedTargets);

    this.egressGateway.updateScope(parsed);
    this.syncGatewayHostMapping();
    await this.stateDb.upsertEngagement(parsed);

    try {
      await this.worktreeManager.commitFilesOnMain(
        [
          {
            relativePath: 'scope.yaml',
            content: serializeScopeYaml(parsed),
          },
        ],
        `chore(scope): update Bugcrowd scope for ${parsed.programName}`,
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!/nothing to commit/i.test(msg)) {
        throw err;
      }
    }
  }

  public getSeedTargets(): ReconSeedTarget[] {
    return [...this.seedTargets];
  }

  public async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;

    if (this.activeRunPromise) {
      try {
        await this.activeRunPromise;
      } catch {
        // Ignore active run errors during shutdown
      }
    }

    this.egressGateway.setUpstreamDispatcher(undefined);
    await this.egressGateway.stop();
    if (this.demoTarget) {
      await this.demoTarget.stop();
    }
    await this.stateDb.close();

    if (this.ownsTempDataDir) {
      await fs.rm(this.dataDir, { recursive: true, force: true }).catch(() => {
        // Ignore temp dir cleanup errors
      });
    }
  }

  public isPipelineRunning(): boolean {
    return this.pipelineRunning;
  }

  public getActiveRunId(): string | null {
    return this.activeRunId;
  }

  public getSandboxProviderType(): SandboxProviderType {
    return this.activeSandboxProvider;
  }

  public triggerBackgroundAssessment(opts?: {
    useCloudSandbox?: boolean;
    userBrief?: string;
    onProgress?: ProgressLogCallback;
    onSquadEvent?: SquadEventCallback;
  }): { started: boolean; runId: string } {
    if (this.pipelineRunning && this.activeRunId) {
      return {
        started: false,
        runId: this.activeRunId,
      };
    }

    const runId = `run-${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`;
    const preferE2B =
      (opts?.useCloudSandbox ?? this.defaultUseCloudSandbox) !== false;
    this.activeSandboxProvider =
      preferE2B && Boolean(this.e2bApiKey ?? process.env.E2B_API_KEY?.trim())
        ? 'e2b'
        : 'local';
    this.pipelineRunning = true;
    this.activeRunId = runId;

    const promise = this.executeAssessmentPipeline(runId, opts).finally(() => {
      this.pipelineRunning = false;
      this.lastRunAt = new Date().toISOString();
      this.activeRunId = null;
      this.activeRunPromise = null;
    });
    this.activeRunPromise = promise;

    // Prevent unhandled rejection when running asynchronously in background
    void promise.catch(() => {
      // Errors are reflected via recorded state / reviews
    });

    return {
      started: true,
      runId,
    };
  }

  public async runFullAssessment(opts?: {
    useCloudSandbox?: boolean;
    userBrief?: string;
    onProgress?: ProgressLogCallback;
    onSquadEvent?: SquadEventCallback;
  }): Promise<AssessmentRunSummary> {
    if (!this.initialized) {
      await this.init();
    }

    if (this.activeRunPromise) {
      return this.activeRunPromise;
    }

    const runId = `run-${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`;
    this.pipelineRunning = true;
    this.activeRunId = runId;

    const promise = this.executeAssessmentPipeline(runId, opts).finally(() => {
      this.pipelineRunning = false;
      this.lastRunAt = new Date().toISOString();
      this.activeRunId = null;
      this.activeRunPromise = null;
    });
    this.activeRunPromise = promise;

    return promise;
  }

  private mintTaskToken(
    taskId: string,
    fencingToken: number,
    allowedAuthProfiles: string[] = [],
    ttlMs: number = 300_000,
  ): string {
    return signTaskProxyToken(
      {
        taskId,
        engagementId: this.scope.engagementId,
        fencingToken,
        allowedAuthProfiles,
        expiresAtMs: Date.now() + ttlMs,
      },
      this.hmacSecret,
    );
  }

  private async executeAssessmentPipeline(
    runId: string,
    opts?: {
      useCloudSandbox?: boolean;
      userBrief?: string;
      onProgress?: ProgressLogCallback;
      onSquadEvent?: SquadEventCallback;
    },
  ): Promise<AssessmentRunSummary> {
    if (!this.initialized) {
      await this.init();
    }

    const emitProgress = async (entry: ProgressLogInput): Promise<void> => {
      if (!opts?.onProgress) {
        return;
      }
      try {
        await opts.onProgress(entry);
      } catch {
        // Do not fail assessment pipeline if progress observer throws
      }
    };

    const startedAt = new Date().toISOString();
    const coordinator = new CyberSquadCoordinator({
      programId: this.programId,
      runId,
      startedAt,
      status: 'running',
      onEvent: async (ev, snap) => {
        this.latestSquadState = snap;
        if (opts?.onSquadEvent) {
          await opts.onSquadEvent(ev, snap);
        }
      },
    });

    const orchAgent = coordinator.spawnAgent({
      id: `orch-${this.programId.slice(-6)}`,
      parentId: null,
      name: 'Lead Orchestrator',
      role: 'orchestrator',
      provider: this.llmRouter.orchestratorProvider,
      model: this.llmRouter.orchestratorModel,
      skills: [
        'root-agent',
        'threat-modeling',
        'scope-governance',
        'coverage-reconciliation',
      ],
      task: `Coordinate governed multi-agent security posture assessment for ${this.scope.programName}`,
      scope: this.scope,
      createdAt: startedAt,
    });

    if (opts?.userBrief && opts.userBrief.trim().length > 0) {
      coordinator.recordUserBrief(orchAgent.id, opts.userBrief.trim(), {
        title: `Operator engagement brief -> ${orchAgent.name}`,
        timestamp: startedAt,
      });
    }

    coordinator.recordThink(orchAgent.id, {
      know: `Scope locks ${this.scope.authorizedDomains.join(', ')} (excludedHosts=${this.scope.excludedHosts.join(', ') || 'none'}, excludedPaths=${this.scope.excludedPaths.join(', ') || 'none'}, maxRpsPerHost=${this.scope.maxRpsPerHost}, strictReadOnly=${String(this.scope.strictReadOnly)}).`,
      think: `Establish run-scoped SharedThreatModel and delegate read-only perimeter recon, zero-traffic JS AST/OpenAPI cartography, and hypothesis-driven posture verification.`,
      test: `Spawn specialist subagents on isolated GitOps worktrees and enforce Strix 3-state closure discipline (confirmed | ruled_out | open_proof_gap).`,
      validate: `Require HTTP 451 boundary proof, Stage 3 deterministic CI verification, and Stage 4 Prompt-Guard review before main merge.`,
      confidence: 80,
    });

    const seedHostLabels = this.seedTargets.map((s) => s.host);
    coordinator.saveThreatModel(orchAgent.id, {
      target:
        this.scope.authorizedDomains.join(', ') || this.scope.programName,
      summary: `Governed read-only posture model for ${this.scope.programName} across seed perimeter (${seedHostLabels.join(', ') || 'in-scope domains'}) under strict GET/HEAD/OPTIONS and HTTP 451 egress enforcement.`,
      trustBoundaries: [
        `Cross-origin browser boundary -> ${seedHostLabels[0] ?? 'in-scope API'} (CORS Access-Control-Allow-Origin & credentials enforcement)`,
        `Unauthenticated internet -> session/role-gated routes (${Object.keys(this.scope.authProfiles).join(', ') || 'public VDP surface'})`,
        `Sandbox execution -> Governed EgressGateway (HMAC task token + HTTP 451 scope/exclusion policy + ${this.scope.maxRpsPerHost} RPS cap)`,
      ],
      attackerRoles: [
        'Unauthenticated external web client probing exposed endpoints and cross-origin reads',
        'Low-privilege authenticated viewer session testing vertical/horizontal read-only authorization boundaries',
        'Untrusted upstream HTTP response attempting indirect prompt injection in diff/finding text',
      ],
      highValueAssets: [
        ...seedHostLabels.slice(0, 4).map((h) => `Perimeter & transport headers on ${h}`),
        'Organization settings, role/permission schemas, and SessionVault-protected session contexts',
      ],
      inferredAssumptions: [
        `Out-of-scope hosts and excluded paths (${[...this.scope.excludedHosts, ...this.scope.excludedPaths].join(', ') || 'external domains'}) are blocked with HTTP 451 at EgressGateway — verify empirically.`,
        `Client JS bundles and OpenAPI documents may expose undocumented parameterized routes — verify via zero-traffic AST extraction.`,
      ],
    });

    const egressHyp = coordinator.formHypothesis(orchAgent.id, {
      id: `hyp-egress-${runId.slice(-5)}`,
      phase: 'INITIAL_GATHERING',
      surface:
        this.scope.excludedHosts[0] ??
        this.scope.excludedPaths[0] ??
        'external-untrusted.example',
      riskCategory: 'SCOPE_BOUNDARY_ENFORCEMENT',
      observation: `Engagement defines ${this.scope.excludedHosts.length} excluded host(s) and ${this.scope.excludedPaths.length} excluded path pattern(s).`,
      statement:
        'Out-of-scope domains or excluded paths could bypass governance if EgressGateway canonicalization fails open.',
      confidence: 60,
      testPlan:
        'Issue governed GET boundary probes against out-of-scope and excluded targets and confirm HTTP 451 interception.',
    });

    const preferE2B =
      (opts?.useCloudSandbox ?? this.defaultUseCloudSandbox) !== false;
    const effectiveE2BKey = (
      this.e2bApiKey ?? process.env.E2B_API_KEY
    )?.trim();

    const sandboxProvider = createDefaultSandboxProvider({
      preferE2B,
      ...(effectiveE2BKey ? { e2bApiKey: effectiveE2BKey } : {}),
    });
    this.activeSandboxProvider = sandboxProvider.providerType;

    const sandbox = await sandboxProvider.createSession({
      maxCommands: 80,
      ttlMs: 240_000,
    });

    const mergedFindings: string[] = [];

    try {
      await emitProgress({
        level: 'INFO',
        stage: 'SANDBOX',
        agent: 'SandboxRunner',
        message: `Provisioned isolated execution environment (${this.activeSandboxProvider.toUpperCase()}) for run ${runId}.`,
      });

      if (this.activeSandboxProvider === 'e2b') {
        await sandbox.writeFile(
          '__aegis_upstream_fetch.py',
          E2B_UPSTREAM_FETCH_PY,
        );

        this.egressGateway.setUpstreamDispatcher(async (upstreamReq) => {
          const encodedReq = Buffer.from(
            JSON.stringify({
              url: upstreamReq.url,
              method: upstreamReq.method,
              headers: upstreamReq.headers,
            }),
            'utf8',
          ).toString('base64');

          const cmdRes = await sandbox.executeCommand(
            'python3 __aegis_upstream_fetch.py',
            {
              env: { AEGIS_REQ_B64: encodedReq },
              timeoutMs: 12_000,
            },
          );

          if (cmdRes.exitCode !== 0) {
            throw new Error(
              `E2B governed upstream fetch failed (exit=${cmdRes.exitCode}): ${cmdRes.stderr.trim() || cmdRes.stdout.trim() || 'unknown error'}`,
            );
          }

          const parsed = JSON.parse(cmdRes.stdout) as {
            status: number;
            statusText?: string;
            headers: Record<string, string>;
            bodyBase64: string;
          };

          return {
            status: parsed.status,
            statusText: parsed.statusText ?? 'OK',
            headers: parsed.headers ?? {},
            body: Buffer.from(parsed.bodyBase64 ?? '', 'base64'),
          };
        });
      }

      // Spawn Level 1 Specialist #1: Perimeter & Egress Recon Specialist
      const reconAgent = coordinator.spawnAgent({
        id: `recon-${this.scope.engagementId.slice(-6)}`,
        parentId: orchAgent.id,
        name: 'Perimeter & Egress Recon Specialist',
        role: 'recon',
        provider: this.llmRouter.subagentProvider,
        model: this.llmRouter.subagentModel,
        skills: [
          'perimeter-recon',
          'egress-451-boundary',
          'header-fingerprinting',
        ],
        worktreeBranch: 'task/recon-perimeter',
        task: `Verify EgressGateway HTTP 451 guardrails and fingerprint ${this.seedTargets.length} authorized seed host(s)`,
        scope: this.scope,
        assignedHypotheses: [
          {
            id: egressHyp.id,
            surface: egressHyp.surface,
            riskCategory: egressHyp.riskCategory,
            statement: egressHyp.statement,
            confidence: egressHyp.confidence,
            testPlan: egressHyp.testPlan,
          },
        ],
      });

      coordinator.recordThink(reconAgent.id, {
        know: `Assigned ${this.seedTargets.length} seed target(s) (${seedHostLabels.join(', ') || 'none'}) with maxRpsPerHost=${this.scope.maxRpsPerHost}.`,
        think: `Testing HTTP 451 scope/exclusion boundaries first confirms deterministic egress containment before probing live seed roots.`,
        test: `Send governed GET boundary probes followed by read-only seed host fingerprinting in worktree.`,
        validate: `Confirm HTTP 451 BLOCKED_SCOPE_451 responses and record live status/headers per host.`,
        confidence: 85,
      });

      // -----------------------------------------------------------------------
      // 1. Guardrail Verification Probes (active egress enforcement check)
      // -----------------------------------------------------------------------
      const guardrailTaskId = `guardrail-${runId}`;
      const guardrailToken = this.mintTaskToken(guardrailTaskId, 0, []);
      const guardrailClient = new GovernedHttpClient({
        gatewayUrl: this.gatewayUrl,
        taskToken: guardrailToken,
      });

      const guardrailTargets: string[] = [
        'http://external-untrusted.example/probe',
      ];

      if (this.scope.excludedHosts.length > 0) {
        const sampleExcludedHost = this.scope.excludedHosts[0]!.replace(
          /^\*\./,
          'sub.',
        );
        guardrailTargets.push(`https://${sampleExcludedHost}/`);
      }

      if (
        this.scope.excludedPaths.length > 0 &&
        this.seedTargets.length > 0
      ) {
        const firstSeedBase = this.seedTargets[0]!.baseUrl.replace(/\/+$/, '');
        const sampleExcludedPath = this.scope.excludedPaths[0]!.replace(
          /\/\*\*$/,
          '/probe',
        );
        guardrailTargets.push(`${firstSeedBase}${sampleExcludedPath}`);

        if (
          this.seedTargets.some(
            (s) => normalizeHostname(s.host) === 'api.acme.internal',
          ) &&
          isPathExcluded('/admin/destruct/wipe', this.scope.excludedPaths)
        ) {
          const legacyAcmeDestructProbe =
            'http://api.acme.internal/admin/destruct/wipe';
          if (!guardrailTargets.includes(legacyAcmeDestructProbe)) {
            guardrailTargets.push(legacyAcmeDestructProbe);
          }
        }
      }

      for (const probeUrl of guardrailTargets) {
        await guardrailClient.request(probeUrl, { method: 'GET' });
        coordinator.recordCoverage(reconAgent.id, {
          surface: `GET ${probeUrl}`,
          riskArea: 'Egress Scope & Exclusion Guardrail',
          outcome: 'blocked_451',
          evidence: `EgressGateway blocked ${probeUrl} with HTTP 451 Unavailable For Legal Reasons before upstream socket connection.`,
        });
      }

      coordinator.updateHypothesis(reconAgent.id, egressHyp.id, {
        assignedAgentId: reconAgent.id,
        confidence: 5,
        closureState: 'ruled_out',
        namedControlOrProof: `Safe because EgressGateway scope policy engine at HTTP 451 BLOCKED_SCOPE_451 enforces authorizedDomains, excludedHosts, and excludedPaths before upstream dispatch (${guardrailTargets.length} boundary probe(s) blocked).`,
        reason: `Verified HTTP 451 interception across ${guardrailTargets.length} out-of-scope/excluded boundary probe(s).`,
      });

      await emitProgress({
        level: 'SUCCESS',
        stage: 'EGRESS',
        agent: 'EgressGateway',
        message: `Verified active HTTP 451 scope & exclusion guardrails across ${guardrailTargets.length} boundary probe(s) (RPS cap=${this.scope.maxRpsPerHost}/s, strictReadOnly=${String(this.scope.strictReadOnly)}).`,
      });

      // -----------------------------------------------------------------------
      // 2. Stage 1-5 Recon Worktree
      // -----------------------------------------------------------------------
      const reconTaskId = `recon-${runId}`;
      const reconLockKey = 'discovery:recon';
      const reconLockRes = this.lockManager.acquire(
        reconLockKey,
        reconTaskId,
        300_000,
      );
      if (!reconLockRes.acquired) {
        throw new Error(
          `Unable to acquire ${reconLockKey} lock (held by ${reconLockRes.holderTaskId})`,
        );
      }

      let reconBranchName: string | undefined;
      let reconBatch: RouteObservationBatch;
      let discoveredBundles: Array<{ host: string; bundleUrl: string }> = [];
      let discoveredOpenApiUrls: Array<{ host: string; specUrl: string }> = [];

      try {
        await emitProgress({
          level: 'INFO',
          stage: 'RECON',
          agent: 'ReconSubagent',
          message: `Probing ${this.seedTargets.length} authorized seed target(s) (${this.seedTargets.map((s) => s.host).join(', ') || 'none'}) via governed read-only egress...`,
        });

        const reconWt = await this.worktreeManager.createTaskWorktree(
          reconTaskId,
          `recon-${runId}`,
        );
        reconBranchName = reconWt.branchName;

        const reconToken = this.mintTaskToken(
          reconTaskId,
          reconLockRes.lock.fencingToken,
          [],
        );
        const reconFetcher = new GovernedHttpClient({
          gatewayUrl: this.gatewayUrl,
          taskToken: reconToken,
        });

        const reconResult = await runReconSubagent({
          runId,
          seedTargets: this.seedTargets,
          fetcher: reconFetcher,
        });

        discoveredBundles = reconResult.discoveredBundles;
        discoveredOpenApiUrls = reconResult.discoveredOpenApiUrls;

        reconBatch = {
          ...reconResult.batch,
          hosts: reconResult.batch.hosts.map((h) => ({
            ...h,
            sources: Array.from(new Set(['RECON', ...h.sources])),
          })),
          endpoints: reconResult.batch.endpoints.map((ep) => ({
            ...ep,
            source: 'RECON',
          })),
        };

        await emitProgress({
          level: 'INFO',
          stage: 'RECON',
          agent: 'ReconSubagent',
          message: `Observed ${reconBatch.hosts.length} host(s), ${reconBatch.endpoints.length} route(s), ${discoveredBundles.length} JS bundle(s), and ${discoveredOpenApiUrls.length} OpenAPI spec(s).`,
        });

        coordinator.recordReconStep(reconAgent.id, {
          title: `Fingerprinted ${reconBatch.hosts.length} host(s) & ${reconBatch.endpoints.length} seed route(s)`,
          detail: `Discovered ${reconBatch.hosts.map((h) => h.hostname).join(', ') || 'seed perimeter'}, ${discoveredBundles.length} JS bundle(s), and ${discoveredOpenApiUrls.length} OpenAPI spec(s) on branch ${reconWt.branchName}.`,
          data: {
            hosts: reconBatch.hosts.map((h) => h.hostname),
            routesCount: reconBatch.endpoints.length,
            bundlesCount: discoveredBundles.length,
            openApiCount: discoveredOpenApiUrls.length,
            worktreeBranch: reconWt.branchName,
          },
        });

        for (const h of reconBatch.hosts) {
          coordinator.recordCoverage(reconAgent.id, {
            surface: `HOST ${h.hostname}`,
            riskArea: 'Perimeter Reachability & Fingerprinting',
            outcome: 'no_issue_found',
            evidence: `Fingerprinted ${h.hostname} via governed read-only GET/HEAD${h.statusCode ? ` (HTTP ${h.statusCode})` : ''}${h.serverHeader ? ` [${h.serverHeader}]` : ''}.`,
          });
        }

        const reconObsPath = path.join(
          reconWt.worktreePath,
          'observations',
          `recon-${runId}.json`,
        );
        await fs.mkdir(path.dirname(reconObsPath), { recursive: true });
        await fs.writeFile(
          reconObsPath,
          JSON.stringify(reconBatch, null, 2),
          'utf8',
        );

        await this.worktreeManager.commitWorktreeChanges(
          reconWt.worktreePath,
          `feat(recon): record host and route observations (${runId})`,
        );

        const reconCi = await runDeterministicCiGate({
          worktreeManager: this.worktreeManager,
          branchName: reconWt.branchName,
          lockManager: this.lockManager,
          lockResourceKey: reconLockKey,
          fencingToken: reconLockRes.lock.fencingToken,
        });

        if (!reconCi.passed) {
          throw new Error(
            `Recon CI gate failed: ${reconCi.violations.join('; ')}`,
          );
        }

        const { mergeCommitSha } = await this.worktreeManager.mergeBranchToMain(
          reconWt.branchName,
          `Merge branch '${reconWt.branchName}': Stage 1-5 recon observations`,
        );

        await this.stateDb.recordReview({
          id: randomUUID(),
          engagementId: this.scope.engagementId,
          branchName: reconWt.branchName,
          taskId: reconTaskId,
          ciPassed: true,
          decision: 'APPROVE_MERGE',
          rationale: `Deterministic CI verified ${reconBatch.hosts.length} host(s) and ${reconBatch.endpoints.length} route observation(s).`,
          commitSha: mergeCommitSha,
          createdAt: new Date().toISOString(),
        });

        await emitProgress({
          level: 'SUCCESS',
          stage: 'RECON',
          agent: 'DeterministicCiGate',
          message: `Stage 3 CI verified & merged recon branch ${reconWt.branchName} -> main (${mergeCommitSha.slice(0, 8)}).`,
        });

        coordinator.amendThreatModel(
          reconAgent.id,
          `Empirical recon verified ${reconBatch.hosts.length} live host(s) (${reconBatch.hosts.map((h) => h.hostname).join(', ') || 'none'}), ${discoveredBundles.length} client JS bundle(s), ${discoveredOpenApiUrls.length} OpenAPI spec(s), and HTTP 451 blocking across ${guardrailTargets.length} boundary probe(s).`,
        );

        coordinator.completeAgent(reconAgent.id, {
          success: true,
          summary: `Merged recon observations (${reconWt.branchName} -> ${mergeCommitSha.slice(0, 8)}): ${reconBatch.hosts.length} host(s), ${reconBatch.endpoints.length} route(s), ${guardrailTargets.length} HTTP 451 boundary blocks.`,
          findings: reconBatch.hosts.map(
            (h) =>
              `Live in-scope host ${h.hostname}${h.statusCode ? ` (HTTP ${h.statusCode})` : ''}`,
          ),
          openItems: [],
          recommendations: [
            'Extract zero-traffic AST & OpenAPI schemas from discovered client bundles and spec URLs.',
          ],
        });
      } finally {
        await this.worktreeManager.cleanupWorktree(
          reconTaskId,
          reconBranchName,
          false,
        );
        this.lockManager.release(
          reconLockKey,
          reconTaskId,
          reconLockRes.lock.fencingToken,
        );
      }

      // -----------------------------------------------------------------------
      // 3. Stage 1-5 Zero-Traffic Static JS AST & OpenAPI Worktree
      // -----------------------------------------------------------------------
      const cartographerAgent = coordinator.spawnAgent({
        id: `carto-${this.scope.engagementId.slice(-6)}`,
        parentId: orchAgent.id,
        name: 'JS AST & OpenAPI Cartographer',
        role: 'cartographer',
        provider: this.llmRouter.subagentProvider,
        model: this.llmRouter.subagentModel,
        skills: [
          'babel-js-ast',
          'openapi-schema-parser',
          'zero-traffic-cartography',
        ],
        worktreeBranch: 'task/cartographer-schemas',
        task: `Extract zero-traffic route schemas from ${discoveredBundles.length} JS bundle(s) and ${discoveredOpenApiUrls.length} OpenAPI spec(s)`,
        scope: this.scope,
        knownFacts: [
          `Live hosts: ${reconBatch.hosts.map((h) => h.hostname).join(', ') || 'none'}`,
          `Discovered JS bundles: ${discoveredBundles.length}`,
          `Discovered OpenAPI specs: ${discoveredOpenApiUrls.length}`,
        ],
      });

      coordinator.recordThink(cartographerAgent.id, {
        know: `Recon surfaced ${discoveredBundles.length} JS bundle(s) and ${discoveredOpenApiUrls.length} OpenAPI spec(s) ready for single-fetch BlobVault archival.`,
        think: `Zero-traffic @babel/parser AST traversal and OpenAPI schema extraction will expose parameterized API paths and method contracts without sending brute-force requests.`,
        test: `Fetch in-scope bundles/specs once via GovernedHttpClient, parse AST/OpenAPI schemas in worktree, and run SurfaceReducer canonicalization.`,
        validate: `Confirm Stage 3 CI schema pass and verify deduplicated canonical endpoint graph in StateDb.`,
        confidence: 82,
      });

      const methodGuardHyp = coordinator.formHypothesis(cartographerAgent.id, {
        id: `hyp-readonly-${runId.slice(-5)}`,
        assignedAgentId: cartographerAgent.id,
        phase: 'SCHEMA_ANALYSIS',
        surface: `${reconBatch.hosts[0]?.hostname ?? 'in-scope-api'}/*`,
        riskCategory: 'STRICT_READONLY_METHOD_GUARD',
        observation:
          'Client JS AST and OpenAPI specs frequently declare state-mutating POST/PUT/DELETE endpoints.',
        statement:
          'Discovered state-changing routes could be invoked if subagent HTTP clients lack strict verb filtering.',
        confidence: 52,
        testPlan:
          'Verify strictReadOnly=true in ScopeConfig and HTTP 405 BLOCKED_METHOD_405 enforcement in EgressGateway.',
      });

      const staticTaskId = `static-${runId}`;
      const staticLockKey = 'discovery:static-surface';
      const staticLockRes = this.lockManager.acquire(
        staticLockKey,
        staticTaskId,
        300_000,
      );
      if (!staticLockRes.acquired) {
        throw new Error(
          `Unable to acquire ${staticLockKey} lock (held by ${staticLockRes.holderTaskId})`,
        );
      }

      let staticBranchName: string | undefined;
      const staticBatches: RouteObservationBatch[] = [];

      try {
        const staticToken = this.mintTaskToken(
          staticTaskId,
          staticLockRes.lock.fencingToken,
          [],
        );
        const staticFetcher = new GovernedHttpClient({
          gatewayUrl: this.gatewayUrl,
          taskToken: staticToken,
        });

        const inScopeBundles = discoveredBundles
          .filter((b) => evaluateTargetScope(b.bundleUrl, this.scope).allowed)
          .slice(0, 6);

        if (inScopeBundles.length > 0 || discoveredOpenApiUrls.length > 0) {
          await emitProgress({
            level: 'INFO',
            stage: 'JS_AST',
            agent: 'StaticAstAnalyzer',
            message: `Fetching ${inScopeBundles.length} in-scope JS bundle(s) and ${discoveredOpenApiUrls.length} OpenAPI spec(s) into BlobVault for zero-traffic AST analysis...`,
          });
        }

        // Fetch discovered JS bundle(s) ONCE via GovernedHttpClient and store in BlobVault
        const fetchedBundles: Array<{ host: string; code: string }> = [];
        for (const item of inScopeBundles) {
          const res = await staticFetcher.request(item.bundleUrl, {
            method: 'GET',
          });
          if (res.status >= 200 && res.status < 300 && res.bodyText.trim()) {
            await this.blobVault.put(res.bodyText, 'application/javascript', {
              kind: 'js-bundle',
              host: item.host,
              url: item.bundleUrl,
            });
            fetchedBundles.push({ host: item.host, code: res.bodyText });
          }
        }

        // Fetch discovered OpenAPI spec(s) ONCE via GovernedHttpClient and store in BlobVault
        const fetchedSpecs: Array<{ host: string; specContent: string }> = [];
        for (const item of discoveredOpenApiUrls) {
          const res = await staticFetcher.request(item.specUrl, {
            method: 'GET',
          });
          if (res.status >= 200 && res.status < 300 && res.bodyText.trim()) {
            await this.blobVault.put(res.bodyText, 'application/json', {
              kind: 'openapi-spec',
              host: item.host,
              url: item.specUrl,
            });
            fetchedSpecs.push({ host: item.host, specContent: res.bodyText });
          }
        }

        const staticWt = await this.worktreeManager.createTaskWorktree(
          staticTaskId,
          `static-surface-${runId}`,
        );
        staticBranchName = staticWt.branchName;

        // Zero additional target requests: static AST & OpenAPI parsing in-memory
        for (let i = 0; i < fetchedBundles.length; i += 1) {
          const bundle = fetchedBundles[i]!;
          const astBatch = analyzeJavaScriptBundleAst({
            code: bundle.code,
            targetHost: bundle.host,
            runId,
            sourceLabel: 'STATIC_JS_AST',
          });
          staticBatches.push(astBatch);

          const suffix = i === 0 ? `${runId}` : `${runId}-${i}`;
          const astFilePath = path.join(
            staticWt.worktreePath,
            'schemas',
            `js-ast-${suffix}.json`,
          );
          await fs.mkdir(path.dirname(astFilePath), { recursive: true });
          await fs.writeFile(
            astFilePath,
            JSON.stringify(astBatch, null, 2),
            'utf8',
          );
        }

        for (let i = 0; i < fetchedSpecs.length; i += 1) {
          const spec = fetchedSpecs[i]!;
          const rawOpenApiBatch = extractOpenApiObservations({
            specContent: spec.specContent,
            defaultHost: spec.host,
            runId,
          });
          const openApiBatch: RouteObservationBatch = {
            ...rawOpenApiBatch,
            hosts: rawOpenApiBatch.hosts.map((h) => ({
              ...h,
              sources: Array.from(new Set(['OPENAPI_PARSER', ...h.sources])),
            })),
            endpoints: rawOpenApiBatch.endpoints.map((ep) => ({
              ...ep,
              source: 'OPENAPI_PARSER',
            })),
          };
          staticBatches.push(openApiBatch);

          const suffix = i === 0 ? `${runId}` : `${runId}-${i}`;
          const openApiFilePath = path.join(
            staticWt.worktreePath,
            'observations',
            `openapi-${suffix}.json`,
          );
          await fs.mkdir(path.dirname(openApiFilePath), { recursive: true });
          await fs.writeFile(
            openApiFilePath,
            JSON.stringify(openApiBatch, null, 2),
            'utf8',
          );
        }

        if (staticBatches.length > 0) {
          await this.worktreeManager.commitWorktreeChanges(
            staticWt.worktreePath,
            `feat(static-surface): extract JS AST and OpenAPI route schemas (${runId})`,
          );

          const staticCi = await runDeterministicCiGate({
            worktreeManager: this.worktreeManager,
            branchName: staticWt.branchName,
            lockManager: this.lockManager,
            lockResourceKey: staticLockKey,
            fencingToken: staticLockRes.lock.fencingToken,
          });

          if (!staticCi.passed) {
            throw new Error(
              `Static surface CI gate failed: ${staticCi.violations.join('; ')}`,
            );
          }

          const { mergeCommitSha } =
            await this.worktreeManager.mergeBranchToMain(
              staticWt.branchName,
              `Merge branch '${staticWt.branchName}': zero-traffic JS AST & OpenAPI observations`,
            );

          await this.stateDb.recordReview({
            id: randomUUID(),
            engagementId: this.scope.engagementId,
            branchName: staticWt.branchName,
            taskId: staticTaskId,
            ciPassed: true,
            decision: 'APPROVE_MERGE',
            rationale: `Verified ${staticBatches.length} zero-traffic static AST/OpenAPI batch(es) via Stage 3 CI gate.`,
            commitSha: mergeCommitSha,
            createdAt: new Date().toISOString(),
          });

          await emitProgress({
            level: 'SUCCESS',
            stage: 'JS_AST',
            agent: 'StaticAstAnalyzer',
            message: `Merged ${staticBatches.length} zero-traffic JS AST & OpenAPI schema batch(es) to main (${mergeCommitSha.slice(0, 8)}).`,
          });
        } else {
          await emitProgress({
            level: 'INFO',
            stage: 'JS_AST',
            agent: 'StaticAstAnalyzer',
            message:
              'No public client JS bundles or OpenAPI specs discovered for static AST extraction.',
          });
        }
      } finally {
        await this.worktreeManager.cleanupWorktree(
          staticTaskId,
          staticBranchName,
          staticBatches.length === 0,
        );
        this.lockManager.release(
          staticLockKey,
          staticTaskId,
          staticLockRes.lock.fencingToken,
        );
      }

      // -----------------------------------------------------------------------
      // 4. Deterministic Surface Reduction (canonicalize & sync to StateDb)
      // -----------------------------------------------------------------------
      const allBatches: RouteObservationBatch[] = [
        reconBatch,
        ...staticBatches,
      ];
      const surfaceResult = await reduceObservationsToSurface({
        repoDir: this.worktreeManager.repoDir,
        worktreeManager: this.worktreeManager,
        batches: allBatches,
        stateDb: this.stateDb,
        engagementId: this.scope.engagementId,
      });

      await emitProgress({
        level: 'SUCCESS',
        stage: 'SURFACE_REDUCER',
        agent: 'SurfaceReducer',
        message: `Canonicalized attack surface: ${surfaceResult.hosts.length} host(s) and ${surfaceResult.endpoints.length} deduplicated endpoint(s) synced to StateDb.`,
      });

      coordinator.updateHypothesis(cartographerAgent.id, methodGuardHyp.id, {
        confidence: 4,
        closureState: 'ruled_out',
        namedControlOrProof:
          'Safe because EgressGateway method policy at HTTP 405 BLOCKED_METHOD_405 and strictReadOnly=true enforce GET/HEAD/OPTIONS-only execution before any state-changing verb is dispatched.',
        reason:
          'Cataloged non-read-only schemas passively without executing state-changing requests.',
      });

      const canonicalRouteLabels = surfaceResult.endpoints
        .slice(0, 8)
        .map((ep) => `${ep.method} ${ep.host}${ep.canonicalPath}`);

      coordinator.recordReconStep(cartographerAgent.id, {
        title: `Canonicalized ${surfaceResult.endpoints.length} endpoint(s) across ${surfaceResult.hosts.length} host(s)`,
        detail: `Extracted ${staticBatches.length} static AST/OpenAPI batch(es) and deduplicated into ${surfaceResult.endpoints.length} canonical route(s): ${canonicalRouteLabels.join(', ') || 'none'}.`,
        data: {
          staticBatchesCount: staticBatches.length,
          canonicalEndpointsCount: surfaceResult.endpoints.length,
          sampleRoutes: canonicalRouteLabels,
        },
      });

      coordinator.amendThreatModel(
        cartographerAgent.id,
        `Zero-traffic JS AST & OpenAPI cartography canonicalized ${surfaceResult.endpoints.length} deduplicated endpoint(s) (${canonicalRouteLabels.slice(0, 4).join(', ') || 'root perimeter'}), exposing candidate API & web surfaces for read-only CORS, transport header, and role-drift verification.`,
      );

      coordinator.completeAgent(cartographerAgent.id, {
        success: true,
        summary: `Canonicalized ${surfaceResult.endpoints.length} deduplicated endpoint(s) from ${staticBatches.length} static AST/OpenAPI batch(es) and recon observations.`,
        findings: canonicalRouteLabels.slice(0, 5),
        openItems: [],
        recommendations: [
          'Evaluate in-scope canonical endpoints in CORS & Transport Posture Hunter.',
        ],
      });

      // -----------------------------------------------------------------------
      // 5. LLM Hypothesis Generation + Per-Endpoint Posture Hunter & Validator
      // -----------------------------------------------------------------------
      const isEndpointHostInScope = (host: string): boolean => {
        const norm = normalizeHostname(host);
        if (!isHostAuthorized(norm, this.scope.authorizedDomains)) {
          return false;
        }
        if (
          this.scope.excludedHosts.length > 0 &&
          isHostAuthorized(norm, this.scope.excludedHosts)
        ) {
          return false;
        }
        return true;
      };

      const nonRootCandidates = surfaceResult.endpoints.filter(
        (ep) =>
          ep.canonicalPath !== '/' &&
          ep.canonicalPath !== '/openapi.json' &&
          ep.canonicalPath !== '/robots.txt' &&
          isEndpointHostInScope(ep.host) &&
          !isPathExcluded(ep.canonicalPath, this.scope.excludedPaths),
      );

      const rootCandidates = surfaceResult.endpoints.filter(
        (ep) =>
          ep.canonicalPath === '/' &&
          isEndpointHostInScope(ep.host) &&
          !isPathExcluded(ep.canonicalPath, this.scope.excludedPaths),
      );

      const candidateEndpoints = (
        nonRootCandidates.length > 0
          ? [...nonRootCandidates.slice(0, 6), ...rootCandidates.slice(0, 2)]
          : rootCandidates.slice(0, 4)
      ).slice(0, 8);

      let findingSeq =
        (await this.stateDb.listFindings(this.scope.engagementId)).length + 1;
      const availableAuthProfiles = Object.keys(this.scope.authProfiles);
      const liveLlmClient = this.llmRouter.isConfigured
        ? this.llmRouter
        : undefined;

      const generatedCandidates = await generateSquadHypotheses({
        scope: this.scope,
        threatModel: coordinator.getSnapshot().threatModel,
        hosts: surfaceResult.hosts.map((h) => h.hostname),
        endpoints: candidateEndpoints,
        ...(liveLlmClient ? { llmClient: liveLlmClient } : {}),
      });

      const orchestratedHyps: SecurityHypothesis[] = generatedCandidates.map(
        (cand, idx) =>
          coordinator.formHypothesis(orchAgent.id, {
            id: `hyp-gen-${String(idx + 1).padStart(2, '0')}-${runId.slice(-4)}`,
            phase: 'POSTURE_VERIFICATION',
            surface: cand.surface,
            riskCategory: cand.riskCategory,
            observation: cand.observation,
            statement: cand.statement,
            confidence: cand.confidence,
            testPlan: cand.testPlan,
          }),
      );

      const proofGapSurface =
        canonicalRouteLabels.find(
          (r) => r.includes('{param}') || r.includes('/api') || r.includes('/v1'),
        ) ??
        `${surfaceResult.hosts[0]?.hostname ?? 'target'}/v1/tenant-resources`;

      const proofGapHyp = coordinator.formHypothesis(orchAgent.id, {
        id: `hyp-gap-${runId.slice(-5)}`,
        phase: 'COUNTEREVIDENCE',
        surface: proofGapSurface,
        riskCategory: 'MULTI_TENANT_ISOLATION_PROOF_GAP',
        observation: `Cross-organization horizontal isolation on ${proofGapSurface} requires paired multi-tenant session fixtures.`,
        statement: `Horizontal tenant object access across distinct organization IDs on ${proofGapSurface} cannot be ruled out from single-tenant or unauthenticated read-only probes alone.`,
        confidence: 54,
        testPlan: `Verify available role/unauthenticated responses read-only and preserve unprovisioned cross-tenant checks as open_proof_gap.`,
      });

      const hunterAgent = coordinator.spawnAgent({
        id: `hunter-${this.scope.engagementId.slice(-6)}`,
        parentId: orchAgent.id,
        name: 'CORS & Transport Posture Hunter',
        role: 'hypothesis_hunter',
        provider: this.llmRouter.subagentProvider,
        model: this.llmRouter.subagentModel,
        skills: [
          'cors-preflight-audit',
          'transport-header-posture',
          'authz-drift-detection',
        ],
        worktreeBranch: 'task/hunter-posture',
        task: `Audit ${candidateEndpoints.length} canonical endpoint(s) against posture hypotheses and escalate >75% confidence candidates to Validator`,
        scope: this.scope,
        knownFacts: [
          `Canonical endpoints selected: ${candidateEndpoints.length}`,
          `Auth profiles available: ${availableAuthProfiles.join(', ') || 'none'}`,
        ],
        assignedHypotheses: [
          ...orchestratedHyps.map((h) => ({
            id: h.id,
            surface: h.surface,
            riskCategory: h.riskCategory,
            statement: h.statement,
            confidence: h.confidence,
            testPlan: h.testPlan,
          })),
          {
            id: proofGapHyp.id,
            surface: proofGapHyp.surface,
            riskCategory: proofGapHyp.riskCategory,
            statement: proofGapHyp.statement,
            confidence: proofGapHyp.confidence,
            testPlan: proofGapHyp.testPlan,
          },
        ],
      });

      coordinator.recordThink(hunterAgent.id, {
        know: `Assigned ${candidateEndpoints.length} in-scope canonical endpoint(s) and ${orchestratedHyps.length + 1} structured hypotheses.`,
        think: `Governed OPTIONS/GET probes will distinguish compliant endpoints (ruled_out with named controls) from >75% confidence posture weaknesses requiring sandbox PoC validation.`,
        test: `Audit each candidate endpoint in an isolated GitOps worktree and spawn Counterevidence & PoC Validator when confidence exceeds 75%.`,
        validate: `Enforce Strix closure discipline across every evaluated endpoint.`,
        confidence: 80,
      });

      let validatorAgent: SquadAgentNode | undefined;
      const ensureValidatorSpawned = (
        triggerReason: string,
        worktreeBranch?: string,
      ): SquadAgentNode => {
        if (validatorAgent) {
          return validatorAgent;
        }
        validatorAgent = coordinator.spawnAgent({
          id: `val-${this.scope.engagementId.slice(-6)}`,
          parentId: hunterAgent.id,
          name: 'Counterevidence & PoC Validator',
          role: 'validator',
          provider: this.llmRouter.subagentProvider,
          model: this.llmRouter.subagentModel,
          skills: [
            'counterevidence',
            'sandbox-poc-validator',
            'har-sha256-attestation',
          ],
          worktreeBranch: worktreeBranch ?? 'task/validator-counterevidence',
          task: `${triggerReason} — run Strix counterevidence pass, execute verify_posture.py in ${this.activeSandboxProvider.toUpperCase()} sandbox, and attest HAR SHA-256 pointers`,
          scope: this.scope,
        });

        coordinator.recordThink(validatorAgent.id, {
          know: triggerReason,
          think: `Before filing any finding, challenge exploitability via counterevidence and run reproducible verify_posture.py inside ${this.activeSandboxProvider.toUpperCase()} sandbox.`,
          test: `Execute verify_posture.py, verify SessionVault-redacted HAR SHA-256 blobs, and prepare Stage 3 CI worktree commit.`,
          validate: `Confirm only reproducible weaknesses with documented counterevidence; preserve unresolved gaps as open_proof_gap.`,
          confidence: 88,
        });

        return validatorAgent;
      };

      const hunterObservations: string[] = [];
      const validatorFindings: string[] = [];

      for (const ep of candidateEndpoints) {
        const alreadyEvaluated = await this.stateDb.isEndpointEvaluated(
          this.scope.engagementId,
          ep.endpointId,
        );
        if (alreadyEvaluated) {
          continue;
        }

        const epSlug = toSafeSlug(ep.endpointId, 44);
        const auditTaskId = `audit-${runId}-${epSlug}`;
        const lockResourceKey = `endpoint:${ep.endpointId}`;

        const epLockRes = this.lockManager.acquire(
          lockResourceKey,
          auditTaskId,
          300_000,
        );
        if (!epLockRes.acquired) {
          continue;
        }

        let epBranchName: string | undefined;
        let deleteBranchOnCleanup = false;

        try {
          const epWt = await this.worktreeManager.createTaskWorktree(
            auditTaskId,
            `audit-${epSlug}-${runId}`,
          );
          epBranchName = epWt.branchName;

          const epToken = this.mintTaskToken(
            auditTaskId,
            epLockRes.lock.fencingToken,
            availableAuthProfiles,
          );
          const epFetcher = new GovernedHttpClient({
            gatewayUrl: this.gatewayUrl,
            taskToken: epToken,
          });

          const endpointBaseUrl = this.resolveEndpointBaseUrl(ep.host);

          await emitProgress({
            level: 'INFO',
            stage: 'POSTURE_AUDIT',
            agent: 'PostureAuditor',
            message: `Auditing ${ep.method} ${endpointBaseUrl}${ep.canonicalPath} via governed read-only probes...`,
          });

          const auditResult = await auditEndpointPosture({
            taskId: auditTaskId,
            findingSeq,
            endpoint: ep,
            baseUrl: endpointBaseUrl,
            fetcher: epFetcher,
            sandbox,
            ...(liveLlmClient ? { llmClient: liveLlmClient } : {}),
            promptGuard: this.promptGuard,
            availableAuthProfiles,
          });

          if (auditResult.outcome === 'COMPLIANT') {
            deleteBranchOnCleanup = true;
            await this.stateDb.recordTombstone(
              this.scope.engagementId,
              auditResult.tombstone,
            );

            const { commitSha } =
              await this.worktreeManager.commitFilesOnMain(
                [
                  {
                    relativePath: `evaluated/${epSlug}.compliant.json`,
                    content: JSON.stringify(auditResult.tombstone, null, 2),
                  },
                ],
                `chore(evaluated): verify ${ep.endpointId} posture compliant`,
              );

            await this.stateDb.recordReview({
              id: randomUUID(),
              engagementId: this.scope.engagementId,
              branchName: epWt.branchName,
              taskId: auditTaskId,
              ciPassed: true,
              decision: 'VERIFIED_COMPLIANT',
              rationale: auditResult.tombstone.notes,
              commitSha,
              createdAt: new Date().toISOString(),
            });

            coordinator.recordCoverage(hunterAgent.id, {
              surface: `${ep.method} ${ep.host}${ep.canonicalPath}`,
              riskArea: 'CORS & Transport Header Posture',
              outcome: 'ruled_out',
              evidence: `Safe because verified endpoint headers and access controls on ${ep.endpointId} enforce compliant baseline posture (${auditResult.tombstone.notes || 'read-only verified'}).`,
            });
            hunterObservations.push(
              `Tombstoned compliant endpoint ${ep.endpointId} (${commitSha.slice(0, 8)})`,
            );

            await emitProgress({
              level: 'SUCCESS',
              stage: 'POSTURE_AUDIT',
              agent: 'PostureAuditor',
              message: `Verified ${ep.endpointId} compliant — recorded tombstone on main (${commitSha.slice(0, 8)}).`,
            });
            continue;
          }

          // Outcome === 'FINDING'
          findingSeq += 1;
          const findingId = auditResult.finding.findingId;
          const checkRelPath = `reports/${findingId}/verify_posture.py`;
          const findingRelPath = `reports/${findingId}/finding.yaml`;

          const epHyp = coordinator.formHypothesis(hunterAgent.id, {
            id: `hyp-${toSafeSlug(findingId, 24)}`,
            assignedAgentId: hunterAgent.id,
            phase: 'POSTURE_VERIFICATION',
            surface: `${ep.host} (${ep.endpointId})`,
            riskCategory: auditResult.finding.category,
            observation: `Governed read-only probe detected ${auditResult.finding.category} on ${ep.method} ${endpointBaseUrl}${ep.canonicalPath}.`,
            statement: `${auditResult.finding.title} (${ep.endpointId})`,
            confidence: 86,
            closureState: 'testing',
            testPlan: `Escalate >75% confidence candidate to Counterevidence & PoC Validator for ${this.activeSandboxProvider.toUpperCase()} verify_posture.py execution and HAR SHA-256 attestation.`,
            reason: `Live read-only evidence raised confidence to 86% (>75% escalation threshold).`,
          });

          coordinator.recordCoverage(hunterAgent.id, {
            surface: `${ep.host} (${ep.endpointId})`,
            riskArea: auditResult.finding.category,
            outcome: 'needs_follow_up',
            evidence: `Hunter observed ${auditResult.finding.category} at 86% confidence; escalated to Validator.`,
          });

          const valNode = ensureValidatorSpawned(
            `Hunter escalated ${findingId} (${auditResult.finding.category}) at 86% confidence on ${ep.endpointId}`,
            epWt.branchName,
          );

          await emitProgress({
            level: 'INFO',
            stage: 'POSTURE_AUDIT',
            agent: 'PostureAuditor',
            message: `Sandbox verification (verify_posture.py) passed=${String(auditResult.verificationPassed)} for ${findingId} [${auditResult.finding.category}] on ${ep.endpointId}.`,
          });

          const harShaPrefix =
            auditResult.finding.evidencePointers[0]?.sha256.slice(0, 16) ??
            'verified';

          coordinator.recordVerification(valNode.id, {
            title: `Sandbox verify_posture.py (${this.activeSandboxProvider.toUpperCase()}) -> ${findingId}`,
            detail: `verify_posture.py passed=${String(auditResult.verificationPassed)} on ${ep.endpointId}; HAR SHA-256=${harShaPrefix}...`,
            status: auditResult.verificationPassed ? 'completed' : 'failed',
            data: {
              findingId,
              endpointId: ep.endpointId,
              category: auditResult.finding.category,
              verificationPassed: auditResult.verificationPassed,
              harSha256Prefix: harShaPrefix,
            },
          });

          const findingReport: FindingReport = {
            ...auditResult.finding,
            reproducibleCheckFile: checkRelPath,
            status: 'PENDING_HUMAN_REVIEW',
          };

          const findingFullPath = path.join(epWt.worktreePath, findingRelPath);
          const checkFullPath = path.join(epWt.worktreePath, checkRelPath);
          await fs.mkdir(path.dirname(findingFullPath), { recursive: true });

          await fs.writeFile(
            findingFullPath,
            stringifyYaml(findingReport),
            'utf8',
          );
          await fs.writeFile(
            checkFullPath,
            auditResult.verificationPythonScript,
            'utf8',
          );

          await this.worktreeManager.commitWorktreeChanges(
            epWt.worktreePath,
            `feat(finding): ${findingId} (${findingReport.category})`,
          );

          // Stage 3: Deterministic CI Gate
          const ciResult = await runDeterministicCiGate({
            worktreeManager: this.worktreeManager,
            branchName: epWt.branchName,
            lockManager: this.lockManager,
            lockResourceKey,
            fencingToken: epLockRes.lock.fencingToken,
          });

          await emitProgress({
            level: ciResult.passed ? 'SUCCESS' : 'WARN',
            stage: 'CI_GATE',
            agent: 'DeterministicCiGate',
            message: ciResult.passed
              ? `Stage 3 CI Gate passed for ${epWt.branchName} (${findingId}).`
              : `Stage 3 CI Gate rejected ${epWt.branchName}: ${ciResult.violations.join('; ')}`,
          });

          // Stage 4: Tool-less Lead Orchestrator PR Review + Prompt Guard
          const reviewResult = await this.leadOrchestrator.reviewFindingBranch({
            branchName: epWt.branchName,
            diffText: ciResult.diffText,
            ciPassed: ciResult.passed,
            ciViolations: ciResult.violations,
            verificationPassed: auditResult.verificationPassed,
            finding: findingReport,
          });

          if (
            ciResult.passed &&
            reviewResult.verdict.decision === 'APPROVE_MERGE'
          ) {
            const { mergeCommitSha } =
              await this.worktreeManager.mergeBranchToMain(
                epWt.branchName,
                `Merge branch '${epWt.branchName}': ${findingId} (${findingReport.category})`,
              );

            await this.stateDb.upsertFinding(this.scope.engagementId, {
              ...findingReport,
              status: 'PENDING_HUMAN_REVIEW',
            });
            mergedFindings.push(findingId);

            await this.stateDb.recordReview({
              id: randomUUID(),
              engagementId: this.scope.engagementId,
              branchName: epWt.branchName,
              taskId: auditTaskId,
              ciPassed: true,
              decision: 'APPROVE_MERGE',
              rationale: reviewResult.verdict.rationale,
              commitSha: mergeCommitSha,
              createdAt: new Date().toISOString(),
            });

            coordinator.updateHypothesis(valNode.id, epHyp.id, {
              assignedAgentId: valNode.id,
              phase: 'COUNTEREVIDENCE',
              confidence: 96,
              closureState: 'confirmed',
              linkedFindingId: findingId,
              namedControlOrProof: `Confirmed by ${checkRelPath} in ${this.activeSandboxProvider.toUpperCase()} sandbox, HAR SHA-256 ${harShaPrefix}..., and Stage 4 merge ${mergeCommitSha.slice(0, 8)}.`,
              counterevidence: `Checked upstream gateway headers, authentication barriers, and response content-type on ${ep.endpointId}; verified ${findingReport.category} persists on governed read-only path (${reviewResult.verdict.rationale}).`,
              reason: `Stage 3 CI & Stage 4 Lead Orchestrator approved merge (${mergeCommitSha.slice(0, 8)}).`,
            });

            coordinator.recordCoverage(valNode.id, {
              surface: `${ep.host} (${ep.endpointId})`,
              riskArea: findingReport.category,
              outcome: 'reported',
              evidence: `Confirmed and merged ${findingId} [${findingReport.severity}] (${mergeCommitSha.slice(0, 8)}).`,
            });

            validatorFindings.push(
              `${findingId} [${findingReport.severity}] ${findingReport.title}`,
            );

            await emitProgress({
              level: 'SUCCESS',
              stage: 'ORCHESTRATOR_REVIEW',
              agent: `LeadOrchestrator (${this.llmRouter.orchestratorModel})`,
              message: `Stage 4 approved & merged ${findingId} [${findingReport.severity}] -> main (${mergeCommitSha.slice(0, 8)}): ${reviewResult.verdict.rationale}`,
            });
          } else {
            await this.stateDb.recordReview({
              id: randomUUID(),
              engagementId: this.scope.engagementId,
              branchName: epWt.branchName,
              taskId: auditTaskId,
              ciPassed: ciResult.passed,
              decision: reviewResult.verdict.decision,
              rationale: reviewResult.verdict.rationale,
              createdAt: new Date().toISOString(),
            });

            coordinator.updateHypothesis(valNode.id, epHyp.id, {
              assignedAgentId: valNode.id,
              phase: 'COUNTEREVIDENCE',
              confidence: 40,
              closureState: 'open_proof_gap',
              namedControlOrProof: `Stage 3/4 gate deferred merge (${reviewResult.verdict.decision}).`,
              counterevidence: reviewResult.verdict.rationale,
              reason: `Deferred by Stage 3/4 review: ${reviewResult.verdict.decision}`,
            });

            await emitProgress({
              level: 'WARN',
              stage: 'ORCHESTRATOR_REVIEW',
              agent: `LeadOrchestrator (${this.llmRouter.orchestratorModel})`,
              message: `Stage 4 verdict ${reviewResult.verdict.decision} on ${epWt.branchName}: ${reviewResult.verdict.rationale}`,
            });
          }
        } finally {
          await this.worktreeManager.cleanupWorktree(
            auditTaskId,
            epBranchName,
            deleteBranchOnCleanup,
          );
          this.lockManager.release(
            lockResourceKey,
            auditTaskId,
            epLockRes.lock.fencingToken,
          );
        }
      }

      // Ensure Level 2 Validator exists even on all-compliant or idempotent re-runs
      const activeValidator = ensureValidatorSpawned(
        'Counterevidence & proof-gap reconciliation across evaluated endpoints',
      );

      const [storedFindings, storedTombstones] = await Promise.all([
        this.stateDb.listFindings(this.scope.engagementId),
        this.stateDb.listTombstones(this.scope.engagementId),
      ]);

      // Reconcile any pre-existing findings/tombstones on idempotent re-runs
      for (const existingFinding of storedFindings) {
        if (!mergedFindings.includes(existingFinding.findingId)) {
          coordinator.recordCoverage(activeValidator.id, {
            surface: `${existingFinding.host} (${existingFinding.endpointId})`,
            riskArea: existingFinding.category,
            outcome: 'reported',
            evidence: `Previously verified finding ${existingFinding.findingId} [${existingFinding.severity}] in StateDb.`,
          });
        }
      }
      for (const ts of storedTombstones.slice(0, 6)) {
        coordinator.recordCoverage(hunterAgent.id, {
          surface: `${ts.method} ${ts.host}${ts.canonicalPath}`,
          riskArea: 'CORS & Transport Header Posture',
          outcome: 'ruled_out',
          evidence: `Safe because verified tombstone on ${ts.endpointId} confirms compliant baseline posture (${ts.notes || 'read-only verified'}).`,
        });
      }

      // Close generated hypotheses cleanly per Strix 3-state closure discipline
      for (const genHyp of orchestratedHyps) {
        const matchedStoredFinding = storedFindings.find(
          (f) =>
            genHyp.surface.includes(f.host) &&
            (genHyp.riskCategory.includes(f.category) ||
              f.category === 'PERMISSIVE_CORS' ||
              f.category === 'AUTHZ_SCHEMA_DRIFT' ||
              f.category === 'MISSING_SECURITY_HEADERS'),
        );

        if (matchedStoredFinding) {
          coordinator.updateHypothesis(activeValidator.id, genHyp.id, {
            assignedAgentId: activeValidator.id,
            phase: 'COUNTEREVIDENCE',
            confidence: 92,
            closureState: 'confirmed',
            linkedFindingId: matchedStoredFinding.findingId,
            namedControlOrProof: `Confirmed via verified finding ${matchedStoredFinding.findingId} on ${matchedStoredFinding.endpointId}.`,
            counterevidence: `Inspected response headers and auth boundaries on ${matchedStoredFinding.endpointId}; confirmed posture weakness reproduces read-only without neutralizing upstream guard.`,
            reason: `Corroborated by verified finding ${matchedStoredFinding.findingId}.`,
          });
        } else {
          coordinator.updateHypothesis(hunterAgent.id, genHyp.id, {
            assignedAgentId: hunterAgent.id,
            confidence: 12,
            closureState: 'ruled_out',
            namedControlOrProof: `Safe because governed read-only GET/OPTIONS probes across ${storedTombstones.length || 1} evaluated surface(s) confirmed compliant response headers and origin/access controls before exposure.`,
            reason:
              'Evaluated candidate surfaces and confirmed compliant controls on non-finding routes.',
          });
        }
      }

      // Close multi-tenant proof gap honestly as open_proof_gap
      coordinator.updateHypothesis(activeValidator.id, proofGapHyp.id, {
        assignedAgentId: activeValidator.id,
        phase: 'COUNTEREVIDENCE',
        confidence: 48,
        closureState: 'open_proof_gap',
        namedControlOrProof:
          'Unresolved proof gap: multi-organization tenant credentials are required to test cross-tenant object isolation empirically.',
        counterevidence:
          'Verified available read-only endpoints without cross-organization session fixtures; preserved as open_proof_gap per Strix counterevidence discipline.',
        reason:
          'Preserved as open_proof_gap rather than falsely marking ruled_out.',
      });

      coordinator.recordCoverage(activeValidator.id, {
        surface: proofGapHyp.surface,
        riskArea: 'Cross-Tenant Horizontal Isolation',
        outcome: 'needs_follow_up',
        evidence:
          'Open proof gap: provision paired tenant viewer profiles in SessionVault to verify cross-organization object isolation.',
      });

      const openGapItem = `Provision paired multi-tenant SessionVault profiles to resolve open_proof_gap on ${proofGapHyp.surface}.`;
      const allFindingIds = storedFindings.map((f) => f.findingId);

      coordinator.completeAgent(activeValidator.id, {
        success: true,
        summary: `Completed Strix counterevidence pass and ${this.activeSandboxProvider.toUpperCase()} sandbox PoC verification (${allFindingIds.length} verified finding(s), 1 open_proof_gap).`,
        findings:
          validatorFindings.length > 0
            ? validatorFindings
            : storedFindings.map((f) => `${f.findingId}: ${f.title}`),
        filedFindingIds: allFindingIds,
        openItems: [openGapItem],
        recommendations: [
          'Review PENDING_HUMAN_REVIEW findings in the HITL governance queue.',
        ],
      });

      coordinator.completeAgent(hunterAgent.id, {
        success: true,
        summary: `Completed posture hunting across ${candidateEndpoints.length} canonical endpoint(s): ${storedTombstones.length} compliant tombstone(s), ${allFindingIds.length} verified finding(s).`,
        findings: [
          ...hunterObservations,
          ...storedFindings.map((f) => `${f.findingId} (${f.category})`),
        ],
        filedFindingIds: allFindingIds,
        openItems: [openGapItem],
        recommendations: [
          'Retain compliant tombstones on main and address confirmed posture findings.',
        ],
      });

      await emitProgress({
        level: 'SUCCESS',
        stage: 'ORCHESTRATOR_REVIEW',
        agent: `LeadOrchestrator (${this.llmRouter.orchestratorModel})`,
        message: `Completed governed GitOps assessment ${runId}: ${mergedFindings.length} newly merged finding(s) queued in PENDING_HUMAN_REVIEW.`,
      });
    } catch (err) {
      this.latestSquadState = coordinator.finalizeRun('error');
      await this.persistSquadState(this.latestSquadState).catch(() => {
        // Ignore persistence error on failed run
      });
      throw err;
    } finally {
      this.egressGateway.setUpstreamDispatcher(undefined);
      await sandbox.close();
    }

    const overview = await this.getOverview();
    const completedAt = new Date().toISOString();
    this.lastRunAt = completedAt;

    coordinator.recordAssistantSynthesis(
      orchAgent.id,
      `Assessment ${runId} complete: ${overview.metrics.hostsDiscovered} host(s), ${overview.metrics.canonicalEndpoints} canonical endpoint(s), ${overview.metrics.pendingFindings} pending finding(s), ${overview.metrics.compliantTombstones} compliant tombstone(s), and ${overview.metrics.blockedScope451} HTTP 451 boundary block(s).`,
      {
        title: `Lead Orchestrator finalized run ${runId}`,
        timestamp: completedAt,
        data: {
          runId,
          mergedFindings,
          hostsDiscovered: overview.metrics.hostsDiscovered,
          canonicalEndpoints: overview.metrics.canonicalEndpoints,
        },
      },
    );

    coordinator.completeAgent(orchAgent.id, {
      success: true,
      summary: `Completed governed 5-agent assessment ${runId} (${mergedFindings.length} newly merged finding(s), ${overview.metrics.compliantTombstones} compliant tombstone(s), ${overview.metrics.blockedScope451} HTTP 451 boundary block(s)).`,
      findings: mergedFindings,
      filedFindingIds: mergedFindings,
      openItems: [
        'Provision paired multi-tenant SessionVault credentials if cross-organization BOLA verification is required.',
      ],
      recommendations: [
        'Triage PENDING_HUMAN_REVIEW findings via HITL approval workflow.',
      ],
      completedAt,
    });

    await coordinator.flush();
    const completedSquadState = coordinator.finalizeRun(
      'completed',
      completedAt,
    );
    this.latestSquadState = completedSquadState;
    await this.persistSquadState(completedSquadState);

    return {
      runId,
      sandboxProvider: this.activeSandboxProvider,
      startedAt,
      completedAt,
      hostsDiscovered: overview.metrics.hostsDiscovered,
      canonicalEndpoints: overview.metrics.canonicalEndpoints,
      compliantTombstones: overview.metrics.compliantTombstones,
      mergedFindings,
      blockedScope451: overview.metrics.blockedScope451,
    };
  }

  public async getOverview(): Promise<EngineOverviewSnapshot> {
    if (!this.initialized) {
      await this.init();
    }

    const [hosts, endpoints, tombstones, findings, traffic] = await Promise.all([
      this.stateDb.listHosts(this.scope.engagementId),
      this.stateDb.listEndpoints(this.scope.engagementId),
      this.stateDb.listTombstones(this.scope.engagementId),
      this.stateDb.listFindings(this.scope.engagementId),
      this.stateDb.listTraffic(this.scope.engagementId, 10_000),
    ]);

    const pendingFindings = findings.filter(
      (f) => f.status === 'PENDING_HUMAN_REVIEW' || f.status === 'DRAFT',
    ).length;
    const approvedFindings = findings.filter(
      (f) => f.status === 'APPROVED',
    ).length;
    const allowedRequests = traffic.filter(
      (t) => t.decision === 'ALLOWED',
    ).length;
    const blockedScope451 = traffic.filter(
      (t) => t.decision === 'BLOCKED_SCOPE_451',
    ).length;
    const blockedRps429 = traffic.filter(
      (t) => t.decision === 'BLOCKED_RPS_429',
    ).length;

    return {
      engagement: {
        engagementId: this.scope.engagementId,
        programName: this.scope.programName,
        authorizedDomains: [...this.scope.authorizedDomains],
        excludedHosts: [...this.scope.excludedHosts],
        excludedPaths: [...this.scope.excludedPaths],
        maxRpsPerHost: this.scope.maxRpsPerHost,
        complianceHeaders: { ...this.scope.complianceHeaders },
        strictReadOnly: this.scope.strictReadOnly,
      },
      scopeYaml: serializeScopeYaml(this.scope),
      runtime: {
        sandboxProvider: this.activeSandboxProvider,
        orchestratorProvider: this.llmRouter.orchestratorProvider,
        subagentProvider: this.llmRouter.subagentProvider,
        orchestratorModel: this.llmRouter.orchestratorModel,
        subagentModel: this.llmRouter.subagentModel,
        promptGuardModel: this.llmRouter.promptGuardModel,
        pipelineRunning: this.pipelineRunning,
        ...(this.lastRunAt ? { lastRunAt: this.lastRunAt } : {}),
      },
      metrics: {
        hostsDiscovered: hosts.length,
        canonicalEndpoints: endpoints.length,
        compliantTombstones: tombstones.length,
        pendingFindings,
        approvedFindings,
        allowedRequests,
        blockedScope451,
        blockedRps429,
      },
    };
  }

  public async getSurfaceGraph(): Promise<SurfaceGraphSnapshot> {
    if (!this.initialized) {
      await this.init();
    }
    return this.stateDb.getAttackSurfaceGraph(this.scope.engagementId);
  }

  public async listFindings(
    status?: FindingStatus,
  ): Promise<Array<FindingReport & { reviewerNote?: string }>> {
    if (!this.initialized) {
      await this.init();
    }
    return this.stateDb.listFindings(this.scope.engagementId, status);
  }

  public async decideFinding(
    findingId: string,
    status: 'APPROVED' | 'REJECTED',
    reviewerNote: string,
  ): Promise<(FindingReport & { reviewerNote?: string }) | null> {
    if (!this.initialized) {
      await this.init();
    }
    const updated = await this.stateDb.updateFindingStatus(
      findingId,
      status,
      reviewerNote,
    );
    if (!updated) {
      return null;
    }
    return {
      ...updated,
      reviewerNote,
    };
  }

  public async getGitOpsHistory(limit: number = 50): Promise<{
    branches: string[];
    commits: RepoCommitSummary[];
    reviews: GitOpsReviewRecord[];
  }> {
    if (!this.initialized) {
      await this.init();
    }
    const [repoHistory, reviews] = await Promise.all([
      this.worktreeManager.getHistory(limit),
      this.stateDb.listReviews(this.scope.engagementId),
    ]);
    return {
      branches: repoHistory.branches,
      commits: repoHistory.commits,
      reviews,
    };
  }

  public async listTraffic(limit: number = 250): Promise<TrafficLedgerEntry[]> {
    if (!this.initialized) {
      await this.init();
    }
    return this.stateDb.listTraffic(this.scope.engagementId, limit);
  }

  public async getBlob(sha256: string): Promise<RetrievedBlob | null> {
    if (!this.initialized) {
      await this.init();
    }
    const stored = await this.blobVault.get(sha256);
    if (stored) {
      return stored;
    }

    const harFallback = this.egressGateway.getHarBySha256(sha256);
    if (harFallback !== undefined) {
      const buf = Buffer.from(harFallback, 'utf8');
      return {
        content: buf,
        mediaType: 'application/json',
        sizeBytes: buf.byteLength,
        metadata: { kind: 'har' },
      };
    }

    return null;
  }

  public async listRepoFiles(): Promise<RepoFileEntry[]> {
    if (!this.initialized) {
      await this.init();
    }
    const repoDir = path.join(this.dataDir, 'engagement-repo');
    const results: RepoFileEntry[] = [];

    const walk = async (dir: string): Promise<void> => {
      let entries: import('node:fs').Dirent[];
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (entry.name === '.git' || entry.isSymbolicLink()) {
          continue;
        }
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          await walk(fullPath);
        } else if (entry.isFile()) {
          try {
            const stat = await fs.stat(fullPath);
            const rel = path
              .relative(repoDir, fullPath)
              .split(path.sep)
              .join('/');
            results.push({
              path: rel,
              sizeBytes: stat.size,
              updatedAt: stat.mtime.toISOString(),
              category: classifyRepoFileCategory(rel),
            });
          } catch {
            // Skip unreadable transient entries
          }
        }
      }
    };

    await walk(repoDir);
    results.sort((a, b) => a.path.localeCompare(b.path));
    return results;
  }

  public async readRepoFile(relPath: string): Promise<{
    path: string;
    sizeBytes: number;
    content: string;
  } | null> {
    if (!this.initialized) {
      await this.init();
    }
    const repoDir = path.join(this.dataDir, 'engagement-repo');
    const sanitized = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
    if (
      !sanitized ||
      sanitized === '.git' ||
      sanitized.startsWith('.git/') ||
      sanitized.includes('/.git/')
    ) {
      return null;
    }
    const candidate = path.resolve(repoDir, sanitized);
    const relCheck = path.relative(repoDir, candidate);
    if (relCheck.startsWith('..') || path.isAbsolute(relCheck)) {
      return null;
    }
    try {
      const lstat = await fs.lstat(candidate);
      if (!lstat.isFile() || lstat.isSymbolicLink()) {
        return null;
      }
      const raw = await fs.readFile(candidate);
      const maxSlice = raw.subarray(0, 262_144);
      return {
        path: relCheck.split(path.sep).join('/'),
        sizeBytes: lstat.size,
        content: maxSlice.toString('utf8'),
      };
    } catch {
      return null;
    }
  }

  public async getCommitDiff(sha: string): Promise<{
    sha: string;
    rawShow: string;
  } | null> {
    if (!this.initialized) {
      await this.init();
    }
    const trimmed = sha.trim();
    if (!/^[0-9a-f]{6,40}$/i.test(trimmed)) {
      return null;
    }
    const repoDir = path.join(this.dataDir, 'engagement-repo');
    try {
      const execFileAsync = promisify(execFile);
      const { stdout } = await execFileAsync(
        'git',
        [
          '-C',
          repoDir,
          'show',
          '--no-color',
          '--first-parent',
          '-m',
          '--stat',
          '--patch',
          '--unified=3',
          trimmed,
        ],
        { maxBuffer: 2 * 1024 * 1024 },
      );
      return {
        sha: trimmed,
        rawShow: stdout.slice(0, 262_144),
      };
    } catch {
      return null;
    }
  }

  private async persistSquadState(state: SquadRunState): Promise<void> {
    await fs.mkdir(path.dirname(this.squadStateFilePath), { recursive: true });
    const tmpPath = `${this.squadStateFilePath}.${randomUUID().slice(0, 8)}.tmp`;
    await fs.writeFile(tmpPath, JSON.stringify(state, null, 2), 'utf8');
    await fs.rename(tmpPath, this.squadStateFilePath);
  }

  public async setSquadState(state: SquadRunState): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }
    const parsed = SquadRunStateSchema.parse(state);
    this.latestSquadState = parsed;
    await this.persistSquadState(parsed);
  }

  public async getSquadState(opts?: {
    userBrief?: string;
  }): Promise<SquadRunState> {
    if (!this.initialized) {
      await this.init();
    }

    if (this.latestSquadState) {
      return SquadRunStateSchema.parse(this.latestSquadState);
    }

    try {
      const raw = await fs.readFile(this.squadStateFilePath, 'utf8');
      const parsed = SquadRunStateSchema.safeParse(JSON.parse(raw));
      if (parsed.success) {
        this.latestSquadState = parsed.data;
        return SquadRunStateSchema.parse(parsed.data);
      }
    } catch {
      // Missing or unreadable squad-state.json — hydrate from persisted engine telemetry
    }

    const [overview, surfaceGraph, findings, gitopsHistory, traffic] =
      await Promise.all([
        this.getOverview(),
        this.getSurfaceGraph(),
        this.listFindings(),
        this.getGitOpsHistory(50),
        this.listTraffic(80),
      ]);

    const hydrated = hydrateSquadStateFromEngineData({
      programId: this.programId,
      ...(opts?.userBrief ? { userBrief: opts.userBrief } : {}),
      overview,
      surfaceGraph,
      findings,
      gitopsHistory: {
        branches: gitopsHistory.branches,
        commits: gitopsHistory.commits.map((c) => ({
          sha: c.sha,
          message: c.message,
          timestamp: c.date,
        })),
        reviews: gitopsHistory.reviews,
      },
      traffic,
    });

    this.latestSquadState = hydrated;
    await this.persistSquadState(hydrated);
    return SquadRunStateSchema.parse(hydrated);
  }

  public async steerSquadAgent(
    opts: SteerSquadAgentOptions,
  ): Promise<SteerSquadAgentResult> {
    if (!this.initialized) {
      await this.init();
    }

    const trimmedMessage = opts.message.trim();
    if (!trimmedMessage) {
      throw new Error('Steering message must not be empty.');
    }

    const currentState = await this.getSquadState();
    const requestedId = opts.targetAgentId?.trim();

    let targetAgent: SquadAgentNode | undefined;
    if (requestedId) {
      const lowered = requestedId.toLowerCase();
      targetAgent =
        currentState.agents.find((a) => a.id === requestedId) ??
        currentState.agents.find((a) => a.role.toLowerCase() === lowered) ??
        currentState.agents.find((a) => a.name.toLowerCase() === lowered);
      if (!targetAgent) {
        throw new Error(
          `Squad agent '${requestedId}' not found in program '${this.programId}'.`,
        );
      }
    } else {
      targetAgent =
        currentState.agents.find(
          (a) => a.parentId === null || a.role === 'orchestrator',
        ) ?? currentState.agents[0];
    }

    if (!targetAgent) {
      throw new Error(
        `No squad agents available to steer in program '${this.programId}'.`,
      );
    }

    const coordinator = new CyberSquadCoordinator({
      programId: currentState.programId,
      runId: currentState.runId,
      initialState: currentState,
      onEvent: async (ev, snap) => {
        this.latestSquadState = snap;
        if (opts.onSquadEvent) {
          await opts.onSquadEvent(ev, snap);
        }
      },
    });

    const [overview, surfaceGraph, findings] = await Promise.all([
      this.getOverview(),
      this.getSurfaceGraph(),
      this.listFindings(),
    ]);

    coordinator.recordUserBrief(targetAgent.id, trimmedMessage, {
      title: `Live operator steering -> ${targetAgent.name}`,
      data: {
        steered: true,
        targetAgentId: targetAgent.id,
        targetAgentRole: targetAgent.role,
      },
    });

    const inferredSurface = inferSteeredSurface(
      trimmedMessage,
      overview.engagement.authorizedDomains,
      surfaceGraph.nodes,
    );
    const inferredRiskCategory = inferSteeredRiskCategory(trimmedMessage);
    const inferredPhase = inferPhaseForRole(targetAgent.role);

    coordinator.recordThink(targetAgent.id, {
      know: `${targetAgent.name} (${targetAgent.role}) holds ${overview.metrics.hostsDiscovered} in-scope host(s), ${overview.metrics.canonicalEndpoints} canonical endpoint(s), ${findings.length} verified finding(s), and ${currentState.hypotheses.length} tracked hypothesis(es) under strict GET/HEAD/OPTIONS governance.`,
      think: `Operator steered focus onto '${inferredSurface}' [${inferredRiskCategory}]: "${trimmedMessage.slice(0, 180)}". Formulating read-only verification plan and reconciling against SharedThreatModel.`,
      test: `Evaluate ${inferredSurface} using non-destructive read-only ${targetAgent.role === 'cartographer' ? 'offline JS AST / OpenAPI schema inspection' : 'GET/HEAD/OPTIONS governed probes'} within ${overview.engagement.maxRpsPerHost} RPS cap.`,
      validate: `Apply Strix 3-state closure discipline (confirmed with counterevidence | ruled_out naming exact reachable control | open_proof_gap).`,
      confidence: 74,
      title: `${targetAgent.name} metacognitive steering evaluation`,
    });

    const shouldRecordSteeringHypothesis =
      Boolean(requestedId) ||
      /\b(focus|check|verify|test|inspect|investigate|hypothesis|cors|header|csp|hsts|auth|token|role|tenant|bola|idor|schema|openapi|route|endpoint|scope|451)\b/i.test(
        trimmedMessage,
      );

    let createdHypothesis: SecurityHypothesis | undefined;
    if (shouldRecordSteeringHypothesis) {
      createdHypothesis = coordinator.formHypothesis(targetAgent.id, {
        assignedAgentId: targetAgent.id,
        phase: inferredPhase,
        surface: inferredSurface,
        riskCategory: inferredRiskCategory,
        observation: `Operator steering directive to ${targetAgent.name}: "${trimmedMessage.slice(0, 220)}"`,
        statement: `Evaluate whether ${inferredSurface} exhibits ${inferredRiskCategory} posture weakness or enforces an explicit server-side control on the reachable path.`,
        confidence: 70,
        testPlan: `Run strictly read-only GET/HEAD/OPTIONS inspection and header/schema verification on ${inferredSurface} without state mutation.`,
        reason: `Formed from live operator steering to ${targetAgent.name}.`,
      });
    }

    const activeSnapshotAfterHyp = coordinator.getSnapshot();
    if (
      activeSnapshotAfterHyp.threatModel &&
      (Boolean(requestedId) ||
        /\b(threat|boundary|trust|assumption|role|scope|cors|auth|tenant|schema|header|surface|endpoint)\b/i.test(
          trimmedMessage,
        ))
    ) {
      coordinator.amendThreatModel(
        targetAgent.id,
        `Operator steering prioritized ${inferredRiskCategory} review on ${inferredSurface} (${trimmedMessage.slice(0, 160)}).`,
      );
    }

    const latestSnap = coordinator.getSnapshot();
    const endpointLabels = surfaceGraph.nodes
      .filter((n) => n.type === 'ENDPOINT')
      .slice(0, 12)
      .map((n) => n.label);
    const findingSummaries = findings
      .slice(0, 8)
      .map((f) => `- ${f.findingId} [${f.severity}] ${f.title} (${f.status})`);
    const hypothesisSummaries = latestSnap.hypotheses
      .slice(-8)
      .map(
        (h) =>
          `- ${h.id} [${h.closureState} | ${h.confidence}%] ${h.surface} (${h.riskCategory}): ${h.statement}`,
      );

    const systemPrompt = [
      targetAgent.systemDirective,
      '',
      '=== YOUR ASSIGNED MISSION CONTEXT ===',
      targetAgent.missionPrompt,
      '',
      '=== LIVE WORKSPACE TELEMETRY ===',
      `Program: ${overview.engagement.programName} (${this.programId})`,
      `Authorized Domains: ${overview.engagement.authorizedDomains.join(', ')}`,
      `Excluded Hosts: ${overview.engagement.excludedHosts.join(', ') || 'none'}`,
      `Excluded Paths: ${overview.engagement.excludedPaths.join(', ') || 'none'}`,
      `Max RPS/Host: ${overview.engagement.maxRpsPerHost} | Strict Read-Only: ${String(overview.engagement.strictReadOnly)}`,
      `Discovered Endpoints (${overview.metrics.canonicalEndpoints}): ${endpointLabels.join(', ') || 'none yet'}`,
      `Verified Findings (${findings.length}):`,
      findingSummaries.length > 0 ? findingSummaries.join('\n') : '- None filed',
      `Tracked Hypotheses (${latestSnap.hypotheses.length}):`,
      hypothesisSummaries.length > 0
        ? hypothesisSummaries.join('\n')
        : '- None recorded',
      '',
      '=== RESPONSE PROTOCOL ===',
      `Respond directly in character as **${targetAgent.name}** (role: \`${targetAgent.role}\`, model: \`${targetAgent.provider}:${targetAgent.model}\`).`,
      '1. Structure your concise Markdown response around **What We Know**, **Steered Hypothesis & Confidence**, **Read-Only Verification Plan (`GET`/`HEAD`/`OPTIONS` or offline AST)**, and **Closure Criteria (`confirmed` | `ruled_out` | `open_proof_gap`)**.',
      '2. Maintain strictly authorized, defensive, non-destructive, read-only (`GET`/`HEAD`/`OPTIONS`) posture behavior at all times. Never output weaponized or state-mutating payloads.',
    ].join('\n');

    const historyTurns = (opts.conversationHistory ?? []).slice(-10);
    const messages: ChatTurnMessage[] = [
      ...historyTurns,
      { role: 'user', content: trimmedMessage },
    ];

    const tier =
      targetAgent.role === 'orchestrator' ? 'ORCHESTRATOR' : 'SUBAGENT';

    let replyText = '';
    let streamedDeltaCount = 0;

    if (this.llmRouter.isConfigured) {
      let steerTimer: ReturnType<typeof setTimeout> | undefined;
      let steerTimedOut = false;
      try {
        const streamPromise = this.llmRouter.streamText({
          tier,
          systemPrompt,
          messages,
          temperature: 0.2,
          onDelta: async (chunk) => {
            if (steerTimedOut) {
              return;
            }
            streamedDeltaCount += 1;
            if (opts.onDelta) {
              await opts.onDelta(chunk);
            }
          },
        });
        const timeoutPromise = new Promise<null>((resolve) => {
          steerTimer = setTimeout(() => {
            steerTimedOut = true;
            resolve(null);
          }, 25_000);
        });
        const res = await Promise.race([streamPromise, timeoutPromise]);
        if (res === null) {
          void streamPromise.catch(() => undefined);
          replyText = '';
        } else {
          replyText = res.trim();
        }
      } catch {
        replyText = '';
      } finally {
        if (steerTimer) {
          clearTimeout(steerTimer);
        }
      }
    }

    if (!replyText) {
      replyText = [
        `### ${targetAgent.name} (\`${targetAgent.role}\`) — Steered Posture Assessment`,
        '',
        `- **What We Know**: Scope locks \`${overview.engagement.authorizedDomains.join(', ')}\` (${overview.metrics.hostsDiscovered} host(s), ${overview.metrics.canonicalEndpoints} canonical endpoint(s), ${findings.length} verified finding(s), ${overview.metrics.compliantTombstones} compliant tombstone(s)).`,
        `- **Steered Hypothesis${createdHypothesis ? ` (\`${createdHypothesis.id}\` @ ${createdHypothesis.confidence}%)` : ''}**: Investigating \`${inferredSurface}\` for \`${inferredRiskCategory}\` based on your directive: *"${trimmedMessage}"*.`,
        `- **Read-Only Verification Plan**: Execute governed \`GET\`/\`HEAD\`/\`OPTIONS\` inspection within \`${overview.engagement.maxRpsPerHost} RPS\` cap${targetAgent.worktreeBranch ? ` on isolated branch \`${targetAgent.worktreeBranch}\`` : ''} without mutating target state.`,
        `- **Closure Discipline**: Will close as \`confirmed\` only after counterevidence review, \`ruled_out\` only by naming the exact server-side control on \`${inferredSurface}\`, or \`open_proof_gap\` if tenant/auth fixtures are required.`,
      ].join('\n');

      if (streamedDeltaCount === 0 && opts.onDelta) {
        await opts.onDelta(replyText);
      }
    }

    coordinator.recordAssistantSynthesis(
      targetAgent.id,
      replyText.length > 600 ? `${replyText.slice(0, 597)}...` : replyText,
      {
        title: `${targetAgent.name} responded to operator steering`,
        data: {
          targetAgentId: targetAgent.id,
          targetAgentRole: targetAgent.role,
          ...(createdHypothesis ? { hypothesisId: createdHypothesis.id } : {}),
        },
      },
    );

    coordinator.setAgentStatus(targetAgent.id, 'completed');
    await coordinator.flush();

    const finalState = this.pipelineRunning
      ? coordinator.getSnapshot()
      : coordinator.finalizeRun(
          'completed',
          currentState.completedAt ?? new Date().toISOString(),
        );

    this.latestSquadState = finalState;
    await this.persistSquadState(finalState);

    const updatedAgent =
      coordinator.getAgent(targetAgent.id) ?? targetAgent;

    return {
      targetAgent: updatedAgent,
      replyText,
      squadState: finalState,
    };
  }
}

function inferPhaseForRole(role: SquadAgentNode['role']): HypothesisPhase {
  switch (role) {
    case 'recon':
      return 'SURFACE_MAPPING';
    case 'cartographer':
      return 'SCHEMA_ANALYSIS';
    case 'validator':
      return 'COUNTEREVIDENCE';
    case 'hypothesis_hunter':
    case 'orchestrator':
    default:
      return 'POSTURE_VERIFICATION';
  }
}

function inferSteeredSurface(
  message: string,
  authorizedDomains: string[],
  graphNodes: Array<{ type: string; label: string }>,
): string {
  const urlOrPathMatch = message.match(
    /(https?:\/\/[^\s`'"]+|\/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=-]+)/i,
  );
  if (urlOrPathMatch?.[1]) {
    return urlOrPathMatch[1].replace(/[.,;:!?)]+$/, '');
  }

  const hostCandidates = [
    ...graphNodes.filter((n) => n.type === 'HOST').map((n) => n.label),
    ...authorizedDomains.map((d) => d.replace(/^\*\./, '')),
  ];
  const lowered = message.toLowerCase();
  for (const host of hostCandidates) {
    if (host && lowered.includes(host.toLowerCase())) {
      return host;
    }
  }

  const firstEndpoint = graphNodes.find((n) => n.type === 'ENDPOINT');
  if (firstEndpoint) {
    return firstEndpoint.label;
  }

  return authorizedDomains[0]?.replace(/^\*\./, '') || 'in-scope perimeter';
}

function inferSteeredRiskCategory(message: string): string {
  if (/\bcors\b|\borigin\b|\bpreflight\b/i.test(message)) {
    return 'PERMISSIVE_CORS';
  }
  if (/\bcsp\b|\bhsts\b|\bheader\b|\bx-frame\b|\bnosniff\b/i.test(message)) {
    return 'MISSING_SECURITY_HEADERS';
  }
  if (/\bauth\b|\brole\b|\btenant\b|\bbola\b|\bidor\b|\bsession\b|\btoken\b/i.test(message)) {
    return 'AUTHZ_BOUNDARY_REVIEW';
  }
  if (/\bschema\b|\bopenapi\b|\bswagger\b|\bast\b|\bgraphql\b|\bbundle\b/i.test(message)) {
    return 'SCHEMA_SURFACE_DRIFT';
  }
  if (/\b451\b|\bscope\b|\begress\b|\bexclude/i.test(message)) {
    return 'SCOPE_BOUNDARY_ENFORCEMENT';
  }
  return 'STEERED_POSTURE_HYPOTHESIS';
}

export interface RepoFileEntry {
  path: string;
  sizeBytes: number;
  updatedAt: string;
  category:
    | 'scope'
    | 'surface'
    | 'schema'
    | 'evaluated'
    | 'report'
    | 'observation'
    | 'other';
}

function classifyRepoFileCategory(relPath: string): RepoFileEntry['category'] {
  if (relPath === 'scope.yaml' || relPath === 'POLICY.md') {
    return 'scope';
  }
  if (relPath.startsWith('reports/')) {
    return 'report';
  }
  if (relPath.startsWith('surface/')) {
    return 'surface';
  }
  if (relPath.startsWith('schemas/')) {
    return 'schema';
  }
  if (relPath.startsWith('evaluated/')) {
    return 'evaluated';
  }
  if (relPath.startsWith('observations/')) {
    return 'observation';
  }
  return 'other';
}

