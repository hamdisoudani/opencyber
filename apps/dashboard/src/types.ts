export interface ProgramSummaryItem {
  programId: string;
  programName: string;
  authorizedDomains: string[];
  excludedHosts: string[];
  excludedPaths: string[];
  maxRpsPerHost: number;
  pipelineRunning: boolean;
  pendingFindings: number;
  approvedFindings: number;
  canonicalEndpoints: number;
  hostsDiscovered: number;
  createdAt: string;
  updatedAt: string;
}

export interface ProgramsResponse {
  programs: ProgramSummaryItem[];
}

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
  stage: ProgramLogStage | (string & {});
  agent: string;
  message: string;
}

export interface ProgramLogsResponse {
  logs: ProgramLogEntry[];
}

export interface ChatMessageItem {
  id: string;
  programId: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: string;
  status?: 'streaming' | 'completed' | 'error';
  logs?: ProgramLogEntry[];
}

export interface ChatMessagesResponse {
  messages: ChatMessageItem[];
}

export interface ChatStreamRequest {
  programId?: string;
  targetAgentId?: string;
  message: string;
  useCloudSandbox: boolean;
}

export interface SseProgramSelectedEvent {
  programId: string;
  programName: string;
  isNew: boolean;
  assistantMessageId: string;
}

export interface SseScopeUpdatedEvent {
  programId: string;
  programName: string;
  authorizedDomains: string[];
  excludedHosts: string[];
  excludedPaths: string[];
  maxRpsPerHost: number;
  complianceHeaders: Record<string, string>;
  scopeYaml: string;
}

export interface SseTelemetryRefreshEvent {
  programId: string;
  reason: string;
}

export interface SseAssistantDeltaEvent {
  programId: string;
  messageId: string;
  delta: string;
}

export interface SseDoneEvent {
  programId: string;
  messageId: string;
}

export interface SseErrorEvent {
  message: string;
}

export interface SseSquadEventPayload {
  programId: string;
  event: SquadTimelineEvent;
  squadState?: SquadRunState;
}

export interface ContinuousMonitoringStatus {
  enabled: boolean;
  intervalSeconds: number;
  completedWaves: number;
  lastWaveAt?: string;
  nextWaveAt?: string;
  totalCompactions?: number;
}

export interface OverviewResponse {
  engagement: {
    engagementId: string;
    programName: string;
    authorizedDomains: string[];
    excludedHosts?: string[];
    excludedPaths: string[];
    maxRpsPerHost: number;
    strictReadOnly: boolean;
    complianceHeaders?: Record<string, string>;
  };
  runtime: {
    sandboxProvider: 'e2b' | 'local';
    orchestratorProvider?: 'openrouter' | 'groq' | string;
    orchestratorModel: string;
    subagentProvider?: 'groq' | 'openrouter' | string;
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
  scopeYaml?: string;
  continuousMonitoring?: ContinuousMonitoringStatus;
}

export interface RunAssessmentRequest {
  useCloudSandbox?: boolean;
}

export interface RunAssessmentResponse {
  started: boolean;
  runId: string;
}

export type SurfaceNodeType =
  | 'PROGRAM'
  | 'HOST'
  | 'ENDPOINT'
  | 'FINDING'
  | 'TOMBSTONE';

export interface SurfaceGraphNode {
  id: string;
  type: SurfaceNodeType;
  label: string;
  metadata: Record<string, unknown>;
}

export interface SurfaceGraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
}

export interface SurfaceGraphResponse {
  nodes: SurfaceGraphNode[];
  edges: SurfaceGraphEdge[];
}

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type FindingCategory =
  | 'MISSING_SECURITY_HEADERS'
  | 'PERMISSIVE_CORS'
  | 'AUTHZ_SCHEMA_DRIFT'
  | 'EXPOSED_DEBUG_SURFACE'
  | 'TLS_OR_COOKIE_POSTURE'
  | (string & {});

export type FindingStatus =
  | 'DRAFT'
  | 'PENDING_HUMAN_REVIEW'
  | 'APPROVED'
  | 'REJECTED';

export interface TrafficEvidencePointer {
  sha256: string;
  blobPath: string;
  requestUrl: string;
  method: string;
  statusCode: number;
  capturedAt: string;
  authProfileUsed?: string;
}

export interface FindingItem {
  findingId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  host: string;
  endpointId: string;
  summary: string;
  architecturalAnalysis: string;
  remediation: string;
  counterevidence?: string;
  reproducibleCheckFile?: string;
  reproducibleCheckSource?: string;
  evidencePointers: TrafficEvidencePointer[];
  status: FindingStatus;
  createdAt: string;
  reviewerNote?: string;
}

export interface FindingsResponse {
  findings: FindingItem[];
}

export interface FindingDecisionPayload {
  status: 'APPROVED' | 'REJECTED';
  reviewerNote: string;
}

export interface FindingDecisionResponse {
  finding: FindingItem;
}

export interface GitOpsCommit {
  sha: string;
  date: string;
  message: string;
  author: string;
}

export interface GitOpsReview {
  id: string;
  branchName: string;
  taskId: string;
  ciPassed: boolean;
  decision: string;
  rationale: string;
  commitSha?: string;
  createdAt: string;
}

export interface GitOpsHistoryResponse {
  branches: string[];
  commits: GitOpsCommit[];
  reviews: GitOpsReview[];
}

export interface CommitDiffResponse {
  sha: string;
  rawShow: string;
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

export interface RepoFilesResponse {
  files: RepoFileEntry[];
}

export interface RepoFileContentResponse {
  path: string;
  sizeBytes: number;
  content: string;
}

export interface BlobPayloadResponse {
  sha256: string;
  mediaType: string;
  sizeBytes: number;
  metadata?: Record<string, unknown>;
  text: string;
  data?: unknown;
}

export type TrafficDecision =
  | 'ALLOWED'
  | 'BLOCKED_SCOPE_451'
  | 'BLOCKED_METHOD_405'
  | 'BLOCKED_AUTH_403'
  | 'BLOCKED_RPS_429';

export interface TrafficEntry {
  id: string;
  timestamp: string;
  engagementId?: string;
  taskId: string;
  fencingToken: number;
  method: string;
  url: string;
  host: string;
  pathname: string;
  authProfile?: string;
  decision: TrafficDecision;
  upstreamStatus?: number;
  durationMs: number;
  harBlobSha256?: string;
}

export interface TrafficResponse {
  entries: TrafficEntry[];
}

export type ConnectionState = 'live' | 'offline';

export type PrimaryWorkspaceView =
  | 'operations'
  | 'hypotheses'
  | 'recon'
  | 'findings'
  | 'gitops';

// ---------------------------------------------------------------------------
// Cyber Squad Multi-Agent Architecture & SSE Contract
// ---------------------------------------------------------------------------

export type SquadAgentRole =
  | 'orchestrator'
  | 'recon'
  | 'cartographer'
  | 'hypothesis_hunter'
  | 'validator'
  | (string & {});

export type SquadAgentStatus =
  | 'running'
  | 'waiting'
  | 'completed'
  | 'stopped'
  | 'failed';

export interface AgentContextStats {
  estimatedTokens: number;
  maxTokens: number;
  compactionCount: number;
  checkpointSummary?: string;
}

export interface ResearcherSkillPack {
  id: string;
  name: string;
  category:
    | 'RECON'
    | 'BROWSER_SPA'
    | 'BUNDLE_AST'
    | 'CROSS_ORIGIN'
    | 'SCHEMA_AUTH'
    | 'CRITIC_VRT'
    | (string & {});
  summary: string;
  recommendedTools: string[];
  methodologySteps: string[];
  falsePositiveRules: string[];
  promptAddendum?: string;
}

export interface ResearcherSkillsResponse {
  skills: ResearcherSkillPack[];
}

export interface SquadAgentCompletionReport {
  success: boolean;
  summary: string;
  findings: string[];
  openItems: string[];
  recommendations: string[];
  completedAt: string;
}

export interface SquadAgentNode {
  id: string;
  parentId: string | null;
  name: string;
  role: SquadAgentRole;
  model: string;
  provider: string;
  skills: string[];
  status: SquadAgentStatus;
  task: string;
  missionPrompt: string;
  systemDirective: string;
  worktreeBranch?: string;
  toolCallCount: number;
  messageCount: number;
  createdAt: string;
  updatedAt: string;
  completionReport?: SquadAgentCompletionReport;
  contextStats?: AgentContextStats;
  personaRationale?: string;
  allowedTools?: string[];
}

export type HypothesisClosureState =
  | 'open'
  | 'testing'
  | 'confirmed'
  | 'ruled_out'
  | 'open_proof_gap';

export interface HypothesisConfidencePoint {
  timestamp: string;
  confidence: number;
  delta: number;
  reason: string;
  agentName: string;
}

export interface SecurityHypothesis {
  id: string;
  createdByAgentId: string;
  assignedAgentId?: string;
  phase:
    | 'INITIAL_GATHERING'
    | 'SURFACE_MAPPING'
    | 'SCHEMA_ANALYSIS'
    | 'POSTURE_VERIFICATION'
    | 'COUNTEREVIDENCE';
  surface: string;
  riskCategory: string;
  observation: string;
  statement: string;
  confidence: number;
  confidenceHistory: HypothesisConfidencePoint[];
  testPlan: string;
  closureState: HypothesisClosureState;
  namedControlOrProof: string;
  counterevidence: string;
  linkedFindingId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ThreatModelAmendment {
  id: string;
  agentId: string;
  agentName: string;
  addendum: string;
  recordedAt: string;
}

export interface SharedThreatModel {
  target: string;
  summary: string;
  trustBoundaries: string[];
  attackerRoles: string[];
  highValueAssets: string[];
  inferredAssumptions: string[];
  amendments: ThreatModelAmendment[];
  updatedAt: string;
}

export type CoverageOutcome =
  | 'reported'
  | 'ruled_out'
  | 'no_issue_found'
  | 'needs_follow_up'
  | 'blocked_451';

export interface SurfaceCoverageEntry {
  id: string;
  surface: string;
  riskArea: string;
  outcome: CoverageOutcome;
  previousOutcomes: CoverageOutcome[];
  evidence: string;
  agentId: string;
  agentName: string;
  updatedAt: string;
}

export type SquadTimelineEventKind =
  | 'user_brief'
  | 'think'
  | 'threat_model'
  | 'hypothesis'
  | 'spawn_agent'
  | 'agent_message'
  | 'recon_step'
  | 'coverage'
  | 'verification'
  | 'assistant_synthesis'
  | (string & {});

export interface SquadTimelineEvent {
  seq: number;
  id: string;
  timestamp: string;
  agentId: string;
  agentName: string;
  agentRole: SquadAgentRole;
  kind: SquadTimelineEventKind;
  title: string;
  detail: string;
  status: 'running' | 'completed' | 'failed';
  data?: Record<string, unknown>;
}

export interface SquadRunState {
  programId: string;
  runId: string;
  status: 'idle' | 'running' | 'completed' | 'error';
  startedAt: string;
  completedAt?: string;
  agents: SquadAgentNode[];
  hypotheses: SecurityHypothesis[];
  threatModel: SharedThreatModel | null;
  coverage: SurfaceCoverageEntry[];
  timeline: SquadTimelineEvent[];
}
