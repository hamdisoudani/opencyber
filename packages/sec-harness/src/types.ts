import { z } from 'zod';

export type SquadAgentRole =
  | 'orchestrator'
  | 'recon'
  | 'cartographer'
  | 'hypothesis_hunter'
  | 'validator';

export const SquadAgentRoleSchema = z.enum([
  'orchestrator',
  'recon',
  'cartographer',
  'hypothesis_hunter',
  'validator',
]);

export type SquadAgentStatus =
  | 'running'
  | 'waiting'
  | 'completed'
  | 'stopped'
  | 'failed';

export const SquadAgentStatusSchema = z.enum([
  'running',
  'waiting',
  'completed',
  'stopped',
  'failed',
]);

export interface SquadAgentCompletionReport {
  success: boolean;
  summary: string;
  findings: string[];
  openItems: string[];
  recommendations: string[];
  completedAt: string;
}

export const SquadAgentCompletionReportSchema: z.ZodType<SquadAgentCompletionReport> =
  z.object({
    success: z.boolean(),
    summary: z.string(),
    findings: z.array(z.string()),
    openItems: z.array(z.string()),
    recommendations: z.array(z.string()),
    completedAt: z.string(),
  });

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
}

export const SquadAgentNodeSchema: z.ZodType<SquadAgentNode> = z
  .object({
    id: z.string().min(1),
    parentId: z.string().nullable(),
    name: z.string().min(1),
    role: SquadAgentRoleSchema,
    model: z.string().min(1),
    provider: z.string().min(1),
    skills: z.array(z.string()),
    status: SquadAgentStatusSchema,
    task: z.string(),
    missionPrompt: z.string(),
    systemDirective: z.string(),
    worktreeBranch: z.string().optional(),
    toolCallCount: z.number().int().nonnegative(),
    messageCount: z.number().int().nonnegative(),
    createdAt: z.string(),
    updatedAt: z.string(),
    completionReport: SquadAgentCompletionReportSchema.optional(),
  })
  .transform((val) => {
    const { worktreeBranch, completionReport, ...rest } = val;
    return {
      ...rest,
      ...(worktreeBranch !== undefined ? { worktreeBranch } : {}),
      ...(completionReport !== undefined ? { completionReport } : {}),
    };
  });

export type HypothesisClosureState =
  | 'open'
  | 'testing'
  | 'confirmed'
  | 'ruled_out'
  | 'open_proof_gap';

export const HypothesisClosureStateSchema = z.enum([
  'open',
  'testing',
  'confirmed',
  'ruled_out',
  'open_proof_gap',
]);

export type HypothesisPhase =
  | 'INITIAL_GATHERING'
  | 'SURFACE_MAPPING'
  | 'SCHEMA_ANALYSIS'
  | 'POSTURE_VERIFICATION'
  | 'COUNTEREVIDENCE';

export const HypothesisPhaseSchema = z.enum([
  'INITIAL_GATHERING',
  'SURFACE_MAPPING',
  'SCHEMA_ANALYSIS',
  'POSTURE_VERIFICATION',
  'COUNTEREVIDENCE',
]);

export interface HypothesisConfidencePoint {
  timestamp: string;
  confidence: number;
  delta: number;
  reason: string;
  agentName: string;
}

export const HypothesisConfidencePointSchema: z.ZodType<HypothesisConfidencePoint> =
  z.object({
    timestamp: z.string(),
    confidence: z.number().min(0).max(100),
    delta: z.number(),
    reason: z.string(),
    agentName: z.string(),
  });

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

export const SecurityHypothesisSchema: z.ZodType<SecurityHypothesis> = z
  .object({
    id: z.string().min(1),
    createdByAgentId: z.string().min(1),
    assignedAgentId: z.string().optional(),
    phase: HypothesisPhaseSchema,
    surface: z.string().min(1),
    riskCategory: z.string().min(1),
    observation: z.string(),
    statement: z.string().min(1),
    confidence: z.number().min(0).max(100),
    confidenceHistory: z.array(HypothesisConfidencePointSchema),
    testPlan: z.string(),
    closureState: HypothesisClosureStateSchema,
    namedControlOrProof: z.string(),
    counterevidence: z.string(),
    linkedFindingId: z.string().optional(),
    createdAt: z.string(),
    updatedAt: z.string(),
  })
  .transform((val) => {
    const { assignedAgentId, linkedFindingId, ...rest } = val;
    return {
      ...rest,
      ...(assignedAgentId !== undefined ? { assignedAgentId } : {}),
      ...(linkedFindingId !== undefined ? { linkedFindingId } : {}),
    };
  });

export interface ThreatModelAmendment {
  id: string;
  agentId: string;
  agentName: string;
  addendum: string;
  recordedAt: string;
}

export const ThreatModelAmendmentSchema: z.ZodType<ThreatModelAmendment> =
  z.object({
    id: z.string().min(1),
    agentId: z.string().min(1),
    agentName: z.string().min(1),
    addendum: z.string().min(1),
    recordedAt: z.string(),
  });

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

export const SharedThreatModelSchema: z.ZodType<SharedThreatModel> = z.object({
  target: z.string().min(1),
  summary: z.string().min(1),
  trustBoundaries: z.array(z.string()),
  attackerRoles: z.array(z.string()),
  highValueAssets: z.array(z.string()),
  inferredAssumptions: z.array(z.string()),
  amendments: z.array(ThreatModelAmendmentSchema),
  updatedAt: z.string(),
});

export type CoverageOutcome =
  | 'reported'
  | 'ruled_out'
  | 'no_issue_found'
  | 'needs_follow_up'
  | 'blocked_451';

export const CoverageOutcomeSchema = z.enum([
  'reported',
  'ruled_out',
  'no_issue_found',
  'needs_follow_up',
  'blocked_451',
]);

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

export const SurfaceCoverageEntrySchema: z.ZodType<SurfaceCoverageEntry> =
  z.object({
    id: z.string().min(1),
    surface: z.string().min(1),
    riskArea: z.string().min(1),
    outcome: CoverageOutcomeSchema,
    previousOutcomes: z.array(CoverageOutcomeSchema),
    evidence: z.string(),
    agentId: z.string().min(1),
    agentName: z.string().min(1),
    updatedAt: z.string(),
  });

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
  | 'assistant_synthesis';

export const SquadTimelineEventKindSchema = z.enum([
  'user_brief',
  'think',
  'threat_model',
  'hypothesis',
  'spawn_agent',
  'agent_message',
  'recon_step',
  'coverage',
  'verification',
  'assistant_synthesis',
]);

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

export const SquadTimelineEventSchema: z.ZodType<SquadTimelineEvent> = z
  .object({
    seq: z.number().int().positive(),
    id: z.string().min(1),
    timestamp: z.string(),
    agentId: z.string().min(1),
    agentName: z.string().min(1),
    agentRole: SquadAgentRoleSchema,
    kind: SquadTimelineEventKindSchema,
    title: z.string(),
    detail: z.string(),
    status: z.enum(['running', 'completed', 'failed']),
    data: z.record(z.string(), z.unknown()).optional(),
  })
  .transform((val) => {
    const { data, ...rest } = val;
    return {
      ...rest,
      ...(data !== undefined ? { data } : {}),
    };
  });

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

export const SquadRunStateSchema: z.ZodType<SquadRunState> = z
  .object({
    programId: z.string().min(1),
    runId: z.string().min(1),
    status: z.enum(['idle', 'running', 'completed', 'error']),
    startedAt: z.string(),
    completedAt: z.string().optional(),
    agents: z.array(SquadAgentNodeSchema),
    hypotheses: z.array(SecurityHypothesisSchema),
    threatModel: SharedThreatModelSchema.nullable(),
    coverage: z.array(SurfaceCoverageEntrySchema),
    timeline: z.array(SquadTimelineEventSchema),
  })
  .transform((val) => {
    const { completedAt, ...rest } = val;
    return {
      ...rest,
      ...(completedAt !== undefined ? { completedAt } : {}),
    };
  });
