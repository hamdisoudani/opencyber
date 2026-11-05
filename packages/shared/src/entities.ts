import { z } from 'zod';
import { HttpMethodSchema } from './canonicalize.js';

export const SeveritySchema = z.enum([
  'INFO',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
]);
export type Severity = z.infer<typeof SeveritySchema>;

export const FindingCategorySchema = z.enum([
  'MISSING_SECURITY_HEADERS',
  'PERMISSIVE_CORS',
  'AUTHZ_SCHEMA_DRIFT',
  'EXPOSED_DEBUG_SURFACE',
  'TLS_OR_COOKIE_POSTURE',
]);
export type FindingCategory = z.infer<typeof FindingCategorySchema>;

export const HostEntitySchema = z.object({
  hostname: z.string().min(1),
  discoveredAt: z.string(),
  sources: z.array(z.string()).default([]),
  statusCode: z.number().int().optional(),
  serverHeader: z.string().optional(),
  securityHeaders: z.record(z.string(), z.string()).default({}),
  fingerprints: z.array(z.string()).default([]),
});
export type HostEntity = z.infer<typeof HostEntitySchema>;

export const CanonicalEndpointSchema = z.object({
  endpointId: z.string().min(1),
  host: z.string().min(1),
  method: HttpMethodSchema,
  canonicalPath: z.string().min(1),
  observedRawPaths: z.array(z.string()).default([]),
  sources: z.array(z.string()).default([]),
  authRequired: z.boolean().optional(),
  parameters: z.array(z.string()).default([]),
  responseContentTypes: z.array(z.string()).default([]),
  firstSeenAt: z.string(),
  lastUpdatedAt: z.string(),
});
export type CanonicalEndpoint = z.infer<typeof CanonicalEndpointSchema>;

export const ObservedEndpointItemSchema = z.object({
  host: z.string().min(1),
  method: HttpMethodSchema,
  rawPath: z.string().min(1),
  source: z.string().min(1),
  parameters: z.array(z.string()).default([]),
  authRequired: z.boolean().optional(),
  responseContentType: z.string().optional(),
});
export type ObservedEndpointItem = z.infer<typeof ObservedEndpointItemSchema>;

export const RouteObservationBatchSchema = z.object({
  runId: z.string().min(1),
  agentRole: z.enum(['RECON', 'STATIC_JS_AST', 'OPENAPI_PARSER']),
  createdAt: z.string(),
  bundleSha256: z.string().optional(),
  hosts: z.array(HostEntitySchema).default([]),
  endpoints: z.array(ObservedEndpointItemSchema).default([]),
});
export type RouteObservationBatch = z.infer<typeof RouteObservationBatchSchema>;

export const TrafficEvidencePointerSchema = z.object({
  sha256: z.string().min(16),
  blobPath: z.string().min(1),
  requestUrl: z.string().min(1),
  method: z.string().min(1),
  statusCode: z.number().int(),
  capturedAt: z.string(),
  authProfileUsed: z.string().optional(),
});
export type TrafficEvidencePointer = z.infer<
  typeof TrafficEvidencePointerSchema
>;

export const FindingStatusSchema = z.enum([
  'DRAFT',
  'PENDING_HUMAN_REVIEW',
  'APPROVED',
  'REJECTED',
]);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

export const FindingReportSchema = z.object({
  findingId: z.string().regex(/^AUD-\d{3,}-[a-z0-9-]+$/),
  title: z.string().min(3),
  category: FindingCategorySchema,
  severity: SeveritySchema,
  host: z.string().min(1),
  endpointId: z.string().min(1),
  summary: z.string().min(10),
  architecturalAnalysis: z.string().min(10),
  remediation: z.string().min(10),
  reproducibleCheckFile: z.string().optional(),
  evidencePointers: z.array(TrafficEvidencePointerSchema).default([]),
  status: FindingStatusSchema.default('PENDING_HUMAN_REVIEW'),
  createdAt: z.string(),
});
export type FindingReport = z.infer<typeof FindingReportSchema>;

export const AuditTombstoneSchema = z.object({
  endpointId: z.string().min(1),
  host: z.string().min(1),
  method: HttpMethodSchema,
  canonicalPath: z.string().min(1),
  evaluatedAt: z.string(),
  evaluatedByTask: z.string().min(1),
  status: z.enum(['COMPLIANT', 'FALSE_HYPOTHESIS']),
  notes: z.string().default(''),
});
export type AuditTombstone = z.infer<typeof AuditTombstoneSchema>;

export const OrchestratorReviewVerdictSchema = z.object({
  decision: z.enum(['APPROVE_MERGE', 'REJECT_COMPLIANT', 'REQUEST_RETRY']),
  confidence: z.number().min(0).max(1),
  rationale: z.string().min(1),
  sanitizedFindingSummary: z.string().optional(),
});
export type OrchestratorReviewVerdict = z.infer<
  typeof OrchestratorReviewVerdictSchema
>;

export const TrafficDecisionSchema = z.enum([
  'ALLOWED',
  'BLOCKED_SCOPE_451',
  'BLOCKED_METHOD_405',
  'BLOCKED_AUTH_403',
  'BLOCKED_RPS_429',
]);
export type TrafficDecision = z.infer<typeof TrafficDecisionSchema>;

export const TrafficLedgerEntrySchema = z.object({
  id: z.string().min(1),
  timestamp: z.string(),
  engagementId: z.string().min(1),
  taskId: z.string().min(1),
  fencingToken: z.number().int().nonnegative(),
  method: z.string().min(1),
  url: z.string().min(1),
  host: z.string().min(1),
  pathname: z.string().min(1),
  authProfile: z.string().optional(),
  decision: TrafficDecisionSchema,
  upstreamStatus: z.number().int().optional(),
  durationMs: z.number().nonnegative(),
  harBlobSha256: z.string().optional(),
});
export type TrafficLedgerEntry = z.infer<typeof TrafficLedgerEntrySchema>;
