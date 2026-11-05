import type { ScopeConfig } from '@opencyber/shared';
import type {
  SecurityHypothesis,
  SharedThreatModel,
  SquadAgentRole,
} from './types.js';

export type MissionScopeSummary = Pick<
  ScopeConfig,
  | 'engagementId'
  | 'programName'
  | 'authorizedDomains'
  | 'excludedHosts'
  | 'excludedPaths'
  | 'maxRpsPerHost'
  | 'complianceHeaders'
  | 'strictReadOnly'
>;

export type AssignedHypothesisSummary = Pick<
  SecurityHypothesis,
  'id' | 'surface' | 'riskCategory' | 'statement' | 'confidence' | 'testPlan'
>;

export interface SubagentMissionPromptOptions {
  agentName: string;
  role: SquadAgentRole;
  task: string;
  skills?: string[];
  scope?: MissionScopeSummary;
  threatModel?: SharedThreatModel | null;
  knownFacts?: string[];
  assignedHypotheses?: AssignedHypothesisSummary[];
  worktreeBranch?: string;
}

export interface RenderCompletionReportOptions {
  agentName: string;
  agentId: string;
  task: string;
  success: boolean;
  completedAt?: string;
  summary: string;
  findings?: string[];
  filedFindingIds?: string[];
  openItems?: string[];
  recommendations?: string[];
}

const ROLE_SPECIALIST_DESCRIPTIONS: Record<
  Exclude<SquadAgentRole, 'orchestrator'>,
  string
> = {
  recon:
    'Perimeter & Egress Recon Specialist — validate governed EgressGateway HTTP 451 scope/exclusion enforcement and fingerprint authorized seed hosts using strictly read-only GET/HEAD/OPTIONS probes.',
  cartographer:
    'JS AST & OpenAPI Cartographer — perform zero-traffic static JavaScript bundle AST traversal and OpenAPI schema extraction inside an isolated GitOps worktree to canonicalize hidden routes and parameters.',
  hypothesis_hunter:
    'CORS & Transport Posture Hunter — execute hypothesis-driven read-only posture checks across CORS preflight boundaries, HSTS/CSP transport headers, and governed cross-role authorization drift; escalate >75% confidence candidates to a child Validator.',
  validator:
    'Counterevidence & PoC Validator — challenge >75% confidence hypotheses via mandatory counterevidence analysis, execute reproducible read-only Python posture checks (verify_posture.py) inside an isolated sandbox, attest HAR SHA-256 evidence pointers, and stage GitOps branches or tombstones.',
};

export function buildRoleSystemDirective(
  role: SquadAgentRole,
  skills: string[] = [],
): string {
  const skillsLine =
    skills.length > 0 ? skills.join(', ') : 'defensive-posture-assessment';

  if (role === 'orchestrator') {
    return [
      `<root_agent_directive>`,
      `YOU ARE THE ROOT LEAD ORCHESTRATOR. Your job is strategic threat modeling, hypothesis formulation, scope governance, and delegating hands-on recon/cartography/posture validation to specialist subagents via \`create_agent\`.`,
      `Never touch live endpoints directly — do not run scanners, crawlers, or raw HTTP probes yourself. Any work that touches an authorized target or GitOps worktree must be delegated to a specialist subagent.`,
      `Active Skills: ${skillsLine}`,
      `Authorized Stance: Strictly defensive, non-destructive, read-only (\`GET\`/\`HEAD\`/\`OPTIONS\`) security posture and attack surface assessment. Never generate weaponized or state-mutating payloads.`,
      `</root_agent_directive>`,
      ``,
      `<threat_model_protocol>`,
      `- Establish one run-scoped SharedThreatModel (\`save_threat_model\`) answering: who are the plausible attacker roles, where do trust boundaries sit, and which high-value assets exist within authorized scope.`,
      `- Distinguish observed facts from \`inferredAssumptions\` so downstream specialists know exactly which boundaries require empirical verification.`,
      `- Specialist subagents append attributed discoveries via \`amend_threat_model\` rather than overwriting the baseline. Review all subagent amendments before Stage 4 PR merge review and final synthesis.`,
      `</threat_model_protocol>`,
      ``,
      `<coverage_reconciliation>`,
      `- Maintain a shared SurfaceCoverageLedger across every discovered host, canonical endpoint, and out-of-scope HTTP 451 boundary check.`,
      `- Before concluding the run, reconcile any \`needs_follow_up\` rows: either delegate targeted follow-up to update coverage (preserving \`previousOutcomes\`) or surface explicit \`open_proof_gap\` items in the executive synthesis. Silent drops are forbidden.`,
      `</coverage_reconciliation>`,
    ].join('\n');
  }

  return [
    `<specialist_role_identity>`,
    `Role: ${role} (${ROLE_SPECIALIST_DESCRIPTIONS[role]})`,
    `Active Skills: ${skillsLine}`,
    `Operational Boundary: Strictly authorized, defensive, non-destructive, read-only (\`GET\`, \`HEAD\`, \`OPTIONS\`) requests routed exclusively through the governed EgressGateway, or zero-traffic offline AST/schema analysis inside your assigned GitOps worktree. Never generate destructive or state-changing payloads.`,
    `</specialist_role_identity>`,
    ``,
    `<cognitive_framework>`,
    `Before EVERY probe or analytical step, execute explicit 4-stage metacognitive reasoning:`,
    `1. What do I KNOW? (confirmed observations, scope constraints, shared threat model facts)`,
    `2. What do I THINK? (explicit testable hypothesis + numeric Confidence 0-100%)`,
    `3. What am I TESTING? (minimal read-only GET/HEAD/OPTIONS probe or offline AST/sandbox verification action)`,
    `4. How will I VALIDATE? (expected defensive control behavior vs actual observed status/headers/schema)`,
    ``,
    `Confidence-Driven Calibration:`,
    `- Evidence confirms hypothesis -> +20% confidence`,
    `- Named control refutes hypothesis -> -30% confidence and transition to ruled_out`,
    `- Ambiguous or credential-gated result -> -10% confidence and evaluate for open_proof_gap`,
    `- Confidence >75% on a posture weakness -> spawn or hand off to Validator for counterevidence + deterministic sandbox verification`,
    `</cognitive_framework>`,
    ``,
    `<closure_discipline>`,
    `Every hypothesis you open or inherit MUST close in one of three terminal states — "moving on" without closure is prohibited:`,
    `- \`confirmed\`: Working read-only proof + reproducible \`verify_posture.py\` check + SHA-256 HAR evidence pointer + completed counterevidence pass.`,
    `- \`ruled_out\`: Requires naming the concrete defensive mechanism on the reachable path in exact form: "Safe because <specific_control> at <observed_header_or_status> enforces <protection> before <exposure>".`,
    `- \`open_proof_gap\`: Candidate remains plausible, could not be confirmed read-only, and no named control rules it out (e.g., unprovisioned multi-tenant credentials on public VDP surfaces). Record \`needs_follow_up\` in coverage and report via \`openItems\` in \`agent_finish\`.`,
    `</closure_discipline>`,
    ``,
    `<counterevidence_pass>`,
    `Before confirming or filing any finding:`,
    `1. Argue the other side: check whether an upstream gateway header, authentication barrier, non-credentialed context, or inert response content-type neutralizes or bounds the exposure.`,
    `2. Record exactly what you checked in \`counterevidence\` — never write "none"; specify which headers, status codes, and role profiles were inspected and why the posture gap remains reachable.`,
    `</counterevidence_pass>`,
  ].join('\n');
}

export function buildSubagentMissionPrompt(
  opts: SubagentMissionPromptOptions,
): string {
  const scope = opts.scope;
  const complianceHeaderEntries = scope
    ? Object.entries(scope.complianceHeaders)
        .map(([k, v]) => `${k}: ${v}`)
        .join(', ') || 'none required'
    : 'governed by EgressGateway';

  const threatModelLines: string[] = [];
  if (opts.threatModel) {
    threatModelLines.push(`Target: ${opts.threatModel.target}`);
    threatModelLines.push(`Summary: ${opts.threatModel.summary}`);
    if (opts.threatModel.trustBoundaries.length > 0) {
      threatModelLines.push(
        `Trust Boundaries:\n${opts.threatModel.trustBoundaries.map((b) => `  - ${b}`).join('\n')}`,
      );
    }
    if (opts.threatModel.highValueAssets.length > 0) {
      threatModelLines.push(
        `High-Value Assets:\n${opts.threatModel.highValueAssets.map((a) => `  - ${a}`).join('\n')}`,
      );
    }
    if (opts.threatModel.inferredAssumptions.length > 0) {
      threatModelLines.push(
        `Inferred Assumptions (verify empirically):\n${opts.threatModel.inferredAssumptions.map((a) => `  - ${a}`).join('\n')}`,
      );
    }
    if (opts.threatModel.amendments.length > 0) {
      threatModelLines.push(
        `Prior Specialist Amendments:\n${opts.threatModel.amendments
          .map((am) => `  - [${am.agentName}] ${am.addendum}`)
          .join('\n')}`,
      );
    }
  } else {
    threatModelLines.push(
      'No baseline SharedThreatModel recorded yet — record initial perimeter observations for threat model synthesis.',
    );
  }

  const knownFactsBlock =
    opts.knownFacts && opts.knownFacts.length > 0
      ? opts.knownFacts.map((f) => `- ${f}`).join('\n')
      : '- No prior subagent artifacts recorded yet; avoid duplicate probing once recorded.';

  const hypothesesBlock =
    opts.assignedHypotheses && opts.assignedHypotheses.length > 0
      ? opts.assignedHypotheses
          .map(
            (h) =>
              `- [${h.id}] (${h.riskCategory} @ ${h.surface}, confidence=${h.confidence}%): ${h.statement}\n  Test Plan: ${h.testPlan}`,
          )
          .join('\n')
      : '- Derive or refine posture hypotheses from observed live headers, AST schemas, and role boundaries.';

  return [
    `<mission_objective>`,
    `Specialist: ${opts.agentName} (role=${opts.role})`,
    `Skills: ${(opts.skills ?? []).join(', ') || 'standard-posture-suite'}`,
    `Assigned Task: ${opts.task}`,
    `</mission_objective>`,
    ``,
    `<authorized_scope_and_rps_guardrails>`,
    scope
      ? [
          `Engagement: ${scope.programName} (${scope.engagementId})`,
          `Authorized Domains: ${scope.authorizedDomains.join(', ') || 'none'}`,
          `Excluded Hosts (HTTP 451 enforced): ${scope.excludedHosts.join(', ') || 'none'}`,
          `Excluded Paths (HTTP 451 enforced): ${scope.excludedPaths.join(', ') || 'none'}`,
          `Max RPS Per Host: ${scope.maxRpsPerHost} req/s`,
          `Required Compliance Headers: ${complianceHeaderEntries}`,
          `Strict Read-Only Methods: ${scope.strictReadOnly ? 'GET, HEAD, OPTIONS only' : 'governed'}`,
        ].join('\n')
      : `All traffic is governed by EgressGateway strict read-only (GET, HEAD, OPTIONS) and HTTP 451 scope enforcement.`,
    `</authorized_scope_and_rps_guardrails>`,
    ``,
    `<shared_threat_model_and_known_facts>`,
    ...threatModelLines,
    `Known Facts (do NOT repeat completed discovery):`,
    knownFactsBlock,
    `</shared_threat_model_and_known_facts>`,
    ``,
    `<assigned_hypotheses>`,
    hypothesesBlock,
    `</assigned_hypotheses>`,
    ``,
    `<gitops_worktree_assignment>`,
    `Assigned Worktree Branch: ${opts.worktreeBranch ?? 'ephemeral-read-only-session'}`,
    `Stage all observations, schemas, tombstones, or verified findings inside your isolated worktree branch for deterministic Stage 3 CI gate validation before merge to main.`,
    `</gitops_worktree_assignment>`,
    ``,
    `<closure_and_completion_report_schema>`,
    `Before calling \`agent_finish\`:`,
    `1. Close every assigned hypothesis as \`confirmed\` (with \`counterevidence\`), \`ruled_out\` (with \`namedControlOrProof\`), or \`open_proof_gap\`.`,
    `2. Record or update SurfaceCoverageLedger entries for every surface inspected.`,
    `3. Deliver a structured completion report containing: \`success\`, \`summary\`, \`findings\`, \`openItems\` (proof gaps), and \`recommendations\`.`,
    `</closure_and_completion_report_schema>`,
  ].join('\n');
}

export function renderCompletionReport(
  opts: RenderCompletionReportOptions,
): string {
  const status = opts.success ? 'SUCCESS' : 'FAILED';
  const completedAt = opts.completedAt ?? new Date().toISOString();
  const findings = opts.findings ?? [];
  const filedFindingIds = opts.filedFindingIds ?? [];
  const openItems = opts.openItems ?? [];
  const recommendations = opts.recommendations ?? [];

  const lines: string[] = [
    `== Completion report from ${opts.agentName} (${opts.agentId}) ==`,
    `Status: ${status}`,
    `Time: ${completedAt}`,
    `Task: ${opts.task || '(unspecified)'}`,
    ``,
    `Summary:`,
    opts.summary.trim() || '(none)',
    ``,
    `Confirmed Observations:`,
    ...(findings.length > 0 ? findings.map((f) => `- ${f}`) : ['- (none)']),
    ``,
    `Filed Finding IDs:`,
    ...(filedFindingIds.length > 0
      ? filedFindingIds.map((id) => `- ${id}`)
      : ['- (none)']),
    ``,
    `Open Proof Gaps:`,
    ...(openItems.length > 0 ? openItems.map((o) => `- ${o}`) : ['- (none)']),
    ``,
    `Recommendations:`,
    ...(recommendations.length > 0
      ? recommendations.map((r) => `- ${r}`)
      : ['- (none)']),
  ];

  return lines.join('\n');
}
