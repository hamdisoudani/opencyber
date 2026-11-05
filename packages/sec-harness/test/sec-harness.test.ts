import { describe, expect, it } from 'vitest';
import {
  buildRoleSystemDirective,
  buildSubagentMissionPrompt,
  CyberSquadCoordinator,
  generateSquadHypotheses,
  hydrateSquadStateFromEngineData,
  renderCompletionReport,
  SquadRunStateSchema,
  type SquadTimelineEvent,
} from '../src/index.js';

describe('@opencyber/sec-harness — Multi-Agent Squad Harness', () => {
  const sampleScope = {
    engagementId: 'eng-test-001',
    programName: 'Acme Perimeter VDP',
    authorizedDomains: ['*.acme.internal', 'api.acme.internal'],
    excludedHosts: ['blog.acme.internal'],
    excludedPaths: ['/admin/destruct/**'],
    maxRpsPerHost: 15,
    complianceHeaders: { 'X-Bug-Bounty-Researcher': 'sec-harness-test' },
    authProfiles: {},
    strictReadOnly: true,
  };

  it('spawns a 3-level agent hierarchy (orchestrator -> hunter -> validator), builds rich missionPrompts, and delivers Strix completion reports', async () => {
    const observedEvents: SquadTimelineEvent[] = [];
    const coordinator = new CyberSquadCoordinator({
      programId: 'prog-test-hierarchy',
      runId: 'run-001',
      onEvent: (ev) => {
        observedEvents.push(ev);
      },
    });

    const orchDirective = buildRoleSystemDirective('orchestrator', [
      'root-agent',
      'threat-modeling',
    ]);
    expect(orchDirective).toContain('<root_agent_directive>');
    expect(orchDirective).toContain('YOU ARE THE ROOT LEAD ORCHESTRATOR');
    expect(orchDirective).toContain('<threat_model_protocol>');
    expect(orchDirective).toContain('<coverage_reconciliation>');

    const specialistDirective = buildRoleSystemDirective('validator', [
      'counterevidence',
    ]);
    expect(specialistDirective).toContain('<cognitive_framework>');
    expect(specialistDirective).toContain('1. What do I KNOW?');
    expect(specialistDirective).toContain('<closure_discipline>');
    expect(specialistDirective).toContain('<counterevidence_pass>');

    const root = coordinator.spawnAgent({
      id: 'agent-orch',
      parentId: null,
      name: 'Lead Orchestrator',
      role: 'orchestrator',
      provider: 'openrouter',
      model: 'stealth/crouton-alpha',
      skills: ['root-agent', 'threat-modeling'],
      task: 'Coordinate perimeter posture assessment',
      scope: sampleScope,
    });

    coordinator.saveThreatModel(root.id, {
      target: '*.acme.internal',
      summary: 'Enterprise API and portal perimeter.',
      trustBoundaries: ['Public browser -> api.acme.internal'],
      attackerRoles: ['Unauthenticated web client'],
      highValueAssets: ['Organization settings endpoint'],
      inferredAssumptions: ['CORS restricts arbitrary Origin reflection'],
    });

    const hyp = coordinator.formHypothesis(root.id, {
      id: 'hyp-cors-01',
      phase: 'POSTURE_VERIFICATION',
      surface: 'GET api.acme.internal/v1/org/settings',
      riskCategory: 'PERMISSIVE_CORS',
      observation: 'Endpoint returns JSON org metadata.',
      statement: 'Origin header may be reflected with Access-Control-Allow-Credentials: true.',
      confidence: 65,
      testPlan: 'Send governed OPTIONS/GET probe with untrusted Origin header.',
    });

    const hunter = coordinator.spawnAgent({
      id: 'agent-hunter',
      parentId: root.id,
      name: 'CORS & Transport Posture Hunter',
      role: 'hypothesis_hunter',
      provider: 'groq',
      model: 'qwen/qwen3.8-27b',
      skills: ['cors-preflight-audit'],
      worktreeBranch: 'task/hunter-posture',
      task: 'Test CORS origin reflection on /v1/org/settings',
      scope: sampleScope,
      knownFacts: ['api.acme.internal answered HTTP 200'],
      assignedHypotheses: [
        {
          id: hyp.id,
          surface: hyp.surface,
          riskCategory: hyp.riskCategory,
          statement: hyp.statement,
          confidence: hyp.confidence,
          testPlan: hyp.testPlan,
        },
      ],
    });

    expect(hunter.parentId).toBe(root.id);
    expect(hunter.missionPrompt).toContain('<mission_objective>');
    expect(hunter.missionPrompt).toContain('<authorized_scope_and_rps_guardrails>');
    expect(hunter.missionPrompt).toContain('<shared_threat_model_and_known_facts>');
    expect(hunter.missionPrompt).toContain('<assigned_hypotheses>');
    expect(hunter.missionPrompt).toContain('<gitops_worktree_assignment>');
    expect(hunter.missionPrompt).toContain('<closure_and_completion_report_schema>');
    expect(hunter.missionPrompt).toContain('task/hunter-posture');

    coordinator.recordThink(hunter.id, {
      know: 'api.acme.internal/v1/org/settings is reachable.',
      think: 'CORS preflight reflects untrusted Origin with credentials.',
      test: 'Send governed OPTIONS probe.',
      validate: 'Inspect ACAO and ACAC headers.',
      confidence: 85,
    });

    const validator = coordinator.spawnAgent({
      id: 'agent-validator',
      parentId: hunter.id,
      name: 'Counterevidence & PoC Validator',
      role: 'validator',
      provider: 'groq',
      model: 'qwen/qwen3.8-27b',
      skills: ['counterevidence', 'sandbox-poc-validator'],
      worktreeBranch: 'task/validator-poc',
      task: 'Run counterevidence pass and verify_posture.py',
      scope: sampleScope,
    });

    expect(validator.parentId).toBe(hunter.id);

    const valReport = coordinator.completeAgent(validator.id, {
      success: true,
      summary: 'Verified CORS reflection in sandbox.',
      findings: ['Confirmed ACAO reflection + ACAC: true'],
      filedFindingIds: ['AUD-001-permissive-cors'],
      openItems: [],
      recommendations: ['Restrict allowed origins to explicit allowlist.'],
    });
    expect(valReport.success).toBe(true);

    coordinator.completeAgent(hunter.id, {
      success: true,
      summary: 'Completed CORS posture hunt.',
      findings: ['AUD-001-permissive-cors validated'],
      filedFindingIds: ['AUD-001-permissive-cors'],
      openItems: [],
      recommendations: [],
    });

    await coordinator.flush();
    const snap = coordinator.finalizeRun('completed');
    const parsed = SquadRunStateSchema.parse(snap);

    expect(parsed.agents).toHaveLength(3);
    const updatedRoot = parsed.agents.find((a) => a.id === root.id)!;
    const updatedHunter = parsed.agents.find((a) => a.id === hunter.id)!;
    const updatedValidator = parsed.agents.find((a) => a.id === validator.id)!;

    // Parent toolCallCount & messageCount incremented on child spawn & completion
    expect(updatedRoot.toolCallCount).toBeGreaterThanOrEqual(3);
    expect(updatedRoot.messageCount).toBe(1);
    expect(updatedHunter.toolCallCount).toBeGreaterThanOrEqual(2);
    expect(updatedHunter.messageCount).toBe(1);
    expect(updatedValidator.status).toBe('completed');

    // Monotonic seq
    expect(observedEvents.map((e) => e.seq)).toEqual(
      observedEvents.map((_, idx) => idx + 1),
    );

    const completionMsgEvent = observedEvents.find(
      (e) => e.kind === 'agent_message' && e.agentId === validator.id,
    );
    expect(completionMsgEvent).toBeDefined();
    expect(completionMsgEvent!.detail).toContain(
      '== Completion report from Counterevidence & PoC Validator (agent-validator) ==',
    );
    expect(completionMsgEvent!.detail).toContain('AUD-001-permissive-cors');

    // Standalone missionPrompt & completionReport helpers
    const standalonePrompt = buildSubagentMissionPrompt({
      agentName: 'Recon Test',
      role: 'recon',
      task: 'Fingerprint hosts',
      scope: sampleScope,
    });
    expect(standalonePrompt).toContain('blog.acme.internal');
    const renderedText = renderCompletionReport({
      agentName: 'Recon Test',
      agentId: 'recon-1',
      task: 'Fingerprint hosts',
      success: true,
      summary: 'Done',
    });
    expect(renderedText).toContain('Status: SUCCESS');
  });

  it('enforces Strix closure discipline on hypotheses and tracks confidenceHistory deltas', () => {
    const coordinator = new CyberSquadCoordinator({
      programId: 'prog-closure',
      runId: 'run-closure',
    });

    const orch = coordinator.spawnAgent({
      parentId: null,
      name: 'Lead Orchestrator',
      role: 'orchestrator',
      provider: 'openrouter',
      model: 'stealth/crouton-alpha',
      task: 'Test closure discipline',
    });

    const h1 = coordinator.formHypothesis(orch.id, {
      phase: 'POSTURE_VERIFICATION',
      surface: 'GET api.acme.internal/v1/health',
      riskCategory: 'EXPOSED_DEBUG_SURFACE',
      observation: 'Health endpoint exists.',
      statement: 'Health endpoint might leak debug env vars.',
      confidence: 55,
      testPlan: 'Send governed GET /v1/health.',
    });

    expect(h1.confidenceHistory).toHaveLength(1);
    expect(h1.confidenceHistory[0]?.delta).toBe(55);

    // Ruling out WITHOUT namedControlOrProof must throw
    expect(() =>
      coordinator.updateHypothesis(orch.id, h1.id, {
        closureState: 'ruled_out',
        confidence: 5,
      }),
    ).toThrow(/namedControlOrProof/i);

    // Ruling out WITH concrete namedControlOrProof succeeds
    const ruledOut = coordinator.updateHypothesis(orch.id, h1.id, {
      closureState: 'ruled_out',
      confidence: 5,
      namedControlOrProof:
        'Safe because static health serializer at HTTP 200 returns only {"ok":true} before any environment dictionary access.',
      reason: 'Verified minimal JSON body.',
    });
    expect(ruledOut.closureState).toBe('ruled_out');
    expect(ruledOut.confidenceHistory).toHaveLength(2);
    expect(ruledOut.confidenceHistory[1]?.delta).toBe(-50);

    // Confirming WITHOUT counterevidence must throw
    const h2 = coordinator.formHypothesis(orch.id, {
      phase: 'COUNTEREVIDENCE',
      surface: 'GET api.acme.internal/v1/org/settings',
      riskCategory: 'PERMISSIVE_CORS',
      observation: 'Reflects Origin header.',
      statement: 'Credentialed cross-origin read is permitted.',
      confidence: 82,
      testPlan: 'Run verify_posture.py.',
    });

    expect(() =>
      coordinator.updateHypothesis(orch.id, h2.id, {
        closureState: 'confirmed',
        confidence: 95,
      }),
    ).toThrow(/counterevidence/i);

    const confirmed = coordinator.updateHypothesis(orch.id, h2.id, {
      closureState: 'confirmed',
      confidence: 95,
      namedControlOrProof: 'Verified by verify_posture.py and HAR SHA-256.',
      counterevidence:
        'Checked whether custom non-simple headers or CSRF tokens prevent cross-origin GET reads; endpoint accepts ambient credentials on standard GET.',
      linkedFindingId: 'AUD-001-cors',
    });
    expect(confirmed.closureState).toBe('confirmed');
    expect(confirmed.linkedFindingId).toBe('AUD-001-cors');
    expect(confirmed.confidenceHistory[1]?.delta).toBe(13);
  });

  it('tracks SharedThreatModel amendments and SurfaceCoverageEntry previousOutcomes transitions', () => {
    const coordinator = new CyberSquadCoordinator({
      programId: 'prog-tm-cov',
      runId: 'run-tm-cov',
    });

    const orch = coordinator.spawnAgent({
      parentId: null,
      name: 'Lead Orchestrator',
      role: 'orchestrator',
      provider: 'openrouter',
      model: 'stealth/crouton-alpha',
      task: 'Threat model & coverage test',
    });

    const recon = coordinator.spawnAgent({
      parentId: orch.id,
      name: 'Perimeter & Egress Recon Specialist',
      role: 'recon',
      provider: 'groq',
      model: 'qwen/qwen3.8-27b',
      task: 'Amend threat model and update coverage',
    });

    // Amending before baseline throws
    expect(() =>
      coordinator.amendThreatModel(recon.id, 'Discovered undocumented host'),
    ).toThrow(/before saveThreatModel/i);

    coordinator.saveThreatModel(orch.id, {
      target: 'acme.internal',
      summary: 'Initial black-box model.',
      trustBoundaries: ['Internet -> Portal'],
      attackerRoles: ['External anonymous user'],
      highValueAssets: ['Portal session'],
      inferredAssumptions: ['/admin is IP-restricted — unverified'],
    });

    const amended = coordinator.amendThreatModel(
      recon.id,
      'Observed api.acme.internal serving OpenAPI 3.1 schema at /openapi.json with role_viewer/role_admin routes.',
    );
    expect(amended.amendments).toHaveLength(1);
    expect(amended.amendments[0]?.agentName).toBe(
      'Perimeter & Egress Recon Specialist',
    );

    // Coverage requires evidence on ruled_out / needs_follow_up
    expect(() =>
      coordinator.recordCoverage(recon.id, {
        surface: 'GET api.acme.internal/v1/users/1/roles',
        riskArea: 'AUTHZ_SCHEMA_DRIFT',
        outcome: 'needs_follow_up',
        evidence: '   ',
      }),
    ).toThrow(/evidence/i);

    const firstCov = coordinator.recordCoverage(recon.id, {
      surface: 'GET api.acme.internal/v1/users/1/roles',
      riskArea: 'AUTHZ_SCHEMA_DRIFT',
      outcome: 'needs_follow_up',
      evidence: 'Observed 200 OK on viewer session; escalating to Validator.',
    });
    expect(firstCov.previousOutcomes).toEqual([]);

    // Upserting same (surface, riskArea) preserves previousOutcomes
    const secondCov = coordinator.recordCoverage(recon.id, {
      surface: 'get api.acme.internal/v1/users/1/roles',
      riskArea: 'authz_schema_drift',
      outcome: 'reported',
      evidence: 'Confirmed AUD-002-authz-drift via verify_posture.py.',
    });
    expect(secondCov.id).toBe(firstCov.id);
    expect(secondCov.outcome).toBe('reported');
    expect(secondCov.previousOutcomes).toEqual(['needs_follow_up']);
    expect(coordinator.getSnapshot().coverage).toHaveLength(1);
  });

  it('hydrates a complete 5-agent 3-level SquadRunState from engine data and falls back deterministically for hypothesis generation', async () => {
    const detCandidates = await generateSquadHypotheses({
      scope: sampleScope,
      threatModel: null,
      hosts: ['api.acme.internal'],
      endpoints: [
        {
          endpointId: 'ep-1',
          host: 'api.acme.internal',
          method: 'GET',
          canonicalPath: '/v1/org/settings',
          observedRawPaths: ['/v1/org/settings'],
          sources: ['RECON'],
          parameters: [],
          responseContentTypes: ['application/json'],
          firstSeenAt: '2026-11-05T00:00:00.000Z',
          lastUpdatedAt: '2026-11-05T00:00:00.000Z',
        },
      ],
    });
    expect(detCandidates.length).toBeGreaterThanOrEqual(2);

    const hydrated = hydrateSquadStateFromEngineData({
      programId: 'prog-firecrawl-test',
      overview: {
        engagement: {
          engagementId: 'prog-firecrawl-test',
          programName: 'Firecrawl VDP',
          authorizedDomains: ['*.firecrawl.dev', 'firecrawl.dev'],
          excludedHosts: ['docs.firecrawl.dev'],
          excludedPaths: ['/admin/destruct/**'],
          maxRpsPerHost: 4,
          complianceHeaders: { 'X-Bug-Bounty': 'opencyber' },
          strictReadOnly: true,
        },
        runtime: {
          sandboxProvider: 'e2b',
          orchestratorProvider: 'openrouter',
          subagentProvider: 'groq',
          orchestratorModel: 'stealth/crouton-alpha',
          subagentModel: 'qwen/qwen3.8-27b',
          lastRunAt: '2026-11-05T12:00:00.000Z',
        },
        metrics: {
          hostsDiscovered: 2,
          canonicalEndpoints: 5,
          compliantTombstones: 3,
          pendingFindings: 1,
          approvedFindings: 0,
          allowedRequests: 14,
          blockedScope451: 2,
        },
      },
      surfaceGraph: {
        nodes: [
          {
            id: 'host:firecrawl.dev',
            type: 'HOST',
            label: 'firecrawl.dev',
            metadata: { statusCode: 200 },
          },
          {
            id: 'host:api.firecrawl.dev',
            type: 'HOST',
            label: 'api.firecrawl.dev',
            metadata: { statusCode: 200 },
          },
          {
            id: 'ep:1',
            type: 'ENDPOINT',
            label: 'GET api.firecrawl.dev/v1/crawl/{param}',
          },
          {
            id: 'ts:1',
            type: 'TOMBSTONE',
            label: 'GET firecrawl.dev/api',
            metadata: { notes: 'Strict headers verified.' },
          },
        ],
        edges: [],
      },
      findings: [
        {
          findingId: 'AUD-001-missing-headers-api-firecrawl-dev',
          title: 'Missing HSTS/CSP Transport Security Headers on api.firecrawl.dev',
          category: 'MISSING_SECURITY_HEADERS',
          severity: 'MEDIUM',
          host: 'api.firecrawl.dev',
          endpointId: 'api.firecrawl.dev:GET:/',
          summary: 'API root omits Content-Security-Policy and frame-ancestors.',
          architecturalAnalysis: 'Direct API responses lack browser framing protections.',
          remediation: 'Add strict Content-Security-Policy and Strict-Transport-Security.',
          reproducibleCheckFile:
            'reports/AUD-001-missing-headers-api-firecrawl-dev/verify_posture.py',
          evidencePointers: [
            {
              sha256:
                'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
              blobPath: 'blobs/a1b2',
              requestUrl: 'https://api.firecrawl.dev/',
              method: 'GET',
              statusCode: 200,
              capturedAt: '2026-11-05T11:59:00.000Z',
            },
          ],
          status: 'PENDING_HUMAN_REVIEW',
          createdAt: '2026-11-05T11:59:30.000Z',
        },
      ],
      gitopsHistory: {
        branches: ['main'],
        commits: [
          {
            sha: '1234567890abcdef1234567890abcdef12345678',
            message: "Merge branch 'task/audit-001'",
          },
        ],
        reviews: [],
      },
      traffic: [
        {
          id: 'tr-1',
          timestamp: '2026-11-05T11:58:00.000Z',
          engagementId: 'prog-firecrawl-test',
          taskId: 'guardrail-1',
          fencingToken: 0,
          method: 'GET',
          url: 'https://docs.firecrawl.dev/',
          host: 'docs.firecrawl.dev',
          pathname: '/',
          decision: 'BLOCKED_SCOPE_451',
          durationMs: 2,
        },
      ],
    });

    const validated = SquadRunStateSchema.parse(hydrated);
    expect(validated.status).toBe('completed');
    expect(validated.agents).toHaveLength(5);

    const orch = validated.agents.find((a) => a.role === 'orchestrator')!;
    const recon = validated.agents.find((a) => a.role === 'recon')!;
    const carto = validated.agents.find((a) => a.role === 'cartographer')!;
    const hunter = validated.agents.find((a) => a.role === 'hypothesis_hunter')!;
    const validator = validated.agents.find((a) => a.role === 'validator')!;

    expect(orch.parentId).toBeNull();
    expect(recon.parentId).toBe(orch.id);
    expect(carto.parentId).toBe(orch.id);
    expect(hunter.parentId).toBe(orch.id);
    expect(validator.parentId).toBe(hunter.id); // Level 2 child!

    expect(validated.threatModel).not.toBeNull();
    expect(validated.threatModel!.amendments.length).toBeGreaterThanOrEqual(2);

    expect(validated.hypotheses.length).toBeGreaterThanOrEqual(4);
    expect(validated.hypotheses.length).toBeLessThanOrEqual(6);

    const closureStates = new Set(
      validated.hypotheses.map((h) => h.closureState),
    );
    expect(closureStates.has('confirmed')).toBe(true);
    expect(closureStates.has('ruled_out')).toBe(true);
    expect(closureStates.has('open_proof_gap')).toBe(true);

    const Outcomes = new Set(validated.coverage.map((c) => c.outcome));
    expect(Outcomes.has('blocked_451')).toBe(true);
    expect(Outcomes.has('reported')).toBe(true);
    expect(Outcomes.has('ruled_out')).toBe(true);
    expect(Outcomes.has('needs_follow_up')).toBe(true);

    const reportedCov = validated.coverage.find(
      (c) => c.outcome === 'reported',
    )!;
    expect(reportedCov.previousOutcomes).toContain('needs_follow_up');
  });
});
