import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  AegisControlPlaneEngine,
  type ChatMessageItem,
  createControlPlaneServer,
  type ProgramLogEntry,
  type ProgramSummaryItem,
  ProgramWorkspaceManager,
  type SquadRunState,
  SquadRunStateSchema,
  type SquadTimelineEvent,
} from '../src/index.js';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const rootEnvPath = path.resolve(currentDir, '../../../.env');
dotenv.config({ path: rootEnvPath });

describe('OpenCyber Control-Plane End-to-End Live Pipeline (E2B + Groq + GitOps)', () => {
  let tempDir = '';
  let engine: AegisControlPlaneEngine;
  let app: ReturnType<typeof createControlPlaneServer>;

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-cp-e2e-'));
    engine = new AegisControlPlaneEngine({
      dataDir: tempDir,
      useDemoTarget: true,
      useCloudSandbox: true,
    });
    await engine.init();
    app = createControlPlaneServer(engine);
  }, 60_000);

  afterAll(async () => {
    if (engine) {
      await engine.close();
    }
    if (tempDir) {
      await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {
        // Ignore cleanup errors
      });
    }
  }, 30_000);

  it(
    'executes full multi-stage GitOps assessment with real E2B cloud sandbox and Groq PR review',
    async () => {
      // 0. Health check & static SPA check
      const healthRes = await app.request('/api/health');
      expect(healthRes.status).toBe(200);
      expect(await healthRes.json()).toEqual({ ok: true });

      const spaRes = await app.request('/');
      expect(spaRes.status).toBe(200);
      expect(spaRes.headers.get('content-type')).toContain('text/html');

      // 1. Trigger full assessment synchronously via POST /api/assessments/run
      const runRes = await app.request('/api/assessments/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          useCloudSandbox: true,
          waitForCompletion: true,
        }),
      });
      expect(runRes.status).toBe(200);
      const runJson = (await runRes.json()) as {
        started: boolean;
        runId: string;
        summary: {
          sandboxProvider: string;
          hostsDiscovered: number;
          canonicalEndpoints: number;
          compliantTombstones: number;
          mergedFindings: string[];
          blockedScope451: number;
        };
      };
      expect(runJson.started).toBe(true);
      expect(runJson.runId).toMatch(/^run-/);
      expect(runJson.summary.sandboxProvider).toBe('e2b');

      // 2. Verify GET /api/overview telemetry & metrics
      const overviewRes = await app.request('/api/overview');
      expect(overviewRes.status).toBe(200);
      const overview = (await overviewRes.json()) as {
        engagement: { engagementId: string; strictReadOnly: boolean };
        runtime: {
          sandboxProvider: string;
          orchestratorProvider: string;
          subagentProvider: string;
          orchestratorModel: string;
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
      };

      expect(overview.engagement.strictReadOnly).toBe(true);
      expect(overview.runtime.sandboxProvider).toBe('e2b');
      expect(overview.runtime.orchestratorProvider).toBe('openrouter');
      expect(overview.runtime.orchestratorModel).toBe('stealth/crouton-alpha');
      expect(overview.runtime.subagentProvider).toBe('groq');
      expect(overview.runtime.pipelineRunning).toBe(false);
      expect(overview.runtime.lastRunAt).toBeTruthy();
      expect(overview.metrics.hostsDiscovered).toBeGreaterThanOrEqual(2);
      expect(overview.metrics.canonicalEndpoints).toBeGreaterThanOrEqual(4);
      expect(overview.metrics.blockedScope451).toBeGreaterThanOrEqual(2);
      expect(overview.metrics.compliantTombstones).toBeGreaterThanOrEqual(1);
      expect(overview.metrics.pendingFindings).toBeGreaterThanOrEqual(2);
      expect(overview.metrics.approvedFindings).toBe(0);

      // 3. Verify GET /api/surface/graph node types, edge relations, and canonical route deduplication
      const graphRes = await app.request('/api/surface/graph');
      expect(graphRes.status).toBe(200);
      const graph = (await graphRes.json()) as {
        nodes: Array<{
          id: string;
          type: string;
          label: string;
          metadata: Record<string, unknown>;
        }>;
        edges: Array<{
          id: string;
          source: string;
          target: string;
          relation: string;
        }>;
      };

      const nodeTypes = new Set(graph.nodes.map((n) => n.type));
      expect(nodeTypes.has('PROGRAM')).toBe(true);
      expect(nodeTypes.has('HOST')).toBe(true);
      expect(nodeTypes.has('ENDPOINT')).toBe(true);
      expect(nodeTypes.has('FINDING')).toBe(true);
      expect(nodeTypes.has('TOMBSTONE')).toBe(true);

      expect(graph.edges.length).toBeGreaterThan(0);
      for (const edge of graph.edges) {
        expect(typeof edge.relation).toBe('string');
        expect(edge.relation.length).toBeGreaterThan(0);
      }
      const edgeRelations = new Set(graph.edges.map((e) => e.relation));
      expect(edgeRelations.has('IN_SCOPE')).toBe(true);
      expect(edgeRelations.has('EXPOSES')).toBe(true);
      expect(edgeRelations.has('HAS_FINDING')).toBe(true);
      expect(edgeRelations.has('VERIFIED_COMPLIANT')).toBe(true);

      const rolesEndpointNode = graph.nodes.find(
        (n) =>
          n.type === 'ENDPOINT' &&
          n.metadata.host === 'api.acme.internal' &&
          n.metadata.canonicalPath === '/v1/users/{param}/roles',
      );
      expect(rolesEndpointNode).toBeDefined();
      const rolesSources = rolesEndpointNode?.metadata.sources as string[];
      const rolesRawPaths = rolesEndpointNode?.metadata
        .observedRawPaths as string[];
      expect(rolesSources).toContain('STATIC_JS_AST');
      expect(rolesSources).toContain('OPENAPI_PARSER');
      expect(rolesRawPaths).toContain('/v1/users/:param/roles');
      expect(rolesRawPaths).toContain('/v1/users/{id}/roles');

      // 4. Verify GET /api/findings & HITL decision workflow
      const findingsRes = await app.request('/api/findings');
      expect(findingsRes.status).toBe(200);
      const { findings } = (await findingsRes.json()) as {
        findings: Array<{
          findingId: string;
          category: string;
          severity: string;
          status: string;
          endpointId: string;
          reviewerNote?: string;
          evidencePointers: Array<{
            sha256: string;
            method: string;
            requestUrl: string;
            authProfileUsed?: string;
          }>;
        }>;
      };

      const categories = new Set(findings.map((f) => f.category));
      expect(categories.has('PERMISSIVE_CORS')).toBe(true);
      expect(categories.has('AUTHZ_SCHEMA_DRIFT')).toBe(true);

      for (const finding of findings) {
        expect(finding.status).toBe('PENDING_HUMAN_REVIEW');
        expect(finding.evidencePointers.length).toBeGreaterThanOrEqual(1);
        for (const ptr of finding.evidencePointers) {
          expect(ptr.sha256).toMatch(/^[a-f0-9]{64}$/);
        }
      }

      const corsFinding = findings.find((f) => f.category === 'PERMISSIVE_CORS')!;
      const authzFinding = findings.find(
        (f) => f.category === 'AUTHZ_SCHEMA_DRIFT',
      )!;
      expect(corsFinding).toBeDefined();
      expect(authzFinding).toBeDefined();

      // Approve the PERMISSIVE_CORS finding via HITL endpoint
      const decisionRes = await app.request(
        `/api/findings/${encodeURIComponent(corsFinding.findingId)}/decision`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            status: 'APPROVED',
            reviewerNote:
              'Confirmed wildcard/origin reflection with credentials on /v1/org/settings.',
          }),
        },
      );
      expect(decisionRes.status).toBe(200);
      const decisionPayload = (await decisionRes.json()) as {
        finding: { findingId: string; status: string; reviewerNote?: string };
      };
      expect(decisionPayload.finding.status).toBe('APPROVED');
      expect(decisionPayload.finding.reviewerNote).toContain(
        '/v1/org/settings',
      );

      const updatedOverviewRes = await app.request('/api/overview');
      const updatedOverview = (await updatedOverviewRes.json()) as {
        metrics: { approvedFindings: number; pendingFindings: number };
      };
      expect(updatedOverview.metrics.approvedFindings).toBe(1);
      expect(updatedOverview.metrics.pendingFindings).toBe(
        overview.metrics.pendingFindings - 1,
      );

      // 5. Verify GET /api/gitops/history contains --no-ff merge commits and Groq APPROVE_MERGE reviews
      const gitopsRes = await app.request('/api/gitops/history');
      expect(gitopsRes.status).toBe(200);
      const gitops = (await gitopsRes.json()) as {
        branches: string[];
        commits: Array<{ sha: string; message: string; author: string }>;
        reviews: Array<{
          id: string;
          branchName: string;
          decision: string;
          ciPassed: boolean;
          rationale: string;
          commitSha?: string;
        }>;
      };

      expect(gitops.branches).toContain('main');
      const mergeCommits = gitops.commits.filter((c) =>
        c.message.startsWith("Merge branch 'task/"),
      );
      expect(mergeCommits.length).toBeGreaterThanOrEqual(4); // recon + static + >=2 finding merges

      const findingApproveReviews = gitops.reviews.filter(
        (r) =>
          r.decision === 'APPROVE_MERGE' && r.branchName.includes('task/audit-'),
      );
      expect(findingApproveReviews.length).toBeGreaterThanOrEqual(2);
      for (const rev of findingApproveReviews) {
        expect(rev.ciPassed).toBe(true);
        expect(rev.rationale.length).toBeGreaterThan(10);
        expect(rev.commitSha).toMatch(/^[a-f0-9]{40}$/);
      }

      // 6. Verify GET /api/traffic & GET /api/blobs/:sha256 SessionVault credential redaction
      const trafficRes = await app.request('/api/traffic');
      expect(trafficRes.status).toBe(200);
      const { entries: trafficEntries } = (await trafficRes.json()) as {
        entries: Array<{
          method: string;
          url: string;
          decision: string;
        }>;
      };
      const blocked451Urls = trafficEntries
        .filter((e) => e.decision === 'BLOCKED_SCOPE_451')
        .map((e) => e.url);
      expect(blocked451Urls).toContain('http://external-untrusted.example/probe');
      expect(blocked451Urls).toContain(
        'http://api.acme.internal/admin/destruct/wipe',
      );
      // Verify POST /v1/reports/export was NEVER executed via state-changing POST
      expect(
        trafficEntries.some(
          (e) =>
            e.method === 'POST' && e.url.includes('/v1/reports/export'),
        ),
      ).toBe(false);

      // Verify HAR evidence blob has [REDACTED_BY_SESSION_VAULT] instead of raw session secrets
      const authPtr = authzFinding.evidencePointers.find(
        (p) => Boolean(p.authProfileUsed),
      ) ?? authzFinding.evidencePointers[0]!;
      expect(authPtr).toBeDefined();

      const blobRes = await app.request(`/api/blobs/${authPtr.sha256}`);
      expect(blobRes.status).toBe(200);
      const blobJson = (await blobRes.json()) as {
        sha256: string;
        mediaType: string;
        metadata: Record<string, string>;
        text: string;
      };
      expect(blobJson.sha256).toBe(authPtr.sha256);
      expect(blobJson.mediaType).toContain('application/json');
      expect(blobJson.metadata.kind).toBe('har');
      expect(blobJson.text).toContain('[REDACTED_BY_SESSION_VAULT]');
      expect(blobJson.text).not.toContain('aegis-viewer-session-');
      expect(blobJson.text).not.toContain('aegis-admin-session-');

      // 7. Verify error handling edge cases (404 missing blob, 404 missing finding, 400 invalid filter)
      const missingBlobRes = await app.request(
        '/api/blobs/0000000000000000000000000000000000000000000000000000000000000000',
      );
      expect(missingBlobRes.status).toBe(404);

      const missingFindingRes = await app.request(
        '/api/findings/AUD-999-nonexistent/decision',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'REJECTED', reviewerNote: 'N/A' }),
        },
      );
      expect(missingFindingRes.status).toBe(404);

      const badStatusFilterRes = await app.request(
        '/api/findings?status=UNKNOWN_STATUS',
      );
      expect(badStatusFilterRes.status).toBe(400);

      const approvedFilterRes = await app.request(
        '/api/findings?status=APPROVED',
      );
      expect(approvedFilterRes.status).toBe(200);
      const approvedFilterBody = (await approvedFilterRes.json()) as {
        findings: Array<{ findingId: string; status: string }>;
      };
      expect(approvedFilterBody.findings).toHaveLength(1);
      expect(approvedFilterBody.findings[0]?.findingId).toBe(
        corsFinding.findingId,
      );

      const missingAssetRes = await app.request('/assets/nonexistent-chunk.js');
      expect(missingAssetRes.status).toBe(404);

      // 7b. Verify GET /api/squad exposes full 5-agent 3-level Strix + Cyber-AutoAgent SquadRunState
      const squadRes = await app.request('/api/squad');
      expect(squadRes.status).toBe(200);
      const squad = SquadRunStateSchema.parse(await squadRes.json());
      expect(squad.status).toBe('completed');
      expect(squad.agents).toHaveLength(5);

      const rootAgent = squad.agents.find((a) => a.parentId === null)!;
      expect(rootAgent).toBeDefined();
      expect(rootAgent.role).toBe('orchestrator');

      const level1Agents = squad.agents.filter((a) => a.parentId === rootAgent.id);
      expect(level1Agents).toHaveLength(3);
      expect(level1Agents.map((a) => a.role)).toEqual(
        expect.arrayContaining(['recon', 'cartographer', 'hypothesis_hunter']),
      );

      const hunterNode = level1Agents.find((a) => a.role === 'hypothesis_hunter')!;
      const validatorNode = squad.agents.find((a) => a.role === 'validator')!;
      expect(validatorNode).toBeDefined();
      expect(validatorNode.parentId).toBe(hunterNode.id);

      expect(squad.threatModel).not.toBeNull();
      expect(squad.threatModel!.amendments.length).toBeGreaterThanOrEqual(2);

      const closureStates = new Set(squad.hypotheses.map((h) => h.closureState));
      expect(closureStates.has('confirmed')).toBe(true);
      expect(closureStates.has('ruled_out')).toBe(true);
      expect(closureStates.has('open_proof_gap')).toBe(true);

      for (const h of squad.hypotheses) {
        if (h.closureState === 'ruled_out') {
          expect(h.namedControlOrProof.trim().length).toBeGreaterThan(0);
        }
        if (h.closureState === 'confirmed') {
          expect(h.counterevidence.trim().length).toBeGreaterThan(0);
        }
      }

      const coverageOutcomes = new Set(squad.coverage.map((c) => c.outcome));
      expect(coverageOutcomes.has('reported')).toBe(true);
      expect(coverageOutcomes.has('blocked_451')).toBe(true);
      expect(squad.timeline.length).toBeGreaterThanOrEqual(15);
      expect(squad.timeline.map((e) => e.seq)).toEqual(
        squad.timeline.map((_, idx) => idx + 1),
      );

      // 8. Verify idempotency: running a second assessment skips already-evaluated endpoints
      const secondRunRes = await app.request('/api/assessments/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          useCloudSandbox: false,
          waitForCompletion: true,
        }),
      });
      expect(secondRunRes.status).toBe(200);
      const secondRunJson = (await secondRunRes.json()) as {
        summary: { mergedFindings: string[] };
      };
      expect(secondRunJson.summary.mergedFindings).toEqual([]);

      const afterSecondFindingsRes = await app.request('/api/findings');
      const afterSecondFindings = (await afterSecondFindingsRes.json()) as {
        findings: unknown[];
      };
      expect(afterSecondFindings.findings).toHaveLength(findings.length);

      const afterSecondSquadRes = await app.request('/api/squad');
      expect(afterSecondSquadRes.status).toBe(200);
      const afterSecondSquad = SquadRunStateSchema.parse(
        await afterSecondSquadRes.json(),
      );
      expect(afterSecondSquad.status).toBe('completed');
      expect(afterSecondSquad.agents).toHaveLength(5);
    },
    120_000,
  );
});

interface ParsedSseFrame {
  event: string;
  data: unknown;
}

function parseSseFrames(rawSseText: string): ParsedSseFrame[] {
  const frames: ParsedSseFrame[] = [];
  const rawBlocks = rawSseText.split('\n\n');
  for (const block of rawBlocks) {
    const trimmed = block.trim();
    if (!trimmed) {
      continue;
    }
    let eventName = 'message';
    const dataLines: string[] = [];
    for (const line of trimmed.split('\n')) {
      if (line.startsWith('event:')) {
        eventName = line.slice('event:'.length).trim();
      } else if (line.startsWith('data:')) {
        dataLines.push(line.slice('data:'.length).trim());
      }
    }
    if (dataLines.length > 0) {
      const joined = dataLines.join('\n');
      frames.push({
        event: eventName,
        data: JSON.parse(joined) as unknown,
      });
    }
  }
  return frames;
}

describe('Chat-First Multi-Program Bugcrowd Orchestrator SSE E2E', () => {
  let tempDir = '';
  let manager: ProgramWorkspaceManager;
  let app: ReturnType<typeof createControlPlaneServer>;

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-multi-prog-e2e-'));
    manager = new ProgramWorkspaceManager({
      dataDir: tempDir,
      useDemoTarget: true,
      useCloudSandbox: true,
    });
    await manager.init();
    app = createControlPlaneServer(manager);
  }, 60_000);

  afterAll(async () => {
    if (manager) {
      await manager.close();
    }
    if (tempDir) {
      await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {
        // Ignore cleanup errors
      });
    }
  }, 30_000);

  it(
    'ingests a Bugcrowd program brief via POST /api/chat/stream SSE, enforces excludedHosts & rate limits, runs E2B + OpenRouter crouton-alpha review, and isolates all program endpoints',
    async () => {
      // 1. Fresh workspace manager starts with zero programs
      const initialProgramsRes = await app.request('/api/programs');
      expect(initialProgramsRes.status).toBe(200);
      expect(await initialProgramsRes.json()).toEqual({ programs: [] });

      // Missing program returns 404
      const missingProgRes = await app.request(
        '/api/programs/prog-does-not-exist/overview',
      );
      expect(missingProgRes.status).toBe(404);

      // Empty message returns clean SSE error event without hanging
      const emptyChatRes = await app.request('/api/chat/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: '   ' }),
      });
      expect(emptyChatRes.status).toBe(200);
      const emptyFrames = parseSseFrames(await emptyChatRes.text());
      expect(emptyFrames.some((f) => f.event === 'error')).toBe(true);

      // 2. Send realistic Bugcrowd program brief over POST /api/chat/stream
      const bugcrowdBrief = [
        '# Bugcrowd Program: Acme FinTech Core Perimeter',
        '',
        '## In-Scope Targets',
        '- `*.acme.internal`',
        '- `portal.acme.internal`',
        '- `api.acme.internal`',
        '',
        '## Out-of-Scope',
        '- `blog.acme.internal`',
        '- `/admin/destruct/**`',
        '',
        '## Rules of Engagement',
        '- Rate Limit: Maximum 12 requests per second per host.',
        '- Required Header: `X-Bug-Bounty-Researcher: bugcrowd-e2e-tester`',
        '- Strictly read-only posture verification (`GET`, `HEAD`, `OPTIONS` only).',
      ].join('\n');

      const sseRes = await app.request('/api/chat/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: bugcrowdBrief,
          useCloudSandbox: true,
        }),
      });

      expect(sseRes.status).toBe(200);
      expect(sseRes.headers.get('content-type')).toContain('text/event-stream');

      const sseText = await sseRes.text();
      const frames = parseSseFrames(sseText);
      expect(frames.some((f) => f.event === 'error')).toBe(false);

      // 3a. Verify event: program_selected
      const programSelectedFrame = frames.find(
        (f) => f.event === 'program_selected',
      );
      expect(programSelectedFrame).toBeDefined();
      const selectedPayload = programSelectedFrame!.data as {
        programId: string;
        programName: string;
        isNew: boolean;
        assistantMessageId: string;
      };
      expect(selectedPayload.programId).toMatch(/^prog-/);
      expect(selectedPayload.isNew).toBe(true);
      expect(selectedPayload.assistantMessageId.length).toBeGreaterThan(8);

      const programId = selectedPayload.programId;

      // 3b. Verify event: scope_updated
      const scopeUpdatedFrame = frames.find((f) => f.event === 'scope_updated');
      expect(scopeUpdatedFrame).toBeDefined();
      const scopePayload = scopeUpdatedFrame!.data as {
        programId: string;
        programName: string;
        authorizedDomains: string[];
        excludedHosts: string[];
        excludedPaths: string[];
        maxRpsPerHost: number;
        complianceHeaders: Record<string, string>;
        scopeYaml: string;
      };
      expect(scopePayload.programId).toBe(programId);
      expect(scopePayload.authorizedDomains).toEqual(
        expect.arrayContaining([
          '*.acme.internal',
          'portal.acme.internal',
          'api.acme.internal',
        ]),
      );
      expect(scopePayload.excludedHosts).toContain('blog.acme.internal');
      expect(scopePayload.excludedPaths).toContain('/admin/destruct/**');
      expect(scopePayload.maxRpsPerHost).toBe(12);
      expect(scopePayload.complianceHeaders['X-Bug-Bounty-Researcher']).toBe(
        'bugcrowd-e2e-tester',
      );
      expect(scopePayload.scopeYaml).toContain('blog.acme.internal');

      // 3c. Verify event: log stages
      const logEntries = frames
        .filter((f) => f.event === 'log')
        .map((f) => f.data as ProgramLogEntry);
      const observedStages = new Set(logEntries.map((l) => l.stage));
      expect(observedStages.has('INGEST')).toBe(true);
      expect(observedStages.has('SANDBOX')).toBe(true);
      expect(observedStages.has('EGRESS')).toBe(true);
      expect(observedStages.has('RECON')).toBe(true);
      expect(observedStages.has('POSTURE_AUDIT')).toBe(true);
      expect(observedStages.has('ORCHESTRATOR_REVIEW')).toBe(true);

      // 3c-bis. Verify event: squad_event real-time timeline frames
      const squadFrames = frames
        .filter((f) => f.event === 'squad_event')
        .map((f) => f.data as SquadTimelineEvent & { programId: string });
      expect(squadFrames.length).toBeGreaterThanOrEqual(15);
      expect(squadFrames.every((ev) => ev.programId === programId)).toBe(true);
      const observedSquadKinds = new Set(squadFrames.map((ev) => ev.kind));
      expect(observedSquadKinds.has('user_brief')).toBe(true);
      expect(observedSquadKinds.has('spawn_agent')).toBe(true);
      expect(observedSquadKinds.has('think')).toBe(true);
      expect(observedSquadKinds.has('threat_model')).toBe(true);
      expect(observedSquadKinds.has('hypothesis')).toBe(true);
      expect(observedSquadKinds.has('recon_step')).toBe(true);
      expect(observedSquadKinds.has('coverage')).toBe(true);
      expect(observedSquadKinds.has('verification')).toBe(true);
      expect(observedSquadKinds.has('agent_message')).toBe(true);
      expect(observedSquadKinds.has('assistant_synthesis')).toBe(true);

      // 3d. Verify event: assistant_delta chunks & event: done
      const deltaFrames = frames.filter((f) => f.event === 'assistant_delta');
      expect(deltaFrames.length).toBeGreaterThan(0);
      const fullStreamedReply = deltaFrames
        .map((f) => (f.data as { delta: string }).delta)
        .join('');
      expect(fullStreamedReply.trim().length).toBeGreaterThan(40);

      const doneFrame = frames.find((f) => f.event === 'done');
      expect(doneFrame).toBeDefined();
      expect((doneFrame!.data as { programId: string }).programId).toBe(
        programId,
      );

      // 4. Verify program-scoped REST endpoints
      const programsListRes = await app.request('/api/programs');
      expect(programsListRes.status).toBe(200);
      const { programs } = (await programsListRes.json()) as {
        programs: ProgramSummaryItem[];
      };
      expect(programs).toHaveLength(1);
      expect(programs[0]?.programId).toBe(programId);
      expect(programs[0]?.excludedHosts).toContain('blog.acme.internal');
      expect(programs[0]?.maxRpsPerHost).toBe(12);
      expect(programs[0]?.pendingFindings).toBeGreaterThanOrEqual(2);
      expect(programs[0]?.canonicalEndpoints).toBeGreaterThanOrEqual(4);
      expect(programs[0]?.hostsDiscovered).toBeGreaterThanOrEqual(2);

      // Overview
      const overviewRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/overview`,
      );
      expect(overviewRes.status).toBe(200);
      const overview = (await overviewRes.json()) as {
        engagement: {
          engagementId: string;
          excludedHosts: string[];
          maxRpsPerHost: number;
          complianceHeaders: Record<string, string>;
        };
        scopeYaml: string;
        runtime: {
          sandboxProvider: string;
          orchestratorProvider: string;
          orchestratorModel: string;
        };
        metrics: {
          blockedScope451: number;
          canonicalEndpoints: number;
          pendingFindings: number;
        };
      };
      expect(overview.engagement.engagementId).toBe(programId);
      expect(overview.engagement.excludedHosts).toContain('blog.acme.internal');
      expect(overview.engagement.maxRpsPerHost).toBe(12);
      expect(
        overview.engagement.complianceHeaders['X-Bug-Bounty-Researcher'],
      ).toBe('bugcrowd-e2e-tester');
      expect(overview.scopeYaml).toContain('maxRpsPerHost: 12');
      expect(overview.runtime.sandboxProvider).toBe('e2b');
      expect(overview.runtime.orchestratorProvider).toBe('openrouter');
      expect(overview.runtime.orchestratorModel).toBe('stealth/crouton-alpha');
      expect(overview.metrics.blockedScope451).toBeGreaterThanOrEqual(3);

      // Messages
      const messagesRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/messages`,
      );
      expect(messagesRes.status).toBe(200);
      const { messages } = (await messagesRes.json()) as {
        messages: ChatMessageItem[];
      };
      expect(messages).toHaveLength(2);
      expect(messages[0]?.role).toBe('user');
      expect(messages[1]?.role).toBe('assistant');
      expect(messages[1]?.status).toBe('completed');
      expect(messages[1]?.content).toBe(fullStreamedReply);
      expect((messages[1]?.logs ?? []).length).toBeGreaterThanOrEqual(6);

      // Logs
      const logsRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/logs`,
      );
      expect(logsRes.status).toBe(200);
      const { logs } = (await logsRes.json()) as {
        logs: ProgramLogEntry[];
      };
      expect(logs.length).toBeGreaterThanOrEqual(6);
      expect(logs.every((l) => l.programId === programId)).toBe(true);

      // Surface Graph
      const graphRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/surface/graph`,
      );
      expect(graphRes.status).toBe(200);
      const graph = (await graphRes.json()) as {
        nodes: Array<{ id: string; type: string }>;
        edges: Array<{ id: string; relation: string }>;
      };
      expect(graph.nodes.some((n) => n.type === 'ENDPOINT')).toBe(true);
      expect(graph.edges.some((e) => e.relation === 'HAS_FINDING')).toBe(true);

      // Findings & HITL Decision
      const findingsRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/findings`,
      );
      expect(findingsRes.status).toBe(200);
      const { findings } = (await findingsRes.json()) as {
        findings: Array<{
          findingId: string;
          status: string;
          category: string;
          evidencePointers: Array<{ sha256: string }>;
        }>;
      };
      expect(findings.length).toBeGreaterThanOrEqual(2);
      expect(
        findings.every((f) => f.status === 'PENDING_HUMAN_REVIEW'),
      ).toBe(true);

      const firstFinding = findings[0]!;
      const evidenceSha = firstFinding.evidencePointers[0]?.sha256;
      expect(evidenceSha).toMatch(/^[a-f0-9]{64}$/);

      // Program-scoped & cross-workspace blob lookup
      const scopedBlobRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/blobs/${evidenceSha}`,
      );
      expect(scopedBlobRes.status).toBe(200);
      const globalBlobRes = await app.request(`/api/blobs/${evidenceSha}`);
      expect(globalBlobRes.status).toBe(200);

      // Approve finding on program-scoped endpoint
      const progDecisionRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/findings/${encodeURIComponent(firstFinding.findingId)}/decision`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            status: 'APPROVED',
            reviewerNote: 'Validated during Bugcrowd multi-program E2E check.',
          }),
        },
      );
      expect(progDecisionRes.status).toBe(200);

      // GitOps History
      const gitopsRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/gitops/history`,
      );
      expect(gitopsRes.status).toBe(200);
      const gitops = (await gitopsRes.json()) as {
        branches: string[];
        commits: Array<{ sha: string; message: string }>;
        reviews: Array<{ decision: string }>;
      };
      expect(gitops.branches).toContain('main');
      expect(gitops.commits.length).toBeGreaterThanOrEqual(4);
      expect(gitops.reviews.some((r) => r.decision === 'APPROVE_MERGE')).toBe(
        true,
      );

      // Traffic Ledger (must include HTTP 451 block on excluded host blog.acme.internal)
      const trafficRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/traffic`,
      );
      expect(trafficRes.status).toBe(200);
      const { entries: trafficEntries } = (await trafficRes.json()) as {
        entries: Array<{ host: string; url: string; decision: string }>;
      };
      expect(
        trafficEntries.some(
          (e) =>
            e.host === 'blog.acme.internal' &&
            e.decision === 'BLOCKED_SCOPE_451',
        ),
      ).toBe(true);

      // 5. Verify GET /api/programs/:programId/squad & 404 handling
      const missingSquadRes = await app.request(
        '/api/programs/prog-does-not-exist/squad',
      );
      expect(missingSquadRes.status).toBe(404);

      const missingSteerRes = await app.request(
        '/api/programs/prog-does-not-exist/steer',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: 'Focus on /v1/org/settings' }),
        },
      );
      expect(missingSteerRes.status).toBe(404);

      const squadRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/squad`,
      );
      expect(squadRes.status).toBe(200);
      const initialSquad: SquadRunState = SquadRunStateSchema.parse(
        await squadRes.json(),
      );
      expect(initialSquad.programId).toBe(programId);
      expect(initialSquad.status).toBe('completed');
      expect(initialSquad.agents).toHaveLength(5);

      const hunterAgent = initialSquad.agents.find(
        (a) => a.role === 'hypothesis_hunter',
      )!;
      expect(hunterAgent).toBeDefined();
      const cartographerAgent = initialSquad.agents.find(
        (a) => a.role === 'cartographer',
      )!;
      expect(cartographerAgent).toBeDefined();

      // Verify squad-state.json was persisted atomically on disk
      const persistedSquadFile = path.join(
        tempDir,
        'programs',
        programId,
        'squad-state.json',
      );
      const diskRawBeforeSteer = await fs.readFile(persistedSquadFile, 'utf8');
      expect(
        SquadRunStateSchema.parse(JSON.parse(diskRawBeforeSteer)).programId,
      ).toBe(programId);

      // 6. Live Agent Steering via POST /api/programs/:programId/steer SSE
      const steerRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/steer`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            targetAgentId: hunterAgent.id,
            message:
              'Focus on CORS preflight credential reflection on /v1/org/settings and outline read-only counterevidence checks.',
          }),
        },
      );
      expect(steerRes.status).toBe(200);
      expect(steerRes.headers.get('content-type')).toContain(
        'text/event-stream',
      );

      const steerFrames = parseSseFrames(await steerRes.text());
      expect(steerFrames.some((f) => f.event === 'error')).toBe(false);

      const steerSquadEvents = steerFrames
        .filter((f) => f.event === 'squad_event')
        .map((f) => f.data as SquadTimelineEvent & { programId: string });
      expect(steerSquadEvents.length).toBeGreaterThanOrEqual(4);
      expect(
        steerSquadEvents.every((ev) => ev.agentId === hunterAgent.id),
      ).toBe(true);
      const steerKinds = new Set(steerSquadEvents.map((ev) => ev.kind));
      expect(steerKinds.has('user_brief')).toBe(true);
      expect(steerKinds.has('think')).toBe(true);
      expect(steerKinds.has('hypothesis')).toBe(true);
      expect(steerKinds.has('assistant_synthesis')).toBe(true);

      const steerDeltaText = steerFrames
        .filter((f) => f.event === 'assistant_delta')
        .map((f) => (f.data as { delta: string }).delta)
        .join('');
      expect(steerDeltaText.trim().length).toBeGreaterThan(30);
      expect(
        steerFrames.some(
          (f) =>
            f.event === 'telemetry_refresh' &&
            (f.data as { reason?: string }).reason === 'agent_steered',
        ),
      ).toBe(true);
      expect(
        steerFrames.some(
          (f) =>
            f.event === 'done' &&
            (f.data as { targetAgentId?: string }).targetAgentId ===
              hunterAgent.id,
        ),
      ).toBe(true);

      // 7. Live Agent Steering via POST /api/chat/stream with targetAgentId
      const chatSteerRes = await app.request('/api/chat/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          programId,
          targetAgentId: cartographerAgent.id,
          message:
            'Inspect parameterized /v1/users/{param}/roles schema drift from offline OpenAPI and JS AST observations.',
        }),
      });
      expect(chatSteerRes.status).toBe(200);
      const chatSteerFrames = parseSseFrames(await chatSteerRes.text());
      expect(chatSteerFrames.some((f) => f.event === 'error')).toBe(false);
      expect(
        chatSteerFrames.some(
          (f) =>
            f.event === 'done' &&
            (f.data as { targetAgentId?: string }).targetAgentId ===
              cartographerAgent.id,
        ),
      ).toBe(true);

      const updatedSquadRes = await app.request(
        `/api/programs/${encodeURIComponent(programId)}/squad`,
      );
      const updatedSquad = SquadRunStateSchema.parse(
        await updatedSquadRes.json(),
      );
      expect(updatedSquad.hypotheses.length).toBeGreaterThan(
        initialSquad.hypotheses.length,
      );
      expect(updatedSquad.timeline.length).toBeGreaterThan(
        initialSquad.timeline.length,
      );
      expect(
        (updatedSquad.threatModel?.amendments.length ?? 0),
      ).toBeGreaterThan(initialSquad.threatModel?.amendments.length ?? 0);

      // 8. Verify startup hydration when an existing persisted workspace lacks squad-state.json
      await manager.close();
      await fs.rm(persistedSquadFile, { force: true });

      const reloadedManager = new ProgramWorkspaceManager({
        dataDir: tempDir,
        useDemoTarget: false,
        useCloudSandbox: false,
      });
      await reloadedManager.init();
      const hydratedSquad = await reloadedManager.getSquadState(programId);
      expect(hydratedSquad).not.toBeNull();
      const parsedHydrated = SquadRunStateSchema.parse(hydratedSquad);
      expect(parsedHydrated.programId).toBe(programId);
      expect(parsedHydrated.agents).toHaveLength(5);
      const rehydratedDiskRaw = await fs.readFile(persistedSquadFile, 'utf8');
      expect(
        SquadRunStateSchema.parse(JSON.parse(rehydratedDiskRaw)).agents,
      ).toHaveLength(5);
      await reloadedManager.close();
    },
    180_000,
  );
});


