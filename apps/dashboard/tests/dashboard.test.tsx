import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { App } from '../src/App';
import { DashboardController } from '../src/dashboardController';
import { CANDID_VDP_BRIEF, FIRECRAWL_VDP_BRIEF } from '../src/emptyState';
import { renderMarkdownBlocks } from '../src/markdown';
import { consumeSseBuffer } from '../src/sseParser';
import type { SquadRunState } from '../src/types';

function createJsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function createSseResponse(chunks: string[]): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(streamController) {
      for (const chunk of chunks) {
        streamController.enqueue(encoder.encode(chunk));
      }
      streamController.close();
    },
  });

  return new Response(stream, {
    status: 200,
    headers: { 'Content-Type': 'text/event-stream' },
  });
}

describe('@opencyber/dashboard zero-mock responsive workspace verification', () => {
  it('1. starts with an honest zero-mock Launchpad state (no fake Acme programs, single <h1>, zero "+ +" bug)', () => {
    const controller = new DashboardController();
    const snap = controller.getSnapshot();
    expect(snap.programs).toEqual([]);
    expect(snap.activeProgramId).toBeNull();
    expect(snap.findings).toEqual([]);

    const html = renderToStaticMarkup(<App controller={controller} />);
    const h1Matches = html.match(/<h1\b/g) ?? [];
    expect(h1Matches).toHaveLength(1);
    expect(html).not.toContain('+ +');
    expect(html).not.toContain('Acme FinTech');
    expect(html).toContain('id="btn-new-engagement"');
    expect(html).toContain('id="nav-operations"');
    expect(html).toContain('id="nav-hypotheses"');
    expect(html).toContain('id="nav-recon"');
    expect(html).toContain('id="nav-findings"');
    expect(html).toContain('id="nav-gitops"');
  });

  it('2. switches between real Bugcrowd Safe-Harbor VDP templates in NewEngagementModal', () => {
    const controller = new DashboardController();
    controller.openNewEngagementModal();
    expect(controller.getSnapshot().newEngagementBrief).toBe('');

    controller.applyBriefPreset('firecrawl');
    expect(controller.getSnapshot().newEngagementBrief).toBe(FIRECRAWL_VDP_BRIEF);

    controller.applyBriefPreset('candid');
    expect(controller.getSnapshot().newEngagementBrief).toBe(CANDID_VDP_BRIEF);

    const html = renderToStaticMarkup(<App controller={controller} />);
    expect(html).toContain('Real Bugcrowd Safe-Harbor VDP Briefs');
    expect(html).toContain('Candid VDP Pro Brief');
  });

  it('3. hydrates live multi-agent SquadRunState and inspects XML Mission Prompt & context telemetry', async () => {
    const squadFixture: SquadRunState = {
      programId: 'prog-firecrawl-live',
      runId: 'run-01',
      status: 'completed',
      startedAt: '2026-11-05T12:00:00Z',
      completedAt: '2026-11-05T12:02:00Z',
      agents: [
        {
          id: 'orch-1',
          parentId: null,
          name: 'Lead Squad Orchestrator',
          role: 'orchestrator',
          model: 'stealth/crouton-alpha',
          provider: 'openrouter',
          skills: ['threat-modeling'],
          status: 'completed',
          task: 'Coordinate scope-governed assessment',
          missionPrompt: '<mission_objective>Coordinate assessment</mission_objective>',
          systemDirective: 'Never send mutating probes.',
          toolCallCount: 4,
          messageCount: 3,
          createdAt: '2026-11-05T12:00:00Z',
          updatedAt: '2026-11-05T12:02:00Z',
          contextStats: {
            estimatedTokens: 2100,
            maxTokens: 12000,
            compactionCount: 1,
            checkpointSummary: 'Verified 2 hosts and 6 canonical endpoints.',
          },
        },
      ],
      hypotheses: [
        {
          id: 'HYP-01',
          createdByAgentId: 'orch-1',
          phase: 'POSTURE_VERIFICATION',
          surface: 'https://api.firecrawl.dev/v1/scrape',
          riskCategory: 'CROSS_ORIGIN_POLICY',
          observation: 'API serves cross-origin SDK requests',
          statement: 'Verify Access-Control-Allow-Credentials pairing',
          confidence: 10,
          confidenceHistory: [
            {
              timestamp: '2026-11-05T12:01:00Z',
              confidence: 10,
              delta: -40,
              reason: 'ACAC header absent',
              agentName: 'Lead Squad Orchestrator',
            },
          ],
          testPlan: 'OPTIONS check via Egress Gateway',
          closureState: 'ruled_out',
          namedControlOrProof: 'Access-Control-Allow-Credentials omitted on Bearer-only API',
          counterevidence: '',
          createdAt: '2026-11-05T12:00:10Z',
          updatedAt: '2026-11-05T12:01:00Z',
        },
      ],
      threatModel: {
        target: '*.firecrawl.dev',
        summary: 'Public developer scraping API perimeter',
        trustBoundaries: ['Browser Origin -> API Gateway'],
        attackerRoles: ['Unauthenticated client'],
        highValueAssets: ['API v1 routes'],
        inferredAssumptions: ['Out-of-scope hosts return HTTP 451'],
        amendments: [],
        updatedAt: '2026-11-05T12:00:05Z',
      },
      coverage: [
        {
          id: 'cov-1',
          surface: 'GET https://docs.firecrawl.dev/',
          riskArea: 'Scope Exclusion',
          outcome: 'blocked_451',
          previousOutcomes: [],
          evidence: 'Blocked with HTTP 451 at Mandatory Egress Gateway',
          agentId: 'orch-1',
          agentName: 'Lead Squad Orchestrator',
          updatedAt: '2026-11-05T12:00:15Z',
        },
      ],
      timeline: [
        {
          seq: 1,
          id: 'ev-1',
          timestamp: '2026-11-05T12:00:02Z',
          agentId: 'orch-1',
          agentName: 'Lead Squad Orchestrator',
          agentRole: 'orchestrator',
          kind: 'think',
          title: 'Initialized scope governance',
          detail: 'Verified read-only GET/HEAD/OPTIONS policy.',
          status: 'completed',
        },
      ],
    };

    const mockFetch: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith('/api/programs')) {
        return createJsonResponse({
          programs: [
            {
              programId: 'prog-firecrawl-live',
              programName: 'Firecrawl VDP',
              authorizedDomains: ['*.firecrawl.dev'],
              excludedHosts: ['docs.firecrawl.dev'],
              excludedPaths: [],
              maxRpsPerHost: 3,
              pipelineRunning: false,
              pendingFindings: 0,
              approvedFindings: 0,
              canonicalEndpoints: 4,
              hostsDiscovered: 2,
              createdAt: '2026-11-05T12:00:00Z',
              updatedAt: '2026-11-05T12:02:00Z',
            },
          ],
        });
      }
      if (url.includes('/squad')) {
        return createJsonResponse(squadFixture);
      }
      if (url.includes('/overview')) {
        return createJsonResponse({
          engagement: {
            engagementId: 'prog-firecrawl-live',
            programName: 'Firecrawl VDP',
            authorizedDomains: ['*.firecrawl.dev'],
            excludedHosts: ['docs.firecrawl.dev'],
            excludedPaths: [],
            maxRpsPerHost: 3,
            strictReadOnly: true,
          },
          runtime: {
            sandboxProvider: 'e2b',
            orchestratorModel: 'stealth/crouton-alpha',
            subagentModel: 'qwen/qwen3.8-27b',
            promptGuardModel: 'meta-llama/llama-prompt-guard-2-86m',
            pipelineRunning: false,
          },
          metrics: {
            hostsDiscovered: 2,
            canonicalEndpoints: 4,
            compliantTombstones: 4,
            pendingFindings: 0,
            approvedFindings: 0,
            allowedRequests: 6,
            blockedScope451: 1,
            blockedRps429: 0,
          },
        });
      }
      return createJsonResponse({});
    };

    const controller = new DashboardController({ fetchImpl: mockFetch });
    await controller.hydrateFromServer();

    controller.openAgentInspector('orch-1', 'prompt');
    const modalHtml = renderToStaticMarkup(<App controller={controller} />);
    expect(modalHtml).toContain('Coordinate assessment');

    controller.closeAgentInspector();
    controller.setActiveView('hypotheses');
    const hypHtml = renderToStaticMarkup(<App controller={controller} />);
    expect(hypHtml).toContain('HYP-01');
    expect(hypHtml).toContain('Access-Control-Allow-Credentials omitted');
  });

  it('4. parses split CRLF/LF SSE chunks and renders XSS-safe Markdown', async () => {
    const sse = consumeSseBuffer(
      'event: squad_event\r\ndata: {"seq":1,"id":"e1","timestamp":"2026-11-05T00:00:00Z","agentId":"a1","agentName":"Orchestrator","agentRole":"orchestrator","kind":"think","title":"Step","detail":"Ok","status":"completed"}\r\n\r\n',
      true,
    );
    expect(sse.frames).toHaveLength(1);

    const mdHtml = renderToStaticMarkup(
      <div>{renderMarkdownBlocks('Safe **bold** and <script>alert(1)</script>')}</div>,
    );
    expect(mdHtml).toContain('<strong class="oc-md-strong">bold</strong>');
    expect(mdHtml).not.toContain('<script>');

    const streamFetch: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith('/api/chat/stream')) {
        return createSseResponse([
          'event: program_selected\ndata: {"programId":"prog-1","programName":"Firecrawl VDP","isNew":true,"assistantMessageId":"m1"}\n\n',
          'event: assistant_delta\ndata: {"programId":"prog-1","messageId":"m1","delta":"Assessment complete."}\n\n',
          'event: done\ndata: {"programId":"prog-1","messageId":"m1"}\n\n',
        ]);
      }
      return createJsonResponse({ programs: [] });
    };

    const controller = new DashboardController({ fetchImpl: streamFetch });
    await controller.launchNewEngagement(FIRECRAWL_VDP_BRIEF);
    expect(controller.getSnapshot().streamingSynthesisText).toContain(
      'Assessment complete.',
    );
  });
});
