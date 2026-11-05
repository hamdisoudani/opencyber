import { randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { RetrievedBlob } from '@opencyber/gitops-engine';
import { FindingStatusSchema } from '@opencyber/shared';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { z } from 'zod';
import type { AegisControlPlaneEngine } from './pipeline.js';
import type {
  ProgramSummaryItem,
  ProgramWorkspaceManager,
} from './workspace-manager.js';

const RunAssessmentRequestSchema = z.object({
  useCloudSandbox: z.boolean().optional(),
  waitForCompletion: z.boolean().optional(),
});

const FindingDecisionRequestSchema = z.object({
  status: z.enum(['APPROVED', 'REJECTED']),
  reviewerNote: z.string().optional().default(''),
});

const ChatStreamRequestSchema = z.object({
  programId: z.string().trim().min(1).optional(),
  targetAgentId: z.string().trim().min(1).optional(),
  message: z.string(),
  useCloudSandbox: z.boolean().optional(),
});

const SteerSquadRequestSchema = z.object({
  targetAgentId: z.string().trim().min(1).optional(),
  agentId: z.string().trim().min(1).optional(),
  message: z.string(),
  useCloudSandbox: z.boolean().optional(),
});

const MIME_BY_EXT: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

function resolveDashboardDistDir(): string {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(currentDir, '../../dashboard/dist');
}

function isWorkspaceManager(
  target: AegisControlPlaneEngine | ProgramWorkspaceManager,
): target is ProgramWorkspaceManager {
  return (
    'listPrograms' in target &&
    typeof (target as ProgramWorkspaceManager).listPrograms === 'function'
  );
}

function formatBlobPayload(
  sha256: string,
  blob: RetrievedBlob,
): Record<string, unknown> {
  const text = blob.content.toString('utf8');
  let parsedJson: unknown;
  if (blob.mediaType.includes('json')) {
    try {
      parsedJson = JSON.parse(text);
    } catch {
      parsedJson = undefined;
    }
  }

  return {
    sha256,
    mediaType: blob.mediaType,
    sizeBytes: blob.sizeBytes,
    metadata: blob.metadata,
    text,
    ...(parsedJson !== undefined ? { data: parsedJson } : {}),
  };
}

async function readStaticAssetSafe(
  distDir: string,
  relRequestPath: string,
): Promise<{ content: Buffer; contentType: string } | null> {
  const sanitizedRel = relRequestPath.replace(/\\/g, '/').replace(/^\/+/, '');
  const candidate = path.resolve(distDir, sanitizedRel);
  const relCheck = path.relative(distDir, candidate);
  if (relCheck.startsWith('..') || path.isAbsolute(relCheck)) {
    return null;
  }

  try {
    const stat = await fs.stat(candidate);
    if (!stat.isFile()) {
      return null;
    }
    const content = await fs.readFile(candidate);
    const ext = path.extname(candidate).toLowerCase();
    const contentType = MIME_BY_EXT[ext] ?? 'application/octet-stream';
    return { content, contentType };
  } catch {
    return null;
  }
}

export function createControlPlaneServer(
  engineOrManager: AegisControlPlaneEngine | ProgramWorkspaceManager,
): Hono {
  const app = new Hono();
  const dashboardDistDir = resolveDashboardDistDir();
  const manager = isWorkspaceManager(engineOrManager) ? engineOrManager : null;

  const resolveLegacyEngine = async (): Promise<AegisControlPlaneEngine> => {
    if (manager) {
      return manager.getOrCreateDefaultEngine();
    }
    return engineOrManager as AegisControlPlaneEngine;
  };

  const resolveProgramEngine = async (
    programId: string,
  ): Promise<AegisControlPlaneEngine | null> => {
    if (manager) {
      return manager.getWorkspaceEngine(programId);
    }
    const singleEngine = engineOrManager as AegisControlPlaneEngine;
    if (singleEngine.scope.engagementId === programId) {
      return singleEngine;
    }
    return null;
  };

  app.use('*', cors());

  app.get('/api/health', (c) => {
    return c.json({ ok: true });
  });

  // ---------------------------------------------------------------------------
  // Multi-Program & Chat-First Orchestrator SSE Routes
  // ---------------------------------------------------------------------------
  app.get('/api/programs', async (c) => {
    if (manager) {
      const programs = await manager.listPrograms();
      return c.json({ programs });
    }

    const singleEngine = engineOrManager as AegisControlPlaneEngine;
    const overview = await singleEngine.getOverview();
    const fallbackNow = overview.runtime.lastRunAt ?? new Date().toISOString();
    const singleSummary: ProgramSummaryItem = {
      programId: overview.engagement.engagementId,
      programName: overview.engagement.programName,
      authorizedDomains: overview.engagement.authorizedDomains,
      excludedHosts: overview.engagement.excludedHosts,
      excludedPaths: overview.engagement.excludedPaths,
      maxRpsPerHost: overview.engagement.maxRpsPerHost,
      pipelineRunning: overview.runtime.pipelineRunning,
      pendingFindings: overview.metrics.pendingFindings,
      approvedFindings: overview.metrics.approvedFindings,
      canonicalEndpoints: overview.metrics.canonicalEndpoints,
      hostsDiscovered: overview.metrics.hostsDiscovered,
      createdAt: fallbackNow,
      updatedAt: fallbackNow,
    };
    return c.json({ programs: [singleSummary] });
  });

  app.post('/api/chat/stream', async (c) => {
    if (!manager) {
      return c.json(
        { error: 'WORKSPACE_MANAGER_REQUIRED_FOR_CHAT_STREAM' },
        501,
      );
    }

    let rawBody: unknown;
    try {
      rawBody = await c.req.json();
    } catch {
      return c.json({ error: 'INVALID_JSON_BODY' }, 400);
    }

    const parsed = ChatStreamRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      return c.json(
        { error: 'INVALID_CHAT_PAYLOAD', issues: parsed.error.issues },
        400,
      );
    }

    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        let closed = false;
        const sendEvent = (event: string, data: unknown): void => {
          if (closed) {
            return;
          }
          try {
            const frame = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
            controller.enqueue(encoder.encode(frame));
          } catch {
            closed = true;
          }
        };

        try {
          await manager.handleChatStream({
            ...(parsed.data.programId !== undefined
              ? { programId: parsed.data.programId }
              : {}),
            ...(parsed.data.targetAgentId !== undefined
              ? { targetAgentId: parsed.data.targetAgentId }
              : {}),
            message: parsed.data.message,
            ...(parsed.data.useCloudSandbox !== undefined
              ? { useCloudSandbox: parsed.data.useCloudSandbox }
              : {}),
            sendEvent,
          });
        } catch (err: unknown) {
          const errMessage = err instanceof Error ? err.message : String(err);
          sendEvent('error', { message: errMessage });
        } finally {
          if (!closed) {
            closed = true;
            try {
              controller.close();
            } catch {
              // Ignore if client closed stream early
            }
          }
        }
      },
    });

    return new Response(stream, {
      status: 200,
      headers: {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      },
    });
  });

  app.get('/api/programs/:programId/overview', async (c) => {
    const programId = c.req.param('programId');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }
    const overview = await programEngine.getOverview();
    return c.json(overview);
  });

  app.post('/api/programs/:programId/assessments/run', async (c) => {
    const programId = c.req.param('programId');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }

    let rawBody: unknown = {};
    try {
      const text = await c.req.text();
      if (text.trim().length > 0) {
        rawBody = JSON.parse(text);
      }
    } catch {
      return c.json({ error: 'INVALID_JSON_BODY' }, 400);
    }

    const parsed = RunAssessmentRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      return c.json(
        { error: 'INVALID_RUN_PAYLOAD', issues: parsed.error.issues },
        400,
      );
    }

    const { useCloudSandbox, waitForCompletion } = parsed.data;
    if (waitForCompletion === true) {
      const summary = await programEngine.runFullAssessment({
        ...(useCloudSandbox !== undefined ? { useCloudSandbox } : {}),
      });
      return c.json({
        started: true,
        runId: summary.runId,
        summary,
      });
    }

    const triggered = programEngine.triggerBackgroundAssessment({
      ...(useCloudSandbox !== undefined ? { useCloudSandbox } : {}),
    });

    return c.json({
      started: true,
      runId: triggered.runId,
    });
  });

  app.get('/api/programs/:programId/messages', async (c) => {
    const programId = c.req.param('programId');
    if (manager) {
      const messages = await manager.getMessages(programId);
      if (!messages) {
        return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
      }
      return c.json({ messages });
    }

    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }
    return c.json({ messages: [] });
  });

  app.get('/api/programs/:programId/logs', async (c) => {
    const programId = c.req.param('programId');
    if (manager) {
      const logs = await manager.getLogs(programId);
      if (!logs) {
        return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
      }
      return c.json({ logs });
    }

    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }
    return c.json({ logs: [] });
  });

  app.get('/api/programs/:programId/surface/graph', async (c) => {
    const programId = c.req.param('programId');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }

    const snapshot = await programEngine.getSurfaceGraph();
    return c.json({
      nodes: snapshot.nodes,
      edges: snapshot.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        relation: e.type,
      })),
    });
  });

  app.get('/api/programs/:programId/findings', async (c) => {
    const programId = c.req.param('programId');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }

    const rawStatus = c.req.query('status');
    let statusFilter: z.infer<typeof FindingStatusSchema> | undefined;
    if (rawStatus) {
      const parsedStatus = FindingStatusSchema.safeParse(rawStatus);
      if (!parsedStatus.success) {
        return c.json(
          { error: 'INVALID_FINDING_STATUS', status: rawStatus },
          400,
        );
      }
      statusFilter = parsedStatus.data;
    }

    const findings = await programEngine.listFindings(statusFilter);
    return c.json({ findings });
  });

  app.post(
    '/api/programs/:programId/findings/:findingId/decision',
    async (c) => {
      const programId = c.req.param('programId');
      const findingId = c.req.param('findingId');
      const programEngine = await resolveProgramEngine(programId);
      if (!programEngine) {
        return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
      }

      let rawBody: unknown;
      try {
        rawBody = await c.req.json();
      } catch {
        return c.json({ error: 'INVALID_JSON_BODY' }, 400);
      }

      const parsed = FindingDecisionRequestSchema.safeParse(rawBody);
      if (!parsed.success) {
        return c.json(
          { error: 'INVALID_DECISION_PAYLOAD', issues: parsed.error.issues },
          400,
        );
      }

      const updated = await programEngine.decideFinding(
        findingId,
        parsed.data.status,
        parsed.data.reviewerNote,
      );

      if (!updated) {
        return c.json({ error: 'FINDING_NOT_FOUND', findingId }, 404);
      }

      return c.json({ finding: updated });
    },
  );

  app.get('/api/programs/:programId/gitops/history', async (c) => {
    const programId = c.req.param('programId');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }

    const rawLimit = c.req.query('limit');
    const limit = rawLimit
      ? Math.min(200, Math.max(1, Number.parseInt(rawLimit, 10) || 50))
      : 50;

    const history = await programEngine.getGitOpsHistory(limit);
    return c.json({
      branches: history.branches,
      commits: history.commits,
      reviews: history.reviews.map((r) => ({
        id: r.id,
        branchName: r.branchName,
        taskId: r.taskId,
        ciPassed: r.ciPassed,
        decision: r.decision,
        rationale: r.rationale,
        ...(r.commitSha ? { commitSha: r.commitSha } : {}),
        createdAt: r.createdAt,
      })),
    });
  });

  app.get('/api/programs/:programId/traffic', async (c) => {
    const programId = c.req.param('programId');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }

    const rawLimit = c.req.query('limit');
    const limit = rawLimit
      ? Math.min(5000, Math.max(1, Number.parseInt(rawLimit, 10) || 250))
      : 250;

    const entries = await programEngine.listTraffic(limit);
    return c.json({ entries });
  });

  app.get('/api/programs/:programId/blobs/:sha256', async (c) => {
    const programId = c.req.param('programId');
    const sha256 = c.req.param('sha256');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }

    const blob = await programEngine.getBlob(sha256);
    if (!blob) {
      return c.json({ error: 'BLOB_NOT_FOUND', sha256 }, 404);
    }

    return c.json(formatBlobPayload(sha256, blob));
  });

  app.get('/api/programs/:programId/repo/files', async (c) => {
    const programId = c.req.param('programId');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }
    const files = await programEngine.listRepoFiles();
    return c.json({ files });
  });

  app.get('/api/programs/:programId/repo/file', async (c) => {
    const programId = c.req.param('programId');
    const reqPath = c.req.query('path') ?? '';
    if (!reqPath.trim()) {
      return c.json({ error: 'MISSING_FILE_PATH' }, 400);
    }
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }
    const file = await programEngine.readRepoFile(reqPath);
    if (!file) {
      return c.json({ error: 'FILE_NOT_FOUND', path: reqPath }, 404);
    }
    return c.json(file);
  });

  app.get('/api/programs/:programId/gitops/commits/:sha', async (c) => {
    const programId = c.req.param('programId');
    const sha = c.req.param('sha');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }
    const diff = await programEngine.getCommitDiff(sha);
    if (!diff) {
      return c.json({ error: 'COMMIT_NOT_FOUND', sha }, 404);
    }
    return c.json(diff);
  });

  app.get('/api/programs/:programId/squad', async (c) => {
    const programId = c.req.param('programId');
    if (manager) {
      const squadState = await manager.getSquadState(programId);
      if (!squadState) {
        return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
      }
      return c.json(squadState);
    }

    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }
    const squadState = await programEngine.getSquadState();
    return c.json(squadState);
  });

  app.post('/api/programs/:programId/steer', async (c) => {
    const programId = c.req.param('programId');
    const programEngine = await resolveProgramEngine(programId);
    if (!programEngine) {
      return c.json({ error: 'PROGRAM_NOT_FOUND', programId }, 404);
    }

    let rawBody: unknown;
    try {
      rawBody = await c.req.json();
    } catch {
      return c.json({ error: 'INVALID_JSON_BODY' }, 400);
    }

    const parsed = SteerSquadRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      return c.json(
        { error: 'INVALID_STEER_PAYLOAD', issues: parsed.error.issues },
        400,
      );
    }

    const effectiveTargetAgentId =
      parsed.data.targetAgentId ?? parsed.data.agentId;

    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        let closed = false;
        const sendEvent = (event: string, data: unknown): void => {
          if (closed) {
            return;
          }
          try {
            const frame = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
            controller.enqueue(encoder.encode(frame));
          } catch {
            closed = true;
          }
        };

        try {
          if (manager) {
            await manager.handleSteerStream({
              programId,
              ...(effectiveTargetAgentId !== undefined
                ? { targetAgentId: effectiveTargetAgentId }
                : {}),
              message: parsed.data.message,
              ...(parsed.data.useCloudSandbox !== undefined
                ? { useCloudSandbox: parsed.data.useCloudSandbox }
                : {}),
              sendEvent,
            });
          } else {
            const trimmedMessage = parsed.data.message.trim();
            if (!trimmedMessage) {
              sendEvent('error', { message: 'Message cannot be empty.' });
              return;
            }

            const assistantMessageId = randomUUID();
            sendEvent('program_selected', {
              programId,
              programName: programEngine.scope.programName,
              isNew: false,
              assistantMessageId,
              ...(effectiveTargetAgentId !== undefined
                ? { targetAgentId: effectiveTargetAgentId }
                : {}),
            });

            const steerRes = await programEngine.steerSquadAgent({
              ...(effectiveTargetAgentId !== undefined
                ? { targetAgentId: effectiveTargetAgentId }
                : {}),
              message: trimmedMessage,
              onSquadEvent: async (ev) => {
                sendEvent('squad_event', { ...ev, programId });
              },
              onDelta: async (delta) => {
                sendEvent('assistant_delta', {
                  programId,
                  messageId: assistantMessageId,
                  delta,
                });
              },
            });

            sendEvent('telemetry_refresh', {
              programId,
              reason: 'agent_steered',
            });

            sendEvent('done', {
              programId,
              messageId: assistantMessageId,
              targetAgentId: steerRes.targetAgent.id,
              targetAgentName: steerRes.targetAgent.name,
              targetAgentRole: steerRes.targetAgent.role,
            });
          }
        } catch (err: unknown) {
          const errMessage = err instanceof Error ? err.message : String(err);
          sendEvent('error', { message: errMessage });
        } finally {
          if (!closed) {
            closed = true;
            try {
              controller.close();
            } catch {
              // Ignore if client closed stream early
            }
          }
        }
      },
    });

    return new Response(stream, {
      status: 200,
      headers: {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      },
    });
  });

  // ---------------------------------------------------------------------------
  // Legacy Single-Engine Compatible Routes
  // ---------------------------------------------------------------------------
  app.get('/api/overview', async (c) => {
    const engine = await resolveLegacyEngine();
    const overview = await engine.getOverview();
    return c.json(overview);
  });

  app.get('/api/squad', async (c) => {
    const engine = await resolveLegacyEngine();
    const squadState = await engine.getSquadState();
    return c.json(squadState);
  });

  app.post('/api/assessments/run', async (c) => {
    const engine = await resolveLegacyEngine();

    let rawBody: unknown = {};
    try {
      const text = await c.req.text();
      if (text.trim().length > 0) {
        rawBody = JSON.parse(text);
      }
    } catch {
      return c.json({ error: 'INVALID_JSON_BODY' }, 400);
    }

    const parsed = RunAssessmentRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      return c.json(
        { error: 'INVALID_RUN_PAYLOAD', issues: parsed.error.issues },
        400,
      );
    }

    const { useCloudSandbox, waitForCompletion } = parsed.data;

    if (waitForCompletion === true) {
      const summary = await engine.runFullAssessment({
        ...(useCloudSandbox !== undefined ? { useCloudSandbox } : {}),
      });
      return c.json({
        started: true,
        runId: summary.runId,
        summary,
      });
    }

    const triggered = engine.triggerBackgroundAssessment({
      ...(useCloudSandbox !== undefined ? { useCloudSandbox } : {}),
    });

    return c.json({
      started: true,
      runId: triggered.runId,
    });
  });

  app.get('/api/surface/graph', async (c) => {
    const engine = await resolveLegacyEngine();
    const snapshot = await engine.getSurfaceGraph();
    return c.json({
      nodes: snapshot.nodes,
      edges: snapshot.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        relation: e.type,
      })),
    });
  });

  app.get('/api/findings', async (c) => {
    const engine = await resolveLegacyEngine();
    const rawStatus = c.req.query('status');
    let statusFilter: z.infer<typeof FindingStatusSchema> | undefined;
    if (rawStatus) {
      const parsedStatus = FindingStatusSchema.safeParse(rawStatus);
      if (!parsedStatus.success) {
        return c.json(
          { error: 'INVALID_FINDING_STATUS', status: rawStatus },
          400,
        );
      }
      statusFilter = parsedStatus.data;
    }

    const findings = await engine.listFindings(statusFilter);
    return c.json({ findings });
  });

  app.post('/api/findings/:findingId/decision', async (c) => {
    const engine = await resolveLegacyEngine();
    const findingId = c.req.param('findingId');
    let rawBody: unknown;
    try {
      rawBody = await c.req.json();
    } catch {
      return c.json({ error: 'INVALID_JSON_BODY' }, 400);
    }

    const parsed = FindingDecisionRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      return c.json(
        { error: 'INVALID_DECISION_PAYLOAD', issues: parsed.error.issues },
        400,
      );
    }

    const updated = await engine.decideFinding(
      findingId,
      parsed.data.status,
      parsed.data.reviewerNote,
    );

    if (!updated) {
      return c.json({ error: 'FINDING_NOT_FOUND', findingId }, 404);
    }

    return c.json({ finding: updated });
  });

  app.get('/api/gitops/history', async (c) => {
    const engine = await resolveLegacyEngine();
    const rawLimit = c.req.query('limit');
    const limit = rawLimit
      ? Math.min(200, Math.max(1, Number.parseInt(rawLimit, 10) || 50))
      : 50;

    const history = await engine.getGitOpsHistory(limit);
    return c.json({
      branches: history.branches,
      commits: history.commits,
      reviews: history.reviews.map((r) => ({
        id: r.id,
        branchName: r.branchName,
        taskId: r.taskId,
        ciPassed: r.ciPassed,
        decision: r.decision,
        rationale: r.rationale,
        ...(r.commitSha ? { commitSha: r.commitSha } : {}),
        createdAt: r.createdAt,
      })),
    });
  });

  app.get('/api/traffic', async (c) => {
    const engine = await resolveLegacyEngine();
    const rawLimit = c.req.query('limit');
    const limit = rawLimit
      ? Math.min(5000, Math.max(1, Number.parseInt(rawLimit, 10) || 250))
      : 250;

    const entries = await engine.listTraffic(limit);
    return c.json({ entries });
  });

  app.get('/api/blobs/:sha256', async (c) => {
    const sha256 = c.req.param('sha256');
    const blob = manager
      ? await manager.getBlobAcrossWorkspaces(sha256)
      : await (engineOrManager as AegisControlPlaneEngine).getBlob(sha256);

    if (!blob) {
      return c.json({ error: 'BLOB_NOT_FOUND', sha256 }, 404);
    }

    return c.json(formatBlobPayload(sha256, blob));
  });

  app.all('/api/*', (c) => {
    return c.json({ error: 'API_ROUTE_NOT_FOUND', path: c.req.path }, 404);
  });

  // Static dashboard SPA serving if apps/dashboard/dist/index.html is built
  app.get('*', async (c) => {
    const reqPath = c.req.path || '/';
    const normalizedPath = reqPath === '/' ? 'index.html' : reqPath;

    const exactAsset = await readStaticAssetSafe(
      dashboardDistDir,
      normalizedPath,
    );
    if (exactAsset) {
      return new Response(new Uint8Array(exactAsset.content), {
        status: 200,
        headers: {
          'Content-Type': exactAsset.contentType,
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }

    // Do not serve index.html for missing static asset files (e.g. /assets/*.js)
    if (reqPath.startsWith('/assets/') || path.extname(reqPath) !== '') {
      return c.json({ error: 'STATIC_ASSET_NOT_FOUND', path: reqPath }, 404);
    }

    const indexFallback = await readStaticAssetSafe(
      dashboardDistDir,
      'index.html',
    );
    if (indexFallback) {
      return new Response(new Uint8Array(indexFallback.content), {
        status: 200,
        headers: {
          'Content-Type': indexFallback.contentType,
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }

    return c.json(
      {
        service: '@opencyber/control-plane',
        status: 'online',
        dashboardBuilt: false,
      },
      200,
    );
  });

  return app;
}
