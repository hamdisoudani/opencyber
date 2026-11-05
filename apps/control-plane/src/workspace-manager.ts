import { randomBytes, randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  AegisModelRouter,
  buildProgramScopeAndSeeds,
  type ChatTurnMessage,
  type LlmProviderName,
  parseBugcrowdBriefMessage,
  type ReconSeedTarget,
  streamOrchestratorReply,
} from '@opencyber/agents';
import type { RetrievedBlob } from '@opencyber/gitops-engine';
import {
  CyberSquadCoordinator,
  type SquadAgentRole,
  type SquadRunState,
} from '@opencyber/sec-harness';
import {
  type ScopeConfig,
  ScopeConfigSchema,
  serializeScopeYaml,
} from '@opencyber/shared';
import { DemoEnterpriseTargetServer } from './demo-target.js';
import {
  AegisControlPlaneEngine,
  type AssessmentRunSummary,
  type ProgramLogEntry,
  type ProgressLogInput,
  toSafeSlug,
} from './pipeline.js';

export interface ChatMessageItem {
  id: string;
  programId: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: string;
  status?: 'streaming' | 'completed' | 'error';
  agentId?: string;
  agentName?: string;
  agentRole?: SquadAgentRole;
  logs?: ProgramLogEntry[];
}

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

export interface ProgramWorkspaceManagerOptions {
  dataDir?: string;
  useDemoTarget?: boolean;
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
}

interface PersistedProgramIndexEntry {
  programId: string;
  createdAt: string;
  updatedAt: string;
  scope: ScopeConfig;
  seedTargets: ReconSeedTarget[];
}

interface PersistedChatState {
  messages: ChatMessageItem[];
  logs: ProgramLogEntry[];
}

interface ManagedProgramWorkspace {
  programId: string;
  programDir: string;
  createdAt: string;
  updatedAt: string;
  seedTargets: ReconSeedTarget[];
  engine: AegisControlPlaneEngine;
  messages: ChatMessageItem[];
  logs: ProgramLogEntry[];
}

const MAX_STORED_PROGRAM_LOGS = 500;

async function writeJsonFileAtomic(
  targetPath: string,
  payload: unknown,
): Promise<void> {
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  const tmpPath = `${targetPath}.tmp-${randomUUID()}`;
  await fs.writeFile(tmpPath, JSON.stringify(payload, null, 2), 'utf8');
  await fs.rename(tmpPath, targetPath);
}

export class ProgramWorkspaceManager {
  public readonly llmRouter: AegisModelRouter;
  public readonly demoTarget: DemoEnterpriseTargetServer | null;

  private readonly dataDir: string;
  private readonly programsRootDir: string;
  private readonly indexFilePath: string;
  private readonly ownsTempDataDir: boolean;
  private readonly defaultUseCloudSandbox: boolean;
  private readonly options: ProgramWorkspaceManagerOptions;
  private readonly workspaces = new Map<string, ManagedProgramWorkspace>();

  private demoTargetOrigin?: string;
  private fallbackLegacyEngine: AegisControlPlaneEngine | null = null;
  private initialized = false;
  private closed = false;

  public constructor(opts?: ProgramWorkspaceManagerOptions) {
    this.options = { ...(opts ?? {}) };

    if (opts?.dataDir) {
      this.dataDir = path.resolve(opts.dataDir);
      this.ownsTempDataDir = false;
    } else {
      this.dataDir = path.join(
        os.tmpdir(),
        `aegis-workspaces-${randomUUID()}`,
      );
      this.ownsTempDataDir = true;
    }

    this.programsRootDir = path.join(this.dataDir, 'programs');
    this.indexFilePath = path.join(this.dataDir, 'programs-index.json');
    this.defaultUseCloudSandbox = opts?.useCloudSandbox !== false;

    this.demoTarget =
      opts?.useDemoTarget !== false ? new DemoEnterpriseTargetServer() : null;

    const resolvedOpenRouterKey = (
      opts?.openRouterApiKey ?? process.env.OPENROUTER_API_KEY
    )?.trim();
    const resolvedGroqKey = (
      opts?.groqApiKey ?? process.env.GROQ_API_KEY
    )?.trim();

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
  }

  private createWorkspaceEngine(
    engineDataDir: string,
    scope?: ScopeConfig,
    seedTargets?: ReconSeedTarget[],
    extra?: { programId?: string; squadStateFilePath?: string },
  ): AegisControlPlaneEngine {
    return new AegisControlPlaneEngine({
      ...(extra?.programId ? { programId: extra.programId } : {}),
      dataDir: engineDataDir,
      ...(extra?.squadStateFilePath
        ? { squadStateFilePath: extra.squadStateFilePath }
        : {}),
      ...(scope ? { scope } : {}),
      ...(seedTargets ? { seedTargets } : {}),
      useDemoTarget: false,
      ...(this.demoTargetOrigin
        ? { demoTargetOrigin: this.demoTargetOrigin }
        : {}),
      useCloudSandbox: this.defaultUseCloudSandbox,
      ...(this.options.hmacSecret
        ? { hmacSecret: this.options.hmacSecret }
        : {}),
      ...(this.options.e2bApiKey ? { e2bApiKey: this.options.e2bApiKey } : {}),
      ...(this.options.openRouterApiKey
        ? { openRouterApiKey: this.options.openRouterApiKey }
        : {}),
      ...(this.options.groqApiKey
        ? { groqApiKey: this.options.groqApiKey }
        : {}),
      ...(this.options.orchestratorProvider
        ? { orchestratorProvider: this.options.orchestratorProvider }
        : {}),
      ...(this.options.subagentProvider
        ? { subagentProvider: this.options.subagentProvider }
        : {}),
      ...(this.options.orchestratorModel
        ? { orchestratorModel: this.options.orchestratorModel }
        : {}),
      ...(this.options.subagentModel
        ? { subagentModel: this.options.subagentModel }
        : {}),
      ...(this.options.promptGuardModel
        ? { promptGuardModel: this.options.promptGuardModel }
        : {}),
      ...(this.options.hostMapping
        ? { hostMapping: this.options.hostMapping }
        : {}),
    });
  }

  public async init(): Promise<void> {
    if (this.initialized) {
      return;
    }

    await fs.mkdir(this.programsRootDir, { recursive: true });

    if (this.demoTarget) {
      const started = await this.demoTarget.start(0);
      this.demoTargetOrigin = started.origin;
    }

    let persistedIndex: PersistedProgramIndexEntry[] = [];
    try {
      const rawIndex = await fs.readFile(this.indexFilePath, 'utf8');
      const parsed = JSON.parse(rawIndex) as unknown;
      if (Array.isArray(parsed)) {
        persistedIndex = parsed as PersistedProgramIndexEntry[];
      }
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw err;
      }
    }

    for (const entry of persistedIndex) {
      if (!entry || typeof entry.programId !== 'string' || !entry.programId) {
        continue;
      }

      const programDir = path.join(this.programsRootDir, entry.programId);
      const validatedScope = ScopeConfigSchema.parse(entry.scope);
      const seedTargets: ReconSeedTarget[] = Array.isArray(entry.seedTargets)
        ? entry.seedTargets.filter(
            (s): s is ReconSeedTarget =>
              Boolean(s) &&
              typeof s.host === 'string' &&
              typeof s.baseUrl === 'string',
          )
        : [];

      const squadStatePath = path.join(programDir, 'squad-state.json');
      const engine = this.createWorkspaceEngine(
        path.join(programDir, 'engine'),
        validatedScope,
        seedTargets,
        {
          programId: entry.programId,
          squadStateFilePath: squadStatePath,
        },
      );
      await engine.init();

      let messages: ChatMessageItem[] = [];
      let logs: ProgramLogEntry[] = [];
      const chatStatePath = path.join(programDir, 'chat-state.json');
      try {
        const rawChat = await fs.readFile(chatStatePath, 'utf8');
        const parsedChat = JSON.parse(rawChat) as Partial<PersistedChatState>;
        if (Array.isArray(parsedChat.messages)) {
          messages = parsedChat.messages.map((m) =>
            m.status === 'streaming' ? { ...m, status: 'completed' } : m,
          );
        }
        if (Array.isArray(parsedChat.logs)) {
          logs = parsedChat.logs.slice(-MAX_STORED_PROGRAM_LOGS);
        }
      } catch (err: unknown) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
          throw err;
        }
      }

      // Ensure persisted workspaces without squad-state.json are hydrated on startup
      const firstUserBrief = messages.find((m) => m.role === 'user')?.content;
      await engine.getSquadState(
        firstUserBrief ? { userBrief: firstUserBrief } : undefined,
      );

      this.workspaces.set(entry.programId, {
        programId: entry.programId,
        programDir,
        createdAt: entry.createdAt || new Date().toISOString(),
        updatedAt: entry.updatedAt || entry.createdAt || new Date().toISOString(),
        seedTargets,
        engine,
        messages,
        logs,
      });
    }

    this.initialized = true;
  }

  public async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;

    const enginesToClose: AegisControlPlaneEngine[] = [];
    for (const ws of this.workspaces.values()) {
      enginesToClose.push(ws.engine);
    }
    if (this.fallbackLegacyEngine) {
      enginesToClose.push(this.fallbackLegacyEngine);
      this.fallbackLegacyEngine = null;
    }

    for (const eng of enginesToClose) {
      await eng.close();
    }

    if (this.demoTarget) {
      await this.demoTarget.stop();
    }

    if (this.ownsTempDataDir) {
      await fs.rm(this.dataDir, { recursive: true, force: true }).catch(() => {
        // Ignore temp dir cleanup errors
      });
    }
  }

  private async persistProgramsIndex(): Promise<void> {
    const entries: PersistedProgramIndexEntry[] = Array.from(
      this.workspaces.values(),
    ).map((ws) => ({
      programId: ws.programId,
      createdAt: ws.createdAt,
      updatedAt: ws.updatedAt,
      scope: ws.engine.scope,
      seedTargets: [...ws.seedTargets],
    }));

    await writeJsonFileAtomic(this.indexFilePath, entries);
  }

  private async persistWorkspaceChatState(
    workspace: ManagedProgramWorkspace,
  ): Promise<void> {
    const chatStatePath = path.join(workspace.programDir, 'chat-state.json');
    const payload: PersistedChatState = {
      messages: workspace.messages,
      logs: workspace.logs.slice(-MAX_STORED_PROGRAM_LOGS),
    };
    await writeJsonFileAtomic(chatStatePath, payload);
  }

  public async listPrograms(): Promise<ProgramSummaryItem[]> {
    if (!this.initialized) {
      await this.init();
    }

    const sortedWorkspaces = Array.from(this.workspaces.values()).sort((a, b) =>
      b.updatedAt.localeCompare(a.updatedAt),
    );

    const summaries: ProgramSummaryItem[] = [];
    for (const ws of sortedWorkspaces) {
      const overview = await ws.engine.getOverview();
      summaries.push({
        programId: ws.programId,
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
        createdAt: ws.createdAt,
        updatedAt: ws.updatedAt,
      });
    }

    return summaries;
  }

  public async getWorkspaceEngine(
    programId: string,
  ): Promise<AegisControlPlaneEngine | null> {
    if (!this.initialized) {
      await this.init();
    }
    return this.workspaces.get(programId)?.engine ?? null;
  }

  public async getMessages(programId: string): Promise<ChatMessageItem[] | null> {
    if (!this.initialized) {
      await this.init();
    }
    const ws = this.workspaces.get(programId);
    if (!ws) {
      return null;
    }
    return ws.messages.map((m) => ({
      ...m,
      ...(m.logs ? { logs: [...m.logs] } : {}),
    }));
  }

  public async getLogs(programId: string): Promise<ProgramLogEntry[] | null> {
    if (!this.initialized) {
      await this.init();
    }
    const ws = this.workspaces.get(programId);
    if (!ws) {
      return null;
    }
    return [...ws.logs];
  }

  public async getSquadState(programId: string): Promise<SquadRunState | null> {
    if (!this.initialized) {
      await this.init();
    }
    const ws = this.workspaces.get(programId);
    if (!ws) {
      return null;
    }
    const firstUserBrief = ws.messages.find((m) => m.role === 'user')?.content;
    return ws.engine.getSquadState(
      firstUserBrief ? { userBrief: firstUserBrief } : undefined,
    );
  }

  public async getBlobAcrossWorkspaces(
    sha256: string,
  ): Promise<RetrievedBlob | null> {
    if (!this.initialized) {
      await this.init();
    }

    for (const ws of this.workspaces.values()) {
      const found = await ws.engine.getBlob(sha256);
      if (found) {
        return found;
      }
    }

    if (this.fallbackLegacyEngine) {
      const fallbackFound = await this.fallbackLegacyEngine.getBlob(sha256);
      if (fallbackFound) {
        return fallbackFound;
      }
    }

    return null;
  }

  public async getOrCreateDefaultEngine(): Promise<AegisControlPlaneEngine> {
    if (!this.initialized) {
      await this.init();
    }

    if (this.workspaces.size > 0) {
      const mostRecent = Array.from(this.workspaces.values()).sort((a, b) =>
        b.updatedAt.localeCompare(a.updatedAt),
      )[0]!;
      return mostRecent.engine;
    }

    if (!this.fallbackLegacyEngine) {
      this.fallbackLegacyEngine = this.createWorkspaceEngine(
        path.join(this.dataDir, 'legacy-default-engine'),
      );
      await this.fallbackLegacyEngine.init();
    }

    return this.fallbackLegacyEngine;
  }

  public async handleSteerStream(opts: {
    programId: string;
    targetAgentId?: string;
    message: string;
    useCloudSandbox?: boolean;
    sendEvent: (event: string, data: unknown) => void | Promise<void>;
  }): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }

    const trimmedMessage = opts.message.trim();
    if (!trimmedMessage) {
      await opts.sendEvent('error', { message: 'Message cannot be empty.' });
      return;
    }

    const activeWorkspace = this.workspaces.get(opts.programId);
    if (!activeWorkspace) {
      await opts.sendEvent('error', {
        message: `Program '${opts.programId}' not found.`,
      });
      return;
    }

    const priorHistory: ChatTurnMessage[] = activeWorkspace.messages
      .filter((m) => m.content.trim().length > 0)
      .map((m) => ({
        role: m.role,
        content: m.content,
      }));

    const userCreatedAt = new Date().toISOString();
    const userMsg: ChatMessageItem = {
      id: randomUUID(),
      programId: activeWorkspace.programId,
      role: 'user',
      content: trimmedMessage,
      createdAt: userCreatedAt,
      status: 'completed',
      ...(opts.targetAgentId ? { agentId: opts.targetAgentId } : {}),
    };

    const assistantMessageId = randomUUID();
    const assistantMsg: ChatMessageItem = {
      id: assistantMessageId,
      programId: activeWorkspace.programId,
      role: 'assistant',
      content: '',
      createdAt: new Date().toISOString(),
      status: 'streaming',
      logs: [],
    };

    activeWorkspace.messages.push(userMsg, assistantMsg);
    activeWorkspace.updatedAt = assistantMsg.createdAt;
    await this.persistWorkspaceChatState(activeWorkspace);

    const recordAndEmitLog = async (
      input: ProgressLogInput,
    ): Promise<void> => {
      const entry: ProgramLogEntry = {
        id: randomUUID(),
        programId: activeWorkspace.programId,
        timestamp: new Date().toISOString(),
        level: input.level,
        stage: input.stage,
        agent: input.agent,
        message: input.message,
      };
      activeWorkspace.logs.push(entry);
      if (activeWorkspace.logs.length > MAX_STORED_PROGRAM_LOGS) {
        activeWorkspace.logs.splice(
          0,
          activeWorkspace.logs.length - MAX_STORED_PROGRAM_LOGS,
        );
      }
      if (!assistantMsg.logs) {
        assistantMsg.logs = [];
      }
      assistantMsg.logs.push(entry);
      await opts.sendEvent('log', entry);
    };

    try {
      await opts.sendEvent('program_selected', {
        programId: activeWorkspace.programId,
        programName: activeWorkspace.engine.scope.programName,
        isNew: false,
        assistantMessageId,
        ...(opts.targetAgentId ? { targetAgentId: opts.targetAgentId } : {}),
      });

      const steerRes = await activeWorkspace.engine.steerSquadAgent({
        ...(opts.targetAgentId ? { targetAgentId: opts.targetAgentId } : {}),
        message: trimmedMessage,
        conversationHistory: priorHistory,
        onSquadEvent: async (ev, snapshot) => {
          await opts.sendEvent('squad_event', {
            ...ev,
            programId: activeWorkspace.programId,
            event: ev,
            squadState: snapshot,
          });
        },
        onDelta: async (delta) => {
          assistantMsg.content += delta;
          await opts.sendEvent('assistant_delta', {
            programId: activeWorkspace.programId,
            messageId: assistantMessageId,
            delta,
          });
        },
      });

      if (!assistantMsg.content && steerRes.replyText) {
        assistantMsg.content = steerRes.replyText;
      }
      assistantMsg.agentId = steerRes.targetAgent.id;
      assistantMsg.agentName = steerRes.targetAgent.name;
      assistantMsg.agentRole = steerRes.targetAgent.role;
      assistantMsg.status = 'completed';

      await recordAndEmitLog({
        level: 'INFO',
        stage: 'ORCHESTRATOR_REVIEW',
        agent: `${steerRes.targetAgent.name} (${steerRes.targetAgent.model})`,
        message: `Processed live operator steering directive on ${activeWorkspace.engine.scope.programName}.`,
      });

      activeWorkspace.updatedAt = new Date().toISOString();
      await this.persistWorkspaceChatState(activeWorkspace);
      await this.persistProgramsIndex();

      await opts.sendEvent('telemetry_refresh', {
        programId: activeWorkspace.programId,
        reason: 'agent_steered',
      });

      await opts.sendEvent('done', {
        programId: activeWorkspace.programId,
        messageId: assistantMessageId,
        targetAgentId: steerRes.targetAgent.id,
        targetAgentName: steerRes.targetAgent.name,
        targetAgentRole: steerRes.targetAgent.role,
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);

      await recordAndEmitLog({
        level: 'ERROR',
        stage: 'ORCHESTRATOR_REVIEW',
        agent: 'SquadSteering',
        message: errMsg,
      }).catch(() => undefined);

      assistantMsg.status = 'error';
      if (!assistantMsg.content) {
        assistantMsg.content = `Error: ${errMsg}`;
      }
      activeWorkspace.updatedAt = new Date().toISOString();
      await this.persistWorkspaceChatState(activeWorkspace).catch(
        () => undefined,
      );
      await this.persistProgramsIndex().catch(() => undefined);

      await opts.sendEvent('error', { message: errMsg });
    }
  }

  public async handleChatStream(opts: {
    programId?: string;
    targetAgentId?: string;
    message: string;
    useCloudSandbox?: boolean;
    sendEvent: (event: string, data: unknown) => void | Promise<void>;
  }): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }

    const trimmedMessage = opts.message.trim();
    if (!trimmedMessage) {
      await opts.sendEvent('error', { message: 'Message cannot be empty.' });
      return;
    }

    if (opts.targetAgentId) {
      if (opts.programId) {
        await this.handleSteerStream({
          programId: opts.programId,
          targetAgentId: opts.targetAgentId,
          message: trimmedMessage,
          ...(opts.useCloudSandbox !== undefined
            ? { useCloudSandbox: opts.useCloudSandbox }
            : {}),
          sendEvent: opts.sendEvent,
        });
        return;
      }

      if (this.workspaces.size > 0) {
        const mostRecent = Array.from(this.workspaces.values()).sort((a, b) =>
          b.updatedAt.localeCompare(a.updatedAt),
        )[0]!;
        await this.handleSteerStream({
          programId: mostRecent.programId,
          targetAgentId: opts.targetAgentId,
          message: trimmedMessage,
          ...(opts.useCloudSandbox !== undefined
            ? { useCloudSandbox: opts.useCloudSandbox }
            : {}),
          sendEvent: opts.sendEvent,
        });
        return;
      }
    }

    const existingWorkspace = opts.programId
      ? this.workspaces.get(opts.programId)
      : undefined;

    const priorHistory: ChatTurnMessage[] = (existingWorkspace?.messages ?? [])
      .filter((m) => m.content.trim().length > 0)
      .map((m) => ({
        role: m.role,
        content: m.content,
      }));

    let workspace: ManagedProgramWorkspace | undefined = existingWorkspace;
    let assistantMsg: ChatMessageItem | undefined;
    let assistantMessageId = '';

    const recordAndEmitLog = async (
      input: ProgressLogInput,
    ): Promise<void> => {
      if (!workspace) {
        return;
      }
      const entry: ProgramLogEntry = {
        id: randomUUID(),
        programId: workspace.programId,
        timestamp: new Date().toISOString(),
        level: input.level,
        stage: input.stage,
        agent: input.agent,
        message: input.message,
      };
      workspace.logs.push(entry);
      if (workspace.logs.length > MAX_STORED_PROGRAM_LOGS) {
        workspace.logs.splice(
          0,
          workspace.logs.length - MAX_STORED_PROGRAM_LOGS,
        );
      }
      if (assistantMsg) {
        if (!assistantMsg.logs) {
          assistantMsg.logs = [];
        }
        assistantMsg.logs.push(entry);
      }
      await opts.sendEvent('log', entry);
    };

    try {
      const liveLlmClient = this.llmRouter.isConfigured
        ? this.llmRouter
        : undefined;

      const intent = await parseBugcrowdBriefMessage({
        userMessage: trimmedMessage,
        ...(existingWorkspace
          ? { existingScope: existingWorkspace.engine.scope }
          : {}),
        conversationHistory: priorHistory,
        ...(liveLlmClient ? { llmClient: liveLlmClient } : {}),
      });

      const isNew = !existingWorkspace;

      if (!workspace) {
        const programId = `prog-${toSafeSlug(intent.programName, 24)}-${randomBytes(3).toString('hex')}`;
        const { scope, seedTargets } = buildProgramScopeAndSeeds({
          engagementId: programId,
          intent,
        });

        const programDir = path.join(this.programsRootDir, programId);
        const engine = this.createWorkspaceEngine(
          path.join(programDir, 'engine'),
          scope,
          seedTargets,
          {
            programId,
            squadStateFilePath: path.join(programDir, 'squad-state.json'),
          },
        );
        await engine.init();

        const createdAt = new Date().toISOString();
        workspace = {
          programId,
          programDir,
          createdAt,
          updatedAt: createdAt,
          seedTargets: [...seedTargets],
          engine,
          messages: [],
          logs: [],
        };
        this.workspaces.set(programId, workspace);
        await this.persistProgramsIndex();
      }

      const activeWorkspace = workspace;
      const userCreatedAt = new Date().toISOString();
      const userMsg: ChatMessageItem = {
        id: randomUUID(),
        programId: activeWorkspace.programId,
        role: 'user',
        content: trimmedMessage,
        createdAt: userCreatedAt,
        status: 'completed',
      };

      assistantMessageId = randomUUID();
      assistantMsg = {
        id: assistantMessageId,
        programId: activeWorkspace.programId,
        role: 'assistant',
        content: '',
        createdAt: new Date().toISOString(),
        status: 'streaming',
        agentRole: 'orchestrator',
        agentName: 'Lead Orchestrator',
        logs: [],
      };

      activeWorkspace.messages.push(userMsg, assistantMsg);
      activeWorkspace.updatedAt = assistantMsg.createdAt;
      await this.persistWorkspaceChatState(activeWorkspace);

      await opts.sendEvent('program_selected', {
        programId: activeWorkspace.programId,
        programName: activeWorkspace.engine.scope.programName,
        isNew,
        assistantMessageId,
      });

      await recordAndEmitLog({
        level: 'INFO',
        stage: 'INGEST',
        agent: 'LeadOrchestrator',
        message: `Lead Orchestrator (${this.llmRouter.orchestratorProvider.toUpperCase()} · ${this.llmRouter.orchestratorModel}) classified message -> ${intent.action}.`,
      });

      if (
        !isNew &&
        intent.action === 'INITIALIZE_OR_UPDATE_SCOPE_AND_SCAN'
      ) {
        const { scope, seedTargets } = buildProgramScopeAndSeeds({
          engagementId: activeWorkspace.programId,
          intent,
          existingScope: activeWorkspace.engine.scope,
        });
        await activeWorkspace.engine.updateScopeAndSeeds(scope, seedTargets);
        activeWorkspace.seedTargets = [...seedTargets];
        activeWorkspace.updatedAt = new Date().toISOString();
        await this.persistProgramsIndex();
      }

      await opts.sendEvent('scope_updated', {
        programId: activeWorkspace.programId,
        programName: activeWorkspace.engine.scope.programName,
        authorizedDomains: activeWorkspace.engine.scope.authorizedDomains,
        excludedHosts: activeWorkspace.engine.scope.excludedHosts,
        excludedPaths: activeWorkspace.engine.scope.excludedPaths,
        maxRpsPerHost: activeWorkspace.engine.scope.maxRpsPerHost,
        complianceHeaders: activeWorkspace.engine.scope.complianceHeaders,
        scopeYaml: serializeScopeYaml(activeWorkspace.engine.scope),
      });

      await opts.sendEvent('telemetry_refresh', {
        programId: activeWorkspace.programId,
        reason: 'scope_ready',
      });

      let runSummary: AssessmentRunSummary | undefined;
      if (
        intent.action === 'INITIALIZE_OR_UPDATE_SCOPE_AND_SCAN' ||
        intent.action === 'RESCAN_CURRENT_SCOPE'
      ) {
        runSummary = await activeWorkspace.engine.runFullAssessment({
          ...(opts.useCloudSandbox !== undefined
            ? { useCloudSandbox: opts.useCloudSandbox }
            : {}),
          userBrief: trimmedMessage,
          onSquadEvent: async (ev, snapshot) => {
            await opts.sendEvent('squad_event', {
              ...ev,
              programId: activeWorkspace.programId,
              event: ev,
              squadState: snapshot,
            });
          },
          onProgress: async (logInput) => {
            await recordAndEmitLog(logInput);
            if (
              logInput.level === 'SUCCESS' ||
              logInput.stage === 'SURFACE_REDUCER' ||
              logInput.stage === 'ORCHESTRATOR_REVIEW'
            ) {
              await opts.sendEvent('telemetry_refresh', {
                programId: activeWorkspace.programId,
                reason: logInput.stage,
              });
            }
          },
        });

        await opts.sendEvent('telemetry_refresh', {
          programId: activeWorkspace.programId,
          reason: 'assessment_complete',
        });
      }

      const [findings, overview, surfaceSnapshot, gitopsHistory, trafficEntries] =
        await Promise.all([
          activeWorkspace.engine.listFindings(),
          activeWorkspace.engine.getOverview(),
          activeWorkspace.engine.getSurfaceGraph(),
          activeWorkspace.engine.getGitOpsHistory(),
          activeWorkspace.engine.listTraffic(40),
        ]);

      let followUpCoordinator: CyberSquadCoordinator | undefined;
      let followUpOrchId: string | undefined;
      if (!runSummary) {
        const currentSquad = await activeWorkspace.engine.getSquadState({
          userBrief: trimmedMessage,
        });
        const rootNode =
          currentSquad.agents.find(
            (a) => a.parentId === null || a.role === 'orchestrator',
          ) ?? currentSquad.agents[0];
        if (rootNode) {
          followUpOrchId = rootNode.id;
          followUpCoordinator = new CyberSquadCoordinator({
            programId: currentSquad.programId,
            runId: currentSquad.runId,
            initialState: currentSquad,
            onEvent: async (ev, snapshot) => {
              await opts.sendEvent('squad_event', {
                ...ev,
                programId: activeWorkspace.programId,
                event: ev,
                squadState: snapshot,
              });
            },
          });
          followUpCoordinator.recordUserBrief(rootNode.id, trimmedMessage, {
            title: `Operator follow-up -> ${rootNode.name}`,
          });
          followUpCoordinator.recordThink(rootNode.id, {
            know: `${overview.metrics.hostsDiscovered} host(s), ${overview.metrics.canonicalEndpoints} endpoint(s), ${findings.length} finding(s), and ${overview.metrics.compliantTombstones} compliant tombstone(s) in StateDb.`,
            think: `Synthesizing evidence-backed response for operator query without triggering redundant target traffic.`,
            test: `Inspecting persisted GitOps telemetry, SharedThreatModel, and SurfaceCoverageLedger.`,
            validate: `Cross-checking every statement against SHA-256 evidence pointers and verified closure states.`,
            confidence: 88,
          });
        }
      }

      const hostLabels = surfaceSnapshot.nodes
        .filter((n) => n.type === 'HOST')
        .map((n) => n.label);
      const endpointLabels = surfaceSnapshot.nodes
        .filter((n) => n.type === 'ENDPOINT')
        .slice(0, 15)
        .map((n) => n.label);
      const blocked451Entries = trafficEntries
        .filter((t) => t.decision === 'BLOCKED_SCOPE_451')
        .slice(0, 10)
        .map((t) => `${t.method} ${t.url} -> HTTP 451 (${t.decision})`);
      const recentGitCommits = gitopsHistory.commits
        .slice(0, 12)
        .map((c) => `${c.sha.slice(0, 8)}: ${c.message}`);
      const recentSubagentLogs = activeWorkspace.logs
        .slice(-20)
        .map((l) => `[${l.stage}] (${l.agent}) ${l.message}`);

      const telemetryContext = [
        `Cumulative Metrics: hostsDiscovered=${overview.metrics.hostsDiscovered}, canonicalEndpoints=${overview.metrics.canonicalEndpoints}, compliantTombstones=${overview.metrics.compliantTombstones}, blockedScope451=${overview.metrics.blockedScope451}, allowedRequests=${overview.metrics.allowedRequests}`,
        `Discovered In-Scope Hosts: ${hostLabels.join(', ') || 'none yet'}`,
        `Canonical Endpoints Sample: ${endpointLabels.join(', ') || 'none yet'}`,
        `Egress HTTP 451 Scope/Exclusion Blocks:\n${blocked451Entries.length > 0 ? blocked451Entries.map((b) => `  - ${b}`).join('\n') : '  - none recorded'}`,
        `Recent GitOps Main Branch Commits:\n${recentGitCommits.length > 0 ? recentGitCommits.map((c) => `  - ${c}`).join('\n') : '  - none recorded'}`,
        `Subagent Delegation Log Trace:\n${recentSubagentLogs.length > 0 ? recentSubagentLogs.map((l) => `  - ${l}`).join('\n') : '  - none recorded'}`,
      ].join('\n');

      const activeAssistantMsg = assistantMsg;

      await streamOrchestratorReply({
        userMessage: trimmedMessage,
        intent,
        scope: activeWorkspace.engine.scope,
        ...(runSummary ? { runSummary } : {}),
        findings,
        telemetryContext,
        conversationHistory: priorHistory,
        ...(liveLlmClient ? { llmClient: liveLlmClient } : {}),
        onDelta: async (delta) => {
          activeAssistantMsg.content += delta;
          await opts.sendEvent('assistant_delta', {
            programId: activeWorkspace.programId,
            messageId: assistantMessageId,
            delta,
          });
        },
      });

      if (followUpCoordinator && followUpOrchId) {
        followUpCoordinator.recordAssistantSynthesis(
          followUpOrchId,
          activeAssistantMsg.content.length > 600
            ? `${activeAssistantMsg.content.slice(0, 597)}...`
            : activeAssistantMsg.content,
          { title: 'Lead Orchestrator follow-up synthesis' },
        );
        followUpCoordinator.setAgentStatus(followUpOrchId, 'completed');
        await followUpCoordinator.flush();
        const updatedState = followUpCoordinator.finalizeRun('completed');
        await activeWorkspace.engine.setSquadState(updatedState);
      }

      activeAssistantMsg.status = 'completed';
      activeWorkspace.updatedAt = new Date().toISOString();
      await this.persistWorkspaceChatState(activeWorkspace);
      await this.persistProgramsIndex();

      await opts.sendEvent('done', {
        programId: activeWorkspace.programId,
        messageId: assistantMessageId,
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);

      if (workspace) {
        await recordAndEmitLog({
          level: 'ERROR',
          stage: 'INGEST',
          agent: 'LeadOrchestrator',
          message: errMsg,
        }).catch(() => undefined);

        if (assistantMsg) {
          assistantMsg.status = 'error';
          if (!assistantMsg.content) {
            assistantMsg.content = `Error: ${errMsg}`;
          }
        }

        workspace.updatedAt = new Date().toISOString();
        await this.persistWorkspaceChatState(workspace).catch(() => undefined);
        await this.persistProgramsIndex().catch(() => undefined);
      }

      await opts.sendEvent('error', { message: errMsg });
    }
  }
}
