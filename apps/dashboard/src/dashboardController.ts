import {
  CANDID_VDP_BRIEF,
  createEmptyOverview,
  createEmptySquadRunState,
  EMPTY_GITOPS_HISTORY,
  EMPTY_SURFACE_GRAPH,
  FIRECRAWL_VDP_BRIEF,
} from './emptyState';
import { consumeSseBuffer } from './sseParser';
import type {
  AgentContextStats,
  BlobPayloadResponse,
  ChatMessageItem,
  ChatMessagesResponse,
  CommitDiffResponse,
  ConnectionState,
  ContinuousMonitoringStatus,
  FindingDecisionPayload,
  FindingDecisionResponse,
  FindingItem,
  FindingsResponse,
  GitOpsHistoryResponse,
  OverviewResponse,
  PrimaryWorkspaceView,
  ProgramLogEntry,
  ProgramLogsResponse,
  ProgramsResponse,
  ProgramSummaryItem,
  RepoFileContentResponse,
  RepoFileEntry,
  RepoFilesResponse,
  ResearcherSkillPack,
  SquadAgentNode,
  SquadRunState,
  SquadTimelineEvent,
  SseAssistantDeltaEvent,
  SseDoneEvent,
  SseErrorEvent,
  SseProgramSelectedEvent,
  SseScopeUpdatedEvent,
  SseSquadEventPayload,
  SseTelemetryRefreshEvent,
  SurfaceGraphResponse,
  TrafficEntry,
  TrafficResponse,
} from './types';

export {
  createEmptyOverview,
  createEmptySquadRunState,
  EMPTY_GITOPS_HISTORY,
  EMPTY_SURFACE_GRAPH,
};

export type InspectorModalTab = 'transcript' | 'prompt' | 'skills' | 'report';
export type OperationsCompactPane = 'stream' | 'agents' | 'hypotheses';
export type ReconSectionTab = 'all' | 'graph' | 'scope';
export type GitOpsSectionTab = 'prs' | 'files' | 'egress';
export type VdpBriefPreset = 'firecrawl' | 'candid';

export interface DashboardState {
  theme: 'dark' | 'light';
  desktopRailCollapsed: boolean;
  mobileDrawerOpen: boolean;
  activeView: PrimaryWorkspaceView;
  opsCompactPane: OperationsCompactPane;
  reconSectionTab: ReconSectionTab;
  gitOpsSectionTab: GitOpsSectionTab;

  connectionState: ConnectionState;
  useCloudSandbox: boolean;
  isSyncing: boolean;

  programs: ProgramSummaryItem[];
  activeProgramId: string | null;

  overview: OverviewResponse;
  squadState: SquadRunState;
  skillPacks: ResearcherSkillPack[];
  messages: ChatMessageItem[];
  programLogs: ProgramLogEntry[];
  surfaceGraph: SurfaceGraphResponse;
  findings: FindingItem[];
  gitOpsHistory: GitOpsHistoryResponse;
  trafficEntries: TrafficEntry[];
  repoFiles: RepoFileEntry[];
  selectedRepoFilePath: string;
  selectedRepoFileContent: string;
  selectedCommitSha: string | null;
  selectedCommitDiff: string;

  focusedFindingId: string | null;
  harBlobsBySha: Record<string, string>;
  loadingHarSha: string | null;

  // Collapsible Steering Composer
  composerExpanded: boolean;
  composerDraft: string;
  steerTargetAgentId: string | null;
  isStreaming: boolean;
  streamingSynthesisText: string;
  streamError: string | null;

  // Agent Inspector Modal
  inspectorAgentId: string | null;
  inspectorTab: InspectorModalTab;
  inspectorSteerDraft: string;

  // New Engagement Launchpad Modal
  newEngagementModalOpen: boolean;
  newEngagementBrief: string;
}

export interface DashboardControllerOptions {
  fetchImpl?: typeof fetch;
  autoHydrate?: boolean;
  initialView?: PrimaryWorkspaceView;
}

export function mergeTimelineEvents(
  existing: SquadTimelineEvent[],
  incoming: SquadTimelineEvent[],
): SquadTimelineEvent[] {
  if (incoming.length === 0) return existing;
  const byId = new Map<string, SquadTimelineEvent>();
  for (const item of existing) {
    byId.set(item.id, item);
  }
  for (const item of incoming) {
    const prev = byId.get(item.id);
    byId.set(item.id, prev ? { ...prev, ...item } : item);
  }
  return Array.from(byId.values()).sort((a, b) => {
    if (a.seq !== b.seq) return a.seq - b.seq;
    return a.timestamp.localeCompare(b.timestamp);
  });
}

function mergeLogs(
  existing: ProgramLogEntry[],
  incoming: ProgramLogEntry[],
): ProgramLogEntry[] {
  if (incoming.length === 0) return existing;
  const seen = new Set(existing.map((l) => l.id));
  const out = [...existing];
  for (const entry of incoming) {
    if (!seen.has(entry.id)) {
      seen.add(entry.id);
      out.push(entry);
    }
  }
  return out;
}

function extractSquadStateResponse(raw: unknown): SquadRunState | null {
  if (!raw || typeof raw !== 'object') return null;
  const obj = raw as Record<string, unknown>;
  if (obj.squad && typeof obj.squad === 'object') {
    return obj.squad as SquadRunState;
  }
  if (Array.isArray(obj.agents) && Array.isArray(obj.timeline)) {
    return obj as unknown as SquadRunState;
  }
  return null;
}

function extractSkillPacksResponse(raw: unknown): ResearcherSkillPack[] | null {
  if (Array.isArray(raw)) {
    return raw as ResearcherSkillPack[];
  }
  if (raw && typeof raw === 'object') {
    const obj = raw as Record<string, unknown>;
    if (Array.isArray(obj.skills)) {
      return obj.skills as ResearcherSkillPack[];
    }
    if (Array.isArray(obj.skillPacks)) {
      return obj.skillPacks as ResearcherSkillPack[];
    }
  }
  return null;
}

function extractContinuousStatusResponse(
  raw: unknown,
  fallback: ContinuousMonitoringStatus,
): ContinuousMonitoringStatus {
  if (!raw || typeof raw !== 'object') return fallback;
  const obj = raw as Record<string, unknown>;
  const candidate =
    obj.continuousMonitoring && typeof obj.continuousMonitoring === 'object'
      ? (obj.continuousMonitoring as Record<string, unknown>)
      : obj.status && typeof obj.status === 'object'
        ? (obj.status as Record<string, unknown>)
        : obj;

  if (typeof candidate.enabled !== 'boolean') {
    return fallback;
  }

  return {
    enabled: candidate.enabled,
    intervalSeconds:
      typeof candidate.intervalSeconds === 'number'
        ? candidate.intervalSeconds
        : fallback.intervalSeconds,
    completedWaves:
      typeof candidate.completedWaves === 'number'
        ? candidate.completedWaves
        : fallback.completedWaves,
    ...(typeof candidate.lastWaveAt === 'string'
      ? { lastWaveAt: candidate.lastWaveAt }
      : fallback.lastWaveAt
        ? { lastWaveAt: fallback.lastWaveAt }
        : {}),
    ...(typeof candidate.nextWaveAt === 'string'
      ? { nextWaveAt: candidate.nextWaveAt }
      : {}),
    ...(typeof candidate.totalCompactions === 'number'
      ? { totalCompactions: candidate.totalCompactions }
      : fallback.totalCompactions !== undefined
        ? { totalCompactions: fallback.totalCompactions }
        : {}),
  };
}

function parseContextStats(raw: unknown): AgentContextStats | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const obj = raw as Record<string, unknown>;
  if (
    typeof obj.estimatedTokens !== 'number' ||
    typeof obj.maxTokens !== 'number'
  ) {
    return undefined;
  }
  return {
    estimatedTokens: obj.estimatedTokens,
    maxTokens: obj.maxTokens,
    compactionCount:
      typeof obj.compactionCount === 'number' ? obj.compactionCount : 0,
    ...(typeof obj.checkpointSummary === 'string'
      ? { checkpointSummary: obj.checkpointSummary }
      : {}),
  };
}

export class DashboardController {
  private state: DashboardState;
  private listeners = new Set<() => void>();
  private fetchImpl: typeof fetch;
  private streamAbort: AbortController | null = null;

  constructor(options?: DashboardControllerOptions) {
    this.fetchImpl =
      options?.fetchImpl ??
      ((...args: Parameters<typeof fetch>) => globalThis.fetch(...args));

    this.state = {
      theme: 'dark',
      desktopRailCollapsed: false,
      mobileDrawerOpen: false,
      activeView: options?.initialView ?? 'operations',
      opsCompactPane: 'stream',
      reconSectionTab: 'all',
      gitOpsSectionTab: 'prs',

      connectionState: 'offline',
      useCloudSandbox: true,
      isSyncing: false,

      programs: [],
      activeProgramId: null,

      overview: createEmptyOverview('', 'No Active Engagement', true, false),
      squadState: createEmptySquadRunState('', false),
      skillPacks: [],
      messages: [],
      programLogs: [],
      surfaceGraph: EMPTY_SURFACE_GRAPH,
      findings: [],
      gitOpsHistory: EMPTY_GITOPS_HISTORY,
      trafficEntries: [],
      repoFiles: [],
      selectedRepoFilePath: '',
      selectedRepoFileContent: '',
      selectedCommitSha: null,
      selectedCommitDiff: '',

      focusedFindingId: null,
      harBlobsBySha: {},
      loadingHarSha: null,

      composerExpanded: false,
      composerDraft: '',
      steerTargetAgentId: null,
      isStreaming: false,
      streamingSynthesisText: '',
      streamError: null,

      inspectorAgentId: null,
      inspectorTab: 'transcript',
      inspectorSteerDraft: '',

      newEngagementModalOpen: false,
      newEngagementBrief: '',
    };
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): DashboardState => {
    return this.state;
  };

  private setState(updater: (prev: DashboardState) => DashboardState): void {
    this.state = updater(this.state);
    for (const listener of this.listeners) {
      listener();
    }
  }

  private async fetchJson<T>(
    url: string,
    init?: RequestInit,
    timeoutMs = 5000,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = globalThis.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await this.fetchImpl(url, {
        ...init,
        signal: controller.signal,
        headers: {
          Accept: 'application/json',
          ...(init?.headers ?? {}),
        },
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status} for ${url}`);
      }
      return (await res.json()) as T;
    } finally {
      globalThis.clearTimeout(timer);
    }
  }

  // -------------------------------------------------------------------------
  // Navigation & UI Actions
  // -------------------------------------------------------------------------

  toggleTheme = (): void => {
    this.setState((prev) => {
      const nextTheme = prev.theme === 'dark' ? 'light' : 'dark';
      if (typeof document !== 'undefined') {
        document.documentElement.setAttribute('data-theme', nextTheme);
      }
      return { ...prev, theme: nextTheme };
    });
  };

  toggleDesktopRail = (): void => {
    this.setState((prev) => ({
      ...prev,
      desktopRailCollapsed: !prev.desktopRailCollapsed,
    }));
  };

  setMobileDrawerOpen = (open: boolean): void => {
    this.setState((prev) => ({ ...prev, mobileDrawerOpen: open }));
  };

  setActiveView = (
    view: PrimaryWorkspaceView,
    subOptions?: {
      reconTab?: ReconSectionTab;
      gitOpsTab?: GitOpsSectionTab;
      findingId?: string;
    },
  ): void => {
    this.setState((prev) => ({
      ...prev,
      activeView: view,
      mobileDrawerOpen: false,
      ...(subOptions?.reconTab ? { reconSectionTab: subOptions.reconTab } : {}),
      ...(subOptions?.gitOpsTab
        ? { gitOpsSectionTab: subOptions.gitOpsTab }
        : {}),
      ...(subOptions?.findingId
        ? { focusedFindingId: subOptions.findingId }
        : {}),
    }));

    if (view === 'findings') {
      const targetFindingId =
        subOptions?.findingId ??
        this.state.focusedFindingId ??
        this.state.findings[0]?.findingId ??
        null;
      if (targetFindingId) {
        void this.selectFinding(targetFindingId);
      }
    }
  };

  setOpsCompactPane = (pane: OperationsCompactPane): void => {
    this.setState((prev) => ({ ...prev, opsCompactPane: pane }));
  };

  setReconSectionTab = (tab: ReconSectionTab): void => {
    this.setState((prev) => ({ ...prev, reconSectionTab: tab }));
  };

  setGitOpsSectionTab = (tab: GitOpsSectionTab): void => {
    this.setState((prev) => ({ ...prev, gitOpsSectionTab: tab }));
  };

  setUseCloudSandbox = (enabled: boolean): void => {
    this.setState((prev) => ({ ...prev, useCloudSandbox: enabled }));
  };

  // -------------------------------------------------------------------------
  // Agent Inspector Modal Actions
  // -------------------------------------------------------------------------

  openAgentInspector = (
    agentId: string,
    initialTab: InspectorModalTab = 'transcript',
  ): void => {
    this.setState((prev) => ({
      ...prev,
      inspectorAgentId: agentId,
      inspectorTab: initialTab,
      inspectorSteerDraft: '',
    }));
  };

  closeAgentInspector = (): void => {
    this.setState((prev) => ({
      ...prev,
      inspectorAgentId: null,
      inspectorSteerDraft: '',
    }));
  };

  setInspectorTab = (tab: InspectorModalTab): void => {
    this.setState((prev) => ({ ...prev, inspectorTab: tab }));
  };

  setInspectorSteerDraft = (draft: string): void => {
    this.setState((prev) => ({ ...prev, inspectorSteerDraft: draft }));
  };

  // -------------------------------------------------------------------------
  // Collapsible Steering Composer Actions
  // -------------------------------------------------------------------------

  setComposerExpanded = (expanded: boolean): void => {
    this.setState((prev) => ({ ...prev, composerExpanded: expanded }));
  };

  setComposerDraft = (draft: string): void => {
    this.setState((prev) => ({ ...prev, composerDraft: draft }));
  };

  setSteerTargetAgentId = (agentId: string | null): void => {
    this.setState((prev) => ({ ...prev, steerTargetAgentId: agentId }));
  };

  // -------------------------------------------------------------------------
  // New Engagement Modal Actions
  // -------------------------------------------------------------------------

  openNewEngagementModal = (preset?: VdpBriefPreset): void => {
    this.setState((prev) => ({
      ...prev,
      newEngagementModalOpen: true,
      mobileDrawerOpen: false,
      streamError: null,
      ...(preset === 'firecrawl'
        ? { newEngagementBrief: FIRECRAWL_VDP_BRIEF }
        : preset === 'candid'
          ? { newEngagementBrief: CANDID_VDP_BRIEF }
          : {}),
    }));
  };

  closeNewEngagementModal = (): void => {
    this.setState((prev) => ({ ...prev, newEngagementModalOpen: false }));
  };

  setNewEngagementBrief = (brief: string): void => {
    this.setState((prev) => ({ ...prev, newEngagementBrief: brief }));
  };

  applyBriefPreset = (preset: VdpBriefPreset): void => {
    const brief =
      preset === 'firecrawl' ? FIRECRAWL_VDP_BRIEF : CANDID_VDP_BRIEF;
    this.setState((prev) => ({ ...prev, newEngagementBrief: brief }));
  };

  // -------------------------------------------------------------------------
  // Server Hydration, Researcher Skills & Program Telemetry Sync
  // -------------------------------------------------------------------------

  fetchSkillPacks = async (): Promise<ResearcherSkillPack[]> => {
    try {
      const raw = await this.fetchJson<unknown>('/api/skills');
      const packs = extractSkillPacksResponse(raw);
      if (packs) {
        this.setState((prev) => ({
          ...prev,
          connectionState: 'live',
          skillPacks: packs,
        }));
        return packs;
      }
      return [];
    } catch {
      this.setState((prev) => ({
        ...prev,
        skillPacks: prev.skillPacks.length > 0 ? prev.skillPacks : [],
      }));
      return [];
    }
  };

  refreshProgramsList = async (): Promise<ProgramSummaryItem[] | null> => {
    try {
      const data = await this.fetchJson<ProgramsResponse>('/api/programs');
      const list = Array.isArray(data.programs) ? data.programs : [];
      this.setState((prev) => ({
        ...prev,
        connectionState: 'live',
        programs: list,
      }));
      return list;
    } catch {
      this.setState((prev) => ({ ...prev, connectionState: 'offline' }));
      return null;
    }
  };

  hydrateFromServer = async (): Promise<void> => {
    const [, list] = await Promise.all([
      this.fetchSkillPacks(),
      this.refreshProgramsList(),
    ]);
    if (!list) return;

    if (list.length === 0) {
      this.setState((prev) => ({
        ...prev,
        activeProgramId: null,
        overview: createEmptyOverview(
          '',
          'No Active Engagement',
          prev.useCloudSandbox,
          false,
        ),
        squadState: createEmptySquadRunState('', false),
        messages: [],
        programLogs: [],
        surfaceGraph: EMPTY_SURFACE_GRAPH,
        findings: [],
        gitOpsHistory: EMPTY_GITOPS_HISTORY,
        trafficEntries: [],
        repoFiles: [],
        selectedRepoFilePath: '',
        selectedRepoFileContent: '',
        selectedCommitSha: null,
        selectedCommitDiff: '',
        focusedFindingId: null,
      }));
      return;
    }

    let urlProgramId: string | null = null;
    if (typeof window !== 'undefined') {
      try {
        urlProgramId = new URLSearchParams(window.location.search).get(
          'program',
        );
      } catch {
        urlProgramId = null;
      }
    }

    const targetId =
      urlProgramId && list.some((p) => p.programId === urlProgramId)
        ? urlProgramId
        : (list[0]?.programId ?? null);

    if (targetId) {
      this.setState((prev) => ({ ...prev, activeProgramId: targetId }));
      await this.syncProgramTelemetry(targetId, { includeMessages: true });
    }
  };

  syncProgramTelemetry = async (
    programId: string,
    opts?: { includeMessages?: boolean },
  ): Promise<void> => {
    const enc = encodeURIComponent(programId);
    this.setState((prev) => ({ ...prev, isSyncing: true }));

    try {
      const [
        ovRes,
        squadRaw,
        msgRes,
        logsRes,
        graphRes,
        findRes,
        gitHistoryRes,
        trafRes,
        filesRes,
      ] = await Promise.all([
        this.fetchJson<OverviewResponse>(`/api/programs/${enc}/overview`).catch(
          () => null,
        ),
        this.fetchJson<unknown>(`/api/programs/${enc}/squad`).catch(() => null),
        opts?.includeMessages !== false
          ? this.fetchJson<ChatMessagesResponse>(
              `/api/programs/${enc}/messages`,
            ).catch(() => null)
          : Promise.resolve(null),
        this.fetchJson<ProgramLogsResponse>(`/api/programs/${enc}/logs`).catch(
          () => null,
        ),
        this.fetchJson<SurfaceGraphResponse>(
          `/api/programs/${enc}/surface/graph`,
        ).catch(() => null),
        this.fetchJson<FindingsResponse>(`/api/programs/${enc}/findings`).catch(
          () => null,
        ),
        this.fetchJson<GitOpsHistoryResponse>(
          `/api/programs/${enc}/gitops/history?limit=60`,
        )
          .catch(() =>
            this.fetchJson<GitOpsHistoryResponse>(
              `/api/programs/${enc}/gitops/commits`,
            ),
          )
          .catch(() => null),
        this.fetchJson<TrafficResponse>(
          `/api/programs/${enc}/traffic?limit=300`,
        ).catch(() => null),
        this.fetchJson<RepoFilesResponse>(
          `/api/programs/${enc}/repo/files`,
        ).catch(() => null),
      ]);

      if (this.state.activeProgramId !== programId) return;

      const parsedSquad = extractSquadStateResponse(squadRaw);
      let fileToLoad: string | null = null;
      let commitToLoad: string | null = null;

      this.setState((prev) => {
        const nextOverview =
          ovRes ??
          (prev.overview.engagement.engagementId === programId
            ? prev.overview
            : createEmptyOverview(
                programId,
                programId,
                prev.useCloudSandbox,
                false,
              ));
        const nextMessages =
          msgRes && Array.isArray(msgRes.messages)
            ? msgRes.messages
            : prev.messages;
        const nextLogs =
          logsRes && Array.isArray(logsRes.logs)
            ? mergeLogs(prev.programLogs, logsRes.logs)
            : prev.programLogs;
        const nextGraph =
          graphRes &&
          Array.isArray(graphRes.nodes) &&
          Array.isArray(graphRes.edges)
            ? graphRes
            : prev.surfaceGraph;
        const nextFindings =
          findRes && Array.isArray(findRes.findings)
            ? findRes.findings
            : prev.findings;
        const nextGit =
          gitHistoryRes &&
          Array.isArray(gitHistoryRes.commits) &&
          Array.isArray(gitHistoryRes.reviews)
            ? gitHistoryRes
            : prev.gitOpsHistory;
        const nextTraffic =
          trafRes && Array.isArray(trafRes.entries)
            ? trafRes.entries
            : prev.trafficEntries;
        const nextFiles =
          filesRes && Array.isArray(filesRes.files)
            ? filesRes.files
            : prev.repoFiles;

        let nextSquad: SquadRunState;
        if (parsedSquad) {
          nextSquad = {
            ...parsedSquad,
            timeline: mergeTimelineEvents(
              prev.squadState.programId === programId
                ? prev.squadState.timeline
                : [],
              parsedSquad.timeline ?? [],
            ),
          };
        } else if (prev.squadState.programId === programId) {
          nextSquad = prev.squadState;
        } else {
          nextSquad = createEmptySquadRunState(
            programId,
            nextOverview.runtime.pipelineRunning,
          );
        }

        const nextFocusedFindingId =
          prev.focusedFindingId &&
          nextFindings.some((f) => f.findingId === prev.focusedFindingId)
            ? prev.focusedFindingId
            : (nextFindings[0]?.findingId ?? null);

        const nextCommitSha =
          prev.selectedCommitSha &&
          nextGit.commits.some((c) => c.sha === prev.selectedCommitSha)
            ? prev.selectedCommitSha
            : (nextGit.reviews.find((r) => Boolean(r.commitSha))?.commitSha ??
              nextGit.commits[0]?.sha ??
              null);

        if (
          nextCommitSha &&
          (nextCommitSha !== prev.selectedCommitSha || !prev.selectedCommitDiff)
        ) {
          commitToLoad = nextCommitSha;
        }

        const nextRepoPath =
          prev.selectedRepoFilePath &&
          nextFiles.some((f) => f.path === prev.selectedRepoFilePath)
            ? prev.selectedRepoFilePath
            : (nextFiles[0]?.path ?? '');

        if (
          nextRepoPath &&
          (nextRepoPath !== prev.selectedRepoFilePath ||
            !prev.selectedRepoFileContent)
        ) {
          fileToLoad = nextRepoPath;
        }

        return {
          ...prev,
          ...(ovRes ? { connectionState: 'live' as const } : {}),
          overview: nextOverview,
          squadState: nextSquad,
          messages: nextMessages,
          programLogs: nextLogs,
          surfaceGraph: nextGraph,
          findings: nextFindings,
          gitOpsHistory: nextGit,
          trafficEntries: nextTraffic,
          repoFiles: nextFiles,
          selectedRepoFilePath: nextRepoPath,
          focusedFindingId: nextFocusedFindingId,
          selectedCommitSha: nextCommitSha,
        };
      });

      const focused = this.state.findings.find(
        (f) => f.findingId === this.state.focusedFindingId,
      );
      const primarySha = focused?.evidencePointers[0]?.sha256;
      if (primarySha && !this.state.harBlobsBySha[primarySha]) {
        void this.loadHarBlob(primarySha);
      }
      if (fileToLoad) {
        void this.selectRepoFile(fileToLoad);
      }
      if (commitToLoad) {
        void this.selectCommitDiff(commitToLoad);
      }
    } finally {
      this.setState((prev) => ({ ...prev, isSyncing: false }));
    }
  };

  selectProgram = async (programId: string): Promise<void> => {
    this.streamAbort?.abort();
    const summary = this.state.programs.find((p) => p.programId === programId);

    this.setState((prev) => ({
      ...prev,
      activeProgramId: programId,
      mobileDrawerOpen: false,
      isStreaming: false,
      streamError: null,
      inspectorAgentId: null,
      overview:
        prev.overview.engagement.engagementId === programId
          ? prev.overview
          : createEmptyOverview(
              programId,
              summary?.programName ?? programId,
              prev.useCloudSandbox,
              summary?.pipelineRunning ?? false,
            ),
      squadState:
        prev.squadState.programId === programId
          ? prev.squadState
          : createEmptySquadRunState(
              programId,
              summary?.pipelineRunning ?? false,
            ),
      messages: [],
      programLogs: [],
      surfaceGraph: EMPTY_SURFACE_GRAPH,
      findings: [],
      gitOpsHistory: EMPTY_GITOPS_HISTORY,
      trafficEntries: [],
      repoFiles: [],
      selectedRepoFilePath: '',
      selectedRepoFileContent: '',
      selectedCommitSha: null,
      selectedCommitDiff: '',
      focusedFindingId: null,
    }));

    if (typeof window !== 'undefined' && window.history?.replaceState) {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('program', programId);
        window.history.replaceState(
          {},
          '',
          `${url.pathname}${url.search}${url.hash}`,
        );
      } catch {
        // Ignore history state errors
      }
    }

    await this.syncProgramTelemetry(programId, { includeMessages: true });
  };

  // -------------------------------------------------------------------------
  // 24/7 Autonomous Continuous Monitoring Loop
  // -------------------------------------------------------------------------

  toggleContinuousMonitoring = async (
    intervalSeconds = 300,
  ): Promise<ContinuousMonitoringStatus | null> => {
    const programId = this.state.activeProgramId;
    if (!programId) return null;

    const current = this.state.overview.continuousMonitoring;
    const nextEnabled = !Boolean(current?.enabled);

    const optimistic: ContinuousMonitoringStatus = {
      enabled: nextEnabled,
      intervalSeconds,
      completedWaves: current?.completedWaves ?? 0,
      ...(current?.lastWaveAt ? { lastWaveAt: current.lastWaveAt } : {}),
      ...(nextEnabled
        ? {
            nextWaveAt: new Date(
              Date.now() + intervalSeconds * 1000,
            ).toISOString(),
          }
        : {}),
      ...(current?.totalCompactions !== undefined
        ? { totalCompactions: current.totalCompactions }
        : {}),
    };

    // Immediately update overview.continuousMonitoring for zero-latency UI feedback
    this.setState((prev) => ({
      ...prev,
      overview: {
        ...prev.overview,
        continuousMonitoring: optimistic,
      },
    }));

    try {
      const encProg = encodeURIComponent(programId);
      const raw = await this.fetchJson<unknown>(
        `/api/programs/${encProg}/continuous`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enabled: nextEnabled,
            intervalSeconds,
          }),
        },
      );

      const resolved = extractContinuousStatusResponse(raw, optimistic);
      this.setState((prev) => ({
        ...prev,
        connectionState: 'live',
        overview: {
          ...prev.overview,
          continuousMonitoring: resolved,
        },
      }));
      return resolved;
    } catch {
      return optimistic;
    }
  };

  // -------------------------------------------------------------------------
  // Findings, HAR Blob Fetch (/api/blobs/:sha256) & HITL Governance Decision
  // -------------------------------------------------------------------------

  selectFinding = async (findingId: string): Promise<void> => {
    this.setState((prev) => ({ ...prev, focusedFindingId: findingId }));
    const match = this.state.findings.find((f) => f.findingId === findingId);
    const primarySha = match?.evidencePointers[0]?.sha256;
    if (primarySha) {
      await this.loadHarBlob(primarySha);
    }
  };

  loadHarBlob = async (sha256: string): Promise<string | null> => {
    if (!sha256) return null;
    this.setState((prev) => ({ ...prev, loadingHarSha: sha256 }));

    try {
      const encSha = encodeURIComponent(sha256);
      let blob: BlobPayloadResponse | null =
        await this.fetchJson<BlobPayloadResponse>(`/api/blobs/${encSha}`).catch(
          () => null,
        );

      if (!blob && this.state.activeProgramId) {
        const encProg = encodeURIComponent(this.state.activeProgramId);
        blob = await this.fetchJson<BlobPayloadResponse>(
          `/api/programs/${encProg}/blobs/${encSha}`,
        ).catch(() => null);
      }

      if (blob) {
        const formatted = blob.data
          ? JSON.stringify(blob.data, null, 2)
          : blob.text;
        this.setState((prev) => ({
          ...prev,
          connectionState: 'live',
          harBlobsBySha: { ...prev.harBlobsBySha, [sha256]: formatted },
        }));
        return formatted;
      }

      return this.state.harBlobsBySha[sha256] ?? null;
    } finally {
      this.setState((prev) => ({
        ...prev,
        loadingHarSha:
          prev.loadingHarSha === sha256 ? null : prev.loadingHarSha,
      }));
    }
  };

  submitFindingDecision = async (
    findingId: string,
    status: 'APPROVED' | 'REJECTED',
    reviewerNote: string,
  ): Promise<{ persistedLive: boolean }> => {
    const payload: FindingDecisionPayload = { status, reviewerNote };
    const encFinding = encodeURIComponent(findingId);

    try {
      let res: FindingDecisionResponse | null =
        await this.fetchJson<FindingDecisionResponse>(
          `/api/findings/${encFinding}/decision`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          },
        ).catch(() => null);

      if (!res && this.state.activeProgramId) {
        const encProg = encodeURIComponent(this.state.activeProgramId);
        res = await this.fetchJson<FindingDecisionResponse>(
          `/api/programs/${encProg}/findings/${encFinding}/decision`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          },
        ).catch(() => null);
      }

      if (res?.finding) {
        const updatedFinding = res.finding;
        this.setState((prev) => ({
          ...prev,
          connectionState: 'live',
          findings: prev.findings.map((f) =>
            f.findingId === findingId ? updatedFinding : f,
          ),
        }));
        if (this.state.activeProgramId) {
          void this.syncProgramTelemetry(this.state.activeProgramId, {
            includeMessages: false,
          });
        }
        void this.refreshProgramsList();
        return { persistedLive: true };
      }
    } catch {
      // Fall back to local optimistic decision below
    }

    this.setState((prev) => ({
      ...prev,
      findings: prev.findings.map((f) =>
        f.findingId === findingId ? { ...f, status, reviewerNote } : f,
      ),
    }));
    return { persistedLive: false };
  };

  // -------------------------------------------------------------------------
  // GitOps Diff & Repository File Selection
  // -------------------------------------------------------------------------

  selectCommitDiff = async (sha: string): Promise<void> => {
    this.setState((prev) => ({ ...prev, selectedCommitSha: sha }));
    if (!this.state.activeProgramId) return;
    const encProg = encodeURIComponent(this.state.activeProgramId);
    const encSha = encodeURIComponent(sha);
    const diff = await this.fetchJson<CommitDiffResponse>(
      `/api/programs/${encProg}/gitops/commits/${encSha}`,
    ).catch(() => null);
    if (diff?.rawShow !== undefined) {
      this.setState((prev) => ({ ...prev, selectedCommitDiff: diff.rawShow }));
    }
  };

  selectRepoFile = async (filePath: string): Promise<void> => {
    this.setState((prev) => ({
      ...prev,
      selectedRepoFilePath: filePath,
    }));
    if (!this.state.activeProgramId) return;
    const encProg = encodeURIComponent(this.state.activeProgramId);
    const res = await this.fetchJson<RepoFileContentResponse>(
      `/api/programs/${encProg}/repo/file?path=${encodeURIComponent(filePath)}`,
    ).catch(() => null);
    if (res?.content !== undefined) {
      this.setState((prev) => ({
        ...prev,
        selectedRepoFileContent: res.content,
      }));
    }
  };

  // -------------------------------------------------------------------------
  // Live SSE Streaming: Launch Engagement OR Steer Active Agent
  // -------------------------------------------------------------------------

  launchFirecrawlAssessment = async (): Promise<void> => {
    this.setState((prev) => ({
      ...prev,
      newEngagementBrief: FIRECRAWL_VDP_BRIEF,
    }));
    await this.launchNewEngagement(FIRECRAWL_VDP_BRIEF);
  };

  launchNewEngagement = async (customBrief?: string): Promise<void> => {
    const brief = (customBrief ?? this.state.newEngagementBrief).trim();
    if (!brief) return;

    this.setState((prev) => ({
      ...prev,
      newEngagementModalOpen: false,
      activeView: 'operations',
      opsCompactPane: 'stream',
      activeProgramId: null,
      overview: createEmptyOverview(
        'launching-engagement',
        'Initializing Engagement…',
        prev.useCloudSandbox,
        true,
      ),
      squadState: createEmptySquadRunState('launching-engagement', true),
      messages: [],
      programLogs: [],
      surfaceGraph: EMPTY_SURFACE_GRAPH,
      findings: [],
      gitOpsHistory: EMPTY_GITOPS_HISTORY,
      trafficEntries: [],
      repoFiles: [],
      selectedRepoFilePath: '',
      selectedRepoFileContent: '',
      selectedCommitSha: null,
      selectedCommitDiff: '',
      focusedFindingId: null,
    }));

    await this.streamChatMessage({
      message: brief,
      isNewEngagement: true,
    });
  };

  sendSteeringPrompt = async (opts?: {
    message?: string;
    targetAgentId?: string | null;
  }): Promise<void> => {
    const text = (opts?.message ?? this.state.composerDraft).trim();
    if (!text) return;

    const targetAgentId =
      opts?.targetAgentId !== undefined
        ? opts.targetAgentId
        : this.state.steerTargetAgentId;

    this.setState((prev) => ({
      ...prev,
      composerDraft: opts?.message !== undefined ? prev.composerDraft : '',
      inspectorSteerDraft: '',
    }));

    await this.streamChatMessage({
      message: text,
      targetAgentId: targetAgentId ?? undefined,
      isNewEngagement: false,
    });
  };

  private streamChatMessage = async (params: {
    message: string;
    targetAgentId?: string;
    isNewEngagement: boolean;
  }): Promise<void> => {
    const { message, targetAgentId, isNewEngagement } = params;

    this.streamAbort?.abort();
    const controller = new AbortController();
    this.streamAbort = controller;

    const nowIso = new Date().toISOString();
    const userEventId = `local-user-${Date.now()}`;
    const synthesisEventId = `live-synthesis-${Date.now()}`;
    const currentProgId = isNewEngagement
      ? undefined
      : (this.state.activeProgramId ?? undefined);

    this.setState((prev) => {
      const targetAgent: SquadAgentNode | undefined = targetAgentId
        ? prev.squadState.agents.find((a) => a.id === targetAgentId)
        : prev.squadState.agents.find((a) => a.parentId === null) ??
          prev.squadState.agents[0];

      const nextSeq =
        prev.squadState.timeline.reduce((m, e) => Math.max(m, e.seq), 0) + 1;

      const userTimelineEvent: SquadTimelineEvent = {
        seq: nextSeq,
        id: userEventId,
        timestamp: nowIso,
        agentId: targetAgent?.id ?? 'supervisor-orchestrator',
        agentName: targetAgent?.name ?? 'Lead Squad Orchestrator',
        agentRole: targetAgent?.role ?? 'orchestrator',
        kind: isNewEngagement ? 'user_brief' : 'agent_message',
        title: isNewEngagement
          ? 'Submitted Bugcrowd Engagement Brief'
          : `Operator Steering -> ${targetAgent?.name ?? 'Lead Squad Orchestrator'}`,
        detail: message,
        status: 'completed',
      };

      return {
        ...prev,
        isStreaming: true,
        streamingSynthesisText: '',
        streamError: null,
        squadState: {
          ...prev.squadState,
          status: 'running',
          timeline: mergeTimelineEvents(prev.squadState.timeline, [
            userTimelineEvent,
          ]),
        },
      };
    });

    try {
      const res = await this.fetchImpl('/api/chat/stream', {
        method: 'POST',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...(currentProgId ? { programId: currentProgId } : {}),
          ...(targetAgentId ? { targetAgentId } : {}),
          message,
          useCloudSandbox: this.state.useCloudSandbox,
        }),
      });

      if (!res.ok || !res.body) {
        throw new Error(`Chat stream returned HTTP ${res.status}`);
      }

      this.setState((prev) => ({ ...prev, connectionState: 'live' }));

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let accumulatedDelta = '';

      const processFrames = (
        frames: Array<{ event: string; data: unknown }>,
      ): void => {
        for (const frame of frames) {
          if (frame.event === 'program_selected') {
            const ev = frame.data as SseProgramSelectedEvent;
            this.setState((prev) => ({
              ...prev,
              activeProgramId: ev.programId,
              overview: {
                ...prev.overview,
                engagement: {
                  ...prev.overview.engagement,
                  engagementId: ev.programId,
                  programName: ev.programName,
                },
                runtime: {
                  ...prev.overview.runtime,
                  pipelineRunning: true,
                },
              },
              squadState: {
                ...prev.squadState,
                programId: ev.programId,
                status: 'running',
              },
            }));
            void this.refreshProgramsList();
          } else if (frame.event === 'scope_updated') {
            const ev = frame.data as SseScopeUpdatedEvent;
            this.setState((prev) => ({
              ...prev,
              overview: {
                ...prev.overview,
                engagement: {
                  ...prev.overview.engagement,
                  engagementId: ev.programId,
                  programName: ev.programName,
                  authorizedDomains: ev.authorizedDomains,
                  excludedHosts: ev.excludedHosts,
                  excludedPaths: ev.excludedPaths,
                  maxRpsPerHost: ev.maxRpsPerHost,
                  complianceHeaders: ev.complianceHeaders,
                },
                scopeYaml: ev.scopeYaml,
              },
            }));
          } else if (frame.event === 'squad_event') {
            const raw = frame.data as
              | SseSquadEventPayload
              | SquadTimelineEvent
              | Record<string, unknown>;
            const eventObj: SquadTimelineEvent | null =
              raw && typeof raw === 'object' && 'event' in raw && raw.event
                ? (raw.event as SquadTimelineEvent)
                : raw && typeof raw === 'object' && 'kind' in raw
                  ? (raw as unknown as SquadTimelineEvent)
                  : null;
            const fullSquadState: SquadRunState | null =
              raw &&
              typeof raw === 'object' &&
              'squadState' in raw &&
              raw.squadState
                ? (raw.squadState as SquadRunState)
                : null;

            this.setState((prev) => {
              let baseSquad = fullSquadState
                ? {
                    ...fullSquadState,
                    timeline: mergeTimelineEvents(
                      prev.squadState.timeline,
                      fullSquadState.timeline ?? [],
                    ),
                  }
                : { ...prev.squadState };

              if (eventObj) {
                baseSquad = {
                  ...baseSquad,
                  timeline: mergeTimelineEvents(baseSquad.timeline, [eventObj]),
                };

                // Ensure root supervisor exists if an event arrives before fullSquadState
                if (
                  eventObj.agentRole === 'orchestrator' &&
                  !baseSquad.agents.some((a) => a.id === eventObj.agentId)
                ) {
                  const rootNode: SquadAgentNode = {
                    id: eventObj.agentId,
                    parentId: null,
                    name: eventObj.agentName || 'Lead Squad Orchestrator',
                    role: 'orchestrator',
                    provider: 'openrouter',
                    model: prev.overview.runtime.orchestratorModel,
                    skills: [],
                    status: 'running',
                    task: eventObj.title,
                    missionPrompt: eventObj.detail,
                    systemDirective:
                      'Dynamic Cyber Squad Supervisor enforcing HTTP 451 scope boundaries and Bugcrowd VRT verification.',
                    worktreeBranch: 'main',
                    toolCallCount: 0,
                    messageCount: 1,
                    createdAt: eventObj.timestamp,
                    updatedAt: eventObj.timestamp,
                  };
                  baseSquad = {
                    ...baseSquad,
                    agents: [rootNode, ...baseSquad.agents],
                  };
                }

                // Ensure spawned child agent appears immediately in Agent Tree even before full snapshot
                if (
                  eventObj.kind === 'spawn_agent' &&
                  eventObj.data &&
                  typeof eventObj.data.childAgentId === 'string'
                ) {
                  const childId = eventObj.data.childAgentId;
                  if (!baseSquad.agents.some((a) => a.id === childId)) {
                    const parsedSkills = Array.isArray(eventObj.data.skills)
                      ? eventObj.data.skills.map((s) => String(s))
                      : [];
                    const parsedTools = Array.isArray(
                      eventObj.data.allowedTools,
                    )
                      ? eventObj.data.allowedTools.map((t) => String(t))
                      : undefined;
                    const parsedCtx = parseContextStats(
                      eventObj.data.contextStats,
                    );

                    const childNode: SquadAgentNode = {
                      id: childId,
                      parentId: eventObj.agentId,
                      name:
                        typeof eventObj.data.childAgentName === 'string'
                          ? eventObj.data.childAgentName
                          : eventObj.title,
                      role:
                        (eventObj.data.childRole as SquadAgentNode['role']) ??
                        'recon',
                      provider:
                        typeof eventObj.data.provider === 'string'
                          ? eventObj.data.provider
                          : 'groq',
                      model:
                        typeof eventObj.data.model === 'string'
                          ? eventObj.data.model
                          : prev.overview.runtime.subagentModel,
                      skills: parsedSkills,
                      status: 'running',
                      task: eventObj.detail,
                      missionPrompt:
                        typeof eventObj.data.missionPrompt === 'string'
                          ? eventObj.data.missionPrompt
                          : eventObj.detail,
                      systemDirective:
                        typeof eventObj.data.systemDirective === 'string'
                          ? eventObj.data.systemDirective
                          : 'Execute scoped specialist task via Mandatory Egress Gateway.',
                      ...(typeof eventObj.data.worktreeBranch === 'string'
                        ? { worktreeBranch: eventObj.data.worktreeBranch }
                        : {}),
                      ...(typeof eventObj.data.personaRationale === 'string'
                        ? { personaRationale: eventObj.data.personaRationale }
                        : {}),
                      ...(parsedTools ? { allowedTools: parsedTools } : {}),
                      ...(parsedCtx ? { contextStats: parsedCtx } : {}),
                      toolCallCount: 1,
                      messageCount: 1,
                      createdAt: eventObj.timestamp,
                      updatedAt: eventObj.timestamp,
                    };
                    baseSquad = {
                      ...baseSquad,
                      agents: [...baseSquad.agents, childNode],
                    };
                  }
                }

                // Live contextStats update on existing agent if emitted on event data
                const liveCtx = parseContextStats(eventObj.data?.contextStats);
                if (liveCtx) {
                  baseSquad = {
                    ...baseSquad,
                    agents: baseSquad.agents.map((a) =>
                      a.id === eventObj.agentId
                        ? { ...a, contextStats: liveCtx }
                        : a,
                    ),
                  };
                }
              }

              return {
                ...prev,
                squadState: baseSquad,
              };
            });
          } else if (frame.event === 'log') {
            const logEntry = frame.data as ProgramLogEntry;
            this.setState((prev) => ({
              ...prev,
              programLogs: mergeLogs(prev.programLogs, [logEntry]),
            }));
          } else if (frame.event === 'assistant_delta') {
            const ev = frame.data as SseAssistantDeltaEvent;
            accumulatedDelta += ev.delta;
            const currentText = accumulatedDelta;
            this.setState((prev) => {
              const maxSeq = prev.squadState.timeline.reduce(
                (m, item) =>
                  item.id === synthesisEventId ? m : Math.max(m, item.seq),
                0,
              );
              const rootAgent = prev.squadState.agents.find(
                (a) => a.parentId === null,
              );
              const synthEvent: SquadTimelineEvent = {
                seq: maxSeq + 1,
                id: synthesisEventId,
                timestamp: new Date().toISOString(),
                agentId: rootAgent?.id ?? 'supervisor-orchestrator',
                agentName: rootAgent?.name ?? 'Lead Squad Orchestrator',
                agentRole: 'orchestrator',
                kind: 'assistant_synthesis',
                title: 'Executive Investigation Synthesis',
                detail: currentText,
                status: 'running',
              };
              return {
                ...prev,
                streamingSynthesisText: currentText,
                squadState: {
                  ...prev.squadState,
                  timeline: mergeTimelineEvents(prev.squadState.timeline, [
                    synthEvent,
                  ]),
                },
              };
            });
          } else if (frame.event === 'telemetry_refresh') {
            const ev = frame.data as SseTelemetryRefreshEvent;
            void this.syncProgramTelemetry(ev.programId, {
              includeMessages: false,
            });
            void this.refreshProgramsList();
          } else if (frame.event === 'done') {
            const ev = frame.data as SseDoneEvent;
            this.setState((prev) => ({
              ...prev,
              isStreaming: false,
              overview: {
                ...prev.overview,
                runtime: {
                  ...prev.overview.runtime,
                  pipelineRunning: false,
                },
              },
              squadState: {
                ...prev.squadState,
                status: 'completed',
                timeline: prev.squadState.timeline.map((item) =>
                  item.id === synthesisEventId
                    ? { ...item, status: 'completed' as const }
                    : item,
                ),
              },
            }));
            void this.syncProgramTelemetry(ev.programId, {
              includeMessages: true,
            });
            void this.refreshProgramsList();
          } else if (frame.event === 'error') {
            const ev = frame.data as SseErrorEvent;
            this.setState((prev) => ({
              ...prev,
              streamError: ev.message,
              isStreaming: false,
            }));
          }
        }
      };

      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          buffer += decoder.decode();
          const parsed = consumeSseBuffer(buffer, true);
          processFrames(parsed.frames);
          break;
        }
        buffer += decoder.decode(value, { stream: true });
        const parsed = consumeSseBuffer(buffer, false);
        buffer = parsed.remainder;
        processFrames(parsed.frames);
      }
    } catch (err: unknown) {
      if ((err as { name?: string })?.name !== 'AbortError') {
        const msg = err instanceof Error ? err.message : String(err);
        this.setState((prev) => ({
          ...prev,
          streamError: msg,
        }));
      }
    } finally {
      this.setState((prev) => ({ ...prev, isStreaming: false }));
    }
  };
}
