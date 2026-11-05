import React, { useEffect, useMemo, useRef, useSyncExternalStore } from 'react';
import { AgentInspectorModal } from './components/AgentInspectorModal';
import { FindingsView } from './components/FindingsView';
import { GitOpsEgressView } from './components/GitOpsEgressView';
import { HypothesesView } from './components/HypothesesView';
import { LeftNavRail } from './components/LeftNavRail';
import { NewEngagementModal } from './components/NewEngagementModal';
import { OperationsView } from './components/OperationsView';
import { ReconCoverageView } from './components/ReconCoverageView';
import { TopHeaderBar } from './components/TopHeaderBar';
import { DashboardController } from './dashboardController';
import type { PrimaryWorkspaceView } from './types';

export interface AppProps {
  controller?: DashboardController;
  initialView?: PrimaryWorkspaceView;
  autoHydrate?: boolean;
}

export const App: React.FC<AppProps> = ({
  controller: externalController,
  initialView,
  autoHydrate,
}) => {
  const internalControllerRef = useRef<DashboardController | null>(null);
  if (!externalController && !internalControllerRef.current) {
    internalControllerRef.current = new DashboardController(
      initialView ? { initialView } : undefined,
    );
  }

  const ctrl = externalController ?? internalControllerRef.current!;
  const state = useSyncExternalStore(
    ctrl.subscribe,
    ctrl.getSnapshot,
    ctrl.getSnapshot,
  );

  const shouldAutoHydrate = autoHydrate ?? !externalController;

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', state.theme);
    }
  }, [state.theme]);

  useEffect(() => {
    if (!shouldAutoHydrate) return;
    void ctrl.hydrateFromServer();
  }, [ctrl, shouldAutoHydrate]);

  useEffect(() => {
    if (
      !shouldAutoHydrate ||
      state.connectionState !== 'live' ||
      !state.activeProgramId ||
      state.isStreaming
    ) {
      return;
    }
    const programId = state.activeProgramId;
    const isPipelineActive =
      state.overview.runtime.pipelineRunning ||
      state.squadState.status === 'running';
    const intervalMs = isPipelineActive ? 2500 : 8000;

    const timer = globalThis.setInterval(() => {
      void ctrl.syncProgramTelemetry(programId, { includeMessages: false });
    }, intervalMs);

    return () => globalThis.clearInterval(timer);
  }, [
    ctrl,
    shouldAutoHydrate,
    state.connectionState,
    state.activeProgramId,
    state.isStreaming,
    state.overview.runtime.pipelineRunning,
    state.squadState.status,
  ]);

  const derivedMetrics = useMemo(() => {
    let graphHosts = 0;
    let graphRoutes = 0;
    for (const node of state.surfaceGraph.nodes) {
      if (node.type === 'HOST') graphHosts += 1;
      if (node.type === 'ENDPOINT') graphRoutes += 1;
    }

    const hosts =
      state.overview.metrics.hostsDiscovered > 0
        ? state.overview.metrics.hostsDiscovered
        : graphHosts;
    const routes =
      state.overview.metrics.canonicalEndpoints > 0
        ? state.overview.metrics.canonicalEndpoints
        : graphRoutes;
    const blockedTrafficCount = state.trafficEntries.filter(
      (t) => t.decision === 'BLOCKED_SCOPE_451',
    ).length;
    const blocked451 = Math.max(
      state.overview.metrics.blockedScope451,
      blockedTrafficCount,
    );
    const pendingFindings = state.findings.filter(
      (f) => f.status === 'PENDING_HUMAN_REVIEW',
    ).length;

    return {
      hosts,
      routes,
      hypotheses: state.squadState.hypotheses.length,
      findings: state.findings.length,
      pendingFindings,
      blocked451,
      coverage: state.squadState.coverage.length,
      agents: state.squadState.agents.length,
      gitops:
        state.gitOpsHistory.reviews.length > 0
          ? state.gitOpsHistory.reviews.length
          : state.gitOpsHistory.commits.length,
    };
  }, [
    state.surfaceGraph.nodes,
    state.overview.metrics,
    state.trafficEntries,
    state.findings,
    state.squadState.hypotheses.length,
    state.squadState.coverage.length,
    state.squadState.agents.length,
    state.gitOpsHistory.reviews.length,
    state.gitOpsHistory.commits.length,
  ]);

  const inspectorAgent = useMemo(() => {
    if (!state.inspectorAgentId) return null;
    return (
      state.squadState.agents.find((a) => a.id === state.inspectorAgentId) ??
      null
    );
  }, [state.inspectorAgentId, state.squadState.agents]);

  const isLiveRunning = Boolean(
    state.isStreaming ||
      state.overview.runtime.pipelineRunning ||
      state.squadState.status === 'running',
  );

  const hasActiveProgram = Boolean(
    state.activeProgramId ||
      state.isStreaming ||
      state.squadState.timeline.length > 0,
  );

  return (
    <div className="oc-app-shell" data-active-view={state.activeView}>
      <LeftNavRail
        theme={state.theme}
        desktopCollapsed={state.desktopRailCollapsed}
        mobileOpen={state.mobileDrawerOpen}
        activeView={state.activeView}
        connectionState={state.connectionState}
        useCloudSandbox={state.useCloudSandbox}
        programs={state.programs}
        activeProgramId={state.activeProgramId}
        counts={{
          agents: derivedMetrics.agents,
          hypotheses: derivedMetrics.hypotheses,
          coverage: derivedMetrics.coverage,
          findings: derivedMetrics.findings,
          pendingFindings: derivedMetrics.pendingFindings,
          gitops: derivedMetrics.gitops,
        }}
        onToggleTheme={ctrl.toggleTheme}
        onCollapseDesktop={ctrl.toggleDesktopRail}
        onCloseMobile={() => ctrl.setMobileDrawerOpen(false)}
        onSelectView={(view) => ctrl.setActiveView(view)}
        onSelectProgram={(programId) => {
          void ctrl.selectProgram(programId);
        }}
        onOpenNewEngagement={ctrl.openNewEngagementModal}
      />

      <div className="oc-main-canvas">
        <TopHeaderBar
          title={state.overview.engagement.programName}
          primaryDomain={state.overview.engagement.authorizedDomains[0]}
          isLiveRunning={isLiveRunning}
          isSyncing={state.isSyncing}
          desktopRailCollapsed={state.desktopRailCollapsed}
          metrics={{
            hosts: derivedMetrics.hosts,
            routes: derivedMetrics.routes,
            hypotheses: derivedMetrics.hypotheses,
            findings: derivedMetrics.findings,
            blocked451: derivedMetrics.blocked451,
          }}
          onOpenMobileDrawer={() => ctrl.setMobileDrawerOpen(true)}
          onExpandDesktopRail={ctrl.toggleDesktopRail}
          onNavigate={(view, subOptions) => ctrl.setActiveView(view, subOptions)}
          onRefreshTelemetry={() => {
            if (state.activeProgramId) {
              void ctrl.syncProgramTelemetry(state.activeProgramId, {
                includeMessages: true,
              });
            } else {
              void ctrl.hydrateFromServer();
            }
          }}
        />

        {state.activeView === 'operations' && (
          <OperationsView
            hasActiveProgram={hasActiveProgram}
            squadState={state.squadState}
            compactPane={state.opsCompactPane}
            composerExpanded={state.composerExpanded}
            composerDraft={state.composerDraft}
            steerTargetAgentId={state.steerTargetAgentId}
            isStreaming={state.isStreaming}
            streamError={state.streamError}
            onSelectCompactPane={ctrl.setOpsCompactPane}
            onInspectAgent={(agentId, tab) =>
              ctrl.openAgentInspector(agentId, tab)
            }
            onNavigateView={(view, opts) => ctrl.setActiveView(view, opts)}
            onOpenNewEngagement={ctrl.openNewEngagementModal}
            onExpandComposer={() => ctrl.setComposerExpanded(true)}
            onCollapseComposer={() => ctrl.setComposerExpanded(false)}
            onDraftChange={ctrl.setComposerDraft}
            onSelectTargetAgent={ctrl.setSteerTargetAgentId}
            onSendSteer={(message) => {
              void ctrl.sendSteeringPrompt({ message });
            }}
          />
        )}

        {state.activeView === 'hypotheses' && (
          <HypothesesView
            hypotheses={state.squadState.hypotheses}
            threatModel={state.squadState.threatModel}
            agents={state.squadState.agents}
            onInspectAgent={(agentId) =>
              ctrl.openAgentInspector(agentId, 'transcript')
            }
            onOpenFinding={(findingId) =>
              ctrl.setActiveView('findings', { findingId })
            }
          />
        )}

        {state.activeView === 'recon' && (
          <ReconCoverageView
            sectionTab={state.reconSectionTab}
            overview={state.overview}
            graph={state.surfaceGraph}
            coverage={state.squadState.coverage}
            findings={state.findings}
            onSelectSectionTab={ctrl.setReconSectionTab}
            onInspectAgent={(agentId) =>
              ctrl.openAgentInspector(agentId, 'transcript')
            }
            onOpenFinding={(findingId) =>
              ctrl.setActiveView('findings', { findingId })
            }
          />
        )}

        {state.activeView === 'findings' && (
          <FindingsView
            findings={state.findings}
            hypotheses={state.squadState.hypotheses}
            focusedFindingId={state.focusedFindingId}
            harBlobsBySha={state.harBlobsBySha}
            loadingHarSha={state.loadingHarSha}
            onSelectFinding={(findingId) => {
              void ctrl.selectFinding(findingId);
            }}
            onLoadHarBlob={(sha256) => {
              void ctrl.loadHarBlob(sha256);
            }}
            onSubmitDecision={ctrl.submitFindingDecision}
          />
        )}

        {state.activeView === 'gitops' && (
          <GitOpsEgressView
            sectionTab={state.gitOpsSectionTab}
            history={state.gitOpsHistory}
            selectedCommitSha={state.selectedCommitSha}
            selectedCommitDiff={state.selectedCommitDiff}
            repoFiles={state.repoFiles}
            selectedFilePath={state.selectedRepoFilePath}
            selectedFileContent={state.selectedRepoFileContent}
            trafficEntries={state.trafficEntries}
            onSelectSectionTab={ctrl.setGitOpsSectionTab}
            onSelectCommit={(sha) => {
              void ctrl.selectCommitDiff(sha);
            }}
            onSelectRepoFile={(filePath) => {
              void ctrl.selectRepoFile(filePath);
            }}
          />
        )}
      </div>

      <AgentInspectorModal
        agent={inspectorAgent}
        timeline={state.squadState.timeline}
        activeTab={state.inspectorTab}
        steerDraft={state.inspectorSteerDraft}
        isStreaming={state.isStreaming}
        onClose={ctrl.closeAgentInspector}
        onSelectTab={ctrl.setInspectorTab}
        onSteerDraftChange={ctrl.setInspectorSteerDraft}
        onSendSteer={(message, targetAgentId) => {
          void ctrl.sendSteeringPrompt({ message, targetAgentId });
        }}
      />

      <NewEngagementModal
        open={state.newEngagementModalOpen}
        brief={state.newEngagementBrief}
        useCloudSandbox={state.useCloudSandbox}
        isStreaming={state.isStreaming}
        onClose={ctrl.closeNewEngagementModal}
        onBriefChange={ctrl.setNewEngagementBrief}
        onApplyPreset={ctrl.applyBriefPreset}
        onToggleSandbox={ctrl.setUseCloudSandbox}
        onLaunch={() => {
          void ctrl.launchNewEngagement();
        }}
      />
    </div>
  );
};

export default App;
