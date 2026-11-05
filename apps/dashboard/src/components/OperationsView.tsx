import React, { useMemo, useState } from 'react';
import {
  ArrowUpRight,
  Bot,
  Brain,
  CheckCircle2,
  ClipboardCheck,
  Compass,
  Crosshair,
  Eye,
  FileText,
  GitBranch,
  Lightbulb,
  MessageSquare,
  Plus,
  Sparkles,
} from 'lucide-react';
import type { OperationsCompactPane } from '../dashboardController';
import { renderMarkdownBlocks } from '../markdown';
import type {
  HypothesisClosureState,
  PrimaryWorkspaceView,
  SecurityHypothesis,
  SquadRunState,
  SquadTimelineEvent,
  SquadTimelineEventKind,
} from '../types';
import { AgentSquadTree } from './AgentSquadTree';
import { SteeringComposerDock } from './SteeringComposerDock';

export interface OperationsViewProps {
  hasActiveProgram: boolean;
  squadState: SquadRunState;
  compactPane: OperationsCompactPane;
  composerExpanded: boolean;
  composerDraft: string;
  steerTargetAgentId: string | null;
  isStreaming: boolean;
  streamError: string | null;
  onSelectCompactPane: (pane: OperationsCompactPane) => void;
  onInspectAgent: (
    agentId: string,
    tab?: 'transcript' | 'prompt' | 'report',
  ) => void;
  onNavigateView: (
    view: PrimaryWorkspaceView,
    opts?: { findingId?: string },
  ) => void;
  onOpenNewEngagement: () => void;
  onExpandComposer: () => void;
  onCollapseComposer: () => void;
  onDraftChange: (draft: string) => void;
  onSelectTargetAgent: (agentId: string | null) => void;
  onSendSteer: (message?: string) => void;
}

type TimelineFilter =
  | 'ALL'
  | 'think'
  | 'recon_step'
  | 'threat_model'
  | 'hypothesis'
  | 'spawn_agent'
  | 'coverage'
  | 'verification';

export function formatShortClock(iso: string): string {
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) return iso;
  return new Date(parsed).toISOString().slice(11, 19) + 'Z';
}

export function eventKindMeta(kind: SquadTimelineEventKind): {
  label: string;
  badgeClass: string;
  icon: React.ReactNode;
} {
  switch (kind) {
    case 'user_brief':
      return {
        label: 'ENGAGEMENT BRIEF',
        badgeClass: 'oc-badge mono',
        icon: <FileText size={13} />,
      };
    case 'think':
      return {
        label: 'THINK · REASONING',
        badgeClass: 'oc-badge oc-badge-amber mono',
        icon: <Brain size={13} />,
      };
    case 'recon_step':
      return {
        label: 'RECON STEP',
        badgeClass: 'oc-badge oc-badge-cyan mono',
        icon: <Compass size={13} />,
      };
    case 'threat_model':
      return {
        label: 'THREAT MODEL',
        badgeClass: 'oc-badge oc-badge-cyan mono',
        icon: <Crosshair size={13} />,
      };
    case 'hypothesis':
      return {
        label: 'HYPOTHESIS',
        badgeClass: 'oc-badge oc-badge-amber mono',
        icon: <Lightbulb size={13} />,
      };
    case 'spawn_agent':
      return {
        label: 'SPAWN SPECIALIST',
        badgeClass: 'oc-badge oc-badge-cyan mono',
        icon: <Bot size={13} />,
      };
    case 'agent_message':
      return {
        label: 'SQUAD COMMS',
        badgeClass: 'oc-badge mono',
        icon: <MessageSquare size={13} />,
      };
    case 'coverage':
      return {
        label: 'COVERAGE LEDGER',
        badgeClass: 'oc-badge oc-badge-emerald mono',
        icon: <ClipboardCheck size={13} />,
      };
    case 'verification':
      return {
        label: 'COUNTEREVIDENCE & POC',
        badgeClass: 'oc-badge oc-badge-emerald mono',
        icon: <CheckCircle2 size={13} />,
      };
    case 'assistant_synthesis':
      return {
        label: 'SQUAD SYNTHESIS',
        badgeClass: 'oc-badge oc-badge-cyan mono',
        icon: <Sparkles size={13} />,
      };
    default:
      return {
        label: String(kind).toUpperCase(),
        badgeClass: 'oc-badge mono',
        icon: <Bot size={13} />,
      };
  }
}

export function closureBadgeMeta(state: HypothesisClosureState): {
  label: string;
  className: string;
  barColor: string;
} {
  switch (state) {
    case 'confirmed':
      return {
        label: 'CONFIRMED',
        className: 'oc-badge oc-badge-coral mono',
        barColor: 'var(--coral-fg)',
      };
    case 'ruled_out':
      return {
        label: 'RULED OUT · CONTROL',
        className: 'oc-badge oc-badge-emerald mono',
        barColor: 'var(--emerald-fg)',
      };
    case 'open_proof_gap':
      return {
        label: 'OPEN PROOF GAP',
        className: 'oc-badge oc-badge-amber mono',
        barColor: 'var(--amber-fg)',
      };
    case 'testing':
      return {
        label: 'TESTING',
        className: 'oc-badge oc-badge-cyan mono',
        barColor: 'var(--cyan-fg)',
      };
    case 'open':
      return {
        label: 'OPEN',
        className: 'oc-badge oc-badge-amber mono',
        barColor: 'var(--amber-fg)',
      };
  }
}

const TimelineEventCard: React.FC<{
  event: SquadTimelineEvent;
  onInspectAgent: (
    agentId: string,
    tab?: 'transcript' | 'prompt' | 'report',
  ) => void;
}> = ({ event, onInspectAgent }) => {
  const [briefExpanded, setBriefExpanded] = useState(false);
  const meta = eventKindMeta(event.kind);

  const spawnedAgentId =
    event.kind === 'spawn_agent' &&
    event.data &&
    typeof event.data.childAgentId === 'string'
      ? event.data.childAgentId
      : event.agentId;

  const worktreeBranch =
    event.data && typeof event.data.worktreeBranch === 'string'
      ? event.data.worktreeBranch
      : null;

  const isLongBrief =
    event.kind === 'user_brief' && event.detail.split('\n').length > 6;
  const displayedDetail =
    isLongBrief && !briefExpanded
      ? event.detail.split('\n').slice(0, 5).join('\n') + '\n…'
      : event.detail;

  return (
    <article className="oc-timeline-card" data-event-kind={event.kind}>
      <div className="oc-timeline-header">
        <div className="oc-timeline-header-left">
          <span className={meta.badgeClass}>
            {meta.icon}
            <span>{meta.label}</span>
          </span>

          <button
            type="button"
            className="oc-badge mono"
            style={{ cursor: 'pointer' }}
            onClick={() => onInspectAgent(event.agentId, 'transcript')}
            title={`Inspect ${event.agentName}`}
          >
            {event.agentName}
          </button>

          {worktreeBranch && (
            <span className="oc-badge mono">
              <GitBranch size={11} />
              {worktreeBranch}
            </span>
          )}
        </div>

        <span
          className="mono"
          style={{ fontSize: '11px', color: 'var(--text-muted)' }}
        >
          {formatShortClock(event.timestamp)}
        </span>
      </div>

      <div className="oc-timeline-title">{event.title}</div>

      {event.kind === 'assistant_synthesis' ? (
        <div className="oc-markdown">{renderMarkdownBlocks(event.detail)}</div>
      ) : (
        <p className="oc-timeline-detail">{displayedDetail}</p>
      )}

      {isLongBrief && (
        <div>
          <button
            type="button"
            className="oc-btn"
            style={{ height: 24, fontSize: '11px', padding: '0 8px' }}
            onClick={() => setBriefExpanded((v) => !v)}
          >
            {briefExpanded ? 'Collapse brief' : 'Show full brief'}
          </button>
        </div>
      )}

      {event.kind === 'spawn_agent' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
          <button
            type="button"
            id={`btn-inspect-spawn-${spawnedAgentId}`}
            className="oc-btn"
            style={{ height: 26, fontSize: '11.5px' }}
            onClick={() => onInspectAgent(spawnedAgentId, 'prompt')}
          >
            <Eye size={12} style={{ color: 'var(--cyan-fg)' }} />
            <span>Inspect Prompt &amp; Transcript</span>
          </button>
        </div>
      )}
    </article>
  );
};

const CompactHypothesisSummaryList: React.FC<{
  hypotheses: SecurityHypothesis[];
  onOpenBoard: () => void;
}> = ({ hypotheses, onOpenBoard }) => {
  return (
    <div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
          marginBottom: 8,
        }}
      >
        <span style={{ fontSize: '12px', fontWeight: 600 }}>
          Active Hypotheses ({hypotheses.length})
        </span>
        <button
          type="button"
          className="oc-btn"
          style={{ height: 23, fontSize: '11px', padding: '0 8px' }}
          onClick={onOpenBoard}
        >
          <span>Full Board</span>
          <ArrowUpRight size={11} />
        </button>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
        {hypotheses.slice(0, 5).map((hyp) => {
          const meta = closureBadgeMeta(hyp.closureState);
          return (
            <div
              key={hyp.id}
              className="oc-agent-node-card"
              style={{ cursor: 'pointer' }}
              onClick={onOpenBoard}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 6,
                }}
              >
                <span className="mono" style={{ fontSize: '11px', fontWeight: 600 }}>
                  {hyp.id} · {hyp.riskCategory}
                </span>
                <span className="mono" style={{ fontSize: '11px', fontWeight: 600 }}>
                  {hyp.confidence}%
                </span>
              </div>

              <div className="oc-confidence-track">
                <div
                  className="oc-confidence-fill"
                  style={{
                    width: `${Math.max(3, Math.min(100, hyp.confidence))}%`,
                    background: meta.barColor,
                  }}
                />
              </div>

              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 6,
                }}
              >
                <span
                  className="mono truncate"
                  style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}
                >
                  {hyp.surface}
                </span>
                <span
                  className={meta.className}
                  style={{ height: 18, fontSize: '9.5px', padding: '0 6px' }}
                >
                  {meta.label}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export const OperationsView: React.FC<OperationsViewProps> = ({
  hasActiveProgram,
  squadState,
  compactPane,
  composerExpanded,
  composerDraft,
  steerTargetAgentId,
  isStreaming,
  streamError,
  onSelectCompactPane,
  onInspectAgent,
  onNavigateView,
  onOpenNewEngagement,
  onExpandComposer,
  onCollapseComposer,
  onDraftChange,
  onSelectTargetAgent,
  onSendSteer,
}) => {
  const [timelineFilter, setTimelineFilter] = useState<TimelineFilter>('ALL');

  const filteredTimeline = useMemo(() => {
    if (timelineFilter === 'ALL') return squadState.timeline;
    return squadState.timeline.filter((ev) => ev.kind === timelineFilter);
  }, [squadState.timeline, timelineFilter]);

  const kindsSeen = useMemo(
    () => new Set(squadState.timeline.map((e) => e.kind)),
    [squadState.timeline],
  );

  const phases = [
    { label: '01 Initial Gathering', done: kindsSeen.has('user_brief') || kindsSeen.has('think') },
    { label: '02 Step-by-Step Recon', done: kindsSeen.has('recon_step') },
    { label: '03 Shared Threat Model', done: Boolean(squadState.threatModel) || kindsSeen.has('threat_model') },
    { label: '04 Hypothesis Board', done: squadState.hypotheses.length > 0 || kindsSeen.has('hypothesis') },
    { label: '05 Counterevidence Validation', done: kindsSeen.has('verification') || squadState.status === 'completed' },
  ];

  return (
    <div className="oc-ops-shell">
      {/* Segmented Switcher Bar for < 1180px Viewports (Zero 3-Column Squeeze) */}
      <div className="oc-ops-mobile-tabs" role="tablist" aria-label="Operations Panels">
        <button
          type="button"
          id="ops-tab-stream"
          role="tab"
          aria-selected={compactPane === 'stream'}
          className={`oc-segmented-btn${compactPane === 'stream' ? ' is-active' : ''}`}
          onClick={() => onSelectCompactPane('stream')}
        >
          Live Stream ({squadState.timeline.length})
        </button>
        <button
          type="button"
          id="ops-tab-agents"
          role="tab"
          aria-selected={compactPane === 'agents'}
          className={`oc-segmented-btn${compactPane === 'agents' ? ' is-active' : ''}`}
          onClick={() => onSelectCompactPane('agents')}
        >
          Agent Tree ({squadState.agents.length})
        </button>
        <button
          type="button"
          id="ops-tab-hypotheses"
          role="tab"
          aria-selected={compactPane === 'hypotheses'}
          className={`oc-segmented-btn${compactPane === 'hypotheses' ? ' is-active' : ''}`}
          onClick={() => onSelectCompactPane('hypotheses')}
        >
          Hypotheses ({squadState.hypotheses.length})
        </button>
      </div>

      <div className="oc-ops-grid">
        {/* Left Pane: Live Squad Investigation Stream + Collapsible Steering Dock */}
        <section
          className={`oc-ops-stream-col${compactPane !== 'stream' ? ' is-compact-hidden' : ''}`}
          aria-label="Live Squad Investigation Stream"
        >
          <div className="oc-ops-stream-scroll">
            {/* Cyber Squad Methodology Progression */}
            <div className="oc-phase-strip">
              {phases.map((p, idx) => {
                const isCurrent =
                  !p.done && (idx === 0 || phases[idx - 1]?.done === true);
                return (
                  <span
                    key={p.label}
                    className={`oc-phase-step mono${
                      p.done ? ' is-done' : isCurrent ? ' is-current' : ''
                    }`}
                  >
                    {p.label}
                  </span>
                );
              })}
            </div>

            {/* Event Kind Filter Bar */}
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                gap: 6,
              }}
            >
              {(
                [
                  ['ALL', 'All Events'],
                  ['think', 'Think'],
                  ['recon_step', 'Recon'],
                  ['threat_model', 'Threat Model'],
                  ['spawn_agent', 'Delegations'],
                  ['hypothesis', 'Hypotheses'],
                  ['coverage', 'Coverage'],
                  ['verification', 'Verification'],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  className={`oc-segmented-btn${timelineFilter === key ? ' is-active' : ''}`}
                  style={{ height: 25, fontSize: '11.5px', padding: '0 9px' }}
                  onClick={() => setTimelineFilter(key)}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Empty / Ready Launchpad Card if no engagement started yet */}
            {!hasActiveProgram && squadState.timeline.length === 0 ? (
              <div
                className="oc-section-card"
                style={{ padding: '28px 22px', textAlign: 'center' }}
              >
                <div
                  style={{
                    fontSize: '15px',
                    fontWeight: 600,
                    marginBottom: 6,
                  }}
                >
                  Launch Autonomous Multi-Agent Cyber Squad
                </div>
                <p
                  style={{
                    margin: '0 auto 14px',
                    maxWidth: 520,
                    fontSize: '12.75px',
                    color: 'var(--text-secondary)',
                  }}
                >
                  Paste a Bugcrowd engagement brief to initialize an immutable{' '}
                  <code className="oc-md-code">scope.yaml</code>, build a Living
                  Shared Threat Model, and coordinate Recon, Cartographer,
                  Hypothesis Hunter, and Counterevidence Validator specialists.
                </p>
                <button
                  type="button"
                  className="oc-btn oc-btn-primary"
                  onClick={onOpenNewEngagement}
                >
                  <Plus size={14} />
                  <span>New Engagement</span>
                </button>
              </div>
            ) : (
              filteredTimeline.map((event) => (
                <TimelineEventCard
                  key={event.id}
                  event={event}
                  onInspectAgent={onInspectAgent}
                />
              ))
            )}
          </div>

          {/* Sleek Collapsible 46px Prompt & Steering Dock */}
          <SteeringComposerDock
            expanded={composerExpanded}
            draft={composerDraft}
            agents={squadState.agents}
            targetAgentId={steerTargetAgentId}
            isStreaming={isStreaming}
            streamError={streamError}
            onExpand={onExpandComposer}
            onCollapse={onCollapseComposer}
            onDraftChange={onDraftChange}
            onSelectTargetAgent={onSelectTargetAgent}
            onSend={onSendSteer}
          />
        </section>

        {/* Right Sticky Rail (>= 1180px) or Selected Compact Pane (< 1180px) */}
        <aside
          className={`oc-ops-rail-col${compactPane === 'stream' ? ' is-compact-hidden' : ''}`}
          aria-label="Hierarchical Agent Tree and Active Hypotheses"
        >
          {(compactPane === 'stream' || compactPane === 'agents') && (
            <AgentSquadTree
              agents={squadState.agents}
              onInspectAgent={(id) => onInspectAgent(id, 'transcript')}
            />
          )}

          {(compactPane === 'stream' || compactPane === 'hypotheses') && (
            <CompactHypothesisSummaryList
              hypotheses={squadState.hypotheses}
              onOpenBoard={() => onNavigateView('hypotheses')}
            />
          )}
        </aside>
      </div>
    </div>
  );
};
