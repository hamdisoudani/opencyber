import React, { useEffect, useMemo } from 'react';
import {
  ArrowUp,
  CheckCircle2,
  GitBranch,
  Loader2,
  X,
} from 'lucide-react';
import type { InspectorModalTab } from '../dashboardController';
import type { SquadAgentNode, SquadTimelineEvent } from '../types';
import { roleBadgeMeta } from './AgentSquadTree';
import { eventKindMeta, formatShortClock } from './OperationsView';

export interface AgentInspectorModalProps {
  agent: SquadAgentNode | null;
  timeline: SquadTimelineEvent[];
  activeTab: InspectorModalTab;
  steerDraft: string;
  isStreaming: boolean;
  onClose: () => void;
  onSelectTab: (tab: InspectorModalTab) => void;
  onSteerDraftChange: (draft: string) => void;
  onSendSteer: (message: string, targetAgentId: string) => void;
}

export const AgentInspectorModal: React.FC<AgentInspectorModalProps> = ({
  agent,
  timeline,
  activeTab,
  steerDraft,
  isStreaming,
  onClose,
  onSelectTab,
  onSteerDraftChange,
  onSendSteer,
}) => {
  useEffect(() => {
    if (!agent || typeof document === 'undefined') return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [agent, onClose]);

  const agentEvents = useMemo(() => {
    if (!agent) return [];
    return timeline.filter(
      (ev) =>
        ev.agentId === agent.id ||
        (ev.kind === 'spawn_agent' && ev.data?.childAgentId === agent.id),
    );
  }, [agent, timeline]);

  if (!agent) return null;

  const roleMeta = roleBadgeMeta(agent.role);
  const modelLabel = agent.provider
    ? `${agent.provider}:${agent.model}`
    : agent.model;
  const canSendSteer = steerDraft.trim().length > 0 && !isStreaming;

  return (
    <div
      className="oc-modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-label={`Agent Inspector: ${agent.name}`}
      onClick={onClose}
    >
      <div className="oc-modal-panel" onClick={(e) => e.stopPropagation()}>
        {/* Header: Status dot, Name, Role badge, Model, Skills pills, git worktree branch */}
        <div className="oc-modal-header">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7, minWidth: 0 }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
              <span
                className={`oc-status-dot is-${agent.status}${
                  agent.status === 'running' ? ' animate-pulse-dot' : ''
                }`}
              />
              <h2 style={{ margin: 0, fontSize: '15px', fontWeight: 600 }}>
                {agent.name}
              </h2>
              <span className={roleMeta.className}>{roleMeta.label}</span>
              <span className="oc-badge mono">{modelLabel}</span>
              {agent.worktreeBranch && (
                <span className="oc-badge oc-badge-cyan mono">
                  <GitBranch size={11} />
                  {agent.worktreeBranch}
                </span>
              )}
            </div>

            {agent.skills.length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {agent.skills.map((skill) => (
                  <span
                    key={skill}
                    className="oc-badge mono"
                    style={{ height: 19, fontSize: '10.5px' }}
                  >
                    {skill}
                  </span>
                ))}
              </div>
            )}
          </div>

          <button
            type="button"
            id="btn-close-agent-inspector"
            className="oc-icon-btn"
            onClick={onClose}
            aria-label="Close agent inspector"
          >
            <X size={16} />
          </button>
        </div>

        {/* 3 Modal Tabs */}
        <div className="oc-modal-tabs" role="tablist">
          <button
            type="button"
            id="tab-inspector-transcript"
            role="tab"
            aria-selected={activeTab === 'transcript'}
            className={`oc-segmented-btn${activeTab === 'transcript' ? ' is-active' : ''}`}
            onClick={() => onSelectTab('transcript')}
          >
            Live Transcript ({agentEvents.length})
          </button>

          <button
            type="button"
            id="tab-inspector-prompt"
            role="tab"
            aria-selected={activeTab === 'prompt'}
            className={`oc-segmented-btn${activeTab === 'prompt' ? ' is-active' : ''}`}
            onClick={() => onSelectTab('prompt')}
          >
            Mission Brief &amp; System Prompt
          </button>

          <button
            type="button"
            id="tab-inspector-report"
            role="tab"
            aria-selected={activeTab === 'report'}
            className={`oc-segmented-btn${activeTab === 'report' ? ' is-active' : ''}`}
            onClick={() => onSelectTab('report')}
          >
            Completion Report
          </button>
        </div>

        {/* Tab Body */}
        <div className="oc-modal-body">
          {activeTab === 'transcript' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {agentEvents.length === 0 ? (
                <div
                  style={{
                    padding: '20px 12px',
                    textAlign: 'center',
                    color: 'var(--text-muted)',
                    fontSize: '12.5px',
                  }}
                >
                  No timeline events recorded for {agent.name} yet.
                </div>
              ) : (
                agentEvents.map((ev) => {
                  const meta = eventKindMeta(ev.kind);
                  return (
                    <div key={ev.id} className="oc-timeline-card">
                      <div className="oc-timeline-header">
                        <span className={meta.badgeClass}>
                          {meta.icon}
                          <span>{meta.label}</span>
                        </span>
                        <span
                          className="mono"
                          style={{
                            fontSize: '11px',
                            color: 'var(--text-muted)',
                          }}
                        >
                          {formatShortClock(ev.timestamp)}
                        </span>
                      </div>
                      <div className="oc-timeline-title">{ev.title}</div>
                      <p className="oc-timeline-detail">{ev.detail}</p>
                    </div>
                  );
                })
              )}
            </div>
          )}

          {activeTab === 'prompt' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div className="oc-kttv-cell">
                <div
                  className="oc-kttv-label"
                  style={{ color: 'var(--cyan-fg)' }}
                >
                  Assigned Task Objective
                </div>
                <div
                  style={{
                    fontSize: '12.75px',
                    color: 'var(--text-primary)',
                  }}
                >
                  {agent.task}
                </div>
              </div>

              <div className="oc-code-box">
                <div className="oc-code-header">
                  <span
                    className="mono"
                    style={{ fontWeight: 600, color: 'var(--cyan-fg)' }}
                  >
                    Structured Parent Mission Brief (missionPrompt)
                  </span>
                </div>
                <pre
                  className="oc-code-pre"
                  style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
                >
                  {agent.missionPrompt}
                </pre>
              </div>

              <div className="oc-code-box">
                <div className="oc-code-header">
                  <span
                    className="mono"
                    style={{ fontWeight: 600, color: 'var(--amber-fg)' }}
                  >
                    Specialist System Directive (systemDirective)
                  </span>
                </div>
                <pre
                  className="oc-code-pre"
                  style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
                >
                  {agent.systemDirective}
                </pre>
              </div>
            </div>
          )}

          {activeTab === 'report' && (
            <div>
              {agent.completionReport ? (
                <div
                  style={{ display: 'flex', flexDirection: 'column', gap: 12 }}
                >
                  <div className="oc-kttv-cell">
                    <div
                      className="oc-kttv-label"
                      style={{
                        color: 'var(--emerald-fg)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6,
                      }}
                    >
                      <CheckCircle2 size={13} />
                      <span>
                        Summary · Completed{' '}
                        {formatShortClock(agent.completionReport.completedAt)}
                      </span>
                    </div>
                    <p
                      style={{
                        margin: 0,
                        fontSize: '13px',
                        color: 'var(--text-primary)',
                      }}
                    >
                      {agent.completionReport.summary}
                    </p>
                  </div>

                  <div className="oc-kttv-grid">
                    <div className="oc-kttv-cell">
                      <div
                        className="oc-kttv-label"
                        style={{ color: 'var(--emerald-fg)' }}
                      >
                        Confirmed Observations (
                        {agent.completionReport.findings.length})
                      </div>
                      <ul
                        style={{
                          margin: 0,
                          paddingLeft: 16,
                          fontSize: '12.25px',
                          color: 'var(--text-secondary)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 4,
                        }}
                      >
                        {agent.completionReport.findings.length === 0 ? (
                          <li>None recorded</li>
                        ) : (
                          agent.completionReport.findings.map((f, idx) => (
                            <li key={idx}>{f}</li>
                          ))
                        )}
                      </ul>
                    </div>

                    <div className="oc-kttv-cell">
                      <div
                        className="oc-kttv-label"
                        style={{ color: 'var(--amber-fg)' }}
                      >
                        Open Proof Gaps (
                        {agent.completionReport.openItems.length})
                      </div>
                      <ul
                        style={{
                          margin: 0,
                          paddingLeft: 16,
                          fontSize: '12.25px',
                          color: 'var(--text-secondary)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 4,
                        }}
                      >
                        {agent.completionReport.openItems.length === 0 ? (
                          <li>Zero unresolved proof gaps</li>
                        ) : (
                          agent.completionReport.openItems.map((item, idx) => (
                            <li key={idx}>{item}</li>
                          ))
                        )}
                      </ul>
                    </div>

                    <div className="oc-kttv-cell">
                      <div
                        className="oc-kttv-label"
                        style={{ color: 'var(--cyan-fg)' }}
                      >
                        Recommendations (
                        {agent.completionReport.recommendations.length})
                      </div>
                      <ul
                        style={{
                          margin: 0,
                          paddingLeft: 16,
                          fontSize: '12.25px',
                          color: 'var(--text-secondary)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 4,
                        }}
                      >
                        {agent.completionReport.recommendations.map(
                          (rec, idx) => (
                            <li key={idx}>{rec}</li>
                          ),
                        )}
                      </ul>
                    </div>
                  </div>
                </div>
              ) : (
                <div
                  style={{
                    padding: '24px 16px',
                    textAlign: 'center',
                    color: 'var(--text-muted)',
                    fontSize: '12.5px',
                  }}
                >
                  {agent.name} is currently {agent.status}. Completion report
                  will populate once the specialist concludes its task.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Pinned Steer <Agent Name> Footer Bar */}
        <div className="oc-modal-footer">
          <form
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
            }}
            onSubmit={(e) => {
              e.preventDefault();
              if (canSendSteer) {
                onSendSteer(steerDraft, agent.id);
              }
            }}
          >
            <input
              type="text"
              id="input-steer-modal-agent"
              className="oc-input"
              style={{ flex: 1 }}
              placeholder={`Steer ${agent.name} directly…`}
              aria-label={`Steer ${agent.name}`}
              value={steerDraft}
              onChange={(e) => onSteerDraftChange(e.target.value)}
            />
            <button
              type="submit"
              id="btn-send-modal-steer"
              className="oc-btn oc-btn-primary"
              disabled={!canSendSteer}
            >
              {isStreaming ? (
                <Loader2 size={13} className="animate-spin-fast" />
              ) : (
                <ArrowUp size={13} />
              )}
              <span>Steer {agent.name}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
