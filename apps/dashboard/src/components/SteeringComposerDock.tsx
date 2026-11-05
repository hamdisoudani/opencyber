import React, { useLayoutEffect, useMemo, useRef } from 'react';
import {
  ArrowUp,
  ChevronDown,
  ChevronUp,
  Crosshair,
  Loader2,
} from 'lucide-react';
import type { SquadAgentNode } from '../types';

export interface SteeringComposerDockProps {
  expanded: boolean;
  draft: string;
  agents: SquadAgentNode[];
  targetAgentId: string | null;
  isStreaming: boolean;
  streamError: string | null;
  onExpand: () => void;
  onCollapse: () => void;
  onDraftChange: (draft: string) => void;
  onSelectTargetAgent: (agentId: string | null) => void;
  onSend: (message?: string) => void;
}

const QUICK_STEER_PROMPTS = [
  {
    label: 'Verify CORS preflight',
    prompt:
      'Verify CORS preflight reflection, Access-Control-Allow-Credentials, and Vary: Origin across all authenticated API routes.',
  },
  {
    label: 'Audit auth boundary',
    prompt:
      'Audit tenant JWT claim binding and cookie SameSite posture across session and resource endpoints.',
  },
  {
    label: 'Challenge with counterevidence',
    prompt:
      'Run adversarial counterevidence checks against open hypotheses and downgrade any benign public payloads to ruled_out.',
  },
  {
    label: 'Inspect JS bundle routes',
    prompt:
      'Extract client-side route templates from SPA JS chunks and diff against published OpenAPI schemas.',
  },
] as const;

export const SteeringComposerDock: React.FC<SteeringComposerDockProps> = ({
  expanded,
  draft,
  agents,
  targetAgentId,
  isStreaming,
  streamError,
  onExpand,
  onCollapse,
  onDraftChange,
  onSelectTargetAgent,
  onSend,
}) => {
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const rootAgent = useMemo(
    () => agents.find((a) => a.parentId === null) ?? agents[0] ?? null,
    [agents],
  );

  const activeTarget = useMemo(() => {
    if (!targetAgentId) return rootAgent;
    return agents.find((a) => a.id === targetAgentId) ?? rootAgent;
  }, [agents, rootAgent, targetAgentId]);

  useLayoutEffect(() => {
    const el = textareaRef.current;
    if (!el || !expanded) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(160, Math.max(44, el.scrollHeight))}px`;
  }, [draft, expanded]);

  if (!expanded) {
    return (
      <div className="oc-composer-dock-wrap">
        <button
          type="button"
          id="btn-expand-composer"
          className="oc-composer-collapsed"
          onClick={() => {
            onExpand();
            requestAnimationFrame(() => textareaRef.current?.focus());
          }}
          aria-expanded={false}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 9,
              minWidth: 0,
              flex: 1,
            }}
          >
            <Crosshair
              size={14}
              style={{ color: 'var(--cyan-fg)', flexShrink: 0 }}
            />
            <span
              className="truncate"
              style={{ fontSize: '12.75px', color: 'var(--text-secondary)' }}
            >
              Steer the cyber squad, propose a hypothesis, or ask a follow-up…
            </span>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              flexShrink: 0,
            }}
          >
            <span className="oc-badge oc-badge-cyan mono">
              Target: {activeTarget?.name ?? 'Lead Orchestrator'}
            </span>
            <ChevronUp size={15} style={{ color: 'var(--text-muted)' }} />
          </div>
        </button>
      </div>
    );
  }

  const canSend = draft.trim().length > 0 && !isStreaming;

  return (
    <div className="oc-composer-dock-wrap">
      <div className="oc-composer-expanded">
        <div className="oc-composer-top">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Crosshair size={14} style={{ color: 'var(--cyan-fg)' }} />
            <span style={{ fontSize: '12px', fontWeight: 600 }}>
              Live Squad Steering
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <label
              htmlFor="select-steer-target"
              style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}
            >
              Target:
            </label>
            <select
              id="select-steer-target"
              className="oc-select mono"
              style={{ height: 26, fontSize: '11.5px', padding: '0 8px' }}
              value={targetAgentId ?? ''}
              onChange={(e) =>
                onSelectTargetAgent(e.target.value ? e.target.value : null)
              }
            >
              <option value="">
                {rootAgent?.name ?? 'Lead Orchestrator'} (Root)
              </option>
              {agents
                .filter((a) => a.parentId !== null)
                .map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name} ({agent.role})
                  </option>
                ))}
            </select>

            <button
              type="button"
              id="btn-collapse-composer"
              className="oc-icon-btn"
              onClick={onCollapse}
              title="Collapse steering composer"
              aria-label="Collapse steering composer"
            >
              <ChevronDown size={15} />
            </button>
          </div>
        </div>

        <textarea
          ref={textareaRef}
          id="input-steering-prompt"
          rows={1}
          className="oc-composer-textarea"
          placeholder={`Send live direction to ${activeTarget?.name ?? 'Lead Orchestrator'}…`}
          value={draft}
          disabled={isStreaming}
          onChange={(e) => onDraftChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey || !e.shiftKey)) {
              e.preventDefault();
              if (canSend) onSend();
            }
          }}
        />

        <div className="oc-composer-bottom">
          <div className="oc-chip-row">
            {QUICK_STEER_PROMPTS.map((chip) => (
              <button
                key={chip.label}
                type="button"
                className="oc-prompt-chip"
                onClick={() => onDraftChange(chip.prompt)}
              >
                {chip.label}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {streamError && (
              <span style={{ fontSize: '11.5px', color: 'var(--coral-fg)' }}>
                {streamError}
              </span>
            )}
            <button
              type="button"
              id="btn-send-steering"
              className="oc-btn oc-btn-primary"
              disabled={!canSend}
              onClick={() => onSend()}
            >
              {isStreaming ? (
                <Loader2 size={13} className="animate-spin-fast" />
              ) : (
                <ArrowUp size={13} />
              )}
              <span>Send</span>
              <span className="mono" style={{ fontSize: '10.5px', opacity: 0.75 }}>
                ⌘↵
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
