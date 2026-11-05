import React, { useMemo, useState } from 'react';
import {
  ArrowUpRight,
  Crosshair,
  History,
  Lightbulb,
  ShieldCheck,
} from 'lucide-react';
import type {
  HypothesisClosureState,
  SecurityHypothesis,
  SharedThreatModel,
  SquadAgentNode,
} from '../types';
import { closureBadgeMeta, formatShortClock } from './OperationsView';

export interface HypothesesViewProps {
  hypotheses: SecurityHypothesis[];
  threatModel: SharedThreatModel | null;
  agents: SquadAgentNode[];
  onInspectAgent: (agentId: string) => void;
  onOpenFinding: (findingId: string) => void;
}

type ClosureFilter = 'ALL' | HypothesisClosureState;

export const HypothesesView: React.FC<HypothesesViewProps> = ({
  hypotheses,
  threatModel,
  agents,
  onInspectAgent,
  onOpenFinding,
}) => {
  const [filter, setFilter] = useState<ClosureFilter>('ALL');

  const agentNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const a of agents) {
      map.set(a.id, a.name);
    }
    return map;
  }, [agents]);

  const filteredHypotheses = useMemo(() => {
    if (filter === 'ALL') return hypotheses;
    return hypotheses.filter((h) => h.closureState === filter);
  }, [hypotheses, filter]);

  const counts = useMemo(() => {
    const c = {
      confirmed: 0,
      ruled_out: 0,
      open_proof_gap: 0,
      testing: 0,
      open: 0,
    };
    for (const h of hypotheses) {
      c[h.closureState] += 1;
    }
    return c;
  }, [hypotheses]);

  return (
    <div
      className="oc-view-scroll"
      style={{ display: 'flex', flexDirection: 'column', gap: 18 }}
    >
      {/* 1. Living Shared Threat Model & Specialist Amendments */}
      {threatModel && (
        <section className="oc-section-card" aria-label="Living Shared Threat Model">
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 8,
              marginBottom: 10,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Crosshair size={15} style={{ color: 'var(--cyan-fg)' }} />
              <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>
                Living Shared Threat Model
              </h2>
              <span className="oc-badge oc-badge-cyan mono">
                {threatModel.target}
              </span>
            </div>
            <span
              className="mono"
              style={{ fontSize: '11px', color: 'var(--text-muted)' }}
            >
              Updated {formatShortClock(threatModel.updatedAt)} ·{' '}
              {threatModel.amendments.length} specialist amendments
            </span>
          </div>

          <p
            style={{
              margin: '0 0 12px',
              fontSize: '13px',
              color: 'var(--text-secondary)',
            }}
          >
            {threatModel.summary}
          </p>

          <div className="oc-grid-auto">
            <div className="oc-kttv-cell">
              <div
                className="oc-kttv-label"
                style={{ color: 'var(--cyan-fg)' }}
              >
                Trust Boundaries ({threatModel.trustBoundaries.length})
              </div>
              <ul
                style={{
                  margin: 0,
                  paddingLeft: 16,
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                }}
              >
                {threatModel.trustBoundaries.map((b, i) => (
                  <li key={i}>{b}</li>
                ))}
              </ul>
            </div>

            <div className="oc-kttv-cell">
              <div
                className="oc-kttv-label"
                style={{ color: 'var(--amber-fg)' }}
              >
                High-Value Assets &amp; Attacker Roles
              </div>
              <ul
                style={{
                  margin: 0,
                  paddingLeft: 16,
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                }}
              >
                {threatModel.highValueAssets.map((a, i) => (
                  <li key={`asset-${i}`}>{a}</li>
                ))}
                {threatModel.attackerRoles.slice(0, 2).map((r, i) => (
                  <li key={`role-${i}`} style={{ color: 'var(--text-muted)' }}>
                    Role: {r}
                  </li>
                ))}
              </ul>
            </div>

            <div className="oc-kttv-cell">
              <div
                className="oc-kttv-label"
                style={{ color: 'var(--emerald-fg)' }}
              >
                Inferred Architectural Assumptions
              </div>
              <ul
                style={{
                  margin: 0,
                  paddingLeft: 16,
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                }}
              >
                {threatModel.inferredAssumptions.map((asmp, i) => (
                  <li key={i}>{asmp}</li>
                ))}
              </ul>
            </div>
          </div>

          {threatModel.amendments.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div
                style={{
                  fontSize: '11.5px',
                  fontWeight: 600,
                  color: 'var(--amber-fg)',
                  marginBottom: 6,
                }}
              >
                Specialist Agent Amendments ({threatModel.amendments.length}) —
                later empirical observations override prior assumptions
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {threatModel.amendments.map((am) => (
                  <div
                    key={am.id}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      border: '1px solid var(--border-subtle)',
                      background: 'var(--bg-surface-2)',
                      fontSize: '12px',
                      display: 'flex',
                      flexWrap: 'wrap',
                      alignItems: 'baseline',
                      gap: 8,
                    }}
                  >
                    <button
                      type="button"
                      className="oc-badge mono"
                      style={{ cursor: 'pointer' }}
                      onClick={() => onInspectAgent(am.agentId)}
                    >
                      {am.agentName}
                    </button>
                    <span
                      style={{
                        color: 'var(--text-secondary)',
                        flex: '1 1 280px',
                      }}
                    >
                      {am.addendum}
                    </span>
                    <span
                      className="mono"
                      style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}
                    >
                      {formatShortClock(am.recordedAt)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* 2. KNOW -> THINK -> TEST -> VALIDATE Hypothesis Board */}
      <section aria-label="Security Hypothesis Board">
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 10,
            marginBottom: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Lightbulb size={15} style={{ color: 'var(--amber-fg)' }} />
            <h2 style={{ margin: 0, fontSize: '14.5px', fontWeight: 600 }}>
              Hypothesis Board (KNOW → THINK → TEST → VALIDATE)
            </h2>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {(
              [
                ['ALL', `All (${hypotheses.length})`],
                ['confirmed', `Confirmed (${counts.confirmed})`],
                ['ruled_out', `Ruled Out (${counts.ruled_out})`],
                ['open_proof_gap', `Open Proof Gap (${counts.open_proof_gap})`],
                ['testing', `Testing (${counts.testing + counts.open})`],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                className={`oc-segmented-btn${filter === key ? ' is-active' : ''}`}
                onClick={() => setFilter(key)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filteredHypotheses.map((hyp) => {
            const closure = closureBadgeMeta(hyp.closureState);
            const ownerName =
              agentNameById.get(hyp.assignedAgentId ?? hyp.createdByAgentId) ??
              hyp.createdByAgentId;

            return (
              <article
                key={hyp.id}
                id={`hypothesis-card-${hyp.id}`}
                className="oc-section-card"
              >
                {/* Card Header */}
                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 10,
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      alignItems: 'center',
                      gap: 7,
                    }}
                  >
                    <span className="oc-badge oc-badge-amber mono">
                      {hyp.id}
                    </span>
                    <span className={closure.className}>{closure.label}</span>
                    <span className="oc-badge mono">{hyp.phase}</span>
                    <span className="oc-badge mono">{hyp.riskCategory}</span>
                    <span
                      className="mono"
                      style={{
                        fontSize: '12px',
                        fontWeight: 600,
                        color: 'var(--text-primary)',
                      }}
                    >
                      {hyp.surface}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <button
                      type="button"
                      className="oc-badge mono"
                      style={{ cursor: 'pointer' }}
                      onClick={() =>
                        onInspectAgent(
                          hyp.assignedAgentId ?? hyp.createdByAgentId,
                        )
                      }
                    >
                      {ownerName}
                    </button>

                    {hyp.linkedFindingId && (
                      <button
                        type="button"
                        className="oc-btn oc-btn-coral mono"
                        style={{ height: 24, fontSize: '11px', padding: '0 8px' }}
                        onClick={() => onOpenFinding(hyp.linkedFindingId!)}
                      >
                        <span>{hyp.linkedFindingId}</span>
                        <ArrowUpRight size={11} />
                      </button>
                    )}
                  </div>
                </div>

                {/* Confidence Bar (0-100%) */}
                <div style={{ marginTop: 10 }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontSize: '11.5px',
                      marginBottom: 4,
                    }}
                  >
                    <span style={{ color: 'var(--text-muted)' }}>
                      Empirical Confidence Score
                    </span>
                    <span className="mono" style={{ fontWeight: 600 }}>
                      {hyp.confidence}%
                    </span>
                  </div>
                  <div className="oc-confidence-track">
                    <div
                      className="oc-confidence-fill"
                      style={{
                        width: `${Math.max(2, Math.min(100, hyp.confidence))}%`,
                        background: closure.barColor,
                      }}
                    />
                  </div>
                </div>

                {/* 4-Column KNOW -> THINK -> TEST -> VALIDATE Matrix */}
                <div className="oc-kttv-grid">
                  <div className="oc-kttv-cell">
                    <div
                      className="oc-kttv-label"
                      style={{ color: 'var(--cyan-fg)' }}
                    >
                      KNOW · Empirical Observation
                    </div>
                    <div
                      style={{
                        fontSize: '12.25px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {hyp.observation}
                    </div>
                  </div>

                  <div className="oc-kttv-cell">
                    <div
                      className="oc-kttv-label"
                      style={{ color: 'var(--amber-fg)' }}
                    >
                      THINK · Security Hypothesis
                    </div>
                    <div
                      style={{
                        fontSize: '12.25px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {hyp.statement}
                    </div>
                  </div>

                  <div className="oc-kttv-cell">
                    <div
                      className="oc-kttv-label"
                      style={{ color: 'var(--text-primary)' }}
                    >
                      TEST · Read-Only Verification Plan
                    </div>
                    <div
                      style={{
                        fontSize: '12.25px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {hyp.testPlan}
                    </div>
                  </div>

                  <div className="oc-kttv-cell">
                    <div
                      className="oc-kttv-label"
                      style={{
                        color:
                          hyp.closureState === 'ruled_out'
                            ? 'var(--emerald-fg)'
                            : 'var(--coral-fg)',
                      }}
                    >
                      VALIDATE · Named Control / Counterevidence
                    </div>
                    <div
                      style={{
                        fontSize: '12.25px',
                        color: 'var(--text-primary)',
                        fontWeight: 500,
                        marginBottom: 4,
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: 5,
                      }}
                    >
                      {hyp.closureState === 'ruled_out' && (
                        <ShieldCheck
                          size={13}
                          style={{
                            color: 'var(--emerald-fg)',
                            flexShrink: 0,
                            marginTop: 2,
                          }}
                        />
                      )}
                      <span>{hyp.namedControlOrProof}</span>
                    </div>
                    <div
                      style={{
                        fontSize: '11.75px',
                        color: 'var(--text-muted)',
                      }}
                    >
                      Counterevidence: {hyp.counterevidence}
                    </div>
                  </div>
                </div>

                {/* Confidence Delta History */}
                {hyp.confidenceHistory.length > 0 && (
                  <div
                    style={{
                      marginTop: 10,
                      paddingTop: 8,
                      borderTop: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexWrap: 'wrap',
                      alignItems: 'center',
                      gap: 8,
                      fontSize: '11.5px',
                    }}
                  >
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                        color: 'var(--text-muted)',
                      }}
                    >
                      <History size={12} />
                      Confidence Trail:
                    </span>
                    {hyp.confidenceHistory.map((pt, idx) => (
                      <span
                        key={idx}
                        className="oc-badge mono"
                        title={`${pt.agentName}: ${pt.reason}`}
                      >
                        <span
                          style={{
                            color:
                              pt.delta >= 0
                                ? 'var(--amber-fg)'
                                : 'var(--emerald-fg)',
                          }}
                        >
                          {pt.delta >= 0 ? `+${pt.delta}%` : `${pt.delta}%`}
                        </span>
                        <span>→ {pt.confidence}%</span>
                        <span style={{ color: 'var(--text-muted)' }}>
                          ({pt.agentName})
                        </span>
                      </span>
                    ))}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
};
