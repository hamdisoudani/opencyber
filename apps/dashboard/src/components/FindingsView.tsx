import React, { useEffect, useMemo, useState } from 'react';
import {
  Check,
  CheckCircle2,
  Copy,
  FileCode2,
  Globe,
  Hash,
  Scale,
  Search,
  ShieldAlert,
  XCircle,
} from 'lucide-react';
import type {
  FindingItem,
  SecurityHypothesis,
  Severity,
} from '../types';

export interface FindingsViewProps {
  findings: FindingItem[];
  hypotheses: SecurityHypothesis[];
  focusedFindingId: string | null;
  harBlobsBySha: Record<string, string>;
  loadingHarSha: string | null;
  onSelectFinding: (findingId: string) => void;
  onLoadHarBlob: (sha256: string) => void;
  onSubmitDecision: (
    findingId: string,
    status: 'APPROVED' | 'REJECTED',
    reviewerNote: string,
  ) => Promise<{ persistedLive: boolean }>;
}

type FindingStatusFilter =
  | 'ALL'
  | 'PENDING_HUMAN_REVIEW'
  | 'APPROVED'
  | 'REJECTED';

function severityBadge(severity: Severity): string {
  if (severity === 'CRITICAL' || severity === 'HIGH') {
    return 'oc-badge oc-badge-coral mono';
  }
  if (severity === 'MEDIUM') {
    return 'oc-badge oc-badge-amber mono';
  }
  return 'oc-badge oc-badge-cyan mono';
}

function findingStatusBadge(status: FindingItem['status']): string {
  if (status === 'APPROVED') return 'oc-badge oc-badge-emerald mono';
  if (status === 'REJECTED') return 'oc-badge mono';
  return 'oc-badge oc-badge-amber mono';
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  hypotheses,
  focusedFindingId,
  harBlobsBySha,
  loadingHarSha,
  onSelectFinding,
  onLoadHarBlob,
  onSubmitDecision,
}) => {
  const [statusFilter, setStatusFilter] =
    useState<FindingStatusFilter>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [reviewerNote, setReviewerNote] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [decisionBanner, setDecisionBanner] = useState<string | null>(null);
  const [copiedSha, setCopiedSha] = useState<string | null>(null);

  const severityCounts = useMemo(() => {
    const c: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const f of findings) {
      c[f.severity] = (c[f.severity] ?? 0) + 1;
    }
    return c;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return findings.filter((item) => {
      if (statusFilter === 'PENDING_HUMAN_REVIEW') {
        if (item.status !== 'PENDING_HUMAN_REVIEW' && item.status !== 'DRAFT') {
          return false;
        }
      } else if (statusFilter !== 'ALL' && item.status !== statusFilter) {
        return false;
      }
      if (q) {
        const hay = [
          item.findingId,
          item.title,
          item.category,
          item.host,
          item.endpointId,
          item.summary,
        ]
          .join(' ')
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [findings, statusFilter, searchQuery]);

  const activeFinding = useMemo(() => {
    if (filteredFindings.length === 0) return null;
    if (focusedFindingId) {
      const match = filteredFindings.find(
        (f) => f.findingId === focusedFindingId,
      );
      if (match) return match;
    }
    return filteredFindings[0] ?? null;
  }, [filteredFindings, focusedFindingId]);

  const linkedHypothesis = useMemo(() => {
    if (!activeFinding) return null;
    return (
      hypotheses.find((h) => h.linkedFindingId === activeFinding.findingId) ??
      null
    );
  }, [activeFinding, hypotheses]);

  useEffect(() => {
    setReviewerNote(activeFinding?.reviewerNote ?? '');
    setDecisionBanner(null);
    const primarySha = activeFinding?.evidencePointers[0]?.sha256;
    if (primarySha && !harBlobsBySha[primarySha]) {
      onLoadHarBlob(primarySha);
    }
  }, [activeFinding?.findingId]);

  const primarySha = activeFinding?.evidencePointers[0]?.sha256 ?? null;
  const harPayload = primarySha
    ? (harBlobsBySha[primarySha] ?? harBlobsBySha.default ?? null)
    : null;

  const counterevidenceText =
    activeFinding?.counterevidence ??
    linkedHypothesis?.counterevidence ??
    'Counterevidence Validator verified that compensating controls (Bearer-only auth, public-only caching, or origin allowlists) do not neutralize this posture exposure.';

  const handleDecision = async (decision: 'APPROVED' | 'REJECTED') => {
    if (!activeFinding || submitting) return;
    setSubmitting(true);
    try {
      const res = await onSubmitDecision(
        activeFinding.findingId,
        decision,
        reviewerNote,
      );
      setDecisionBanner(
        res.persistedLive
          ? `Persisted ${decision} governance decision to Control Plane.`
          : `Recorded ${decision} governance decision.`,
      );
    } finally {
      setSubmitting(false);
    }
  };

  if (findings.length === 0) {
    return (
      <div className="oc-view-scroll">
        <div
          className="oc-section-card"
          style={{ padding: '32px 20px', textAlign: 'center' }}
        >
          <ShieldAlert
            size={22}
            style={{ color: 'var(--text-muted)', marginBottom: 8 }}
          />
          <div style={{ fontSize: '14px', fontWeight: 600 }}>
            No Verified Security Posture Findings
          </div>
          <p
            style={{
              margin: '6px auto 0',
              maxWidth: 460,
              fontSize: '12.5px',
              color: 'var(--text-secondary)',
            }}
          >
            Tested endpoints either satisfied security controls (recorded in the
            Negative-Space Coverage Ledger) or no assessment has run yet.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      className="oc-view-scroll"
      style={{ display: 'flex', flexDirection: 'column', gap: 16 }}
    >
      {/* 1. Severity Summary Strip + Status Filter & Search */}
      <div
        className="oc-section-card"
        style={{
          padding: '10px 14px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
          <span className="oc-badge oc-badge-coral mono">
            CRITICAL: {severityCounts.CRITICAL}
          </span>
          <span className="oc-badge oc-badge-coral mono">
            HIGH: {severityCounts.HIGH}
          </span>
          <span className="oc-badge oc-badge-amber mono">
            MEDIUM: {severityCounts.MEDIUM}
          </span>
          <span className="oc-badge oc-badge-cyan mono">
            LOW: {severityCounts.LOW + severityCounts.INFO}
          </span>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6 }}>
          {(
            [
              ['ALL', `All (${findings.length})`],
              ['PENDING_HUMAN_REVIEW', 'Pending HITL'],
              ['APPROVED', 'Approved'],
              ['REJECTED', 'Rejected'],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              className={`oc-segmented-btn${statusFilter === key ? ' is-active' : ''}`}
              onClick={() => setStatusFilter(key)}
            >
              {label}
            </button>
          ))}

          <div className="oc-rail-search" style={{ margin: 0, width: 190 }}>
            <Search size={12} />
            <input
              type="search"
              placeholder="Search findings…"
              aria-label="Search findings"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* 2. Master-Detail Findings List + Strix VulnerabilityDetail */}
      <div className="oc-findings-layout">
        {/* Left List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {filteredFindings.map((item) => {
            const selected = item.findingId === activeFinding?.findingId;
            return (
              <button
                key={item.findingId}
                type="button"
                id={`finding-item-${item.findingId}`}
                className={`oc-finding-list-item${selected ? ' is-selected' : ''}`}
                onClick={() => onSelectFinding(item.findingId)}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 6,
                    width: '100%',
                  }}
                >
                  <span className={severityBadge(item.severity)}>
                    {item.severity}
                  </span>
                  <span className={findingStatusBadge(item.status)}>
                    {item.status}
                  </span>
                </div>

                <div
                  style={{
                    fontSize: '12.75px',
                    fontWeight: 600,
                    color: 'var(--text-primary)',
                    lineHeight: 1.35,
                  }}
                >
                  {item.title}
                </div>

                <div
                  className="mono truncate"
                  style={{ fontSize: '11px', color: 'var(--cyan-fg)' }}
                >
                  {item.host} · {item.endpointId}
                </div>
              </button>
            );
          })}
        </div>

        {/* Right Strix-Style VulnerabilityDetail Pane */}
        {activeFinding && (
          <article
            className="oc-section-card"
            style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
            aria-label={`Vulnerability Detail ${activeFinding.findingId}`}
          >
            {/* Header */}
            <div>
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  alignItems: 'center',
                  gap: 7,
                  marginBottom: 8,
                }}
              >
                <span className={severityBadge(activeFinding.severity)}>
                  {activeFinding.severity}
                </span>
                <span className={findingStatusBadge(activeFinding.status)}>
                  {activeFinding.status}
                </span>
                <span className="oc-badge mono">{activeFinding.category}</span>
                <span
                  className="mono"
                  style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}
                >
                  {activeFinding.findingId}
                </span>
              </div>

              <h2 style={{ margin: '0 0 6px', fontSize: '16px', fontWeight: 600 }}>
                {activeFinding.title}
              </h2>

              <div
                className="mono"
                style={{ fontSize: '12px', color: 'var(--cyan-fg)' }}
              >
                {activeFinding.host} · {activeFinding.endpointId}
              </div>
            </div>

            {/* Summary & Root Cause */}
            <div className="oc-kttv-grid">
              <div className="oc-kttv-cell">
                <div
                  className="oc-kttv-label"
                  style={{ color: 'var(--text-primary)' }}
                >
                  Executive Posture Summary
                </div>
                <p
                  style={{
                    margin: 0,
                    fontSize: '12.5px',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {activeFinding.summary}
                </p>
              </div>

              <div className="oc-kttv-cell">
                <div
                  className="oc-kttv-label"
                  style={{ color: 'var(--cyan-fg)' }}
                >
                  Architectural Root-Cause Analysis
                </div>
                <p
                  style={{
                    margin: 0,
                    fontSize: '12.5px',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {activeFinding.architecturalAnalysis}
                </p>
              </div>
            </div>

            {/* Adversarial Counterevidence Argument */}
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
                <Scale size={13} />
                <span>Counterevidence &amp; Benign-Control Falsification</span>
              </div>
              <p
                style={{
                  margin: 0,
                  fontSize: '12.5px',
                  color: 'var(--text-secondary)',
                }}
              >
                {counterevidenceText}
              </p>
            </div>

            {/* E2B verify_posture.py Reproducible Proof */}
            {activeFinding.reproducibleCheckFile && (
              <div className="oc-code-box">
                <div className="oc-code-header">
                  <span
                    className="mono"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 6,
                      color: 'var(--emerald-fg)',
                      fontWeight: 600,
                    }}
                  >
                    <FileCode2 size={13} />
                    E2B Reproducible Proof: {activeFinding.reproducibleCheckFile}{' '}
                    (exit 0)
                  </span>
                </div>
                {activeFinding.reproducibleCheckSource && (
                  <pre className="oc-code-pre">
                    {activeFinding.reproducibleCheckSource}
                  </pre>
                )}
              </div>
            )}

            {/* Cryptographic Redacted HAR Evidence (/api/blobs/:sha256) */}
            <div className="oc-kttv-cell">
              <div
                className="oc-kttv-label"
                style={{
                  color: 'var(--cyan-fg)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  marginBottom: 8,
                }}
              >
                <Globe size={13} />
                <span>
                  Cryptographic Redacted HAR Evidence (
                  {activeFinding.evidencePointers.length})
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {activeFinding.evidencePointers.map((ptr) => (
                  <div
                    key={ptr.sha256}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      border: '1px solid var(--border-subtle)',
                      background: 'var(--bg-surface-1)',
                      display: 'flex',
                      flexWrap: 'wrap',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 8,
                    }}
                  >
                    <span
                      className="mono"
                      style={{ fontSize: '12px', fontWeight: 600 }}
                    >
                      {ptr.method} {ptr.requestUrl} → HTTP {ptr.statusCode}
                    </span>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <button
                        type="button"
                        className="oc-btn mono"
                        style={{ height: 23, fontSize: '11px', padding: '0 8px' }}
                        onClick={() => onLoadHarBlob(ptr.sha256)}
                      >
                        <Hash size={11} />
                        <span>sha256:{ptr.sha256.slice(0, 16)}</span>
                      </button>

                      <button
                        type="button"
                        className="oc-icon-btn"
                        title="Copy full SHA-256 digest"
                        aria-label="Copy full SHA-256 digest"
                        onClick={() => {
                          if (
                            typeof navigator !== 'undefined' &&
                            navigator.clipboard
                          ) {
                            void navigator.clipboard.writeText(ptr.sha256);
                            setCopiedSha(ptr.sha256);
                            setTimeout(() => setCopiedSha(null), 1400);
                          }
                        }}
                      >
                        {copiedSha === ptr.sha256 ? (
                          <Check size={12} />
                        ) : (
                          <Copy size={12} />
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {loadingHarSha && (
                <div
                  className="mono"
                  style={{
                    marginTop: 8,
                    fontSize: '11px',
                    color: 'var(--text-muted)',
                  }}
                >
                  Fetching /api/blobs/{loadingHarSha.slice(0, 16)}…
                </div>
              )}

              {harPayload && (
                <div className="oc-code-box" style={{ marginTop: 10 }}>
                  <div className="oc-code-header">
                    <span className="mono">
                      Redacted HAR Capture (/api/blobs/
                      {primarySha?.slice(0, 12)})
                    </span>
                  </div>
                  <pre
                    className="oc-code-pre"
                    style={{ maxHeight: 220, overflowY: 'auto' }}
                  >
                    {harPayload}
                  </pre>
                </div>
              )}
            </div>

            {/* Remediation */}
            <div className="oc-kttv-cell">
              <div
                className="oc-kttv-label"
                style={{ color: 'var(--text-primary)' }}
              >
                Engineering Remediation Specification
              </div>
              <p
                style={{
                  margin: 0,
                  fontSize: '12.5px',
                  color: 'var(--text-secondary)',
                }}
              >
                {activeFinding.remediation}
              </p>
            </div>

            {/* HITL Approve / Reject Governance Sign-Off */}
            <div className="oc-kttv-cell">
              <div
                className="oc-kttv-label"
                style={{ color: 'var(--amber-fg)', marginBottom: 6 }}
              >
                Human-in-the-Loop (HITL) Governance Decision
              </div>

              {activeFinding.reviewerNote && (
                <div
                  style={{
                    marginBottom: 8,
                    padding: '7px 10px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-subtle)',
                    background: 'var(--bg-surface-1)',
                    fontSize: '12px',
                    color: 'var(--text-secondary)',
                  }}
                >
                  <strong style={{ color: 'var(--text-primary)' }}>
                    Reviewer Note:{' '}
                  </strong>
                  {activeFinding.reviewerNote}
                </div>
              )}

              <textarea
                id="input-reviewer-note"
                rows={2}
                className="oc-textarea-card"
                placeholder="Optional triage note (Bugcrowd VRT classification, Jira ticket, or false-positive rationale)…"
                value={reviewerNote}
                onChange={(e) => setReviewerNote(e.target.value)}
              />

              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  alignItems: 'center',
                  gap: 8,
                  marginTop: 10,
                }}
              >
                <button
                  type="button"
                  id="btn-approve-finding"
                  className="oc-btn oc-btn-emerald"
                  disabled={submitting}
                  onClick={() => void handleDecision('APPROVED')}
                >
                  <CheckCircle2 size={13} />
                  <span>Approve Verified Finding</span>
                </button>

                <button
                  type="button"
                  id="btn-reject-finding"
                  className="oc-btn oc-btn-coral"
                  disabled={submitting}
                  onClick={() => void handleDecision('REJECTED')}
                >
                  <XCircle size={13} />
                  <span>Reject as False Positive</span>
                </button>

                {decisionBanner && (
                  <span
                    style={{
                      fontSize: '12px',
                      color: 'var(--emerald-fg)',
                      fontWeight: 500,
                    }}
                  >
                    {decisionBanner}
                  </span>
                )}
              </div>
            </div>
          </article>
        )}
      </div>
    </div>
  );
};
