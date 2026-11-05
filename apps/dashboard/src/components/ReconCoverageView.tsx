import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowUpRight,
  Ban,
  Check,
  CheckCircle2,
  ClipboardList,
  Copy,
  Gauge,
  Globe,
  HelpCircle,
  Lock,
  Network,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { ReconSectionTab } from '../dashboardController';
import type {
  CoverageOutcome,
  FindingItem,
  OverviewResponse,
  SurfaceCoverageEntry,
  SurfaceGraphNode,
  SurfaceGraphResponse,
} from '../types';

export interface ReconCoverageViewProps {
  sectionTab: ReconSectionTab;
  overview: OverviewResponse;
  graph: SurfaceGraphResponse;
  coverage: SurfaceCoverageEntry[];
  findings: FindingItem[];
  onSelectSectionTab: (tab: ReconSectionTab) => void;
  onInspectAgent: (agentId: string) => void;
  onOpenFinding: (findingId: string) => void;
}

function asStringArray(val: unknown): string[] {
  return Array.isArray(val) ? val.map((v) => String(v)) : [];
}

export function coverageOutcomeMeta(outcome: CoverageOutcome): {
  label: string;
  badgeClass: string;
  icon: React.ReactNode;
} {
  switch (outcome) {
    case 'reported':
      return {
        label: 'reported',
        badgeClass: 'oc-badge oc-badge-coral mono',
        icon: <AlertTriangle size={12} />,
      };
    case 'ruled_out':
      return {
        label: 'ruled_out',
        badgeClass: 'oc-badge oc-badge-emerald mono',
        icon: <ShieldCheck size={12} />,
      };
    case 'no_issue_found':
      return {
        label: 'no_issue_found',
        badgeClass: 'oc-badge oc-badge-emerald mono',
        icon: <CheckCircle2 size={12} />,
      };
    case 'needs_follow_up':
      return {
        label: 'needs_follow_up',
        badgeClass: 'oc-badge oc-badge-amber mono',
        icon: <HelpCircle size={12} />,
      };
    case 'blocked_451':
      return {
        label: 'blocked_451',
        badgeClass: 'oc-badge oc-badge-coral mono',
        icon: <Ban size={12} />,
      };
  }
}

function synthesizeScopeYaml(overview: OverviewResponse): string {
  if (overview.scopeYaml?.trim()) return overview.scopeYaml.trim();
  const { engagement } = overview;
  const excludedHosts = engagement.excludedHosts ?? [];
  const headers = Object.entries(engagement.complianceHeaders ?? {});
  const lines = [
    `engagementId: "${engagement.engagementId}"`,
    `programName: "${engagement.programName}"`,
    `strictReadOnly: ${engagement.strictReadOnly}`,
    `maxRpsPerHost: ${engagement.maxRpsPerHost}`,
    'authorizedDomains:',
    ...engagement.authorizedDomains.map((d) => `  - "${d}"`),
    'excludedHosts:',
    ...(excludedHosts.length > 0
      ? excludedHosts.map((h) => `  - "${h}"`)
      : ['  []']),
    'excludedPaths:',
    ...(engagement.excludedPaths.length > 0
      ? engagement.excludedPaths.map((p) => `  - "${p}"`)
      : ['  []']),
  ];
  if (headers.length > 0) {
    lines.push('complianceHeaders:');
    for (const [k, v] of headers) {
      lines.push(`  ${k}: "${v}"`);
    }
  }
  return lines.join('\n');
}

export const ReconCoverageView: React.FC<ReconCoverageViewProps> = ({
  sectionTab,
  overview,
  graph,
  coverage,
  findings,
  onSelectSectionTab,
  onInspectAgent,
  onOpenFinding,
}) => {
  const [outcomeFilter, setOutcomeFilter] = useState<'ALL' | CoverageOutcome>(
    'ALL',
  );
  const [routeSearch, setRouteSearch] = useState<string>('');
  const [copiedYaml, setCopiedYaml] = useState<boolean>(false);

  const hostNodes = useMemo(
    () => graph.nodes.filter((n) => n.type === 'HOST'),
    [graph.nodes],
  );
  const endpointNodes = useMemo(
    () => graph.nodes.filter((n) => n.type === 'ENDPOINT'),
    [graph.nodes],
  );
  const tombstoneNodes = useMemo(
    () => graph.nodes.filter((n) => n.type === 'TOMBSTONE'),
    [graph.nodes],
  );

  const filteredCoverage = useMemo(() => {
    if (outcomeFilter === 'ALL') return coverage;
    return coverage.filter((c) => c.outcome === outcomeFilter);
  }, [coverage, outcomeFilter]);

  const outcomeCounts = useMemo(() => {
    const counts: Record<CoverageOutcome, number> = {
      reported: 0,
      ruled_out: 0,
      no_issue_found: 0,
      needs_follow_up: 0,
      blocked_451: 0,
    };
    for (const entry of coverage) {
      counts[entry.outcome] += 1;
    }
    return counts;
  }, [coverage]);

  const filteredEndpoints = useMemo(() => {
    const q = routeSearch.trim().toLowerCase();
    if (!q) return endpointNodes;
    return endpointNodes.filter((ep) =>
      JSON.stringify({ label: ep.label, meta: ep.metadata })
        .toLowerCase()
        .includes(q),
    );
  }, [endpointNodes, routeSearch]);

  const findEndpointPosture = (ep: SurfaceGraphNode) => {
    const epId = String(ep.metadata.endpointId ?? ep.id);
    const finding = findings.find(
      (f) => f.endpointId === epId || ep.label.includes(f.endpointId),
    );
    if (finding) return { kind: 'finding' as const, finding };
    const hasTomb = tombstoneNodes.some(
      (t) =>
        String(t.metadata.endpointId ?? '') === epId ||
        graph.edges.some((e) => e.source === ep.id && e.target === t.id),
    );
    return { kind: hasTomb ? ('ruled_out' as const) : ('mapped' as const) };
  };

  const scopeYamlText = useMemo(
    () => synthesizeScopeYaml(overview),
    [overview],
  );

  const svgHeight = Math.max(
    190,
    Math.max(hostNodes.length, Math.min(endpointNodes.length, 8)) * 38 + 46,
  );

  return (
    <div
      className="oc-view-scroll"
      style={{ display: 'flex', flexDirection: 'column', gap: 18 }}
    >
      {/* Sub-Navigation Bar */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          <button
            type="button"
            id="recon-tab-all"
            className={`oc-segmented-btn${sectionTab === 'all' ? ' is-active' : ''}`}
            onClick={() => onSelectSectionTab('all')}
          >
            Hosts, Routes &amp; Coverage Ledger ({coverage.length})
          </button>
          <button
            type="button"
            id="recon-tab-graph"
            className={`oc-segmented-btn${sectionTab === 'graph' ? ' is-active' : ''}`}
            onClick={() => onSelectSectionTab('graph')}
          >
            Attack Surface Topology ({graph.nodes.length})
          </button>
          <button
            type="button"
            id="recon-tab-scope"
            className={`oc-segmented-btn${sectionTab === 'scope' ? ' is-active' : ''}`}
            onClick={() => onSelectSectionTab('scope')}
          >
            Immutable scope.yaml
          </button>
        </div>
      </div>

      {/* SECTION A: Strix-Style Negative-Space Coverage Ledger + Recon Hosts & Canonical Routes */}
      {sectionTab === 'all' && (
        <>
          {/* 1. Strix Negative-Space Coverage Ledger */}
          <section
            className="oc-section-card"
            aria-label="Negative-Space Coverage Ledger"
          >
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
                <ClipboardList size={15} style={{ color: 'var(--cyan-fg)' }} />
                <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>
                  Negative-Space Coverage Ledger
                </h2>
                <span
                  style={{ fontSize: '12px', color: 'var(--text-muted)' }}
                >
                  Every cleared control, reported surface, proof gap, and HTTP
                  451 block
                </span>
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {(
                  [
                    ['ALL', `All (${coverage.length})`],
                    ['reported', `reported (${outcomeCounts.reported})`],
                    ['ruled_out', `ruled_out (${outcomeCounts.ruled_out})`],
                    [
                      'no_issue_found',
                      `no_issue_found (${outcomeCounts.no_issue_found})`,
                    ],
                    [
                      'needs_follow_up',
                      `needs_follow_up (${outcomeCounts.needs_follow_up})`,
                    ],
                    [
                      'blocked_451',
                      `blocked_451 (${outcomeCounts.blocked_451})`,
                    ],
                  ] as const
                ).map(([key, label]) => (
                  <button
                    key={key}
                    type="button"
                    className={`oc-segmented-btn mono${outcomeFilter === key ? ' is-active' : ''}`}
                    style={{ height: 25, fontSize: '11px', padding: '0 8px' }}
                    onClick={() => setOutcomeFilter(key)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div className="oc-table-wrap">
              <table className="oc-table">
                <thead>
                  <tr>
                    <th>Outcome</th>
                    <th>Surface &amp; Risk Area</th>
                    <th>Named Control / Empirical Evidence</th>
                    <th>Recorded By</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCoverage.map((entry) => {
                    const meta = coverageOutcomeMeta(entry.outcome);
                    return (
                      <tr key={entry.id}>
                        <td>
                          <div
                            style={{
                              display: 'flex',
                              flexDirection: 'column',
                              gap: 4,
                              alignItems: 'flex-start',
                            }}
                          >
                            <span className={meta.badgeClass}>
                              {meta.icon}
                              <span>{meta.label}</span>
                            </span>
                            {entry.previousOutcomes.length > 0 && (
                              <span
                                className="mono"
                                style={{
                                  fontSize: '10.5px',
                                  color: 'var(--text-muted)',
                                }}
                              >
                                was {entry.previousOutcomes.join(' → ')}
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div
                            className="mono"
                            style={{
                              fontWeight: 600,
                              color: 'var(--text-primary)',
                            }}
                          >
                            {entry.surface}
                          </div>
                          <div
                            style={{
                              fontSize: '11.5px',
                              color: 'var(--text-muted)',
                              marginTop: 2,
                            }}
                          >
                            {entry.riskArea}
                          </div>
                        </td>
                        <td style={{ color: 'var(--text-secondary)' }}>
                          {entry.evidence}
                        </td>
                        <td>
                          <button
                            type="button"
                            className="oc-badge mono"
                            style={{ cursor: 'pointer' }}
                            onClick={() => onInspectAgent(entry.agentId)}
                          >
                            {entry.agentName}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>

          {/* 2. Step-by-Step Discovered Hosts */}
          <section aria-label="Discovered In-Scope Hosts">
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                marginBottom: 10,
              }}
            >
              <Server size={15} style={{ color: 'var(--cyan-fg)' }} />
              <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>
                Discovered In-Scope Hosts ({hostNodes.length})
              </h2>
            </div>

            <div className="oc-grid-auto">
              {hostNodes.map((host) => {
                const sources = asStringArray(host.metadata.sources);
                const fingerprints = asStringArray(host.metadata.fingerprints);
                const status = host.metadata.statusCode
                  ? `HTTP ${String(host.metadata.statusCode)}`
                  : 'LIVE';

                return (
                  <div key={host.id} className="oc-section-card">
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 8,
                        marginBottom: 6,
                      }}
                    >
                      <span
                        className="mono"
                        style={{
                          fontWeight: 600,
                          fontSize: '13px',
                          color: 'var(--text-primary)',
                        }}
                      >
                        {host.label}
                      </span>
                      <span className="oc-badge oc-badge-emerald mono">
                        {status}
                      </span>
                    </div>

                    {fingerprints.length > 0 && (
                      <div
                        style={{
                          fontSize: '12px',
                          color: 'var(--text-secondary)',
                          marginBottom: 6,
                        }}
                      >
                        {fingerprints.join(' · ')}
                      </div>
                    )}

                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {sources.map((src) => (
                        <span key={src} className="oc-badge mono">
                          {src}
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* 3. Canonical JS AST & OpenAPI Routes */}
          <section aria-label="Canonical Parameterized Routes">
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 10,
                marginBottom: 10,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Globe size={15} style={{ color: 'var(--cyan-fg)' }} />
                <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>
                  Canonical JS AST &amp; OpenAPI Routes (
                  {filteredEndpoints.length})
                </h2>
              </div>

              <div
                className="oc-rail-search"
                style={{ margin: 0, width: 220 }}
              >
                <Search size={12} />
                <input
                  type="search"
                  placeholder="Filter host or route…"
                  aria-label="Filter canonical routes"
                  value={routeSearch}
                  onChange={(e) => setRouteSearch(e.target.value)}
                />
              </div>
            </div>

            <div className="oc-table-wrap">
              <table className="oc-table">
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>Canonical Route &amp; Collapsed Paths</th>
                    <th>Sources</th>
                    <th>Posture Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEndpoints.map((ep) => {
                    const host = String(ep.metadata.host ?? '');
                    const rawPaths = asStringArray(
                      ep.metadata.observedRawPaths ?? ep.metadata.rawPaths,
                    );
                    const sources = asStringArray(ep.metadata.sources);
                    const posture = findEndpointPosture(ep);

                    return (
                      <tr key={ep.id}>
                        <td
                          className="mono"
                          style={{ color: 'var(--text-primary)' }}
                        >
                          {host}
                        </td>
                        <td>
                          <div
                            className="mono"
                            style={{
                              fontWeight: 600,
                              color: 'var(--text-primary)',
                            }}
                          >
                            {ep.label}
                          </div>
                          {rawPaths.length > 0 && (
                            <div
                              className="mono"
                              style={{
                                fontSize: '11px',
                                color: 'var(--text-muted)',
                                marginTop: 2,
                              }}
                            >
                              Collapsed: {rawPaths.join(', ')}
                            </div>
                          )}
                        </td>
                        <td>
                          <div
                            style={{
                              display: 'flex',
                              flexWrap: 'wrap',
                              gap: 4,
                            }}
                          >
                            {sources.map((s) => (
                              <span key={s} className="oc-badge mono">
                                {s}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td>
                          {posture.kind === 'finding' ? (
                            <button
                              type="button"
                              className="oc-btn oc-btn-coral mono"
                              style={{
                                height: 23,
                                fontSize: '11px',
                                padding: '0 8px',
                              }}
                              onClick={() =>
                                onOpenFinding(posture.finding.findingId)
                              }
                            >
                              <ShieldAlert size={11} />
                              <span>{posture.finding.findingId}</span>
                              <ArrowUpRight size={11} />
                            </button>
                          ) : posture.kind === 'ruled_out' ? (
                            <span className="oc-badge oc-badge-emerald mono">
                              <ShieldCheck size={11} />
                              RULED OUT · CONTROL
                            </span>
                          ) : (
                            <span className="oc-badge mono">MAPPED</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {/* SECTION B: Interactive Attack Surface Topology SVG */}
      {sectionTab === 'graph' && (
        <section className="oc-section-card" aria-label="Attack Surface Graph">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              marginBottom: 12,
            }}
          >
            <Network size={15} style={{ color: 'var(--cyan-fg)' }} />
            <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>
              Hierarchical Attack Surface Topology ({hostNodes.length} Hosts →{' '}
              {endpointNodes.length} Canonical Endpoints)
            </h2>
          </div>

          <div
            style={{
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              background: 'var(--bg-code)',
              overflowX: 'auto',
              padding: 10,
            }}
          >
            <svg
              width="720"
              height={svgHeight}
              viewBox={`0 0 720 ${svgHeight}`}
              role="img"
              aria-label="Attack Surface Topology Diagram"
            >
              <text
                x="16"
                y="20"
                fill="var(--text-muted)"
                fontSize="10"
                fontFamily="var(--font-mono)"
              >
                HOSTS ({hostNodes.length})
              </text>
              <text
                x="264"
                y="20"
                fill="var(--text-muted)"
                fontSize="10"
                fontFamily="var(--font-mono)"
              >
                CANONICAL ENDPOINTS ({endpointNodes.length})
              </text>

              {hostNodes.map((h, hIdx) => {
                const hy = 34 + hIdx * 42;
                return (
                  <g key={h.id}>
                    <rect
                      x="14"
                      y={hy}
                      width="200"
                      height="30"
                      rx="6"
                      fill="var(--bg-surface-2)"
                      stroke="var(--border-strong)"
                    />
                    <text
                      x="24"
                      y={hy + 19}
                      fill="var(--text-primary)"
                      fontSize="11.5"
                      fontFamily="var(--font-mono)"
                    >
                      {h.label}
                    </text>
                  </g>
                );
              })}

              {endpointNodes.slice(0, 8).map((ep, eIdx) => {
                const ey = 34 + eIdx * 36;
                const hostName = String(ep.metadata.host ?? '');
                const hostIdx = Math.max(
                  0,
                  hostNodes.findIndex((h) => h.label === hostName),
                );
                const hy = 49 + hostIdx * 42;
                const posture = findEndpointPosture(ep);
                const strokeCol =
                  posture.kind === 'finding'
                    ? 'var(--coral-fg)'
                    : posture.kind === 'ruled_out'
                      ? 'var(--emerald-fg)'
                      : 'var(--border-subtle)';

                return (
                  <g key={ep.id}>
                    <path
                      d={`M 214 ${hy} C 238 ${hy}, 238 ${ey + 14}, 262 ${ey + 14}`}
                      fill="none"
                      stroke="var(--border-strong)"
                      strokeWidth="1"
                    />
                    <rect
                      x="262"
                      y={ey}
                      width="440"
                      height="28"
                      rx="5"
                      fill="var(--bg-surface-2)"
                      stroke={strokeCol}
                    />
                    <text
                      x="274"
                      y={ey + 18}
                      fill="var(--text-primary)"
                      fontSize="11"
                      fontFamily="var(--font-mono)"
                    >
                      {ep.label.slice(0, 58)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </section>
      )}

      {/* SECTION C: Immutable Scope YAML & Governance Rules */}
      {sectionTab === 'scope' && (
        <section
          style={{ display: 'flex', flexDirection: 'column', gap: 14 }}
          aria-label="Immutable Scope YAML Inspector"
        >
          <div className="oc-grid-auto">
            <div className="oc-section-card">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: '12.5px',
                  fontWeight: 600,
                  marginBottom: 8,
                }}
              >
                <Globe size={14} style={{ color: 'var(--emerald-fg)' }} />
                <span>In-Scope Authorized Domains</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {overview.engagement.authorizedDomains.map((d) => (
                  <span key={d} className="oc-badge oc-badge-emerald mono">
                    {d}
                  </span>
                ))}
              </div>
            </div>

            <div className="oc-section-card">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: '12.5px',
                  fontWeight: 600,
                  marginBottom: 8,
                }}
              >
                <Ban size={14} style={{ color: 'var(--coral-fg)' }} />
                <span>HTTP 451 Excluded Hosts &amp; Paths</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {(overview.engagement.excludedHosts ?? []).map((h) => (
                  <span key={h} className="oc-badge oc-badge-coral mono">
                    {h}
                  </span>
                ))}
                {overview.engagement.excludedPaths.map((p) => (
                  <span key={p} className="oc-badge oc-badge-coral mono">
                    {p}
                  </span>
                ))}
              </div>
            </div>

            <div className="oc-section-card">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: '12.5px',
                  fontWeight: 600,
                  marginBottom: 8,
                }}
              >
                <Gauge size={14} style={{ color: 'var(--cyan-fg)' }} />
                <span>Egress Rate Cap &amp; Method Lock</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                <span className="oc-badge oc-badge-cyan mono">
                  {overview.engagement.maxRpsPerHost} req/s/host
                </span>
                <span className="oc-badge oc-badge-emerald mono">
                  <Lock size={11} />
                  {overview.engagement.strictReadOnly
                    ? 'GET / HEAD / OPTIONS'
                    : 'Custom'}
                </span>
              </div>
            </div>
          </div>

          <div className="oc-code-box">
            <div className="oc-code-header">
              <span className="mono" style={{ fontWeight: 600 }}>
                scope.yaml (Locked on main)
              </span>
              <button
                type="button"
                className="oc-btn"
                style={{ height: 24, fontSize: '11px', padding: '0 8px' }}
                onClick={() => {
                  if (
                    typeof navigator !== 'undefined' &&
                    navigator.clipboard
                  ) {
                    void navigator.clipboard.writeText(scopeYamlText);
                    setCopiedYaml(true);
                    setTimeout(() => setCopiedYaml(false), 1400);
                  }
                }}
              >
                {copiedYaml ? <Check size={11} /> : <Copy size={11} />}
                <span>{copiedYaml ? 'Copied' : 'Copy YAML'}</span>
              </button>
            </div>
            <pre className="oc-code-pre">{scopeYamlText}</pre>
          </div>
        </section>
      )}
    </div>
  );
};
