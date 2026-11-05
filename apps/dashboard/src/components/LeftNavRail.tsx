import React, { useMemo, useState } from 'react';
import {
  Activity,
  Compass,
  GitBranch,
  Lightbulb,
  Loader2,
  Moon,
  PanelLeftClose,
  Plus,
  Search,
  Shield,
  ShieldAlert,
  Sun,
  X,
} from 'lucide-react';
import type {
  ConnectionState,
  PrimaryWorkspaceView,
  ProgramSummaryItem,
} from '../types';

export interface LeftNavRailProps {
  theme: 'dark' | 'light';
  desktopCollapsed: boolean;
  mobileOpen: boolean;
  activeView: PrimaryWorkspaceView;
  connectionState: ConnectionState;
  useCloudSandbox: boolean;
  programs: ProgramSummaryItem[];
  activeProgramId: string | null;
  counts: {
    agents: number;
    hypotheses: number;
    coverage: number;
    findings: number;
    pendingFindings: number;
    gitops: number;
  };
  onToggleTheme: () => void;
  onCollapseDesktop: () => void;
  onCloseMobile: () => void;
  onSelectView: (view: PrimaryWorkspaceView) => void;
  onSelectProgram: (programId: string) => void;
  onOpenNewEngagement: () => void;
}

export const LeftNavRail: React.FC<LeftNavRailProps> = ({
  theme,
  desktopCollapsed,
  mobileOpen,
  activeView,
  connectionState,
  useCloudSandbox,
  programs,
  activeProgramId,
  counts,
  onToggleTheme,
  onCollapseDesktop,
  onCloseMobile,
  onSelectView,
  onSelectProgram,
  onOpenNewEngagement,
}) => {
  const [filterQuery, setFilterQuery] = useState<string>('');

  const filteredPrograms = useMemo(() => {
    const q = filterQuery.trim().toLowerCase();
    if (!q) return programs;
    return programs.filter((prog) => {
      const hay = [
        prog.programName,
        prog.programId,
        ...prog.authorizedDomains,
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  }, [programs, filterQuery]);

  const navItems: Array<{
    id: PrimaryWorkspaceView;
    domId: string;
    label: string;
    icon: React.ReactNode;
    badge: string;
    badgeClass?: string;
  }> = [
    {
      id: 'operations',
      domId: 'nav-operations',
      label: 'Operations',
      icon: <Activity size={14} />,
      badge: String(counts.agents),
      badgeClass: 'oc-badge oc-badge-cyan mono',
    },
    {
      id: 'hypotheses',
      domId: 'nav-hypotheses',
      label: 'Hypotheses',
      icon: <Lightbulb size={14} />,
      badge: String(counts.hypotheses),
      badgeClass: 'oc-badge oc-badge-amber mono',
    },
    {
      id: 'recon',
      domId: 'nav-recon',
      label: 'Recon & Coverage',
      icon: <Compass size={14} />,
      badge: String(counts.coverage),
      badgeClass: 'oc-badge mono',
    },
    {
      id: 'findings',
      domId: 'nav-findings',
      label: 'Findings',
      icon: <ShieldAlert size={14} />,
      badge: String(counts.findings),
      badgeClass:
        counts.pendingFindings > 0
          ? 'oc-badge oc-badge-coral mono'
          : 'oc-badge mono',
    },
    {
      id: 'gitops',
      domId: 'nav-gitops',
      label: 'GitOps & Egress',
      icon: <GitBranch size={14} />,
      badge: String(counts.gitops),
      badgeClass: 'oc-badge mono',
    },
  ];

  return (
    <>
      <div
        className={`oc-rail-backdrop${mobileOpen ? ' is-visible' : ''}`}
        onClick={onCloseMobile}
        aria-hidden="true"
      />

      <aside
        className={`oc-left-rail${desktopCollapsed ? ' is-desktop-collapsed' : ''}${mobileOpen ? ' is-mobile-open' : ''}`}
        aria-label="Workspace Navigation Rail"
      >
        {/* Brand Header */}
        <div className="oc-rail-header">
          <div className="oc-brand">
            <span className="oc-brand-mark" aria-hidden="true">
              <Shield size={14} />
            </span>
            <span className="oc-brand-name">OpenCyber · Aegis</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <button
              type="button"
              id="btn-toggle-theme"
              className="oc-icon-btn"
              onClick={onToggleTheme}
              title={
                theme === 'dark'
                  ? 'Switch to Daylight Light theme'
                  : 'Switch to Precision Carbon Dark theme'
              }
              aria-label="Toggle color theme"
            >
              {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
            </button>

            {mobileOpen ? (
              <button
                type="button"
                id="btn-close-mobile-drawer"
                className="oc-icon-btn"
                onClick={onCloseMobile}
                aria-label="Close navigation drawer"
              >
                <X size={15} />
              </button>
            ) : (
              <button
                type="button"
                id="btn-collapse-rail"
                className="oc-icon-btn"
                onClick={onCollapseDesktop}
                title="Collapse navigation rail"
                aria-label="Collapse navigation rail"
              >
                <PanelLeftClose size={14} />
              </button>
            )}
          </div>
        </div>

        {/* Single + Icon + New Engagement Button (Zero Double-Plus Bug) */}
        <div className="oc-rail-cta-wrap">
          <button
            type="button"
            id="btn-new-engagement"
            className="oc-btn-new-engagement"
            onClick={onOpenNewEngagement}
          >
            <Plus size={14} style={{ color: 'var(--cyan-fg)', flexShrink: 0 }} />
            <span>New Engagement</span>
          </button>
        </div>

        {/* 5 Primary Workspace Views */}
        <div className="oc-rail-section-label">
          <span>Workspace</span>
        </div>

        <nav className="oc-nav-list" aria-label="Primary Workspace Views">
          {navItems.map((item) => {
            const active = activeView === item.id;
            return (
              <button
                key={item.id}
                type="button"
                id={item.domId}
                className={`oc-nav-item${active ? ' is-active' : ''}`}
                onClick={() => onSelectView(item.id)}
                aria-current={active ? 'page' : undefined}
              >
                <span className="oc-nav-item-left">
                  <span
                    style={{
                      display: 'inline-flex',
                      color: active ? 'var(--cyan-fg)' : 'currentColor',
                    }}
                  >
                    {item.icon}
                  </span>
                  <span className="truncate">{item.label}</span>
                </span>
                <span className={item.badgeClass ?? 'oc-badge mono'}>
                  {item.badge}
                </span>
              </button>
            );
          })}
        </nav>

        {/* Engagements List */}
        <div className="oc-rail-section-label" style={{ marginTop: 8 }}>
          <span>Engagements</span>
          <span className="mono">{filteredPrograms.length}</span>
        </div>

        <div className="oc-rail-search">
          <Search size={12} />
          <input
            type="search"
            id="input-filter-programs"
            placeholder="Filter programs…"
            aria-label="Filter programs"
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
          />
        </div>

        <div className="oc-rail-programs" role="list">
          {filteredPrograms.length === 0 ? (
            <div
              style={{
                padding: '12px 10px',
                fontSize: '11.5px',
                color: 'var(--text-muted)',
                lineHeight: 1.45,
              }}
            >
              {programs.length === 0
                ? 'No active programs yet. Click New Engagement above to launch a cyber squad.'
                : 'No programs match your filter.'}
            </div>
          ) : (
            filteredPrograms.map((prog) => {
              const selected = prog.programId === activeProgramId;
              const domain = prog.authorizedDomains[0] ?? prog.programId;
              return (
                <button
                  key={prog.programId}
                  type="button"
                  id={`program-item-${prog.programId}`}
                  className={`oc-program-card${selected ? ' is-active' : ''}`}
                  onClick={() => onSelectProgram(prog.programId)}
                  role="listitem"
                >
                  <div className="oc-program-card-top">
                    {prog.pipelineRunning ? (
                      <Loader2
                        size={12}
                        className="animate-spin-fast"
                        style={{ color: 'var(--cyan-fg)', flexShrink: 0 }}
                      />
                    ) : (
                      <span
                        className={`oc-status-dot ${
                          prog.pendingFindings > 0
                            ? 'is-waiting'
                            : 'is-completed'
                        }`}
                      />
                    )}
                    <span className="oc-program-card-title">
                      {prog.programName}
                    </span>
                  </div>
                  <div className="oc-program-card-meta">
                    <span className="mono truncate" style={{ maxWidth: 120 }}>
                      {domain}
                    </span>
                    <span className="mono" style={{ flexShrink: 0 }}>
                      {prog.canonicalEndpoints} routes
                    </span>
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Runtime Status Footer */}
        <div className="oc-rail-footer">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 6,
            }}
          >
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                fontWeight: 600,
                color:
                  connectionState === 'live'
                    ? 'var(--emerald-fg)'
                    : 'var(--text-secondary)',
              }}
            >
              <span
                className={`oc-status-dot ${
                  connectionState === 'live'
                    ? 'is-completed animate-pulse-dot'
                    : ''
                }`}
              />
              {connectionState === 'live'
                ? 'CONTROL PLANE LIVE'
                : 'SNAPSHOT READY'}
            </span>
            <span className="mono" style={{ fontSize: '10px' }}>
              {useCloudSandbox ? 'E2B Sandbox' : 'Local'}
            </span>
          </div>
          <div
            className="mono truncate"
            style={{ fontSize: '10px', color: 'var(--text-muted)' }}
            title="openrouter:stealth/crouton-alpha · groq:qwen/qwen3.8-27b"
          >
            crouton-alpha · qwen3.8-27b
          </div>
        </div>
      </aside>
    </>
  );
};
