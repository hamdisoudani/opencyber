import React from 'react';
import { Menu, PanelLeftOpen, RefreshCw } from 'lucide-react';
import type {
  GitOpsSectionTab,
  ReconSectionTab,
} from '../dashboardController';
import type { PrimaryWorkspaceView } from '../types';

export interface TopHeaderBarProps {
  title: string;
  primaryDomain?: string;
  isLiveRunning: boolean;
  isSyncing: boolean;
  desktopRailCollapsed: boolean;
  metrics: {
    hosts: number;
    routes: number;
    hypotheses: number;
    findings: number;
    blocked451: number;
  };
  onOpenMobileDrawer: () => void;
  onExpandDesktopRail: () => void;
  onNavigate: (
    view: PrimaryWorkspaceView,
    subOptions?: {
      reconTab?: ReconSectionTab;
      gitOpsTab?: GitOpsSectionTab;
    },
  ) => void;
  onRefreshTelemetry: () => void;
}

export const TopHeaderBar: React.FC<TopHeaderBarProps> = ({
  title,
  primaryDomain,
  isLiveRunning,
  isSyncing,
  desktopRailCollapsed,
  metrics,
  onOpenMobileDrawer,
  onExpandDesktopRail,
  onNavigate,
  onRefreshTelemetry,
}) => {
  return (
    <header className="oc-topbar">
      {/* Left Group: min-width: 0; flex: 1 1 260px -> zero collision ever */}
      <div className="oc-topbar-left">
        <button
          type="button"
          id="btn-open-mobile-drawer"
          className="oc-icon-btn oc-rail-toggle-desktop-hidden"
          onClick={onOpenMobileDrawer}
          title="Open navigation drawer"
          aria-label="Open navigation drawer"
        >
          <Menu size={16} />
        </button>

        {desktopRailCollapsed && (
          <button
            type="button"
            id="btn-expand-rail"
            className="oc-icon-btn"
            onClick={onExpandDesktopRail}
            title="Expand navigation rail"
            aria-label="Expand navigation rail"
          >
            <PanelLeftOpen size={15} />
          </button>
        )}

        <h1 className="oc-topbar-title" title={title}>
          {title}
        </h1>

        <span
          className={`oc-badge mono ${
            isLiveRunning ? 'oc-badge-cyan' : 'oc-badge-emerald'
          }`}
          style={{ flexShrink: 0 }}
        >
          <span
            className={`oc-status-dot ${
              isLiveRunning ? 'is-running animate-pulse-dot' : 'is-completed'
            }`}
          />
          {isLiveRunning ? 'LIVE SQUAD' : 'COMPLETE'}
        </span>

        {primaryDomain && (
          <span
            className="oc-badge mono truncate"
            style={{ maxWidth: 180 }}
            title={`Primary Authorized Scope: ${primaryDomain}`}
          >
            {primaryDomain}
          </span>
        )}
      </div>

      {/* Right Group: flex-wrap: wrap; flex-shrink: 0 -> wraps cleanly at narrow viewports */}
      <div className="oc-topbar-right">
        <button
          type="button"
          id="pill-hosts"
          className="oc-metric-pill mono"
          onClick={() => onNavigate('recon', { reconTab: 'all' })}
          title="Inspect discovered hosts in Recon & Coverage"
        >
          <strong>{metrics.hosts}</strong>
          <span>Hosts</span>
        </button>

        <button
          type="button"
          id="pill-routes"
          className="oc-metric-pill mono"
          onClick={() => onNavigate('recon', { reconTab: 'all' })}
          title="Inspect canonical endpoints in Recon & Coverage"
        >
          <strong>{metrics.routes}</strong>
          <span>Routes</span>
        </button>

        <button
          type="button"
          id="pill-hypotheses"
          className={`oc-metric-pill mono${metrics.hypotheses > 0 ? ' is-amber' : ''}`}
          onClick={() => onNavigate('hypotheses')}
          title="Open KNOW -> THINK -> TEST -> VALIDATE Hypothesis Board"
        >
          <strong>{metrics.hypotheses}</strong>
          <span>Hypotheses</span>
        </button>

        <button
          type="button"
          id="pill-findings"
          className={`oc-metric-pill mono${metrics.findings > 0 ? ' is-coral' : ''}`}
          onClick={() => onNavigate('findings')}
          title="Open Verified Findings & HITL Governance"
        >
          <strong>{metrics.findings}</strong>
          <span>Findings</span>
        </button>

        <button
          type="button"
          id="pill-blocked-451"
          className={`oc-metric-pill mono${metrics.blocked451 > 0 ? ' is-coral' : ''}`}
          onClick={() => onNavigate('gitops', { gitOpsTab: 'egress' })}
          title="Inspect HTTP 451 Mandatory Egress Scope Blocks"
        >
          <strong>{metrics.blocked451}</strong>
          <span>451 Blocked</span>
        </button>

        <button
          type="button"
          id="btn-refresh-telemetry"
          className="oc-icon-btn"
          onClick={onRefreshTelemetry}
          title="Refresh squad & telemetry state"
          aria-label="Refresh squad and telemetry state"
        >
          <RefreshCw
            size={14}
            className={isSyncing ? 'animate-spin-fast' : ''}
          />
        </button>
      </div>
    </header>
  );
};
